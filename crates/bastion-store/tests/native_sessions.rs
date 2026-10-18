//! RFC-006 N1 native entry against real PostgreSQL: login isolation, refresh rotation/replay, native tickets.
//! Run on Unix with BASTION_GUAC_STORE_FIXTURE set: cargo test -p bastion-store --test native_sessions -- --ignored.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_store::{AssetCreate, Collection, PageRequest, PgStore};
use serde::Deserialize;
use serde_json::Value;
use sqlx::Row;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    server_id: String,
    gateway_id: String,
    username: String,
    asset_id: Uuid,
    account_id: Uuid,
}
const KEY: &str =
    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZbpRJIMtxDOgmfuMBMjqc0KTjiTRG/H/N/jegwxgxg";
fn shell() -> Vec<String> {
    vec!["shell".into()]
}
fn native(asset: Uuid, account: Uuid) -> NativeTicketRequest {
    NativeTicketRequest {
        asset_id: asset,
        account_id: account,
        capabilities: shell(),
    }
}
async fn ticket_state(store: &PgStore, id: Uuid) -> String {
    sqlx::query_scalar("SELECT state FROM connection_tickets WHERE id=$1")
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap()
}
async fn audit_payload(store: &PgStore, action: &str, connection: Uuid) -> (Value, Option<String>) {
    let row = sqlx::query("SELECT sanitized_payload,host(client_ip) AS ip FROM audit_events WHERE action=$1 AND resource_id=$2 ORDER BY occurred_at DESC LIMIT 1")
        .bind(action).bind(connection).fetch_one(&store.pool).await.unwrap();
    (row.get("sanitized_payload"), row.get("ip"))
}

#[tokio::test]
#[ignore = "requires BASTION_GUAC_STORE_FIXTURE or stdin: disposable zt-guac-v2- PostgreSQL schema2 owner fixture; no database is bundled"]
async fn native_logins_tickets_and_catalog_stay_isolated_from_the_browser() {
    let (fixture, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &fixture.server_id, &fixture.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store.check_identity().await.unwrap();
    let (root, phc) = store
        .login_candidate(&fixture.username)
        .await
        .unwrap()
        .unwrap();
    let admin_login = store
        .login_web(&root, &phc, "admin browser", Uuid::new_v4())
        .await
        .unwrap();
    let admin = store
        .authenticate_web(&admin_login.access_token)
        .await
        .unwrap();
    let user = store
        .create_user(
            &admin,
            &format!("native-{}", Uuid::new_v4().simple()),
            &phc,
            Role::Operator,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let asset = store
        .create_asset(
            &admin,
            &AssetCreate {
                group_id: None,
                name: "native ssh".into(),
                host: "10.20.30.40".into(),
                port: 22,
                tags: vec![],
                protocol: TargetProtocol::Ssh,
                security: None,
                ssh_host_key: Some(KEY.into()),
                rdp_certificate_sha256: None,
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let account = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO target_accounts(id,asset_id,label,username) VALUES($1,$2,'ops','root')",
    )
    .bind(account)
    .bind(asset.id)
    .execute(&store.pool)
    .await
    .unwrap();
    // A username-less account on the same asset never reaches the native catalog.
    sqlx::query(
        "INSERT INTO target_accounts(id,asset_id,label,username) VALUES($1,$2,'unnamed',NULL)",
    )
    .bind(Uuid::new_v4())
    .bind(asset.id)
    .execute(&store.pool)
    .await
    .unwrap();
    store
        .create_grant(&admin, user.id, asset.id, account, None, Uuid::new_v4())
        .await
        .unwrap();
    store
        .create_grant(
            &admin,
            user.id,
            fixture.asset_id,
            fixture.account_id,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();

    // Login isolation: each token only authenticates in its own family.
    let web_login = store
        .login_web(&user, &phc, "browser", Uuid::new_v4())
        .await
        .unwrap();
    let web = store
        .authenticate_web(&web_login.access_token)
        .await
        .unwrap();
    let device = store
        .login_native(&user, &phc, "ZeroTerm laptop", Uuid::new_v4())
        .await
        .unwrap();
    let me = store
        .authenticate_native(&device.access_token)
        .await
        .unwrap();
    assert_eq!(
        store.authenticate_web(&device.access_token).await.err(),
        Some(ErrorCode::Unauthenticated)
    );
    assert_eq!(
        store
            .authenticate_native(&web_login.access_token)
            .await
            .err(),
        Some(ErrorCode::Unauthenticated)
    );
    let kind: String = sqlx::query_scalar("SELECT client_type FROM login_sessions WHERE id=$1")
        .bind(device.login_session_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(kind, "native");
    // `/me/sessions` lists both device kinds.
    let devices = store
        .list_page(&web, Collection::DeviceSessions, PageRequest::default())
        .await
        .unwrap();
    let kinds: Vec<_> = devices["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["client_type"].as_str().unwrap().to_owned())
        .collect();
    assert!(
        kinds.contains(&"web".into()) && kinds.contains(&"native".into()),
        "{kinds:?}"
    );

    // Refresh: the other family's refresh endpoint neither rotates nor revokes; replay revokes the family.
    let spare = store
        .login_native(&user, &phc, "ZeroTerm CLI", Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(
        store
            .refresh_web(&spare.refresh_token, Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::Unauthenticated)
    );
    assert_eq!(
        store
            .refresh_native(&web_login.refresh_token, Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::Unauthenticated)
    );
    let rotated = store
        .refresh_native(&spare.refresh_token, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(rotated.login_session_id, spare.login_session_id);
    store
        .authenticate_native(&rotated.access_token)
        .await
        .unwrap();
    assert_eq!(
        store
            .refresh_native(&spare.refresh_token, Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::LoginSessionRevoked)
    );
    assert_eq!(
        store.authenticate_native(&rotated.access_token).await.err(),
        Some(ErrorCode::LoginSessionRevoked)
    );
    assert!(store
        .refresh_native(&rotated.refresh_token, Uuid::new_v4())
        .await
        .is_err());
    store
        .authenticate_web(&web_login.access_token)
        .await
        .unwrap();
    store
        .authenticate_native(&device.access_token)
        .await
        .unwrap();

    // Issuance validation: capabilities, SSH only, and the login family must match the transport.
    // Any non-empty subset of shell/exec/sftp is accepted.
    for bad in [
        vec![],
        vec!["sftp", "sftp"]
            .into_iter()
            .map(str::to_owned)
            .collect(),
        vec!["shell".into(), "unknown".into()],
        vec!["shell".into(), "shell".into()],
        vec!["exec".into(), "shell".into(), "exec".into()],
        vec!["telnet".into()],
        vec!["Exec".into()],
    ] {
        let request = NativeTicketRequest {
            capabilities: bad,
            ..native(asset.id, account)
        };
        assert_eq!(
            store
                .issue_native_ticket(&me, request, Uuid::new_v4())
                .await
                .err(),
            Some(ErrorCode::InvalidArgument)
        );
    }
    assert_eq!(
        store
            .issue_native_ticket(
                &me,
                native(fixture.asset_id, fixture.account_id),
                Uuid::new_v4()
            )
            .await
            .err(),
        Some(ErrorCode::PermissionDenied)
    );
    assert_eq!(
        store
            .issue_native_ticket(&web, native(asset.id, account), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::Unauthenticated)
    );
    let browser_request = SessionRequest {
        asset_id: asset.id,
        account_id: account,
        display: Display::default(),
    };
    assert_eq!(
        store
            .issue_web_session(&me, browser_request.clone(), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::Unauthenticated)
    );

    let issued = store
        .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(issued.capabilities, shell());
    assert!(
        issued.ticket_secret.len() >= 43,
        "at least 32 random bytes in base64url"
    );
    let row = sqlx::query("SELECT t.transport AS tt,t.capabilities,c.transport AS ct,c.width,c.height,c.dpi FROM connection_tickets t JOIN connections c ON c.id=t.connection_id WHERE t.id=$1").bind(issued.ticket_id).fetch_one(&store.pool).await.unwrap();
    assert_eq!(
        (row.get::<String, _>("tt"), row.get::<String, _>("ct")),
        ("native_ssh".into(), "native_ssh".into())
    );
    assert_eq!(
        row.get::<Option<Vec<String>>, _>("capabilities"),
        Some(shell())
    );
    assert!(
        row.get::<Option<i32>, _>("width").is_none() && row.get::<Option<i32>, _>("dpi").is_none()
    );
    let (payload, _) = audit_payload(&store, "ticket.issued", issued.connection_id).await;
    assert_eq!(
        (
            payload["transport"].as_str(),
            payload["capabilities"].clone()
        ),
        (Some("native_ssh"), serde_json::json!(["shell"]))
    );
    let pending = store
        .own_connection(&me, issued.connection_id)
        .await
        .unwrap();
    assert_eq!(
        (pending.state, pending.transport, pending.display),
        (
            ConnectionState::Pending,
            Transport::NativeSsh,
            Display::default()
        )
    );
    let listed = store
        .list_page(&me, Collection::Connections, PageRequest::default())
        .await
        .unwrap();
    let entry = listed["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == serde_json::json!(issued.connection_id))
        .cloned()
        .unwrap();
    assert_eq!(
        (entry["transport"].as_str(), entry["display"].is_null()),
        (Some("native_ssh"), true)
    );

    // Consumption: wrong secret or transport never burns the ticket.
    let peer: std::net::IpAddr = "198.51.100.7".parse().unwrap();
    assert_eq!(
        store
            .consume_native_ticket(issued.ticket_id, "wrong secret", peer)
            .await
            .err(),
        Some(ErrorCode::TicketInvalid)
    );
    assert_eq!(
        store
            .consume_native_ticket(Uuid::new_v4(), &issued.ticket_secret, peer)
            .await
            .err(),
        Some(ErrorCode::TicketInvalid)
    );
    assert_eq!(
        store
            .consume_web_session(issued.ticket_id, &issued.ticket_secret, &me)
            .await
            .err(),
        Some(ErrorCode::TicketInvalid)
    );
    assert_eq!(ticket_state(&store, issued.ticket_id).await, "issued");
    let browser_ticket = store
        .issue_web_session(&web, browser_request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(
        store
            .consume_native_ticket(browser_ticket.session_id, &browser_ticket.ws_token, peer)
            .await
            .err(),
        Some(ErrorCode::TicketInvalid)
    );
    assert_eq!(
        ticket_state(&store, browser_ticket.session_id).await,
        "issued"
    );
    store
        .request_disconnect(&web, browser_ticket.connection_id, Uuid::new_v4())
        .await
        .unwrap();

    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..10 {
        let (store, id, secret) = (
            store.clone(),
            issued.ticket_id,
            issued.ticket_secret.clone(),
        );
        racers.spawn(async move { store.consume_native_ticket(id, &secret, peer).await });
    }
    let mut won = None;
    while let Some(result) = racers.join_next().await {
        match result.unwrap() {
            Ok(session) => assert!(won.replace(session).is_none(), "two consumers won"),
            Err(ErrorCode::TicketUsed) => {}
            Err(code) => panic!("unexpected consumption error: {code:?}"),
        }
    }
    let session = won.expect("one consumer must win");
    assert_eq!(session.capabilities, shell());
    let connection = session.connection;
    assert_eq!(
        (connection.id, connection.state, connection.transport),
        (
            issued.connection_id,
            ConnectionState::Connecting,
            Transport::NativeSsh
        )
    );
    assert_eq!(
        (connection.user_id, connection.login_session_id),
        (Some(user.id), Some(me.login_session_id))
    );
    assert_eq!(connection.display, Display::default());
    let (payload, ip) = audit_payload(&store, "ticket.consumed", connection.id).await;
    assert_eq!(
        (payload["transport"].as_str(), ip.as_deref()),
        (Some("native_ssh"), Some("198.51.100.7"))
    );
    store.authorize_connection(&connection).await.unwrap();
    assert_eq!(
        store
            .target_snapshot(&connection)
            .await
            .unwrap()
            .username
            .as_deref(),
        Some("root")
    );
    assert_eq!(
        store
            .consume_native_ticket(issued.ticket_id, &issued.ticket_secret, peer)
            .await
            .err(),
        Some(ErrorCode::TicketUsed)
    );
    // `/native/connections/{id}` is owner-only, even for administrators.
    assert_eq!(
        store.own_connection(&admin, connection.id).await.err(),
        Some(ErrorCode::ResourceNotFound)
    );
    store.connection(&admin, connection.id).await.unwrap();
    store
        .transition(
            connection.id,
            ConnectionState::Failed,
            Some(ErrorCode::TargetUnreachable),
        )
        .await
        .unwrap();
    let failed = store.own_connection(&me, connection.id).await.unwrap();
    assert_eq!(
        serde_json::to_value(&failed).unwrap()["failure"],
        serde_json::json!({"code":"TARGET_UNREACHABLE"})
    );
    assert!(serde_json::to_value(&pending).unwrap()["failure"].is_null());

    // 30-second deadline.
    let late = store
        .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    let ttl: f64 = sqlx::query_scalar("SELECT extract(epoch FROM expires_at-clock_timestamp())::float8 FROM connection_tickets WHERE id=$1").bind(late.ticket_id).fetch_one(&store.pool).await.unwrap();
    assert!(ttl > 25.0 && ttl <= 30.0, "{ttl}");
    sqlx::query("UPDATE connection_tickets SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(late.ticket_id).execute(&store.pool).await.unwrap();
    assert_eq!(
        store
            .consume_native_ticket(late.ticket_id, &late.ticket_secret, peer)
            .await
            .err(),
        Some(ErrorCode::TicketExpired)
    );
    assert_eq!(ticket_state(&store, late.ticket_id).await, "expired");

    // Revision changes after issuance make the ticket stale, and the rejection is audited with transport.
    let stale = store
        .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    let mut change = store.pool.begin().await.unwrap();
    sqlx::query("SELECT policy_revision FROM server_settings WHERE singleton FOR UPDATE")
        .fetch_one(&mut *change)
        .await
        .unwrap();
    sqlx::query("UPDATE target_accounts SET security_revision=security_revision+1 WHERE id=$1")
        .bind(account)
        .execute(&mut *change)
        .await
        .unwrap();
    change.commit().await.unwrap();
    assert_eq!(
        store
            .consume_native_ticket(stale.ticket_id, &stale.ticket_secret, peer)
            .await
            .err(),
        Some(ErrorCode::TicketStale)
    );
    let (payload, _) = audit_payload(&store, "ticket.rejected", stale.connection_id).await;
    assert_eq!(
        (
            payload["reason_code"].as_str(),
            payload["transport"].as_str()
        ),
        (Some("SESSION_TICKET_STALE"), Some("native_ssh"))
    );

    // Pending and concurrent ceilings are shared with the browser, not a separate allowance.
    store.configure_session_limits(10, 1, 2).unwrap();
    let first = store
        .issue_web_session(&web, browser_request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    let second = store
        .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(
        store
            .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::ConnectionLimit)
    );
    assert_eq!(
        store
            .issue_web_session(&web, browser_request.clone(), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::ConnectionLimit)
    );
    store
        .request_disconnect(&web, first.connection_id, Uuid::new_v4())
        .await
        .unwrap();
    let running = store
        .consume_native_ticket(second.ticket_id, &second.ticket_secret, peer)
        .await
        .unwrap()
        .connection;
    assert_eq!(
        store
            .issue_web_session(&web, browser_request.clone(), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::ConnectionLimit)
    );
    store
        .transition(
            running.id,
            ConnectionState::Failed,
            Some(ErrorCode::TargetUnreachable),
        )
        .await
        .unwrap();
    store.configure_session_limits(10, 3, 20).unwrap();

    // RFC-006 §14: capability subsets are stored and echoed in request order.
    let subset = |caps: &[&str]| NativeTicketRequest {
        capabilities: caps.iter().map(|c| c.to_string()).collect(),
        ..native(asset.id, account)
    };
    let both = store
        .issue_native_ticket(&me, subset(&["exec", "shell"]), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(both.capabilities, ["exec", "shell"]);
    let stored: Option<Vec<String>> =
        sqlx::query_scalar("SELECT capabilities FROM connection_tickets WHERE id=$1")
            .bind(both.ticket_id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(
        stored.as_deref(),
        Some(&["exec".to_owned(), "shell".into()][..])
    );
    let (payload, _) = audit_payload(&store, "ticket.issued", both.connection_id).await;
    assert_eq!(
        payload["capabilities"],
        serde_json::json!(["exec", "shell"])
    );
    let both = store
        .consume_native_ticket(both.ticket_id, &both.ticket_secret, peer)
        .await
        .unwrap();
    assert_eq!(both.capabilities, ["exec", "shell"]);
    let shell_exec = store
        .issue_native_ticket(&me, subset(&["shell", "exec"]), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(shell_exec.capabilities, ["shell", "exec"]);

    // An exec-only connection becomes active without any recording, with the usual audit.
    let exec_ticket = store
        .issue_native_ticket(&me, subset(&["exec"]), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(exec_ticket.capabilities, ["exec"]);
    let exec = store
        .consume_native_ticket(exec_ticket.ticket_id, &exec_ticket.ticket_secret, peer)
        .await
        .unwrap();
    assert_eq!(exec.capabilities, ["exec"]);
    let exec = exec.connection;
    let mut forged = exec.clone();
    forged.auth_revision += 1;
    assert_eq!(
        store.activate_native_connection(&forged).await.err(),
        Some(ErrorCode::TicketStale)
    );
    store.activate_native_connection(&exec).await.unwrap();
    assert_eq!(
        store.own_connection(&me, exec.id).await.unwrap().state,
        ConnectionState::Active
    );
    let recordings: i64 =
        sqlx::query_scalar("SELECT count(*) FROM recordings WHERE connection_id=$1")
            .bind(exec.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(recordings, 0);
    let (payload, _) = audit_payload(&store, "connection.active", exec.id).await;
    assert_eq!(
        (
            payload["recording_id"].is_null(),
            payload["transport"].as_str()
        ),
        (true, Some("native_ssh"))
    );
    // Repeating it (a later channel) is a no-op: no second audit row, state unchanged.
    store.activate_native_connection(&exec).await.unwrap();
    let activations: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action='connection.active' AND resource_id=$1",
    )
    .bind(exec.id)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(activations, 1);

    // Browser connections only activate through their recording.
    let browser_ticket = store
        .issue_web_session(&web, browser_request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    let browser_connection = store
        .consume_web_session(browser_ticket.session_id, &browser_ticket.ws_token, &web)
        .await
        .unwrap();
    let mut disguised = browser_connection.clone();
    disguised.transport = Transport::NativeSsh;
    for candidate in [&browser_connection, &disguised] {
        assert_eq!(
            store.activate_native_connection(candidate).await.err(),
            Some(ErrorCode::InvalidArgument)
        );
    }
    assert_eq!(
        store
            .connection(&web, browser_connection.id)
            .await
            .unwrap()
            .state,
        ConnectionState::Connecting
    );

    // Exec audit rows: command preview, full-command hash, counters, no output.
    store
        .exec_completed(
            &exec,
            b"uptime",
            &ExecOutcome {
                exit_status: Some(0),
                exit_signal: None,
                stdin_bytes: 0,
                stdout_bytes: 61,
                stderr_bytes: 0,
                duration_ms: 12,
            },
        )
        .await
        .unwrap();
    let row = sqlx::query("SELECT actor_id,login_session_id,resource_type,sanitized_payload FROM audit_events WHERE action='exec.completed' AND resource_id=$1")
        .bind(exec.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        (
            row.get::<Option<Uuid>, _>("actor_id"),
            row.get::<Option<Uuid>, _>("login_session_id"),
            row.get::<String, _>("resource_type")
        ),
        (
            Some(user.id),
            Some(me.login_session_id),
            "connection".into()
        )
    );
    assert_eq!(
        row.get::<Value, _>("sanitized_payload"),
        serde_json::json!({
            "connection_id": exec.id,
            "transport": "native_ssh",
            "command": "uptime",
            "command_sha256": "dd291cd6294bafef2a7e9c378eb320e87198d6dae214272addb569775750c802",
            "command_bytes": 6,
            "truncated": false,
            "exit_status": 0,
            "exit_signal": null,
            "stdin_bytes": 0,
            "stdout_bytes": 61,
            "stderr_bytes": 0,
            "duration_ms": 12
        })
    );
    store
        .exec_completed(
            &exec,
            b"sleep 600",
            &ExecOutcome {
                exit_signal: Some("TERM".into()),
                stdin_bytes: 3,
                duration_ms: 900,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let (payload, _) = audit_payload(&store, "exec.completed", exec.id).await;
    assert_eq!(
        (
            payload["exit_status"].is_null(),
            payload["exit_signal"].as_str(),
            payload["stdin_bytes"].as_u64()
        ),
        (true, Some("TERM"), Some(3))
    );
    let mut long = vec![b'x'; 70 * 1024];
    long[0] = 0xc3;
    long[5] = 0;
    store
        .exec_rejected(&exec, &long, ErrorCode::InvalidArgument)
        .await
        .unwrap();
    let (payload, _) = audit_payload(&store, "exec.rejected", exec.id).await;
    let preview = payload["command"].as_str().unwrap();
    assert!(
        preview.starts_with('\u{fffd}') && !preview.contains('\0'),
        "{preview:?}"
    );
    assert!(preview.chars().count() <= 4096);
    assert_eq!(
        (
            payload["truncated"].as_bool(),
            payload["command_bytes"].as_u64(),
            payload["command_sha256"].as_str().map(str::len),
            payload["reason_code"].as_str(),
            payload["connection_id"].clone()
        ),
        (
            Some(true),
            Some(70 * 1024),
            Some(64),
            Some("INVALID_ARGUMENT"),
            serde_json::json!(exec.id)
        )
    );
    assert!(payload.get("exit_status").is_none() && payload.get("stdout_bytes").is_none());
    assert_eq!(
        store
            .exec_rejected(&browser_connection, b"id", ErrorCode::PermissionDenied)
            .await
            .err(),
        Some(ErrorCode::InvalidArgument)
    );
    for id in [exec.id, both.connection.id, browser_connection.id] {
        store
            .transition(
                id,
                ConnectionState::Failed,
                Some(ErrorCode::TargetUnreachable),
            )
            .await
            .unwrap();
    }
    store
        .request_disconnect(&me, shell_exec.connection_id, Uuid::new_v4())
        .await
        .unwrap();

    // Exec can activate first, then a shell attaches its single recording while already active.
    let issued = store
        .issue_native_ticket(&me, subset(&["sftp", "shell", "exec"]), Uuid::new_v4())
        .await
        .unwrap();
    let late_shell = store
        .consume_native_ticket(issued.ticket_id, &issued.ticket_secret, peer)
        .await
        .unwrap();
    assert_eq!(late_shell.capabilities, ["sftp", "shell", "exec"]);
    let late_shell = late_shell.connection;
    store.activate_native_connection(&late_shell).await.unwrap();
    let rid = Uuid::new_v4();
    store
        .create_recording(
            &late_shell,
            RecordingCreate {
                id: rid,
                relative_path: format!("{rid}.ztrec"),
                format_version: 2,
                retention_until: chrono::Utc::now() + chrono::Duration::days(1),
                wrapped_dek: vec![0; 48],
                wrap_nonce: vec![0; 24],
                key_version: 1,
                nonce_prefix: vec![0; 16],
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    store.checkpoint_recording(rid, 0, 0, 100).await.unwrap();
    store.activate_recording(rid).await.unwrap();
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action='connection.active' AND resource_id=$1",
    )
    .bind(late_shell.id)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(
        count, 1,
        "late shell must not activate the connection twice"
    );
    let payload:Value=sqlx::query_scalar("SELECT sanitized_payload FROM audit_events WHERE action='recording.active' AND resource_id=$1")
        .bind(rid).fetch_one(&store.pool).await.unwrap();
    assert_eq!(payload["connection_id"], serde_json::json!(late_shell.id));
    let mut raw_path = b"/tmp/\0\xff".to_vec();
    raw_path.extend("长".repeat(5000).as_bytes());
    for status in [Some(0), None, Some(3)] {
        let entry = SftpAudit::File {
            path: raw_path.clone(),
            flags: 0x1a,
            status,
            read_bytes: 8,
            write_bytes: 9,
            sha256: None,
            read_sha256: Some("r".repeat(64)),
            write_sha256: None,
        };
        store.sftp_audit(&late_shell, &entry).await.unwrap();
        let (payload, _) = audit_payload(&store, "sftp.file", late_shell.id).await;
        assert_eq!(payload["connection_id"], serde_json::json!(late_shell.id));
        assert_eq!(payload["transport"], "native_ssh");
        assert_eq!(payload["status"], serde_json::json!(status));
        assert_eq!(payload["read_bytes"], 8);
        assert_eq!(payload["write_bytes"], 9);
        assert_eq!(payload["flags"], 0x1a);
        assert_eq!(payload["path"].as_str().unwrap().chars().count(), 4096);
        assert!(payload["path"]
            .as_str()
            .unwrap()
            .starts_with("/tmp/\u{fffd}\u{fffd}"));
    }
    for op in [
        SftpOp::Setstat,
        SftpOp::Fsetstat,
        SftpOp::Remove,
        SftpOp::Mkdir,
        SftpOp::Rmdir,
        SftpOp::Rename,
        SftpOp::Symlink,
        SftpOp::PosixRename,
        SftpOp::Hardlink,
    ] {
        let entry = SftpAudit::Operation {
            op,
            path: b"/source".to_vec(),
            target_path: Some(b"/target\0\xff".to_vec()),
            status: 3,
        };
        store.sftp_audit(&late_shell, &entry).await.unwrap();
        let row=sqlx::query("SELECT sanitized_payload,resource_type,actor_id FROM audit_events WHERE action=$1 AND resource_id=$2 ORDER BY occurred_at DESC LIMIT 1")
            .bind(op.as_action()).bind(late_shell.id).fetch_one(&store.pool).await.unwrap();
        assert_eq!(row.get::<String, _>("resource_type"), "connection");
        assert_eq!(row.get::<Option<Uuid>, _>("actor_id"), late_shell.user_id);
        let payload: Value = row.get("sanitized_payload");
        assert_eq!(payload["target_path"], "/target\u{fffd}\u{fffd}");
        assert_eq!(payload["status"], 3);
    }
    let summary = SftpAudit::Session {
        requests: std::collections::BTreeMap::from([("read".into(), 2)]),
        input_bytes: 100,
        output_bytes: 200,
    };
    store.sftp_audit(&late_shell, &summary).await.unwrap();
    let (payload, _) = audit_payload(&store, "sftp.session", late_shell.id).await;
    assert_eq!(
        payload,
        serde_json::json!({"connection_id":late_shell.id,"transport":"native_ssh","requests":{"read":2},"input_bytes":100,"output_bytes":200})
    );
    store
        .sftp_rejected(&late_shell, ErrorCode::PermissionDenied)
        .await
        .unwrap();
    let (payload, _) = audit_payload(&store, "sftp.rejected", late_shell.id).await;
    assert_eq!(
        payload,
        serde_json::json!({"connection_id":late_shell.id,"transport":"native_ssh","reason_code":"PERMISSION_DENIED"})
    );
    assert_eq!(
        store.sftp_audit(&browser_connection, &summary).await,
        Err(ErrorCode::InvalidArgument)
    );
    assert_eq!(
        store
            .sftp_rejected(&browser_connection, ErrorCode::PermissionDenied)
            .await,
        Err(ErrorCode::InvalidArgument)
    );
    let mut missing = late_shell.clone();
    missing.id = Uuid::new_v4();
    assert_eq!(
        store.sftp_audit(&missing, &summary).await,
        Err(ErrorCode::ResourceNotFound)
    );
    store
        .transition(
            late_shell.id,
            ConnectionState::Failed,
            Some(ErrorCode::TargetUnreachable),
        )
        .await
        .unwrap();

    // Revoking the native device from the browser ends its runtime binding and pending tickets.
    let held = store
        .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    let live = store
        .issue_native_ticket(&me, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    let live = store
        .consume_native_ticket(live.ticket_id, &live.ticket_secret, peer)
        .await
        .unwrap()
        .connection;
    store
        .revoke_device_session(&web, me.login_session_id, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store.authorize_connection(&live).await.is_err());
    assert_eq!(ticket_state(&store, held.ticket_id).await, "revoked");
    assert!(store
        .consume_native_ticket(held.ticket_id, &held.ticket_secret, peer)
        .await
        .is_err());
    assert_eq!(
        store.authenticate_native(&device.access_token).await.err(),
        Some(ErrorCode::LoginSessionRevoked)
    );

    // Native catalog: SSH only, named accounts only, each with the capabilities handed in.
    let other = store
        .login_native(&user, &phc, "ZeroTerm desktop", Uuid::new_v4())
        .await
        .unwrap();
    let other = store
        .authenticate_native(&other.access_token)
        .await
        .unwrap();
    let page = store
        .native_assets(&other, None, PageRequest::default(), &["shell"])
        .await
        .unwrap();
    let items = page["items"].as_array().unwrap();
    assert!(items.iter().all(|a| a["protocol"] == "ssh"));
    assert!(
        !items
            .iter()
            .any(|a| a["id"] == serde_json::json!(fixture.asset_id)),
        "VNC asset leaked into the native catalog"
    );
    let mine = items
        .iter()
        .find(|a| a["id"] == serde_json::json!(asset.id))
        .unwrap();
    assert_eq!(
        mine["accounts"],
        serde_json::json!([{"id":account,"label":"ops","username":"root","domain":null,"credential_kind":"none","capabilities":["shell"]}])
    );
    assert!(page["groups"].is_array() && page["policy_revision"].is_i64());
    let closed = store
        .native_assets(&other, Some(asset.id), PageRequest::default(), &[])
        .await
        .unwrap();
    assert_eq!(
        closed["items"][0]["accounts"][0]["capabilities"],
        serde_json::json!([])
    );
    assert!(closed.get("groups").is_none());
    let vnc = store
        .native_assets(
            &other,
            Some(fixture.asset_id),
            PageRequest::default(),
            &["shell"],
        )
        .await
        .unwrap();
    assert_eq!(vnc["items"], serde_json::json!([]));
    // Administrators see every account implicitly, yet a username-less SSH account stays out.
    let root_native = store
        .login_native(&root, &phc, "admin ZeroTerm", Uuid::new_v4())
        .await
        .unwrap();
    let root_native = store
        .authenticate_native(&root_native.access_token)
        .await
        .unwrap();
    let all = store
        .native_assets(
            &root_native,
            Some(asset.id),
            PageRequest::default(),
            &["shell"],
        )
        .await
        .unwrap();
    let labels: Vec<_> = all["items"][0]["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["label"].as_str().unwrap())
        .collect();
    assert_eq!(labels, ["ops"]);
    // Gateway-side failures are audited with the source address and never the secret.
    store
        .native_auth_failure(peer, Some(issued.ticket_id), ErrorCode::TicketInvalid)
        .await
        .unwrap();
    let row = sqlx::query("SELECT sanitized_payload,host(client_ip) AS ip FROM audit_events WHERE action='native.auth_failure' ORDER BY occurred_at DESC LIMIT 1").fetch_one(&store.pool).await.unwrap();
    assert_eq!(
        row.get::<Option<String>, _>("ip").as_deref(),
        Some("198.51.100.7")
    );
    assert!(!row
        .get::<Value, _>("sanitized_payload")
        .to_string()
        .contains(&issued.ticket_secret));
    // Browser catalog is unchanged: no capabilities field, VNC asset still listed.
    let browser = store
        .list_page(&web, Collection::Assets, PageRequest::default())
        .await
        .unwrap();
    assert!(browser["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|a| a["id"] == serde_json::json!(fixture.asset_id)));
    assert!(browser["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|a| a["accounts"]
            .as_array()
            .unwrap()
            .iter()
            .all(|t| t.get("capabilities").is_none())));

    // Schema guards: transports match their ticket, and display presence follows transport.
    let check = store
        .issue_native_ticket(&other, native(asset.id, account), Uuid::new_v4())
        .await
        .unwrap();
    for sql in [
        "UPDATE connections SET width=1280,height=720,dpi=96 WHERE id=$1",
        "UPDATE connections SET transport='websocket' WHERE id=$1",
        "UPDATE connection_tickets SET capabilities=NULL WHERE connection_id=$1",
        "UPDATE connection_tickets SET capabilities='{}' WHERE connection_id=$1",
        "UPDATE connection_tickets SET capabilities='{telnet}' WHERE connection_id=$1",
        "UPDATE connection_tickets SET capabilities='{shell,NULL}' WHERE connection_id=$1",
    ] {
        assert!(
            sqlx::query(sql)
                .bind(check.connection_id)
                .execute(&store.pool)
                .await
                .is_err(),
            "{sql}"
        );
    }
    let mut tx = store.pool.begin().await.unwrap();
    sqlx::query("UPDATE connection_tickets SET transport='websocket',capabilities=NULL WHERE connection_id=$1").bind(check.connection_id).execute(&mut *tx).await.unwrap();
    assert!(
        tx.commit().await.is_err(),
        "deferred ticket/connection transport identity must hold"
    );
    assert!(
        sqlx::query("UPDATE login_sessions SET client_type='zeroterm' WHERE id=$1")
            .bind(other.login_session_id)
            .execute(&store.pool)
            .await
            .is_err()
    );
    let browser_row = sqlx::query("SELECT transport,width FROM connections WHERE id=$1")
        .bind(first.connection_id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(
        (
            browser_row.get::<String, _>("transport"),
            browser_row.get::<Option<i32>, _>("width")
        ),
        ("websocket".into(), Some(1280))
    ); // Soft deletion preserves connection history; audits read actor/login from the connection row.
    let current = store.user(user.id).await.unwrap();
    store
        .delete_user(&admin, user.id, current.revision, Uuid::new_v4())
        .await
        .unwrap();
    store.sftp_audit(&late_shell, &summary).await.unwrap();
    let actor:Option<Uuid>=sqlx::query_scalar("SELECT actor_id FROM audit_events WHERE action='sftp.session' AND resource_id=$1 ORDER BY occurred_at DESC LIMIT 1")
        .bind(late_shell.id).fetch_one(&store.pool).await.unwrap();
    let row_actor: Option<Uuid> = sqlx::query_scalar("SELECT user_id FROM connections WHERE id=$1")
        .bind(late_shell.id)
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(actor, row_actor);
}
