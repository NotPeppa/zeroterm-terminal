//! Real PostgreSQL checks. Reuses the isolated fixture created by tests/m1_smoke.py.
//! Run on Unix with BASTION_M1_FIXTURE set: cargo test -p bastion-store --test web_sessions -- --ignored.
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_store::PgStore;
use serde::Deserialize;
use sqlx::Row;
use std::time::Duration;
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    server_id: String,
    gateway_id: String,
    username: String,
    asset_id: Uuid,
    account_id: Uuid,
}

#[tokio::test]
#[ignore = "requires isolated real PostgreSQL and BASTION_M1_FIXTURE; no database is bundled"]
async fn web_transport_owner_replay_expiry_and_login_domains() {
    let (fixture, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &fixture.server_id, &fixture.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    pg_fixture::probe(&store).await;
    let (admin, phc) = store
        .login_candidate(&fixture.username)
        .await
        .unwrap()
        .unwrap();
    let login = store
        .login_web(&admin, &phc, "web store tests", Uuid::new_v4())
        .await
        .unwrap();
    let administrator = store.authenticate_web(&login.access_token).await.unwrap();
    let user = store
        .create_user(
            &administrator,
            &format!("ws-{}", Uuid::new_v4().simple()),
            &phc,
            Role::Operator,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let web = store
        .login_web(&user, &phc, "browser", Uuid::new_v4())
        .await
        .unwrap();
    let identity = store.authenticate_web(&web.access_token).await.unwrap();
    let other_login = store
        .login_web(&user, &phc, "other browser", Uuid::new_v4())
        .await
        .unwrap();
    let other_identity = store
        .authenticate_web(&other_login.access_token)
        .await
        .unwrap();
    let bearer = store
        .login(&user, &phc, "zeroterm", Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        store.authenticate(&web.access_token).await,
        Err(ErrorCode::Unauthenticated)
    ));
    assert!(matches!(
        store.authenticate_web(&bearer.access_token).await,
        Err(ErrorCode::Unauthenticated)
    ));
    assert!(matches!(
        store.refresh(&web.refresh_token, Uuid::new_v4()).await,
        Err(ErrorCode::Unauthenticated)
    ));
    assert!(matches!(
        store
            .refresh_web(&bearer.refresh_token, Uuid::new_v4())
            .await,
        Err(ErrorCode::Unauthenticated)
    ));
    // Cross-domain refresh rejection must not revoke the legitimate family.
    store.authenticate(&bearer.access_token).await.unwrap();
    store.authenticate_web(&web.access_token).await.unwrap();

    let grant = store
        .create_grant(
            &administrator,
            user.id,
            fixture.asset_id,
            fixture.account_id,
            &[Capability::Shell],
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let request = TicketRequest {
        asset_id: fixture.asset_id,
        account_id: fixture.account_id,
        capabilities: vec![Capability::Shell],
        purpose: Purpose::Terminal,
    };
    let gateway = GatewayAddress {
        id: fixture.gateway_id.clone(),
        host: "127.0.0.1".into(),
        port: 2222,
        username: String::new(),
    };
    let issue = || store.issue_web_session(&identity, request.clone(), Uuid::new_v4());
    let issue_started = std::time::Instant::now();
    let issue_result = issue().await;
    if issue_result.is_err() {
        pg_fixture::failure(&store, "issue_web_session", issue_started.elapsed()).await;
    }
    let session = issue_result.unwrap();
    assert!(matches!(
        store
            .consume_ticket(session.session_id, &session.ws_token)
            .await,
        Err(ErrorCode::TicketInvalid)
    ));
    assert!(matches!(
        store
            .consume_web_session(session.session_id, "wrong secret", &identity)
            .await,
        Err(ErrorCode::TicketInvalid)
    ));
    assert!(matches!(
        store
            .consume_web_session(session.session_id, &session.ws_token, &other_identity)
            .await,
        Err(ErrorCode::TicketInvalid)
    ));
    assert!(matches!(
        store
            .consume_web_session(session.session_id, &session.ws_token, &administrator)
            .await,
        Err(ErrorCode::TicketInvalid)
    ));
    let pending = store
        .connection(&identity, session.connection_id)
        .await
        .unwrap();
    assert_eq!(pending.state, ConnectionState::Pending);
    assert_eq!(pending.transport, TicketTransport::Websocket);
    assert_eq!(pending.protocol_version, 1);
    assert_eq!(
        sqlx::query_scalar::<_, String>("SELECT state FROM connection_tickets WHERE id=$1")
            .bind(session.session_id)
            .fetch_one(&store.pool)
            .await
            .unwrap(),
        "issued"
    );

    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let store = store.clone();
        let identity = identity.clone();
        let id = session.session_id;
        let secret = session.ws_token.clone();
        racers.spawn(async move { store.consume_web_session(id, &secret, &identity).await });
    }
    let mut wins = 0;
    while let Some(result) = racers.join_next().await {
        match result.unwrap() {
            Ok(connection) => {
                wins += 1;
                assert_eq!(connection.id, session.connection_id);
                assert_eq!(connection.state, ConnectionState::Connecting);
            }
            Err(ErrorCode::TicketUsed) => {}
            Err(code) => panic!("unexpected consumption error: {code:?}"),
        }
    }
    assert_eq!(wins, 1);
    store
        .transition(
            session.connection_id,
            ConnectionState::Failed,
            Some(ErrorCode::TargetUnreachable),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .consume_web_session(session.session_id, &session.ws_token, &identity)
            .await,
        Err(ErrorCode::TicketUsed)
    ));
    let ssh = store
        .issue_ticket(&identity, request.clone(), gateway, Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        store
            .consume_web_session(ssh.ticket_id, &ssh.ticket_secret, &identity)
            .await,
        Err(ErrorCode::TicketInvalid)
    ));
    let ssh_connection = store
        .consume_ticket(ssh.ticket_id, &ssh.ticket_secret)
        .await
        .unwrap();
    assert_eq!(ssh_connection.transport, TicketTransport::Ssh);
    store
        .transition(ssh_connection.id, ConnectionState::Failed, None)
        .await
        .unwrap();

    // Even database writers cannot mismatch ticket and connection transport.
    let check = issue().await.unwrap();
    for statement in [
        "UPDATE connection_tickets SET transport='http' WHERE id=$1",
        "UPDATE connection_tickets SET protocol_version=2 WHERE id=$1",
    ] {
        assert!(sqlx::query(statement)
            .bind(check.session_id)
            .execute(&store.pool)
            .await
            .is_err());
    }
    let mut mismatch = store.pool.begin().await.unwrap();
    sqlx::query("UPDATE connections SET transport='ssh' WHERE id=$1")
        .bind(check.connection_id)
        .execute(&mut *mismatch)
        .await
        .unwrap();
    assert!(mismatch.commit().await.is_err());
    assert!(
        sqlx::query("UPDATE login_sessions SET client_type='other' WHERE id=$1")
            .bind(identity.login_session_id)
            .execute(&store.pool)
            .await
            .is_err()
    );
    store
        .request_disconnect(&identity, check.connection_id, Uuid::new_v4())
        .await
        .unwrap();

    // Projection timestamps taken before a row lock wait are not sufficient.
    for expiry in ["ticket", "grant", "login"] {
        let session = issue().await.unwrap();
        match expiry {
            "ticket" => {
                sqlx::query("UPDATE connection_tickets SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1").bind(session.session_id).execute(&store.pool).await.unwrap();
            }
            "grant" => {
                sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1").bind(grant.id).execute(&store.pool).await.unwrap();
            }
            _ => {
                sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1").bind(identity.login_session_id).execute(&store.pool).await.unwrap();
            }
        }
        let mut lock = store.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM connection_tickets WHERE id=$1 FOR UPDATE")
            .bind(session.session_id)
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        let consumer = store.clone();
        let owner = identity.clone();
        let waiting = tokio::spawn(async move {
            consumer
                .consume_web_session(session.session_id, &session.ws_token, &owner)
                .await
        });
        tokio::time::sleep(Duration::from_millis(1000)).await;
        lock.commit().await.unwrap();
        let expected = match expiry {
            "ticket" => ErrorCode::TicketExpired,
            "grant" => ErrorCode::PermissionDenied,
            _ => ErrorCode::LoginSessionRevoked,
        };
        assert!(matches!(waiting.await.unwrap(), Err(code) if code == expected));
        if expiry == "grant" {
            sqlx::query("UPDATE grants SET expires_at=NULL WHERE id=$1")
                .bind(grant.id)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        if expiry == "login" {
            sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()+interval '7 days' WHERE id=$1").bind(identity.login_session_id).execute(&store.pool).await.unwrap();
        }
    }
    // Active authorization must re-read deadlines after its connection-row lock wait.
    for login_deadline in [false, true] {
        let session = issue().await.unwrap();
        let connection = store
            .consume_web_session(session.session_id, &session.ws_token, &identity)
            .await
            .unwrap();
        store
            .transition(connection.id, ConnectionState::Active, None)
            .await
            .unwrap();
        store.authorize_connection(&connection).await.unwrap();
        if login_deadline {
            sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1")
                .bind(identity.login_session_id).execute(&store.pool).await.unwrap();
        } else {
            sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1")
                .bind(grant.id).execute(&store.pool).await.unwrap();
        }
        // This deliberately external fixture transaction holds only the connection
        // row; it never asks for a policy/identity lock in the opposite order.
        let mut lock = store.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM connections WHERE id=$1 FOR UPDATE")
            .bind(connection.id)
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        let checker = store.clone();
        let active = connection.clone();
        let waiting = tokio::spawn(async move { checker.authorize_connection(&active).await });
        tokio::time::sleep(Duration::from_millis(1000)).await;
        lock.commit().await.unwrap();
        let expected = if login_deadline {
            ErrorCode::LoginSessionRevoked
        } else {
            ErrorCode::PermissionDenied
        };
        assert!(matches!(waiting.await.unwrap(), Err(code) if code == expected));
        if login_deadline {
            sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()+interval '7 days' WHERE id=$1")
                .bind(identity.login_session_id).execute(&store.pool).await.unwrap();
        } else {
            sqlx::query("UPDATE grants SET expires_at=NULL WHERE id=$1")
                .bind(grant.id)
                .execute(&store.pool)
                .await
                .unwrap();
        }
        store.authorize_connection(&connection).await.unwrap();
        store
            .transition(connection.id, ConnectionState::Failed, Some(expected))
            .await
            .unwrap();
    }
    // Configuration revisions are checked at consumption, not only issuance.
    let stale = issue().await.unwrap();
    let mut change = store.pool.begin().await.unwrap();
    sqlx::query("SELECT policy_revision FROM server_settings WHERE singleton FOR UPDATE")
        .fetch_one(&mut *change)
        .await
        .unwrap();
    sqlx::query("UPDATE target_accounts SET config_revision=config_revision+1 WHERE id=$1")
        .bind(fixture.account_id)
        .execute(&mut *change)
        .await
        .unwrap();
    change.commit().await.unwrap();
    assert!(matches!(
        store
            .consume_web_session(stale.session_id, &stale.ws_token, &identity)
            .await,
        Err(ErrorCode::TicketStale)
    ));

    let revoked = issue().await.unwrap();
    store
        .revoke_grant(&administrator, grant.id, grant.revision, Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        store
            .consume_web_session(revoked.session_id, &revoked.ws_token, &identity)
            .await,
        Err(ErrorCode::TicketStale)
    ));
    let replacement = store
        .create_grant(
            &administrator,
            user.id,
            fixture.asset_id,
            fixture.account_id,
            &[Capability::Shell],
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let logged_out = issue().await.unwrap();
    store
        .logout(&identity, false, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store
        .consume_web_session(logged_out.session_id, &logged_out.ws_token, &identity)
        .await
        .is_err());
    let row = sqlx::query("SELECT t.state AS ticket_state,c.state AS connection_state FROM connection_tickets t JOIN connections c ON c.ticket_id=t.id WHERE t.id=$1").bind(logged_out.session_id).fetch_one(&store.pool).await.unwrap();
    assert_eq!(row.get::<String, _>("ticket_state"), "revoked");
    assert_eq!(row.get::<String, _>("connection_state"), "revoked");
    store
        .revoke_grant(
            &administrator,
            replacement.id,
            replacement.revision,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    // Correct-domain refresh remains available; replay revokes only that family.
    let rotated = store
        .refresh_web(&other_login.refresh_token, Uuid::new_v4())
        .await
        .unwrap();
    store.authenticate_web(&rotated.access_token).await.unwrap();
    assert!(matches!(
        store
            .refresh_web(&other_login.refresh_token, Uuid::new_v4())
            .await,
        Err(ErrorCode::LoginSessionRevoked)
    ));
    store.authenticate(&bearer.access_token).await.unwrap();
}
