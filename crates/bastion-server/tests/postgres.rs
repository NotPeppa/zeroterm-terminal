//! Opt-in PostgreSQL acceptance. Only an explicitly named disposable schema-2 DB is used.
use bastion_domain::{Display, ErrorCode, Role, SessionRequest, TargetProtocol};
use bastion_secrets::{hash_password, read_secret_file, KeyRing, Secret};
use bastion_store::{AccountCreate, AccountUpdate, AssetCreate, AssetUpdate, PgStore};
use sqlx::Connection as _;
use std::collections::BTreeMap;
use uuid::Uuid;
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;

#[tokio::test]
#[ignore = "requires BASTION_GUAC_TEST_DB_URL_FILE for a disposable zt_guac_v2_* PostgreSQL database"]
async fn browser_ticket_races_snapshots_none_credentials_and_revocation() {
    let url = if std::env::var("BASTION_TEST_FIXTURE_STDIN").as_deref() == Ok("1") {
        pg_fixture::load::<serde_json::Value>().1
    } else {
        let file = std::env::var("BASTION_GUAC_TEST_DB_URL_FILE")
            .expect("explicit disposable DB URL file required");
        read_secret_file(std::path::Path::new(&file)).unwrap()
    };
    let mut probe = sqlx::PgConnection::connect(url.expose().trim())
        .await
        .unwrap();
    let name: String = sqlx::query_scalar("SELECT current_database()")
        .fetch_one(&mut probe)
        .await
        .unwrap();
    assert!(
        name.starts_with("zt_guac_v2_"),
        "refusing a non-disposable DB"
    );
    let store = PgStore::connect(url.expose().trim(), "guac-v2-tests", "main")
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store.check_identity().await.unwrap();
    let phc = hash_password("isolated acceptance password").unwrap();
    let user = store
        .bootstrap_admin("guac-admin", &phc, Uuid::new_v4())
        .await
        .unwrap();
    let login = store
        .login_web(&user, &phc, "integration", Uuid::new_v4())
        .await
        .unwrap();
    let admin = store.authenticate_web(&login.access_token).await.unwrap();
    let root = tempfile::tempdir().unwrap();
    let kek_file = root.path().join("kek-v1");
    std::fs::write(&kek_file, Secret::random().expose()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&kek_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let keys = KeyRing::from_files(1, &BTreeMap::from([(1, kek_file)])).unwrap();
    let asset = store
        .create_asset(
            &admin,
            &AssetCreate {
                group_id: None,
                name: "trusted VNC fixture".into(),
                host: "10.20.30.40".into(),
                port: 5900,
                tags: vec![],
                protocol: TargetProtocol::Vnc,
                security: None,
                ssh_host_key: None,
                rdp_certificate_sha256: None,
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let account = store
        .create_account(
            &admin,
            asset.id,
            &AccountCreate {
                label: "none fixture".into(),
                username: None,
                domain: None,
                credential: bastion_secrets::Credential::None,
            },
            &keys,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(account.credential_kind, "none");
    assert_eq!(account.credential_revision, None);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM credentials")
        .fetch_one(&mut probe)
        .await
        .unwrap();
    assert_eq!(
        count, 0,
        "VNC none must not create an encrypted dummy credential"
    );
    assert_eq!(store.accounts(asset.id).await.unwrap().len(), 1);
    let request = SessionRequest {
        asset_id: asset.id,
        account_id: account.id,
        display: Display::default(),
    };
    let ticket = store
        .issue_web_session(&admin, request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(ticket.stream_protocol, "bastion.guac.v1");
    assert_eq!(ticket.target_protocol, TargetProtocol::Vnc);
    assert!(store
        .consume_web_session(ticket.session_id, "wrong", &admin)
        .await
        .is_err());
    let (a, b) = tokio::join!(
        store.consume_web_session(ticket.session_id, &ticket.ws_token, &admin),
        store.consume_web_session(ticket.session_id, &ticket.ws_token, &admin)
    );
    assert_ne!(
        a.is_ok(),
        b.is_ok(),
        "exactly one concurrent consumer must win"
    );
    let connection = a.or(b).unwrap();
    let snapshot = store.target_snapshot(&connection).await.unwrap();
    assert!(snapshot.credential.is_none() && snapshot.context.is_none());
    assert!(store
        .consume_web_session(ticket.session_id, &ticket.ws_token, &admin)
        .await
        .is_err());
    let updated = store
        .update_account(
            &admin,
            account.id,
            account.revision,
            &AccountUpdate {
                label: Some("renamed".into()),
                ..Default::default()
            },
            &keys,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    store.authorize_connection(&connection).await.unwrap();
    let renamed = store
        .update_asset(
            &admin,
            asset.id,
            asset.revision,
            &AssetUpdate {
                name: Some("metadata-only".into()),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    store.authorize_connection(&connection).await.unwrap();
    let protected = store
        .update_account(
            &admin,
            account.id,
            updated.revision,
            &AccountUpdate {
                credential: Some(bastion_secrets::Credential::Password {
                    password: "fixture".into(),
                }),
                ..Default::default()
            },
            &keys,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(store.authorize_connection(&connection).await.is_err());
    assert!(
        store.target_snapshot(&connection).await.is_err(),
        "rotation cannot substitute a current secret into an old connection"
    );
    let ticket = store
        .issue_web_session(&admin, request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    let other = store
        .login_web(&user, &phc, "other device", Uuid::new_v4())
        .await
        .unwrap();
    let other_identity = store.authenticate_web(&other.access_token).await.unwrap();
    assert!(store
        .consume_web_session(ticket.session_id, &ticket.ws_token, &other_identity)
        .await
        .is_err());
    assert!(
        store
            .consume_web_session(ticket.session_id, &ticket.ws_token, &admin)
            .await
            .is_ok(),
        "a wrong login cannot burn the real ticket"
    );
    let expired = store
        .issue_web_session(&admin, request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    sqlx::query("UPDATE connection_tickets SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(expired.session_id).execute(&mut probe).await.unwrap();
    assert_eq!(
        store
            .consume_web_session(expired.session_id, &expired.ws_token, &admin)
            .await
            .unwrap_err(),
        ErrorCode::TicketExpired
    );
    let pending = store
        .issue_web_session(&admin, request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    store
        .update_asset(
            &admin,
            asset.id,
            renamed.revision,
            &AssetUpdate {
                host: Some("10.20.30.41".into()),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(store
        .consume_web_session(pending.session_id, &pending.ws_token, &admin)
        .await
        .is_err());
    // Role-based authorization is exact-account, not a hidden shell/exec capability bundle.
    let operator = store
        .create_user(
            &admin,
            "guac-operator",
            &phc,
            Role::Operator,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let session = store
        .login_web(&operator, &phc, "operator", Uuid::new_v4())
        .await
        .unwrap();
    let operator = store.authenticate_web(&session.access_token).await.unwrap();
    assert!(store
        .issue_web_session(&operator, request.clone(), Uuid::new_v4())
        .await
        .is_err());
    let grant = store
        .create_grant(
            &admin,
            operator.user.id,
            asset.id,
            account.id,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let operator_ticket = store
        .issue_web_session(&operator, request.clone(), Uuid::new_v4())
        .await
        .unwrap();
    let operator_connection = store
        .consume_web_session(
            operator_ticket.session_id,
            &operator_ticket.ws_token,
            &operator,
        )
        .await
        .unwrap();
    store
        .revoke_grant(&admin, grant.id, grant.revision, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store
        .authorize_connection(&operator_connection)
        .await
        .is_err());
    store
        .revoke_device_session(&admin, admin.login_session_id, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store.authenticate_web(&login.access_token).await.is_err());
    assert!(store.authorize_connection(&connection).await.is_err());
    assert_eq!(
        store.account(account.id).await.unwrap().credential_revision,
        protected.credential_revision
    );
    let old: i64 = sqlx::query_scalar("SELECT count(*) FROM information_schema.tables WHERE table_schema=current_schema() AND table_name IN ('channels','copy_jobs','asset_host_keys')")
        .fetch_one(&mut probe).await.unwrap();
    assert_eq!(old, 0);
}
