//! Explicit disposable schema2 PostgreSQL policy regression; no target-network access.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_store::{Collection, PageRequest, PgStore};
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;
#[derive(Deserialize)]
struct Fixture {
    server_id: String,
    gateway_id: String,
    username: String,
    asset_id: Uuid,
    account_id: Uuid,
}
fn request(f: &Fixture) -> SessionRequest {
    SessionRequest {
        asset_id: f.asset_id,
        account_id: f.account_id,
        display: Display::default(),
    }
}
async fn identity(store: &PgStore, root: &Identity, phc: &str, role: Role) -> Identity {
    let user = store
        .create_user(
            root,
            &format!("policy-{}", Uuid::new_v4().simple()),
            phc,
            role,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let login = store
        .login_web(&user, phc, "policy browser", Uuid::new_v4())
        .await
        .unwrap();
    store.authenticate_web(&login.access_token).await.unwrap()
}
async fn issue(
    store: &PgStore,
    who: &Identity,
    f: &Fixture,
) -> Result<WebSessionResponse, ErrorCode> {
    store
        .issue_web_session(who, request(f), Uuid::new_v4())
        .await
}
async fn connect(store: &PgStore, who: &Identity, f: &Fixture) -> Connection {
    let ticket = issue(store, who, f).await.unwrap();
    store
        .consume_web_session(ticket.session_id, &ticket.ws_token, who)
        .await
        .unwrap()
}
async fn page(store: &PgStore, who: &Identity, collection: Collection) -> Value {
    store
        .list_page(
            who,
            collection,
            PageRequest {
                limit: Some(200),
                ..Default::default()
            },
        )
        .await
        .unwrap()
}
fn contains(page: &Value, id: Uuid) -> bool {
    page["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["id"] == json!(id))
}
async fn end(store: &PgStore, c: &Connection) {
    store
        .transition(c.id, ConnectionState::Failed, None)
        .await
        .unwrap();
}
#[tokio::test]
#[ignore = "requires disposable zt-guac-v2- PostgreSQL fixture"]
async fn pending_ssh_trust_confirmation_revision_and_revocation() {
    use bastion_store::{AssetCreate, AssetUpdate};
    let (f, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &f.server_id, &f.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (user, phc) = store.login_candidate(&f.username).await.unwrap().unwrap();
    let login = store
        .login_web(&user, &phc, "SSH confirmation regression", Uuid::new_v4())
        .await
        .unwrap();
    let admin = store.authenticate_web(&login.access_token).await.unwrap();
    let pending = store
        .create_asset(
            &admin,
            &AssetCreate {
                group_id: None,
                name: "pending SSH trust".into(),
                host: "127.0.0.1".into(),
                port: 22,
                tags: vec![],
                protocol: TargetProtocol::Ssh,
                security: None,
                ssh_host_key: None,
                rdp_certificate_sha256: None,
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(pending.ssh_host_key.is_none());
    // Policy-only fixture: no credential is submitted and no network is used.
    let account = Uuid::new_v4();
    sqlx::query("INSERT INTO target_accounts(id,asset_id,label,username) VALUES($1,$2,'policy-only','fixture')")
        .bind(account).bind(pending.id).execute(&store.pool).await.unwrap();
    let request = || SessionRequest {
        asset_id: pending.id,
        account_id: account,
        display: Display::default(),
    };
    assert_eq!(
        store
            .issue_web_session(&admin, request(), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::TargetHostKeyUnknown)
    );
    let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZbpRJIMtxDOgmfuMBMjqc0KTjiTRG/H/N/jegwxgxg";
    let approval = AssetUpdate {
        ssh_host_key: Some(Some(key.into())),
        ..Default::default()
    };
    let edited = store
        .update_asset(
            &admin,
            pending.id,
            pending.revision,
            &AssetUpdate {
                host: Some("localhost".into()),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(
        store
            .update_asset(
                &admin,
                pending.id,
                pending.revision,
                &approval,
                Uuid::new_v4()
            )
            .await
            .err(),
        Some(ErrorCode::RevisionConflict)
    );
    let approved = store
        .update_asset(
            &admin,
            pending.id,
            edited.revision,
            &approval,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(approved.ssh_host_key.as_deref(), Some(key));
    store.migrate().await.unwrap();
    assert_eq!(
        store
            .asset(pending.id)
            .await
            .unwrap()
            .ssh_host_key
            .as_deref(),
        Some(key)
    );
    let ticket = store
        .issue_web_session(&admin, request(), Uuid::new_v4())
        .await
        .unwrap();
    let cleared = store
        .update_asset(
            &admin,
            pending.id,
            approved.revision,
            &AssetUpdate {
                ssh_host_key: Some(None),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(cleared.ssh_host_key.is_none());
    assert_eq!(
        store
            .consume_web_session(ticket.session_id, &ticket.ws_token, &admin)
            .await
            .err(),
        Some(ErrorCode::TicketStale)
    );
    assert_eq!(
        store
            .issue_web_session(&admin, request(), Uuid::new_v4())
            .await
            .err(),
        Some(ErrorCode::TargetHostKeyUnknown)
    );
    store.pool.close().await;
}
#[tokio::test]
#[ignore = "requires BASTION_GUAC_STORE_FIXTURE or stdin: disposable zt-guac-v2- PostgreSQL schema2 owner fixture; no database is bundled"]
async fn implicit_admin_exact_grants_owner_isolation_and_live_revocation() {
    let (f, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &f.server_id, &f.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (user, phc) = store.login_candidate(&f.username).await.unwrap().unwrap();
    let login = store
        .login_web(&user, &phc, "policy root", Uuid::new_v4())
        .await
        .unwrap();
    let root = store.authenticate_web(&login.access_token).await.unwrap();
    let admin = identity(&store, &root, &phc, Role::Admin).await;
    let operator = identity(&store, &root, &phc, Role::Operator).await;
    let other = identity(&store, &root, &phc, Role::Operator).await;
    let auditor = identity(&store, &root, &phc, Role::Auditor).await;
    assert_eq!(
        issue(&store, &operator, &f).await.err(),
        Some(ErrorCode::PermissionDenied)
    );
    assert_eq!(
        issue(&store, &auditor, &f).await.err(),
        Some(ErrorCode::PermissionDenied)
    );
    let assets = page(&store, &admin, Collection::Assets).await;
    assert!(contains(&assets, f.asset_id));
    let asset = assets["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|asset| asset["id"] == f.asset_id.to_string())
        .unwrap();
    let account = asset["accounts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|account| account["id"] == f.account_id.to_string())
        .unwrap();
    assert_eq!(account["credential_kind"], "none");
    assert!(account["username"].is_null() && account["domain"].is_null());
    for secret in ["password", "ciphertext", "wrapped_dek", "key_pem"] {
        assert!(account.get(secret).is_none());
    }
    assert!(!contains(
        &page(&store, &operator, Collection::Assets).await,
        f.asset_id
    ));
    let implicit = connect(&store, &admin, &f).await;
    store.authorize_connection(&implicit).await.unwrap();
    store.target_snapshot(&implicit).await.unwrap();
    let grant = store
        .create_grant(
            &root,
            operator.user.id,
            f.asset_id,
            f.account_id,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(contains(
        &page(&store, &operator, Collection::Assets).await,
        f.asset_id
    ));
    let granted = connect(&store, &operator, &f).await;
    store.authorize_connection(&granted).await.unwrap();
    assert!(store.connection(&other, granted.id).await.is_err());
    assert!(contains(
        &page(&store, &root, Collection::Connections).await,
        granted.id
    ));
    assert!(contains(
        &page(&store, &auditor, Collection::Connections).await,
        granted.id
    ));
    assert!(!contains(
        &page(&store, &other, Collection::Connections).await,
        granted.id
    ));
    assert_eq!(
        store
            .request_disconnect(&other, granted.id, Uuid::new_v4())
            .await,
        Err(ErrorCode::ResourceNotFound)
    );
    assert_eq!(
        store
            .request_disconnect(&auditor, granted.id, Uuid::new_v4())
            .await,
        Err(ErrorCode::PermissionDenied)
    );
    let pending = issue(&store, &operator, &f).await.unwrap();
    let duplicate = store
        .create_grant(
            &root,
            operator.user.id,
            f.asset_id,
            f.account_id,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    store
        .revoke_grant(&root, grant.id, grant.revision, Uuid::new_v4())
        .await
        .unwrap();
    store.authorize_connection(&granted).await.unwrap();
    let consumed = store
        .consume_web_session(pending.session_id, &pending.ws_token, &operator)
        .await
        .unwrap();
    end(&store, &consumed).await;
    let invalidated = issue(&store, &operator, &f).await.unwrap();
    store
        .revoke_grant(&root, duplicate.id, duplicate.revision, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store.authorize_connection(&granted).await.is_err());
    assert_eq!(
        store
            .consume_web_session(invalidated.session_id, &invalidated.ws_token, &operator)
            .await
            .err(),
        Some(ErrorCode::TicketStale)
    );
    assert!(!contains(
        &page(&store, &operator, Collection::Assets).await,
        f.asset_id
    ));
    store.authorize_connection(&implicit).await.unwrap();
    end(&store, &granted).await;
    end(&store, &implicit).await;
    // Demotion invalidates an administrator's frozen identity even when a new grant exists.
    let frozen = issue(&store, &admin, &f).await.unwrap();
    let live = connect(&store, &admin, &f).await;
    store
        .create_grant(
            &root,
            admin.user.id,
            f.asset_id,
            f.account_id,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    store
        .update_user(
            &root,
            admin.user.id,
            admin.user.revision,
            Some(Role::Operator),
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(store.authorize_connection(&live).await.is_err());
    assert!(store
        .consume_web_session(frozen.session_id, &frozen.ws_token, &admin)
        .await
        .is_err());
    assert!(issue(&store, &admin, &f).await.is_err());
    assert!(store.assets_for(&admin).await.is_err());
    end(&store, &live).await;
    // Every runtime snapshot rechecks user/login expiry and device revocation.
    for scenario in ["disable", "logout", "expiry"] {
        let who = identity(&store, &root, &phc, Role::Admin).await;
        let live = connect(&store, &who, &f).await;
        match scenario {
            "disable" => {
                store
                    .update_user(
                        &root,
                        who.user.id,
                        who.user.revision,
                        None,
                        Some(false),
                        Uuid::new_v4(),
                    )
                    .await
                    .unwrap();
            }
            "logout" => {
                store.logout(&who, false, Uuid::new_v4()).await.unwrap();
            }
            _ => {
                sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(who.login_session_id).execute(&store.pool).await.unwrap();
            }
        }
        assert!(store.authorize_connection(&live).await.is_err());
        assert!(store.target_snapshot(&live).await.is_err());
        assert!(issue(&store, &who, &f).await.is_err());
        end(&store, &live).await;
    }
}
