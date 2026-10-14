//! Explicitly selected disposable PostgreSQL fixture only; never use a demo database.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_secrets::hash_password;
use bastion_store::{Collection, PageRequest, PgStore};
use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
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
fn request(f: &Fixture) -> SessionRequest {
    SessionRequest {
        asset_id: f.asset_id,
        account_id: f.account_id,
        display: Display::default(),
    }
}
async fn new_user(store: &PgStore, root: &Identity, phc: &str, role: Role) -> UserView {
    store
        .create_user(
            root,
            &format!("delete-{}", Uuid::new_v4().simple()),
            phc,
            role,
            Uuid::new_v4(),
        )
        .await
        .unwrap()
}
async fn users(store: &PgStore, root: &Identity) -> Vec<Value> {
    let mut result = Vec::new();
    let mut cursor = None;
    loop {
        let page = store
            .list_page(
                root,
                Collection::Users,
                PageRequest {
                    limit: Some(2),
                    cursor,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        result.extend(page["items"].as_array().unwrap().iter().cloned());
        cursor = page["next_cursor"].as_str().map(str::to_owned);
        if cursor.is_none() {
            return result;
        }
    }
}
async fn connected(store: &PgStore, actor: &Identity, f: &Fixture) -> Connection {
    let ticket = store
        .issue_web_session(actor, request(f), Uuid::new_v4())
        .await
        .unwrap();
    store
        .consume_web_session(ticket.session_id, &ticket.ws_token, actor)
        .await
        .unwrap()
}
async fn count(store: &PgStore, sql: &str, id: Uuid) -> i64 {
    sqlx::query_scalar(sql)
        .bind(id)
        .fetch_one(&store.pool)
        .await
        .unwrap()
}

#[tokio::test]
#[ignore = "requires BASTION_GUAC_STORE_FIXTURE or stdin: disposable zt-guac-v2- PostgreSQL schema2 owner fixture; no database is bundled"]
async fn deletion_revocation_history_reuse_and_races() {
    // Only one test loads stdin, which is consumed once per test executable.
    let (f, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &f.server_id, &f.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store.migrate().await.unwrap();
    let (admin, phc) = store.login_candidate(&f.username).await.unwrap().unwrap();
    let root_login = store
        .login_web(&admin, &phc, "user deletion fixture", Uuid::new_v4())
        .await
        .unwrap();
    let root = store
        .authenticate_web(&root_login.access_token)
        .await
        .unwrap();
    let migration_count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(
        migration_count as usize,
        sqlx::migrate!("../../migrations").migrations.len()
    );
    assert!(matches!(
        store
            .delete_user(&root, root.user.id, root.user.revision, Uuid::new_v4())
            .await,
        Err(ErrorCode::PermissionDenied)
    ));
    assert!(matches!(
        store
            .delete_user(&root, Uuid::new_v4(), 1, Uuid::new_v4())
            .await,
        Err(ErrorCode::ResourceNotFound)
    ));

    let mut victim = new_user(&store, &root, &phc, Role::Operator).await;
    // A disabled but not deleted identity stays visible, reserves its name and is resettable by CLI.
    victim = store
        .update_user(
            &root,
            victim.id,
            victim.revision,
            None,
            Some(false),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(store
        .login_candidate(&victim.username)
        .await
        .unwrap()
        .is_some());
    assert!(users(&store, &root)
        .await
        .iter()
        .any(|item| item["id"] == json!(victim.id) && item["enabled"] == false));
    assert!(matches!(
        store
            .create_user(
                &root,
                &victim.username,
                &phc,
                Role::Operator,
                Uuid::new_v4()
            )
            .await,
        Err(ErrorCode::ResourceConflict)
    ));
    store
        .reset_password(None, victim.id, victim.revision, &phc, Uuid::new_v4())
        .await
        .unwrap();
    victim = store.user(victim.id).await.unwrap();
    assert!(victim.enabled);
    let secondary = store
        .login_web(&victim, &phc, "second browser victim", Uuid::new_v4())
        .await
        .unwrap();
    let other_browser = store
        .authenticate_web(&secondary.access_token)
        .await
        .unwrap();
    let web = store
        .login_web(&victim, &phc, "web victim", Uuid::new_v4())
        .await
        .unwrap();
    let browser = store.authenticate_web(&web.access_token).await.unwrap();
    assert!(matches!(
        store
            .delete_user(&other_browser, admin.id, admin.revision, Uuid::new_v4())
            .await,
        Err(ErrorCode::PermissionDenied)
    ));
    assert!(matches!(
        store
            .delete_user(&root, victim.id, victim.revision - 1, Uuid::new_v4())
            .await,
        Err(ErrorCode::RevisionConflict)
    ));
    assert!(store.user(victim.id).await.unwrap().enabled);
    let grant = store
        .create_grant(
            &root,
            victim.id,
            f.asset_id,
            f.account_id,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let pending = store
        .issue_web_session(&browser, request(&f), Uuid::new_v4())
        .await
        .unwrap();
    let connecting = connected(&store, &browser, &f).await;
    let active = connected(&store, &browser, &f).await;
    let recording = Uuid::new_v4();
    store
        .create_recording(
            &active,
            RecordingCreate {
                id: recording,
                relative_path: format!("{recording}.ztrec"),
                format_version: 2,
                retention_until: Utc::now() + chrono::Duration::days(1),
                wrapped_dek: vec![0; 48],
                wrap_nonce: vec![0; 24],
                key_version: 1,
                nonce_prefix: vec![0; 16],
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    store
        .checkpoint_recording(recording, 0, 0, 100)
        .await
        .unwrap();
    store.activate_recording(recording).await.unwrap();
    store
        .checkpoint_recording(recording, 1, 1, 200)
        .await
        .unwrap();
    store
        .finish_recording(
            recording,
            RecordingState::Complete,
            200,
            Some(&"a".repeat(64)),
            None,
        )
        .await
        .unwrap();
    let unaffected = store
        .issue_web_session(&root, request(&f), Uuid::new_v4())
        .await
        .unwrap();
    let policy = store.policy_revision().await.unwrap();
    let old_audits = count(
        &store,
        "SELECT count(*) FROM audit_events WHERE actor_id=$1",
        victim.id,
    )
    .await;

    // An audit write failure must roll back the tombstone, revocation and connection changes.
    sqlx::query("CREATE FUNCTION fixture_reject_user_delete() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='user.deleted' THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END $$").execute(&store.pool).await.unwrap();
    sqlx::query("CREATE TRIGGER fixture_reject_user_delete BEFORE INSERT ON audit_events FOR EACH ROW EXECUTE FUNCTION fixture_reject_user_delete()").execute(&store.pool).await.unwrap();
    let failed = store
        .delete_user(&root, victim.id, victim.revision, Uuid::new_v4())
        .await;
    sqlx::query("DROP TRIGGER fixture_reject_user_delete ON audit_events")
        .execute(&store.pool)
        .await
        .unwrap();
    sqlx::query("DROP FUNCTION fixture_reject_user_delete()")
        .execute(&store.pool)
        .await
        .unwrap();
    assert!(failed.is_err());
    assert_eq!(
        store.user(victim.id).await.unwrap().revision,
        victim.revision
    );
    store
        .authenticate_web(&secondary.access_token)
        .await
        .unwrap();
    assert_eq!(
        store.connection(&root, active.id).await.unwrap().state,
        ConnectionState::Active
    );
    // The shared policy lock enforces the existing bounded transaction budget without partial deletion.
    let mut lock = store.pool.begin().await.unwrap();
    sqlx::query("SELECT policy_revision FROM server_settings WHERE singleton FOR UPDATE")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let timeout = store
        .delete_user(&root, victim.id, victim.revision, Uuid::new_v4())
        .await;
    lock.rollback().await.unwrap();
    assert!(matches!(timeout, Err(ErrorCode::PolicyStoreUnavailable)));
    assert_eq!(
        store.user(victim.id).await.unwrap().revision,
        victim.revision
    );

    let delete_request = Uuid::new_v4();
    store
        .delete_user(&root, victim.id, victim.revision, delete_request)
        .await
        .unwrap();
    assert_eq!(
        store.policy_revision().await.unwrap(),
        policy,
        "unrelated users' tickets must not become policy-stale"
    );
    let unaffected_connection = store
        .consume_web_session(unaffected.session_id, &unaffected.ws_token, &root)
        .await
        .unwrap();
    store
        .transition(unaffected_connection.id, ConnectionState::Failed, None)
        .await
        .unwrap();
    assert!(!users(&store, &root)
        .await
        .iter()
        .any(|item| item["id"] == json!(victim.id)));
    assert!(!store
        .users()
        .await
        .unwrap()
        .iter()
        .any(|item| item.id == victim.id));
    assert!(matches!(
        store.user(victim.id).await,
        Err(ErrorCode::ResourceNotFound)
    ));
    assert!(store
        .login_candidate(&victim.username)
        .await
        .unwrap()
        .is_none());
    assert!(store
        .login_web(&victim, &phc, "old verified candidate", Uuid::new_v4())
        .await
        .is_err());
    assert!(store
        .authenticate_web(&secondary.access_token)
        .await
        .is_err());
    assert!(store.authenticate_web(&web.access_token).await.is_err());
    assert!(store
        .refresh_web(&secondary.refresh_token, Uuid::new_v4())
        .await
        .is_err());
    assert!(store
        .refresh_web(&web.refresh_token, Uuid::new_v4())
        .await
        .is_err());
    assert!(store
        .issue_web_session(&browser, request(&f), Uuid::new_v4())
        .await
        .is_err());
    assert!(store
        .consume_web_session(pending.session_id, &pending.ws_token, &browser)
        .await
        .is_err());
    assert!(store.authorize_connection(&active).await.is_err());
    for id in [pending.connection_id] {
        assert_eq!(
            store.connection(&root, id).await.unwrap().state,
            ConnectionState::Revoked
        );
    }
    for id in [connecting.id, active.id] {
        assert_eq!(
            store.connection(&root, id).await.unwrap().state,
            ConnectionState::Closing
        );
    }
    assert_eq!(
        store
            .recording_metadata(&root, recording)
            .await
            .unwrap()
            .state,
        RecordingState::Complete
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM audit_events WHERE actor_id=$1",
            victim.id
        )
        .await,
        old_audits + 2
    );
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM audit_events WHERE actor_id=$1 AND action='user.refresh_replay'",
            victim.id
        )
        .await,
        2
    );
    let deletion = sqlx::query("SELECT request_id,sanitized_payload FROM audit_events WHERE action='user.deleted' AND resource_id=$1").bind(victim.id).fetch_one(&store.pool).await.unwrap();
    assert_eq!(deletion.get::<Uuid, _>("request_id"), delete_request);
    let payload = deletion.get::<Value, _>("sanitized_payload").to_string();
    for secret in [
        &phc,
        &secondary.access_token,
        &secondary.refresh_token,
        &web.access_token,
        &web.refresh_token,
    ] {
        assert!(!payload.contains(secret));
    }
    let tombstone =
        sqlx::query("SELECT username,enabled,auth_revision,deleted_at FROM users WHERE id=$1")
            .bind(victim.id)
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(tombstone.get::<String, _>("username"), victim.username);
    assert!(!tombstone.get::<bool, _>("enabled"));
    assert_eq!(
        tombstone.get::<i64, _>("auth_revision"),
        victim.revision + 1
    );
    assert!(tombstone
        .get::<Option<chrono::DateTime<Utc>>, _>("deleted_at")
        .is_some());
    assert!(sqlx::query("UPDATE users SET enabled=true WHERE id=$1")
        .bind(victim.id)
        .execute(&store.pool)
        .await
        .is_err());
    for revision in [victim.revision, victim.revision + 1] {
        assert!(matches!(
            store
                .update_user(&root, victim.id, revision, None, Some(true), Uuid::new_v4())
                .await,
            Err(ErrorCode::ResourceNotFound)
        ));
        for actor in [Some(&root), None] {
            assert!(matches!(
                store
                    .reset_password(actor, victim.id, revision, &phc, Uuid::new_v4())
                    .await,
                Err(ErrorCode::ResourceNotFound)
            ));
        }
        assert!(matches!(
            store
                .delete_user(&root, victim.id, revision, Uuid::new_v4())
                .await,
            Err(ErrorCode::ResourceNotFound)
        ));
    }
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM audit_events WHERE action='user.deleted' AND resource_id=$1",
            victim.id
        )
        .await,
        1
    );
    assert!(matches!(
        store
            .create_grant(
                &root,
                victim.id,
                f.asset_id,
                f.account_id,
                None,
                Uuid::new_v4()
            )
            .await,
        Err(ErrorCode::ResourceNotFound)
    ));
    assert!(matches!(
        store
            .update_grant(
                &root,
                grant.id,
                grant.revision,
                Some(true),
                None,
                Uuid::new_v4()
            )
            .await,
        Err(ErrorCode::ResourceNotFound)
    ));
    assert!(matches!(
        store
            .update_grant(
                &root,
                grant.id,
                grant.revision,
                None,
                Some(Some(Utc::now() + chrono::Duration::days(1))),
                Uuid::new_v4()
            )
            .await,
        Err(ErrorCode::ResourceNotFound)
    ));
    let revoked = store
        .update_grant(
            &root,
            grant.id,
            grant.revision,
            Some(false),
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(!revoked.enabled);

    let new_phc = hash_password("new-account-password-at-least-twelve").unwrap();
    let (a, b) = tokio::join!(
        store.create_user(
            &root,
            &victim.username,
            &new_phc,
            Role::Operator,
            Uuid::new_v4()
        ),
        store.create_user(
            &root,
            &victim.username,
            &new_phc,
            Role::Operator,
            Uuid::new_v4()
        )
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let replacement = match (a, b) {
        (Ok(user), Err(ErrorCode::ResourceConflict))
        | (Err(ErrorCode::ResourceConflict), Ok(user)) => user,
        other => panic!("unexpected same-name race: {other:?}"),
    };
    assert_ne!(replacement.id, victim.id);
    assert_eq!(replacement.revision, 1);
    let candidate = store
        .login_candidate(&victim.username)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(candidate.0.id, replacement.id);
    assert_eq!(candidate.1, new_phc);
    assert!(store
        .login_web(&replacement, &phc, "old password", Uuid::new_v4())
        .await
        .is_err());
    let replacement_login = store
        .login_web(&replacement, &new_phc, "new identity", Uuid::new_v4())
        .await
        .unwrap();
    let replacement_actor = store
        .authenticate_web(&replacement_login.access_token)
        .await
        .unwrap();
    for table in ["grants", "connections", "connection_tickets"] {
        assert_eq!(
            count(
                &store,
                &format!("SELECT count(*) FROM {table} WHERE user_id=$1"),
                replacement.id
            )
            .await,
            0
        );
    }
    assert_eq!(
        count(
            &store,
            "SELECT count(*) FROM login_sessions WHERE user_id=$1",
            replacement.id
        )
        .await,
        1
    );
    assert!(store
        .issue_web_session(&replacement_actor, request(&f), Uuid::new_v4())
        .await
        .is_err());
    assert!(store
        .recording_metadata(&replacement_actor, recording)
        .await
        .is_err());
    assert_eq!(
        store.connection(&root, active.id).await.unwrap().user_id,
        Some(victim.id)
    );

    // Concurrent deletion/edit: only one original revision may succeed, and the losing operation is explicit.
    let racer = new_user(&store, &root, &phc, Role::Operator).await;
    let (deleted, edited) = tokio::join!(
        store.delete_user(&root, racer.id, racer.revision, Uuid::new_v4()),
        store.update_user(
            &root,
            racer.id,
            racer.revision,
            None,
            Some(false),
            Uuid::new_v4()
        )
    );
    assert_eq!(
        usize::from(deleted.is_ok()) + usize::from(edited.is_ok()),
        1
    );
    match (deleted, edited) {
        (Ok(()), Err(ErrorCode::ResourceNotFound)) => {}
        (Err(ErrorCode::RevisionConflict), Ok(changed)) => store
            .delete_user(&root, changed.id, changed.revision, Uuid::new_v4())
            .await
            .unwrap(),
        other => panic!("unexpected delete/edit race: {other:?}"),
    }
    let racer = new_user(&store, &root, &phc, Role::Operator).await;
    let (deleted, reset) = tokio::join!(
        store.delete_user(&root, racer.id, racer.revision, Uuid::new_v4()),
        store.reset_password(None, racer.id, racer.revision, &new_phc, Uuid::new_v4())
    );
    assert_eq!(usize::from(deleted.is_ok()) + usize::from(reset.is_ok()), 1);
    match (deleted, reset) {
        (Ok(()), Err(ErrorCode::ResourceNotFound)) => {}
        (Err(ErrorCode::RevisionConflict), Ok(())) => store
            .delete_user(&root, racer.id, racer.revision + 1, Uuid::new_v4())
            .await
            .unwrap(),
        other => panic!("unexpected delete/reset race: {other:?}"),
    }

    // Two admins cannot use stale request identities to delete one another after the first commit.
    let a = new_user(&store, &root, &phc, Role::Admin).await;
    let b = new_user(&store, &root, &phc, Role::Admin).await;
    let a_login = store
        .login_web(&a, &phc, "admin a", Uuid::new_v4())
        .await
        .unwrap();
    let b_login = store
        .login_web(&b, &phc, "admin b", Uuid::new_v4())
        .await
        .unwrap();
    let a_actor = store.authenticate_web(&a_login.access_token).await.unwrap();
    let b_actor = store.authenticate_web(&b_login.access_token).await.unwrap();
    let (left, right) = tokio::join!(
        store.delete_user(&a_actor, b.id, b.revision, Uuid::new_v4()),
        store.delete_user(&b_actor, a.id, a.revision, Uuid::new_v4())
    );
    assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
    assert!(matches!(
        (left, right),
        (Ok(()), Err(ErrorCode::UserDisabled)) | (Err(ErrorCode::UserDisabled), Ok(()))
    ));
    store
        .authenticate_web(&root_login.access_token)
        .await
        .unwrap();
    println!("user deletion: migration, rollback, revocation, history, name reuse and concurrent identity guards passed");
}
