//! Opt-in isolated PostgreSQL metadata checks; no target or recording-file acceptance claim.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_store::{AssetUpdate, Collection, PageRequest, PgStore};
use chrono::Utc;
use serde::Deserialize;
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
fn recording(id: Uuid) -> RecordingCreate {
    RecordingCreate {
        id,
        relative_path: format!("{id}.ztrec"),
        format_version: 2,
        retention_until: Utc::now() + chrono::Duration::days(1),
        wrapped_dek: vec![0; 48],
        wrap_nonce: vec![0; 24],
        key_version: 1,
        nonce_prefix: vec![0; 16],
    }
}
#[tokio::test]
#[ignore = "requires BASTION_GUAC_STORE_FIXTURE or stdin: disposable zt-guac-v2- PostgreSQL schema2 owner fixture; no database is bundled"]
async fn connection_recording_activation_revision_recovery_and_devices() {
    let (f, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &f.server_id, &f.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (user, phc) = store.login_candidate(&f.username).await.unwrap().unwrap();
    let login = store
        .login_web(
            &user,
            &phc,
            "connection recording regression",
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let identity = store.authenticate_web(&login.access_token).await.unwrap();
    let ticket = store
        .issue_web_session(&identity, request(&f), Uuid::new_v4())
        .await
        .unwrap();
    let asset = store.asset(f.asset_id).await.unwrap();
    let renamed = store
        .update_asset(
            &identity,
            asset.id,
            asset.revision,
            &AssetUpdate {
                name: Some(format!("metadata {}", Uuid::new_v4())),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(asset.routing_revision, renamed.routing_revision);
    let connection = store
        .consume_web_session(ticket.session_id, &ticket.ws_token, &identity)
        .await
        .unwrap();
    store.target_snapshot(&connection).await.unwrap();
    let rid = Uuid::new_v4();
    let view = store
        .create_recording(&connection, recording(rid), Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(view.connection_id, connection.id);
    assert_eq!(view.target_protocol, connection.target_protocol);
    assert_eq!(view.format_version, 2);
    assert_eq!(
        store.activate_recording(rid).await,
        Err(ErrorCode::RecordingUnavailable)
    );
    assert_eq!(
        store
            .connection(&identity, connection.id)
            .await
            .unwrap()
            .state,
        ConnectionState::Connecting
    );
    assert!(store
        .create_recording(&connection, recording(Uuid::new_v4()), Uuid::new_v4())
        .await
        .is_err());
    store.checkpoint_recording(rid, 0, 0, 100).await.unwrap();
    store.activate_recording(rid).await.unwrap();
    let filtered = store
        .list_page(
            &identity,
            Collection::Recordings,
            PageRequest {
                filter: bastion_store::ListFilter {
                    connection_id: Some(connection.id),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(filtered["items"].as_array().unwrap().len(), 1);
    assert_eq!(filtered["items"][0]["id"], rid.to_string());
    let unrelated = store
        .list_page(
            &identity,
            Collection::Recordings,
            PageRequest {
                filter: bastion_store::ListFilter {
                    connection_id: Some(Uuid::new_v4()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(unrelated["items"].as_array().unwrap().is_empty());
    assert_eq!(
        store
            .connection(&identity, connection.id)
            .await
            .unwrap()
            .state,
        ConnectionState::Active
    );
    assert_eq!(
        store
            .recording_metadata(&identity, rid)
            .await
            .unwrap()
            .state,
        RecordingState::Active
    );
    assert_eq!(
        store.checkpoint_recording(rid, -1, -1, 50).await,
        Err(ErrorCode::RecordingUnavailable)
    );
    assert_eq!(
        store.checkpoint_recording(rid, 1, 2, 100).await,
        Err(ErrorCode::InvalidArgument)
    );
    store.checkpoint_recording(rid, 1, 0, 200).await.unwrap();
    assert_eq!(
        store
            .finish_recording(
                rid,
                RecordingState::Complete,
                200,
                Some(&"a".repeat(64)),
                None
            )
            .await,
        Err(ErrorCode::RecordingUnavailable)
    );
    store.checkpoint_recording(rid, 1, 1, 200).await.unwrap();
    store
        .finish_recording(
            rid,
            RecordingState::Complete,
            200,
            Some(&"a".repeat(64)),
            None,
        )
        .await
        .unwrap();
    assert!(store
        .finish_recording(rid, RecordingState::Partial, 200, None, None)
        .await
        .is_err());
    let replay = store
        .recording_for_replay(&identity, rid, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(replay.metadata.state, RecordingState::Complete);
    assert_eq!(replay.metadata.checksum, Some("a".repeat(64)));
    let projection = store
        .list_page(&identity, Collection::Connections, PageRequest::default())
        .await
        .unwrap()
        .to_string();
    assert!(projection.contains("target_protocol"));
    assert!(!projection.contains("wrapped_dek"));
    assert!(!projection.contains("relative_path"));
    store
        .transition(connection.id, ConnectionState::Closing, None)
        .await
        .unwrap();
    store
        .transition(connection.id, ConnectionState::Closed, None)
        .await
        .unwrap();
    let next = store
        .issue_web_session(&identity, request(&f), Uuid::new_v4())
        .await
        .unwrap();
    let interrupted = store
        .consume_web_session(next.session_id, &next.ws_token, &identity)
        .await
        .unwrap();
    let partial = Uuid::new_v4();
    store
        .create_recording(&interrupted, recording(partial), Uuid::new_v4())
        .await
        .unwrap();
    store
        .checkpoint_recording(partial, 0, 0, 100)
        .await
        .unwrap();
    store.activate_recording(partial).await.unwrap();
    store.recover_gateway().await.unwrap();
    assert_eq!(
        store
            .connection(&identity, interrupted.id)
            .await
            .unwrap()
            .state,
        ConnectionState::Interrupted
    );
    assert_eq!(
        store
            .recording_metadata(&identity, partial)
            .await
            .unwrap()
            .state,
        RecordingState::Partial
    );
    assert_eq!(
        store
            .recording_metadata(&identity, rid)
            .await
            .unwrap()
            .state,
        RecordingState::Complete
    );
    let child = store
        .login_web(&user, &phc, "other browser", Uuid::new_v4())
        .await
        .unwrap();
    store
        .revoke_device_session(&identity, child.login_session_id, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store.authenticate_web(&child.access_token).await.is_err());
    assert!(store
        .device_sessions(&identity)
        .await
        .unwrap()
        .iter()
        .any(|s| s.id == identity.login_session_id && s.current));
    let schema: i32 =
        sqlx::query_scalar("SELECT schema_version FROM server_settings WHERE singleton")
            .fetch_one(&store.pool)
            .await
            .unwrap();
    assert_eq!(schema, 2);
}
