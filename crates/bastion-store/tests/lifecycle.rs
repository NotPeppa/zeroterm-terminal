//! Isolated PostgreSQL regression checks; never contacts a DB unless explicitly selected.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_store::{Collection, PageRequest, PgStore};
use chrono::Utc;
use serde::Deserialize;
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
#[tokio::test]
#[ignore = "requires isolated PostgreSQL and protected BASTION_M1_FIXTURE"]
async fn channel_recording_projection_revision_and_recovery() {
    let (f, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &f.server_id, &f.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (user, phc) = store.login_candidate(&f.username).await.unwrap().unwrap();
    let login = store
        .login_web(&user, &phc, "M3 store regression", Uuid::new_v4())
        .await
        .unwrap();
    let identity = store.authenticate_web(&login.access_token).await.unwrap();
    let grant = store
        .create_grant(
            &identity,
            user.id,
            f.asset_id,
            f.account_id,
            &[Capability::Shell, Capability::Exec, Capability::Sftp],
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let ticket = store
        .issue_web_session(
            &identity,
            TicketRequest {
                asset_id: f.asset_id,
                account_id: f.account_id,
                capabilities: vec![Capability::Shell],
                purpose: Purpose::Terminal,
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    // Metadata-only updates change UI revision but preserve routing authorization.
    let asset = store.asset(f.asset_id).await.unwrap();
    let changed = store
        .update_asset(
            &identity,
            asset.id,
            asset.revision,
            Some(&format!("M3 {}", Uuid::new_v4())),
            None,
            None,
            None,
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(asset.routing_revision, changed.routing_revision);
    let connection = store
        .consume_web_session(ticket.session_id, &ticket.ws_token, &identity)
        .await
        .unwrap();
    store
        .transition(connection.id, ConnectionState::Active, None)
        .await
        .unwrap();
    let rid = Uuid::new_v4();
    let channel = store
        .begin_channel(
            &connection,
            1,
            ChannelKind::Shell,
            Some(RecordingCreate {
                id: rid,
                relative_path: format!("{rid}.ztrec"),
                format_version: 1,
                retention_until: Utc::now() + chrono::Duration::days(1),
                wrapped_dek: vec![0; 48],
                wrap_nonce: vec![0; 24],
                key_version: 1,
                nonce_prefix: vec![0; 16],
            }),
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(channel.recording_id, Some(rid));
    assert_eq!(
        store
            .transition_channel(channel.id, ChannelState::Streaming)
            .await,
        Err(ErrorCode::InvalidArgument)
    );
    store
        .transition_channel(channel.id, ChannelState::Starting)
        .await
        .unwrap();
    assert_eq!(
        store
            .transition_channel(channel.id, ChannelState::Streaming)
            .await,
        Err(ErrorCode::RecordingUnavailable)
    );
    store.activate_recording(rid).await.unwrap();
    store
        .transition_channel(channel.id, ChannelState::Streaming)
        .await
        .unwrap();
    store.checkpoint_recording(rid, 0, 0, 100).await.unwrap();
    assert_eq!(
        store.checkpoint_recording(rid, -1, -1, 50).await,
        Err(ErrorCode::RecordingUnavailable)
    );
    assert_eq!(
        store.checkpoint_recording(rid, 1, 2, 100).await,
        Err(ErrorCode::InvalidArgument)
    );
    assert!(store
        .begin_channel(&connection, 1, ChannelKind::Shell, None, Uuid::new_v4())
        .await
        .is_err());
    store
        .finish_channel_and_recording(
            channel.id,
            Some(7),
            None,
            None,
            Some(RecordingState::Complete),
            Some(&"a".repeat(64)),
        )
        .await
        .unwrap();
    // Exactly-once completion preserves exit metadata rather than overwriting it.
    store
        .finish_channel_and_recording(channel.id, Some(9), None, None, None, None)
        .await
        .unwrap();
    assert_eq!(
        store
            .channel_queries(&identity, connection.id)
            .await
            .unwrap()[0]
            .exit_code,
        Some(7)
    );
    let replay = store
        .recording_for_replay(&identity, rid, Uuid::new_v4())
        .await
        .unwrap();
    assert_eq!(replay.metadata.state, RecordingState::Complete);
    let projected = store
        .list_page(&identity, Collection::Connections, PageRequest::default())
        .await
        .unwrap();
    let public = projected.to_string();
    assert!(public.contains("protocol_version"));
    assert!(public.contains("websocket"));
    assert!(!public.contains("wrapped_dek"));
    assert!(!public.contains("relative_path"));
    let audit_count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM audit_events WHERE action='recording.viewed' AND resource_id=$1",
    )
    .bind(rid)
    .fetch_one(&store.pool)
    .await
    .unwrap();
    assert_eq!(audit_count, 1);
    let begin = store
        .begin_channel(&connection, 2, ChannelKind::Shell, None, Uuid::new_v4())
        .await
        .unwrap();
    store.recover_gateway().await.unwrap();
    assert_eq!(
        store
            .channel_queries(&identity, connection.id)
            .await
            .unwrap()
            .iter()
            .find(|c| c.id == begin.id)
            .unwrap()
            .state,
        ChannelState::Failed
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
        .login_web(&user, &phc, "other device", Uuid::new_v4())
        .await
        .unwrap();
    store
        .revoke_device_session(&identity, child.login_session_id, Uuid::new_v4())
        .await
        .unwrap();
    assert!(store.authenticate_web(&child.access_token).await.is_err());
    let devices = store.device_sessions(&identity).await.unwrap();
    assert!(devices
        .iter()
        .any(|s| s.id == identity.login_session_id && s.current));
    store
        .revoke_grant(&identity, grant.id, grant.revision, Uuid::new_v4())
        .await
        .unwrap();
    let row = sqlx::query("SELECT schema_version FROM server_settings WHERE singleton")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i32, _>("schema_version"), 1);
}
