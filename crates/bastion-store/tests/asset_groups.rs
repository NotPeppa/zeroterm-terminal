//! Isolated metadata/authorization checks; never dial a target.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::*;
use bastion_store::{
    AssetGroupCreateInput, AssetGroupPatchInput, AssetUpdate, Collection, ListFilter, PageRequest,
    PgStore,
};
use serde::Deserialize;
use serde_json::json;
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
#[tokio::test]
#[ignore = "requires disposable zt-guac-v2- PostgreSQL fixture"]
async fn group_crud_filter_revision_and_authorization() {
    let (f, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &f.server_id, &f.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    let (user, phc) = store.login_candidate(&f.username).await.unwrap().unwrap();
    let login = store
        .login_web(&user, &phc, "group regression", Uuid::new_v4())
        .await
        .unwrap();
    let admin = store.authenticate_web(&login.access_token).await.unwrap();
    let input = AssetGroupCreateInput {
        name: format!("group-{}", Uuid::new_v4()),
        parent_id: None,
        sort_order: None,
    };
    let group = store
        .create_asset_group(&admin, &input, Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        store
            .create_asset_group(&admin, &input, Uuid::new_v4())
            .await,
        Err(ErrorCode::ResourceConflict)
    ));
    let renamed = store
        .patch_asset_group(
            &admin,
            group.id,
            group.revision,
            &AssetGroupPatchInput {
                name: Some(format!("renamed-{}", Uuid::new_v4())),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(renamed.revision, group.revision + 1);
    assert!(matches!(
        store
            .patch_asset_group(
                &admin,
                group.id,
                group.revision,
                &AssetGroupPatchInput {
                    name: Some(input.name.clone()),
                    ..Default::default()
                },
                Uuid::new_v4()
            )
            .await,
        Err(ErrorCode::RevisionConflict)
    ));
    assert_eq!(
        store
            .delete_asset_group(&admin, group.id, group.revision, Uuid::new_v4())
            .await,
        Err(ErrorCode::RevisionConflict)
    );
    let before = store.asset(f.asset_id).await.unwrap();
    assert!(matches!(
        store
            .update_asset(
                &admin,
                before.id,
                before.revision,
                &AssetUpdate {
                    group_id: Some(Some(Uuid::new_v4())),
                    ..Default::default()
                },
                Uuid::new_v4()
            )
            .await,
        Err(ErrorCode::ResourceNotFound)
    ));
    let ticket = store
        .issue_web_session(&admin, request(&f), Uuid::new_v4())
        .await
        .unwrap();
    let moved = store
        .update_asset(
            &admin,
            before.id,
            before.revision,
            &AssetUpdate {
                group_id: Some(Some(group.id)),
                ..Default::default()
            },
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert_eq!(moved.group_id, Some(group.id));
    assert_eq!(moved.routing_revision, before.routing_revision);
    assert_eq!(moved.revision, before.revision + 1);
    let connection = store
        .consume_web_session(ticket.session_id, &ticket.ws_token, &admin)
        .await
        .unwrap();
    store.target_snapshot(&connection).await.unwrap();
    let page = store
        .list_page(
            &admin,
            Collection::Assets,
            PageRequest {
                filter: ListFilter {
                    group_id: Some(group.id),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(page["items"][0]["id"], json!(before.id));
    assert_eq!(page["items"][0]["group_name"], json!(renamed.name));
    for role in [Role::Operator, Role::Auditor] {
        let user = store
            .create_user(
                &admin,
                &format!("group-{}", Uuid::new_v4().simple()),
                &phc,
                role,
                Uuid::new_v4(),
            )
            .await
            .unwrap();
        let login = store
            .login_web(&user, &phc, "group denied", Uuid::new_v4())
            .await
            .unwrap();
        let who = store.authenticate_web(&login.access_token).await.unwrap();
        assert!(matches!(
            store.create_asset_group(&who, &input, Uuid::new_v4()).await,
            Err(ErrorCode::PermissionDenied)
        ));
        assert!(matches!(
            store
                .list_page(&who, Collection::AssetGroups, PageRequest::default())
                .await,
            Err(ErrorCode::PermissionDenied)
        ));
        assert!(matches!(
            store
                .update_asset(
                    &who,
                    before.id,
                    moved.revision,
                    &AssetUpdate {
                        group_id: Some(None),
                        ..Default::default()
                    },
                    Uuid::new_v4()
                )
                .await,
            Err(ErrorCode::PermissionDenied)
        ));
        if role == Role::Operator {
            let empty = store
                .list_page(
                    &who,
                    Collection::Assets,
                    PageRequest {
                        filter: ListFilter {
                            group_id: Some(group.id),
                            ..Default::default()
                        },
                        ..Default::default()
                    },
                )
                .await
                .unwrap();
            assert!(empty["items"].as_array().unwrap().is_empty());
            store
                .create_grant(
                    &admin,
                    who.user.id,
                    before.id,
                    f.account_id,
                    None,
                    Uuid::new_v4(),
                )
                .await
                .unwrap();
            let visible = store
                .list_page(&who, Collection::Assets, PageRequest::default())
                .await
                .unwrap();
            assert_eq!(visible["items"][0]["group_name"], json!(renamed.name));
        }
    }
    store
        .delete_asset_group(&admin, group.id, renamed.revision, Uuid::new_v4())
        .await
        .unwrap();
    let after = store.asset(before.id).await.unwrap();
    assert_eq!(after.group_id, None);
    assert_eq!(after.routing_revision, before.routing_revision);
    assert_eq!(after.revision, moved.revision + 1);
    store.target_snapshot(&connection).await.unwrap();
    store
        .transition(connection.id, ConnectionState::Failed, None)
        .await
        .unwrap();
    assert!(matches!(
        store.asset_group(group.id).await,
        Err(ErrorCode::ResourceNotFound)
    ));
    let ungrouped = store
        .list_page(
            &admin,
            Collection::AdminAssets,
            PageRequest {
                filter: ListFilter {
                    ungrouped: Some(true),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert!(ungrouped["items"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["id"] == json!(before.id)));
}
