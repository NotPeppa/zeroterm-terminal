use super::*;
use bastion_store::{AssetGroupCreateInput, AssetGroupPatchInput, AssetGroupView};

pub(super) async fn list(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&actor, Collection::AssetGroups, page)
            .await?,
    ))
}
pub(super) async fn get(
    State(state): State<Arc<ControlApi>>,
    Path(value): Path<String>,
) -> ApiResult<Json<AssetGroupView>> {
    Ok(Json(state.store.asset_group(id(&value)?).await?))
}
pub(super) async fn create(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<AssetGroupCreateInput>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<AssetGroupView>)> {
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .create_asset_group(&actor, &input(body)?, ctx.id)
                .await?,
        ),
    ))
}
/// Renames and/or moves a group; `parent_id: null` promotes it to a root.
pub(super) async fn patch(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<AssetGroupPatchInput>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<AssetGroupView>> {
    Ok(Json(
        state
            .store
            .patch_asset_group(
                &actor,
                id(&value)?,
                revision(&headers)?,
                &input(body)?,
                ctx.id,
            )
            .await?,
    ))
}
pub(super) async fn remove(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    state
        .store
        .delete_asset_group(&actor, id(&value)?, revision(&headers)?, ctx.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
