use super::*;
use axum::body::{Body, Bytes};
use bastion_gateway::SftpSession;
use futures_util::StreamExt;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileQuery {
    path: String,
    operation: Option<String>,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Mkdir { path: String },
    Remove { path: String },
    Rename { path: String, destination: String },
}
async fn lane(state: &ControlApi, identity: &Identity, connection: Uuid) -> ApiResult<SftpSession> {
    let backend = state
        .backend
        .as_ref()
        .ok_or(ApiError(ErrorCode::PermissionDenied))?
        .clone();
    let session =
        backend
            .registry()
            .get(connection, identity.user.id, identity.login_session_id)?;
    Ok(session
        .open_sftp(identity.user.id, identity.login_session_id)
        .await?)
}
pub(super) async fn metadata(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    Query(query): Query<FileQuery>,
) -> ApiResult<Json<Value>> {
    let connection = id(&value)?;
    let lane = lane(&state, &identity, connection).await?;
    let result = async {
        match query.operation.as_deref().unwrap_or("list") {
            "list" => Ok(json!({"items":lane.read_dir(&query.path).await?})),
            "stat" => Ok(json!(lane.metadata(&query.path).await?)),
            _ => Err(ApiError(ErrorCode::InvalidArgument)),
        }
    }
    .await;
    let closed = lane.close().await;
    let result: Value = result?;
    closed?;
    Ok(Json(result))
}
pub(super) async fn operate(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    body: Result<Json<Operation>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let operation = input(body)?;
    let connection = id(&value)?;
    let lane = lane(&state, &identity, connection).await?;
    let result = match operation {
        Operation::Mkdir { path } => lane.create_dir(&path).await,
        Operation::Remove { path } => lane.remove_file(&path).await,
        Operation::Rename { path, destination } => lane.rename(&path, &destination).await,
    };
    let closed = lane.close().await;
    result?;
    closed?;
    Ok(StatusCode::NO_CONTENT)
}
pub(super) async fn download(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    if headers.contains_key(header::RANGE) || query.operation.is_some() {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let connection = id(&value)?;
    let lane = lane(&state, &identity, connection).await?;
    let prepared = async {
        let metadata = lane.metadata(&query.path).await?;
        if metadata.size.is_none_or(|size| size > state.file_max_bytes) {
            return Err(ApiError(ErrorCode::InvalidArgument));
        }
        Ok(lane.open_download(&query.path).await?)
    }
    .await;
    let file = match prepared {
        Ok(file) => file,
        Err(error) => {
            let _ = lane.close().await;
            return Err(error);
        }
    };
    let limit = state.file_max_bytes;
    let stream = futures_util::stream::unfold(Some((file, lane, 0u64)), move |file| async move {
        let (mut file, lane, bytes) = file?;
        match file.read_chunk().await {
            Ok(Some(chunk))
                if bytes
                    .checked_add(chunk.len() as u64)
                    .is_some_and(|total| total <= limit) =>
            {
                let next = bytes + chunk.len() as u64;
                Some((
                    Ok::<Bytes, std::io::Error>(Bytes::from(chunk)),
                    Some((file, lane, next)),
                ))
            }
            Ok(None) => {
                let file_closed = file.close().await;
                let lane_closed = lane.close().await;
                if file_closed.is_ok() && lane_closed.is_ok() {
                    None
                } else {
                    Some((Err(std::io::Error::other("remote close failed")), None))
                }
            }
            _ => {
                let _ = file.close().await;
                let _ = lane.close().await;
                Some((Err(std::io::Error::other("remote download failed")), None))
            }
        }
    });
    let name = query
        .path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("download");
    let encoded: String = name
        .bytes()
        .map(|byte| {
            if byte.is_ascii_alphanumeric() || b"-_.".contains(&byte) {
                (byte as char).to_string()
            } else {
                format!("%{byte:02X}")
            }
        })
        .collect();
    let disposition = format!("attachment; filename*=UTF-8''{encoded}");
    Ok((
        [
            (header::CONTENT_TYPE, "application/octet-stream"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONTENT_DISPOSITION, disposition.as_str()),
        ],
        Body::from_stream(stream),
    )
        .into_response())
}
pub(super) async fn upload(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    Query(query): Query<FileQuery>,
    headers: HeaderMap,
    body: Body,
) -> ApiResult<(StatusCode, Json<Value>)> {
    if query.operation.is_some()
        || headers.contains_key(header::CONTENT_RANGE)
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/octet-stream")
        || headers.get(header::CONTENT_LENGTH).is_some_and(|v| {
            v.to_str()
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .is_none_or(|n| n > state.file_max_bytes)
        })
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let connection = id(&value)?;
    let lane = lane(&state, &identity, connection).await?;
    let mut upload = match lane.begin_upload(&query.path).await {
        Ok(upload) => upload,
        Err(error) => {
            let _ = lane.close().await;
            return Err(ApiError(error));
        }
    };
    let mut data = body.into_data_stream();
    let mut bytes = 0u64;
    let result = async {
        loop {
            let next = tokio::select! {
                _=state.shutdown.cancelled()=>return Err(ApiError(ErrorCode::PolicyStoreUnavailable)),
                next=tokio::time::timeout(Duration::from_secs(30),data.next())=>next.map_err(|_|ApiError(ErrorCode::TargetTimeout))?,
            };
            let Some(chunk) = next else { break; };
            let chunk = chunk.map_err(|_|ApiError(ErrorCode::InvalidArgument))?;
            bytes = bytes.checked_add(chunk.len() as u64).filter(|n|*n<=state.file_max_bytes).ok_or(ApiError(ErrorCode::InvalidArgument))?;
            for piece in chunk.chunks(32768) { upload.write_chunk(piece).await?; }
        }
        Ok::<(),ApiError>(())
    }.await;
    if let Err(error) = result {
        let _ = upload.cancel().await;
        let _ = lane.close().await;
        return Err(error);
    }
    let committed = upload.commit().await;
    let closed = lane.close().await;
    let bytes = committed?;
    closed?;
    Ok((StatusCode::CREATED, Json(json!({"bytes":bytes}))))
}
pub(super) async fn jobs(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::CopyJobs, page)
            .await?,
    ))
}
pub(super) async fn job(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<CopyJobView>> {
    Ok(Json(state.store.copy_job(&identity, id(&value)?).await?))
}
pub(super) async fn cancel_job(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .store
        .cancel_copy_job(&identity, id(&value)?, ctx.id)
        .await?;
    Ok(StatusCode::ACCEPTED)
}
pub(super) async fn create_job(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<CopyJobCreate>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<CopyJobView>)> {
    // Standard SFTPv3 cannot enforce atomic NOFOLLOW. Advertise copy_jobs=false
    // and persist an explicit failed job rather than pretending a safe copy ran.
    let body = input(body)?;
    let job = state
        .store
        .create_copy_job(&identity, &body, ctx.id)
        .await?;
    state
        .store
        .transition_copy_job(
            job.id,
            CopyJobState::Failed,
            0,
            Some(ErrorCode::TargetRequestRejected),
        )
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(state.store.copy_job(&identity, job.id).await?),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn operation_shapes_are_typed_and_do_not_accept_shell_escape() {
        for body in [
            r#"{"operation":"mkdir","path":"/new"}"#,
            r#"{"operation":"rename","path":"/old","destination":"/new"}"#,
        ] {
            assert!(serde_json::from_str::<Operation>(body).is_ok());
        }
        for body in [
            r#"{"operation":"exec","path":"/new","command":"rm"}"#,
            r#"{"operation":"remove","path":"/new","recursive":true}"#,
            r#"{"operation":"rename","path":"/old"}"#,
        ] {
            assert!(serde_json::from_str::<Operation>(body).is_err());
        }
    }
}
