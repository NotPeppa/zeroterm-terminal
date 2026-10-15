mod browser;
mod groups;
mod recordings;
#[cfg(test)]
mod tests;
use browser::BrowserLogin;
pub use recordings::{remove_recording_file, verify_recording_file};

use axum::{
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Extension, Json, Router,
};
use bastion_domain::*;
use bastion_secrets::{hash_password, verify_password, Credential, KeyRing, Secret};
use bastion_store::{
    AccountCreate as CreateAccount, AccountUpdate as UpdateAccount, AccountView,
    AssetCreate as CreateAsset, AssetUpdate as UpdateAsset, AssetView, Collection, GrantView,
    PageRequest, PgStore,
};
use chrono::{DateTime, Utc};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;
use uuid::Uuid;

pub struct ControlApi {
    pub store: PgStore,
    pub keys: Arc<KeyRing>,
    pub guacd: bastion_gateway::GuacdConfig,
    pub network: Arc<bastion_gateway::NetworkPolicy>,
    browser: Option<browser::BrowserConfig>,
    recording_required: bool,
    recording_available: bool,
    recording_directory: Option<std::path::PathBuf>,
    backend: Option<Arc<dyn bastion_gateway::GatewayBackend>>,
    shutdown: tokio_util::sync::CancellationToken,
    dummy_phc: String,
    password_work: Arc<Semaphore>,
    rate: Mutex<HashMap<String, (Instant, u32)>>,
}
impl ControlApi {
    pub fn new(
        store: PgStore,
        keys: Arc<KeyRing>,
        network: Arc<bastion_gateway::NetworkPolicy>,
        guacd: bastion_gateway::GuacdConfig,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            store,
            keys,
            guacd,
            network,
            browser: None,
            recording_required: false,
            recording_available: false,
            recording_directory: None,
            backend: None,
            shutdown: tokio_util::sync::CancellationToken::new(),
            dummy_phc: hash_password(Secret::random().expose())?,
            password_work: Arc::new(Semaphore::new(4)),
            rate: Mutex::new(HashMap::new()),
        })
    }
    pub fn with_browser(
        mut self,
        origin: String,
        backend: Arc<dyn bastion_gateway::GatewayBackend>,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> anyhow::Result<Self> {
        self.shutdown = shutdown.clone();
        self.backend = Some(backend.clone());
        self.browser = Some(browser::BrowserConfig::new(origin, backend, shutdown)?);
        Ok(self)
    }
    pub fn with_service_state(
        mut self,
        shutdown: tokio_util::sync::CancellationToken,
        recording_required: bool,
        recording_available: bool,
    ) -> Self {
        self.shutdown = shutdown;
        self.recording_required = recording_required;
        self.recording_available = recording_available;
        self
    }
    pub fn with_recordings(mut self, directory: std::path::PathBuf) -> Self {
        self.recording_directory = Some(directory);
        self.recording_available = true;
        self
    }
    fn hit(&self, key: String, limit: u32) -> bool {
        let mut buckets = self.rate.lock().expect("rate map poisoned");
        let now = Instant::now();
        buckets.retain(|_, (time, _)| now.duration_since(*time) < Duration::from_secs(60));
        if !buckets.contains_key(&key) && buckets.len() >= 10000 {
            return false;
        }
        let entry = buckets.entry(key).or_insert((now, 0));
        if entry.1 >= limit {
            return false;
        }
        entry.1 += 1;
        true
    }
    fn username_limited(&self, name: &str) -> bool {
        self.rate
            .lock()
            .expect("rate map poisoned")
            .get(&format!("user:{name}"))
            .is_some_and(|(time, count)| time.elapsed() < Duration::from_secs(60) && *count >= 5)
    }
    async fn password_hash(&self, password: Secret) -> ApiResult<String> {
        let permit = self
            .password_work
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError(ErrorCode::RateLimited))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            hash_password(password.expose())
        })
        .await
        .map_err(|_| ApiError(ErrorCode::InternalError))?
        .map_err(|_| ApiError(ErrorCode::InvalidArgument))
    }
    async fn password_matches(&self, password: Secret, phc: String) -> ApiResult<bool> {
        let permit = self
            .password_work
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError(ErrorCode::RateLimited))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            verify_password(password.expose(), &phc)
        })
        .await
        .map_err(|_| ApiError(ErrorCode::InternalError))
    }
    async fn target(&self, connection: &Connection) -> Result<bastion_gateway::Target, ErrorCode> {
        use bastion_gateway::{Target, TargetAuth, TargetEndpoint};
        let snapshot = self.store.target_snapshot(connection).await?;
        let auth = match (snapshot.context, snapshot.credential) {
            (Some(context), Some(envelope)) => TargetAuth::Encrypted {
                context,
                envelope,
                keys: self.keys.clone(),
            },
            (None, None) if snapshot.protocol == TargetProtocol::Vnc => TargetAuth::None,
            _ => return Err(ErrorCode::TargetAuthFailed),
        };
        Ok(Target {
            protocol: snapshot.protocol,
            address: TargetEndpoint::Restricted {
                host: snapshot.host,
                port: snapshot.port,
                policy: self.network.clone(),
            },
            security: snapshot.security,
            ssh_host_key: snapshot.ssh_host_key,
            rdp_certificate_sha256: snapshot.rdp_certificate_sha256,
            username: snapshot.username,
            domain: snapshot.domain,
            auth,
        })
    }
}

#[derive(Clone)]
struct RequestContext {
    id: Uuid,
    ip: IpAddr,
}
type ApiResult<T> = Result<T, ApiError>;
#[derive(Debug)]
struct ApiError(ErrorCode);
impl From<ErrorCode> for ApiError {
    fn from(code: ErrorCode) -> Self {
        Self(code)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthenticated
            | ErrorCode::AccessTokenExpired
            | ErrorCode::LoginSessionRevoked => StatusCode::UNAUTHORIZED,
            ErrorCode::PermissionDenied
            | ErrorCode::UserDisabled
            | ErrorCode::TargetAddressDenied => StatusCode::FORBIDDEN,
            ErrorCode::ResourceNotFound => StatusCode::NOT_FOUND,
            ErrorCode::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            ErrorCode::RevisionConflict => StatusCode::PRECONDITION_FAILED,
            ErrorCode::RateLimited | ErrorCode::ConnectionLimit => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::PolicyStoreUnavailable
            | ErrorCode::RecordingUnavailable
            | ErrorCode::TargetProtocolUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::ClientProtocolUnsupported => StatusCode::UPGRADE_REQUIRED,
            ErrorCode::AuthOrGatewayFailed => StatusCode::BAD_GATEWAY,
            ErrorCode::TicketExpired
            | ErrorCode::TicketUsed
            | ErrorCode::TicketInvalid
            | ErrorCode::TicketStale
            | ErrorCode::TargetHostKeyChanged
            | ErrorCode::TargetHostKeyUnknown
            | ErrorCode::TargetCertificateChanged
            | ErrorCode::ResourceConflict => StatusCode::CONFLICT,
            ErrorCode::TargetTimeout => StatusCode::GATEWAY_TIMEOUT,
            ErrorCode::TargetUnreachable
            | ErrorCode::TargetAuthFailed
            | ErrorCode::TargetRequestRejected => StatusCode::BAD_GATEWAY,
            ErrorCode::InternalError => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let mut response = (
            status,
            Json(json!({"error":{"code":self.0,"message":self.0.to_string()}})),
        )
            .into_response();
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("60"));
        }
        response
    }
}

pub fn control_router(state: Arc<ControlApi>) -> Router {
    let admin = Router::new()
        .route("/admin/users", get(users).post(create_user))
        .route(
            "/admin/users/{id}",
            get(user).patch(update_user).delete(delete_user),
        )
        .route("/admin/users/{id}/reset-password", post(reset_password))
        .route("/admin/assets", get(admin_assets).post(create_asset))
        .route(
            "/admin/asset-groups",
            get(groups::list).post(groups::create),
        )
        .route(
            "/admin/asset-groups/{id}",
            get(groups::get).patch(groups::patch).delete(groups::remove),
        )
        .route(
            "/admin/assets/{id}",
            get(admin_asset).patch(update_asset).delete(delete_asset),
        )
        .route(
            "/admin/assets/{id}/ssh-host-key/scan",
            post(scan_ssh_host_key),
        )
        .route(
            "/admin/assets/{id}/rdp-certificate/scan",
            post(scan_rdp_certificate),
        )
        .route(
            "/admin/assets/{id}/accounts",
            get(accounts).post(create_account),
        )
        .route(
            "/admin/accounts/{id}",
            get(account).patch(update_account).delete(delete_account),
        )
        .route(
            "/admin/accounts/{id}/credential",
            axum::routing::put(replace_credential),
        )
        .route("/admin/grants", get(grants).post(create_grant))
        .route(
            "/admin/grants/{id}",
            get(grant).patch(update_grant).delete(revoke_grant),
        )
        .layer(middleware::from_fn(require_admin));
    let protected = Router::new()
        .merge(admin)
        .route("/me", get(me))
        .route("/me/sessions", get(device_sessions))
        .route("/me/sessions/{id}", axum::routing::delete(revoke_device))
        .route("/me/password", post(change_password))
        .route("/auth/logout", post(logout))
        .route("/auth/logout-all", post(logout_all))
        .route("/assets", get(assets))
        .route("/assets/{id}", get(asset))
        .route("/sessions", post(browser::issue_session))
        .route("/sessions/{id}/stream", get(browser::stream))
        .route("/connections", get(connections))
        .route("/connections/{id}", get(connection))
        .route("/recordings", get(recordings::list))
        .route("/recordings/{id}", get(recordings::metadata))
        .route("/recordings/{id}/content", get(recordings::content))
        .route("/connections/{id}/disconnect", post(disconnect))
        .route("/audit-events", get(audit_events))
        .layer(middleware::from_fn_with_state(state.clone(), authenticate));
    Router::new()
        .nest(
            "/api/v1",
            Router::new()
                .merge(protected)
                .route("/info", get(info))
                .route("/auth/login", post(login))
                .route("/auth/csrf", get(browser::csrf_token))
                .route("/auth/refresh", post(browser::refresh))
                .fallback(|| async { ApiError(ErrorCode::ResourceNotFound) }),
        )
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(readiness))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(context))
        .with_state(state)
}
async fn context(mut request: axum::extract::Request, next: Next) -> Response {
    let id = Uuid::new_v4();
    // Replay handlers stream outside the JSON request deadline. Their own
    // bounded I/O and authorization deadlines apply; DB calls retain the 2s budget.
    let streamed = request.method() == axum::http::Method::GET
        && request.uri().path().contains("/recordings/")
        && request.uri().path().ends_with("/content");
    let ip = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ConnectInfo(addr)| addr.ip())
        .unwrap_or_else(|| "127.0.0.1".parse().unwrap());
    request.extensions_mut().insert(RequestContext { id, ip });
    let mut response = if streamed {
        next.run(request).await
    } else {
        match tokio::time::timeout(Duration::from_secs(15), next.run(request)).await {
            Ok(response) => response,
            Err(_) => ApiError(ErrorCode::PolicyStoreUnavailable).into_response(),
        }
    };
    if response.status().is_client_error() || response.status().is_server_error() {
        let (parts, body) = response.into_parts();
        let body = axum::body::to_bytes(body, 65536).await.unwrap_or_default();
        let mut value: Value = serde_json::from_slice(&body).unwrap_or_else(
            |_| json!({"error":{"code":"INVALID_ARGUMENT","message":"请求不符合接口格式"}}),
        );
        if let Some(error) = value.get_mut("error").and_then(Value::as_object_mut) {
            error.insert("request_id".into(), json!(id));
        }
        response = Response::from_parts(parts, axum::body::Body::from(value.to_string()));
        response.headers_mut().remove(header::CONTENT_LENGTH);
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
    }
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&id.to_string()).unwrap(),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}
use browser::authenticate;
async fn require_admin(request: axum::extract::Request, next: Next) -> Response {
    if request
        .extensions()
        .get::<Identity>()
        .is_none_or(|identity| identity.user.role != Role::Admin)
    {
        return ApiError(ErrorCode::PermissionDenied).into_response();
    }
    next.run(request).await
}
fn normalize_username(name: &str) -> ApiResult<String> {
    let normalized = name.trim().to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 64
        || !normalized.as_bytes()[0].is_ascii_alphanumeric()
        || normalized
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"_.-".contains(&b))
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok(normalized)
}
pub fn valid_host(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return true;
    }
    !host.is_empty()
        && host.len() <= 253
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
}
fn revision(headers: &HeaderMap) -> ApiResult<i64> {
    let value = headers
        .get(header::IF_MATCH)
        .ok_or(ApiError(ErrorCode::PreconditionRequired))?
        .to_str()
        .map_err(|_| ApiError(ErrorCode::InvalidArgument))?;
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .and_then(|v| v.parse().ok())
        .filter(|v| *v > 0)
        .ok_or(ApiError(ErrorCode::InvalidArgument))
}
fn id(value: &str) -> ApiResult<Uuid> {
    Uuid::parse_str(value).map_err(|_| ApiError(ErrorCode::InvalidArgument))
}
fn input<T>(value: Result<Json<T>, axum::extract::rejection::JsonRejection>) -> ApiResult<T> {
    value
        .map(|Json(v)| v)
        .map_err(|_| ApiError(ErrorCode::InvalidArgument))
}

async fn info(State(state): State<Arc<ControlApi>>) -> Json<Value> {
    let recording_available = state.recording_available
        && !state.shutdown.is_cancelled()
        && recording_ready(&state).await.is_ok();
    let replay_available = state.recording_available
        && !state.shutdown.is_cancelled()
        && recordings::available(&state).await;
    let usable = state.browser.is_some()
        && state.backend.is_some()
        && (!state.recording_required || recording_available)
        && !state.shutdown.is_cancelled();
    let (rdp, vnc) = if usable {
        tokio::join!(
            bastion_gateway::protocol_available(&state.guacd, TargetProtocol::Rdp),
            bastion_gateway::protocol_available(&state.guacd, TargetProtocol::Vnc)
        )
    } else {
        (false, false)
    };
    Json(
        json!({"server_id":state.store.server_id,"schema_version":2,"protocol_version":2,
        "stream_protocol":STREAM_PROTOCOL,"production_ready":false,
        "stream_protocols":{"ssh":SSH_STREAM_PROTOCOL,"rdp":STREAM_PROTOCOL,"vnc":STREAM_PROTOCOL},
        "recording":{"required":state.recording_required,"format_version":2,"available":recording_available},
        "password_min_length":bastion_secrets::password_min_length().unwrap_or(12),
        "features":{"web_ssh":usable,"web_rdp":rdp,"web_vnc":vnc,"recording_replay":replay_available,"device_sessions":true}}),
    )
}
async fn recording_ready(state: &ControlApi) -> ApiResult<()> {
    if state.recording_required {
        let recording = state
            .backend
            .as_ref()
            .and_then(|backend| backend.recording_config())
            .ok_or(ApiError(ErrorCode::RecordingUnavailable))?;
        static PROBES: std::sync::OnceLock<Arc<Semaphore>> = std::sync::OnceLock::new();
        let probes = PROBES.get_or_init(|| Arc::new(Semaphore::new(1))).clone();
        tokio::time::timeout(Duration::from_secs(2), async move {
            let permit = probes
                .acquire_owned()
                .await
                .map_err(|_| ErrorCode::RecordingUnavailable)?;
            tokio::task::spawn_blocking(move || {
                let _permit = permit;
                bastion_gateway::check_recording_directory(
                    &recording.directory,
                    recording.min_free_bytes,
                )
            })
            .await
            .unwrap_or(Err(ErrorCode::RecordingUnavailable))
        })
        .await
        .map_err(|_| ApiError(ErrorCode::RecordingUnavailable))??;
    }
    Ok(())
}
async fn readiness(State(state): State<Arc<ControlApi>>) -> ApiResult<&'static str> {
    if state.shutdown.is_cancelled() || state.recording_required && !state.recording_available {
        return Err(ApiError(ErrorCode::RecordingUnavailable));
    }
    recording_ready(&state).await?;
    state.store.check_identity().await?;
    Ok("ok")
}
async fn me(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({"user":identity.user,"login_session_id":identity.login_session_id,"policy_revision":state.store.policy_revision().await?,"csrf_token":browser::csrf_for_me(&headers),"access_expires_at":identity.access_expires_at}),
    ))
}
async fn login(
    State(state): State<Arc<ControlApi>>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    body: Result<Json<BrowserLogin>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Response> {
    let mut body = input(body)?;
    browser::web_login(&state, &headers)?;
    if !state.hit(format!("ip:{}", ctx.ip), 10) {
        return Err(ApiError(ErrorCode::RateLimited));
    }
    let normalized = normalize_username(&body.username).ok();
    let username = normalized.as_deref().unwrap_or("invalid-user-format");
    if state.username_limited(username) {
        return Err(ApiError(ErrorCode::RateLimited));
    }
    if body.device_label.is_empty()
        || body.device_label.len() > 128
        || body.device_label.chars().any(char::is_control)
        || body.password.len() > 1024
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let candidate = if normalized.is_some() {
        state.store.login_candidate(username).await?
    } else {
        None
    };
    let phc = candidate
        .as_ref()
        .map(|(_, hash)| hash.clone())
        .unwrap_or_else(|| state.dummy_phc.clone());
    let matches = state
        .password_matches(Secret::new(std::mem::take(&mut body.password)), phc)
        .await?;
    if let Some((user, hash)) = candidate {
        if matches && user.enabled {
            let result = state
                .store
                .login_web(&user, &hash, &body.device_label, ctx.id)
                .await?;
            return browser::login_response(&state, result);
        }
    }
    state.hit(format!("user:{username}"), 5);
    state.store.login_failure(ctx.id).await?;
    Err(ApiError(ErrorCode::Unauthenticated))
}
async fn logout(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
) -> ApiResult<Response> {
    state.store.logout(&identity, false, ctx.id).await?;
    if let Some(backend) = &state.backend {
        backend.registry().revoke_login(identity.login_session_id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    browser::clear_cookies(&state, &mut response);
    Ok(response)
}
async fn logout_all(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
) -> ApiResult<Response> {
    state.store.logout(&identity, true, ctx.id).await?;
    if let Some(backend) = &state.backend {
        backend.registry().revoke_user(identity.user.id);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    browser::clear_cookies(&state, &mut response);
    Ok(response)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateUser {
    username: String,
    password: String,
    role: Role,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateUser {
    role: Option<Role>,
    enabled: Option<bool>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewPassword {
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    current_password: String,
    new_password: String,
}
async fn users(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Users, page)
            .await?,
    ))
}
async fn user(
    State(state): State<Arc<ControlApi>>,
    Path(value): Path<String>,
) -> ApiResult<Json<UserView>> {
    Ok(Json(state.store.user(id(&value)?).await?))
}
async fn create_user(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<CreateUser>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<UserView>)> {
    let body = input(body)?;
    let username = normalize_username(&body.username)?;
    let phc = state.password_hash(Secret::new(body.password)).await?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .create_user(&actor, &username, &phc, body.role, ctx.id)
                .await?,
        ),
    ))
}
async fn update_user(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UpdateUser>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<UserView>> {
    let body = input(body)?;
    if body.role.is_none() && body.enabled.is_none() {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok(Json(
        state
            .store
            .update_user(
                &actor,
                id(&value)?,
                revision(&headers)?,
                body.role,
                body.enabled,
                ctx.id,
            )
            .await?,
    ))
}
async fn delete_user(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    let id = id(&value)?;
    state
        .store
        .delete_user(&actor, id, revision(&headers)?, ctx.id)
        .await?;
    if let Some(backend) = &state.backend {
        backend.registry().revoke_user(id);
    }
    Ok(StatusCode::NO_CONTENT)
}
async fn reset_password(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<NewPassword>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let body = input(body)?;
    let revision = revision(&headers)?;
    let phc = state.password_hash(Secret::new(body.password)).await?;
    state
        .store
        .reset_password(Some(&actor), id(&value)?, revision, &phc, ctx.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn change_password(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<ChangePassword>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<StatusCode> {
    let body = input(body)?;
    let (_, previous) = state
        .store
        .login_candidate(&actor.user.username)
        .await?
        .ok_or(ApiError(ErrorCode::Unauthenticated))?;
    if !state
        .password_matches(Secret::new(body.current_password), previous.clone())
        .await?
    {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    let phc = state.password_hash(Secret::new(body.new_password)).await?;
    state
        .store
        .change_password(&actor, &previous, &phc, ctx.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

fn valid_asset(name: &str, host: &str, port: u16, tags: &[String]) -> bool {
    !name.is_empty()
        && name.chars().count() <= 128
        && valid_host(host)
        && port > 0
        && tags.len() <= 32
        && tags.iter().all(|tag| tag.len() <= 64)
}
async fn admin_assets(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::AdminAssets, page)
            .await?,
    ))
}
async fn admin_asset(
    State(state): State<Arc<ControlApi>>,
    Path(value): Path<String>,
) -> ApiResult<Json<AssetView>> {
    Ok(Json(state.store.asset(id(&value)?).await?))
}
/// Shared trust-discovery guard: the asset revision shown to the administrator, its protocol,
/// per-admin rate and global concurrency. Returns the asset, its port and the held permit.
async fn scan_target(
    state: &ControlApi,
    actor: &Identity,
    value: &str,
    headers: &HeaderMap,
    protocol: TargetProtocol,
) -> ApiResult<(AssetView, u16, tokio::sync::SemaphorePermit<'static>)> {
    let expected = revision(headers)?;
    let asset = state.store.asset(id(value)?).await?;
    if asset.revision != expected {
        return Err(ApiError(ErrorCode::RevisionConflict));
    }
    if asset.protocol != protocol || !asset.enabled {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    if !state.hit(format!("trust-scan:{}", actor.user.id), 10) {
        return Err(ApiError(ErrorCode::RateLimited));
    }
    static SCANS: std::sync::OnceLock<Semaphore> = std::sync::OnceLock::new();
    let permit = SCANS
        .get_or_init(|| Semaphore::new(4))
        .try_acquire()
        .map_err(|_| ApiError(ErrorCode::RateLimited))?;
    let port = u16::try_from(asset.port).map_err(|_| ApiError(ErrorCode::InternalError))?;
    Ok((asset, port, permit))
}
/// Approval must use the address/revision actually shown to the administrator.
async fn unchanged(state: &ControlApi, asset: &AssetView) -> ApiResult<()> {
    if state.store.asset(asset.id).await?.revision != asset.revision {
        return Err(ApiError(ErrorCode::RevisionConflict));
    }
    Ok(())
}
async fn scan_ssh_host_key(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (asset, port, _permit) =
        scan_target(&state, &actor, &value, &headers, TargetProtocol::Ssh).await?;
    let keys = bastion_gateway::scan_ssh_host_keys(&state.network, &asset.host, port).await?;
    unchanged(&state, &asset).await?;
    let approved_fingerprint = asset
        .ssh_host_key
        .as_deref()
        .map(bastion_gateway::ssh_host_key_fingerprint)
        .transpose()?;
    Ok(Json(
        json!({"asset_id":asset.id,"host":asset.host,"port":asset.port,
        "revision":asset.revision,"approved_fingerprint":approved_fingerprint,"keys":keys}),
    ))
}
/// Bodyless like SSH: discovers the pin and the security protocol the server selects; the
/// administrator confirms both with asset PATCH using the returned revision.
async fn scan_rdp_certificate(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (asset, port, _permit) =
        scan_target(&state, &actor, &value, &headers, TargetProtocol::Rdp).await?;
    let certificate =
        bastion_gateway::scan_rdp_certificate(&state.network, &asset.host, port).await?;
    unchanged(&state, &asset).await?;
    let security = if certificate.selected_protocol == "tls" {
        "tls"
    } else {
        "nla"
    };
    Ok(Json(
        json!({"asset_id":asset.id,"host":asset.host,"port":asset.port,"revision":asset.revision,
        "approved_sha256":asset.rdp_certificate_sha256,"approved_security":asset.security,
        "sha256":certificate.sha256,"selected_protocol":certificate.selected_protocol,"security":security}),
    ))
}
async fn create_asset(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<CreateAsset>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<AssetView>)> {
    let body = input(body)?;
    if !valid_asset(&body.name, &body.host, body.port, &body.tags) {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok((
        StatusCode::CREATED,
        Json(state.store.create_asset(&actor, &body, ctx.id).await?),
    ))
}
async fn update_asset(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UpdateAsset>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<AssetView>> {
    let body = input(body)?;
    if body
        .tags
        .as_ref()
        .is_some_and(|tags| tags.len() > 32 || tags.iter().any(|tag| tag.len() > 64))
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    if body.host.as_ref().is_some_and(|host| !valid_host(host))
        || body.port == Some(0)
        || body
            .name
            .as_ref()
            .is_some_and(|name| name.is_empty() || name.chars().count() > 128)
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok(Json(
        state
            .store
            .update_asset(&actor, id(&value)?, revision(&headers)?, &body, ctx.id)
            .await?,
    ))
}
async fn assets(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Assets, page)
            .await?,
    ))
}
async fn asset(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<Value>> {
    if identity.user.role == Role::Auditor {
        return Err(ApiError(ErrorCode::ResourceNotFound));
    }
    let page = state
        .store
        .list_page(
            &identity,
            Collection::Asset(id(&value)?),
            PageRequest::default(),
        )
        .await?;
    Ok(Json(
        page["items"]
            .as_array()
            .unwrap()
            .first()
            .cloned()
            .ok_or(ApiError(ErrorCode::ResourceNotFound))?,
    ))
}

async fn accounts(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Accounts(id(&value)?), page)
            .await?,
    ))
}
async fn account(
    State(state): State<Arc<ControlApi>>,
    Path(value): Path<String>,
) -> ApiResult<Json<AccountView>> {
    Ok(Json(state.store.account(id(&value)?).await?))
}
async fn create_account(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    body: Result<Json<CreateAccount>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<AccountView>)> {
    let body = input(body)?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .create_account(&actor, id(&value)?, &body, &state.keys, ctx.id)
                .await?,
        ),
    ))
}
async fn update_account(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UpdateAccount>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<AccountView>> {
    let body = input(body)?;
    Ok(Json(
        state
            .store
            .update_account(
                &actor,
                id(&value)?,
                revision(&headers)?,
                &body,
                &state.keys,
                ctx.id,
            )
            .await?,
    ))
}
async fn replace_credential(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<Credential>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<AccountView>> {
    let revision = revision(&headers)?;
    let credential = input(body)?;
    Ok(Json(
        state
            .store
            .replace_credential(
                &actor,
                id(&value)?,
                revision,
                credential,
                &state.keys,
                ctx.id,
            )
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateGrant {
    user_id: Uuid,
    asset_id: Uuid,
    account_id: Uuid,
    expires_at: Option<DateTime<Utc>>,
}
async fn grants(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Grants, page)
            .await?,
    ))
}
async fn grant(
    State(state): State<Arc<ControlApi>>,
    Path(value): Path<String>,
) -> ApiResult<Json<GrantView>> {
    Ok(Json(state.store.grant(id(&value)?).await?))
}
async fn create_grant(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<CreateGrant>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<GrantView>)> {
    let body = input(body)?;
    if body.expires_at.is_some_and(|expiry| expiry <= Utc::now()) {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .create_grant(
                    &actor,
                    body.user_id,
                    body.asset_id,
                    body.account_id,
                    body.expires_at,
                    ctx.id,
                )
                .await?,
        ),
    ))
}
async fn revoke_grant(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    state
        .store
        .revoke_grant(&actor, id(&value)?, revision(&headers)?, ctx.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn delete_asset(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    state
        .store
        .delete_asset(&actor, id(&value)?, revision(&headers)?, ctx.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn delete_account(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    state
        .store
        .delete_account(&actor, id(&value)?, revision(&headers)?, ctx.id)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
async fn connection(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<Connection>> {
    Ok(Json(state.store.connection(&identity, id(&value)?).await?))
}
async fn disconnect(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
) -> ApiResult<StatusCode> {
    state
        .store
        .request_disconnect(&identity, id(&value)?, ctx.id)
        .await?;
    if let Some(backend) = &state.backend {
        backend.registry().revoke_connection(id(&value)?);
    }
    Ok(StatusCode::ACCEPTED)
}
async fn audit_events(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Audit, page)
            .await?,
    ))
}

async fn connections(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::Connections, page)
            .await?,
    ))
}

fn nullable<'de, D, T>(deserializer: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer).map(Some)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateGrant {
    enabled: Option<bool>,
    #[serde(default, deserialize_with = "nullable")]
    expires_at: Option<Option<DateTime<Utc>>>,
}
async fn update_grant(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    headers: HeaderMap,
    body: Result<Json<UpdateGrant>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<GrantView>> {
    let body = input(body)?;
    if body.enabled.is_none() && body.expires_at.is_none() {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    if body.expires_at.flatten().is_some_and(|v| v <= Utc::now()) {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok(Json(
        state
            .store
            .update_grant(
                &actor,
                id(&value)?,
                revision(&headers)?,
                body.enabled,
                body.expires_at,
                ctx.id,
            )
            .await?,
    ))
}

async fn device_sessions(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::DeviceSessions, page)
            .await?,
    ))
}
async fn revoke_device(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
) -> ApiResult<Response> {
    let device = id(&value)?;
    state
        .store
        .revoke_device_session(&identity, device, ctx.id)
        .await?;
    if let Some(backend) = &state.backend {
        backend.registry().revoke_login(device);
    }
    let mut response = StatusCode::NO_CONTENT.into_response();
    if device == identity.login_session_id {
        browser::clear_cookies(&state, &mut response);
    }
    Ok(response)
}
