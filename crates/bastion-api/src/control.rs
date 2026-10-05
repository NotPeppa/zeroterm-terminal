mod browser;
mod files;
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
    AccountView, AssetView, Collection, GrantView, HostKeyView, PageRequest, PgStore,
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
    pub gateway: GatewayAddress,
    pub gateway_public_key: String,
    pub network: Arc<bastion_gateway::NetworkPolicy>,
    browser: Option<browser::BrowserConfig>,
    recording_required: bool,
    recording_available: bool,
    recording_directory: Option<std::path::PathBuf>,
    file_max_bytes: u64,
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
        gateway: GatewayAddress,
        gateway_public_key: String,
        network: Arc<bastion_gateway::NetworkPolicy>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            store,
            keys,
            gateway,
            gateway_public_key,
            network,
            browser: None,
            recording_required: false,
            recording_available: false,
            recording_directory: None,
            file_max_bytes: 1024 * 1024 * 1024,
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
    pub fn with_backend(
        mut self,
        backend: Arc<dyn bastion_gateway::GatewayBackend>,
        file_max_bytes: u64,
    ) -> Self {
        self.backend = Some(backend);
        self.file_max_bytes = file_max_bytes;
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
    async fn validate_credential(&self, credential: Credential) -> ApiResult<Credential> {
        if !credential.validate_lengths() {
            return Err(ApiError(ErrorCode::InvalidArgument));
        }
        let permit = self
            .password_work
            .clone()
            .try_acquire_owned()
            .map_err(|_| ApiError(ErrorCode::RateLimited))?;
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            if let Credential::PrivateKey {
                key_pem,
                passphrase,
            } = &credential
            {
                russh::keys::decode_secret_key(key_pem, passphrase.as_deref())
                    .map_err(|_| ApiError(ErrorCode::InvalidArgument))?;
            }
            Ok(credential)
        })
        .await
        .map_err(|_| ApiError(ErrorCode::InternalError))?
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
            ErrorCode::InvalidArgument | ErrorCode::UnknownCapability => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthenticated
            | ErrorCode::AccessTokenExpired
            | ErrorCode::LoginSessionRevoked => StatusCode::UNAUTHORIZED,
            ErrorCode::PermissionDenied
            | ErrorCode::ChannelPermissionDenied
            | ErrorCode::UserDisabled
            | ErrorCode::TargetAddressDenied => StatusCode::FORBIDDEN,
            ErrorCode::ResourceNotFound => StatusCode::NOT_FOUND,
            ErrorCode::PreconditionRequired => StatusCode::PRECONDITION_REQUIRED,
            ErrorCode::RevisionConflict => StatusCode::PRECONDITION_FAILED,
            ErrorCode::RateLimited | ErrorCode::ConnectionLimit => StatusCode::TOO_MANY_REQUESTS,
            ErrorCode::PolicyStoreUnavailable | ErrorCode::RecordingUnavailable => {
                StatusCode::SERVICE_UNAVAILABLE
            }
            ErrorCode::ClientProtocolUnsupported => StatusCode::UPGRADE_REQUIRED,
            ErrorCode::AuthOrGatewayFailed => StatusCode::BAD_GATEWAY,
            ErrorCode::TicketExpired
            | ErrorCode::TicketUsed
            | ErrorCode::TicketInvalid
            | ErrorCode::TicketStale
            | ErrorCode::TargetHostKeyChanged
            | ErrorCode::TargetHostKeyUnknown
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
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
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
        .route("/admin/users/{id}", get(user).patch(update_user))
        .route("/admin/users/{id}/reset-password", post(reset_password))
        .route("/admin/assets", get(admin_assets).post(create_asset))
        .route("/admin/assets/{id}", get(admin_asset).patch(update_asset))
        .route(
            "/admin/assets/{id}/accounts",
            get(accounts).post(create_account),
        )
        .route("/admin/accounts/{id}", get(account).patch(update_account))
        .route("/admin/accounts/{id}/test", post(test_account))
        .route(
            "/admin/accounts/{id}/credential",
            axum::routing::put(replace_credential),
        )
        .route("/admin/assets/{id}/host-key-scan", post(scan_host_key))
        .route(
            "/admin/assets/{id}/host-keys",
            get(host_keys).post(approve_host_key),
        )
        .route(
            "/admin/assets/{asset}/host-keys/{id}",
            axum::routing::delete(revoke_host_key),
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
        .route("/connection-tickets", post(issue_ticket))
        .route(
            "/integrations/zeroterm/connection-tickets",
            post(issue_ticket),
        )
        .route("/sessions", post(browser::issue_session))
        .route("/sessions/{id}/stream", get(browser::stream))
        .route("/connections", get(connections))
        .route("/connections/{id}", get(connection))
        .route("/connections/{id}/channels", get(channels))
        .route("/connections/{id}/files", get(files::metadata))
        .route("/connections/{id}/files/operations", post(files::operate))
        .route(
            "/connections/{id}/files/content",
            get(files::download)
                .put(files::upload)
                .layer(DefaultBodyLimit::disable()),
        )
        .route("/recordings", get(recordings::list))
        .route("/recordings/{id}", get(recordings::metadata))
        .route("/recordings/{id}/content", get(recordings::content))
        .route("/copy-jobs", get(files::jobs).post(files::create_job))
        .route("/copy-jobs/{id}", get(files::job))
        .route("/copy-jobs/{id}/cancel", post(files::cancel_job))
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
                .route("/auth/refresh", post(browser::refresh)),
        )
        .route("/health/live", get(|| async { "ok" }))
        .route("/health/ready", get(readiness))
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(context))
        .with_state(state)
}
async fn context(mut request: axum::extract::Request, next: Next) -> Response {
    let id = Uuid::new_v4();
    // Upload and replay handlers stream outside the JSON request deadline. Their own
    // bounded I/O and authorization deadlines apply; DB calls retain the 2s budget.
    let streamed = request.method() == axum::http::Method::PUT
        && request.uri().path().ends_with("/files/content")
        || request.method() == axum::http::Method::GET
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
    Json(
        json!({"server_id":state.store.server_id,"protocol_version":1,"websocket_protocol_version":1,"ssh_protocol_version":1,"minimum_client_protocol_version":1,"production_ready":false,
            "recording":{"required":state.recording_required,"format_version":1,"available":state.recording_available},
            "features":{"ssh_terminal":state.backend.is_some() && (!state.recording_required || state.recording_available),"ssh_exec":state.backend.is_some(),"ssh_sftp":state.backend.is_some(),"web_terminal":state.browser.is_some() && (!state.recording_required || state.recording_available),"web_exec":state.browser.is_some() && state.backend.is_some(),"web_sftp":state.browser.is_some() && state.backend.is_some(),"recording_replay":state.recording_available,"copy_jobs":false,"device_sessions":true},
            "gateway":{"id":state.gateway.id,"host":state.gateway.host,"port":state.gateway.port,"public_key":state.gateway_public_key}}),
    )
}
async fn readiness(State(state): State<Arc<ControlApi>>) -> ApiResult<&'static str> {
    if state.shutdown.is_cancelled() || state.recording_required && !state.recording_available {
        return Err(ApiError(ErrorCode::RecordingUnavailable));
    }
    if state.recording_required {
        let recording = state
            .backend
            .as_ref()
            .and_then(|backend| backend.recording_config())
            .ok_or(ApiError(ErrorCode::RecordingUnavailable))?;
        tokio::time::timeout(
            Duration::from_secs(2),
            tokio::task::spawn_blocking(move || {
                bastion_gateway::check_recording_directory(
                    &recording.directory,
                    recording.min_free_bytes,
                )
            }),
        )
        .await
        .map_err(|_| ApiError(ErrorCode::RecordingUnavailable))?
        .map_err(|_| ApiError(ErrorCode::RecordingUnavailable))??;
    }
    state.store.check_identity().await?;
    Ok("ok")
}
async fn me(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({"user":identity.user,"login_session_id":identity.login_session_id,"policy_revision":state.store.policy_revision().await?,"csrf_token":browser::csrf_for_me(&headers)}),
    ))
}
async fn login(
    State(state): State<Arc<ControlApi>>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    body: Result<Json<BrowserLogin>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Response> {
    let mut body = input(body)?;
    let web = browser::web_login(&state, &headers, &body)?;
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
            let result = if web {
                state
                    .store
                    .login_web(&user, &hash, &body.device_label, ctx.id)
                    .await?
            } else {
                state
                    .store
                    .login(&user, &hash, &body.device_label, ctx.id)
                    .await?
            };
            return browser::login_response(&state, result, web);
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAsset {
    name: String,
    host: String,
    port: u16,
    #[serde(default)]
    tags: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAsset {
    name: Option<String>,
    host: Option<String>,
    port: Option<u16>,
    enabled: Option<bool>,
    tags: Option<Vec<String>>,
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
        Json(
            state
                .store
                .create_asset(
                    &actor, &body.name, &body.host, body.port, &body.tags, ctx.id,
                )
                .await?,
        ),
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
            .update_asset(
                &actor,
                id(&value)?,
                revision(&headers)?,
                body.name.as_deref(),
                body.host.as_deref(),
                body.port,
                body.enabled,
                body.tags.as_deref(),
                ctx.id,
            )
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateAccount {
    username: String,
    credential: Credential,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateAccount {
    enabled: Option<bool>,
    username: Option<String>,
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
    if body.username.is_empty()
        || body.username.len() > 128
        || body.username.chars().any(char::is_control)
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let credential = state.validate_credential(body.credential).await?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .create_account(
                    &actor,
                    id(&value)?,
                    &body.username,
                    &credential,
                    &state.keys,
                    ctx.id,
                )
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
    if (body.enabled.is_none() && body.username.is_none())
        || body
            .username
            .as_ref()
            .is_some_and(|v| v.is_empty() || v.len() > 128 || v.chars().any(char::is_control))
    {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    Ok(Json(
        state
            .store
            .update_account(
                &actor,
                id(&value)?,
                revision(&headers)?,
                body.enabled,
                body.username.as_deref(),
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
    let credential = state.validate_credential(input(body)?).await?;
    Ok(Json(
        state
            .store
            .replace_credential(
                &actor,
                id(&value)?,
                revision,
                &credential,
                &state.keys,
                ctx.id,
            )
            .await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostKeyApproval {
    algorithm: String,
    public_key: String,
}
async fn host_keys(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        state
            .store
            .list_page(&identity, Collection::HostKeys(id(&value)?), page)
            .await?,
    ))
}
async fn approve_host_key(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
    body: Result<Json<HostKeyApproval>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<HostKeyView>)> {
    let body = input(body)?;
    if body.public_key.len() > 16384 {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let key = russh::keys::PublicKey::from_openssh(&body.public_key)
        .map_err(|_| ApiError(ErrorCode::InvalidArgument))?;
    let algorithm = key.algorithm().to_string();
    if algorithm != body.algorithm {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    let public = key
        .to_openssh()
        .map_err(|_| ApiError(ErrorCode::InvalidArgument))?;
    let fingerprint = key
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .save_host_key(
                    &actor,
                    id(&value)?,
                    &algorithm,
                    &public,
                    &fingerprint,
                    true,
                    ctx.id,
                )
                .await?,
        ),
    ))
}
async fn revoke_host_key(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path((asset, value)): Path<(String, String)>,
    headers: HeaderMap,
) -> ApiResult<StatusCode> {
    state
        .store
        .revoke_host_key(
            &actor,
            id(&asset)?,
            id(&value)?,
            revision(&headers)?,
            ctx.id,
        )
        .await?;
    Ok(StatusCode::NO_CONTENT)
}
struct ScanClient(Arc<Mutex<Option<russh::keys::PublicKey>>>);
impl russh::client::Handler for ScanClient {
    type Error = russh::Error;
    async fn check_server_key(
        &mut self,
        key: &russh::keys::PublicKey,
    ) -> Result<bool, Self::Error> {
        *self.0.lock().expect("scan key poisoned") = Some(key.clone());
        Ok(false)
    }
}
async fn scan_host_key(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
) -> ApiResult<Json<HostKeyView>> {
    let asset = state.store.asset(id(&value)?).await?;
    let address = state
        .network
        .resolve(&asset.host, asset.port as u16)
        .await?;
    let key = Arc::new(Mutex::new(None));
    let _ = tokio::time::timeout(
        Duration::from_secs(10),
        russh::client::connect(
            Arc::new(russh::client::Config::default()),
            address,
            ScanClient(key.clone()),
        ),
    )
    .await;
    let key = key
        .lock()
        .expect("scan key poisoned")
        .take()
        .ok_or(ApiError(ErrorCode::TargetUnreachable))?;
    let public = key
        .to_openssh()
        .map_err(|_| ApiError(ErrorCode::InternalError))?;
    let algorithm = key.algorithm().to_string();
    let fingerprint = key
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();
    Ok(Json(
        state
            .store
            .save_host_key(
                &actor,
                asset.id,
                &algorithm,
                &public,
                &fingerprint,
                false,
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
    capabilities: Vec<Capability>,
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
    let mut body = input(body)?;
    let mut request = TicketRequest {
        asset_id: body.asset_id,
        account_id: body.account_id,
        capabilities: std::mem::take(&mut body.capabilities),
        purpose: Purpose::Terminal,
    };
    request.validate(&[Capability::Shell, Capability::Exec, Capability::Sftp])?;
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
                    &request.capabilities,
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
async fn issue_ticket(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    body: Result<Json<TicketRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<TicketResponse>)> {
    // Native tickets never accept browser Cookie authentication, even on the alias.
    browser::require_bearer(&headers)?;
    if state.shutdown.is_cancelled() {
        return Err(ApiError(ErrorCode::PolicyStoreUnavailable));
    }
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .issue_ticket(&identity, input(body)?, state.gateway.clone(), ctx.id)
                .await?,
        ),
    ))
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

async fn test_account(
    State(state): State<Arc<ControlApi>>,
    Extension(actor): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    Path(value): Path<String>,
) -> ApiResult<Json<Value>> {
    let account = state.store.account(id(&value)?).await?;
    state
        .store
        .account_test_audit(&actor, account.id, ctx.id, None, false)
        .await?;
    let snapshot = state
        .store
        .account_snapshot(account.asset_id, account.id)
        .await?;
    let public_keys = snapshot
        .keys
        .iter()
        .map(|key| {
            russh::keys::PublicKey::from_openssh(key)
                .map_err(|_| ApiError(ErrorCode::TargetHostKeyUnknown))
        })
        .collect::<ApiResult<Vec<_>>>()?;
    let target = bastion_gateway::Target {
        address: bastion_gateway::TargetEndpoint::Restricted {
            host: snapshot.host,
            port: snapshot.port,
            policy: state.network.clone(),
        },
        username: snapshot.username,
        public_keys,
        auth: bastion_gateway::TargetAuth::Encrypted {
            context: snapshot.context,
            envelope: snapshot.credential,
            keys: state.keys.clone(),
        },
    };
    let result = bastion_gateway::test_target(&target).await;
    state
        .store
        .account_test_audit(&actor, account.id, ctx.id, result.err(), true)
        .await?;
    result?;
    Ok(Json(json!({"authenticated":true})))
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
    capabilities: Option<Vec<Capability>>,
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
    let mut body = input(body)?;
    if body.capabilities.is_none() && body.enabled.is_none() && body.expires_at.is_none() {
        return Err(ApiError(ErrorCode::InvalidArgument));
    }
    if let Some(caps) = &mut body.capabilities {
        if caps.is_empty() || caps.len() > 3 {
            return Err(ApiError(ErrorCode::InvalidArgument));
        }
        caps.sort();
        caps.dedup();
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
                body.capabilities.as_deref(),
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
async fn channels(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<Value>> {
    Ok(Json(
        json!({"items":state.store.channel_queries(&identity, id(&value)?).await?}),
    ))
}
