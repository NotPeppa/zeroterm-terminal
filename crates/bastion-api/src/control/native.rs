//! RFC-006 native ZeroTerm entry: Bearer-only `/api/v1/native/*`. Cookies are never read here, no
//! Origin/CSRF is required and no CORS header is sent; browser routes keep rejecting Authorization.
use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// Public identity of the native SSH gateway, configured at startup.
#[derive(Clone)]
pub struct NativeGateway {
    pub id: String,
    pub host: String,
    pub port: u16,
    /// OpenSSH public line of the gateway host key, `ssh-ed25519 AAAA…` without comment.
    pub public_key: String,
    running: Arc<AtomicBool>,
}
impl NativeGateway {
    pub fn new(id: String, host: String, port: u16, public_key: String) -> Self {
        Self {
            id,
            host,
            port,
            public_key,
            running: Arc::new(AtomicBool::new(false)),
        }
    }
    /// Listener liveness hook. The SSH listener stores `true` once it is bound and accepting, and
    /// `false` before it stops; until then `/info.native.available` is false and no ticket is issued.
    pub fn listener_running(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeLogin {
    username: String,
    password: String,
    device_label: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct NativeRefresh {
    refresh_token: String,
}

fn gateway(state: &ControlApi) -> ApiResult<&NativeGateway> {
    state
        .native
        .as_ref()
        .ok_or(ApiError(ErrorCode::ResourceNotFound))
}
/// Same rule as `web_ssh`, plus a running listener: recording, engine and shutdown state are real.
fn available(state: &ControlApi, recording_available: bool) -> bool {
    state.native.as_ref().is_some_and(|native| {
        native.running.load(Ordering::Acquire)
            && state.backend.is_some()
            && (!state.recording_required || recording_available)
            && !state.shutdown.is_cancelled()
    })
}
async fn recording_available(state: &ControlApi) -> bool {
    state.recording_available
        && !state.shutdown.is_cancelled()
        && recording_ready(state).await.is_ok()
}
/// `/info.native`, absent when the listener is not configured.
pub(super) fn info(state: &ControlApi, recording_available: bool) -> Option<Value> {
    let native = state.native.as_ref()?;
    let open = available(state, recording_available);
    let feature = |name: &str| open && NATIVE_CAPABILITIES.contains(&name);
    Some(json!({
        "protocol_version": NATIVE_PROTOCOL_VERSION,
        "minimum_client_protocol_version": NATIVE_PROTOCOL_VERSION,
        "available": open,
        "gateway": {"id": native.id, "host": native.host, "port": native.port, "public_key": native.public_key},
        // Every open capability shares the shell availability rule (RFC-006 §14.1).
        "features": {"shell": feature("shell"), "exec": feature("exec"), "sftp": feature("sftp")},
    }))
}
pub(super) async fn enabled(
    State(state): State<Arc<ControlApi>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    match gateway(&state) {
        Ok(_) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}
fn bearer(headers: &HeaderMap) -> Option<&str> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    let token = value.strip_prefix("Bearer ")?;
    browser::valid_secret(token).then_some(token)
}
fn unauthenticated(code: ErrorCode) -> Response {
    let mut response = ApiError(code).into_response();
    response
        .headers_mut()
        .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}
pub(super) async fn authenticate(
    State(state): State<Arc<ControlApi>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    // Cookies are ignored entirely: a browser session can never reach a native route.
    let Some(token) = bearer(request.headers()).map(str::to_owned) else {
        return unauthenticated(ErrorCode::Unauthenticated);
    };
    match state.store.authenticate_native(&token).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(code) if code == ErrorCode::PolicyStoreUnavailable => ApiError(code).into_response(),
        Err(code) => unauthenticated(code),
    }
}
fn tokens(result: LoginResponse) -> Json<Value> {
    Json(
        json!({"access_token":result.access_token,"refresh_token":result.refresh_token,"access_expires_at":result.access_expires_at}),
    )
}
pub(super) async fn login(
    State(state): State<Arc<ControlApi>>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<NativeLogin>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<Value>> {
    let mut body = input(body)?;
    let (user, hash) = verify_login(
        &state,
        &ctx,
        &body.username,
        std::mem::take(&mut body.password),
        &body.device_label,
    )
    .await?;
    Ok(tokens(
        state
            .store
            .login_native(&user, &hash, &body.device_label, ctx.id)
            .await?,
    ))
}
pub(super) async fn refresh(
    State(state): State<Arc<ControlApi>>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<NativeRefresh>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Json<Value>> {
    let token = Secret::new(input(body)?.refresh_token);
    if !state.hit(format!("refresh:{}", ctx.ip), 30) {
        return Err(ApiError(ErrorCode::RateLimited));
    }
    if !browser::valid_secret(token.expose()) {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    Ok(tokens(
        state.store.refresh_native(token.expose(), ctx.id).await?,
    ))
}
pub(super) async fn logout(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
) -> ApiResult<StatusCode> {
    state.store.logout(&identity, false, ctx.id).await?;
    if let Some(backend) = &state.backend {
        backend.registry().revoke_login(identity.login_session_id);
    }
    Ok(StatusCode::NO_CONTENT)
}
/// Capabilities each `/native/assets` account lists: every open one while the entry is available.
/// Grants are all-or-nothing (RFC-006 §10.1), so this does not vary per account.
pub(super) async fn capabilities(state: &ControlApi) -> &'static [&'static str] {
    if available(state, recording_available(state).await) {
        NATIVE_CAPABILITIES
    } else {
        &[]
    }
}
pub(super) async fn assets(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Query(page): Query<PageRequest>,
) -> ApiResult<Json<Value>> {
    let open = capabilities(&state).await;
    Ok(Json(
        state
            .store
            .native_assets(&identity, None, page, open)
            .await?,
    ))
}
pub(super) async fn asset(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<Value>> {
    if identity.user.role == Role::Auditor {
        return Err(ApiError(ErrorCode::ResourceNotFound));
    }
    let open = capabilities(&state).await;
    let page = state
        .store
        .native_assets(&identity, Some(id(&value)?), PageRequest::default(), open)
        .await?;
    Ok(Json(
        page["items"]
            .as_array()
            .and_then(|items| items.first())
            .cloned()
            .ok_or(ApiError(ErrorCode::ResourceNotFound))?,
    ))
}
pub(super) async fn issue_ticket(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    body: Result<Json<NativeTicketRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    let native = gateway(&state)?;
    let request = input(body)?;
    validate_native_capabilities(&request.capabilities)?;
    if state.shutdown.is_cancelled() {
        return Err(ApiError(ErrorCode::PolicyStoreUnavailable));
    }
    let recording = recording_available(&state).await;
    if state.recording_required && !recording {
        return Err(ApiError(ErrorCode::RecordingUnavailable));
    }
    // A ticket nobody can redeem is never issued.
    if !available(&state, recording) {
        return Err(ApiError(ErrorCode::TargetProtocolUnavailable));
    }
    let issued = state
        .store
        .issue_native_ticket(&identity, request, ctx.id)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "protocol_version": NATIVE_PROTOCOL_VERSION,
            "ticket_id": issued.ticket_id,
            "ticket_secret": issued.ticket_secret,
            "connection_id": issued.connection_id,
            "gateway": {"host": native.host, "port": native.port, "username": format!("zt1:{}", issued.ticket_id)},
            "capabilities": issued.capabilities,
            "expires_at": issued.expires_at,
        })),
    ))
}
pub(super) async fn connection(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
) -> ApiResult<Json<Connection>> {
    Ok(Json(
        state.store.own_connection(&identity, id(&value)?).await?,
    ))
}

/// Redeems `zt1:` tickets for the SSH listener (RFC-006 §4.2). Holds the API so the target snapshot,
/// key ring, network policy and the shared rate map are the ones the HTTP side uses.
pub struct NativeTicketService(pub Arc<ControlApi>);
#[async_trait::async_trait]
impl bastion_gateway::NativeTickets for NativeTicketService {
    async fn redeem(
        &self,
        ticket: Option<Uuid>,
        secret: &str,
        peer: IpAddr,
    ) -> Result<bastion_gateway::NativeTicket, ErrorCode> {
        let state = &self.0;
        // Failed attempts per source IP share the login limiter's 60 s window; failures are audited.
        let key = format!("native-ssh:{peer}");
        let redeemed = match ticket {
            _ if state.exhausted(&key, 10) => Err(ErrorCode::RateLimited),
            Some(id) if browser::valid_secret(secret) => {
                state.store.consume_native_ticket(id, secret, peer).await
            }
            _ => Err(ErrorCode::TicketInvalid),
        };
        let session = match redeemed {
            Ok(session) => session,
            Err(code) => {
                state.hit(key, 10);
                let _ = state.store.native_auth_failure(peer, ticket, code).await;
                return Err(code);
            }
        };
        // Consumption is committed; a target failure ends the connection as failed, like the browser.
        match state.target(&session.connection).await {
            Ok(target) => Ok(bastion_gateway::NativeTicket {
                connection: session.connection,
                capabilities: session.capabilities,
                target,
            }),
            Err(code) => {
                let _ = state
                    .store
                    .transition(session.connection.id, ConnectionState::Failed, Some(code))
                    .await;
                Err(code)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_bodies_are_strict_and_bearer_is_exact() {
        assert!(serde_json::from_str::<NativeLogin>(
            r#"{"username":"u","password":"p","device_label":"d"}"#
        )
        .is_ok());
        for extra in [r#","client_type":"native""#, r#","purpose":"x""#] {
            assert!(serde_json::from_str::<NativeLogin>(&format!(
                r#"{{"username":"u","password":"p","device_label":"d"{extra}}}"#
            ))
            .is_err());
        }
        assert!(serde_json::from_str::<NativeRefresh>(r#"{"refresh_token":"t"}"#).is_ok());
        assert!(serde_json::from_str::<NativeRefresh>(r#"{}"#).is_err());
        assert!(serde_json::from_str::<NativeRefresh>(
            r#"{"refresh_token":"t","client_type":"x"}"#
        )
        .is_err());
        let token = "a".repeat(43);
        let mut headers = HeaderMap::new();
        assert!(bearer(&headers).is_none());
        for bad in [
            format!("bearer {token}"),
            format!("Basic {token}"),
            format!("Bearer {token} "),
            "Bearer short".into(),
        ] {
            headers.insert(header::AUTHORIZATION, HeaderValue::from_str(&bad).unwrap());
            assert!(bearer(&headers).is_none(), "{bad}");
        }
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert_eq!(bearer(&headers), Some(token.as_str()));
        headers.append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        assert!(
            bearer(&headers).is_none(),
            "duplicate Authorization is ambiguous"
        );
    }
}
