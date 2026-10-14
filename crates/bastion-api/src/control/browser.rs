use super::*;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{Method, Uri};
use bastion_gateway::{GatewayBackend, Target};
use bastion_secrets::matches_hash;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

const ACCESS: &str = "bastion_session";
const REFRESH: &str = "bastion_refresh";
const CSRF: &str = "bastion_csrf";
const CSRF_HEADER: &str = "x-bastion-csrf";

pub struct BrowserConfig {
    pub origin: String,
    pub secure: bool,
    pub backend: Arc<dyn GatewayBackend>,
    pub shutdown: CancellationToken,
}
impl BrowserConfig {
    pub fn new(
        origin: String,
        backend: Arc<dyn GatewayBackend>,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        let secure = validate_origin(&origin)?;
        Ok(Self {
            origin: origin.trim_end_matches('/').into(),
            secure,
            backend,
            shutdown,
        })
    }
}
fn validate_origin(origin: &str) -> anyhow::Result<bool> {
    let uri: Uri = origin.parse()?;
    let scheme = uri.scheme_str().unwrap_or("");
    let host = uri.host().unwrap_or("");
    let loopback = host == "localhost"
        || host
            .trim_matches(['[', ']'])
            .parse::<IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    if uri.authority().is_none()
        || uri.authority().is_some_and(|a| a.as_str().contains('@'))
        || uri.path_and_query().is_some_and(|p| p.as_str() != "/")
        || !(scheme == "https" || scheme == "http" && loopback)
    {
        anyhow::bail!("browser origin must be HTTPS or explicit loopback HTTP without a path");
    }
    Ok(scheme == "https")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLogin {
    pub username: String,
    pub password: String,
    pub device_label: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRefresh {}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for entry in value.to_str().ok()?.split(';') {
            let (key, value) = entry.trim().split_once('=')?;
            if key == name {
                // Ambiguous duplicates fail closed rather than pick a proxy-dependent value.
                if found.is_some() || !valid_secret(value) {
                    return None;
                }
                found = Some(value.to_owned());
            }
        }
    }
    found
}
fn valid_secret(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}
fn config(state: &ControlApi) -> ApiResult<&BrowserConfig> {
    state
        .browser
        .as_ref()
        .ok_or(ApiError(ErrorCode::PermissionDenied))
}
fn same_origin(state: &ControlApi, headers: &HeaderMap) -> ApiResult<()> {
    check_origin(&config(state)?.origin, headers)
}
fn check_origin(origin: &str, headers: &HeaderMap) -> ApiResult<()> {
    if headers.get_all(header::ORIGIN).iter().count() != 1
        || headers.get(header::ORIGIN).and_then(|v| v.to_str().ok()) != Some(origin)
    {
        return Err(ApiError(ErrorCode::PermissionDenied));
    }
    Ok(())
}
fn csrf(state: &ControlApi, headers: &HeaderMap) -> ApiResult<()> {
    check_csrf(&config(state)?.origin, headers)
}
fn check_csrf(origin: &str, headers: &HeaderMap) -> ApiResult<()> {
    check_origin(origin, headers)?;
    let token = cookie(headers, CSRF).ok_or(ApiError(ErrorCode::PermissionDenied))?;
    let supplied = headers
        .get(CSRF_HEADER)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if headers.get_all(CSRF_HEADER).iter().count() != 1
        || !matches_hash(&bastion_secrets::hash(&token), supplied)
    {
        return Err(ApiError(ErrorCode::PermissionDenied));
    }
    Ok(())
}
fn set_cookie(
    response: &mut Response,
    name: &str,
    value: &str,
    http_only: bool,
    secure: bool,
    max_age: i64,
) {
    let value = format!(
        "{name}={value}; Path=/; SameSite=Strict; Max-Age={max_age}{}{}",
        if http_only { "; HttpOnly" } else { "" },
        if secure { "; Secure" } else { "" }
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&value).expect("generated cookie"),
    );
}
pub fn clear_cookies(state: &ControlApi, response: &mut Response) {
    if let Some(browser) = &state.browser {
        for name in [ACCESS, REFRESH, CSRF] {
            set_cookie(response, name, "", true, browser.secure, 0);
        }
    }
}
pub fn login_response(state: &ControlApi, result: LoginResponse) -> ApiResult<Response> {
    let browser = config(state)?;
    let now = Utc::now();
    let mut response = Json(json!({"user":result.user,"login_session_id":result.login_session_id,"access_expires_at":result.access_expires_at,"refresh_expires_at":result.refresh_expires_at})).into_response();
    // Keep expired access cookies until family expiry so /me can explain access expiry.
    let remaining = (result.refresh_expires_at - now).num_seconds().max(0);
    set_cookie(
        &mut response,
        ACCESS,
        &result.access_token,
        true,
        browser.secure,
        remaining,
    );
    set_cookie(
        &mut response,
        REFRESH,
        &result.refresh_token,
        true,
        browser.secure,
        remaining,
    );
    Ok(response)
}
pub async fn csrf_token(
    State(state): State<Arc<ControlApi>>,
    headers: HeaderMap,
) -> ApiResult<Response> {
    let browser = config(&state)?;
    if headers.contains_key(header::ORIGIN) {
        same_origin(&state, &headers)?;
    }
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| !matches!(v, "same-origin" | "none"))
    {
        return Err(ApiError(ErrorCode::PermissionDenied));
    }
    let token = cookie(&headers, CSRF).unwrap_or_else(|| Secret::random().expose().to_owned());
    let mut response = Json(json!({"csrf_token":token})).into_response();
    set_cookie(
        &mut response,
        CSRF,
        &token,
        false,
        browser.secure,
        7 * 24 * 3600,
    );
    Ok(response)
}
pub async fn authenticate(
    State(state): State<Arc<ControlApi>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    // The API has no native/Bearer branch. Ambiguous cookies fail closed.
    if request.headers().contains_key(header::AUTHORIZATION) {
        return ApiError(ErrorCode::Unauthenticated).into_response();
    }
    if let Err(error) = config(&state) {
        return error.into_response();
    }
    let Some(token) = cookie(request.headers(), ACCESS) else {
        return ApiError(ErrorCode::Unauthenticated).into_response();
    };
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        if let Err(error) = csrf(&state, request.headers()) {
            return error.into_response();
        }
    }
    match state.store.authenticate_web(&token).await {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(code) => {
            let mut response = ApiError(code).into_response();
            if matches!(
                code,
                ErrorCode::LoginSessionRevoked | ErrorCode::UserDisabled
            ) {
                clear_cookies(&state, &mut response);
            }
            response
        }
    }
}
pub fn web_login(state: &ControlApi, headers: &HeaderMap) -> ApiResult<()> {
    if headers.contains_key(header::AUTHORIZATION) {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    csrf(state, headers)
}
pub async fn refresh(
    State(state): State<Arc<ControlApi>>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    body: Result<Json<BrowserRefresh>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Response> {
    let _ = input(body)?;
    web_login(&state, &headers)?;
    if !state.hit(format!("refresh:{}", ctx.ip), 30) {
        return Err(ApiError(ErrorCode::RateLimited));
    }
    let token = Secret::new(cookie(&headers, REFRESH).ok_or(ApiError(ErrorCode::Unauthenticated))?);
    match state.store.refresh_web(token.expose(), ctx.id).await {
        Ok(result) => login_response(&state, result),
        Err(code) => {
            let mut response = ApiError(code).into_response();
            if !matches!(
                code,
                ErrorCode::PolicyStoreUnavailable | ErrorCode::RateLimited
            ) {
                clear_cookies(&state, &mut response);
            }
            Ok(response)
        }
    }
}
pub fn csrf_for_me(headers: &HeaderMap) -> Option<String> {
    cookie(headers, CSRF)
}
pub async fn issue_session(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    body: Result<Json<SessionRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<WebSessionResponse>)> {
    config(&state)?;
    if cookie(&headers, ACCESS).is_none() || headers.contains_key(header::AUTHORIZATION) {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    if state.shutdown.is_cancelled() {
        return Err(ApiError(ErrorCode::PolicyStoreUnavailable));
    }
    if state.recording_required && !state.recording_available {
        return Err(ApiError(ErrorCode::RecordingUnavailable));
    }
    let request = input(body)?;
    request.display.validate()?;
    Ok((
        StatusCode::CREATED,
        Json(
            state
                .store
                .issue_web_session(&identity, request, ctx.id)
                .await?,
        ),
    ))
}
fn ws_secret(headers: &HeaderMap) -> ApiResult<String> {
    let values: Vec<_> = headers
        .get_all(header::SEC_WEBSOCKET_PROTOCOL)
        .iter()
        .map(|v| v.to_str())
        .collect::<Result<_, _>>()
        .map_err(|_| ApiError(ErrorCode::Unauthenticated))?;
    let protocols: Vec<_> = values
        .iter()
        .flat_map(|v| v.split(',').map(str::trim))
        .collect();
    if protocols.len() != 2
        || ![STREAM_PROTOCOL, SSH_STREAM_PROTOCOL].contains(&protocols[0])
        || !valid_secret(protocols[1])
    {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    Ok(protocols[1].to_owned())
}
pub async fn stream(
    State(state): State<Arc<ControlApi>>,
    Extension(identity): Extension<Identity>,
    Path(value): Path<String>,
    headers: HeaderMap,
    uri: Uri,
    upgrade: WebSocketUpgrade,
) -> ApiResult<Response> {
    let browser = config(&state)?;
    let reject = || ApiError(ErrorCode::Unauthenticated);
    if uri.query().is_some()
        || headers.contains_key(header::AUTHORIZATION)
        || cookie(&headers, ACCESS).is_none()
        || same_origin(&state, &headers).is_err()
        || state.shutdown.is_cancelled()
    {
        return Err(reject());
    }
    let secret = Secret::new(ws_secret(&headers)?);
    let requested_protocol = headers
        .get(header::SEC_WEBSOCKET_PROTOCOL)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .map(str::trim)
        .ok_or_else(reject)?;
    let connection = state
        .store
        .consume_web_session_with_stream(
            id(&value).map_err(|_| reject())?,
            secret.expose(),
            &identity,
            Some(requested_protocol),
        )
        .await
        .map_err(|_| reject())?;
    // Consumption is committed before any network work and is never undone on failure.
    let target = match state.target(&connection).await {
        Ok(target) => target,
        Err(code) => {
            let _ = state
                .store
                .transition(connection.id, ConnectionState::Failed, Some(code))
                .await;
            return Err(ApiError(code));
        }
    };
    let backend = browser.backend.clone();
    let shutdown = browser.shutdown.clone();
    let guacd = state.guacd.clone();
    let failed_store = state.store.clone();
    let connection_id = connection.id;
    let stream_protocol = connection.target_protocol.stream_protocol();
    Ok(upgrade
        .protocols([stream_protocol])
        .max_message_size(MAX_DATA_BYTES)
        .max_frame_size(MAX_DATA_BYTES)
        .on_failed_upgrade(move |_| {
            tokio::spawn(async move {
                let _ = failed_store
                    .transition(
                        connection_id,
                        ConnectionState::Failed,
                        Some(ErrorCode::AuthOrGatewayFailed),
                    )
                    .await;
            });
        })
        .on_upgrade(move |socket| run_socket(socket, connection, target, backend, shutdown, guacd)))
}
async fn run_socket(
    socket: WebSocket,
    connection: Connection,
    target: Target,
    backend: Arc<dyn GatewayBackend>,
    shutdown: CancellationToken,
    guacd: bastion_gateway::GuacdConfig,
) {
    let stop = shutdown.child_token();
    // Queue count times maximum chunk is a hard byte bound (256 KiB per direction).
    let capacity = (backend.registry().limits().queue_bytes / MAX_DATA_BYTES).max(1);
    let stall_timeout = backend.registry().limits().stall_timeout;
    let (input, incoming) = mpsc::channel::<Vec<u8>>(capacity);
    let (outgoing, mut output) = mpsc::channel::<Vec<u8>>(capacity);
    let (mut sink, mut source) = socket.split();
    let read_stop = stop.clone();
    let closing = CancellationToken::new();
    let read_closing = closing.clone();
    let mut read = tokio::spawn(async move {
        loop {
            let message = tokio::select! { _ = read_stop.cancelled() => break, value = source.next() => value };
            match message {
                Some(Ok(Message::Binary(data)))
                    if !data.is_empty() && data.len() <= MAX_DATA_BYTES =>
                {
                    let sent = tokio::select! {
                        _ = read_stop.cancelled() => break,
                        value = tokio::time::timeout(stall_timeout, input.send(data.to_vec())) => value
                    };
                    if !matches!(sent, Ok(Ok(()))) {
                        break;
                    }
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Close(Some(frame)))) if frame.code == 1000 => {
                    read_closing.cancel();
                    return true; // Drop input sender: drain queued instructions, then validate EOF.
                }
                _ => break,
            }
        }
        read_stop.cancel();
        false
    });
    let write_stop = stop.clone();
    let write_closing = closing.clone();
    let mut write = tokio::spawn(async move {
        loop {
            let data = tokio::select! { _ = write_stop.cancelled() => break, value = output.recv() => value };
            let Some(data) = data else {
                break;
            };
            if data.len() > MAX_DATA_BYTES {
                break;
            }
            if write_closing.is_cancelled() {
                continue;
            }
            let sent = tokio::select! {
                _ = write_stop.cancelled() => break,
                value = tokio::time::timeout(stall_timeout, sink.send(Message::Binary(data.into()))) => value
            };
            if !matches!(sent, Ok(Ok(()))) && !write_closing.is_cancelled() {
                break;
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), sink.close()).await;
        if !write_closing.is_cancelled() {
            write_stop.cancel();
        }
    });
    let gateway_stop = stop.clone();
    let mut gateway = tokio::spawn(bastion_gateway::run_web_session(
        connection,
        target,
        backend,
        incoming,
        outgoing,
        gateway_stop,
        guacd,
    ));
    let (finished, graceful) = tokio::select! {
        _ = shutdown.cancelled() => (0, false),
        result = &mut read => (1, matches!(result, Ok(true))),
        _ = &mut write => (2, false),
        _ = &mut gateway => (3, false)
    };
    if !graceful {
        stop.cancel();
    }
    if finished != 3
        && tokio::time::timeout(Duration::from_secs(8), &mut gateway)
            .await
            .is_err()
    {
        stop.cancel();
        gateway.abort();
        let _ = gateway.await;
    }
    stop.cancel();
    if finished != 1 {
        read.abort();
        let _ = read.await;
    }
    if finished != 2 {
        write.abort();
        let _ = write.await;
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browser_origin_requires_https_or_explicit_loopback() {
        for origin in ["https://bastion.test", "https://bastion.test:8443/"] {
            assert!(validate_origin(origin).unwrap());
        }
        for origin in [
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://[::1]:5173",
        ] {
            assert!(!validate_origin(origin).unwrap());
        }
        for origin in [
            "http://bastion.test",
            "https://user@bastion.test",
            "https://bastion.test/path",
            "https://bastion.test/?token=x",
            "ws://127.0.0.1",
            "//bastion.test",
        ] {
            assert!(validate_origin(origin).is_err(), "accepted {origin}");
        }
    }
    #[test]
    fn origin_csrf_and_cookie_security_fail_closed() {
        let origin = "https://bastion.test";
        let token = "a".repeat(43);
        let mut headers = HeaderMap::new();
        assert!(check_origin(origin, &headers).is_err());
        headers.insert(header::ORIGIN, origin.parse().unwrap());
        assert!(check_csrf(origin, &headers).is_err());
        headers.insert(
            header::COOKIE,
            format!("bastion_csrf={token}").parse().unwrap(),
        );
        headers.insert(CSRF_HEADER, token.parse().unwrap());
        assert!(check_csrf(origin, &headers).is_ok());
        headers.insert(CSRF_HEADER, "wrong".parse().unwrap());
        assert!(check_csrf(origin, &headers).is_err());
        headers.insert(CSRF_HEADER, token.parse().unwrap());
        headers.append(header::ORIGIN, origin.parse().unwrap());
        assert!(check_csrf(origin, &headers).is_err());
        let mut response = StatusCode::OK.into_response();
        set_cookie(&mut response, ACCESS, &token, true, true, 60);
        let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
        assert!(
            cookie.contains("HttpOnly")
                && cookie.contains("Secure")
                && cookie.contains("SameSite=Strict")
        );
        assert!(!cookie.contains("Domain="));
        assert!(serde_json::from_str::<BrowserLogin>(
            r#"{"username":"u","password":"p","device_label":"d","host":"target"}"#
        )
        .is_err());
    }
    #[test]
    fn cookies_reject_duplicates_and_subprotocol_has_no_fallback() {
        let token = "a".repeat(43);
        let mut h = HeaderMap::new();
        h.insert(
            header::COOKIE,
            format!("bastion_session={token}; bastion_csrf={token}")
                .parse()
                .unwrap(),
        );
        assert_eq!(cookie(&h, ACCESS), Some(token.clone()));
        h.append(
            header::COOKIE,
            format!("bastion_session={token}").parse().unwrap(),
        );
        assert!(cookie(&h, ACCESS).is_none());
        h.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            format!("bastion.guac.v1, {token}").parse().unwrap(),
        );
        assert_eq!(ws_secret(&h).unwrap(), token);
        h.insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            format!("bastion.ssh.v1, {token}").parse().unwrap(),
        );
        assert_eq!(ws_secret(&h).unwrap(), token);
        for value in [
            "bastion.guac.v1",
            "bastion.v1, wrong",
            "bastion.guac.v1, secret, extra",
        ] {
            h.insert(header::SEC_WEBSOCKET_PROTOCOL, value.parse().unwrap());
            assert!(ws_secret(&h).is_err());
        }
    }
    #[test]
    fn browser_login_rejects_native_type_and_refresh_token() {
        assert!(serde_json::from_str::<BrowserLogin>(
            r#"{"username":"u","password":"p","device_label":"d","client_type":"web"}"#
        )
        .is_err());
        assert!(serde_json::from_str::<BrowserRefresh>(r#"{"refresh_token":"secret"}"#).is_err());
    }
}
