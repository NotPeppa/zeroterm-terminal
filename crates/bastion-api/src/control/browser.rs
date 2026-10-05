use super::*;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::http::{Method, Uri};
use bastion_gateway::{GatewayBackend, Target, TargetAuth, TargetEndpoint};
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

#[derive(Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ClientType {
    Web,
    #[default]
    Zeroterm,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserLogin {
    pub username: String,
    pub password: String,
    pub device_label: String,
    #[serde(default)]
    pub client_type: ClientType,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserRefresh {
    pub refresh_token: Option<String>,
}

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
pub(super) fn require_bearer(headers: &HeaderMap) -> ApiResult<()> {
    if headers.contains_key(header::COOKIE)
        || headers.get_all(header::AUTHORIZATION).iter().count() != 1
        || !headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|v| v.strip_prefix("Bearer ").is_some_and(valid_secret))
    {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    Ok(())
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
pub fn login_response(state: &ControlApi, result: LoginResponse, web: bool) -> ApiResult<Response> {
    if !web {
        return Ok(Json(result).into_response());
    }
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
    if request
        .headers()
        .get_all(header::AUTHORIZATION)
        .iter()
        .count()
        > 1
    {
        return ApiError(ErrorCode::Unauthenticated).into_response();
    }
    let authorization = request.headers().get(header::AUTHORIZATION);
    let browser_token = cookie(request.headers(), ACCESS);
    let web = browser_token.is_some()
        || request
            .headers()
            .get_all(header::COOKIE)
            .iter()
            .any(|h| h.to_str().is_ok_and(|h| h.contains("bastion_session=")));
    if web && authorization.is_some() {
        return ApiError(ErrorCode::Unauthenticated).into_response();
    }
    let token = if web {
        if !matches!(
            *request.method(),
            Method::GET | Method::HEAD | Method::OPTIONS
        ) {
            if let Err(e) = csrf(&state, request.headers()) {
                return e.into_response();
            }
        }
        if let Err(e) = config(&state) {
            return e.into_response();
        }
        browser_token
    } else {
        authorization
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .filter(|v| v.len() <= 256)
            .map(str::to_owned)
    };
    let Some(token) = token else {
        return ApiError(ErrorCode::Unauthenticated).into_response();
    };
    if !web
        && request.method() == Method::POST
        && request
            .extensions()
            .get::<axum::extract::OriginalUri>()
            .is_some_and(|uri| uri.0.path() == "/api/v1/auth/logout")
    {
        match state.store.logout_completed(&token).await {
            Ok(true) => return StatusCode::NO_CONTENT.into_response(),
            Err(code) => return ApiError(code).into_response(),
            Ok(false) => {}
        }
    }
    let identity = if web {
        state.store.authenticate_web(&token).await
    } else {
        state.store.authenticate(&token).await
    };
    match identity {
        Ok(identity) => {
            request.extensions_mut().insert(identity);
            next.run(request).await
        }
        Err(code) => {
            let mut response = ApiError(code).into_response();
            if web
                && matches!(
                    code,
                    ErrorCode::LoginSessionRevoked | ErrorCode::UserDisabled
                )
            {
                clear_cookies(&state, &mut response);
            }
            response
        }
    }
}
pub fn web_login(state: &ControlApi, headers: &HeaderMap, body: &BrowserLogin) -> ApiResult<bool> {
    let web = matches!(body.client_type, ClientType::Web);
    if web {
        csrf(state, headers)?;
    }
    // A browser must never accidentally receive the native token response.
    if !web && (headers.contains_key(header::ORIGIN) || headers.contains_key(header::COOKIE)) {
        return Err(ApiError(ErrorCode::PermissionDenied));
    }
    Ok(web)
}
pub async fn refresh(
    State(state): State<Arc<ControlApi>>,
    Extension(ctx): Extension<RequestContext>,
    headers: HeaderMap,
    body: Result<Json<BrowserRefresh>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<Response> {
    let body = input(body)?;
    let web = cookie(&headers, REFRESH).is_some() || headers.contains_key(header::ORIGIN);
    if web {
        csrf(&state, &headers)?;
    }
    if !state.hit(format!("refresh:{}", ctx.ip), 30) {
        return Err(ApiError(ErrorCode::RateLimited));
    }
    let token = if web {
        if body.refresh_token.is_some() {
            return Err(ApiError(ErrorCode::InvalidArgument));
        }
        cookie(&headers, REFRESH)
    } else {
        body.refresh_token
    };
    let token = Secret::new(token.ok_or(ApiError(ErrorCode::Unauthenticated))?);
    if token.expose().len() > 256 {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    let result = if web {
        state.store.refresh_web(token.expose(), ctx.id).await
    } else {
        state.store.refresh(token.expose(), ctx.id).await
    };
    match result {
        Ok(result) => login_response(&state, result, web),
        Err(code) => {
            let mut response = ApiError(code).into_response();
            if web
                && !matches!(
                    code,
                    ErrorCode::PolicyStoreUnavailable | ErrorCode::RateLimited
                )
            {
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
    body: Result<Json<TicketRequest>, axum::extract::rejection::JsonRejection>,
) -> ApiResult<(StatusCode, Json<WebSessionResponse>)> {
    config(&state)?;
    if cookie(&headers, ACCESS).is_none() || headers.contains_key(header::AUTHORIZATION) {
        return Err(ApiError(ErrorCode::Unauthenticated));
    }
    if state.shutdown.is_cancelled() {
        return Err(ApiError(ErrorCode::PolicyStoreUnavailable));
    }
    let mut request = input(body)?;
    request.validate(&[Capability::Shell, Capability::Exec, Capability::Sftp])?;
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
    if protocols.len() != 2 || protocols[0] != "bastion.v1" || !valid_secret(protocols[1]) {
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
    // Deliberately uniform rejection for all handshake credential/ownership failures.
    let reject = || ApiError(ErrorCode::Unauthenticated);
    if uri.query().is_some()
        || headers.contains_key(header::AUTHORIZATION)
        || cookie(&headers, ACCESS).is_none()
        || same_origin(&state, &headers).is_err()
    {
        return Err(reject());
    }
    let session_id = Uuid::parse_str(&value).map_err(|_| reject())?;
    let secret = Secret::new(ws_secret(&headers).map_err(|_| reject())?);
    let connection = state
        .store
        .consume_web_session(session_id, secret.expose(), &identity)
        .await
        .map_err(|code| {
            if code == ErrorCode::PolicyStoreUnavailable {
                ApiError(code)
            } else {
                reject()
            }
        })?;
    let snapshot = match state.store.target_snapshot(&connection).await {
        Ok(s) => s,
        Err(code) => {
            let _ = state
                .store
                .transition(connection.id, ConnectionState::Failed, Some(code))
                .await;
            return Err(ApiError(code));
        }
    };
    let public_keys = match snapshot
        .keys
        .iter()
        .map(|k| {
            russh::keys::PublicKey::from_openssh(k).map_err(|_| ErrorCode::TargetHostKeyUnknown)
        })
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(k) => k,
        Err(code) => {
            let _ = state
                .store
                .transition(connection.id, ConnectionState::Failed, Some(code))
                .await;
            return Err(ApiError(code));
        }
    };
    let target = Target {
        address: TargetEndpoint::Restricted {
            host: snapshot.host,
            port: snapshot.port,
            policy: state.network.clone(),
        },
        username: snapshot.username,
        public_keys,
        auth: TargetAuth::Encrypted {
            context: snapshot.context,
            envelope: snapshot.credential,
            keys: state.keys.clone(),
        },
    };
    let backend = browser.backend.clone();
    let stop = browser.shutdown.child_token();
    let store = state.store.clone();
    let id = connection.id;
    Ok(upgrade
        .protocols(["bastion.v1"])
        .max_message_size(96 * 1024)
        .max_frame_size(96 * 1024)
        .on_failed_upgrade(move |_| {
            tokio::spawn(async move {
                let _ = store
                    .transition(
                        id,
                        ConnectionState::Failed,
                        Some(ErrorCode::AuthOrGatewayFailed),
                    )
                    .await;
            });
        })
        .on_upgrade(move |socket| bridge(socket, connection, target, backend, stop))
        .into_response())
}
async fn bridge(
    socket: WebSocket,
    connection: Connection,
    target: Target,
    backend: Arc<dyn GatewayBackend>,
    stop: CancellationToken,
) {
    let (mut sink, mut source) = socket.split();
    let (input_tx, input_rx) = mpsc::channel(8);
    let (output_tx, mut output_rx) = mpsc::channel(8);
    let error_tx = output_tx.clone();
    let gateway = bastion_gateway::run_web_session(
        connection,
        target,
        backend,
        input_rx,
        output_tx,
        stop.clone(),
    );
    let mut read = Box::pin(async move {
        while let Some(message) = source.next().await {
            let frame = match message {
                Ok(Message::Text(text)) => ClientFrame::decode_text(&text),
                Ok(Message::Binary(bytes)) => ClientFrame::decode_binary(&bytes),
                Ok(Message::Close(_)) | Err(_) => break,
                Ok(Message::Ping(_) | Message::Pong(_)) => continue,
            };
            let frame = match frame {
                Ok(frame) => frame,
                Err(code) => {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        error_tx.send(ServerFrame::Control(ServerControl::Error {
                            v: WEBSOCKET_VERSION,
                            channel_id: None,
                            code,
                        })),
                    )
                    .await;
                    break;
                }
            };
            if input_tx.send(frame).await.is_err() {
                break;
            }
        }
    });
    let mut write = Box::pin(async move {
        while let Some(frame) = output_rx.recv().await {
            let message = match &frame {
                ServerFrame::Control(_) => frame.encode_text().map(|s| Message::Text(s.into())),
                ServerFrame::Data { .. } => {
                    frame.encode_binary().map(|b| Message::Binary(b.into()))
                }
            };
            let Ok(message) = message else { break };
            if sink.send(message).await.is_err() {
                break;
            }
        }
        let _ = sink.close().await;
    });
    tokio::pin!(gateway);
    let finished = tokio::select! {
        _=&mut gateway=>0, _=&mut read=>1, _=&mut write=>2, _=stop.cancelled()=>3,
    };
    // Drop the reader and its error sender before draining, so the output receiver can close.
    drop(read);
    if finished == 0 {
        let _ = tokio::time::timeout(Duration::from_secs(2), &mut write).await;
        stop.cancel();
    } else {
        stop.cancel();
        if finished == 2 {
            let _ = tokio::time::timeout(Duration::from_secs(8), &mut gateway).await;
        } else {
            let _ = tokio::time::timeout(Duration::from_secs(8), async {
                let _ = tokio::join!(&mut gateway, &mut write);
            })
            .await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formal_native_ticket_requires_one_bearer_and_no_cookie() {
        let mut headers = HeaderMap::new();
        assert!(require_bearer(&headers).is_err());
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "a".repeat(43)).parse().unwrap(),
        );
        assert!(require_bearer(&headers).is_ok());
        headers.append(
            header::AUTHORIZATION,
            format!("Bearer {}", "b".repeat(43)).parse().unwrap(),
        );
        assert!(require_bearer(&headers).is_err());
        headers.remove(header::AUTHORIZATION);
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {}", "a".repeat(43)).parse().unwrap(),
        );
        headers.insert(header::COOKIE, "unrelated=value".parse().unwrap());
        assert!(require_bearer(&headers).is_err());
    }
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
        let response = BrowserLogin {
            username: "u".into(),
            password: "p".into(),
            device_label: "d".into(),
            client_type: ClientType::Web,
        };
        assert!(matches!(response.client_type, ClientType::Web));
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
            format!("bastion.v1, {token}").parse().unwrap(),
        );
        assert_eq!(ws_secret(&h).unwrap(), token);
        for value in [
            "bastion.v1",
            "bastion.v2, wrong",
            "bastion.v1, secret, extra",
        ] {
            h.insert(header::SEC_WEBSOCKET_PROTOCOL, value.parse().unwrap());
            assert!(ws_secret(&h).is_err());
        }
    }
}
