use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

#[test]
fn exact_account_grants_reject_removed_fields_and_preserve_nullable_expiry() {
    let base =
        json!({"user_id":Uuid::new_v4(),"asset_id":Uuid::new_v4(),"account_id":Uuid::new_v4()});
    assert!(serde_json::from_value::<CreateGrant>(base.clone()).is_ok());
    for removed in ["capabilities", "purpose", "transport"] {
        let mut value = base.clone();
        value[removed] = json!(["shell"]);
        assert!(serde_json::from_value::<CreateGrant>(value).is_err());
    }
    let update: UpdateGrant = serde_json::from_value(json!({"enabled":true})).unwrap();
    assert!(update.expires_at.is_none());
    let clear: UpdateGrant = serde_json::from_value(json!({"expires_at":null})).unwrap();
    assert_eq!(clear.expires_at, Some(None));
    assert!(serde_json::from_value::<UpdateGrant>(json!({"capabilities":null})).is_err());
}

#[test]
fn user_mutation_if_match_keeps_428_and_400_contract() {
    let mut headers = HeaderMap::new();
    assert_eq!(
        revision(&headers).unwrap_err().into_response().status(),
        StatusCode::PRECONDITION_REQUIRED
    );
    for value in ["1", "W/\"1\"", "\"0\"", "\"-1\"", "\"bad\"", "\"1\",\"2\""] {
        headers.insert(header::IF_MATCH, HeaderValue::from_str(value).unwrap());
        assert_eq!(
            revision(&headers).unwrap_err().into_response().status(),
            StatusCode::BAD_REQUEST,
            "{value}"
        );
    }
    headers.insert(header::IF_MATCH, HeaderValue::from_static("\"7\""));
    assert_eq!(revision(&headers).unwrap(), 7);
}

#[tokio::test]
async fn error_envelope_keeps_one_request_id_and_safe_code() {
    let app = Router::new()
        .route(
            "/fail",
            get(|| async { ApiError(ErrorCode::PolicyStoreUnavailable) }),
        )
        .layer(middleware::from_fn(context));
    let response = app
        .oneshot(Request::builder().uri("/fail").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    assert!(Uuid::parse_str(&request_id).is_ok());
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["request_id"], request_id);
    assert_eq!(body["error"]["code"], "POLICY_STORE_UNAVAILABLE");
}
#[tokio::test]
async fn body_limit_rejections_are_correlated_not_secret_logs() {
    async fn limited(
        body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
    ) -> ApiResult<Json<Value>> {
        Ok(Json(input(body)?))
    }
    let app = Router::new()
        .route("/body", post(limited))
        .layer(DefaultBodyLimit::max(8))
        .layer(middleware::from_fn(context));
    let response = app
        .oneshot(
            Request::builder()
                .uri("/body")
                .method("POST")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"secret":"neverlog"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert!(response.status().is_client_error());
    let request_id = response.headers()["x-request-id"]
        .to_str()
        .unwrap()
        .to_owned();
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(body["error"]["request_id"], request_id);
    assert!(!String::from_utf8_lossy(&bytes).contains("neverlog"));
}

#[cfg(unix)]
/// Routing-only state: the lazy pool never connects, so every assertion below is decided before the store.
fn offline_api(native: Option<NativeGateway>) -> Arc<ControlApi> {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("bastion-api-test-{}", Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let kek = dir.join("kek-v1");
    std::fs::write(&kek, Secret::random().expose()).unwrap();
    std::fs::set_permissions(&kek, std::fs::Permissions::from_mode(0o600)).unwrap();
    let keys = KeyRing::from_files(1, &std::collections::BTreeMap::from([(1, kek)])).unwrap();
    std::fs::remove_dir_all(&dir).unwrap();
    let store =
        PgStore::connect_lazy("postgres://offline@127.0.0.1:1/none", "test", "main").unwrap();
    let guacd = serde_json::from_value(json!({"address":"127.0.0.1:4822","bridge_bind":"127.0.0.1:0","bridge_advertise_host":"127.0.0.1","allowed_source_ips":["127.0.0.1"],"version":"1.6.0"})).unwrap();
    let network = Arc::new(bastion_gateway::NetworkPolicy {
        allow: vec![],
        deny: vec![],
    });
    let mut api = ControlApi::new(store, Arc::new(keys), network, guacd).unwrap();
    if let Some(native) = native {
        api = api.with_native(native);
    }
    Arc::new(api)
}
#[cfg(unix)]
async fn call(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = app.clone().oneshot(request).await.unwrap();
    let (status, headers) = (response.status(), response.headers().clone());
    let bytes = axum::body::to_bytes(response.into_body(), 65536)
        .await
        .unwrap();
    (
        status,
        headers,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}
#[cfg(unix)]
fn gateway() -> NativeGateway {
    NativeGateway::new(
        "main".into(),
        "bastion.example.com".into(),
        2222,
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHZbpRJIMtxDOgmfuMBMjqc0KTjiTRG/H/N/jegwxgxg".into(),
    )
}

#[cfg(unix)]
#[tokio::test]
async fn info_native_block_is_absent_until_configured_and_honest_about_the_listener() {
    let get = || {
        Request::builder()
            .uri("/api/v1/info")
            .body(Body::empty())
            .unwrap()
    };
    let (status, _, info) = call(&control_router(offline_api(None)), get()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        info.get("native").is_none(),
        "unconfigured listener must omit native"
    );
    assert_eq!(info["production_ready"], false);
    assert_eq!(info["recording"]["format_version"], 2);
    let native = gateway();
    let running = native.listener_running();
    let app = control_router(offline_api(Some(native)));
    for listener in [false, true] {
        running.store(listener, std::sync::atomic::Ordering::Release);
        let (_, _, info) = call(&app, get()).await;
        let block = &info["native"];
        assert_eq!(block["protocol_version"], 1);
        assert_eq!(block["minimum_client_protocol_version"], 1);
        // No gateway backend/recording engine here, so even a running listener is not available.
        assert_eq!(block["available"], false);
        assert_eq!(
            block["gateway"],
            json!({"id":"main","host":"bastion.example.com","port":2222,"public_key":gateway().public_key})
        );
        assert_eq!(
            block["features"],
            json!({"shell":false,"exec":false,"sftp":false})
        );
        assert_eq!(
            info["features"]["web_ssh"], false,
            "browser features are unchanged"
        );
    }
}

/// Stands in for the gateway engine; the routing tests below never reach it.
#[cfg(unix)]
struct IdleBackend;
#[cfg(unix)]
#[async_trait::async_trait]
impl bastion_gateway::GatewayBackend for IdleBackend {
    async fn authorize(&self, _: &Connection) -> Result<(), ErrorCode> {
        Err(ErrorCode::PolicyStoreUnavailable)
    }
    async fn transition(
        &self,
        _: Uuid,
        _: ConnectionState,
        _: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::PolicyStoreUnavailable)
    }
    async fn begin_recording(&self, _: &Connection, _: RecordingCreate) -> Result<(), ErrorCode> {
        Err(ErrorCode::RecordingUnavailable)
    }
    async fn activate_recording(&self, _: &Connection, _: Uuid) -> Result<(), ErrorCode> {
        Err(ErrorCode::RecordingUnavailable)
    }
    async fn checkpoint_recording(&self, _: Uuid, _: i64, _: i64, _: i64) -> Result<(), ErrorCode> {
        Err(ErrorCode::RecordingUnavailable)
    }
    async fn finish_recording(
        &self,
        _: Uuid,
        _: RecordingState,
        _: i64,
        _: Option<String>,
        _: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        Err(ErrorCode::RecordingUnavailable)
    }
}

#[cfg(unix)]
#[tokio::test]
async fn available_native_entry_opens_all_native_capabilities() {
    let native = gateway();
    let running = native.listener_running();
    let mut api = offline_api(Some(native));
    let shutdown = tokio_util::sync::CancellationToken::new();
    {
        let api = Arc::get_mut(&mut api).unwrap();
        api.backend = Some(Arc::new(IdleBackend));
        api.shutdown = shutdown.clone();
    }
    let app = control_router(api.clone());
    let get = || {
        Request::builder()
            .uri("/api/v1/info")
            .body(Body::empty())
            .unwrap()
    };
    // Recording is not required here, so a running listener with an engine is available.
    running.store(true, std::sync::atomic::Ordering::Release);
    let (_, _, info) = call(&app, get()).await;
    assert_eq!(info["native"]["available"], true);
    assert_eq!(
        info["native"]["features"],
        json!({"shell":true,"exec":true,"sftp":true})
    );
    assert_eq!(native::capabilities(&api).await, ["shell", "exec", "sftp"]);
    // One availability rule: a stopped listener or a draining server closes every capability.
    running.store(false, std::sync::atomic::Ordering::Release);
    let (_, _, info) = call(&app, get()).await;
    assert_eq!(
        info["native"]["features"],
        json!({"shell":false,"exec":false,"sftp":false})
    );
    assert!(native::capabilities(&api).await.is_empty());
    running.store(true, std::sync::atomic::Ordering::Release);
    shutdown.cancel();
    let (_, _, info) = call(&app, get()).await;
    assert_eq!(info["native"]["available"], false);
    assert_eq!(
        info["native"]["features"],
        json!({"shell":false,"exec":false,"sftp":false})
    );
    assert!(native::capabilities(&api).await.is_empty());
}

#[cfg(unix)]
#[tokio::test]
async fn native_and_browser_credentials_never_cross_routes() {
    let token = "a".repeat(43);
    let app = control_router(offline_api(Some(gateway())));
    // A browser cookie (and CSRF/Origin) on a native route is ignored: no Bearer means 401.
    for (method, path) in [
        ("GET", "/api/v1/native/assets"),
        ("POST", "/api/v1/native/connection-tickets"),
        (
            "GET",
            "/api/v1/native/connections/00000000-0000-0000-0000-000000000001",
        ),
        ("POST", "/api/v1/native/auth/logout"),
    ] {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header(
                header::COOKIE,
                format!("bastion_session={token}; bastion_csrf={token}"),
            )
            .header(header::ORIGIN, "https://bastion.example.com")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, headers, body) = call(&app, request).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{path}");
        assert_eq!(body["error"]["code"], "UNAUTHENTICATED");
        assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
        assert!(headers.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).is_none());
        assert!(headers.get(header::SET_COOKIE).is_none());
    }
    // A Bearer token on any browser route is rejected before any lookup.
    for path in ["/api/v1/me", "/api/v1/assets", "/api/v1/connections/x"] {
        let request = Request::builder()
            .uri(path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::COOKIE, format!("bastion_session={token}"))
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            call(&app, request).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    // Strict native bodies: removed/unknown fields fail before credentials are checked.
    for (path, body) in [
        (
            "/api/v1/native/auth/login",
            json!({"username":"u","password":"p","device_label":"d","client_type":"native"}),
        ),
        (
            "/api/v1/native/auth/refresh",
            json!({"refresh_token":token,"client_type":"native"}),
        ),
        ("/api/v1/native/auth/refresh", json!({})),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        assert_eq!(
            call(&app, request).await.0,
            StatusCode::BAD_REQUEST,
            "{path} {body}"
        );
    }
    // Native routes do not exist while the listener is not configured.
    let app = control_router(offline_api(None));
    let request = Request::builder()
        .method("POST")
        .uri("/api/v1/native/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"username":"u","password":"p","device_label":"d"}).to_string(),
        ))
        .unwrap();
    assert_eq!(call(&app, request).await.0, StatusCode::NOT_FOUND);
}
