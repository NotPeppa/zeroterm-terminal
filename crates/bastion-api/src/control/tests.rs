use super::*;
use axum::{body::Body, http::Request};
use tower::ServiceExt;

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
