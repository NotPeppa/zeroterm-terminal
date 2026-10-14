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
