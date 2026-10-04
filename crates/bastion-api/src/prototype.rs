use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use bastion_domain::*;
use bastion_secrets::matches_hash;
use bastion_store::PrototypeStore;
use serde_json::json;
use std::sync::Arc;
use uuid::Uuid;

pub struct PrototypeApi {
    pub store: Arc<PrototypeStore>,
    pub bearer_hash: [u8; 32],
    pub server_id: String,
    pub gateway: GatewayAddress,
    pub gateway_public_key: String,
    pub asset_id: Uuid,
    pub account_id: Uuid,
    pub asset_name: String,
    pub target_username: String,
    pub allowed: Vec<Capability>,
}

pub fn router(state: Arc<PrototypeApi>) -> Router {
    Router::new()
        .route("/api/v1/info", get(info))
        .route("/health/live", get(|| async { "ok" }))
        .merge(
            Router::new()
                .route("/api/v1/assets", get(assets))
                .route("/api/v1/connection-tickets", post(issue))
                .route("/api/v1/connections/{id}", get(connection))
                .layer(middleware::from_fn_with_state(state.clone(), authenticate)),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(response_headers))
        .with_state(state)
}

async fn response_headers(request: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if !response.headers().contains_key("x-request-id") {
        response.headers_mut().insert(
            "x-request-id",
            HeaderValue::from_str(&Uuid::new_v4().to_string()).unwrap(),
        );
    }
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

async fn authenticate(
    State(state): State<Arc<PrototypeApi>>,
    request: axum::extract::Request,
    next: Next,
) -> Response {
    if !authorized(request.headers(), &state.bearer_hash) {
        return ApiError(ErrorCode::Unauthenticated).into_response();
    }
    next.run(request).await
}
fn authorized(headers: &HeaderMap, hash: &[u8; 32]) -> bool {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .filter(|token| token.len() <= 1024)
        .is_some_and(|token| matches_hash(hash, token))
}

async fn info(State(state): State<Arc<PrototypeApi>>) -> Json<serde_json::Value> {
    Json(
        json!({ "server_id": state.server_id, "protocol_version": 1, "minimum_client_protocol_version": 1,
        "mode": "development_prototype", "production_ready": false,
        "gateway": { "id": state.gateway.id, "host": state.gateway.host, "port": state.gateway.port, "public_key": state.gateway_public_key } }),
    )
}
async fn assets(State(state): State<Arc<PrototypeApi>>) -> Json<serde_json::Value> {
    Json(
        json!({ "items": [{ "id": state.asset_id, "name": state.asset_name, "revision": 1, "tags": ["development"],
        "accounts": [{ "id": state.account_id, "username": state.target_username, "capabilities": state.allowed }] }],
        "next_cursor": null, "policy_revision": 1 }),
    )
}
async fn issue(
    State(state): State<Arc<PrototypeApi>>,
    input: Result<Json<TicketRequest>, axum::extract::rejection::JsonRejection>,
) -> Result<(StatusCode, Json<TicketResponse>), ApiError> {
    let Json(mut request) = input.map_err(|_| ApiError(ErrorCode::InvalidArgument))?;
    if request.asset_id != state.asset_id || request.account_id != state.account_id {
        return Err(ApiError(ErrorCode::PermissionDenied));
    }
    request.validate(&state.allowed).map_err(ApiError)?;
    let result = state
        .store
        .issue(request, state.gateway.clone())
        .map_err(ApiError)?;
    Ok((StatusCode::CREATED, Json(result)))
}
async fn connection(
    State(state): State<Arc<PrototypeApi>>,
    Path(id): Path<String>,
) -> Result<Json<Connection>, ApiError> {
    let id = Uuid::parse_str(&id).map_err(|_| ApiError(ErrorCode::InvalidArgument))?;
    state
        .store
        .get(id)
        .map(Json)
        .ok_or(ApiError(ErrorCode::ResourceNotFound))
}
struct ApiError(ErrorCode);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.0 {
            ErrorCode::InvalidArgument => StatusCode::BAD_REQUEST,
            ErrorCode::Unauthenticated => StatusCode::UNAUTHORIZED,
            ErrorCode::PermissionDenied => StatusCode::FORBIDDEN,
            ErrorCode::ResourceNotFound => StatusCode::NOT_FOUND,
            ErrorCode::ConnectionLimit => StatusCode::TOO_MANY_REQUESTS,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        let request_id = Uuid::new_v4().to_string();
        let mut response = (
            status,
            Json(json!({ "error": { "code": self.0, "message": self.0.to_string(), "request_id": request_id } })),
        )
        .into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
        if status == StatusCode::UNAUTHORIZED {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("30"));
        }
        response
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use bastion_secrets::Secret;
    use tower::ServiceExt;
    fn app() -> (Router, String, Uuid, Uuid) {
        let secret = Secret::random();
        let asset_id = Uuid::new_v4();
        let account_id = Uuid::new_v4();
        let state = PrototypeApi {
            store: Arc::new(PrototypeStore::new(std::time::Duration::from_secs(30))),
            bearer_hash: secret.hash(),
            server_id: "test".into(),
            gateway: GatewayAddress {
                id: "g".into(),
                host: "127.0.0.1".into(),
                port: 2222,
                username: String::new(),
            },
            gateway_public_key: "public".into(),
            asset_id,
            account_id,
            asset_name: "test".into(),
            target_username: "target".into(),
            allowed: vec![Capability::Sftp],
        };
        (
            router(Arc::new(state)),
            secret.expose().to_owned(),
            asset_id,
            account_id,
        )
    }
    #[tokio::test]
    async fn authentication_and_capabilities_cannot_be_bypassed() {
        let (app, token, asset, account) = app();
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/v1/assets")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        for (capability, status) in [
            ("exec", StatusCode::FORBIDDEN),
            ("forward", StatusCode::BAD_REQUEST),
            ("sftp", StatusCode::CREATED),
        ] {
            let response = app.clone().oneshot(Request::builder().method("POST").uri("/api/v1/connection-tickets")
                .header("Authorization", format!("Bearer {token}")).header("Content-Type","application/json")
                .body(Body::from(json!({"asset_id":asset,"account_id":account,"capabilities":[capability],"purpose":"sftp"}).to_string())).unwrap()).await.unwrap();
            assert_eq!(response.status(), status);
            assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
            let body = to_bytes(response.into_body(), 65536).await.unwrap();
            assert!(!String::from_utf8_lossy(&body).contains(&token));
        }
    }
}
