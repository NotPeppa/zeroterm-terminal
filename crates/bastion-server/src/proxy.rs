use axum::{
    extract::{ConnectInfo, State},
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use ipnet::IpNet;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use uuid::Uuid;

fn forwarded(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[IpNet],
) -> Result<Option<IpAddr>, ()> {
    let has_forwarded = headers.contains_key("forwarded")
        || headers.contains_key("x-forwarded-for")
        || headers.contains_key("x-forwarded-proto");
    if !has_forwarded {
        return Ok(None);
    }
    if !trusted.iter().any(|net| net.contains(&peer))
        || headers.contains_key("forwarded")
        || headers.get_all("x-forwarded-for").iter().count() != 1
        || headers.get_all("x-forwarded-proto").iter().count() != 1
        || headers
            .get("x-forwarded-proto")
            .and_then(|v| v.to_str().ok())
            != Some("https")
    {
        return Err(());
    }
    let ip = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<IpAddr>().ok())
        .ok_or(())?;
    if ip.is_unspecified() {
        return Err(());
    }
    Ok(Some(ip))
}
pub(super) async fn enforce(
    State(trusted): State<Arc<Vec<IpNet>>>,
    mut request: axum::extract::Request,
    next: Next,
) -> Response {
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|v| v.0);
    let Some(peer) = peer else {
        return reject();
    };
    match forwarded(peer.ip(), request.headers(), &trusted) {
        Ok(Some(ip)) => {
            request
                .extensions_mut()
                .insert(ConnectInfo(SocketAddr::new(ip, peer.port())));
        }
        Ok(None) if request.uri().path().starts_with("/health/") => {}
        _ => return reject(),
    }
    next.run(request).await
}
fn reject() -> Response {
    let id = Uuid::new_v4().to_string();
    (StatusCode::FORBIDDEN,[(header::CONTENT_TYPE,"application/json"),(header::CACHE_CONTROL,"no-store"),(header::HeaderName::from_static("x-request-id"),id.as_str())],
        format!(r#"{{"error":{{"code":"PERMISSION_DENIED","message":"Untrusted proxy request","request_id":"{id}"}}}}"#)).into_response()
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn forwarded_identity_requires_overwritten_single_https_proxy_headers() {
        let trusted = vec!["127.0.0.1/32".parse().unwrap()];
        let peer = "127.0.0.1".parse().unwrap();
        let mut headers = axum::http::HeaderMap::new();
        assert_eq!(forwarded(peer, &headers, &trusted), Ok(None));
        headers.insert("x-forwarded-for", "192.0.2.4".parse().unwrap());
        headers.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            forwarded(peer, &headers, &trusted),
            Ok(Some("192.0.2.4".parse().unwrap()))
        );
        assert!(forwarded("192.0.2.5".parse().unwrap(), &headers, &trusted).is_err());
        headers.insert("x-forwarded-for", "192.0.2.4, 192.0.2.5".parse().unwrap());
        assert!(forwarded(peer, &headers, &trusted).is_err());
        headers.insert("x-forwarded-for", "192.0.2.4".parse().unwrap());
        headers.append("x-forwarded-proto", "https".parse().unwrap());
        assert!(forwarded(peer, &headers, &trusted).is_err());
    }
}
