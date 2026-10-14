//! Opt-in browser API/WS checks through the service's loopback trusted-proxy boundary.
//! HTTPS browser/native display acceptance is separate; this test never labels loopback HTTP as WSS.
use bastion_domain::{guac_encode, GuacParser, MAX_DATA_BYTES, MAX_INSTRUCTION_BYTES};
use bastion_secrets::read_secret_file;
use futures_util::{SinkExt, StreamExt};
use reqwest::{header, Client, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path, time::Duration};
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
};
use uuid::Uuid;
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    api_url: String,
    public_origin: String,
    username: String,
    password: String,
    asset_id: Uuid,
    account_id: Uuid,
}
struct Browser {
    http: Client,
    base: String,
    origin: String,
    cookies: BTreeMap<String, String>,
    csrf: String,
}
impl Browser {
    fn cookie(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
    async fn request(&mut self, path: &str, body: Option<Value>, expected: StatusCode) -> Value {
        let mut request = if body.is_some() {
            self.http.post(format!("{}/api/v1{path}", self.base))
        } else {
            self.http.get(format!("{}/api/v1{path}", self.base))
        };
        request = request
            .header(header::ORIGIN, &self.origin)
            .header(header::COOKIE, self.cookie())
            .header("X-Forwarded-Proto", "https")
            .header("X-Forwarded-For", "127.0.0.1");
        if let Some(body) = body {
            request = request.header("X-Bastion-CSRF", &self.csrf).json(&body);
        }
        let response = request.send().await.unwrap();
        assert_eq!(response.status(), expected, "unexpected status for {path}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().contains_key("x-request-id"));
        for value in response.headers().get_all(header::SET_COOKIE) {
            let value = value.to_str().unwrap();
            assert!(value.contains("SameSite=Strict"));
            let (name, token) = value.split(';').next().unwrap().split_once('=').unwrap();
            if token.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.into(), token.into());
            }
            if name != "bastion_csrf" {
                assert!(value.contains("HttpOnly") && value.contains("Secure"));
            }
        }
        if expected == StatusCode::NO_CONTENT {
            Value::Null
        } else {
            response.json().await.unwrap()
        }
    }
    async fn ticket(&mut self, fixture: &Fixture) -> Value {
        let value=self.request("/sessions",Some(json!({"asset_id":fixture.asset_id,"account_id":fixture.account_id,"display":{"width":1280,"height":720,"dpi":96}})),StatusCode::CREATED).await;
        assert_eq!(
            value["stream_protocol"],
            if value["target_protocol"] == "ssh" {
                "bastion.ssh.v1"
            } else {
                "bastion.guac.v1"
            }
        );
        assert_eq!(value["ws_token"].as_str().unwrap().len(), 43);
        assert!(value.get("capabilities").is_none());
        value
    }
    fn upgrade(
        &self,
        ticket: &Value,
        origin: &str,
        query: &str,
    ) -> tokio_tungstenite::tungstenite::http::Request<()> {
        let url = format!(
            "{}/api/v1/sessions/{}/stream{query}",
            self.base.replacen("http://", "ws://", 1),
            ticket["session_id"].as_str().unwrap()
        );
        let mut request = url.into_client_request().unwrap();
        let cookie = self.cookie();
        for (key, value) in [
            ("Origin", origin),
            ("Cookie", cookie.as_str()),
            ("X-Forwarded-Proto", "https"),
            ("X-Forwarded-For", "127.0.0.1"),
        ] {
            request.headers_mut().insert(key, value.parse().unwrap());
        }
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            format!(
                "{}, {}",
                ticket["stream_protocol"].as_str().unwrap(),
                ticket["ws_token"].as_str().unwrap()
            )
            .parse()
            .unwrap(),
        );
        request
    }
}
#[tokio::test]
#[ignore = "requires BASTION_GUAC_TEST_FIXTURE_FILE and an isolated loopback browser-only server with real guacd"]
async fn cookie_bound_single_use_guacamole_and_removed_native_routes() {
    let file = std::env::var("BASTION_GUAC_TEST_FIXTURE_FILE")
        .expect("explicit isolated fixture file required");
    let bytes = read_secret_file(Path::new(&file)).unwrap();
    let fixture: Fixture = serde_json::from_str(bytes.expose()).unwrap();
    let uri: reqwest::Url = fixture.api_url.parse().unwrap();
    assert!(
        uri.scheme() == "http"
            && (uri.host_str() == Some("localhost")
                || uri.host_str().is_some_and(|v| v
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.is_loopback()))),
        "loopback proxy-boundary test only"
    );
    assert!(fixture.public_origin.starts_with("https://"));
    let mut browser = Browser {
        http: Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap(),
        base: fixture.api_url.clone(),
        origin: fixture.public_origin.clone(),
        cookies: BTreeMap::new(),
        csrf: String::new(),
    };
    let info = browser.request("/info", None, StatusCode::OK).await;
    assert_eq!(info["schema_version"], 2);
    assert_eq!(info["production_ready"], false);
    assert!(
        info["server_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("zt-guac-v2-")),
        "refusing a non-disposable service"
    );
    browser.csrf = browser.request("/auth/csrf", None, StatusCode::OK).await["csrf_token"]
        .as_str()
        .unwrap()
        .into();
    let login=browser.request("/auth/login",Some(json!({"username":fixture.username,"password":fixture.password,"device_label":"guac integration"})),StatusCode::OK).await;
    assert!(login.get("access_token").is_none() && login.get("refresh_token").is_none());
    for removed in [
        "/connection-tickets",
        "/integrations/zeroterm/connection-tickets",
        "/copy-jobs",
    ] {
        browser
            .request(removed, Some(json!({})), StatusCode::NOT_FOUND)
            .await;
    }
    let ticket = browser.ticket(&fixture).await;
    assert!(
        connect_async(browser.upgrade(&ticket, "https://wrong.invalid", ""))
            .await
            .is_err()
    );
    assert!(
        connect_async(browser.upgrade(&ticket, &fixture.public_origin, "?token=forbidden"))
            .await
            .is_err()
    );
    let (mut socket, response) =
        connect_async(browser.upgrade(&ticket, &fixture.public_origin, ""))
            .await
            .unwrap();
    assert_eq!(
        response.headers()["Sec-WebSocket-Protocol"],
        ticket["stream_protocol"].as_str().unwrap()
    );
    assert!(!format!("{:?}", response.headers()).contains(ticket["ws_token"].as_str().unwrap()));
    if ticket["target_protocol"] == "ssh" {
        socket
            .send(Message::Binary(
                bastion_domain::terminal_size_frame(80, 24).unwrap().into(),
            ))
            .await
            .unwrap();
    }
    assert!(
        connect_async(browser.upgrade(&ticket, &fixture.public_origin, ""))
            .await
            .is_err()
    );
    let mut parser = GuacParser::new(MAX_INSTRUCTION_BYTES);
    let deadline = tokio::time::Instant::now() + Duration::from_secs(45);
    let mut saw_display = false;
    loop {
        let message = tokio::time::timeout_at(deadline, socket.next())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        match message {
            Message::Binary(bytes) => {
                assert!(bytes.len() <= MAX_DATA_BYTES);
                if ticket["target_protocol"] == "ssh" {
                    if bytes.as_ref() == [bastion_domain::TERMINAL_READY] {
                        saw_display = true;
                        break;
                    }
                    bastion_domain::validate_terminal_output(&bytes).unwrap();
                    continue;
                }
                for instruction in parser.push(&bytes).unwrap() {
                    assert!(!matches!(
                        instruction.opcode(),
                        "args" | "ready" | "connect" | "clipboard" | "audio" | "file" | "pipe"
                    ));
                    if matches!(
                        instruction.opcode(),
                        "img" | "png" | "jpeg" | "size" | "rect" | "cfill"
                    ) {
                        saw_display = true;
                    }
                    if instruction.opcode() == "sync" {
                        socket
                            .send(Message::Binary(
                                guac_encode(&["sync", &instruction.args()[0]]).into(),
                            ))
                            .await
                            .unwrap();
                        if saw_display {
                            break;
                        }
                    }
                }
                if saw_display {
                    break;
                }
            }
            Message::Ping(bytes) => socket.send(Message::Pong(bytes)).await.unwrap(),
            _ => panic!("display stream ended before target output"),
        }
    }
    assert!(saw_display, "ready alone is not target display evidence");
    // Text frames are forbidden in the new binary UTF-8 stream, even valid Guacamole text.
    socket
        .send(Message::Text("4.sync,1.1;".into()))
        .await
        .unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(10), socket.next()).await;
    let connection = browser
        .request(
            &format!("/connections/{}", ticket["connection_id"].as_str().unwrap()),
            None,
            StatusCode::OK,
        )
        .await;
    assert!(connection.get("target_protocol").is_some());
    assert!(connection.get("transport").is_none());
    let clean_ticket = browser.ticket(&fixture).await;
    let (mut clean_socket, _) =
        connect_async(browser.upgrade(&clean_ticket, &fixture.public_origin, ""))
            .await
            .unwrap();
    let mut clean_parser = GuacParser::new(MAX_INSTRUCTION_BYTES);
    if clean_ticket["target_protocol"] == "ssh" {
        clean_socket
            .send(Message::Binary(
                bastion_domain::terminal_size_frame(80, 24).unwrap().into(),
            ))
            .await
            .unwrap();
    }
    let mut images = std::collections::HashSet::new();
    tokio::time::timeout(Duration::from_secs(45), async {
        loop {
            match clean_socket.next().await.unwrap().unwrap() {
                Message::Binary(bytes) => {
                    if clean_ticket["target_protocol"] == "ssh" {
                        if bytes.as_ref() == [bastion_domain::TERMINAL_READY] {
                            break;
                        }
                        bastion_domain::validate_terminal_output(&bytes).unwrap();
                        continue;
                    }
                    let mut frame_ended = false;
                    for instruction in clean_parser.push(&bytes).unwrap() {
                        match instruction.opcode() {
                            "img" => {
                                images.insert(instruction.args()[0].clone());
                            }
                            "end" => {
                                images.remove(&instruction.args()[0]);
                            }
                            "sync" => {
                                clean_socket
                                    .send(Message::Binary(
                                        guac_encode(&["sync", &instruction.args()[0]]).into(),
                                    ))
                                    .await
                                    .unwrap();
                                frame_ended = images.is_empty();
                            }
                            _ => {}
                        }
                    }
                    if frame_ended && clean_parser.finish().is_ok() {
                        break;
                    }
                }
                Message::Ping(bytes) => clean_socket.send(Message::Pong(bytes)).await.unwrap(),
                _ => panic!("normal-close fixture failed before approved output"),
            }
        }
    })
    .await
    .unwrap();
    if clean_ticket["target_protocol"] != "ssh" {
        clean_socket
            .send(Message::Binary(guac_encode(&["disconnect"]).into()))
            .await
            .unwrap();
    }
    clean_socket
        .close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
            code: tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode::Normal,
            reason: "".into(),
        }))
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let ended = browser
                .request(
                    &format!(
                        "/connections/{}",
                        clean_ticket["connection_id"].as_str().unwrap()
                    ),
                    None,
                    StatusCode::OK,
                )
                .await;
            if ended["state"] == "closed" {
                let recordings = browser
                    .request(
                        &format!(
                            "/recordings?connection_id={}",
                            clean_ticket["connection_id"].as_str().unwrap()
                        ),
                        None,
                        StatusCode::OK,
                    )
                    .await;
                assert_eq!(recordings["items"].as_array().unwrap().len(), 1);
                let recording = &recordings["items"][0];
                assert_eq!(
                    recording["state"], "complete",
                    "normal Close must not race recording completion"
                );
                break;
            }
            assert_ne!(ended["state"], "failed", "normal-close gateway failed");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap();
    browser
        .request("/auth/logout", Some(json!({})), StatusCode::NO_CONTENT)
        .await;
}
