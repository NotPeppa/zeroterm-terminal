//! Opt-in real PostgreSQL + OpenSSH validation; tests/m1_smoke.py owns the fixture.
use bastion_domain::{ClientControl, ClientFrame, DataStream, ServerControl, ServerFrame};
use bastion_secrets::read_secret_file;
use futures_util::{SinkExt, StreamExt};
use reqwest::{header, Client, StatusCode};
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    connect_async,
    tungstenite::{client::IntoClientRequest, Message},
    MaybeTlsStream, WebSocketStream,
};
use uuid::Uuid;

type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;
#[derive(Deserialize)]
struct Fixture {
    api_url: String,
    username: String,
    password: String,
    asset_id: Uuid,
    account_id: Uuid,
}
struct Browser {
    http: Client,
    base: String,
    cookies: BTreeMap<String, String>,
    csrf: String,
}
impl Browser {
    fn cookie_header(&self) -> String {
        self.cookies
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
    async fn request(&mut self, path: &str, body: Option<Value>, expected: StatusCode) -> Value {
        let url = format!("{}/api/v1{path}", self.base);
        let mut req = if body.is_some() {
            self.http.post(url)
        } else {
            self.http.get(url)
        }
        .header(header::COOKIE, self.cookie_header())
        .header(header::ORIGIN, &self.base);
        if let Some(body) = body {
            req = req.header("X-Bastion-CSRF", &self.csrf).json(&body);
        }
        let response = req.send().await.unwrap();
        assert_eq!(response.status(), expected, "unexpected status for {path}");
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
        assert!(response.headers().contains_key("x-request-id"));
        for cookie in response.headers().get_all(header::SET_COOKIE) {
            let raw = cookie.to_str().unwrap();
            assert!(raw.contains("SameSite=Strict"));
            let (name, value) = raw.split(';').next().unwrap().split_once('=').unwrap();
            if value.is_empty() {
                self.cookies.remove(name);
            } else {
                self.cookies.insert(name.into(), value.into());
            }
            if name != "bastion_csrf" {
                assert!(raw.contains("HttpOnly"));
            }
        }
        if expected == StatusCode::NO_CONTENT {
            return Value::Null;
        }
        response.json().await.unwrap()
    }
    async fn ticket(&mut self, f: &Fixture) -> Value {
        self.request("/sessions",Some(json!({"asset_id":f.asset_id,"account_id":f.account_id,"capabilities":["shell"],"purpose":"terminal"})),StatusCode::CREATED).await
    }
    fn upgrade(
        &self,
        ticket: &Value,
        origin: &str,
        query: &str,
    ) -> tokio_tungstenite::tungstenite::http::Request<()> {
        let url = format!(
            "{}/api/v1/sessions/{}/stream{}",
            self.base.replacen("http://", "ws://", 1),
            ticket["session_id"].as_str().unwrap(),
            query
        );
        let mut request = url.into_client_request().unwrap();
        request
            .headers_mut()
            .insert("Origin", origin.parse().unwrap());
        request
            .headers_mut()
            .insert("Cookie", self.cookie_header().parse().unwrap());
        request.headers_mut().insert(
            "Sec-WebSocket-Protocol",
            format!("bastion.v1, {}", ticket["ws_token"].as_str().unwrap())
                .parse()
                .unwrap(),
        );
        request
    }
}
async fn control(socket: &mut Socket) -> ServerControl {
    let message = tokio::time::timeout(Duration::from_secs(35), socket.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    match message {
        Message::Text(text) => match ServerFrame::decode_text(&text).unwrap() {
            ServerFrame::Control(c) => c,
            _ => panic!("control expected"),
        },
        _ => panic!("control message expected"),
    }
}
async fn send(socket: &mut Socket, control: ClientControl) {
    let text = ClientFrame::Control(control).encode_text().unwrap();
    socket.send(Message::Text(text.into())).await.unwrap();
}
async fn start(browser: &Browser, ticket: &Value, pty: bool) -> Socket {
    let (mut socket, response) = connect_async(browser.upgrade(ticket, &browser.base, ""))
        .await
        .unwrap();
    assert_eq!(response.headers()["Sec-WebSocket-Protocol"], "bastion.v1");
    assert!(
        matches!(control(&mut socket).await,ServerControl::SessionReady{connection_id,..} if connection_id.to_string()==ticket["connection_id"].as_str().unwrap())
    );
    send(
        &mut socket,
        ClientControl::Open {
            v: 1,
            channel_id: 1,
            kind: bastion_domain::ChannelKind::Shell,
        },
    )
    .await;
    assert!(matches!(
        control(&mut socket).await,
        ServerControl::Opened { channel_id: 1, .. }
    ));
    if pty {
        send(
            &mut socket,
            ClientControl::Pty {
                v: 1,
                channel_id: 1,
                term: "xterm-256color".into(),
                cols: 80,
                rows: 24,
            },
        )
        .await;
        assert!(matches!(
            control(&mut socket).await,
            ServerControl::PtyReady { channel_id: 1, .. }
        ));
    }
    send(
        &mut socket,
        ClientControl::Shell {
            v: 1,
            channel_id: 1,
        },
    )
    .await;
    assert!(matches!(
        control(&mut socket).await,
        ServerControl::Ready { channel_id: 1, .. }
    ));
    socket
}
async fn input(socket: &mut Socket, data: &[u8]) {
    let binary = ClientFrame::Data {
        channel_id: 1,
        data: data.to_vec(),
    }
    .encode_binary()
    .unwrap();
    socket.send(Message::Binary(binary.into())).await.unwrap();
}
async fn drain(socket: &mut Socket) -> (Vec<u8>, Vec<u8>, Option<u32>) {
    tokio::time::timeout(Duration::from_secs(15), async {
        let (mut stdout, mut stderr, mut exit) = (Vec::new(), Vec::new(), None);
        while let Some(message) = socket.next().await {
            match message.unwrap() {
                Message::Binary(bytes) => match ServerFrame::decode_binary(&bytes).unwrap() {
                    ServerFrame::Data {
                        channel_id: 1,
                        stream: DataStream::Output,
                        data,
                    } => stdout.extend(data),
                    ServerFrame::Data {
                        channel_id: 1,
                        stream: DataStream::Stderr,
                        data,
                    } => stderr.extend(data),
                    _ => panic!("invalid channel/direction"),
                },
                Message::Text(text) => match ServerFrame::decode_text(&text).unwrap() {
                    ServerFrame::Control(ServerControl::Exit {
                        exit_code: Some(code),
                        ..
                    }) => {
                        exit = Some(code);
                    }
                    ServerFrame::Control(ServerControl::Closed { .. }) => break,
                    ServerFrame::Control(ServerControl::Error { code, .. }) => {
                        panic!("gateway fault {code:?}")
                    }
                    _ => {}
                },
                Message::Close(_) => break,
                _ => {}
            }
        }
        (stdout, stderr, exit)
    })
    .await
    .unwrap()
}

#[tokio::test]
#[ignore = "requires the isolated tests/m1_smoke.py PostgreSQL/OpenSSH fixture"]
async fn browser_cookie_origin_tickets_and_real_shell() {
    let fixture =
        read_secret_file(&PathBuf::from(std::env::var("BASTION_M1_FIXTURE").unwrap())).unwrap();
    let f: Fixture = serde_json::from_str(fixture.expose()).unwrap();
    let http = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .timeout(Duration::from_secs(20))
        .build()
        .unwrap();
    let native = http
        .post(format!("{}/api/v1/auth/login", f.api_url))
        .json(&json!({"username":f.username,"password":f.password,"device_label":"native fixture"}))
        .send()
        .await
        .unwrap();
    assert_eq!(native.status(), StatusCode::OK);
    let native: Value = native.json().await.unwrap();
    let grant=http.post(format!("{}/api/v1/admin/grants",f.api_url)).bearer_auth(native["access_token"].as_str().unwrap()).json(&json!({"user_id":native["user"]["id"],"asset_id":f.asset_id,"account_id":f.account_id,"capabilities":["shell"]})).send().await.unwrap();
    assert_eq!(grant.status(), StatusCode::CREATED);
    let mut b = Browser {
        http,
        base: f.api_url.clone(),
        cookies: BTreeMap::new(),
        csrf: String::new(),
    };
    let bootstrap = b.request("/auth/csrf", None, StatusCode::OK).await;
    b.csrf = bootstrap["csrf_token"].as_str().unwrap().into();
    let login = json!({"username":f.username,"password":f.password,"device_label":"browser fixture","client_type":"web"});
    let saved = b.csrf.clone();
    b.csrf = "wrong".into();
    b.request("/auth/login", Some(login.clone()), StatusCode::FORBIDDEN)
        .await;
    b.csrf = saved;
    let metadata = b.request("/auth/login", Some(login), StatusCode::OK).await;
    assert!(metadata.get("access_token").is_none() && metadata.get("refresh_token").is_none());
    let web_secret = b.cookies["bastion_session"].clone();
    let wrong_domain = b
        .http
        .get(format!("{}/api/v1/me", b.base))
        .bearer_auth(&web_secret)
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_domain.status(), StatusCode::UNAUTHORIZED);
    b.request("/me", None, StatusCode::OK).await;
    let ticket = b.ticket(&f).await;
    assert!(
        connect_async(b.upgrade(&ticket, "https://foreign.invalid", ""))
            .await
            .is_err()
    );
    assert!(
        connect_async(b.upgrade(&ticket, &b.base, "?token=forbidden"))
            .await
            .is_err()
    );
    let mut wrong = ticket.clone();
    wrong["ws_token"] = Value::String("a".repeat(43));
    assert!(connect_async(b.upgrade(&wrong, &b.base, "")).await.is_err());
    // Bad attempts did not consume the valid ticket; raw shell has separate stderr.
    let mut socket = start(&b, &ticket, false).await;
    input(
        &mut socket,
        "printf '中文🙂'; printf 'stderr-marker' >&2; exit 7\n".as_bytes(),
    )
    .await;
    send(
        &mut socket,
        ClientControl::Eof {
            v: 1,
            channel_id: 1,
        },
    )
    .await;
    let (out, err, exit) = drain(&mut socket).await;
    let marker = "中文🙂".as_bytes();
    assert!(out.windows(marker.len()).any(|bytes| bytes == marker));
    assert!(err
        .windows(b"stderr-marker".len())
        .any(|bytes| bytes == b"stderr-marker"));
    assert_eq!(exit, Some(7));
    assert!(connect_async(b.upgrade(&ticket, &b.base, ""))
        .await
        .is_err());
    // New ticket and real PTY resize, not an echoed frontend dimension.
    let resized = b.ticket(&f).await;
    let mut socket = start(&b, &resized, true).await;
    send(
        &mut socket,
        ClientControl::Resize {
            v: 1,
            channel_id: 1,
            cols: 100,
            rows: 40,
        },
    )
    .await;
    input(&mut socket, b"stty size; exit\n").await;
    let (out, _, exit) = drain(&mut socket).await;
    assert!(String::from_utf8_lossy(&out).contains("40 100"));
    assert_eq!(exit, Some(0));
    // Logout invalidates pending tickets and clears all browser cookies.
    let pending = b.ticket(&f).await;
    b.request("/auth/logout", Some(json!({})), StatusCode::NO_CONTENT)
        .await;
    assert!(b.cookies.is_empty());
    assert!(connect_async(b.upgrade(&pending, &b.base, ""))
        .await
        .is_err());
    // Server logs must not contain any browser/native/ticket/login secrets.
    if let Ok(path) = std::env::var("BASTION_M1_GATEWAY_LOG") {
        let log = std::fs::read_to_string(path).unwrap();
        for secret in [
            web_secret.as_str(),
            native["access_token"].as_str().unwrap(),
            pending["ws_token"].as_str().unwrap(),
            f.password.as_str(),
        ] {
            assert!(!log.contains(secret), "secret leaked into server log");
        }
    }
}
