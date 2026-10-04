use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bastion_domain::{Connection, ConnectionState, ErrorCode, GatewayAddress};
use bastion_gateway::{GatewayBackend, NetworkPolicy, Target, TargetAuth, TargetEndpoint};
use bastion_secrets::{hash_password, read_secret_file, KeyRing, Secret};
use bastion_store::PgStore;
use ipnet::IpNet;
use serde::Deserialize;
use sqlx::Connection as _;
use std::{
    collections::BTreeMap,
    future::IntoFuture,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server_id: String,
    gateway_id: String,
    api_listen: SocketAddr,
    #[serde(default)]
    public_origin: Option<String>,
    #[serde(default)]
    web_root: Option<PathBuf>,
    ssh_listen: SocketAddr,
    database_url_file: PathBuf,
    ssh_host_key_file: PathBuf,
    active_kek_version: i64,
    kek_files: BTreeMap<String, PathBuf>,
    network: Policy,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Policy {
    allow: Vec<IpNet>,
    deny: Vec<IpNet>,
}
impl Config {
    fn load(path: &Path) -> Result<Self> {
        let config: Self = toml::from_str(
            &std::fs::read_to_string(path).context("cannot read M1 configuration")?,
        )?;
        // M1 has no mandatory output recording or TLS listener. Do not expose it remotely.
        if !config.api_listen.ip().is_loopback()
            || !config.ssh_listen.ip().is_loopback()
            || config.api_listen.port() == 0
            || config.ssh_listen.port() == 0
        {
            bail!("M1 integration service must listen on loopback with explicit nonzero ports");
        }
        for id in [&config.server_id, &config.gateway_id] {
            if id.is_empty() || id.len() > 128 || id.chars().any(char::is_control) {
                bail!("invalid server or gateway identity");
            }
        }
        if config.network.allow.is_empty() {
            bail!("explicit target allow CIDRs are required");
        }
        Ok(config)
    }
    async fn store(&self) -> Result<PgStore> {
        let url = read_secret_file(&self.database_url_file)?;
        PgStore::connect(
            url.expose().trim_end_matches(['\r', '\n']),
            &self.server_id,
            &self.gateway_id,
        )
        .await
        .map_err(|code| anyhow::anyhow!("database initialization failed: {code}"))
    }
    fn keys(&self) -> Result<KeyRing> {
        let files = self
            .kek_files
            .iter()
            .map(|(version, path)| {
                Ok((
                    version.parse::<i64>().context("invalid KEK version")?,
                    path.clone(),
                ))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        KeyRing::from_files(self.active_kek_version, &files)
    }
}
fn store_error(code: ErrorCode) -> anyhow::Error {
    anyhow::anyhow!("{code:?}: {code}")
}
pub async fn migrate(path: PathBuf) -> Result<()> {
    Config::load(&path)?
        .store()
        .await?
        .migrate()
        .await
        .map_err(store_error)?;
    println!("Database migrations applied and server identity verified");
    Ok(())
}
fn password(stdin: bool) -> Result<Secret> {
    if stdin {
        let mut bytes = String::new();
        std::io::stdin().take(1026).read_to_string(&mut bytes)?;
        if bytes.len() > 1025 {
            bail!("password input exceeds limit");
        }
        // Strip one input line ending, keeping intentional spaces and other bytes.
        if bytes.ends_with('\n') {
            bytes.pop();
            if bytes.ends_with('\r') {
                bytes.pop();
            }
        }
        Ok(Secret::new(bytes))
    } else {
        Ok(Secret::new(rpassword::prompt_password(
            "New password (12+ bytes): ",
        )?))
    }
}
pub async fn create_admin(path: PathBuf, username: String, stdin: bool) -> Result<()> {
    let username = username.trim().to_ascii_lowercase();
    if username.is_empty()
        || username.len() > 64
        || !username.as_bytes()[0].is_ascii_alphanumeric()
        || username
            .bytes()
            .any(|b| !b.is_ascii_alphanumeric() && !b"_.-".contains(&b))
    {
        bail!("invalid username");
    }
    let store = Config::load(&path)?.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let password = password(stdin)?;
    let phc = hash_password(password.expose())?;
    let user = store
        .bootstrap_admin(&username, &phc, Uuid::new_v4())
        .await
        .map_err(store_error)?;
    println!("Administrator created: {} ({})", user.username, user.id);
    Ok(())
}
pub async fn reset_user(path: PathBuf, username: String, stdin: bool) -> Result<()> {
    let store = Config::load(&path)?.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let (user, _) = store
        .login_candidate(&username.trim().to_ascii_lowercase())
        .await
        .map_err(store_error)?
        .context("user does not exist")?;
    let password = password(stdin)?;
    let phc = hash_password(password.expose())?;
    store
        .reset_password(None, user.id, user.revision, &phc, Uuid::new_v4())
        .await
        .map_err(store_error)?;
    println!(
        "Password reset; existing login sessions revoked for {}",
        user.username
    );
    Ok(())
}
struct Backend {
    store: PgStore,
    keys: Arc<KeyRing>,
    network: Arc<NetworkPolicy>,
}
#[async_trait]
impl GatewayBackend for Backend {
    async fn consume(&self, id: Uuid, secret: &str) -> Result<(Connection, Target), ErrorCode> {
        let connection = self.store.consume_ticket(id, secret).await?;
        let snapshot = match self.store.target_snapshot(&connection).await {
            Ok(value) => value,
            Err(code) => {
                let _ = self
                    .store
                    .transition(connection.id, ConnectionState::Failed, Some(code))
                    .await;
                return Err(code);
            }
        };
        let public_keys = snapshot
            .keys
            .iter()
            .map(|key| {
                russh::keys::PublicKey::from_openssh(key)
                    .map_err(|_| ErrorCode::TargetHostKeyUnknown)
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((
            connection,
            Target {
                address: TargetEndpoint::Restricted {
                    host: snapshot.host,
                    port: snapshot.port,
                    policy: self.network.clone(),
                },
                username: snapshot.username,
                public_keys,
                auth: TargetAuth::Encrypted {
                    context: snapshot.context,
                    envelope: snapshot.credential,
                    keys: self.keys.clone(),
                },
            },
        ))
    }
    async fn authorize(&self, connection: &Connection) -> Result<(), ErrorCode> {
        self.store.authorize_connection(connection).await
    }
    async fn transition(
        &self,
        id: Uuid,
        state: ConnectionState,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.store.transition(id, state, failure).await
    }
    async fn channel_audit(
        &self,
        connection: &Connection,
        kind: &str,
        command_hash: Option<String>,
        command_len: Option<usize>,
    ) -> Result<(), ErrorCode> {
        self.store
            .channel_audit(connection, kind, command_hash, command_len)
            .await
    }
}
async fn web_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{
        http::{header, HeaderValue, StatusCode},
        response::IntoResponse,
    };
    let path = request.uri().path().to_owned();
    let mut response = next.run(request).await;
    if response
        .headers()
        .get(header::CONTENT_TYPE)
        .is_some_and(|v| v.to_str().is_ok_and(|s| s.starts_with("text/html")))
        && (path.starts_with("/api/") || path.starts_with("/health/"))
    {
        response = StatusCode::NOT_FOUND.into_response();
    }
    for (name, value) in [
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        response.headers_mut().insert(name, HeaderValue::from_static(value));
    }
    response
}

pub async fn serve(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let mut lease = store.gateway_lock().await.map_err(store_error)?;
    store.recover_gateway().await.map_err(store_error)?;
    let keys = Arc::new(config.keys()?);
    let encoded = read_secret_file(&config.ssh_host_key_file)?;
    let key = russh::keys::decode_secret_key(encoded.expose(), None)?;
    let network = Arc::new(NetworkPolicy {
        allow: config.network.allow,
        deny: config.network.deny,
    });
    let gateway = GatewayAddress {
        id: config.gateway_id,
        host: config.ssh_listen.ip().to_string(),
        port: config.ssh_listen.port(),
        username: String::new(),
    };
    let backend = Arc::new(Backend {
        store: store.clone(),
        keys: keys.clone(),
        network: network.clone(),
    });
    let shutdown = CancellationToken::new();
    let mut api = bastion_api::ControlApi::new(
        store.clone(),
        keys.clone(),
        gateway,
        key.public_key().to_openssh()?,
        network.clone(),
    )?;
    if let Some(origin) = config.public_origin {
        api = api.with_browser(origin, backend.clone(), shutdown.clone())?;
    }
    let api = Arc::new(api);
    let http_listener = TcpListener::bind(config.api_listen).await?;
    let ssh_listener = TcpListener::bind(config.ssh_listen).await?;
    let signal_shutdown = shutdown.clone();
    let signal = tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal handler");
            tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        signal_shutdown.cancel();
    });
    // Loss of the dedicated advisory-lock connection stops the whole gateway.
    // Never reconnect and continue without reacquiring its ownership lock.
    let lease_shutdown = shutdown.clone();
    let lease_lost = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ownership_lost = lease_lost.clone();
    let ownership = tokio::spawn(async move {
        loop {
            tokio::select! {_=lease_shutdown.cancelled()=>break,_=tokio::time::sleep(Duration::from_secs(1))=>{}}
            if !matches!(
                tokio::time::timeout(
                    Duration::from_secs(2),
                    sqlx::query("SELECT 1").execute(&mut lease)
                )
                .await,
                Ok(Ok(_))
            ) {
                tracing::error!("gateway ownership connection lost; stopping service");
                ownership_lost.store(true, std::sync::atomic::Ordering::Relaxed);
                lease_shutdown.cancel();
                break;
            }
        }
        let _ = lease.close().await;
    });
    tracing::info!(api=%config.api_listen,ssh=%config.ssh_listen,"M1 integration service started; output recording is not implemented");
    let mut app = bastion_api::control_router(api);
    if let Some(root) = config.web_root {
        if !root.join("index.html").is_file() {
            bail!("web_root must contain the built index.html; run the web build first");
        }
        let index = tower_http::services::ServeFile::new(root.join("index.html"));
        app = app
            .fallback_service(tower_http::services::ServeDir::new(root).not_found_service(index));
    }
    app = app.layer(axum::middleware::from_fn(web_headers));
    let http = axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.clone().cancelled_owned())
    .into_future();
    let ssh = bastion_gateway::run_backend(ssh_listener, key, backend, shutdown.clone());
    let (http_result, ssh_result) = tokio::join!(
        async {
            let result = http.await;
            shutdown.cancel();
            result
        },
        async {
            let result = ssh.await;
            shutdown.cancel();
            result
        }
    );
    signal.abort();
    ownership.abort();
    if lease_lost.load(std::sync::atomic::Ordering::Relaxed) {
        bail!("gateway database ownership was lost; restart required");
    }
    http_result?;
    ssh_result
}
