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
mod maintenance;
pub async fn partition_audit(path: PathBuf, offline: bool) -> Result<()> {
    maintenance::partition_audit(path, offline).await
}
pub async fn retain_audit(path: PathBuf, offline: bool, days: u32) -> Result<()> {
    maintenance::retain_audit(path, offline, days).await
}
pub async fn rewrap_keys(path: PathBuf) -> Result<()> {
    maintenance::rewrap_keys(path).await
}
pub async fn verify_backup(path: PathBuf, manifest: PathBuf) -> Result<()> {
    maintenance::verify_backup(path, manifest).await
}
pub async fn recover_restore(path: PathBuf) -> Result<()> {
    maintenance::recover_restore(path).await
}
pub async fn retain_recordings(path: PathBuf) -> Result<()> {
    maintenance::retain_recordings(path).await
}

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
    ssh_public_host: Option<String>,
    ssh_public_port: Option<u16>,
    production: Option<crate::production::Production>,
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
        let config: Self =
            toml::from_str(&std::fs::read_to_string(path).context("cannot read configuration")?)?;
        if let Some(production) = &config.production {
            production.validate()?;
            let origin: axum::http::Uri = config
                .public_origin
                .as_deref()
                .context("production HTTPS origin is required")?
                .parse()
                .context("invalid production origin")?;
            if origin.scheme_str() != Some("https")
                || origin
                    .authority()
                    .is_none_or(|authority| authority.as_str().contains('@'))
                || origin.host().is_none_or(|host| host.is_empty())
                || origin
                    .path_and_query()
                    .is_some_and(|path| path.as_str() != "/")
            {
                bail!("production origin must be exact HTTPS authority without userinfo, path or query");
            }
            if !config.api_listen.ip().is_loopback()
                || config.api_listen.port() == 0
                || config.ssh_listen.port() == 0
                || !config
                    .public_origin
                    .as_ref()
                    .is_some_and(|origin| origin.starts_with("https://"))
                || !config.ssh_public_host.as_ref().is_some_and(|host| {
                    bastion_api::valid_host(host)
                        && !host
                            .parse::<std::net::IpAddr>()
                            .is_ok_and(|ip| ip.is_unspecified())
                })
                || config.ssh_public_port.is_none_or(|port| port == 0)
            {
                bail!("production requires loopback API behind HTTPS, explicit public SSH host/port and nonzero listeners");
            }
        } else if !config.api_listen.ip().is_loopback()
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
    registry: Arc<bastion_gateway::RuntimeRegistry>,
    recording: Option<bastion_gateway::RecordingConfig>,
    legacy_unrecorded_shell: bool,
    shutdown: CancellationToken,
}
#[async_trait]
impl GatewayBackend for Backend {
    fn registry(&self) -> Arc<bastion_gateway::RuntimeRegistry> {
        self.registry.clone()
    }
    fn recording_config(&self) -> Option<bastion_gateway::RecordingConfig> {
        self.recording.clone()
    }
    fn allows_unrecorded_shell(&self) -> bool {
        self.legacy_unrecorded_shell
    }
    async fn begin_shell(
        &self,
        connection: &Connection,
        upstream: u32,
        recording: bastion_domain::RecordingCreate,
    ) -> Result<Uuid, ErrorCode> {
        if self.shutdown.is_cancelled() {
            return Err(ErrorCode::RecordingUnavailable);
        }
        Ok(self
            .store
            .begin_channel(
                connection,
                upstream,
                bastion_domain::ChannelKind::Shell,
                Some(recording),
                Uuid::new_v4(),
            )
            .await?
            .id)
    }
    async fn activate_shell(
        &self,
        connection: &Connection,
        channel: Uuid,
        recording: Uuid,
    ) -> Result<(), ErrorCode> {
        if self.shutdown.is_cancelled() {
            return Err(ErrorCode::RecordingUnavailable);
        }
        self.store.authorize_connection(connection).await?;
        self.store.activate_recording(recording).await?;
        self.store
            .transition_channel(channel, bastion_domain::ChannelState::Starting)
            .await
    }
    async fn checkpoint_recording(
        &self,
        id: Uuid,
        written: i64,
        synced: i64,
        bytes: i64,
    ) -> Result<(), ErrorCode> {
        self.store
            .checkpoint_recording(id, written, synced, bytes)
            .await
    }
    async fn finish_shell(
        &self,
        channel: Uuid,
        _recording: Uuid,
        state: bastion_domain::RecordingState,
        _bytes: i64,
        checksum: Option<String>,
        exit_code: Option<u32>,
        exit_signal: Option<String>,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.store
            .finish_channel_and_recording(
                channel,
                exit_code,
                exit_signal.as_deref(),
                failure,
                Some(state),
                checksum.as_deref(),
            )
            .await
    }
    async fn begin_channel(
        &self,
        connection: &Connection,
        upstream: u32,
        kind: bastion_domain::ChannelKind,
    ) -> Result<Uuid, ErrorCode> {
        if self.shutdown.is_cancelled() {
            return Err(ErrorCode::PolicyStoreUnavailable);
        }
        let channel = self
            .store
            .begin_channel(connection, upstream, kind, None, Uuid::new_v4())
            .await?;
        self.store
            .transition_channel(channel.id, bastion_domain::ChannelState::Starting)
            .await?;
        Ok(channel.id)
    }
    async fn mark_streaming(&self, channel: Uuid) -> Result<(), ErrorCode> {
        self.store
            .transition_channel(channel, bastion_domain::ChannelState::Streaming)
            .await
    }
    async fn finish_channel(
        &self,
        channel: Uuid,
        exit_code: Option<u32>,
        exit_signal: Option<String>,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.store
            .finish_channel_and_recording(
                channel,
                exit_code,
                exit_signal.as_deref(),
                failure,
                None,
                None,
            )
            .await
    }
    async fn consume(&self, id: Uuid, secret: &str) -> Result<(Connection, Target), ErrorCode> {
        if self.shutdown.is_cancelled() {
            return Err(ErrorCode::PolicyStoreUnavailable);
        }
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
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        response = (StatusCode::NOT_FOUND, [(header::CONTENT_TYPE, "application/json")],
            format!(r#"{{"error":{{"code":"RESOURCE_NOT_FOUND","message":"资源不存在","request_id":"{request_id}"}}}}"#)).into_response();
        response
            .headers_mut()
            .insert("x-request-id", HeaderValue::from_str(&request_id).unwrap());
        response
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
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
    serve_mode(path, false).await
}
pub async fn serve_production(path: PathBuf) -> Result<()> {
    serve_mode(path, true).await
}
async fn serve_mode(path: PathBuf, production_mode: bool) -> Result<()> {
    let config = Config::load(&path)?;
    if production_mode != config.production.is_some() {
        bail!("serve requires production configuration; serve-m1 requires legacy configuration");
    }
    if let Some(production) = &config.production {
        production.preflight()?;
        for path in std::iter::once(&config.database_url_file)
            .chain(std::iter::once(&config.ssh_host_key_file))
            .chain(config.kek_files.values())
        {
            crate::production::private_path(path, false)?;
        }
    }
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let mut lease = store.gateway_lock().await.map_err(store_error)?;
    store.recover_gateway().await.map_err(store_error)?;
    let keys = Arc::new(config.keys()?);
    if production_mode
        && store
            .referenced_key_versions()
            .await
            .map_err(store_error)?
            .iter()
            .any(|version| !config.kek_files.contains_key(&version.to_string()))
    {
        bail!("an in-use credential or recording KEK is missing; service is not ready");
    }
    let encoded = read_secret_file(&config.ssh_host_key_file)?;
    let key = russh::keys::decode_secret_key(encoded.expose(), None)?;
    let network = Arc::new(NetworkPolicy {
        allow: config.network.allow,
        deny: config.network.deny,
    });
    let gateway = GatewayAddress {
        id: config.gateway_id,
        host: config
            .ssh_public_host
            .clone()
            .unwrap_or_else(|| config.ssh_listen.ip().to_string()),
        port: config.ssh_public_port.unwrap_or(config.ssh_listen.port()),
        username: String::new(),
    };
    let shutdown = CancellationToken::new();
    let (registry, recording, file_max_bytes) = if let Some(production) = &config.production {
        let l = &production.limits;
        let limits = bastion_gateway::RuntimeLimits {
            global_connections: l.connections_global as usize,
            user_connections: l.connections_per_user as usize,
            pending_connections: l.pending_connections as usize,
            connection_channels: l.channels_per_connection as usize,
            user_channels: l.channels_per_user as usize,
            queue_bytes: l.queue_bytes as usize,
            max_duration: Duration::from_secs(l.absolute_seconds),
            idle_timeout: Duration::from_secs(l.idle_seconds),
            stall_timeout: Duration::from_secs(l.stalled_seconds),
        };
        let registry =
            Arc::new(bastion_gateway::RuntimeRegistry::with_limits(limits).map_err(store_error)?);
        let recording = bastion_gateway::RecordingConfig {
            server_id: config.server_id.clone(),
            directory: production.recording_directory.clone(),
            keys: keys.clone(),
            retention: Duration::from_secs(u64::from(production.retention_days) * 86400),
            min_free_bytes: production.minimum_free_bytes,
        };
        (registry, Some(recording), l.file_max_bytes)
    } else {
        (
            Arc::new(bastion_gateway::RuntimeRegistry::new()),
            None,
            1024 * 1024 * 1024,
        )
    };
    let backend = Arc::new(Backend {
        store: store.clone(),
        keys: keys.clone(),
        network: network.clone(),
        registry,
        recording,
        legacy_unrecorded_shell: !production_mode,
        shutdown: shutdown.clone(),
    });
    let mut api = bastion_api::ControlApi::new(
        store.clone(),
        keys.clone(),
        gateway,
        key.public_key().to_openssh()?,
        network.clone(),
    )?
    .with_service_state(shutdown.clone(), production_mode, false)
    .with_backend(backend.clone(), file_max_bytes);
    if let Some(production) = &config.production {
        api = api.with_recordings(production.recording_directory.clone());
    }
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
    tracing::info!(api=%config.api_listen,ssh=%config.ssh_listen,production=production_mode,"bastion service started; production release readiness remains false");
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
    let mut metrics_task = if let Some(production) = &config.production {
        app = app.layer(axum::middleware::from_fn_with_state(
            Arc::new(production.trusted_proxies.clone()),
            crate::proxy::enforce,
        ));
        let listener = TcpListener::bind(production.metrics_listen).await?;
        let metrics_stop = shutdown.clone();
        let shutdown_on_error = shutdown.clone();
        let status = shutdown.clone();
        let metrics=axum::Router::new().route("/metrics",axum::routing::get(move || {let status=status.clone();async move {
            ([(axum::http::header::CONTENT_TYPE,"text/plain; version=0.0.4")],format!("bastion_accepting_requests {}\nbastion_production_ready 0\nbastion_recording_required 1\nbastion_database_budget_seconds 2\n",u8::from(!status.is_cancelled())))
        }}));
        Some(tokio::spawn(async move {
            let result = axum::serve(listener, metrics)
                .with_graceful_shutdown(metrics_stop.cancelled_owned())
                .await;
            if result.is_err() {
                shutdown_on_error.cancel();
            }
            result
        }))
    } else {
        None
    };
    let http = axum::serve(
        http_listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown.clone().cancelled_owned())
    .into_future();
    let shutdown_registry = backend.registry();
    let ssh = bastion_gateway::run_backend(ssh_listener, key, backend, shutdown.clone());
    let mut http_task = tokio::spawn(http);
    let mut ssh_task = tokio::spawn(ssh);
    let first = tokio::select! {
        result = &mut http_task => { shutdown.cancel(); (Some(result), None) },
        result = &mut ssh_task => { shutdown.cancel(); (None, Some(result)) },
        _ = shutdown.cancelled() => (None, None),
    };
    let drain = async {
        let http_result = match first.0 {
            Some(result) => result,
            None => (&mut http_task).await,
        };
        let ssh_result = match first.1 {
            Some(result) => result,
            None => (&mut ssh_task).await,
        };
        http_result.context("HTTP task failed")??;
        ssh_result.context("SSH task failed")??;
        shutdown_registry
            .drain(Duration::from_secs(10))
            .await
            .map_err(store_error)?;
        Ok::<(), anyhow::Error>(())
    };
    let drained = tokio::time::timeout(Duration::from_secs(10), drain).await;
    signal.abort();
    ownership.abort();
    let _ = signal.await;
    let _ = ownership.await;
    if drained.is_err() {
        http_task.abort();
        ssh_task.abort();
        if let Some(task) = metrics_task.as_mut() {
            task.abort();
        }
        bail!("bounded gateway shutdown expired; recovery is required");
    }
    drained.unwrap()?;
    if let Some(task) = metrics_task.as_mut() {
        match tokio::time::timeout(Duration::from_secs(1), &mut *task).await {
            Ok(result) => result.context("metrics task failed")??,
            Err(_) => {
                task.abort();
                bail!("metrics shutdown exceeded deadline");
            }
        }
    }
    if lease_lost.load(std::sync::atomic::Ordering::Relaxed) {
        bail!("gateway database ownership was lost; restart required");
    }
    Ok(())
}
