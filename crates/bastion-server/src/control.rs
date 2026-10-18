use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use bastion_domain::{Connection, ConnectionState, ErrorCode};
use bastion_gateway::{GatewayBackend, NetworkPolicy};
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
    guacd: bastion_gateway::GuacdConfig,
    production: Option<crate::production::Production>,
    database_url_file: PathBuf,
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
fn private_api_address(address: SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            std::net::IpAddr::V4(ip) => ip.is_loopback() || ip.is_private(),
            std::net::IpAddr::V6(ip) => ip.is_loopback() || ip.is_unique_local(),
        }
}
impl Config {
    fn load(path: &Path) -> Result<Self> {
        let config: Self =
            toml::from_str(&std::fs::read_to_string(path).context("cannot read configuration")?)?;
        let production = config
            .production
            .as_ref()
            .context("browser-only service requires production configuration")?;
        production.validate()?;
        let origin: axum::http::Uri = config
            .public_origin
            .as_deref()
            .context("HTTPS origin is required")?
            .parse()
            .context("invalid HTTPS origin")?;
        if origin.scheme_str() != Some("https")
            || origin.authority().is_none_or(|a| a.as_str().contains('@'))
            || origin.host().is_none_or(|h| h.is_empty())
            || origin.path_and_query().is_some_and(|p| p.as_str() != "/")
            || !private_api_address(config.api_listen)
        {
            bail!("browser-only service requires a private API address and exact HTTPS authority");
        }
        if config.guacd.version != "1.6.0"
            || config.guacd.bridge_bind.port() != 0
            || config.guacd.bridge_bind.ip().is_unspecified()
            || config.guacd.allowed_source_ips.is_empty()
            || config.guacd.address.port() == 0
            || config.guacd.address.ip().is_unspecified()
            || config
                .guacd
                .bridge_advertise_host
                .parse::<std::net::IpAddr>()
                .is_err()
        {
            bail!("guacd requires an explicit pinned engine and restricted private TCP bridge");
        }
        config.guacd.validate().map_err(store_error)?;
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
/// Reads at most one password line, stripping one line ending but keeping intentional spaces.
fn password_line(input: impl Read) -> Result<Secret> {
    let mut bytes = String::new();
    input.take(1026).read_to_string(&mut bytes)?;
    if bytes.len() > 1025 {
        bail!("password input exceeds limit");
    }
    if bytes.ends_with('\n') {
        bytes.pop();
        if bytes.ends_with('\r') {
            bytes.pop();
        }
    }
    Ok(Secret::new(bytes))
}
fn password(stdin: bool) -> Result<Secret> {
    if stdin {
        password_line(std::io::stdin())
    } else {
        let min = bastion_secrets::password_min_length()?;
        Ok(Secret::new(rpassword::prompt_password(format!(
            "New password ({min}+ bytes): "
        ))?))
    }
}
fn admin_username(username: &str) -> Result<String> {
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
    Ok(username)
}
/// The first administrator's password: an explicit value or file wins; otherwise one is generated.
/// Also returns whether it was generated, because only a generated password may be printed.
fn bootstrap_password(value: Option<String>, file: Option<String>) -> Result<(Secret, bool)> {
    match (
        value.filter(|v| !v.is_empty()),
        file.filter(|v| !v.is_empty()),
    ) {
        (Some(_), Some(_)) => {
            bail!("set only one of BASTION_ADMIN_PASSWORD and BASTION_ADMIN_PASSWORD_FILE")
        }
        (Some(value), None) => Ok((Secret::new(value), false)),
        // A plain read: Docker secrets are typically 0444 root-owned, unlike owner-only KEK files.
        (None, Some(path)) => {
            let file =
                std::fs::File::open(&path).context("cannot open BASTION_ADMIN_PASSWORD_FILE")?;
            Ok((password_line(file)?, false))
        }
        (None, None) => Ok((Secret::random(), true)),
    }
}
/// Idempotent bootstrap for `docker compose up`: creates the first administrator only when none
/// exists, so a later run can never reset an existing password.
pub async fn ensure_admin(path: PathBuf, username: String) -> Result<()> {
    let username = admin_username(&username)?;
    let store = Config::load(&path)?.store().await?;
    store.check_identity().await.map_err(store_error)?;
    if store.admin_exists().await.map_err(store_error)? {
        println!(
            "An administrator already exists; nothing to do (admin password settings are ignored)."
        );
        return Ok(());
    }
    let (password, generated) = bootstrap_password(
        std::env::var("BASTION_ADMIN_PASSWORD").ok(),
        std::env::var("BASTION_ADMIN_PASSWORD_FILE").ok(),
    )?;
    let phc = hash_password(password.expose())?;
    let user = store
        .bootstrap_admin(&username, &phc, Uuid::new_v4())
        .await
        .map_err(store_error)?;
    if generated {
        println!("==================================================================");
        println!(" Initial administrator created: {}", user.username);
        println!(
            " Generated password (printed only this once): {}",
            password.expose()
        );
        println!(" Log in and change it under 个人设置. This container's log keeps it");
        println!(" until the container is removed (docker compose rm bootstrap-admin).");
        println!("==================================================================");
    } else {
        println!(
            "Initial administrator created: {} (password from the environment)",
            user.username
        );
    }
    Ok(())
}
pub async fn create_admin(path: PathBuf, username: String, stdin: bool) -> Result<()> {
    let username = admin_username(&username)?;
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
    registry: Arc<bastion_gateway::RuntimeRegistry>,
    recording: Option<bastion_gateway::RecordingConfig>,
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
    async fn authorize(&self, connection: &Connection) -> Result<(), ErrorCode> {
        if self.shutdown.is_cancelled() {
            return Err(ErrorCode::PolicyStoreUnavailable);
        }
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
    async fn begin_recording(
        &self,
        connection: &Connection,
        recording: bastion_domain::RecordingCreate,
    ) -> Result<(), ErrorCode> {
        if self.shutdown.is_cancelled() {
            return Err(ErrorCode::RecordingUnavailable);
        }
        self.store
            .create_recording(connection, recording, Uuid::new_v4())
            .await?;
        Ok(())
    }
    async fn activate_recording(
        &self,
        connection: &Connection,
        recording: Uuid,
    ) -> Result<(), ErrorCode> {
        self.authorize(connection).await?;
        self.store.activate_recording(recording).await
    }
    async fn activate_native_connection(&self, connection: &Connection) -> Result<(), ErrorCode> {
        self.authorize(connection).await?;
        self.store.activate_native_connection(connection).await
    }
    async fn exec_completed(
        &self,
        connection: &Connection,
        command: &[u8],
        outcome: &bastion_domain::ExecOutcome,
    ) -> Result<(), ErrorCode> {
        self.store
            .exec_completed(connection, command, outcome)
            .await
    }
    async fn sftp_audit(
        &self,
        connection: &Connection,
        entry: &bastion_domain::SftpAudit,
    ) -> Result<(), ErrorCode> {
        self.store.sftp_audit(connection, entry).await
    }
    async fn sftp_rejected(
        &self,
        connection: &Connection,
        reason: ErrorCode,
    ) -> Result<(), ErrorCode> {
        self.store.sftp_rejected(connection, reason).await
    }
    async fn exec_rejected(
        &self,
        connection: &Connection,
        command: &[u8],
        reason: ErrorCode,
    ) -> Result<(), ErrorCode> {
        self.store.exec_rejected(connection, command, reason).await
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
    async fn finish_recording(
        &self,
        id: Uuid,
        state: bastion_domain::RecordingState,
        bytes: i64,
        checksum: Option<String>,
        failure: Option<ErrorCode>,
    ) -> Result<(), ErrorCode> {
        self.store
            .finish_recording(id, state, bytes, checksum.as_deref(), failure)
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
        ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; font-src 'self'; img-src 'self' data: blob:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
    ] {
        response.headers_mut().insert(name, HeaderValue::from_static(value));
    }
    response
}

pub async fn serve_production(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    let production = config
        .production
        .as_ref()
        .context("production configuration is required")?;
    production.preflight()?;
    for path in std::iter::once(&config.database_url_file).chain(config.kek_files.values()) {
        crate::production::private_path(path, false)?;
    }
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let mut lease = store.gateway_lock().await.map_err(store_error)?;
    store.recover_gateway().await.map_err(store_error)?;
    let keys = Arc::new(config.keys()?);
    if store
        .referenced_key_versions()
        .await
        .map_err(store_error)?
        .iter()
        .any(|version| !config.kek_files.contains_key(&version.to_string()))
    {
        bail!("an in-use credential or recording KEK is missing; service is not ready");
    }
    let network = Arc::new(NetworkPolicy {
        allow: config.network.allow.clone(),
        deny: config.network.deny.clone(),
    });
    let shutdown = CancellationToken::new();
    let l = &production.limits;
    let limits = bastion_gateway::RuntimeLimits {
        global_connections: l.connections_global as usize,
        user_connections: l.connections_per_user as usize,
        pending_connections: l.pending_connections as usize,
        queue_bytes: l.queue_bytes as usize,
        startup_timeout: Duration::from_secs(l.startup_seconds),
        max_duration: Duration::from_secs(l.absolute_seconds),
        idle_timeout: Duration::from_secs(l.idle_seconds),
        stall_timeout: Duration::from_secs(l.stalled_seconds),
    };
    store
        .configure_session_limits(
            l.connections_global as usize,
            l.connections_per_user as usize,
            l.pending_connections as usize,
        )
        .map_err(store_error)?;
    let registry =
        Arc::new(bastion_gateway::RuntimeRegistry::with_limits(limits).map_err(store_error)?);
    let recording = bastion_gateway::RecordingConfig {
        server_id: config.server_id.clone(),
        directory: production.recording_directory.clone(),
        keys: keys.clone(),
        retention: Duration::from_secs(u64::from(production.retention_days) * 86400),
        min_free_bytes: production.minimum_free_bytes,
    };
    let backend = Arc::new(Backend {
        store: store.clone(),
        registry,
        recording: Some(recording),
        shutdown: shutdown.clone(),
    });
    let origin = config
        .public_origin
        .clone()
        .context("HTTPS origin required")?;
    let origin_host = origin
        .parse::<axum::http::Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_owned))
        .context("HTTPS origin required")?;
    let native = crate::native::load(&path, &origin_host, |name| std::env::var(name).ok())?;
    let mut api = bastion_api::ControlApi::new(store.clone(), keys, network, config.guacd.clone())?
        .with_service_state(shutdown.clone(), true, false)
        .with_recordings(production.recording_directory.clone())
        .with_browser(origin, backend.clone(), shutdown.clone())?;
    let mut native_listener = None;
    if let Some(native) = &native {
        let gateway = bastion_api::NativeGateway::new(
            config.gateway_id.clone(),
            native.public_host.clone(),
            native.public_port,
            native.public_key()?,
        );
        let listener = TcpListener::bind(native.listen)
            .await
            .context("cannot bind BASTION_NATIVE_SSH_LISTEN")?;
        native_listener = Some((listener, gateway.listener_running()));
        api = api.with_native(gateway);
    }
    let api = Arc::new(api);
    let http_listener = TcpListener::bind(config.api_listen).await?;
    // RFC-006 §7: the SSH listener shares the API's ticket store, limiter, registry and shutdown.
    let mut native_task = match (native, native_listener) {
        (Some(native), Some((listener, running))) => {
            let listener_config = bastion_gateway::NativeListenerConfig {
                host_key: native.host_key,
                max_unauthenticated: native.max_unauthenticated,
                handshake_timeout: Duration::from_secs(10),
            };
            let tickets = Arc::new(bastion_api::NativeTicketService(api.clone()));
            let gateway_backend: Arc<dyn GatewayBackend> = backend.clone();
            let stop = shutdown.clone();
            tracing::info!(listen=%native.listen,"native SSH entry listening");
            Some(tokio::spawn(async move {
                let result = bastion_gateway::serve_native(
                    listener,
                    listener_config,
                    tickets,
                    gateway_backend,
                    stop.clone(),
                    running,
                )
                .await;
                // A listener that stopped on its own is a service failure, not a silent downgrade.
                stop.cancel();
                result
            }))
        }
        _ => None,
    };
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
    tracing::info!(api=%config.api_listen,"browser-only bastion started; production release readiness remains false");
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
    let mut http_task = tokio::spawn(http);
    let first = tokio::select! {
        result = &mut http_task => { shutdown.cancel(); Some(result) },
        _ = shutdown.cancelled() => None,
    };
    let drain = async {
        let result = match first {
            Some(result) => result,
            None => (&mut http_task).await,
        };
        result.context("HTTP task failed")??;
        if let Some(task) = native_task.as_mut() {
            task.await
                .context("native SSH task failed")?
                .map_err(|code| anyhow::anyhow!("native SSH listener: {code}"))?;
        }
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
        if let Some(task) = native_task.as_mut() {
            task.abort();
        }
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

#[cfg(test)]
mod bootstrap_tests {
    use super::{bootstrap_password, password_line};
    #[test]
    fn explicit_password_wins_and_only_an_absent_one_is_generated() {
        let (value, generated) =
            bootstrap_password(Some("explicit-pass-123".into()), None).unwrap();
        assert_eq!((value.expose(), generated), ("explicit-pass-123", false));
        let (value, generated) = bootstrap_password(Some(String::new()), None).unwrap();
        assert!(generated, "an empty variable counts as unset");
        assert!(value.expose().len() >= 32);
        let (other, _) = bootstrap_password(None, None).unwrap();
        assert_ne!(
            value.expose(),
            other.expose(),
            "generated passwords are random"
        );
        assert!(bootstrap_password(Some("a".into()), Some("/x".into())).is_err());
        assert!(bootstrap_password(None, Some("/nonexistent/admin-password".into())).is_err());
    }
    #[test]
    fn password_lines_strip_one_line_ending_only() {
        assert_eq!(
            password_line(&b"secret pass \r\n"[..]).unwrap().expose(),
            "secret pass "
        );
        assert_eq!(password_line(&b"two\n\n"[..]).unwrap().expose(), "two\n");
        assert!(password_line(&vec![b'a'; 1026][..]).is_err());
    }
}
#[cfg(test)]
mod listener_tests {
    use super::private_api_address;
    #[test]
    fn internal_listener_requires_an_explicit_private_address() {
        for address in [
            "127.0.0.1:8080",
            "172.30.63.2:8080",
            "[::1]:8080",
            "[fd00::2]:8080",
        ] {
            assert!(private_api_address(address.parse().unwrap()));
        }
        for address in [
            "0.0.0.0:8080",
            "172.30.63.2:0",
            "192.0.2.2:8080",
            "[::]:8080",
            "[2001:db8::2]:8080",
        ] {
            assert!(!private_api_address(address.parse().unwrap()));
        }
    }
}
