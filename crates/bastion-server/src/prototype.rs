use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bastion_domain::{Capability, GatewayAddress};
use bastion_gateway::{Target, TargetAuth};
use bastion_secrets::{read_secret_file, Secret};
use serde::Deserialize;
use std::{future::IntoFuture, net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    server_id: String,
    api_listen: SocketAddr,
    ssh_listen: SocketAddr,
    api_token_file: PathBuf,
    ssh_host_key_file: PathBuf,
    target: TargetConfig,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TargetConfig {
    asset_id: Uuid,
    account_id: Uuid,
    name: String,
    address: SocketAddr,
    username: String,
    host_key_file: PathBuf,
    capabilities: Vec<Capability>,
    credentials: AuthConfig,
}
#[derive(Deserialize)]
#[serde(tag = "auth", rename_all = "snake_case", deny_unknown_fields)]
enum AuthConfig {
    Password {
        password_file: PathBuf,
    },
    PrivateKey {
        private_key_file: PathBuf,
        passphrase_file: Option<PathBuf>,
    },
}

pub async fn serve(path: PathBuf) -> Result<()> {
    let config: Config = toml::from_str(
        &std::fs::read_to_string(&path).context("cannot read prototype configuration")?,
    )?;
    if !config.api_listen.ip().is_loopback()
        || !config.ssh_listen.ip().is_loopback()
        || config.api_listen.port() == 0
        || config.ssh_listen.port() == 0
    {
        bail!("development prototype must listen on loopback with explicit nonzero ports");
    }
    if config.server_id.is_empty()
        || config.target.capabilities.is_empty()
        || config.target.capabilities.len() > 3
        || config.target.address.port() == 0
        || config.target.username.is_empty()
        || config.target.username.len() > 128
        || config.target.username.chars().any(char::is_control)
    {
        bail!("invalid server identity, target username, capabilities or port");
    }
    let token = read_secret_file(&config.api_token_file)?;
    let token = Secret::new(token.expose().trim_end_matches(['\r', '\n']).to_owned());
    if URL_SAFE_NO_PAD.decode(token.expose())?.len() < 32 {
        bail!("development bearer must contain at least 32 random bytes");
    }
    let key = read_secret_file(&config.ssh_host_key_file)?;
    let key = russh::keys::decode_secret_key(key.expose(), None)?;
    let public_key = russh::keys::PublicKey::from_openssh(&std::fs::read_to_string(
        &config.target.host_key_file,
    )?)?;
    let auth = match config.target.credentials {
        AuthConfig::Password { password_file } => TargetAuth::PasswordFile(password_file),
        AuthConfig::PrivateKey {
            private_key_file,
            passphrase_file,
        } => TargetAuth::PrivateKeyFile {
            path: private_key_file,
            passphrase_file,
        },
    };
    let target = Target {
        address: bastion_gateway::TargetEndpoint::Direct(config.target.address),
        username: config.target.username.clone(),
        public_keys: vec![public_key],
        auth,
    };
    let store = Arc::new(bastion_store::PrototypeStore::new(Duration::from_secs(30)));
    let api = Arc::new(bastion_api::PrototypeApi {
        store: store.clone(),
        bearer_hash: token.hash(),
        server_id: config.server_id,
        gateway: GatewayAddress {
            id: "prototype-main".into(),
            host: config.ssh_listen.ip().to_string(),
            port: config.ssh_listen.port(),
            username: String::new(),
        },
        gateway_public_key: key.public_key().to_openssh()?,
        asset_id: config.target.asset_id,
        account_id: config.target.account_id,
        asset_name: config.target.name,
        target_username: config.target.username,
        allowed: config.target.capabilities,
    });
    let api_listener = TcpListener::bind(config.api_listen).await?;
    let ssh_listener = TcpListener::bind(config.ssh_listen).await?;
    let shutdown = CancellationToken::new();
    let signal_shutdown = shutdown.clone();
    let signal = tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut term =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("signal handler");
            tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
        }
        #[cfg(not(unix))]
        let _ = tokio::signal::ctrl_c().await;
        signal_shutdown.cancel();
    });
    tracing::info!(api = %config.api_listen, ssh = %config.ssh_listen, "M0 prototype started; no production authentication or recording");
    let api_shutdown = shutdown.clone();
    let http = axum::serve(api_listener, bastion_api::router(api))
        .with_graceful_shutdown(api_shutdown.cancelled_owned())
        .into_future();
    let gateway = bastion_gateway::run(ssh_listener, key, target, store, shutdown.clone());
    let (http_result, gateway_result) = tokio::join!(
        async {
            let result = http.await;
            shutdown.cancel();
            result
        },
        async {
            let result = gateway.await;
            shutdown.cancel();
            result
        }
    );
    signal.abort();
    http_result?;
    gateway_result
}
