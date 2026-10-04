use anyhow::{bail, Context, Result};
use bastion_secrets::Secret;
use clap::{Parser, Subcommand};
use std::{io::Write, path::PathBuf};
mod control;

#[cfg(feature = "dev-prototype")]
mod prototype;

#[derive(Parser)]
#[command(
    version,
    about = "ZeroTerm companion SSH bastion (M1 integration milestone)"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run the authenticated M1 integration service (loopback only).
    ServeM1 {
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply PostgreSQL migrations explicitly.
    Migrate {
        #[arg(long)]
        config: PathBuf,
    },
    /// Create the first administrator. Password is read securely, never from argv.
    CreateAdmin {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Recover a local user and revoke all of their login sessions.
    ResetUser {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        username: String,
        #[arg(long)]
        password_stdin: bool,
    },
    /// Initialize a development gateway host key and API bearer file.
    Init {
        #[arg(long, default_value = ".local")]
        directory: PathBuf,
    },
    /// Run the development-only fixed-asset gateway. Requires --features dev-prototype.
    #[cfg(feature = "dev-prototype")]
    Prototype {
        #[arg(long)]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // No protocol debug logs or request bodies: these can contain credentials.
    tracing_subscriber::fmt()
        .with_env_filter("bastion_server=info,bastion_gateway=info")
        .init();
    match Cli::parse().command {
        Command::ServeM1 { config } => control::serve(config).await,
        Command::Migrate { config } => control::migrate(config).await,
        Command::CreateAdmin {
            config,
            username,
            password_stdin,
        } => control::create_admin(config, username, password_stdin).await,
        Command::ResetUser {
            config,
            username,
            password_stdin,
        } => control::reset_user(config, username, password_stdin).await,
        Command::Init { directory } => init(directory),
        #[cfg(feature = "dev-prototype")]
        Command::Prototype { config } => prototype::serve(config).await,
    }
}

fn init(directory: PathBuf) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
    if !directory.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)?;
    }
    let meta = std::fs::symlink_metadata(&directory)?;
    if !meta.is_dir() || meta.permissions().mode() & 0o077 != 0 {
        bail!("initialization directory must be a real directory with mode 0700");
    }
    let key_path = directory.join("ssh_host_ed25519_key");
    let token_path = directory.join("api-token");
    let kek_path = directory.join("kek-v1");
    if key_path.exists() || token_path.exists() || kek_path.exists() {
        bail!("initialization files already exist; refusing to overwrite identity");
    }
    let key = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)?;
    let encoded = key.to_openssh(russh::keys::ssh_key::LineEnding::LF)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&key_path)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    std::fs::write(
        directory.join("ssh_host_ed25519_key.pub"),
        key.public_key().to_openssh()?,
    )?;
    let token = Secret::random();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&token_path)
        .context("cannot create API token file")?;
    file.write_all(token.expose().as_bytes())?;
    file.sync_all()?;
    let kek = Secret::random();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(kek_path)?;
    file.write_all(kek.expose().as_bytes())?;
    file.sync_all()?;
    println!("Initialized development files in {}", directory.display());
    Ok(())
}
