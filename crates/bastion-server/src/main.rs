use anyhow::{bail, Result};
#[cfg(unix)]
use bastion_secrets::Secret;
use clap::{Parser, Subcommand};
#[cfg(unix)]
use std::io::Write;
use std::path::PathBuf;
mod control;
mod native;
mod production;
mod proxy;

#[derive(Parser)]
#[command(
    version,
    about = "SSH/RDP/VNC bastion with browser and native SSH entry"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Run the production service behind a trusted TLS reverse proxy.
    Serve {
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
    /// Create the first administrator only if none exists, for unattended setup. The password comes
    /// from BASTION_ADMIN_PASSWORD or BASTION_ADMIN_PASSWORD_FILE, or is generated and printed once.
    EnsureAdmin {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "admin")]
        username: String,
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
    /// Initialize a fresh owner-only credential-encryption key (KEK).
    Init {
        #[arg(long, default_value = ".local")]
        directory: PathBuf,
    },
    /// Verify a disposable backup without migration or restoring secrets.
    VerifyBackup {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        manifest: PathBuf,
    },
    /// Revoke restored login families and mark runtime state interrupted.
    RecoverRestore {
        #[arg(long)]
        config: PathBuf,
    },
    /// Rewrap credential and recording DEKs under the active KEK without rewriting files.
    RewrapKeys {
        #[arg(long)]
        config: PathBuf,
    },
    /// Expire only inactive recording files selected by database retention.
    RetainRecordings {
        #[arg(long)]
        config: PathBuf,
    },
    /// Offline maintenance-owner conversion to registered monthly audit partitions.
    PartitionAudit {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        offline: bool,
    },
    /// Offline maintenance-owner retention; never drop the default audit partition.
    RetainAudit {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        offline: bool,
        #[arg(long, default_value_t = 180)]
        days: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // No protocol debug logs or request bodies: these can contain credentials.
    tracing_subscriber::fmt()
        .with_env_filter("bastion_server=info,bastion_gateway=info")
        .init();
    // A bad BASTION_PASSWORD_MIN_LENGTH must stop startup, not surface on the first password change.
    bastion_secrets::password_min_length()?;
    match Cli::parse().command {
        Command::Serve { config } => control::serve_production(config).await,
        Command::Migrate { config } => control::migrate(config).await,
        Command::CreateAdmin {
            config,
            username,
            password_stdin,
        } => control::create_admin(config, username, password_stdin).await,
        Command::EnsureAdmin { config, username } => control::ensure_admin(config, username).await,
        Command::ResetUser {
            config,
            username,
            password_stdin,
        } => control::reset_user(config, username, password_stdin).await,
        Command::VerifyBackup { config, manifest } => {
            control::verify_backup(config, manifest).await
        }
        Command::RecoverRestore { config } => control::recover_restore(config).await,
        Command::RewrapKeys { config } => control::rewrap_keys(config).await,
        Command::RetainRecordings { config } => control::retain_recordings(config).await,
        Command::PartitionAudit { config, offline } => {
            control::partition_audit(config, offline).await
        }
        Command::RetainAudit {
            config,
            offline,
            days,
        } => control::retain_audit(config, offline, days).await,
        Command::Init { directory } => init(directory),
    }
}

#[cfg(not(unix))]
fn init(_directory: PathBuf) -> Result<()> {
    bail!("bastion initialization requires a Unix host with owner-only secret permissions")
}

#[cfg(unix)]
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
    let kek_path = directory.join("kek-v1");
    if kek_path.exists() {
        bail!("KEK already exists; refusing to overwrite encryption identity");
    }
    let kek = Secret::random();
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(kek_path)?;
    file.write_all(kek.expose().as_bytes())?;
    file.sync_all()?;
    println!("Initialized KEK in {}", directory.display());
    Ok(())
}
