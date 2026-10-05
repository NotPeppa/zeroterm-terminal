use super::*;
use bastion_domain::RecordingState;
use serde::Deserialize;

async fn audit_connection(config: &Config) -> Result<sqlx::PgConnection> {
    use sqlx::ConnectOptions;
    use std::str::FromStr;
    let secret = read_secret_file(&config.database_url_file)?;
    let options =
        sqlx::postgres::PgConnectOptions::from_str(secret.expose().trim_end_matches(['\r', '\n']))
            .map_err(|_| anyhow::anyhow!("invalid maintenance database connection configuration"))?
            .disable_statement_logging();
    tokio::time::timeout(
        Duration::from_secs(2),
        sqlx::PgConnection::connect_with(&options),
    )
    .await
    .map_err(|_| anyhow::anyhow!("maintenance database connection budget elapsed"))?
    .map_err(|_| anyhow::anyhow!("maintenance database connection failed"))
}
pub(super) async fn partition_audit(path: PathBuf, offline: bool) -> Result<()> {
    if !offline {
        bail!("partition-audit requires explicit --offline and stopped database clients");
    }
    let config = Config::load(&path)?;
    let mut connection = audit_connection(&config).await?;
    bastion_store::audit_partition_upgrade(&mut connection, &config.server_id, &config.gateway_id)
        .await
        .map_err(store_error)?;
    connection
        .close()
        .await
        .map_err(|_| anyhow::anyhow!("maintenance connection close failed"))?;
    println!("Offline audit partition conversion verified; append-only protections remain enabled");
    Ok(())
}
pub(super) async fn retain_audit(path: PathBuf, offline: bool, days: u32) -> Result<()> {
    if !offline {
        bail!("retain-audit requires explicit --offline and stopped database clients");
    }
    if !(1..=3650).contains(&days) {
        bail!("audit retention days must be 1..3650");
    }
    let config = Config::load(&path)?;
    let mut connection = audit_connection(&config).await?;
    let result = bastion_store::maintain_audit_partitions(
        &mut connection,
        &config.server_id,
        &config.gateway_id,
        days as u16,
    )
    .await
    .map_err(store_error)?;
    connection
        .close()
        .await
        .map_err(|_| anyhow::anyhow!("maintenance connection close failed"))?;
    println!("Audit maintenance created {} monthly partitions, dropped {} expired partitions, default partition rows {}; repeat explicit offline maintenance to process more",result.created.len(),usize::from(result.dropped.is_some()),result.default_rows);
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupManifest {
    server_id: String,
    schema_version: u32,
    credential_count: u64,
    recording_count: u64,
    host_key_count: u64,
    kek_versions: Vec<i64>,
}
/// Verify a disposable restored database/files against its separately preserved manifest.
/// Holds gateway ownership, does not migrate or restore credentials, and never emits secrets.
pub(super) async fn verify_backup(path: PathBuf, manifest_path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    let production = config
        .production
        .as_ref()
        .context("backup verification requires production configuration")?;
    production.preflight()?;
    let mut manifest_bytes = Vec::new();
    std::fs::File::open(&manifest_path)
        .context("cannot read backup manifest")?
        .take(16385)
        .read_to_end(&mut manifest_bytes)?;
    if manifest_bytes.len() > 16384 {
        bail!("backup manifest too large");
    }
    let mut manifest: BackupManifest =
        serde_json::from_slice(&manifest_bytes).context("invalid backup manifest")?;
    if manifest.server_id != config.server_id || manifest.schema_version != 1 {
        bail!("backup manifest identity/schema mismatch");
    }
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let lease = store.gateway_lock().await.map_err(store_error)?;
    let keys = Arc::new(config.keys()?);
    let versions = store.referenced_key_versions().await.map_err(store_error)?;
    manifest.kek_versions.sort();
    manifest.kek_versions.dedup();
    if versions != manifest.kek_versions
        || versions
            .iter()
            .any(|version| !config.kek_files.contains_key(&version.to_string()))
    {
        bail!("backup in-use KEK manifest mismatch");
    }
    let mut credentials = 0u64;
    let mut after = None;
    loop {
        let batch = store
            .credential_manifest(after, 200)
            .await
            .map_err(store_error)?;
        if batch.is_empty() {
            break;
        }
        for entry in batch {
            after = Some(entry.context.credential_id);
            let credential = keys
                .open(&entry.context, &entry.envelope)
                .map_err(|_| anyhow::anyhow!("backup credential verification failed"))?;
            if let bastion_secrets::Credential::PrivateKey {
                key_pem,
                passphrase,
            } = &credential
            {
                russh::keys::decode_secret_key(key_pem, passphrase.as_deref())
                    .map_err(|_| anyhow::anyhow!("backup private key validation failed"))?;
            }
            credentials += 1;
        }
    }
    let mut host_keys = 0u64;
    for asset in store.admin_assets().await.map_err(store_error)? {
        for host_key in store.host_keys(asset.id).await.map_err(store_error)? {
            let key = russh::keys::PublicKey::from_openssh(&host_key.public_key)
                .map_err(|_| anyhow::anyhow!("backup host key validation failed"))?;
            let fingerprint = key.fingerprint(russh::keys::HashAlg::Sha256).to_string();
            if fingerprint != host_key.fingerprint {
                bail!("backup host key fingerprint mismatch");
            }
            host_keys += 1;
        }
    }
    let mut recordings = 0u64;
    after = None;
    loop {
        let batch = store
            .recording_manifest(after, 200)
            .await
            .map_err(store_error)?;
        if batch.is_empty() {
            break;
        }
        for entry in batch {
            after = Some(entry.metadata.id);
            if !matches!(
                entry.metadata.state,
                RecordingState::Complete | RecordingState::Partial
            ) {
                bail!("backup contains unavailable recording");
            }
            let root = production.recording_directory.clone();
            let keys = keys.clone();
            let server_id = config.server_id.clone();
            tokio::task::spawn_blocking(move || {
                bastion_api::verify_recording_file(root, entry, keys, server_id)
            })
            .await
            .context("backup replay task failed")?
            .map_err(|_| anyhow::anyhow!("backup recording integrity verification failed"))?;
            recordings += 1;
        }
    }
    if (credentials, recordings, host_keys)
        != (
            manifest.credential_count,
            manifest.recording_count,
            manifest.host_key_count,
        )
    {
        bail!("backup manifest object counts mismatch");
    }
    lease.close().await?;
    println!("Backup identity, schema, in-use keys, credentials, host keys and recording integrity verified; release readiness remains false");
    Ok(())
}
pub(super) async fn rewrap_keys(path: PathBuf) -> Result<()> {
    use bastion_secrets::recording::{RecordingContext, RecordingEnvelope};
    let config = Config::load(&path)?;
    if config.production.is_none() {
        bail!("KEK rewrap requires production configuration");
    }
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let lease = store.gateway_lock().await.map_err(store_error)?;
    let keys = config.keys()?;
    let mut credentials = 0u64;
    let mut recordings = 0u64;
    let mut after = None;
    loop {
        let batch = store
            .credential_manifest(after, 200)
            .await
            .map_err(store_error)?;
        if batch.is_empty() {
            break;
        }
        for entry in batch {
            after = Some(entry.context.credential_id);
            if entry.envelope.key_version == config.active_kek_version {
                continue;
            }
            let envelope = keys
                .rewrap_credential_dek(&entry.context, &entry.envelope)
                .map_err(|_| anyhow::anyhow!("credential KEK rewrap failed"))?;
            if !store
                .rewrap_credential(
                    entry.context.credential_id,
                    entry.envelope.key_version,
                    &envelope,
                )
                .await
                .map_err(store_error)?
            {
                bail!("credential changed during rewrap; stop and rerun without automatic retry");
            }
            credentials += 1;
        }
    }
    after = None;
    loop {
        let batch = store
            .recording_manifest(after, 200)
            .await
            .map_err(store_error)?;
        if batch.is_empty() {
            break;
        }
        for entry in batch {
            after = Some(entry.metadata.id);
            if entry.key_version == config.active_kek_version {
                continue;
            }
            let context = RecordingContext::new(&config.server_id, entry.metadata.id);
            let old = RecordingEnvelope {
                wrapped_dek: entry.wrapped_dek,
                wrap_nonce: entry.wrap_nonce,
                key_version: entry.key_version,
            };
            let envelope = keys
                .rewrap_recording_dek(&context, &old)
                .map_err(|_| anyhow::anyhow!("recording KEK rewrap failed"))?;
            if !store
                .rewrap_recording(
                    entry.metadata.id,
                    old.key_version,
                    &envelope.wrapped_dek,
                    &envelope.wrap_nonce,
                    envelope.key_version,
                )
                .await
                .map_err(store_error)?
            {
                bail!("recording changed during rewrap; stop and rerun without automatic retry");
            }
            recordings += 1;
        }
    }
    lease.close().await?;
    println!("Rewrapped {credentials} credential DEKs and {recordings} recording DEKs; retain all old KEKs until backups and references are verified");
    Ok(())
}

pub(super) async fn recover_restore(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let lease = store.gateway_lock().await.map_err(store_error)?;
    while store
        .revoke_restored_login_families(200)
        .await
        .map_err(store_error)?
        != 0
    {}
    store.recover_gateway().await.map_err(store_error)?;
    lease.close().await?;
    println!("Restored login families revoked; tickets and active runtime state interrupted; no replay or resume");
    Ok(())
}
pub(super) async fn retain_recordings(path: PathBuf) -> Result<()> {
    let config = Config::load(&path)?;
    let production = config
        .production
        .as_ref()
        .context("retention requires production recording directory")?;
    crate::production::private_path(&production.recording_directory, true)?;
    bastion_gateway::check_recording_directory(&production.recording_directory, 0)
        .map_err(store_error)?;
    let store = config.store().await?;
    store.check_identity().await.map_err(store_error)?;
    let lease = store.gateway_lock().await.map_err(store_error)?;
    let mut expired = 0u64;
    loop {
        let batch = store
            .recording_retention_candidates(200)
            .await
            .map_err(store_error)?;
        if batch.is_empty() {
            break;
        }
        for item in batch {
            let root = production.recording_directory.clone();
            let result = tokio::task::spawn_blocking(move || {
                bastion_api::remove_recording_file(&root, &item.relative_path)
            })
            .await
            .context("retention file task failed")?;
            if result.is_err() {
                bail!("recording retention failed; metadata was not expired");
            }
            store.expire_recording(item.id).await.map_err(store_error)?;
            expired += 1;
        }
    }
    lease.close().await?;
    println!("Expired {expired} inactive recording files; audit retention is not performed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn manifest_is_public_metadata_only_and_rejects_unknown_fields() {
        assert!(serde_json::from_str::<BackupManifest>(r#"{"server_id":"a","schema_version":1,"credential_count":0,"recording_count":0,"host_key_count":0,"kek_versions":[1]}"#).is_ok());
        assert!(serde_json::from_str::<BackupManifest>(r#"{"server_id":"a","schema_version":1,"credential_count":0,"recording_count":0,"host_key_count":0,"kek_versions":[1],"kek":"secret"}"#).is_err());
    }
}
