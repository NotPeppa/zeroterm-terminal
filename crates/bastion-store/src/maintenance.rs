use crate::postgres::{db, revoke_session};
use crate::{bounded, PgStore, RecordingRead, StoreResult};
use bastion_domain::{ErrorCode, RecordingState, RecordingView};
use bastion_secrets::{CipherContext, Envelope};
use sqlx::{Postgres, Row, Transaction};
use uuid::Uuid;

pub struct RetentionCandidate {
    pub id: Uuid,
    pub relative_path: String,
    pub state: RecordingState,
}
/// Encrypted backup material, never a public API response.
pub struct CredentialManifestEntry {
    pub context: CipherContext,
    pub envelope: Envelope,
}
fn limit(value: u16) -> StoreResult<i64> {
    if (1..=200).contains(&value) {
        Ok(i64::from(value))
    } else {
        Err(ErrorCode::InvalidArgument)
    }
}
pub(super) async fn recover_dependents(
    tx: &mut Transaction<'_, Postgres>,
    gateway: &str,
) -> StoreResult<()> {
    sqlx::query("UPDATE recordings r SET state=CASE WHEN r.state='preparing' THEN 'failed' ELSE 'partial' END,ended_at=clock_timestamp() FROM channels ch JOIN connections c ON c.id=ch.connection_id WHERE r.channel_id=ch.id AND c.gateway_id=$1 AND c.state IN ('closed','failed','expired','revoked','interrupted') AND r.state IN ('preparing','active')").bind(gateway).execute(&mut **tx).await.map_err(db)?;
    sqlx::query("UPDATE channels ch SET state='failed',ended_at=clock_timestamp(),failure_code='RECORDING_UNAVAILABLE' FROM connections c WHERE ch.connection_id=c.id AND c.gateway_id=$1 AND c.state IN ('closed','failed','expired','revoked','interrupted') AND ch.state NOT IN ('closed','failed')").bind(gateway).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
impl PgStore {
    pub async fn recording_retention_candidates(
        &self,
        batch: u16,
    ) -> StoreResult<Vec<RetentionCandidate>> {
        let batch = limit(batch)?;
        bounded(async {
            let rows=sqlx::query("SELECT r.id,r.relative_path,r.state FROM recordings r JOIN channels ch ON ch.id=r.channel_id WHERE r.state IN ('complete','partial','failed','corrupt','missing') AND ch.state IN ('closed','failed') AND r.retention_until<=clock_timestamp() ORDER BY r.retention_until,r.id LIMIT $1").bind(batch).fetch_all(&self.pool).await.map_err(db)?;
            rows.iter().map(|r|Ok(RetentionCandidate{id:r.get("id"),relative_path:r.get("relative_path"),state:serde_json::from_value(serde_json::json!(r.get::<String,_>("state"))).map_err(|_|ErrorCode::InternalError)?})).collect()
        }).await
    }
    /// Call only after safely unlinking the managed file; never selects active data.
    pub async fn expire_recording(&self, id: Uuid) -> StoreResult<()> {
        bounded(async {
            let changed=sqlx::query("UPDATE recordings SET state='expired' WHERE id=$1 AND state IN ('complete','partial','failed','corrupt','missing','expired') AND retention_until<=clock_timestamp() AND EXISTS(SELECT 1 FROM channels ch WHERE ch.id=recordings.channel_id AND ch.state IN ('closed','failed'))").bind(id).execute(&self.pool).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RecordingUnavailable);}Ok(())
        }).await
    }
    pub async fn mark_recording_unavailable(
        &self,
        id: Uuid,
        state: RecordingState,
    ) -> StoreResult<()> {
        if !matches!(state, RecordingState::Missing | RecordingState::Corrupt) {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {
            let changed=sqlx::query("UPDATE recordings SET state=$2 WHERE id=$1 AND state NOT IN ('preparing','active','expired')").bind(id).bind(state.as_str()).execute(&self.pool).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RecordingUnavailable);}Ok(())
        }).await
    }
    pub async fn referenced_key_versions(&self) -> StoreResult<Vec<i64>> {
        bounded(async {sqlx::query_scalar("SELECT key_version FROM credentials UNION SELECT key_version FROM recordings WHERE state<>'expired' ORDER BY key_version").fetch_all(&self.pool).await.map_err(db)}).await
    }
    pub async fn credential_manifest(
        &self,
        after: Option<Uuid>,
        batch: u16,
    ) -> StoreResult<Vec<CredentialManifestEntry>> {
        let batch = limit(batch)?;
        bounded(async {
            let rows = sqlx::query(
                "SELECT * FROM credentials WHERE ($1::uuid IS NULL OR id>$1) ORDER BY id LIMIT $2",
            )
            .bind(after)
            .bind(batch)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            Ok(rows
                .iter()
                .map(|r| CredentialManifestEntry {
                    context: CipherContext {
                        server_id: self.server_id.to_string(),
                        credential_id: r.get("id"),
                        kind: r.get("kind"),
                        revision: r.get("revision"),
                    },
                    envelope: Envelope {
                        ciphertext: r.get("ciphertext"),
                        nonce: r.get("nonce"),
                        wrapped_dek: r.get("wrapped_dek"),
                        wrap_nonce: r.get("wrap_nonce"),
                        key_version: r.get("key_version"),
                    },
                })
                .collect())
        })
        .await
    }
    pub async fn recording_manifest(
        &self,
        after: Option<Uuid>,
        batch: u16,
    ) -> StoreResult<Vec<RecordingRead>> {
        let batch = limit(batch)?;
        bounded(async {
            let rows=sqlx::query("SELECT * FROM recordings WHERE ($1::uuid IS NULL OR id>$1) AND state<>'expired' ORDER BY id LIMIT $2").bind(after).bind(batch).fetch_all(&self.pool).await.map_err(db)?;
            rows.iter().map(|r|Ok(RecordingRead{metadata:RecordingView{id:r.get("id"),channel_id:r.get("channel_id"),format_version:r.get::<i32,_>("format_version") as u32,bytes:r.get("bytes"),checksum:r.get("checksum"),state:serde_json::from_value(serde_json::json!(r.get::<String,_>("state"))).map_err(|_|ErrorCode::InternalError)?,retention_until:r.get("retention_until"),last_written_seq:r.get("last_written_seq"),last_synced_seq:r.get("last_synced_seq")},relative_path:r.get("relative_path"),wrapped_dek:r.get("wrapped_dek"),wrap_nonce:r.get("wrap_nonce"),key_version:r.get("key_version"),nonce_prefix:r.get("nonce_prefix")})).collect()
        }).await
    }
    /// Explicit offline restore action; caller drains batches until zero, then recover_gateway.
    /// Ordinary gateway restart must NOT revoke all unrelated login families.
    pub async fn revoke_restored_login_families(&self, batch: u16) -> StoreResult<usize> {
        let batch = limit(batch)?;
        bounded(async {
            let mut tx=self.begin().await?;
            let ids:Vec<Uuid>=sqlx::query_scalar("SELECT id FROM login_sessions WHERE revoked_at IS NULL ORDER BY id LIMIT $1 FOR UPDATE").bind(batch).fetch_all(&mut *tx).await.map_err(db)?;
            for id in &ids {revoke_session(&mut tx,*id).await?;}
            tx.commit().await.map_err(db)?;Ok(ids.len())
        }).await
    }
    pub async fn update_connection_bytes(
        &self,
        id: Uuid,
        bytes_in: i64,
        bytes_out: i64,
    ) -> StoreResult<()> {
        if bytes_in < 0 || bytes_out < 0 {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {
            let changed=sqlx::query("UPDATE connections SET bytes_in=$2,bytes_out=$3 WHERE id=$1 AND bytes_in<=$2 AND bytes_out<=$3").bind(id).bind(bytes_in).bind(bytes_out).execute(&self.pool).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::InvalidArgument);}Ok(())
        }).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maintenance_batches_are_bounded() {
        assert!(limit(0).is_err());
        assert!(limit(201).is_err());
        assert_eq!(limit(200), Ok(200));
    }
}
