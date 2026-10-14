use crate::postgres::{audit, db, revoke_session};
use crate::{bounded, PgStore, StoreResult};
use bastion_domain::*;
#[cfg(test)]
use chrono::Utc;
use serde::de::DeserializeOwned;
use serde_json::json;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;
/// Internal replay material. Deliberately neither Serialize nor Debug.
pub struct RecordingRead {
    pub metadata: RecordingView,
    pub relative_path: String,
    pub wrapped_dek: Vec<u8>,
    pub wrap_nonce: Vec<u8>,
    pub key_version: i64,
    pub nonce_prefix: Vec<u8>,
}
fn parse<T: DeserializeOwned>(value: String) -> StoreResult<T> {
    serde_json::from_value(json!(value)).map_err(|_| ErrorCode::InternalError)
}
pub(super) fn recording_view(row: &PgRow) -> StoreResult<RecordingView> {
    Ok(RecordingView {
        id: row.get("id"),
        connection_id: row.get("connection_id"),
        target_protocol: parse(row.get("target_protocol"))?,
        format_version: u32::try_from(row.get::<i32, _>("format_version"))
            .map_err(|_| ErrorCode::InternalError)?,
        bytes: row.get("bytes"),
        checksum: row.get("checksum"),
        state: parse(row.get("state"))?,
        retention_until: row.get("retention_until"),
        last_written_seq: row.get("last_written_seq"),
        last_synced_seq: row.get("last_synced_seq"),
    })
}
pub(super) fn validate_recording(value: &RecordingCreate) -> StoreResult<()> {
    let path = &value.relative_path;
    if value.format_version != 2
        || value.wrapped_dek.len() != 48
        || value.wrap_nonce.len() != 24
        || value.nonce_prefix.len() != 16
        || value.key_version <= 0
        || path != &format!("{}.ztrec", value.id)
    {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(())
}
impl PgStore {
    pub async fn recording_metadata(
        &self,
        identity: &Identity,
        id: Uuid,
    ) -> StoreResult<RecordingView> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, identity, false).await?;
            let row = recording_for(&mut tx, identity, id).await?;
            let view = recording_view(&row)?;
            tx.commit().await.map_err(db)?;
            Ok(view)
        })
        .await
    }
    pub async fn recording_for_replay(
        &self,
        identity: &Identity,
        id: Uuid,
        request_id: Uuid,
    ) -> StoreResult<RecordingRead> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, identity, false).await?;
            let row = recording_for(&mut tx, identity, id).await?;
            let metadata = recording_view(&row)?;
            if !matches!(
                metadata.state,
                RecordingState::Complete | RecordingState::Partial
            ) {
                return Err(ErrorCode::RecordingUnavailable);
            }
            let value = RecordingRead {
                metadata,
                relative_path: row.get("relative_path"),
                wrapped_dek: row.get("wrapped_dek"),
                wrap_nonce: row.get("wrap_nonce"),
                key_version: row.get("key_version"),
                nonce_prefix: row.get("nonce_prefix"),
            };
            audit(
                &mut tx,
                Some(identity.user.id),
                Some(identity.login_session_id),
                "recording.viewed",
                "recording",
                Some(id),
                request_id,
                json!({}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(value)
        })
        .await
    }
    pub async fn device_sessions(
        &self,
        identity: &Identity,
    ) -> StoreResult<Vec<DeviceSessionView>> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            let rows=sqlx::query("SELECT id,device_label,created_at,expires_at,revoked_at FROM login_sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT 200").bind(identity.user.id).fetch_all(&mut *tx).await.map_err(db)?;
            let items=rows.iter().map(|r|DeviceSessionView{id:r.get("id"),device_label:r.get("device_label"),current:r.get::<Uuid,_>("id")==identity.login_session_id,created_at:r.get("created_at"),expires_at:r.get("expires_at"),revoked_at:r.get("revoked_at")}).collect();
            tx.commit().await.map_err(db)?;Ok(items)
        }).await
    }
    pub async fn revoke_device_session(
        &self,
        identity: &Identity,
        id: Uuid,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            sqlx::query("SELECT id FROM login_sessions WHERE id=$1 AND user_id=$2 FOR UPDATE").bind(id).bind(identity.user.id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            revoke_session(&mut tx,id).await?;
            sqlx::query("UPDATE connections SET state='closing' WHERE login_session_id=$1 AND state IN ('connecting','active')").bind(id).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"login_session.revoked","login_session",Some(id),request_id,json!({})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
}
async fn recording_for(
    tx: &mut Transaction<'_, Postgres>,
    identity: &Identity,
    id: Uuid,
) -> StoreResult<PgRow> {
    sqlx::query("SELECT r.* FROM recordings r JOIN connections c ON c.id=r.connection_id WHERE r.id=$1 AND (c.user_id=$2 OR $3)").bind(id).bind(identity.user.id).bind(matches!(identity.user.role,Role::Admin|Role::Auditor)).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recording_path_and_crypto_sizes_are_checked() {
        let id = Uuid::new_v4();
        let mut value = RecordingCreate {
            id,
            relative_path: format!("{id}.ztrec"),
            format_version: 2,
            retention_until: Utc::now(),
            wrapped_dek: vec![0; 48],
            wrap_nonce: vec![0; 24],
            key_version: 1,
            nonce_prefix: vec![0; 16],
        };
        assert!(validate_recording(&value).is_ok());
        for path in [
            "record.ztrec",
            "a/record.ztrec",
            "",
            ".ztrec",
            "a.txt",
            "a\0.ztrec",
            "../a.ztrec",
            "/a.ztrec",
            "a\\b.ztrec",
            "a//b.ztrec",
            "a/./b.ztrec",
            "a b.ztrec",
        ] {
            value.relative_path = path.into();
            assert_eq!(validate_recording(&value), Err(ErrorCode::InvalidArgument));
        }
        value.relative_path = format!("{}.ztrec", Uuid::new_v4());
        assert_eq!(validate_recording(&value), Err(ErrorCode::InvalidArgument));
        value.relative_path = format!("{}.ztrec", value.id);
        value.nonce_prefix.pop();
        assert_eq!(validate_recording(&value), Err(ErrorCode::InvalidArgument));
    }
}
