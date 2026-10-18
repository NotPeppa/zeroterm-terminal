use crate::{
    postgres::{audit, db},
    *,
};
use bastion_domain::*;
use serde_json::json;
use sqlx::Row;
use uuid::Uuid;
impl PgStore {
    pub async fn create_recording(
        &self,
        connection: &Connection,
        recording: RecordingCreate,
        request_id: Uuid,
    ) -> StoreResult<RecordingView> {
        crate::lifecycle::validate_recording(&recording)?;
        bounded(async{let mut tx=self.begin().await?;let current=self.runtime_connection(&mut tx,connection.id).await?;if !(current.state==ConnectionState::Connecting || (current.transport==Transport::NativeSsh && current.state==ConnectionState::Active)){return Err(ErrorCode::RecordingUnavailable);}
   let row=sqlx::query("INSERT INTO recordings(id,connection_id,target_protocol,relative_path,format_version,retention_until,wrapped_dek,wrap_nonce,key_version,nonce_prefix) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *").bind(recording.id).bind(current.id).bind(current.target_protocol.as_str()).bind(recording.relative_path).bind(recording.format_version as i32).bind(recording.retention_until).bind(recording.wrapped_dek).bind(recording.wrap_nonce).bind(recording.key_version).bind(recording.nonce_prefix).fetch_one(&mut *tx).await.map_err(db)?;
   audit(&mut tx,current.user_id,current.login_session_id,"recording.preparing","recording",Some(recording.id),request_id,json!({"connection_id":current.id})).await?;tx.commit().await.map_err(db)?;crate::lifecycle::recording_view(&row)
  }).await
    }
    pub async fn activate_recording(&self, id: Uuid) -> StoreResult<()> {
        bounded(async{let mut tx=self.begin().await?;let cid:Uuid=sqlx::query_scalar("SELECT connection_id FROM recordings WHERE id=$1").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;let current=self.runtime_connection(&mut tx,cid).await?;if !(current.state==ConnectionState::Connecting || (current.transport==Transport::NativeSsh && current.state==ConnectionState::Active)){return Err(ErrorCode::RecordingUnavailable);}
   let ready=sqlx::query("UPDATE recordings SET state='active' WHERE id=$1 AND connection_id=$2 AND state='preparing' AND last_written_seq>=0 AND last_synced_seq>=0").bind(id).bind(cid).execute(&mut *tx).await.map_err(db)?;if ready.rows_affected()!=1{return Err(ErrorCode::RecordingUnavailable);}
   sqlx::query("UPDATE connections SET state='active' WHERE id=$1 AND state='connecting'").bind(cid).execute(&mut *tx).await.map_err(db)?;if current.state==ConnectionState::Connecting {audit(&mut tx,current.user_id,current.login_session_id,"connection.active","connection",Some(cid),Uuid::new_v4(),json!({"recording_id":id})).await?;} audit(&mut tx,current.user_id,current.login_session_id,"recording.active","recording",Some(id),Uuid::new_v4(),json!({"connection_id":cid})).await?;tx.commit().await.map_err(db)
  }).await
    }
    pub async fn checkpoint_recording(
        &self,
        id: Uuid,
        written: i64,
        synced: i64,
        bytes: i64,
    ) -> StoreResult<()> {
        if written < -1 || synced < -1 || synced > written || bytes < 0 {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async{let changed=sqlx::query("UPDATE recordings SET last_written_seq=$2,last_synced_seq=$3,bytes=$4 WHERE id=$1 AND state IN ('preparing','active') AND last_written_seq<=$2 AND last_synced_seq<=$3 AND bytes<=$4").bind(id).bind(written).bind(synced).bind(bytes).execute(&self.pool).await.map_err(db)?;if changed.rows_affected()!=1{Err(ErrorCode::RecordingUnavailable)}else{Ok(())}}).await
    }
    pub async fn finish_recording(
        &self,
        id: Uuid,
        state: RecordingState,
        bytes: i64,
        checksum: Option<&str>,
        failure: Option<ErrorCode>,
    ) -> StoreResult<()> {
        if bytes < 0
            || matches!(
                state,
                RecordingState::Preparing | RecordingState::Active | RecordingState::Expired
            )
            || checksum.is_some_and(|s| !crate::valid_certificate_pin(s))
            || (state == RecordingState::Complete && (checksum.is_none() || failure.is_some()))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async{let mut tx=self.begin().await?;let route=sqlx::query("SELECT connection_id FROM recordings WHERE id=$1").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;let cid:Uuid=route.get("connection_id");let c=sqlx::query("SELECT user_id,login_session_id FROM connections WHERE id=$1 FOR UPDATE").bind(cid).fetch_one(&mut *tx).await.map_err(db)?;
   let changed=sqlx::query("UPDATE recordings SET state=$2,bytes=$3,checksum=$4,ended_at=clock_timestamp() WHERE id=$1 AND state IN ('preparing','active') AND bytes<=$3 AND ($2<>'complete' OR (last_written_seq=last_synced_seq AND last_written_seq>=1))").bind(id).bind(state.as_str()).bind(bytes).bind(checksum).execute(&mut *tx).await.map_err(db)?;
   if changed.rows_affected()!=1 {return Err(ErrorCode::RecordingUnavailable);}
   audit(&mut tx,Some(c.get("user_id")),Some(c.get("login_session_id")),"recording.finalized","recording",Some(id),Uuid::new_v4(),json!({"state":state,"reason_code":failure})).await?;tx.commit().await.map_err(db)
  }).await
    }
}
