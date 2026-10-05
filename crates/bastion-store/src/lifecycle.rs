use crate::postgres::{audit, connection_view, db, revoke_session};
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
fn code(value: Option<ErrorCode>) -> Option<String> {
    value.map(|v| {
        serde_json::to_value(v)
            .unwrap()
            .as_str()
            .unwrap()
            .to_owned()
    })
}
fn channel_view(row: &PgRow) -> StoreResult<ChannelView> {
    Ok(ChannelView {
        id: row.get("id"),
        connection_id: row.get("connection_id"),
        upstream_channel_id: u32::try_from(row.get::<i64, _>("upstream_channel_id"))
            .map_err(|_| ErrorCode::InternalError)?,
        kind: parse(row.get("kind"))?,
        state: parse(row.get("state"))?,
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        ended_at: row.get("ended_at"),
        exit_code: row
            .get::<Option<i64>, _>("exit_code")
            .map(u32::try_from)
            .transpose()
            .map_err(|_| ErrorCode::InternalError)?,
        exit_signal: row.get("exit_signal"),
        recording_id: row.get("recording_id"),
    })
}
fn recording_view(row: &PgRow) -> StoreResult<RecordingView> {
    Ok(RecordingView {
        id: row.get("id"),
        channel_id: row.get("channel_id"),
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
fn validate_recording(value: &RecordingCreate) -> StoreResult<()> {
    let path = &value.relative_path;
    if value.format_version != 1
        || value.wrapped_dek.len() != 48
        || value.wrap_nonce.len() != 24
        || value.nonce_prefix.len() != 16
        || value.key_version <= 0
        || path.len() > 1024
        || !path.ends_with(".ztrec")
        || !path
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        || !path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
        || path.contains(' ')
    {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(())
}
impl PgStore {
    /// The policy lock must already be held. Locks identity/target before connection.
    pub(super) async fn runtime_connection(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> StoreResult<Connection> {
        let row = sqlx::query("SELECT * FROM connections WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        let route = connection_view(&row)?;
        let uid = route.user_id.ok_or(ErrorCode::Unauthenticated)?;
        let session = route.login_session_id.ok_or(ErrorCode::Unauthenticated)?;
        self.binding(tx, uid, session, route.asset_id, route.account_id)
            .await?;
        let row = sqlx::query("SELECT * FROM connections WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
        // clock_timestamp binding is repeated after the possible connection lock wait.
        let binding = self
            .binding(tx, uid, session, route.asset_id, route.account_id)
            .await?;
        if !matches!(
            row.get::<String, _>("state").as_str(),
            "connecting" | "active"
        ) || row.get::<i64, _>("auth_revision") != binding.user.revision
            || row.get::<i64, _>("routing_revision") != binding.asset.routing_revision
            || row.get::<String, _>("target_username") != binding.username
            || route
                .capabilities
                .iter()
                .any(|cap| !binding.capabilities.contains(cap))
        {
            return Err(ErrorCode::PermissionDenied);
        }
        connection_view(&row)
    }
    pub async fn begin_channel(
        &self,
        connection: &Connection,
        upstream_channel_id: u32,
        kind: ChannelKind,
        recording: Option<RecordingCreate>,
        request_id: Uuid,
    ) -> StoreResult<ChannelView> {
        if recording.is_some() && kind != ChannelKind::Shell {
            return Err(ErrorCode::InvalidArgument);
        }
        if let Some(value) = &recording {
            validate_recording(value)?;
        }
        bounded(async {
            let mut tx=self.begin().await?;
            let current=self.runtime_connection(&mut tx,connection.id).await?;
            let required=match kind {ChannelKind::Shell=>Capability::Shell,ChannelKind::Exec=>Capability::Exec,ChannelKind::Sftp=>Capability::Sftp};
            if !current.capabilities.contains(&required) {return Err(ErrorCode::ChannelPermissionDenied);}
            let counts=sqlx::query("SELECT count(*) FILTER(WHERE ch.connection_id=$1) AS per_connection,count(*) AS per_user FROM channels ch JOIN connections c ON c.id=ch.connection_id WHERE c.user_id=$2 AND ch.state NOT IN ('closed','failed')").bind(current.id).bind(current.user_id).fetch_one(&mut *tx).await.map_err(db)?;
            if counts.get::<i64,_>("per_connection")>=16 || counts.get::<i64,_>("per_user")>=64 {return Err(ErrorCode::ConnectionLimit);}
            let id=Uuid::new_v4();
            let row=sqlx::query("INSERT INTO channels(id,connection_id,upstream_channel_id,kind) VALUES($1,$2,$3,$4) RETURNING *,NULL::uuid AS recording_id").bind(id).bind(current.id).bind(i64::from(upstream_channel_id)).bind(kind.as_str()).fetch_one(&mut *tx).await.map_err(db)?;
            let mut view=channel_view(&row)?;
            if let Some(value)=recording {view.recording_id=Some(value.id);insert_recording(&mut tx,id,&value).await?;}
            audit(&mut tx,current.user_id,current.login_session_id,"channel.allocated","channel",Some(id),request_id,json!({"connection_id":current.id,"kind":kind})).await?;
            tx.commit().await.map_err(db)?;Ok(view)
        }).await
    }
    pub async fn create_recording(
        &self,
        channel_id: Uuid,
        recording: RecordingCreate,
        request_id: Uuid,
    ) -> StoreResult<RecordingView> {
        validate_recording(&recording)?;
        bounded(async {
            let mut tx = self.begin().await?;
            let channel = sqlx::query("SELECT ch.*,(SELECT r.id FROM recordings r WHERE r.channel_id=ch.id) AS recording_id FROM channels ch WHERE id=$1")
                .bind(channel_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            let connection = self
                .runtime_connection(&mut tx, channel.get("connection_id"))
                .await?;
            if channel.get::<String, _>("kind") != "shell"
                || !matches!(
                    channel.get::<String, _>("state").as_str(),
                    "allocated" | "configuring" | "starting"
                )
            {
                return Err(ErrorCode::InvalidArgument);
            }
            let view = insert_recording(&mut tx, channel_id, &recording).await?;
            audit(
                &mut tx,
                connection.user_id,
                connection.login_session_id,
                "recording.preparing",
                "recording",
                Some(view.id),
                request_id,
                json!({"channel_id":channel_id}),
            )
            .await?;
            tx.commit().await.map_err(db)?;
            Ok(view)
        })
        .await
    }
    pub async fn transition_channel(&self, id: Uuid, state: ChannelState) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT ch.*,(SELECT r.id FROM recordings r WHERE r.channel_id=ch.id) AS recording_id FROM channels ch WHERE id=$1").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let view=channel_view(&row)?;
            if view.state==state {return Ok(());}
            if !view.state.permits(state) {return Err(ErrorCode::InvalidArgument);}
            if !matches!(state,ChannelState::Closed|ChannelState::Failed|ChannelState::Draining) {
                self.runtime_connection(&mut tx,view.connection_id).await?;
            }
            if state==ChannelState::Streaming && view.kind==ChannelKind::Shell {
                let ready:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM recordings WHERE id=$1 AND state='active')").bind(view.recording_id).fetch_one(&mut *tx).await.map_err(db)?;
                if !ready {return Err(ErrorCode::RecordingUnavailable);}
            }
            sqlx::query("UPDATE channels SET state=$2,started_at=CASE WHEN $2='streaming' THEN COALESCE(started_at,clock_timestamp()) ELSE started_at END,ended_at=CASE WHEN $2 IN ('closed','failed') THEN clock_timestamp() ELSE ended_at END WHERE id=$1").bind(id).bind(state.as_str()).execute(&mut *tx).await.map_err(db)?;
            if matches!(state,ChannelState::Closed|ChannelState::Failed) {partial_recording(&mut tx,view.recording_id).await?;}
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn activate_recording(&self, id: Uuid) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;
            let connection:Uuid=sqlx::query_scalar("SELECT ch.connection_id FROM recordings r JOIN channels ch ON ch.id=r.channel_id WHERE r.id=$1").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let current=self.runtime_connection(&mut tx,connection).await?;
            if current.state!=ConnectionState::Active || !current.capabilities.contains(&Capability::Shell) {return Err(ErrorCode::RecordingUnavailable);}
            let changed=sqlx::query("UPDATE recordings SET state='active' WHERE id=$1 AND state='preparing' AND EXISTS(SELECT 1 FROM channels ch WHERE ch.id=recordings.channel_id AND ch.state NOT IN ('closed','failed'))").bind(id).execute(&mut *tx).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RecordingUnavailable);}
            tx.commit().await.map_err(db)
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
        bounded(async {
            // One autocommit statement, no policy lock and never one call per frame.
            let changed=sqlx::query("UPDATE recordings SET last_written_seq=$2,last_synced_seq=$3,bytes=$4 WHERE id=$1 AND state='active' AND last_written_seq<=$2 AND last_synced_seq<=$3 AND bytes<=$4").bind(id).bind(written).bind(synced).bind(bytes).execute(&self.pool).await.map_err(db)?;
            if changed.rows_affected()!=1 {return Err(ErrorCode::RecordingUnavailable);}
            Ok(())
        }).await
    }
    #[allow(clippy::too_many_arguments)]
    pub async fn finish_channel_and_recording(
        &self,
        id: Uuid,
        exit_code: Option<u32>,
        exit_signal: Option<&str>,
        failure: Option<ErrorCode>,
        recording_state: Option<RecordingState>,
        checksum: Option<&str>,
    ) -> StoreResult<()> {
        if exit_signal.is_some_and(|s| s.len() > 128 || s.chars().any(char::is_control))
            || checksum.is_some_and(|s| {
                s.len() != 64
                    || !s
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
            || recording_state.is_some_and(|s| {
                matches!(
                    s,
                    RecordingState::Preparing | RecordingState::Active | RecordingState::Expired
                )
            })
        {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {
            let mut tx=self.begin().await?;
            let row=sqlx::query("SELECT ch.*,(SELECT r.id FROM recordings r WHERE r.channel_id=ch.id) AS recording_id FROM channels ch WHERE id=$1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let channel=channel_view(&row)?;
            if matches!(channel.state,ChannelState::Closed|ChannelState::Failed) {return Ok(());}
            if let Some(recording_id)=channel.recording_id {
                let state=recording_state.unwrap_or(RecordingState::Partial);
                if state==RecordingState::Complete && (failure.is_some() || checksum.is_none()) {return Err(ErrorCode::InvalidArgument);}
                let changed=sqlx::query("UPDATE recordings SET state=$2,checksum=$3,ended_at=clock_timestamp() WHERE id=$1 AND state IN ('preparing','active') AND ($2<>'complete' OR last_written_seq=last_synced_seq)").bind(recording_id).bind(state.as_str()).bind(checksum).execute(&mut *tx).await.map_err(db)?;
                if changed.rows_affected()!=1 {return Err(ErrorCode::RecordingUnavailable);}
            } else if recording_state.is_some() {return Err(ErrorCode::InvalidArgument);}
            sqlx::query("UPDATE channels SET state=$2,exit_code=$3,exit_signal=$4,failure_code=$5,ended_at=clock_timestamp() WHERE id=$1").bind(id).bind(if failure.is_some(){"failed"}else{"closed"}).bind(exit_code.map(i64::from)).bind(exit_signal).bind(code(failure)).execute(&mut *tx).await.map_err(db)?;
            let connection=sqlx::query("SELECT user_id,login_session_id FROM connections WHERE id=$1").bind(channel.connection_id).fetch_one(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(connection.get("user_id")),Some(connection.get("login_session_id")),"channel.closed","channel",Some(id),Uuid::new_v4(),json!({"exit_code":exit_code,"exit_signal":exit_signal,"reason_code":failure,"recording_state":recording_state})).await?;
            if failure.is_some() && channel.recording_id.is_some() {audit(&mut tx,Some(connection.get("user_id")),Some(connection.get("login_session_id")),"recording.failed","recording",channel.recording_id,Uuid::new_v4(),json!({"reason_code":failure})).await?;}
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn channel_queries(
        &self,
        identity: &Identity,
        connection_id: Uuid,
    ) -> StoreResult<Vec<ChannelView>> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, identity, false).await?;
            sqlx::query("SELECT id FROM connections WHERE id=$1 AND (user_id=$2 OR $3)")
                .bind(connection_id)
                .bind(identity.user.id)
                .bind(matches!(identity.user.role, Role::Admin | Role::Auditor))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            let rows =
                sqlx::query("SELECT ch.*,(SELECT r.id FROM recordings r WHERE r.channel_id=ch.id) AS recording_id FROM channels ch WHERE connection_id=$1 ORDER BY created_at,id")
                    .bind(connection_id)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(db)?;
            let result = rows.iter().map(channel_view).collect();
            tx.commit().await.map_err(db)?;
            result
        })
        .await
    }
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
            let rows=sqlx::query("SELECT id,device_label,client_type,created_at,expires_at,revoked_at FROM login_sessions WHERE user_id=$1 ORDER BY created_at DESC,id DESC LIMIT 200").bind(identity.user.id).fetch_all(&mut *tx).await.map_err(db)?;
            let items=rows.iter().map(|r|DeviceSessionView{id:r.get("id"),device_label:r.get("device_label"),client_type:r.get("client_type"),current:r.get::<Uuid,_>("id")==identity.login_session_id,created_at:r.get("created_at"),expires_at:r.get("expires_at"),revoked_at:r.get("revoked_at")}).collect();
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
            sqlx::query("UPDATE copy_jobs SET state='cancelled',ended_at=clock_timestamp() WHERE login_session_id=$1 AND state IN ('queued','running')").bind(id).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"login_session.revoked","login_session",Some(id),request_id,json!({})).await?;
            tx.commit().await.map_err(db)
        }).await
    }
}
async fn insert_recording(
    tx: &mut Transaction<'_, Postgres>,
    channel: Uuid,
    value: &RecordingCreate,
) -> StoreResult<RecordingView> {
    let row=sqlx::query("INSERT INTO recordings(id,channel_id,relative_path,format_version,retention_until,wrapped_dek,wrap_nonce,key_version,nonce_prefix) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *").bind(value.id).bind(channel).bind(&value.relative_path).bind(value.format_version as i32).bind(value.retention_until).bind(&value.wrapped_dek).bind(&value.wrap_nonce).bind(value.key_version).bind(&value.nonce_prefix).fetch_one(&mut **tx).await.map_err(db)?;
    recording_view(&row)
}
async fn partial_recording(
    tx: &mut Transaction<'_, Postgres>,
    id: Option<Uuid>,
) -> StoreResult<()> {
    sqlx::query("UPDATE recordings SET state=CASE WHEN state='preparing' THEN 'failed' ELSE 'partial' END,ended_at=clock_timestamp() WHERE id=$1 AND state IN ('preparing','active')").bind(id).execute(&mut **tx).await.map_err(db)?;
    Ok(())
}
async fn recording_for(
    tx: &mut Transaction<'_, Postgres>,
    identity: &Identity,
    id: Uuid,
) -> StoreResult<PgRow> {
    sqlx::query("SELECT r.* FROM recordings r JOIN channels ch ON ch.id=r.channel_id JOIN connections c ON c.id=ch.connection_id WHERE r.id=$1 AND (c.user_id=$2 OR $3)").bind(id).bind(identity.user.id).bind(matches!(identity.user.role,Role::Admin|Role::Auditor)).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn recording_path_and_crypto_sizes_are_checked() {
        let mut value = RecordingCreate {
            id: Uuid::new_v4(),
            relative_path: "record.ztrec".into(),
            format_version: 1,
            retention_until: Utc::now(),
            wrapped_dek: vec![0; 48],
            wrap_nonce: vec![0; 24],
            key_version: 1,
            nonce_prefix: vec![0; 16],
        };
        assert!(validate_recording(&value).is_ok());
        for path in [
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
        value.relative_path = "ok.ztrec".into();
        value.nonce_prefix.pop();
        assert_eq!(validate_recording(&value), Err(ErrorCode::InvalidArgument));
    }
}
