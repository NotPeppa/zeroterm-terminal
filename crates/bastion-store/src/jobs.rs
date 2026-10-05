use crate::postgres::{audit, db};
use crate::{bounded, PgStore, StoreResult};
use bastion_domain::*;
use serde_json::json;
use sqlx::{postgres::PgRow, Postgres, Row, Transaction};
use uuid::Uuid;
fn job_view(row: &PgRow) -> StoreResult<CopyJobView> {
    Ok(CopyJobView {
        id: row.get("id"),
        user_id: row.get("user_id"),
        source_asset_id: row.get("source_asset_id"),
        source_account_id: row.get("source_account_id"),
        source_path: row.get("source_path"),
        destination_asset_id: row.get("destination_asset_id"),
        destination_account_id: row.get("destination_account_id"),
        destination_path: row.get("destination_path"),
        state: serde_json::from_value(json!(row.get::<String, _>("state")))
            .map_err(|_| ErrorCode::InternalError)?,
        bytes_total: row.get("bytes_total"),
        bytes_copied: row.get("bytes_copied"),
        failure_code: row
            .get::<Option<String>, _>("failure_code")
            .map(|s| serde_json::from_value(json!(s)))
            .transpose()
            .map_err(|_| ErrorCode::InternalError)?,
        created_at: row.get("created_at"),
        started_at: row.get("started_at"),
        ended_at: row.get("ended_at"),
    })
}
fn path(value: &str) -> bool {
    !value.is_empty() && value.len() <= 4096 && !value.as_bytes().contains(&0)
}
fn permits(old: CopyJobState, new: CopyJobState) -> bool {
    use CopyJobState::*;
    old == new
        || matches!(
            (old, new),
            (Queued, Running | Failed | Cancelled | Interrupted)
                | (Running, Completed | Failed | Cancelled | Interrupted)
        )
}
impl PgStore {
    pub async fn create_copy_job(
        &self,
        identity: &Identity,
        input: &CopyJobCreate,
        request_id: Uuid,
    ) -> StoreResult<CopyJobView> {
        if !path(&input.source_path)
            || !path(&input.destination_path)
            || input.bytes_total.is_some_and(|v| v < 0)
        {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            for (asset,account) in [(input.source_asset_id,input.source_account_id),(input.destination_asset_id,input.destination_account_id)] {
                let binding=self.binding(&mut tx,identity.user.id,identity.login_session_id,asset,account).await?;
                if !binding.capabilities.contains(&Capability::Sftp) {return Err(ErrorCode::ChannelPermissionDenied);}
            }
            let count:i64=sqlx::query_scalar("SELECT count(*) FROM copy_jobs WHERE user_id=$1 AND state IN ('queued','running')").bind(identity.user.id).fetch_one(&mut *tx).await.map_err(db)?;
            if count>=4 {return Err(ErrorCode::ConnectionLimit);}
            let id=Uuid::new_v4();
            let row=sqlx::query("INSERT INTO copy_jobs(id,user_id,login_session_id,gateway_id,source_asset_id,source_account_id,source_path,destination_asset_id,destination_account_id,destination_path,bytes_total) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *").bind(id).bind(identity.user.id).bind(identity.login_session_id).bind(self.gateway_id.as_ref()).bind(input.source_asset_id).bind(input.source_account_id).bind(&input.source_path).bind(input.destination_asset_id).bind(input.destination_account_id).bind(&input.destination_path).bind(input.bytes_total).fetch_one(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"copy_job.created","copy_job",Some(id),request_id,json!({"source_asset_id":input.source_asset_id,"destination_asset_id":input.destination_asset_id})).await?;
            let view=job_view(&row)?;tx.commit().await.map_err(db)?;Ok(view)
        }).await
    }
    pub async fn copy_job(&self, identity: &Identity, id: Uuid) -> StoreResult<CopyJobView> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.actor(&mut tx, identity, false).await?;
            let row = sqlx::query("SELECT * FROM copy_jobs WHERE id=$1 AND (user_id=$2 OR $3)")
                .bind(id)
                .bind(identity.user.id)
                .bind(matches!(identity.user.role, Role::Admin | Role::Auditor))
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?
                .ok_or(ErrorCode::ResourceNotFound)?;
            let view = job_view(&row)?;
            tx.commit().await.map_err(db)?;
            Ok(view)
        })
        .await
    }
    async fn job_authorization(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        id: Uuid,
    ) -> StoreResult<PgRow> {
        let row = sqlx::query("SELECT * FROM copy_jobs WHERE id=$1")
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(db)?
            .ok_or(ErrorCode::ResourceNotFound)?;
        for (asset, account) in [
            (row.get("source_asset_id"), row.get("source_account_id")),
            (
                row.get("destination_asset_id"),
                row.get("destination_account_id"),
            ),
        ] {
            let binding = self
                .binding(
                    tx,
                    row.get("user_id"),
                    row.get("login_session_id"),
                    asset,
                    account,
                )
                .await?;
            if !binding.capabilities.contains(&Capability::Sftp) {
                return Err(ErrorCode::ChannelPermissionDenied);
            }
        }
        if row.get::<String, _>("gateway_id") != self.gateway_id.as_ref()
            || !matches!(row.get::<String, _>("state").as_str(), "queued" | "running")
        {
            return Err(ErrorCode::PermissionDenied);
        }
        Ok(row)
    }
    pub async fn authorize_copy_job(&self, id: Uuid) -> StoreResult<()> {
        bounded(async {
            let mut tx = self.begin().await?;
            self.job_authorization(&mut tx, id).await?;
            tx.commit().await.map_err(db)
        })
        .await
    }
    pub async fn transition_copy_job(
        &self,
        id: Uuid,
        state: CopyJobState,
        bytes_copied: i64,
        failure: Option<ErrorCode>,
    ) -> StoreResult<()> {
        if bytes_copied < 0 {
            return Err(ErrorCode::InvalidArgument);
        }
        bounded(async {
            let mut tx=self.begin().await?;
            if matches!(state,CopyJobState::Running|CopyJobState::Completed) {self.job_authorization(&mut tx,id).await?;}
            let row=sqlx::query("SELECT * FROM copy_jobs WHERE id=$1 FOR UPDATE").bind(id).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            let job=job_view(&row)?;
            if !permits(job.state,state) || bytes_copied<job.bytes_copied || job.bytes_total.is_some_and(|n|bytes_copied>n) || state==CopyJobState::Completed && (failure.is_some() || job.bytes_total.is_some_and(|n|n!=bytes_copied)) {return Err(ErrorCode::InvalidArgument);}
            if matches!(job.state,CopyJobState::Completed|CopyJobState::Failed|CopyJobState::Cancelled|CopyJobState::Interrupted) {return Ok(());}
            sqlx::query("UPDATE copy_jobs SET state=$2,bytes_copied=$3,failure_code=$4,started_at=CASE WHEN $2='running' THEN COALESCE(started_at,clock_timestamp()) ELSE started_at END,ended_at=CASE WHEN $2 NOT IN ('queued','running') THEN clock_timestamp() ELSE ended_at END WHERE id=$1").bind(id).bind(state.as_str()).bind(bytes_copied).bind(failure.map(|v|serde_json::to_value(v).unwrap().as_str().unwrap().to_owned())).execute(&mut *tx).await.map_err(db)?;
            if job.state!=state {audit(&mut tx,Some(job.user_id),Some(row.get("login_session_id")),"copy_job.state_changed","copy_job",Some(id),Uuid::new_v4(),json!({"state":state,"bytes_copied":bytes_copied,"reason_code":failure})).await?;}
            tx.commit().await.map_err(db)
        }).await
    }
    pub async fn cancel_copy_job(
        &self,
        identity: &Identity,
        id: Uuid,
        request_id: Uuid,
    ) -> StoreResult<()> {
        bounded(async {
            let mut tx=self.begin().await?;self.actor(&mut tx,identity,false).await?;
            let row=sqlx::query("SELECT id FROM copy_jobs WHERE id=$1 AND (user_id=$2 OR $3) FOR UPDATE").bind(id).bind(identity.user.id).bind(identity.user.role==Role::Admin).fetch_optional(&mut *tx).await.map_err(db)?.ok_or(ErrorCode::ResourceNotFound)?;
            sqlx::query("UPDATE copy_jobs SET state='cancelled',ended_at=clock_timestamp() WHERE id=$1 AND state IN ('queued','running')").bind(id).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,Some(identity.user.id),Some(identity.login_session_id),"copy_job.cancel_requested","copy_job",Some(row.get("id")),request_id,json!({})).await?;tx.commit().await.map_err(db)
        }).await
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn single_file_jobs_never_restart_terminal_states() {
        for state in [
            CopyJobState::Completed,
            CopyJobState::Failed,
            CopyJobState::Cancelled,
            CopyJobState::Interrupted,
        ] {
            assert!(!permits(state, CopyJobState::Running));
        }
        assert!(!path("a\0b"));
        assert!(!path(""));
        assert!(path("/原始/file name"));
    }
}
