//! Offline audit partition maintenance. No web route, row DELETE, SECURITY DEFINER,
//! disabled trigger, or longer policy transaction budget.
use crate::postgres::{audit, db};
use crate::{bounded, StoreResult};
use bastion_domain::ErrorCode;
use chrono::{DateTime, Datelike, Months, Timelike, Utc};
use serde_json::json;
use sqlx::{Connection, PgConnection, Postgres, Row, Transaction};
use uuid::Uuid;

#[derive(Debug, Default)]
pub struct AuditPartitionMaintenance {
    pub created: Vec<String>,
    pub dropped: Option<String>,
    /// Default is never dropped. Nonzero means missed-window history is retained.
    pub default_rows: i64,
}
async fn guard(tx: &mut Transaction<'_, Postgres>, server: &str, gateway: &str) -> StoreResult<()> {
    sqlx::raw_sql(
        "SET LOCAL statement_timeout='2s'; SET LOCAL lock_timeout='2s'; SET LOCAL TIME ZONE 'UTC'",
    )
    .execute(&mut **tx)
    .await
    .map_err(db)?;
    let valid:bool=sqlx::query_scalar("SELECT c.relowner=(SELECT oid FROM pg_roles WHERE rolname=current_user) AND n.nspname='public' AND has_schema_privilege(current_user,n.oid,'CREATE') FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE c.oid='public.audit_events'::regclass").fetch_one(&mut **tx).await.map_err(db)?;
    if !valid {
        return Err(ErrorCode::PermissionDenied);
    }
    let identity: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM server_settings WHERE singleton AND server_id=$1)",
    )
    .bind(server)
    .fetch_one(&mut **tx)
    .await
    .map_err(db)?;
    if !identity {
        return Err(ErrorCode::ResourceConflict);
    }
    let locked: bool =
        sqlx::query_scalar("SELECT pg_try_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!("zeroterm-bastion:{server}:{gateway}"))
            .fetch_one(&mut **tx)
            .await
            .map_err(db)?;
    let offline:bool=sqlx::query_scalar("SELECT NOT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datid=(SELECT oid FROM pg_database WHERE datname=current_database()) AND pid<>pg_backend_pid() AND backend_type='client backend')").fetch_one(&mut **tx).await.map_err(db)?;
    if !locked || !offline {
        return Err(ErrorCode::ResourceConflict);
    }
    // A strong lock stabilizes catalog validation through DDL/commit. Nothing
    // runs concurrently: caller stopped gateway, guard rejects other sessions.
    sqlx::query("LOCK TABLE public.audit_events IN ACCESS EXCLUSIVE MODE")
        .execute(&mut **tx)
        .await
        .map_err(db)?;
    let append_only:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='public.audit_events'::regclass AND tgname='audit_append_only' AND tgenabled IN ('O','A') AND tgfoid='public.audit_append_only()'::regprocedure)").fetch_one(&mut **tx).await.map_err(db)?;
    if !append_only {
        return Err(ErrorCode::ResourceConflict);
    }
    Ok(())
}
async fn partitioned(tx: &mut Transaction<'_, Postgres>) -> StoreResult<bool> {
    sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_partitioned_table WHERE partrelid='public.audit_events'::regclass AND partstrat='r' AND partnatts=1 AND partattrs[0]=(SELECT attnum::int2 FROM pg_attribute WHERE attrelid='public.audit_events'::regclass AND attname='occurred_at'))").fetch_one(&mut **tx).await.map_err(db)
}
async fn registry_guard(tx: &mut Transaction<'_, Postgres>) -> StoreResult<()> {
    if !partitioned(tx).await? {
        return Err(ErrorCode::ResourceConflict);
    }
    let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_class registry JOIN pg_namespace n ON n.oid=registry.relnamespace JOIN pg_class parent ON parent.oid='public.audit_events'::regclass WHERE registry.relname='audit_partition_registry' AND n.nspname='public' AND registry.relowner=parent.relowner AND registry.relkind='r') AND EXISTS(SELECT 1 FROM pg_class child JOIN pg_namespace n ON n.oid=child.relnamespace JOIN pg_inherits i ON i.inhrelid=child.oid JOIN pg_class parent ON parent.oid=i.inhparent WHERE parent.oid='public.audit_events'::regclass AND n.nspname='public' AND child.relname='audit_events_default' AND child.relowner=parent.relowner AND pg_get_expr(child.relpartbound,child.oid)='DEFAULT')").fetch_one(&mut **tx).await.map_err(db)?;
    if !valid {
        return Err(ErrorCode::ResourceConflict);
    }
    Ok(())
}
fn name(start: DateTime<Utc>) -> StoreResult<String> {
    if !(1..=9999).contains(&start.year())
        || start.day() != 1
        || start.hour() != 0
        || start.minute() != 0
        || start.second() != 0
        || start.nanosecond() != 0
    {
        return Err(ErrorCode::InvalidArgument);
    }
    Ok(format!("audit_events_m_{}", start.format("%Y%m")))
}
async fn month(
    tx: &mut Transaction<'_, Postgres>,
    next: bool,
) -> StoreResult<(DateTime<Utc>, DateTime<Utc>)> {
    let start:DateTime<Utc>=sqlx::query_scalar("SELECT date_trunc('month',clock_timestamp())+CASE WHEN $1 THEN interval '1 month' ELSE interval '0' END").bind(next).fetch_one(&mut **tx).await.map_err(db)?;
    let end = start
        .checked_add_months(Months::new(1))
        .ok_or(ErrorCode::InvalidArgument)?;
    Ok((start, end))
}
async fn validate_partition(
    tx: &mut Transaction<'_, Postgres>,
    partition: &str,
) -> StoreResult<()> {
    let row=sqlx::query("SELECT r.lower_bound,r.upper_bound,r.bound_expression,pg_get_expr(c.relpartbound,c.oid) AS actual,c.relowner=parent.relowner AS owned,n.nspname='public' AS schema_ok,c.relkind='r' AS table_ok,EXISTS(SELECT 1 FROM pg_inherits i WHERE i.inhrelid=c.oid AND i.inhparent=parent.oid) AS attached,EXISTS(SELECT 1 FROM pg_trigger t WHERE t.tgrelid=c.oid AND t.tgname='audit_append_only' AND t.tgenabled IN ('O','A') AND t.tgfoid='public.audit_append_only()'::regprocedure) AS append_only FROM public.audit_partition_registry r JOIN pg_class c ON c.oid=r.relation_oid AND c.relname=r.partition_name JOIN pg_namespace n ON n.oid=c.relnamespace CROSS JOIN pg_class parent WHERE r.partition_name=$1 AND parent.oid='public.audit_events'::regclass").bind(partition).fetch_optional(&mut **tx).await.map_err(db)?.ok_or(ErrorCode::ResourceConflict)?;
    let lower: DateTime<Utc> = row.get("lower_bound");
    let upper: DateTime<Utc> = row.get("upper_bound");
    if name(lower).map_err(|_| ErrorCode::ResourceConflict)? != partition
        || lower.checked_add_months(Months::new(1)) != Some(upper)
        || !["owned", "schema_ok", "table_ok", "attached", "append_only"]
            .iter()
            .all(|v| row.get::<bool, _>(*v))
    {
        return Err(ErrorCode::ResourceConflict);
    }
    if row.get::<String, _>("actual") != row.get::<String, _>("bound_expression") {
        return Err(ErrorCode::ResourceConflict);
    }
    Ok(())
}
/// Explicit offline one-time upgrade; no automatic SQLx migration runs this SQL.
/// Large histories that cannot copy within two seconds roll back unchanged.
pub async fn audit_partition_upgrade(
    connection: &mut PgConnection,
    server_id: &str,
    gateway_id: &str,
) -> StoreResult<()> {
    bounded(async {
        let mut tx = connection.begin().await.map_err(db)?;
        guard(&mut tx, server_id, gateway_id).await?;
        if partitioned(&mut tx).await? {
            registry_guard(&mut tx).await?;
            tx.commit().await.map_err(db)?;
            return Ok(());
        }
        sqlx::raw_sql(include_str!("../sql/audit_partition_upgrade.sql"))
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        registry_guard(&mut tx).await?;
        audit(
            &mut tx,
            None,
            None,
            "audit.partition_upgrade",
            "audit",
            None,
            Uuid::new_v4(),
            json!({"retention_mode":"managed_monthly_partitions","default_retained":true}),
        )
        .await?;
        tx.commit().await.map_err(db)
    })
    .await
}
/// Create current/next months and drop at most one whole expired managed month.
/// Each DDL transaction has its own two-second total budget. Run only offline;
/// repeat while `dropped` is Some. Default rows are reported and NEVER deleted.
pub async fn maintain_audit_partitions(
    connection: &mut PgConnection,
    server_id: &str,
    gateway_id: &str,
    retention_days: u16,
) -> StoreResult<AuditPartitionMaintenance> {
    if !(1..=3650).contains(&retention_days) {
        return Err(ErrorCode::InvalidArgument);
    }
    let mut result = AuditPartitionMaintenance::default();
    for next in [false, true] {
        let created=bounded(async {
            let mut tx=connection.begin().await.map_err(db)?;guard(&mut tx,server_id,gateway_id).await?;registry_guard(&mut tx).await?;
            let (start,end)=month(&mut tx,next).await?;let partition=name(start)?;
            let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.audit_partition_registry WHERE partition_name=$1)").bind(&partition).fetch_one(&mut *tx).await.map_err(db)?;
            if exists {validate_partition(&mut tx,&partition).await?;tx.commit().await.map_err(db)?;return Ok(None);}
            let overlap:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM public.audit_events_default WHERE occurred_at>=$1 AND occurred_at<$2)").bind(start).bind(end).fetch_one(&mut *tx).await.map_err(db)?;
            if overlap {return Err(ErrorCode::ResourceConflict);}
            // Identifier is generated only by name(); values are generated UTC
            // month boundaries, never strings supplied by an API caller.
            let ddl=format!("CREATE TABLE public.\"{partition}\" PARTITION OF public.audit_events FOR VALUES FROM ('{}') TO ('{}')",start.to_rfc3339(),end.to_rfc3339());
            sqlx::query(&ddl).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("INSERT INTO public.audit_partition_registry SELECT $1,c.oid,$2,$3,pg_get_expr(c.relpartbound,c.oid) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relname=$1").bind(&partition).bind(start).bind(end).execute(&mut *tx).await.map_err(db)?;
            validate_partition(&mut tx,&partition).await?;
            audit(&mut tx,None,None,"audit.partition_created","audit",None,Uuid::new_v4(),json!({"partition":partition,"lower_bound":start,"upper_bound":end})).await?;
            tx.commit().await.map_err(db)?;Ok(Some(partition))
        }).await?;
        if let Some(partition) = created {
            result.created.push(partition);
        }
    }
    let (dropped,default_rows)=bounded(async {
        let mut tx=connection.begin().await.map_err(db)?;guard(&mut tx,server_id,gateway_id).await?;registry_guard(&mut tx).await?;
        let row=sqlx::query("SELECT partition_name,lower_bound,upper_bound FROM public.audit_partition_registry WHERE upper_bound<=clock_timestamp()-make_interval(days=>$1) ORDER BY upper_bound,partition_name LIMIT 1 FOR UPDATE").bind(i32::from(retention_days)).fetch_optional(&mut *tx).await.map_err(db)?;
        let dropped=if let Some(row)=row {
            let partition:String=row.get("partition_name");validate_partition(&mut tx,&partition).await?;
            let payload=json!({"partition":partition,"lower_bound":row.get::<DateTime<Utc>,_>("lower_bound"),"upper_bound":row.get::<DateTime<Utc>,_>("upper_bound"),"retention_days":retention_days});let request=Uuid::new_v4();
            audit(&mut tx,None,None,"audit.partition_drop_started","audit",None,request,payload.clone()).await?;
            sqlx::query(&format!("DROP TABLE public.\"{partition}\"")).execute(&mut *tx).await.map_err(db)?;
            sqlx::query("DELETE FROM public.audit_partition_registry WHERE partition_name=$1").bind(&partition).execute(&mut *tx).await.map_err(db)?;
            audit(&mut tx,None,None,"audit.partition_dropped","audit",None,request,payload).await?;
            Some(partition)
        }else{None};
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM public.audit_events_default").fetch_one(&mut *tx).await.map_err(db)?;
        tx.commit().await.map_err(db)?;Ok((dropped,count))
    }).await?;
    result.dropped = dropped;
    result.default_rows = default_rows;
    Ok(result)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn partition_identifiers_are_generated_from_utc_month_boundaries_only() {
        let start = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(name(start).unwrap(), "audit_events_m_202601");
        assert!(name(start + chrono::Duration::seconds(1)).is_err());
        assert!(name(start + chrono::Duration::days(1)).is_err());
    }
}
