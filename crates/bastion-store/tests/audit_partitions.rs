//! Explicit isolated/offline PostgreSQL tests. No database access by default.
#[allow(dead_code)]
#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::ErrorCode;
use bastion_store::{audit_partition_upgrade, maintain_audit_partitions, PgStore};
use chrono::{DateTime, Months, Utc};
use serde::Deserialize;
use sqlx::{Connection, PgConnection};
use uuid::Uuid;
#[derive(Deserialize)]
struct Fixture {
    server_id: String,
    gateway_id: String,
}
async fn insert(
    connection: &mut PgConnection,
    id: Uuid,
    time: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO public.audit_events(id,occurred_at,action,resource_type,request_id,sanitized_payload) VALUES($1,$2,'audit.partition_test','audit',$3,'{}')").bind(id).bind(time).bind(Uuid::new_v4()).execute(connection).await?;
    Ok(())
}
#[tokio::test]
#[ignore = "requires isolated PostgreSQL owner fixture, stopped gateway and no other database sessions"]
async fn offline_audit_upgrade_retention_append_only_roles_and_default_safety() {
    let (fixture, url) = pg_fixture::load::<Fixture>();
    let store = PgStore::connect(url.expose(), &fixture.server_id, &fixture.gateway_id)
        .await
        .unwrap();
    store.migrate().await.unwrap();
    store.pool.close().await;
    let mut connection = PgConnection::connect(url.expose()).await.unwrap();
    let now: DateTime<Utc> = sqlx::query_scalar(
        "SELECT date_trunc('month',clock_timestamp() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC'",
    )
    .fetch_one(&mut connection)
    .await
    .unwrap();
    let old = now.checked_sub_months(Months::new(8)).unwrap();
    let current_id = Uuid::new_v4();
    let old_id = Uuid::new_v4();
    insert(&mut connection, current_id, now + chrono::Duration::days(1))
        .await
        .unwrap();
    insert(&mut connection, old_id, old + chrono::Duration::days(1))
        .await
        .unwrap();
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    let other = PgConnection::connect(url.expose()).await.unwrap();
    assert_eq!(
        audit_partition_upgrade(&mut connection, &fixture.server_id, &fixture.gateway_id).await,
        Err(ErrorCode::ResourceConflict)
    );
    other.close().await.unwrap();
    audit_partition_upgrade(&mut connection, &fixture.server_id, &fixture.gateway_id)
        .await
        .unwrap();
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(after, before + 1);
    assert!(
        sqlx::query("UPDATE audit_events SET action='forbidden' WHERE id=$1")
            .bind(current_id)
            .execute(&mut connection)
            .await
            .is_err()
    );
    assert!(sqlx::query("DELETE FROM audit_events WHERE id=$1")
        .bind(current_id)
        .execute(&mut connection)
        .await
        .is_err());
    assert_eq!(
        maintain_audit_partitions(&mut connection, &fixture.server_id, &fixture.gateway_id, 0)
            .await
            .unwrap_err(),
        ErrorCode::InvalidArgument
    );
    let retained = maintain_audit_partitions(
        &mut connection,
        &fixture.server_id,
        &fixture.gateway_id,
        180,
    )
    .await
    .unwrap();
    assert_eq!(
        retained.dropped,
        Some(format!("audit_events_m_{}", old.format("%Y%m")))
    );
    let old_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE id=$1")
        .bind(old_id)
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(old_count, 0);
    let current_count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE id=$1")
        .bind(current_id)
        .fetch_one(&mut connection)
        .await
        .unwrap();
    assert_eq!(current_count, 1);
    let drop_audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE action IN ('audit.partition_drop_started','audit.partition_dropped') AND sanitized_payload->>'partition'=$1").bind(retained.dropped.as_ref().unwrap()).fetch_one(&mut connection).await.unwrap();
    assert_eq!(drop_audits, 2);
    // Even an ancient row in DEFAULT is never discarded by retention.
    let default_id = Uuid::new_v4();
    insert(&mut connection, default_id, old + chrono::Duration::days(2))
        .await
        .unwrap();
    let result = maintain_audit_partitions(
        &mut connection,
        &fixture.server_id,
        &fixture.gateway_id,
        180,
    )
    .await
    .unwrap();
    assert_eq!(result.default_rows, 1);
    assert_eq!(result.dropped, None);
    // Registry drift cannot turn a current partition into an eligible old one.
    let partition = format!("audit_events_m_{}", now.format("%Y%m"));
    sqlx::query("UPDATE audit_partition_registry SET lower_bound=lower_bound-interval '1 day' WHERE partition_name=$1").bind(&partition).execute(&mut connection).await.unwrap();
    assert_eq!(
        maintain_audit_partitions(
            &mut connection,
            &fixture.server_id,
            &fixture.gateway_id,
            180
        )
        .await
        .unwrap_err(),
        ErrorCode::ResourceConflict
    );
    sqlx::query("UPDATE audit_partition_registry SET lower_bound=lower_bound+interval '1 day' WHERE partition_name=$1").bind(&partition).execute(&mut connection).await.unwrap();
    // Runtime role can append/read parent but cannot mutate/delete/drop parent
    // or invoke owner maintenance. Role is test-only and cleaned up below.
    let role = format!("audit_test_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE ROLE \"{role}\" NOLOGIN"))
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("GRANT USAGE ON SCHEMA public TO \"{role}\"; GRANT SELECT,INSERT ON public.audit_events TO \"{role}\"")).execute(&mut connection).await.unwrap();
    sqlx::query(&format!("SET ROLE \"{role}\""))
        .execute(&mut connection)
        .await
        .unwrap();
    insert(
        &mut connection,
        Uuid::new_v4(),
        now + chrono::Duration::days(3),
    )
    .await
    .unwrap();
    assert!(sqlx::query("UPDATE audit_events SET action='forbidden'")
        .execute(&mut connection)
        .await
        .is_err());
    assert!(sqlx::query("DELETE FROM audit_events")
        .execute(&mut connection)
        .await
        .is_err());
    assert!(sqlx::query("DROP TABLE audit_events")
        .execute(&mut connection)
        .await
        .is_err());
    assert!(sqlx::query("DROP TABLE audit_events_default")
        .execute(&mut connection)
        .await
        .is_err());
    assert_eq!(
        audit_partition_upgrade(&mut connection, &fixture.server_id, &fixture.gateway_id).await,
        Err(ErrorCode::PermissionDenied)
    );
    sqlx::query("RESET ROLE")
        .execute(&mut connection)
        .await
        .unwrap();
    sqlx::raw_sql(&format!("REVOKE SELECT,INSERT ON public.audit_events FROM \"{role}\"; REVOKE USAGE ON SCHEMA public FROM \"{role}\"; DROP ROLE \"{role}\"")).execute(&mut connection).await.unwrap();
    connection.close().await.unwrap();
}
