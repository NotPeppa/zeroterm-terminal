#[path = "../../../tests/pg_fixture.rs"]
mod pg_fixture;
use bastion_domain::{
    Capability, ConnectionState, ErrorCode, GatewayAddress, Purpose, TicketRequest,
};
use bastion_secrets::verify_password;
use serde::Deserialize;
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

#[derive(Deserialize)]
struct Fixture {
    server_id: String,
    gateway_id: String,
    username: String,
    password: String,
    asset_id: Uuid,
    account_id: Uuid,
    operator_id: Uuid,
}

#[tokio::test]
#[ignore = "run through tests/m1_smoke.py against its isolated PostgreSQL fixture"]
async fn transaction_races_and_revocation() {
    let (fixture, url) = pg_fixture::load::<Fixture>();
    let store =
        bastion_store::PgStore::connect(url.expose(), &fixture.server_id, &fixture.gateway_id)
            .await
            .unwrap();
    pg_fixture::probe(&store).await;
    let (user, phc) = store
        .login_candidate(&fixture.username)
        .await
        .unwrap()
        .unwrap();
    assert!(verify_password(&fixture.password, &phc));
    let login_started = std::time::Instant::now();
    let login_result = store
        .login(&user, &phc, "transaction tests", Uuid::new_v4())
        .await;
    if login_result.is_err() {
        pg_fixture::failure(&store, "login", login_started.elapsed()).await;
    }
    let login = login_result.unwrap();
    let actor = store.authenticate(&login.access_token).await.unwrap();
    let grant = store
        .create_grant(
            &actor,
            user.id,
            fixture.asset_id,
            fixture.account_id,
            &[Capability::Exec],
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    let gateway = GatewayAddress {
        id: fixture.gateway_id.clone(),
        host: "127.0.0.1".into(),
        port: 2222,
        username: String::new(),
    };
    let request = TicketRequest {
        asset_id: fixture.asset_id,
        account_id: fixture.account_id,
        capabilities: vec![Capability::Exec],
        purpose: Purpose::Terminal,
    };
    let issue = || store.issue_ticket(&actor, request.clone(), gateway.clone(), Uuid::new_v4());
    let issue_started = std::time::Instant::now();
    let issue_result = issue().await;
    if issue_result.is_err() {
        pg_fixture::failure(&store, "issue_ticket", issue_started.elapsed()).await;
    }
    let ticket = issue_result.unwrap();
    assert!(matches!(
        store.consume_ticket(ticket.ticket_id, "wrong secret").await,
        Err(ErrorCode::TicketInvalid)
    ));
    let secret = Arc::new(ticket.ticket_secret);
    let mut racers = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let store = store.clone();
        let secret = secret.clone();
        let id = ticket.ticket_id;
        racers.spawn(async move { store.consume_ticket(id, &secret).await });
    }
    let mut won = 0;
    while let Some(result) = racers.join_next().await {
        match result.unwrap() {
            Ok(connection) => {
                won += 1;
                assert_eq!(connection.id, ticket.connection_id);
            }
            Err(ErrorCode::TicketUsed) => {}
            Err(code) => panic!("unexpected race failure: {code:?}"),
        }
    }
    assert_eq!(
        won, 1,
        "a ticket must establish exactly one target connection"
    );
    store
        .transition(
            ticket.connection_id,
            ConnectionState::Failed,
            Some(ErrorCode::TargetUnreachable),
        )
        .await
        .unwrap();
    assert!(matches!(
        store.consume_ticket(ticket.ticket_id, &secret).await,
        Err(ErrorCode::TicketUsed)
    ));
    // Expiration is checked again after waiting on a ticket lock.
    let expired = issue().await.unwrap();
    sqlx::query("UPDATE connection_tickets SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1").bind(expired.ticket_id).execute(&store.pool).await.unwrap();
    let mut lock = store.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM connection_tickets WHERE id=$1 FOR UPDATE")
        .bind(expired.ticket_id)
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let consumer = store.clone();
    let id = expired.ticket_id;
    let secret = expired.ticket_secret;
    let waiting = tokio::spawn(async move { consumer.consume_ticket(id, &secret).await });
    tokio::time::sleep(Duration::from_millis(1000)).await;
    lock.commit().await.unwrap();
    assert!(matches!(
        waiting.await.unwrap(),
        Err(ErrorCode::TicketExpired)
    ));

    // Grant and login deadlines are also re-evaluated after that lock wait.
    for login_deadline in [false, true] {
        let ticket = issue().await.unwrap();
        if login_deadline {
            sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1").bind(actor.login_session_id).execute(&store.pool).await.unwrap();
        } else {
            sqlx::query("UPDATE grants SET expires_at=clock_timestamp()+interval '750 milliseconds' WHERE id=$1").bind(grant.id).execute(&store.pool).await.unwrap();
        }
        let mut lock = store.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM connection_tickets WHERE id=$1 FOR UPDATE")
            .bind(ticket.ticket_id)
            .fetch_one(&mut *lock)
            .await
            .unwrap();
        let consumer = store.clone();
        let waiting = tokio::spawn(async move {
            consumer
                .consume_ticket(ticket.ticket_id, &ticket.ticket_secret)
                .await
        });
        tokio::time::sleep(Duration::from_millis(1000)).await;
        lock.commit().await.unwrap();
        let expected = if login_deadline {
            ErrorCode::LoginSessionRevoked
        } else {
            ErrorCode::PermissionDenied
        };
        assert!(matches!(waiting.await.unwrap(),Err(code) if code==expected));
        if login_deadline {
            sqlx::query("UPDATE login_sessions SET expires_at=clock_timestamp()+interval '7 days' WHERE id=$1").bind(actor.login_session_id).execute(&store.pool).await.unwrap();
        } else {
            sqlx::query("UPDATE grants SET expires_at=NULL WHERE id=$1")
                .bind(grant.id)
                .execute(&store.pool)
                .await
                .unwrap();
        }
    }
    // An unrelated policy edit invalidates unconsumed tickets, but an established
    // connection is evaluated against its current effective grants.
    let stale = issue().await.unwrap();
    let established = issue().await.unwrap();
    let established = store
        .consume_ticket(established.ticket_id, &established.ticket_secret)
        .await
        .unwrap();
    let unrelated = store
        .create_grant(
            &actor,
            fixture.operator_id,
            fixture.asset_id,
            fixture.account_id,
            &[Capability::Sftp],
            None,
            Uuid::new_v4(),
        )
        .await
        .unwrap();
    assert!(matches!(
        store
            .consume_ticket(stale.ticket_id, &stale.ticket_secret)
            .await,
        Err(ErrorCode::TicketStale)
    ));
    store.authorize_connection(&established).await.unwrap();
    store
        .revoke_grant(&actor, grant.id, grant.revision, Uuid::new_v4())
        .await
        .unwrap();
    assert!(matches!(
        store.authorize_connection(&established).await,
        Err(ErrorCode::PermissionDenied)
    ));
    store
        .transition(
            established.id,
            ConnectionState::Failed,
            Some(ErrorCode::PermissionDenied),
        )
        .await
        .unwrap();
    store
        .revoke_grant(&actor, unrelated.id, unrelated.revision, Uuid::new_v4())
        .await
        .unwrap();
    // Critical transactions have a total two-second budget even under lock contention.
    let mut lock = store.pool.begin().await.unwrap();
    sqlx::query("SELECT policy_revision FROM server_settings FOR UPDATE")
        .fetch_one(&mut *lock)
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    assert!(matches!(
        issue().await,
        Err(ErrorCode::PolicyStoreUnavailable)
    ));
    assert!(started.elapsed() < Duration::from_millis(2300));
    lock.rollback().await.unwrap();
    println!("single consumption, lock expiry, policy revision, revocation and bounded transaction tests passed");
}
