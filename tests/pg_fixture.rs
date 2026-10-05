//! Shared test-only fixture loader. Production secret-file checks are deliberately unchanged.
use bastion_secrets::{read_secret_file, Secret};
use serde::{de::DeserializeOwned, Deserialize};
use std::{io::Read, path::PathBuf};

#[derive(Deserialize)]
struct StdinFixture<T> {
    fixture: T,
    database_url: String,
}

pub fn load<T: DeserializeOwned>() -> (T, Secret) {
    if std::env::var("BASTION_TEST_FIXTURE_STDIN").as_deref() == Ok("1") {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .expect("test fixture stdin required");
        let input = Secret::new(input);
        let envelope: StdinFixture<T> =
            serde_json::from_str(input.expose()).expect("invalid stdin test fixture");
        return (envelope.fixture, Secret::new(envelope.database_url));
    }
    let path = std::env::var("BASTION_M1_FIXTURE").expect("isolated fixture path required");
    let contents = read_secret_file(&PathBuf::from(path)).expect("protected test fixture required");
    #[derive(Deserialize)]
    struct Location {
        database_url_file: PathBuf,
    }
    let location: Location =
        serde_json::from_str(contents.expose()).expect("invalid test fixture location");
    let fixture = serde_json::from_str(contents.expose()).expect("invalid test fixture");
    let url =
        read_secret_file(&location.database_url_file).expect("protected database URL required");
    (fixture, url)
}

pub async fn probe(store: &bastion_store::PgStore) {
    if std::env::var("BASTION_TEST_DB_DIAGNOSTICS").as_deref() != Ok("1") {
        return;
    }
    for index in 1..=3 {
        let start = std::time::Instant::now();
        let result = sqlx::query_scalar::<_, i32>("SELECT 1")
            .fetch_one(&store.pool)
            .await;
        eprintln!(
            "DB probe {index}: {}ms, success={}",
            start.elapsed().as_millis(),
            result.is_ok()
        );
    }
}

pub async fn failure(store: &bastion_store::PgStore, label: &str, elapsed: std::time::Duration) {
    if std::env::var("BASTION_TEST_DB_DIAGNOSTICS").as_deref() != Ok("1") {
        return;
    }
    eprintln!(
        "DB operation {label} failed after {}ms (production total budget: 2000ms)",
        elapsed.as_millis()
    );
    let rows = sqlx::query_as::<_, (String, String, i64)>("SELECT COALESCE(state,'unknown'),COALESCE(wait_event_type,'none'),count(*) FROM pg_stat_activity WHERE datname=current_database() GROUP BY state,wait_event_type").fetch_all(&store.pool).await;
    if let Ok(rows) = rows {
        for (state, wait, count) in rows {
            eprintln!("Isolated DB sessions: state={state}, wait={wait}, count={count}");
        }
    }
}
