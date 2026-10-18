//! Disposable local PostgreSQL suites; test credentials arrive only through stdin.
use bastion_domain::{Role, TargetProtocol};
use bastion_secrets::{hash_password, Secret};
use bastion_store::{AssetCreate, PgStore};
use serde::Deserialize;
use serde_json::json;
use sqlx::{postgres::PgConnectOptions, ConnectOptions, Connection, PgConnection, Row};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    database_url: String,
}

async fn fixture(
    options: &PgConnectOptions,
    id: Uuid,
    server_postgres: bool,
) -> Result<Secret, String> {
    let url = Secret::new(options.to_url_lossy().to_string());
    let server_id = format!("zt-guac-v2-pg-{id}");
    if server_postgres {
        return Ok(Secret::new(
            json!({"database_url":url.expose(),"fixture":{"server_id":server_id}}).to_string(),
        ));
    }
    let store = PgStore::connect(url.expose(), &server_id, "main")
        .await
        .map_err(|code| format!("store error {code:?}"))?;
    let result = async {
        store.migrate().await.map_err(|code| format!("migration error {code:?}"))?;
        let password = Secret::random();
        let phc = hash_password(password.expose()).map_err(|_| "fixture password hashing failed")?;
        let admin = store.bootstrap_admin("acceptance-admin", &phc, Uuid::new_v4()).await.map_err(|code| format!("bootstrap error {code:?}"))?;
        let login = store.login_web(&admin, &phc, "isolated fixture", Uuid::new_v4()).await.map_err(|code| format!("login error {code:?}"))?;
        let actor = store.authenticate_web(&login.access_token).await.map_err(|code| format!("identity error {code:?}"))?;
        let operator = store.create_user(&actor, "acceptance-operator", &phc, Role::Operator, Uuid::new_v4()).await.map_err(|code| format!("operator error {code:?}"))?;
        let asset = store.create_asset(&actor, &AssetCreate {group_id:None,name:"database-only fixture".into(), host:"127.0.0.1".into(), port:5900, tags:vec![], protocol:TargetProtocol::Vnc, security:None, ssh_host_key:None, rdp_certificate_sha256:None}, Uuid::new_v4()).await.map_err(|code| format!("asset error {code:?}"))?;
        let account = Uuid::new_v4();
        sqlx::query("INSERT INTO target_accounts(id,asset_id,label,username,credential_id) VALUES($1,$2,'fixture-only',NULL,NULL)").bind(account).bind(asset.id).execute(&store.pool).await.map_err(|_| "fixture account insert failed")?;
        Ok(Secret::new(json!({"database_url":url.expose(),"fixture":{"server_id":server_id,"gateway_id":"main","username":"acceptance-admin","password":password.expose(),"asset_id":asset.id,"account_id":account,"operator_id":operator.id}}).to_string()))
    }.await;
    store.pool.close().await;
    result
}

fn run_test(path: &PathBuf, envelope: &Secret) -> Result<(), String> {
    let mut child = Command::new(path)
        .args(["--ignored", "--nocapture", "--test-threads=1"])
        .env("BASTION_TEST_FIXTURE_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "test binary start failed")?;
    if child
        .stdin
        .take()
        .ok_or("test stdin missing")?
        .write_all(envelope.expose().as_bytes())
        .is_err()
    {
        let _ = child.kill();
        let _ = child.wait();
        return Err("test fixture write failed".into());
    }
    if !child.wait().map_err(|_| "test wait failed")?.success() {
        return Err("PostgreSQL suite failed".into());
    }
    Ok(())
}

async fn execute() -> Result<(), String> {
    let mut raw = String::new();
    std::io::stdin()
        .take(16385)
        .read_to_string(&mut raw)
        .map_err(|_| "fixture input failed")?;
    let raw = Secret::new(raw);
    if raw.expose().len() > 16384 {
        return Err("fixture input too large".into());
    }
    let input: Input = serde_json::from_str(raw.expose()).map_err(|_| "invalid fixture input")?;
    let options = PgConnectOptions::from_str(&input.database_url)
        .map_err(|_| "invalid local database URL")?
        .disable_statement_logging();
    if !matches!(options.get_host(), "127.0.0.1" | "localhost" | "::1")
        || options.get_database() != Some("postgres")
    {
        return Err(
            "maintenance URL must address loopback postgres; remote databases are forbidden".into(),
        );
    }
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.is_empty() || !args.len().is_multiple_of(2) {
        return Err("pass suite-name and built binary path pairs".into());
    }
    let mut control = PgConnection::connect_with(&options)
        .await
        .map_err(|_| "local PostgreSQL connection failed")?;
    let mut failures = 0;
    for pair in args.chunks_exact(2) {
        let suite = pair[0].to_str().ok_or("invalid suite name")?;
        if !matches!(
            suite,
            "server-postgres"
                | "web_sessions"
                | "lifecycle"
                | "implicit_access"
                | "user_deletion"
                | "audit_partitions"
                | "asset_groups"
                | "native_sessions"
        ) {
            return Err("unknown isolated suite".into());
        }
        let path = PathBuf::from(&pair[1]);
        if !path.is_file() {
            return Err("built test binary missing".into());
        }
        let id = Uuid::new_v4();
        let name = format!("zt_guac_v2_{}", id.simple());
        let marker = format!("zeroterm-local-acceptance:{id}");
        sqlx::query(&format!("CREATE DATABASE \"{name}\" TEMPLATE template0"))
            .execute(&mut control)
            .await
            .map_err(|_| "isolated database creation failed")?;
        sqlx::query(&format!("COMMENT ON DATABASE \"{name}\" IS '{marker}'"))
            .execute(&mut control)
            .await
            .map_err(|_| "isolated database marker failed")?;
        let oid: i64 = sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname=$1")
            .bind(&name)
            .fetch_one(&mut control)
            .await
            .map_err(|_| "isolated database identity failed")?;
        println!("Running {suite} in new database {name}");
        let result = match fixture(
            &options.clone().database(&name),
            id,
            suite == "server-postgres",
        )
        .await
        {
            Ok(envelope) => run_test(&path, &envelope),
            Err(error) => Err(error),
        };
        let row = sqlx::query("SELECT oid::bigint AS oid,pg_get_userbyid(datdba)=current_user AS owned,shobj_description(oid,'pg_database') AS marker FROM pg_database WHERE datname=$1").bind(&name).fetch_one(&mut control).await.map_err(|_| "cleanup identity lookup failed")?;
        if row.get::<i64, _>("oid") != oid
            || !row.get::<bool, _>("owned")
            || row.get::<Option<String>, _>("marker").as_deref() != Some(&marker)
        {
            return Err("cleanup identity mismatch; database retained".into());
        }
        sqlx::query(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
            .execute(&mut control)
            .await
            .map_err(|_| "isolated database cleanup failed")?;
        if let Err(error) = result {
            failures += 1;
            eprintln!("{suite}: {error}");
        }
    }
    control
        .close()
        .await
        .map_err(|_| "local control connection close failed")?;
    if failures != 0 {
        return Err(format!("{failures} PostgreSQL suites failed"));
    }
    Ok(())
}

#[tokio::main]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("Local PostgreSQL acceptance failed: {error}");
        std::process::exit(1);
    }
    println!("All selected real PostgreSQL suites passed; browser/engine acceptance is separate");
}
