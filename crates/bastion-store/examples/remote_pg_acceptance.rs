//! Opt-in remote PostgreSQL acceptance. Credentials arrive only through stdin.
//! Creates its own database; never migrates the supplied maintenance database.
use bastion_domain::Role;
use bastion_secrets::{hash_password, Secret};
use bastion_store::PgStore;
use serde::Deserialize;
use serde_json::json;
use sqlx::{
    postgres::{PgConnectOptions, PgSslMode},
    ConnectOptions, Connection, PgConnection, Row,
};
use std::{
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
    str::FromStr,
    time::Duration,
};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    database_url: String,
    allow_unverified_tls: bool,
}
fn db_error(error: sqlx::Error) -> String {
    // Do not print server messages, connection options, credentials or SQL parameters.
    match error {
        sqlx::Error::Database(e) => format!(
            "database error SQLSTATE {}",
            e.code().as_deref().unwrap_or("unknown")
        ),
        _ => "database transport/timeout error".into(),
    }
}
fn store_error(code: bastion_domain::ErrorCode) -> String {
    format!("store error {code:?}")
}
async fn connect(options: &PgConnectOptions) -> Result<PgConnection, String> {
    tokio::time::timeout(Duration::from_secs(15), PgConnection::connect_with(options))
        .await
        .map_err(|_| "database connection timed out".to_string())?
        .map_err(db_error)
}
fn run_test(exe: PathBuf, envelope: &Secret) -> Result<(), String> {
    let mut child = Command::new(exe)
        .args(["--ignored", "--nocapture", "--test-threads=1"])
        .env("BASTION_TEST_FIXTURE_STDIN", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|_| "failed to start test binary".to_string())?;
    let sent = child
        .stdin
        .take()
        .ok_or("test stdin missing")?
        .write_all(envelope.expose().as_bytes());
    if sent.is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err("test stdin write failed".into());
    }
    let status = child.wait().map_err(|_| "test wait failed".to_string())?;
    if !status.success() {
        return Err("real database test failed".into());
    }
    Ok(())
}
async fn test_database(options: &PgConnectOptions) -> Result<(), String> {
    let url = Secret::new(options.to_url_lossy().to_string());
    let store = PgStore::connect(url.expose(), "remote-pg-acceptance", "main")
        .await
        .map_err(store_error)?;
    let result=async {
        store.migrate().await.map_err(store_error)?;
        store.migrate().await.map_err(store_error)?;
        let count:i64=sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success").fetch_one(&store.pool).await.map_err(db_error)?;
        if count!=5{return Err("expected five successful migrations".into());}
        println!("Migrations 0001–0005 and repeat migration: passed");
        let password=Secret::random();let phc=hash_password(password.expose()).map_err(|_|"test password hashing failed".to_string())?;
        let admin=store.bootstrap_admin("acceptance-admin",&phc,Uuid::new_v4()).await.map_err(store_error)?;
        let login=store.login(&admin,&phc,"remote acceptance",Uuid::new_v4()).await.map_err(store_error)?;
        let actor=store.authenticate(&login.access_token).await.map_err(store_error)?;
        let operator=store.create_user(&actor,"acceptance-operator",&phc,Role::Operator,Uuid::new_v4()).await.map_err(store_error)?;
        let asset=store.create_asset(&actor,"database-only fixture","127.0.0.1",22,&[],Uuid::new_v4()).await.map_err(store_error)?;
        // Inert schema-valid ciphertext: these tests never connect or decrypt a target credential.
        let credential=Uuid::new_v4();let account=Uuid::new_v4();
        sqlx::query("INSERT INTO credentials(id,kind,revision,ciphertext,nonce,wrapped_dek,wrap_nonce,key_version) VALUES($1,'password',1,$2,$3,$4,$5,1)").bind(credential).bind(vec![0u8;17]).bind(vec![0u8;24]).bind(vec![0u8;48]).bind(vec![0u8;24]).execute(&store.pool).await.map_err(db_error)?;
        sqlx::query("INSERT INTO target_accounts(id,asset_id,username,credential_id) VALUES($1,$2,'fixture-only',$3)").bind(account).bind(asset.id).bind(credential).execute(&store.pool).await.map_err(db_error)?;
        let fixture=Secret::new(json!({"database_url":url.expose(),"fixture":{"server_id":"remote-pg-acceptance","gateway_id":"main","username":"acceptance-admin","password":password.expose(),"asset_id":asset.id,"account_id":account,"operator_id":operator.id}}).to_string());
        let tests:Vec<PathBuf>=std::env::args_os().skip(1).map(PathBuf::from).collect();
        if tests.len()!=2 || tests.iter().any(|path|!path.is_file()){return Err("pass exactly the built postgres and web_sessions test binaries".into());}
        let mut failures=0;
        for (index,exe) in tests.into_iter().enumerate(){
            println!("Real PostgreSQL fixture suite {}/2",index+1);
            if run_test(exe,&fixture).is_err(){failures+=1;}
        }
        let encrypted:bool=sqlx::query_scalar("SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetch_one(&store.pool).await.map_err(db_error)?;
        if !encrypted{return Err("database test connection was not TLS encrypted".into());}
        let audits:i64=sqlx::query_scalar("SELECT count(*) FROM audit_events").fetch_one(&store.pool).await.map_err(db_error)?;
        println!("Encrypted test connection and audit persistence: passed ({audits} events)");
        if failures>0{return Err(format!("{failures} real PostgreSQL fixture suite(s) failed"));}
        Ok(())
    }.await;
    store.pool.close().await;
    result
}
async fn execute() -> Result<(), String> {
    let mut raw = String::new();
    std::io::stdin()
        .read_to_string(&mut raw)
        .map_err(|_| "credential stdin read failed".to_string())?;
    let raw = Secret::new(raw);
    let input: Input =
        serde_json::from_str(raw.expose()).map_err(|_| "invalid credential input".to_string())?;
    if !input.allow_unverified_tls {
        return Err("this test runner requires explicit acknowledgement of unverified TLS".into());
    }
    let options = PgConnectOptions::from_str(&input.database_url)
        .map_err(db_error)?
        .ssl_mode(PgSslMode::Require)
        .disable_statement_logging();
    let mut maintenance = connect(&options).await?;
    let (database,encrypted,create):(String,bool,bool)=sqlx::query_as("SELECT current_database(),COALESCE((SELECT ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()),false),(SELECT rolcreatedb OR rolsuper FROM pg_roles WHERE rolname=current_user)").fetch_one(&mut maintenance).await.map_err(db_error)?;
    if database != "postgres" || !encrypted || !create {
        return Err(
            "maintenance must be postgres, encrypted, and allow isolated database creation".into(),
        );
    }
    let version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(&mut maintenance)
        .await
        .map_err(db_error)?;
    println!("PostgreSQL {version}: TLS encrypted, certificate verification disabled by explicit test approval");
    let id = Uuid::new_v4().simple().to_string();
    let name = format!("bastion_acceptance_{id}");
    let marker = format!("bastion-isolated-acceptance:{id}");
    // Name/marker contain only our constant prefix and random hex, never user SQL input.
    println!("Temporary database planned: {name}");
    sqlx::query(&format!("CREATE DATABASE \"{name}\" TEMPLATE template0"))
        .execute(&mut maintenance)
        .await
        .map_err(db_error)?;
    let oid: i64 = sqlx::query_scalar("SELECT oid::bigint FROM pg_database WHERE datname=$1")
        .bind(&name)
        .fetch_one(&mut maintenance)
        .await
        .map_err(db_error)?;
    let marked = sqlx::query(&format!("COMMENT ON DATABASE \"{name}\" IS '{marker}'"))
        .execute(&mut maintenance)
        .await
        .map_err(db_error);
    let result = match marked {
        Ok(_) => test_database(&options.clone().database(&name)).await,
        Err(e) => Err(e),
    };
    // Recover the control connection if a network error closed it. Never drop any other DB.
    if maintenance.ping().await.is_err() {
        maintenance = connect(&options).await?;
    }
    let row=sqlx::query("SELECT oid::bigint AS oid,pg_get_userbyid(datdba)=current_user AS owned,shobj_description(oid,'pg_database') AS marker FROM pg_database WHERE datname=$1").bind(&name).fetch_one(&mut maintenance).await.map_err(db_error)?;
    if row.get::<i64, _>("oid") != oid
        || !row.get::<bool, _>("owned")
        || row.get::<Option<String>, _>("marker").as_deref() != Some(&marker)
    {
        return Err(format!(
            "cleanup identity check failed; inspect only temporary database {name}"
        ));
    }
    sqlx::query(&format!("DROP DATABASE \"{name}\" WITH (FORCE)"))
        .execute(&mut maintenance)
        .await
        .map_err(db_error)?;
    let remains: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname=$1)")
            .bind(&name)
            .fetch_one(&mut maintenance)
            .await
            .map_err(db_error)?;
    if remains {
        return Err(format!("temporary database cleanup unverified: {name}"));
    }
    println!("Temporary database cleanup verified: {name}");
    maintenance.close().await.map_err(db_error)?;
    result
}
#[tokio::main]
async fn main() {
    if let Err(error) = execute().await {
        eprintln!("Remote PostgreSQL acceptance failed: {error}");
        std::process::exit(1)
    }
    println!("Remote PostgreSQL acceptance passed; no SSH or browser acceptance claimed");
}
