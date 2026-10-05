#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::process::Command;

#[cfg(unix)]
#[test]
fn initialization_protects_files_and_refuses_to_replace_identity() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("state");
    let init = || {
        Command::new(env!("CARGO_BIN_EXE_bastion-server"))
            .args(["init", "--directory"])
            .arg(&directory)
            .output()
            .unwrap()
    };
    assert!(init().status.success());
    for file in ["ssh_host_ed25519_key", "api-token", "kek-v1"] {
        let metadata = std::fs::metadata(directory.join(file)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(
        std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let identity = std::fs::read(directory.join("ssh_host_ed25519_key")).unwrap();
    assert!(!init().status.success());
    assert_eq!(
        std::fs::read(directory.join("ssh_host_ed25519_key")).unwrap(),
        identity
    );
}

#[cfg(not(unix))]
#[test]
fn initialization_fails_closed_without_unix_permission_guarantees() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("state");
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .args(["init", "--directory"])
        .arg(&directory)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("Unix"));
    assert!(!directory.exists());
}

#[cfg(not(feature = "dev-prototype"))]
#[test]
fn default_binary_has_no_development_authentication_entrypoint() {
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(!String::from_utf8_lossy(&result.stdout).contains("prototype"));
}

#[cfg(feature = "dev-prototype")]
#[test]
fn prototype_refuses_non_loopback_before_opening_credentials_or_sockets() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config.toml");
    std::fs::write(
        &config,
        r#"
server_id = "test"
api_listen = "0.0.0.0:8080"
ssh_listen = "127.0.0.1:2222"
api_token_file = "/does/not/exist"
ssh_host_key_file = "/does/not/exist"
[target]
asset_id = "11111111-1111-4111-8111-111111111111"
account_id = "22222222-2222-4222-8222-222222222222"
name = "test"
address = "127.0.0.1:2200"
username = "test"
host_key_file = "/does/not/exist"
capabilities = ["exec"]
[target.credentials]
auth = "password"
password_file = "/does/not/exist"
"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .args(["prototype", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("must listen on loopback"));
}

#[test]
fn m1_refuses_non_loopback_before_database_or_secret_loading() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("m1.toml");
    std::fs::write(
        &config,
        r#"
server_id="test"
gateway_id="main"
api_listen="0.0.0.0:8080"
ssh_listen="127.0.0.1:2222"
database_url_file="/does/not/exist"
ssh_host_key_file="/does/not/exist"
active_kek_version=1
[kek_files]
"1"="/does/not/exist"
[network]
allow=["10.0.0.0/8"]
deny=[]
"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .args(["serve-m1", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("must listen on loopback"));
}

#[test]
fn production_refuses_legacy_configuration_before_secret_or_database_loading() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("legacy.toml");
    std::fs::write(
        &config,
        r#"
server_id="test"
gateway_id="main"
api_listen="127.0.0.1:8080"
ssh_listen="127.0.0.1:2222"
database_url_file="/missing"
ssh_host_key_file="/missing"
active_kek_version=1
[kek_files]
"1"="/missing"
[network]
allow=["10.0.0.0/8"]
deny=[]
"#,
    )
    .unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .args(["serve", "--config"])
        .arg(config)
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr).contains("serve requires production configuration")
    );
}

#[test]
fn maintenance_commands_are_explicit_and_backup_requires_manifest() {
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(result.status.success());
    let help = String::from_utf8_lossy(&result.stdout);
    for command in [
        "verify-backup",
        "recover-restore",
        "retain-recordings",
        "rewrap-keys",
        "partition-audit",
        "retain-audit",
    ] {
        assert!(help.contains(command));
    }
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .args(["verify-backup", "--config", "/missing"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("--manifest"));
}

#[test]
fn audit_maintenance_requires_offline_intent_and_bounded_days() {
    for command in ["partition-audit", "retain-audit"] {
        let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
            .args([command, "--config", "/missing"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("requires explicit --offline"));
    }
    for days in ["0", "3651"] {
        let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
            .args([
                "retain-audit",
                "--config",
                "/missing",
                "--offline",
                "--days",
                days,
            ])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("retention days must be 1..3650"));
    }
}
