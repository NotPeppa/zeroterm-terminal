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
    for file in ["kek-v1"] {
        let metadata = std::fs::metadata(directory.join(file)).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
    assert_eq!(
        std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(!directory.join("api-token").exists());
    assert!(!directory.join("ssh_host_ed25519_key").exists());
    let identity = std::fs::read(directory.join("kek-v1")).unwrap();
    assert!(!init().status.success());
    assert_eq!(std::fs::read(directory.join("kek-v1")).unwrap(), identity);
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

#[test]
fn default_binary_has_no_development_authentication_entrypoint() {
    let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(result.status.success());
    let help = String::from_utf8_lossy(&result.stdout);
    assert!(!help.contains("prototype"));
    assert!(!help.contains("serve-m1"));
    for legacy in ["prototype", "serve-m1"] {
        let result = Command::new(env!("CARGO_BIN_EXE_bastion-server"))
            .args([legacy, "--config", "/missing"])
            .output()
            .unwrap();
        assert!(!result.status.success());
        assert!(String::from_utf8_lossy(&result.stderr).contains("unrecognized subcommand"));
    }
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
    assert!(String::from_utf8_lossy(&result.stderr).contains("unknown field"));
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
