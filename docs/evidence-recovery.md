# Release recovery acceptance evidence

## Canonical candidate: one complete scoped run passed

The canonical recovery fixture returned **exit0** on 2026-10-05 at 17:21:31 UTC. This is a result for the tested recovery phases, **not a production-readiness or race-fix claim**. `production_ready=false` throughout. Earlier intermittent normal-shell recording failure remains recorded below; one successful run does not establish that the race is fixed.

[Canonical phase/timestamp evidence](../tests/release_recovery-evidence-canonical.json) records these exact inputs:

| Input | SHA256 |
|---|---|
| User-provided canonical ZIP | `bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9` |
| Added recovery runner | `f51a8faeda061ce3168cba6ec056bc6c0c6f71fd0e14c1cced277980beaf147a` |
| Added recovery phase helper | `8290d8442a2ed7698ffbfb01a62e382aa2c2bb661da6b4394e3dc447886a0039` |
| Freshly built server binary | `2a1e4d68a0706265b57c5d3e646a411c763522ddd26a23bdfa36cb77badbef99` |
| Rust/TOML/SQL/lock source manifest | `a6c87dc7f3b4259c950363699dc69f392a35ad06420f7e924251d9c2cf397628` |

The ZIP was SHA-verified and unpacked once as UID1000 into a new private directory. Both added runner hashes were checked before building. A new target directory, absent before the run, and an independently copied Cargo cache were used; `cargo build --locked -p bastion-server` succeeded in 2m41s. No production source in the canonical archive was patched during acceptance. Post-run checks verified unchanged source/runner hashes, an absent runner PID and zero PG PID files. A non-printing scan of24 fixture logs against13 known fixture secret, private-key and DB-URL files found no matches; all13 files were mode0600.

```text
fixture root: /var/tmp/bastion-release-recovery-8da992077b2c464a9591085a3ffed75b
canonical source: <fixture root>/source-candidate
fresh target: <canonical source>/target
runner wrapper PID: 669132
```

## Actual canonical phases

| Phase | Actual assertion/result |
|---|---|
| Required recording discovery | Pass: required=true, available=true, production_ready=false |
| Directory permissions | Pass: mode0755 startup rejected; runtime mode0500 denied shell with zero Streaming channels |
| Low-free-space preflight | Pass: actual free72,337,846,272 bytes, required73,411,588,096 bytes, startup rejected; no disk fill |
| Complete recording/replay | Pass: Complete, encrypted614 bytes, verified replay343 bytes |
| Backup/restore | Pass: real pg_dump/pg_restore into a second isolated cluster; exact2 credentials,1 recording,2 host keys, KEK version1; public/private gateway host-key bytes unchanged; real credential authentication and identical replay |
| Restore session recovery | Pass: old Bearer rejected; old unused native ticket rejected through SSH; zero live login families and zero issued tickets |
| KEK rewrap | Pass: credential ciphertext/data nonce, recording nonce prefix and encrypted-file hash unchanged; new-key-only verify-backup, credential authentication and replay succeeded |
| Missing in-use KEK | Pass: startup rejected |
| AEAD corruption | Pass: no successful clean EOF; metadata Corrupt, not Complete |
| Separate recording truncation | Pass: HTTP503, safe RECORDING_UNAVAILABLE error, metadata Corrupt; correlated request ID and no-store checked |
| Active device-family revoke | Pass: native shell closed in0.029s, client exit255 |
| SIGKILL/restart | Pass: active connection Interrupted, unused ticket actually Revoked, gateway host-key hash unchanged |
| DB fast-stop | Pass: pg_ctl fast stop closed native shell in0.671s, within5s |
| Shutdown/cleanup | Gateway after DB outage drained in6.041s; no7s fixture-deadline SIGKILL. Final cleanup0.128s, zero live tracked children, zero PG PID files |
| True disk-full / genuinely blocked writes | **Not tested**; no host disk fill, fake success or production-security bypass |

Only synthetic credentials were used. TLS validated against the isolated CA; native SSH used strict gateway host-key pins. Secrets stayed in memory or0600 files. The fixture ran as `bastion-acceptance` UID1000, using dynamic loopback ports that excluded22 and5432. Existing host PostgreSQL/sshd and other services were not changed. SIGKILL was intentionally used only for the tracked gateway recovery drill; no unrelated process was killed. Protected working directories are retained for forensic inspection, while only secret-free evidence is copied here.

## Earlier failure and coverage limits

The earlier candidate binary SHA256 was `56eb2a9492587ed58d347024827771421e38a90cc715502000306200f14fca70`, not the canonical binary above. [Earlier backup/KEK/corruption evidence](../tests/release_recovery-evidence-backup.json) and [independent runtime-only evidence](../tests/release_recovery-evidence-runtime.json) preserve their actual results, including a corrected fixture-reporting error rather than relabelling that whole run successful.

[Earlier normal-shell failure evidence](../tests/release_recovery-evidence-failure.json) records a fixture exit1. Post-stop SQL inspection showed healthy native client exit7 but `connections.state=closed`, `channels.state=failed`, `channels.failure_code=RECORDING_UNAVAILABLE`, and `recordings.state=partial, bytes=614, last_written_seq=last_synced_seq=3, checksum=NULL`. This was reported to the lead without modifying another owner's production code. The apparent race is upstream Close publication before recording seal/DB finalization. The canonical source still publishes Close in that order, and this single canonical run does **not** establish a fix; the gateway owner must confirm resolution and regression coverage. No retry loop hides the earlier failure.

Non-root Debian OpenSSH aborts PTY login-record writes. This fixture therefore uses genuine native **non-PTY RequestShell** (`ssh -T`), not Exec. It does not claim PTY/browser coverage; the lead's browser fixture is separate. Low-free-space-threshold and permission tests do not establish true disk-full or blocked-write behavior.

## Reproduce

Use the [recovery runner](../tests/release_recovery.py) and [phase helper](../tests/release_recovery_cases.py) with a new owned0700 fixture root:

```sh
BASTION_PG_BIN=/usr/lib/postgresql/17/bin \
  python3 tests/release_recovery.py --root /var/tmp/bastion-release-recovery-<new-uuid>

# Independent runtime faults only; cannot replace the full recovery suite.
BASTION_PG_BIN=/usr/lib/postgresql/17/bin \
  python3 tests/release_recovery.py --root /var/tmp/bastion-release-recovery-<another-uuid> --runtime-only
```

For canonical archive runs, supply the archive identity and both runner hashes in the private canonical manifest before starting, and set `CARGO_TARGET_DIR` to a fresh source-candidate target. Each phase is independently labelled and timestamped; protected subprocess logs are not copied into public documentation.
