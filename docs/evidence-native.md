# RFC-004 real native release evidence

Status: **in progress; no release pass claimed**. `production_ready=false` remains mandatory. This document distinguishes real ZeroTerm CLI operation from mock/unit tests and desktop manual acceptance.

## Scope and isolation

- Remote SSH administration uses `y189` only to execute the test workload as `bastion-acceptance` (UID 1000), not root.
- Native work root: `/var/tmp/bastion-release-native-3347a2f3-f703-41a3-ac5e-08c541b3fd62`, owner UID 1000, mode 0700.
- Do not reuse PostgreSQL 5432, system sshd 22, user vaults, old fixtures or a Cargo target directory shared by different source snapshots.
- Source-only adjacent ZeroTerm archive SHA-256: `70b66288214e286d6d70f9985023363a5e6a4c4dcf43b96159dcc2e9b64bba76`.
- Ordered source manifest SHA-256: `0bdfe92f17b3b3292449fb81c78958253c921020f56492297f3ff5d3fb03a9c9` (372 files; ZeroTerm HEAD `6cea6e2e57fd640760ec1fb17c1c788569603335` plus current approved client fixes).
- Native CLI build uses that single source snapshot and its own `native-target` directory.
- `cargo build --locked -p zeroterm-cli`, run as UID 1000 with `CARGO_PROFILE_DEV_DEBUG=0` / `CARGO_PROFILE_TEST_DEBUG=0`: **exit 0**, finished in 32m28s after initial crates.io timeouts. Build PID 607215 exited and was collected.
- Actual executable SHA-256: `8a72a71900af728f7bdaabc6b5df49bf7b924a2da859a81029e82ca1660756e3`.
- Actual executable `--version`: `zeroterm 0.1.11`; `--help` exposes real `bastion`, `exec`, and `sftp` entrypoints. This proves a real CLI build, **not** a gateway/session acceptance pass.
- Canonical gateway archive SHA-256: `bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9`, verified before non-root extraction to `source-candidate` under the unique work root. The earlier partial upload was never used.
- Strict HTTPS fixture launch PID 659947 uses a fresh independent `server-target` directory and the existing M3 fixture helpers; build exit 0 in 2m57s. Exact server binary SHA-256: `3040e427a732519ac39b0e660f3bea8f6942499659e03a1cffd6278564204010`.
- Fixture reached readiness after its existing real HTTPS/WSS automated smoke passed. It is shared with lead browser/desktop verification and remains held until the lead's stop file or its two-hour deadline. HTTPS is `https://localhost:52345`; advertised SSH gateway is `127.0.0.1:51569`; `server_id=m3-https-isolated`. Native trust uses the fixture CA PEM and pinned fingerprint `SHA256:kzhENmAr4BjktUHC1NQnv4yLgLNr0Bszh2BLvC2pqZ0`, never TLS/host-key bypass.

## Runner and fixture interface

[Fixture wrapper](<../tests/release_native_fixture.py>) reuses the canonical [M3 HTTPS fixture](<../tests/m3_https_smoke.py>) unchanged, with a short temporary child directory inside the isolated work root (PostgreSQL Unix socket length limit), protected native profile metadata and a maximum two-hour hold. `PYTHONPATH` must point at the canonical candidate tests directory; `CARGO_TARGET_DIR` must be inside this one isolated work/source root. Stop it through its own control-directory `stop` file so PostgreSQL, targets, gateway and TLS proxy are collected by the existing context managers.

```sh
export PYTHONPATH=/path/to/canonical-candidate/tests
export CARGO_TARGET_DIR=/var/tmp/bastion-release-native-<unique-id>/server-target
python3 tests/release_native_fixture.py --work-dir /var/tmp/bastion-release-native-<unique-id> --control-dir /var/tmp/bastion-release-native-<unique-id>/control
```

[Real CLI runner](<../tests/release_native_cli.py>) uses Python's stdlib PTY to answer actual ZeroTerm vault/profile/login selectors and controlling-terminal password prompts. It never injects a server-issued ticket into ordinary SSH auth. stdout is a separate pipe for byte-exact checks; stderr remains on a real PTY with output postprocessing disabled.

The protected fixture file must be owned by the non-root runner user, regular, non-symlink, mode 0600:

```json
{
  "api_url": "https://localhost:<isolated HTTPS port>",
  "username": "operator",
  "password": "<fixture-only secret, never printed or placed in argv>",
  "server_id": "m3-https-isolated",
  "gateway_host": "127.0.0.1",
  "gateway_port": 12345,
  "gateway_host_key_sha256": "SHA256:<verified gateway public-key fingerprint>",
  "ca_file": "<isolated private CA PEM path>",
  "fixture_root": "<isolated fixture directory>",
  "assets": [{
    "name": "M3 target A",
    "username": "bastion-acceptance",
    "asset_id": "<public authorized asset UUID>",
    "account_id": "<public authorized account UUID>"
  }]
}
```

`gateway_host_key_sha256` is computed from the verified `/info.gateway.public_key` or the gateway initialization public key, not from unauthenticated network key scanning. The first selector item must be authorized target A; failure to meet this prerequisite is not a pass.

Run with public paths only:

```sh
export BASTION_NATIVE_FIXTURE=/path/to/protected/native-fixture.json
export BASTION_NATIVE_WORKDIR=/var/tmp/bastion-release-native-<unique-id>
export ZEROTERM_CLI=/path/to/exact/native-target/debug/zeroterm
python3 tests/release_native_cli.py
```

The runner writes public results and a binary SHA-256 to `native-results.json` in the work root. Passwords are read into memory and sent only to hidden TTY prompts. Native profile files contain public metadata only. A password is never used as an argument, environment value, logged transcript, or API response field.

## Baseline real CLI checks (base ZIP, before native-close patch)

Confirmation run PID 688301 completed against the canonical shared fixture. Final runner SHA-256: `a05c4f35cfda0c093a664e9acee1b23866c39832ad80fc704a4d7b88c1983487`; public results are in the isolated work root's `native-results.json` (0600). This is real CLI/gateway/target execution, not a mock or ordinary OpenSSH substitute.

| Check | Actual result |
|---|---|
| Real public profile import, vault creation, login, authorized asset selection | **Passed** |
| Managed shell reaches target A (split input marker prevents an echo false positive) | **Passed**, `NATIVE-SHELL-A`, remote/process exit 7 |
| Exec stdout exactly `ff 00`; stderr preserves `80 00`; exit status 7 | **Passed**, byte-exact stdout and embedded binary stderr |
| Exec `cat` completes on client stdin EOF and drains output | **Passed**, stdout exactly `NATIVE-EOF`, exit 0 |
| Two separate Managed alias connections obtain fresh formal tickets | **Passed**, distinct public connection/ticket IDs cross-checked in isolated PostgreSQL |
| Real Managed SFTP 1 MiB upload/download SHA-256 and removal | **Passed**, SHA-256 `cc00c909236d104e3e9a3e26018bdb5917a7a4e7fbc4a475ec071a672ea392d4` |
| Managed CLI forwarding escape rejected before target command | **Passed**, exit 1 / `CHANNEL_PERMISSION_DENIED`; escape output absent |
| Valid but incorrect SSH fingerprint rejected at gateway host-key verification | **Passed**, exit 1 / `GATEWAY_HOST_KEY_CHANGED` |
| Omitted private CA rejects the real HTTPS certificate | **Passed**, exit 1 / sanitized `API_UNREACHABLE`; valid CA profile succeeded |
| Known passwords absent from CLI transcript, plaintext vault and fixture logs | **Passed** for tested passwords and logs; not a complete memory-forensics claim |
| Real Web Cookie login cannot issue formal native SSH ticket | **Passed**, HTTP 401, no ticket secret; login response contains no native tokens |

Ticket provenance (public IDs only):

- `907d7c4a-881d-4ae8-9359-ba5d3481347f` → ticket `c6f4ebc7-d17e-4f30-acdc-89f1f24775a4`, SSH exec closed, exit 7.
- `1a4f4a87-c629-405c-a9f8-b7679c8fdc92` → ticket `598da916-c2a4-4370-991f-e5b9c1028b39`, SSH exec closed, exit 0.
- Both match fixture target A asset `d76281cd-00b4-453d-b1e9-aa368b531e03` / account `e562cb49-f567-4146-babe-c1d83ec50864`.

Earlier unsuccessful attempts were runner defects, not ignored native failures: initial shell expectation was 0 despite sending `exit 7`; two launches omitted environment exports; PTY local echo was enabled; TLS expected a nonexistent error label; Cookie-only native ticket denial correctly returned 401 rather than the runner's initial 403 expectation. These were fixed in the runner only and all checks reran successfully. No native or server code was modified during this acceptance phase.

**Not tested by this CLI runner:** native logout-close, since the CLI exposes no logout command; in-process reconnect with an existing client handle; desktop Tauri UI. Reopening the actual CLI tests a fresh Managed connection, not an in-process reconnect.

## Native-close patched candidate: actual CLI / Complete / replay passed

**Independent patched-candidate result; not inherited from baseline.** Input identity is base ZIP SHA-256 `bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9` plus the three-file patch ZIP SHA-256 `a0a6659ddc5a6d83c6ad49e362c46056fa1002e8c2906566255ac75dc02ffc3c`. Worker D's immutable source directory was used read-only; all three input hashes were verified before and after build: protocol `06cdab…`, recording `b63143…`, regression test `0c3a92…`. Exact hashes are preserved in [candidate inputs](<../target/native-postfix-evidence/candidate-input.json>).

Worker F missed D's healthy window and did **not** start a CLI during D's fault phase. Per lead instruction, F created its own normal healthy fixture after D finished: `/var/tmp/bastion-native-postfix-66611e23-7e3b-4a0d-a2f8-4ed996ab4cc7`, UID 1000 / 0700; fresh `server-target`, offline cached dependencies, jobs 2, no mounts or injected faults. Build completed in 3m00s, exit 0; actual server SHA-256 `83a21f8a68b9557153c741106e61fecb1a8afe04d24dc727ac65a2f3f5e31ea0`. This separately identified build is not assumed byte-identical to D's build; exact source inputs were checked and no Cargo target was reused between roots. Actual client was reused without recompilation and rehashed as `8a72a71900af728f7bdaabc6b5df49bf7b924a2da859a81029e82ca1660756e3`.

Fixture PID 725812 reached readiness after its existing real HTTPS/WSS smoke passed. HTTPS was `https://localhost:49713`, advertised SSH `127.0.0.1:42983`, fixture child `f-30s40ywr`. Confirmation runner PID 734001 and the [recording proof](<../tests/release_native_recording.py>) both returned exit 0. The initial attempt PID 733726 reached a successful shell exit 7 but failed the newly added UUID parser because the vault-directory banner also contained a UUID; only the test parser was corrected to match the exact Managed identity line, then all checks reran. Final CLI runner SHA-256 `f0dbd8456d2aa4f53af07ba7839efcc3a7357d5c6ed94763a03832c4b14ee600`; proof SHA-256 `384d2ac69b4ca77064ef4692d7cf6997dedee8dd67bc07f10cdb27d3a361c0cb`. No native client or server source was modified by F.

| Patched-candidate actual check | Result |
|---|---|
| Managed profile/vault/login/authorized shell target A | **Passed**, remote/process exit 7 |
| Raw exec stdout `ff 00`, binary stderr `80 00`, exit 7 | **Passed** |
| Exec stdin EOF and output drain | **Passed** |
| Fresh native connections and formal ticket IDs | **Passed**, independent SQL cross-check |
| Managed SFTP 1 MiB put/get/hash/rm | **Passed**, SHA-256 `fdb5fb9403370f3822396b9d7e555f427f648904be77670fcb792142b051de91` |
| Forwarding escape, wrong SSH pin, omitted private CA | **Passed**, respective sanitized rejections |
| Password absence and Web Cookie native-ticket isolation | **Passed**, Cookie-only ticket request HTTP 401 |
| Actual shell recording Complete / synchronized checksum | **Passed**, read-only PostgreSQL metadata plus actual encrypted-file SHA-256 |
| Actual native shell authenticated replay | **Passed**, private-CA verified HTTPS, Cookie owner auth, ten contiguous events, meta → end, exit 7, actual target-A output marker |

Actual normal-close proof: shell connection `f7ca6536-1e5d-46b0-a742-dc8532543d61`, ticket `a83280e6-b6c2-4874-9390-ee05f73aaa4a`, channel `d731be0e-100a-4ed9-921d-7678855fcc9a`, recording `ef1532b9-ac6c-457d-ab09-ffe71e0dc76b`. Connection/channel are Closed, exit 7, no failure; recording is **Complete**, ended, written/synced sequence both 9. Actual encrypted-file SHA-256 matches metadata: `cb0cb253f714f833347d7613347d46f13043643a54ed67b92b3694626c88d090`. Replay is ten events, sequence 0–9, first meta / final end, exit 7 and `NATIVE-SHELL-A`; known fixture password is absent. Replay NDJSON SHA-256 `6a83acdbe5d4dbfa6621e20a8ee9ff3afca07928a68744141720b16a2660cae9`. Replay checks reuse the existing [M3 event assertions](<../tests/m3_web_smoke.mjs#L120-L131>) against this actual native recording ID, not a newly created Web shell.

Fresh exec connections use distinct formal tickets: `feb51d8b-1d3d-4e2e-81a7-8a1c04e23e6f` → `9cf882b1-1b3a-43c9-a0eb-35d916bd38b0`; `b03168a4-c56f-4fe6-96d0-b89349dc0dd3` → `150c0e48-a92c-44a1-b4ae-30e45b4762e3`. Both are Closed / SSH and match the actual authorized target-A asset/account.

Public evidence: [machine-readable results](<../target/native-postfix-evidence/native-results.json>), [safe native log](<../target/native-postfix-evidence/native-confirm.log>), [build/fixture log](<../target/native-postfix-evidence/fixture.log>) and [cleanup proof](<../target/native-postfix-evidence/cleanup-evidence.json>). Results were stored 0600 remotely; no password, token, ticket secret, DEK or nonce was downloaded into public evidence.

Own stop flag was written only after runner/proof/replay results were collected. Context cleanup exited 0; PostgreSQL PID 733539 and all 17 captured owned service PIDs are absent, fixture child directory was removed, protected duplicate credential JSON was deleted. The original shared fixture 659947 and existing user desktop/vault/profile sessions were not stopped or modified by F.

**Remaining boundaries:** native CLI logout-close (no CLI command), in-process reconnect, desktop manual acceptance, future C HTTP file-stream pipeline, and D's separate fault closure deadline evidence are **not** passed by this healthy native rerun. In particular, D's reported 5.005s against its extra strict five-second gate remains a failure; healthy Complete/replay does not erase it. `production_ready=false`.

## New manual frontend29 namespace (held for lead/user)

The original shared fixture later reached its two-hour deadline and exited 0, as verified by lead; it was not extended. The completed F post-fix CLI fixture above was already stopped after its proof. Neither historical endpoint is a live manual URL.

Lead approved a separate manual namespace: `/var/tmp/bastion-manual29-fe0f7d91-1315-40ef-a106-a45c3f4121a5`, owner UID 1000 / 0700, fresh own extracted source and Cargo target. Inputs are canonical base `bd7248…`, exact native-close three-file overlay `a0a665…` and frontend29 static ZIP SHA-256 `6c2773c2ae8f96a525a9810dbad17347e0b28a5492f52884edc64b8393f1758b`. Only this owned source's static web output was replaced; Worker D's source and Worker C's work-in-progress pipeline were not changed. All remaining base source files were byte-compared with the archive, normalizing ZIP `./` prefixes.

[Manual certificate-reuse wrapper](<../tests/release_browser_fixture.py>) SHA-256 `0bdaba6e7b81dbcb46fce7ba05f135e7c62d5fdfb19712b5e82f2f06b2b95c3f` copies no CA signing key and uses the existing user's approved test CA/leaf/server key, copied to private owned 0600 files before startup. It verifies the explicitly approved CA SHA-256 `7866161f440f4533436dc94f5cfe86bfa182915a1d817c303119028b2f47e7a4`, OpenSSL chain / `sslserver` purpose / hostname / validity, and stdlib SSL certificate-key matching. Wrong approved digest is a tested negative guard. CA SHA-1 fingerprint is `5DA4FB569635161F203BEEB972DA5D046D111B49`; CA and leaf validity span October 4–8, 2026 and leaf SAN covers localhost / 127.0.0.1. No TLS bypass, extra proxy, Origin rewriting or live TLS mutation is used.

Fresh build: jobs 1 / offline cached dependencies / debug 0, 5m36s, exit 0, actual server SHA-256 `83a21f8a68b9557153c741106e61fecb1a8afe04d24dc727ac65a2f3f5e31ea0`. Existing real HTTPS/WSS automated smoke passed; this still does not certify the browser UI.

Manual wrapper PID **745456** reached readiness and is intentionally held until lead's stop file or the existing maximum two-hour readiness deadline. Public origin is exactly **https://localhost:55921**; default remote TLS proxy **55921**, private plain API **53883**, optional native SSH gateway **54887**. Lead's browser tunnel must use local **55921 → remote 55921**, preserving the exact Origin/Host; native SSH tunneling is unnecessary for browser-only testing. The frontend serves at the origin root, not `/ui`.

Strict verified HTTPS fetched the actual served files with status 200 and matched the approved bundle bytes:

- index SHA-256 `9b16a0557f2c053971b005c8145af95ede82f2f3fd1221427cbee09129ae94af`;
- JavaScript SHA-256 `44bc48ad0be252780157b22a68022916b3924f1ba3e8ddadab1f117309973d6e`;
- CSS SHA-256 `6b8756dcbfb139fb412cf798b7844cf1f443e06bb59c151b1730afcab4a197b7`.

Username/password-only manual handoff is stored in the new control directory, 0600 / UID 1000, for lead's protected download/Windows ACL/Notepad path. Values were never printed or included in public evidence. F will **not** stop this manual fixture after automated checks; lead/user frontend29 replay/upload verification remains pending and no new performance or future C-pipeline pass is claimed. `production_ready=false`.

## Real desktop manual procedure (lead/user)

Do not touch existing user sessions, passwords or profiles. Use an explicitly approved temporary Bastion profile in the actual ZeroTerm desktop. A Chromium browser bridge is not a Tauri WebView and must never be used to claim a desktop pass.

1. Arrange loopback tunnels for HTTPS **and** gateway SSH using the fixture's same advertised local port numbers. Profile SSH host/port must match the advertisement exactly.
2. Add one temporary profile with `name`, `api_url`, `server_id`, `ssh_host`, `ssh_port`, `ssh_host_key_sha256`, `ca_pem`. `ca_pem` is the isolated CA's PEM text; no system trust-store modification is required for native ZeroTerm.
3. Read the fixture-only password through an approved protected channel, enter it in the actual desktop login form, and confirm the password field clears immediately. The existing Tauri command accepts this one transient input only and returns no token, ticket or password.
4. Select target A and verify UI target/account, capabilities, public connection ID and connected/disconnected status. Execute a shell marker based on `BASTION_TARGET_ID`; open the Files/SFTP pane and compare an uploaded/downloaded file hash.
5. Disconnect/reconnect and verify a new public connection ID. Log out that temporary profile while its shell/SFTP is active and confirm closure. This is required before claiming native logout-close.
6. In separate temporary profiles, verify incorrect SSH pin and missing private CA fail closed; never select an insecure TLS or host-key bypass.
7. Remove only temporary profiles, fixture files and test sessions. Record actual outcomes and screenshots with secrets redacted. Do not call a static IPC inspection or backend mock a desktop test.

F performed no Tauri UI automation or desktop observation in this phase. Lead/user manual desktop outcomes belong to their separate acceptance records and must not be inferred from F's CLI or fixture checks.
