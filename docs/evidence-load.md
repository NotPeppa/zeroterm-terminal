# Release-load evidence — canonical hour completed; matched HTTP performance failed

## Canonical run status (original frozen source hour completed)

The exact canonical source archive SHA256 is `bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9`. It was extracted once into the new owned `source-candidate` directory, never overlaid on the historical build. Default-feature `cargo build --release --locked --offline` used a fresh `source-candidate/target`; binary SHA256 is `7adf52e700576d7973e23d6fb37ab57bb97206ac971dae0af1caf0d64ec4627d`.

The repaired large-body adapter uses native Node HTTPS32KiB stream backpressure and incremental GET hashing; small JSON controls still use fetch. A separate four-file64MiB preflight passed SHA256, recording and cleanup checks before the full run. Preflight adapter RSS peaked180.8MB, not the historical4.48GB.

The canonical50-base-shell +20-terminal hour began **2026-10-05T17:36:42.532Z** and held for **3625.161s**; client completion was18:37:15.112Z. Runner689868/gateway689927/client690084 and all owned listeners have exited.70 recordings are Complete and10 intentional revocation-probe recordings are Partial; final active connections/channels/recordings are all zero. All70 complete ciphertext SHA256, size and written/synced checkpoints matched persisted snapshot metadata;80 files are0600/UID1000, directory0700, no symlinks, valid `ZTREC001` headers. The stopped private database was briefly restarted on dynamic loopback59231 for read-only integrity checks and stopped in `finally`; PostgreSQL5432 was untouched.

Final echo n7560: P50=8.729ms, P95=16.099ms, max=179.742ms; target pulse n7635:44.137/49.805/523.136ms. Late revocation n5:21.187/23.900/23.900ms.731 resource samples: gateway RSS peak46.54MB, CPUmean10.33%/P95sample13.59%/max87.85%, FDpeak255 and32 before shutdown; original hour client RSS peak231.71MB and200.43MB before exit, FDpeak103→21; host available RAM minimum4.410GB, disk free minimum55.52GB. Target listener metrics still exclude SSH children; no total-process-tree claim is made. Additional matched benchmark CPU jitter is retained, not removed from the pulse maximum.

[Canonical raw result](<tests/release_load_evidence/canonical-c1/result.json>), [resource summary](<tests/release_load_evidence/canonical-c1/resource-summary.json>), [reclamation](<tests/release_load_evidence/canonical-c1/reclamation.json>), [recording integrity](<tests/release_load_evidence/canonical-c1/recording-integrity.json>), [matched throughput](<tests/release_load_evidence/canonical-c1/matched-throughput-ratios4.json>), [environment](<tests/release_load_evidence/canonical-c1/benchmark-environment.json>) and [component hashes](<tests/release_load_evidence/canonical-c1/component-hashes.json>) preserve independent evidence. This hour covers its frozen source, **not the later native-close or proposed file-pipeline patches**.

All four1GiB PUT/GET pairs completed with matching SHA256 during70 active required-recording shells. The earlier four-flow sum-of-per-file means divided by a single direct flow was **not a matched-concurrency release gate**;70.714% /90.146% remains diagnostic only, and the earlier narrow-PASS interpretation is withdrawn. A supplemental matched four-pair test used the same four1GiB source files, target/account, strict pin,32KiB chunks and active70-shell environment. Each direction is now total4GiB divided by first-start to last-finish wallclock: direct upload331.99MB/s in12.937s /download308.70MB/s in13.913s; HTTP file facade upload148.05MB/s in29.011s /download161.32MB/s in26.623s. **44.593% upload /52.258% download: FAIL70%, a genuine release blocker.** All source/remote/download SHA256 values matched. Supplement client RSS peak217.7MB and gateway44.5MB show this remaining deficit is not the historical4GiB adapter retention. The facade serializes one32KiB request/ACK at a time per SFTP session; default OpenSSH direct clients pipeline requests. That is a measured-scope/root-cause lead, not permission to reduce the direct denominator to `-R1` or change production code. **This result measures the Web HTTP file facade, not native SSH-gateway raw-SFTP byte-bridge performance**; no native throughput PASS is inferred. Compiler profile and adapter changed together between historical/canonical runs, so their improvement is not attributed solely to the client.

Actual fixture host:4 logical/affinity CPUs (Intel Xeon Skylake),8,333,946,880bytes RAM, OpenSSH10.0p2 Debian-7+deb13u4/OpenSSL3.5.7, Linux6.12.107+deb13-cloud-amd64. All legs are loopback, not an external8-vCPU/WAN baseline.20 loopback ICMP samples had P50=0.039ms, P95=0.064ms, max=0.116ms; application echo is measured separately and is not claimed to be precisely decomposed by subtracting unpaired ICMP samples. Shared-host CPU/load is captured, but is not used to excuse the matched failure.

The lead’s subsequent native SSH `ShellRecordingClose` fix is **not exercised by this Web-only hour**. No new hour or production overlay was started; post-fix native-close proof and component hash comparison are separate coordinated gates.

Five canonical under-load device probes completed with P50=24.194ms, P95/max=31.128ms; afterward the private DB still showed70 active connections/70 streaming shells/70 active recordings and five partial probe recordings. The full hour and cleanup are now complete, but **matched HTTP throughput failed**. `/info.production_ready=false` and later source-fix validation remain further gates.

## Archived noncanonical hour (retain failure and identity)

The section below is the original historical measurement, **not canonical-source evidence**. Its preserved source-tree SHA256 is `1fe3966a16c43db90985afd53f0dae35ff22b30bf23eb196eaa0981d694254ad` (sorted path/hash pairs for142 crates/vendor/Cargo.toml/Cargo.lock files); no original archive hash was available for that clone. [Historical source identity](<tests/release_load_evidence/20261005-c4d72f/historical-source-identity.json>) records the method and binary identity; original raw filenames and results remain unchanged.

**Historical verdict:** the requested real one-hour stability/required-recording workload completed. All four1GiB upload/download pairs matched SHA256; observed device revocation and cleanup passed. **Do not approve release from this result:** proxy throughput was only27.53% upload /29.97% download of the direct baseline, below70%, and the load adapter retained excessive memory. `/info.production_ready` remained `false`.

## Scope and candidate

- Only the owned y189 fixture `/var/tmp/bastion-release-load-20261005-c4d72f`, non-root `bastion-acceptance` UID1000,0700, was used. All candidate/target/DB/TLS listeners were dynamically selected loopback ports. Main PostgreSQL5432 and SSH22 were not used or modified.
- The source was an isolated copy of the verified candidate. Recording/API/server-control SHA256 values matched the working checkout. The first build used a fresh independent target directory; an isolated copy of the existing offline Cargo cache avoided another job’s package-cache lock. Only this worker’s obsolete waiting build was stopped.
- Profile: **Cargo dev, unoptimized + debuginfo**, with the real production assembly and required recording enabled. This is **not an optimized release-profile benchmark**.
- Binary SHA256: `00f76a8569ebca55d16d5968faf020a311b8fd74a0f65ce9b7f5b90d6ef6fb48`.
- Gateway limits were not raised:100 global connections,10/user,20 pending,16 channels/connection,64/user,256KiB queue,600s idle,30s stall,1GiB HTTP file limit. The supported eight-hour absolute limit was used instead of the smoke fixture’s one-hour absolute cutoff, so connection creation skew could not truncate a full-hour hold.
- Five base users held ten connections each. Two additional users held ten mixed terminals each; a separate user owned the four file connections. Probe users were independent. Required recording was never disabled; real target output included the target’s configured identity. Pulses were issued no faster than once per30s steady-state cycle, not mere WebSocket keepalives.
- TLS trusted the isolated CA and verified hostname. Target SSH keys were approved/pinned; direct SFTP used strict known-host verification and a fake private-key **file path**, never key material/password in argv. Secrets stayed in memory or0600 files under the0700 fixture. No credential/header/environment dump is included in the public evidence.

## Completed workload

| Gate | Observed result |
|---|---|
|50 active required-recording base shells for>=1h | **Passed:**50 base +20 additional terminals, hold started2026-10-05T14:54:23.680Z and lasted**3613.077s** |
| Real target business activity |7,565 acknowledged target-pulse samples; real target identity marker, with required output recording ACKs |
| Four concurrent>=1GiB PUT/GET pairs +20 terminals | **Passed integrity:** each file was1,073,741,824bytes; every incremental SHA256 matched; all70 terminals remained active during transfers |
| Recording finalization | **70 Complete**,10 Partial intentional revocation-probe recordings; all70 complete ciphertext SHA256, file size, and written/synced sequence checkpoints matched persisted metadata |
| Recording storage protection |80 files, all0600, directory0700, no recording symlinks, all `ZTREC001` headers |
| Device revocation under load |Five independent probes during70 active shells; all closed within3s; active hold remained70 connections/70 streaming shells/70 active recordings afterward |
| Final DB resource reclamation |Zero active connections, channels, or preparing/active recordings |
| Fixture shutdown |Main runner/client/gateway/TLS/target PIDs gone; all seven owned listeners closed; no process command line retained the fixture path |
| Proxy>=70% direct throughput | **Failed:**27.53% upload /29.97% download |

Client completion was2026-10-05T15:54:56.739Z; the fixture then stopped its owned PostgreSQL, SSH, gateway, and TLS processes. A separate15.78s preflight was preserved remotely and **was not substituted for the hour**.

## Latency

Values below use **empirical nearest-rank** percentiles, index `ceil(n*p)-1`, recomputed from retained raw samples. The original full-run output used lower-order rounding; it remains unchanged for provenance. The current helper/self-check now uses nearest rank. Five revocation samples are not a statistically strong tail-confidence study.

| Measurement | Samples | P50 | P95 | Maximum |
|---|---:|---:|---:|---:|
| Single-byte target PTY keystroke echo, with recording ACK |7,490 |10.800ms |15.950ms |163.870ms |
| Actual target pulse round trip |7,565 |45.803ms |50.609ms |127.856ms |
| Device revocation during70-shell hold |5 |29.332ms |38.787ms |38.787ms |
| Device revocation after hold |5 |26.184ms |28.470ms |28.470ms |

## Throughput — blocking performance result

The strict pinned direct OpenSSH SFTP baseline transferred a1GiB random file in4.691s upload and5.139s download; its downloaded SHA256 matched the source. No shell-command copy, third-party target, or fabricated key was used.

| Comparison | Upload | Download |
|---|---:|---:|
| Direct single-file baseline |228.90MB/s |208.94MB/s |
| Each proxy file duration |68.07–68.25s |68.30–69.09s |
| Sum of four per-file mean proxy rates |63.02MB/s |62.61MB/s |
| Proxy aggregate /direct single-file baseline |**27.53%** |**29.97%** |

MB/s is decimal. This aggregate-of-four-versus-single-direct comparison is explicitly stated, not a matched four-flow direct baseline. It already misses70%; do not label it PASS. An optimized release-profile, matched-concurrency retest and throughput investigation are further gates, not conclusions inferred from this unoptimized run. No production code was modified by this load worker.

## Resource evidence

736 five-second samples captured the gateway, client, TLS proxy, and target listener PIDs plus host available memory/load and free disk. CPU is per-process,100%=one CPU core; target listener statistics do **not** sum SSH children or PostgreSQL workers.

| Measurement | Initial /peak /last before shutdown |
|---|---|
| Gateway RSS |32.59MiB /110.85MiB /38.06MiB |
| Gateway FDs |15 /254 /26; all process FDs disappeared on exit |
| Gateway CPU |Mean32.19%, P95 sample63.74%, max196.57% |
| Node24 adapter RSS |78.42MiB /**4.1726GiB** /4.1342GiB |
| Adapter FDs |22 /103 /21 before client exit |
| TLS proxy peak RSS /FDs |57.40MiB /163 |
| Host available memory minimum |1.0878GiB |
| Disk free minimum /last |63.97GiB /72.08GiB |
| Final recording files /ciphertext size |80 /7,692,806bytes |

The client used32KiB `createReadStream` upload chunks and incremental GET hashing, with no whole-file `arrayBuffer`; nevertheless its measured memory retention is an **adapter concern**, not evidence of a gateway leak or proof of constant-memory operation. Gateway RSS did not track the4GiB payload size. Shared-host load and disk activity are included in telemetry; no total process-tree CPU/RAM claim is made. The persistent gateway had26FDs after the workload rather than its initial15; cleanup was verified by zero active DB resources followed by actual process/listener shutdown, not by falsely claiming identical pre/post live-process FD counts.

## Evidence and reproduction

Primary local artifacts, containing no fixture passwords/cookies/private keys:

- [Raw run result and samples](<tests/release_load_evidence/20261005-c4d72f/result.json>)
- [Nearest-rank latency statistics](<tests/release_load_evidence/20261005-c4d72f/statistics.json>)
- [Resource summary and listener/PID shutdown](<tests/release_load_evidence/20261005-c4d72f/resource-summary.json>) and [raw five-second telemetry](<tests/release_load_evidence/20261005-c4d72f/resources.jsonl>)
- [Final DB reclamation](<tests/release_load_evidence/20261005-c4d72f/reclamation.json>) and [recording integrity](<tests/release_load_evidence/20261005-c4d72f/recording-integrity.json>)
- [Protected recording-file checks](<tests/release_load_evidence/20261005-c4d72f/recording-file-checks.json>)
- [Under-load revocation samples](<tests/release_load_evidence/20261005-c4d72f/revoke-under-load.json>), [direct baseline](<tests/release_load_evidence/20261005-c4d72f/direct-baseline.json>), and [terminal status](<tests/release_load_evidence/20261005-c4d72f/status.json>)

The remote private fixture/evidence remains under the owned0700 load root for authorized inspection; no owned background listener/job is still running. Its database was briefly restarted on a new dynamic loopback port56849 for **read-only** post-run checksum/size/checkpoint verification, then stopped in `finally`; no gateway was restarted and main PostgreSQL5432 was untouched.

[Python runner](<tests/release_load.py>), [streaming client](<tests/release_load.mjs>), [under-load revoke probe](<tests/release_load_revoke.mjs>), and [stdlib helper check](<tests/release_load_test.py>) are the only new executable sources. Existing smoke scripts were imported/read but not edited.

```sh
# Current canonical runner (historical measurements above remain immutable).
export PATH="$HOME/.cargo/bin:$HOME/tools/node-v24.18.0-linux-x64/bin:$PATH"
export BASTION_PG_BIN=/usr/lib/postgresql/17/bin
export PYTHONPATH="$LOAD_ROOT/source-candidate/tests"
export CARGO_HOME="$LOAD_ROOT/cargo-home"
export CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2
python3 tests/release_load.py --source "$LOAD_ROOT/source-candidate" --root "$LOAD_ROOT/c1" --release --seconds 3600 --source-archive /var/tmp/bastion-acceptance-20261005-a6f8d2/release-candidate.zip
# --preflight now uses3 shells/four64MiB files; never substitute it for the hour.
```

Remaining gates/limitations: `production_ready=false`; failed throughput target; adapter memory retention; small revocation sample count and untested ten-connection same-login revoke fan-out; no total-process-tree resource accounting; ordinary SFTPv3 safe cross-host copy remains disabled; remote temporary-file cleanup after transport loss is best-effort; Windows production-recording readiness remains unsupported. These are not hidden by the successful hour/stability/integrity checks.
