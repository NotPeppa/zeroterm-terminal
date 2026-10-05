# Dedicated recording-filesystem fault evidence

## Result

The corrected post-fix fault fixture completed on **2026-10-05 at18:45:54 UTC**, with **exit1** preserved: the measured strict marker-send→SSH-client-close latency was **5.005028s**, exceeding the test's5s end-to-end threshold. It was not rounded down or retried into a pass.

The safety assertions passed: a genuinely full dedicated filesystem rejected unrecorded output, genuinely frozen recording writes forwarded no marker, and both faulted recordings finalized **Partial / RECORDING_UNAVAILABLE**, never Complete. Watchdog thaw, owned unmount/detach/image removal and process cleanup all succeeded. `production_ready=false`; this is not an all-release acceptance pass.

Evidence: [fault phases and timestamps](../tests/release_recording_faults-evidence.json), [management/identity/thaw/cleanup](../tests/release_recording_faults-management.json), [exact source/binary/runner identities](../tests/release_recording_faults-input.json).

## Approved post-fix input

| Input | SHA256 |
|---|---|
| Canonical base ZIP | `bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9` |
| Approved exact three-file overlay ZIP | `a0a6659ddc5a6d83c6ad49e362c46056fa1002e8c2906566255ac75dc02ffc3c` |
| [Native protocol](../crates/bastion-gateway/src/protocol.rs) overlay | `06cdab09562a9cda9c12a71c9faf04410a00d9811e77fc8807cfe59de31c58f1` |
| [Recording actor](../crates/bastion-gateway/src/protocol/recording.rs) overlay | `b631437000a8d857ad96d6d6197a315211b468345039ba6758f6c10b4e932110` |
| [Native-close regression](../crates/bastion-gateway/src/protocol/native_close_tests.rs) overlay | `0c3a92e16f4936c4f46f638be118080ee43bfeebd69c1d4a62d5b5655a1c0259` |
| Server binary | `afb0f6a466f6895ecbed724527092d6ad92b9e346b1917bb555ba958337f4bb6` |
| [UID1000 driver](../tests/release_recording_faults.py) | `70e9d4e0378266dade88d552205a0ec804c0c4587ea4208f1db797d997ef4ab0` |
| [Root management helper](../tests/release_recording_faults_root.py) | `ce3d82b59d4223825a4ea0712d7daeabd675a2494d77218043731e3d2cef616d` |

The base and overlay archives were SHA-verified and safely unpacked once into each new source root as UID1000. Only the three authorized production/test source overlays were applied before compiling. The first source used a fresh target and independent Cargo cache; `cargo build --locked -p bastion-server` succeeded as UID1000 in2m18s. The corrected second fixture reused a SHA-verified copy of that same-source binary rather than claiming another fresh compilation. Both source overlays and runner/binary hashes remained unchanged after the test.

```text
first fixture: /var/tmp/bastion-record-fault-39c2601ca87e47f79a6b50fd325f6ccf
corrected fixture: /var/tmp/bastion-record-fault-9a01823b4e92432c91dad21d7a7dcb82
corrected source: <corrected fixture>/source-candidate
dedicated image: <corrected fixture>/control/recording512.img
exact mountpoint: <corrected fixture>/recording-mount
loop device during test: /dev/loop0
root management wrapper/supervisor PIDs: 724469 / 724470
UID1000 driver PID: 724481
UID1000 gateway PID: 724533
independent root thaw watchdog PID: 724990
```

## Actual assertions

| Phase | Actual result |
|---|---|
| Repeated normal close | Two separate fixtures each passed20/20 native non-PTY RequestShell closures: client exit7; metadata already Complete immediately after client exit; stored checksum matched encrypted-file SHA256; written/synced sequence equal; authenticated contiguous replay with clean final EOF and recorded exit7. These40 successful samples are not a whole-suite pass claim. |
| Production startup floor | Dedicated image536,870,912bytes; ext4 initially499,982,336bytes free, above the unchanged256MiB production minimum. Directory UID1000/mode0700; required recording available, production_ready=false. |
| True full filesystem | Non-root posix_fallocate filled only the dedicated mounted image:499,892,224bytes allocated, final4KiB attempt returned actual ENOSPC28, free0bytes. Next marker was not forwarded; SSH closed in0.003060s; recording Partial with RECORDING_UNAVAILABLE. |
| Real blocked writes | New recording Active/channel Streaming with499,892,224bytes free; verified fsfreeze succeeded only on the owned loop mount. The owned gateway thread724965 was observed in kernel `percpu_rwsem_wait`. |
| Write ACK/client close | Marker was not forwarded. External marker-send→client-close **5.005028s**, so strict external≤5s check **failed**. Configured in-process ACK budget remains5s; no network/scheduling delay was subtracted. |
| Bounded independent thaw | Root watchdog was ready before freeze; scheduled thaw at7.5s leaves verification margin inside8s. Actual armed→successful thaw7.606783s, return0. |
| Metadata after thaw | Partial / RECORDING_UNAVAILABLE, never Complete; settled within the20s post-thaw bound. |
| Shutdown | Gateway stopped gracefully in0.021s, no deadline-triggered SIGKILL; tracked children0 and PG PID files0. |
| Filesystem cleanup | Verified exact owned mount unmounted; same loop/backing-image association checked before detach; bounded512MiB image removed only after identity checks; watchdog/driver/supervisor absent. No forced unmount or unrelated process kill. |

The true-full result is **real full filesystem plus the legitimate production free-space gate**. It does **not** claim that the recorder append itself reached its ENOSPC error branch: the gate may reject before append. Frozen-write coverage is real kernel filesystem freeze, not a production feature flag, mock or injected runtime bypass.

The5.005028s external metric includes target/gateway/SSH transport and process observation. It is an additional stricter test assertion, not the same boundary as the RFC's5second recording-write wait/timeout requirement. [Sanitized existing-log timing evidence](../tests/release_recording_faults-timing.json) records the real actor warning `recording IO exceeded ACK deadline` at2026-10-05T18:45:52.066955Z. No IO-start or client-close-initiation timestamp was available, so exact initiation timing cannot be reconstructed or retroactively declared passed. The configured ACK budget remains5s; no production timeout was shortened to fit transport overhead. The stricter observed end-to-end failure and fixture exit1 remain explicit; they do not by themselves establish an RFC initiation-deadline violation.

## Preserved initial fixture error and native CLI scope

[First-attempt phase evidence](../tests/release_recording_faults-evidence-first.json) preserves20 healthy immediate Complete/checksum/replay passes and a **fixture-only** assertion error before any fill/freeze: it incorrectly compared RecordingState to Streaming. Actual states are RecordingState::Active and ChannelState::Streaming. [First-attempt management evidence](../tests/release_recording_faults-management-first.json) preserves owned-loop cleanup and no freeze request. That run was not relabelled successful; the correction ran under a new fixture root.

The corrected fixture offered a protected UID1000/mode0600 native-CLI handoff and waited150s before any fault. No continuation was received; the actual unchanged ZeroTerm CLI test was **NOT TESTED** in this fixture. The lead explicitly declined starting a90s CLI run late, so no CLI/fault overlap occurred. The40 native RequestShell checks above must not be represented as that independent actual-client test.

Non-root Debian OpenSSH PTY login-record limitations remain outside this non-PTY fixture. Browser/PTY acceptance and the unchanged native-client application are separately owned tests.

## Isolation and post-run verification

Root performed only dedicated image/mount/freeze/thaw management. Gateway, PG, target SSH daemons, TLS proxy and native peers ran as UID1000. Mount flags were nodev/nosuid/noexec; no other mount or main filesystem was frozen/filled, no host PostgreSQL5432 or sshd22 settings changed, and no other process was killed. The main filesystem held one bounded preallocated512MiB backing file, later removed.

Post-run read-only checks confirmed unchanged source/binary/runner hashes, absent own process PIDs/PG PID files, no exact mount or own loop association, and removed image. A non-printing scan of10 private fixture logs against10 protected fixture files plus the known generated password found no matches. All checked private files were owner UID1000/mode0600. Protected logs and credential files are not copied into public artifacts.

All duration measurements use the remote monotonic clock. Evidence timestamps are remote UTC; desktop/local timestamps may be UTC+8 and must not be compared as raw wall times.
