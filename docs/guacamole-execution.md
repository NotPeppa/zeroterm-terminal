# RFC-005 execution evidence

Release status: **`production_ready=false`**. This file records executed checks, not a support promise.
The patched engine is a ZeroTerm candidate derived from official tags, not stock guacd behavior.

## Current workspace deployed to the live service, 2026-10-14 UTC

The user asked to put every current workspace change on the test service. The whole tree was packaged
(218 files, evidence directories excluded), [built](../tests/evidence_deploy20261014b_build.json) to
`sha256:b58fba01…` and switched in place under the existing project `zeroterm-test-guac-v2`. The build was
a 1-second cache hit whose image ID equals the previous deploy's, because the Dockerfile did not change in
between; the binary inside carries `ensure-admin` and the frontend bundle was built from the finished web
sources, so the reused layers are the current code rather than a stale tag.

This was the first live switch to the one-shot chain from the base `compose.yaml` (the previous deploy used
an older compose plus an override). `./compose.sh up -d --wait bastion guacd` ran `init`, `migrate`,
`grant-runtime` and `bootstrap-admin` in order, each exiting 0 before bastion started, and reported
`Secrets already initialized; nothing to do.`, `Database migrations applied and server identity verified`,
`Docker runtime role and grants refreshed.` and `An administrator already exists; nothing to do (admin
password settings are ignored).` respectively. Before touching containers a `pg_dump` was taken to
`predeploy-20261014-1715/bastion.dump`, the old source tree was kept at `source-backup-20261014-1715`, and
the previous `override.json` at `override.json.pre-20261014-1720`. Migration versions stayed 1–6 and users,
assets, accounts, groups and recordings were unchanged. PostgreSQL and guacd were recreated by the new
`init` dependency (new `StartedAt`) with their volumes and all rows intact; the five legacy containers were
untouched.

The new compose mounts its config files as `./.local/docker/...` relative to its own directory, so the
compose-relative paths were symlinked to the project-root files the live deployment keeps there, and
`override.json` carries over what the base file does not know about this host: the proxy's TLS bind and
limits, and bastion's `targets` network plus resource caps. That `targets` entry was missed on the first
attempt and had to be restored — without it the app cannot reach the legacy target containers.

[Verification](../tests/evidence_deploy20261014b_verify.json) covers live HTTPS `ok`, `/info` reporting
`schema_version` 2, `production_ready=false` and the new `password_min_length` 12, admin login, the RDP
rules (`rdp` asset accepted with a null pin, `409 TARGET_HOST_KEY_UNKNOWN` before confirmation, PATCH
confirming pin and security, soft delete removing it from the catalog), and the live minimum length (a
10-byte password is refused with `400 INVALID_ARGUMENT`, a 12-byte one is accepted). A real SSH session was
then driven through the deployed service to the demo target
([evidence](../tests/evidence_deploy20261014b_live_ssh.json)): ticket issued for `bastion.ssh.v1`, WebSocket
upgrade `101`, size frame accepted, readiness frame received, live shell output, an exact marker echoed by
the target, and an `active` recording while the session ran. The two SSH assets in the live catalog
(`Jakarta`, `7刀`) point at hosts that no longer answer, so the gateway correctly reported
`TARGET_UNREACHABLE` for them; the end-to-end session used a temporary asset for the reachable demo target,
which was soft-deleted afterwards with the live catalog left at `Jakarta`, `7刀` and `oracle`. The client
bugs found while writing that check were all in the check itself, not the product: a cookie jar that
appended instead of replacing (the server correctly fails closed on duplicate cookie names), and a size
frame that never wrote its type byte. `production_ready=false`.

## Unattended first administrator, 2026-10-14 UTC

At the user's request a fourth one-shot, `bootstrap-admin`, runs the new `ensure-admin` command with the
runtime role after `grant-runtime`; bastion waits for it. It creates the first administrator only when no
administrator exists (including deleted ones), so later runs never reset a password. The password comes
from `BASTION_ADMIN_PASSWORD` or `BASTION_ADMIN_PASSWORD_FILE` (plain read: Docker secrets are 0444
root-owned); an empty variable counts as unset; with neither set a 43-character random password is generated
and printed once. A password that is set but invalid fails instead of falling back. Image app2
`sha256:bf132fef…` in a throwaway project ([output](../tests/evidence_deploy20261014_bootstrap_admin.txt)):
generated password logs in (200; wrong 401) and a second run reports nothing to do; an env password set
after bootstrap is ignored (old 200, new 401); a configured password logs in and never appears in the log;
a 5-byte password stops `bootstrap-admin` with exit 1 and bastion never starts. Known limits, documented in
the README: environment values stay visible in `docker inspect`, and a generated password stays in that
container's log until it is removed, so the first login should change it. Not deployed.

## One-shot init, migration and runtime grants in Compose, 2026-10-14 UTC

At the user's request `docker compose up bastion` now performs the whole setup: one-shot `init`
(fresh secrets; skips when initialized, refuses a partial state), `migrate` (owner connection) and
`grant-runtime` (postgres image, as the secret files' UID 10001, pgpass on a private tmpfs) must each exit 0
before bastion starts. The app keeps only the runtime role. An isolated throwaway project on the test host
with shifted subnets ([output](../tests/evidence_deploy20261014_compose_oneshot.txt)) showed: a fresh `up`
completes all three and bastion is healthy; `create-admin` through `maintenance` works; a second `up`
reports init has nothing to do; the runtime role is refused `CREATE TABLE` (`permission denied for schema
public`) and `DELETE FROM audit_events`; HTTPS health returns `ok`; with one secret volume emptied, init
refuses (`Existing secrets found; refusing to overwrite or convert.`) and the KEK remains. Two failed
attempts are noted: the first ran grant-runtime as root with all capabilities dropped and could not read
the 0600 files; the second used `run bastion create-admin`, which collides with a running bastion's fixed
IPs. Not yet applied to the live test service. `production_ready=false`.

## Deployment of the RDP confirmation build, 2026-10-14 UTC

At the user's request the whole workspace was [built](../tests/evidence_deploy20261014_build.json) and
deployed to the live test service as app `sha256:ba847a85…`. The user asked for no data migration and said
old data did not matter, but the change only relaxes a database CHECK, so migration 0006 was applied in
place and the existing admin, assets, accounts, credentials and recordings were kept
([verification](../tests/evidence_deploy20261014_verify.json)); a `pg_dump` was taken first at
`/tmp/pre-deploy-0006.dump` inside the postgres container.

The first attempt **failed and rolled back automatically**: raising the startup schema gate from migration 5
to 6 means the app refuses to run before 0006 exists, and this deployment path never migrated by itself.
The container logged `PolicyStoreUnavailable` until `maintenance migrate --config
/etc/zeroterm-bastion/maintenance.toml` was run explicitly, after which bastion and proxy started healthy.
PostgreSQL and guacd containers were not recreated and the five legacy containers were unchanged.

Verified live: migrations 1–6, existing data unchanged, new frontend bundle `index-BtUId_tm.js`, admin login,
and the new RDP rule end to end — an asset created without a pin is accepted (`security` defaults to NLA),
a session for it is refused with `409 TARGET_HOST_KEY_UNKNOWN`, PATCH confirms pin and security, and soft
delete removes it from the catalog. `production_ready=false`.

## RDP certificate discovery and first-connect confirmation, 2026-10-14 UTC

First version (host/port scan filled into the asset form): app3 `sha256:96b8a405…`
[built](../tests/evidence_accept20261013_build3.json) and was checked on a real xrdp fixture
([evidence](../tests/evidence_accept20261013_rdp_scan.json)): the scanned pin equalled
`openssl x509 -outform DER | sha256sum` run on the target, `selected_protocol` was `tls`, bad inputs were
rejected, and the xrdp log shows each scan closing before MCS Connect-Initial with no sesman login.

At the user's request it then became like SSH: migration `0006_rdp_certificate_confirmation` lets an RDP
asset omit its pin (security still defaults to NLA); session issuance refuses an unconfirmed RDP asset with
`TARGET_HOST_KEY_UNKNOWN`; the host/port endpoint was replaced by bodyless, If-Match-bound
`POST /admin/assets/{id}/rdp-certificate/scan`, sharing the SSH discovery guard and rate limit, returning the
pin and the server-selected mode (`nla` for CredSSP, else `tls`). An administrator's first connect, or the
asset row's 确认/重新核验主机指纹, shows the fingerprint, the detected mode and any change against the
approved pin; confirming PATCHes both. The asset form no longer asks for the security mode; a pin can still
be imported manually. Startup now requires migration 6. Local checks: Rust unit tests including new
pending-RDP validation, clippy and fmt for the changed files, frontend 159 tests. **The revised flow has
not been built or run against a real target**, and the previous real-target runner was removed because it
tested the replaced endpoint. Not deployed. `production_ready=false`.

## Non-NLA acceptance rerun on the xterm SSH path, 2026-10-13 UTC

At the user's request, every gate runnable without Windows was rerun on the authorized test host, in
isolated `zt-guac-v2-accept-20261013*` projects. The live `zeroterm-test-guac-v2-*` service and legacy
`zeroterm-test-*` containers were not stopped, changed or migrated; all fixtures, the restored cluster,
loop mounts and the fault directory were removed afterwards.

Source: workspace snapshot `56a1a20f…` (205 files). App image `sha256:9e364e76…`
([build](../tests/evidence_accept20261013_build.json)); after the Ctrl+V fix below, app2
`sha256:e1c5419d…` ([build](../tests/evidence_accept20261013_build2.json)), which differs only in
`web/src/terminal.ts` and test runners. Engine `sha256:689c462e…` (the live engine, unchanged).

| Gate | Result | Image |
|---|---|---|
| Linux release workspace tests (inside the test-image build) | passed, 0 failed; real-fixture tests ignored there | app |
| Seven real PostgreSQL suites | [passed](../tests/evidence_accept20261013_pg.json) | tests |
| Today's SQL changes: group `PATCH {parent_id:null}` moves to root, absent field leaves parent; grant list returns user/asset/account names | [passed](../tests/evidence_accept20261013_sql_changes.json) against the real fixture | app |
| `browser_e2e`: six auth profiles with verified offline replay, revocation/permission/checkpoint faults close partial, guacd outage, mixed smoke | [passed](../tests/evidence_accept20261013_browser.json) | app |
| `browser_groups` | [passed](../tests/evidence_accept20261013_groups.json) | app |
| `browser_clipboard` RDP-TLS, VNC none/password, SSH | [passed](../tests/evidence_accept20261013_clipboard.json); SSH only after the fix | app / app2 |
| `browser_recovery`: cold restore, new-KEK-only replay, ten mixed sessions (4 SSH/3 RDP/3 VNC, 181 s, 11th rejected), five startup and five active recording syscall faults on SSH, end fsync, real ENOSPC, DB finalization, SIGKILL restart, tamper, truncation, retention | [passed](../tests/evidence_accept20261013_recovery.json); blocked write/fsync closed in 8.46/8.47 s | app2 |

**Product defect found and fixed.** In the xterm SSH terminal, plain Ctrl+V did not paste although the
hint advertises it: xterm.js mapped it to `^V` (0x16) and cancelled the native paste, so the target saw a
literal-next and the next Enter echoed as `^M`. A [controlled diagnosis](../tests/evidence_accept20261013_ctrlv_diagnosis.json)
on the same page showed a plain textarea pasting, xterm Ctrl+V producing zero paste events, and
Ctrl+Shift+V working. The key handler now returns plain Ctrl+V to the browser; Ctrl+C and other control
keys still reach the target. A unit test covers it, and the real SSH clipboard roundtrip (6 KB heredoc with
non-BMP text) then passed on app2. The [failed run](../tests/evidence_accept20261013_clipboard_ssh_ctrlv_failed.json) is kept.

**Runner corrections, not product changes.** Runners still assumed SSH used guacd:
`browser_e2e` required `web_ssh=false` during a guacd outage (now: RDP/VNC unavailable, SSH still
available, per [the SSH contract](ssh-xterm.md)); `browser_groups`, `browser_recovery` waited only for the
Guacamole ready text, and `browser_groups` used the removed asset-filter select and Guacamole paste
status; `docker_recording_probe.py` ignored a `--subnet-offset` fixture's own `compose.yaml`, so
restore could not recreate containers. Failed runs are kept: [e2e run 1](../tests/evidence_accept20261013_browser_run1_network_failed.json)
(client network dropped every SSH session at once), [e2e run 2](../tests/evidence_accept20261013_browser_run2_stale_assertion_failed.json),
[recovery run 2](../tests/evidence_accept20261013_recovery_run2_probe_subnet_failed.json). The passing e2e run
resumed completed profiles from run 2 on the same fixture and image; recovery passed from a fresh fixture.
Group runs 3 and 4 also collided with groups left by earlier failed runs (unique-name conflict); those
leftovers were removed before the passing run.

**Engine security matrix on the live engine.** `docker_guacd_acceptance.py` was rerun against the exact
live engine `sha256:689c462e…` (rebuilt for clipboard on 10-10; the matrix had last run on earlier engine
builds). [Passed](../tests/evidence_accept20261013_engine.json): SSH password/Ed25519 plain/encrypted,
xrdp TLS, VNC none/password with real authentication and one bridge accept each; wrong SSH key, wrong RDP
pin, CA-valid wrong leaf (TLS established, zero application bytes; matching-pin control 415 bytes), real
redirect PDU, missing/invalid pin, insecure mode and missing/false ready/display-only flags all rejected;
every egress probe (app API/metrics/SSH, target SSH/RDP, host, internet) denied. The
[first attempt](../tests/evidence_accept20261013_engine_run1_tag_failed.json) failed only because a
bare image ID cannot be used in `FROM`; the rerun tagged that same ID locally.

**Indefinite recording I/O stall.** The test-only shim gained `stuck-write`/`stuck-fsync`: every recording
write or fsync blocks until the controller switches the mode off, then fails with EIO.
[`browser_stall.mjs`](../tests/browser_stall.mjs) holds each stall for 90 s on SSH (app2, live engine):
the live session closes in 10.46 s, its connection is `failed` and its recording stays `active` (never
complete) during the stall; health stays 200, a fresh login and API work, a second session started during
the stall fails without reaching ready or receiving any frame; bastion thread count does not grow
(8→6, 5→7). After release the stuck recording seals `partial`, the second `failed`, and a new session
records `complete`. [Passed](../tests/evidence_accept20261013_stall.json). The recorder deliberately waits
for the outstanding I/O before sealing metadata (logged as `recording IO exceeded ACK deadline; waiting
for IO before metadata seal`), so an I/O that never returns leaves that one recording `active` until it
does; it is never shown complete. Two earlier runs expected sealing during the stall and are kept
([run 1](../tests/evidence_accept20261013_stall_run1_wrong_expectation.json),
[run 2](../tests/evidence_accept20261013_stall_run2_wrong_expectation.json)). Login during the stall
(8.6–8.9 s) matched an unstalled baseline (9.1–10.3 s, mostly page load over the tunnel).

**Sustained high-output SSH stress (not a capacity claim).** [`browser_load.mjs`](../tests/browser_load.mjs)
ran 8 SSH sessions (3 operator users) each printing `head -c 49152 /dev/urandom | base64` in a loop, plus
one interactive admin session, for 603 s on app2 and the live engine, on this 2 vCPU/1 GiB host with
Chromium on the remote client. [Result](../tests/evidence_accept20261013_load.json): all 9 sessions active
in all 11 samples; 9 recordings `complete`, 1.34 GB at 2.11 MiB/s; interactive keystroke echo p50/p95/max
1287/1937/1939 ms and command roundtrip 1256/1705/1908 ms (n=32) against an unloaded baseline of
1071–1105/642–857 ms, which is dominated by the client tunnel; bastion CPU avg/max 26.0/36.9 %, memory
26.5→31.9 MiB peak, 30.6 MiB at the end (no growth trend); guacd unused by SSH. The runner's 120 s replay
wait was too short: replay is real time without seeking, and a separate full replay of the ~10 min
interactive recording completed cleanly in 688 s. The flood recordings were not replayed. Earlier runs are kept: [run 1](../tests/evidence_accept20261013_load_run1_client_network_drop.json)
lost every WebSocket when the client tunnel dropped at 4.5 min (the server marked all sessions `failed`,
recordings `partial`); [run 2](../tests/evidence_accept20261013_load_run2_harness_access_expiry.json) hit
the runner's own expired access cookie at 557 s (it polled with plain fetch; it now refreshes once and
retries, like the app). This is a stress observation on an undersized host, not production sizing.

Not covered: Windows NLA (deferred by the user), native OS IME, hostile cross-child pending-bridge races
(not executed), capacity on production-class hardware, and long-term audit partition operation.
`production_ready=false`.

At the user's request, the accepted app2 image itself (not a rebuild) was then
[deployed](../tests/evidence_accept20261013_deploy.json) to the live test service: app/proxy recreated,
PostgreSQL/guacd and legacy containers unchanged, no migration (Rust sources identical), data counts
unchanged, live bundle `index-hU-NsQTO.js` matching the accepted build, and a temporary grant created,
listed with resolved names and removed. The live source tree received only the eight changed web/test files.

## Frontend refresh with accessibility-only validation, 2026-10-10 08:30 UTC

At the user's request, the current worktree (asset group tree, viewport-sized
initial connection display, dark scrollbars and updated icon) was
[built](../tests/evidence_latest_frontend_build.json) and
[deployed](../tests/evidence_latest_frontend_deploy.json) to the test service.
App/proxy were replaced; PostgreSQL/guacd were preserved, with no migration or
backup. The user explicitly limited post-deployment checks to service access.
[HTTPS checks](../tests/evidence_latest_frontend_access.json) verified 200 for
the page, live/ready health routes and `/api/v1/info` with the correct server ID.
No browser connection, recording or protocol integration acceptance was performed
for this deployment; `production_ready=false` remains.

## Independent console window redeployment, 2026-10-10 08:09 UTC

The requested worktree refresh replaces sidebar-based session navigation with an
independent `#/console/{asset_id}/{account_id}` window opened by an asset's
“连接” action. The console hides management navigation and fills its viewport;
it automatically requests one session after identity and target loading. Canvas
smoothing now follows local scale. The existing pointer-exit clipping, cursor
handling and stable resize calculation remain enabled.

Before deployment, the target-selection path was corrected to rebuild the
account options before selecting the route's exact account, reject missing
accounts, and use the existing authorized asset-detail endpoint for targets
outside the first page. Route disposal cancels that read. Console initialization
skips the concurrent first-page load that could overwrite the selected target;
management pages still load the asset list normally. Invalid extra path segments
are rejected. Frontend check/build and all 135 tests passed, including second
account selection, off-page loading and disposed-route callbacks. The
[build](../tests/evidence_console_window_build.json) confirms no backend or
migration change from the accepted asset-group version.

[Preview](../tests/evidence_console_window_preview.json) and
[public browser checks](../tests/evidence_console_window_public.json) open an
actual popup from the asset table, verify exactly one new active connection to
the requested asset/account, real SSH input, native paste, initial fit, an 800px
console window, stable dimensions after edge/exit movement, asset-group forms
and complete recording finalization. Existing active user connections are
excluded from the test's new-connection count. Earlier preview-script failures
used obsolete sidebar bounds or counted existing connections; they are retained
locally and not counted as successful checks.

[Deployment](../tests/evidence_console_window_deploy.json) updates app/proxy only,
preserves PostgreSQL/guacd, performs no migration and creates no backup per user
preference. [Final inspection](../tests/evidence_console_window_environment.json)
checks live health/image identity, every deployed static file against the tested
build, and stopped build tooling. Browser fixture runners follow the new console
auto-connect flow and check requested IDs; syntax checks passed, while the full
RDP/VNC matrix and Windows NLA were not rerun. `production_ready=false` remains.

## Chrome pointer-exit resize flicker, 2026-10-10

The user reported SSH flicker with changing terminal dimensions when the mouse
left the display. Initial headless Chromium checks missed it because the browser
hid scrollbars. Repeating the edge movement with `--hide-scrollbars` removed
from Chromium's default arguments reproduced the size feedback: 730×388 became
715×373 and back; 816×456 became 801×441 and back. The
[before trace](../tests/evidence_cursor_resize_before.json) contains eight
client size instructions for a sequence that only needs four. Software cursor
overflow caused scrollbars to alter `clientWidth/clientHeight`, which were used
to resize the remote terminal, producing additional full redraws.

The viewport now clips display overflow, hides scrollbars in fit mode, and hides
the software cursor on official mouseout events (reshowing it on interaction,
as illustrated in the [official Mouse documentation](https://guacamole.apache.org/doc/guacamole-common-js/Guacamole.Mouse.html)).
Manual zoom still allows scrolling. Remote sizing uses the stable workspace
layout box minus borders, so scrollbars cannot request a smaller remote display.
Unchanged display scales are not reapplied. Mouse button releases still occur
on exit and blur, and old mouseout callbacks are cleared when replacing a client.

Frontend check/build and all 133 tests passed, including stable size requests
under simulated scrollbar changes, cursor exit/reentry and button release using
the official Mouse implementation. Both
[preview](../tests/evidence_cursor_resize_preview.json) and
[deployed browser regression](../tests/evidence_cursor_resize_public.json) use
real Chromium with visible scrollbars, real guacd and the existing SSH target.
Six cases (1280×720, 1366×768, 1440×1000; fit and 100% zoom) assert zero resize
instructions and unchanged display dimensions after edge movement/exit.
The connection finalizes a complete recording. The
[build](../tests/evidence_cursor_resize_build.json) and
[deployment](../tests/evidence_cursor_resize_deploy.json) change only app/proxy,
preserving PostgreSQL/guacd and performing no migration or backup. The full
RDP/VNC matrix and Windows NLA were not repeated; `production_ready=false`.
The [final environment check](../tests/evidence_cursor_resize_environment.json)
verifies service health, deployed static-file hashes and the stopped test builder.

## Requested worktree redeployment, 2026-10-10 07:04 UTC

The latest frontend changes replace the header target selectors with a searchable
left target list beside the Guacamole display, and simplify group presentation.
Two deployment blockers were fixed before release: the removed DOM selectors
still serve as in-memory selection state and now fall back to detached selects;
changing assets rebuilds account options before selecting the requested account.
A regression test verifies selection of the second account on another asset.
Frontend check/build and all 133 tests passed. Backend, migration and engine
sources remain identical to the accepted asset-group version.

[The new build](../tests/evidence_redeploy_build.json) was tested first through
[a local-client preview](../tests/evidence_redeploy_preview.json) against the real
HTTPS test API/guacd/SSH target, then through
[the deployed public page](../tests/evidence_redeploy_public.json). Both passed
target selection/search, exact session request IDs, initial display fit, narrow
layout, native clipboard paste, real SSH input, group form and complete recording
finalization without page errors. The command's output marker was visually
verified in the rendered display.

[Deployment](../tests/evidence_redeploy_deploy.json) recreates only app/proxy,
preserves PostgreSQL/guacd IDs, makes no migration and creates no backup at the
user's request. [Final inspection](../tests/evidence_redeploy_environment.json)
verifies live images/health, matching hashes for every tested static file and
the stopped owned builder. Browser acceptance runners now select targets through
the sidebar rather than deleted header controls; their syntax was checked, while
the full RDP/VNC fault/recovery matrix was not repeated for this frontend-only
deployment. Windows NLA remains deferred and `production_ready=false`.

## Flat asset groups, 2026-10-10

Assets now have one optional group. Admins create/rename/delete groups, select
membership in create/edit forms, and view assets in collapsible groups with a
group filter. Public available-asset grouping/filtering uses only the user's
authorized snapshot. Catalog management is admin-only; exact asset/account
grants remain authoritative. Migration 0003 adds the catalog, nullable FK and
index without changing earlier migration checksums. Existing assets default to
ungrouped. Group deletion returns members to ungrouped and increments only
configuration revisions; accounts, grants and routing/credential revisions stay
intact. Missing migration 0003 prevents startup; no automatic migration occurs.

Rust fmt/check/clippy passed; frontend check/build and all 132 tests passed.
The local Windows workspace run had two CLI failures involving Unix/platform
behavior and is not counted as full workspace acceptance. The
[Linux application build](../tests/evidence_asset_groups_build.json) and
[final test build](../tests/evidence_asset_groups_test_build.json) ran the full
Linux Rust workspace tests. Seven real
[isolated PostgreSQL suites](../tests/evidence_asset_groups_pg.json) passed,
including group CRUD, name uniqueness, revision conflicts, unknown memberships,
operator/auditor denial, scoped asset visibility, ticket validity across moves,
and deletion preserving the connection's target snapshot. Earlier exploratory
rounds failed due to a missing test-suite registration and an obsolete migration
count assertion; those results remain failed in the local/remote evidence cache.
The fixture launcher now registers the new suite, and migration-count assertions
follow the compiled migration list.

[Real browser checks](../tests/evidence_asset_groups_browser.json) passed group
creation, escaped text rendering, folding, form selection, scoped filtering,
rename, stale If-Match rejection and deletion. A real OpenSSH connection remained
active across membership changes/deletion, accepted later input and finalized a
complete recording. Earlier browser-script locator/timing failures are retained
as failed; the passing runner waits for the asynchronously loaded asset dialog
and addresses its named select controls. These runner-only changes do not alter
the accepted application image.

The [test deployment](../tests/evidence_asset_groups_deploy.json) explicitly
migrated the existing family-2 database and refreshed runtime grants. It verified
unchanged asset/account/grant data and encrypted credential payloads, retained
the existing PostgreSQL/guacd containers, and made no backup per user preference.
[Public browser verification](../tests/evidence_asset_groups_public.json) creates,
renames and removes only its temporary empty group and confirms existing assets
remain unchanged. Windows NLA remains deferred; `production_ready=false`.

## Optional account display names, 2026-10-10

The asset dialog is now titled “新建资产”, with a “连接账号与凭据” section;
“首个账号” and the mandatory “账号标签” wording are removed. Display name is
optional in creation, adding accounts and editing. Blank names default to the
SSH username, RDP `domain\username`, or VNC “无认证” / “密码认证”. Existing custom
names remain editable and unchanged unless explicitly cleared. Existing generated
names are shown blank in the editor so username/domain edits update the default;
VNC keep-credential edits derive the name from the stored credential kind.
Overlong automatic names fail before creating an asset and require a shorter
custom display name. The frontend supplies the existing required API `label`,
with no schema, credential or authorization change.

Frontend check/build and all 124 tests passed, covering default generation across
the protocols, keep-credential edits, restoring automatic names and the length
boundary. The [build](../tests/evidence_account_names_build.json) verifies Rust
sources remain identical to the accepted clipboard version. The
[deployment](../tests/evidence_account_names_deploy.json) updates only app/proxy,
preserving PostgreSQL and guacd container IDs and making no database migration
or backup. [Public browser checks](../tests/evidence_account_names_browser.json)
verify real create/edit forms, optional fields for all protocols, retained stored
account metadata and no administrator mutation requests during the checks.

## Bidirectional text clipboard, explicitly requested 2026-10-10

The user enabled clipboard across SSH, RDP and VNC. All three now permit only
`text/plain`, with a 256 KiB decoded UTF-8 limit, bounded stream ownership and
four concurrent clipboard streams per direction. Browser uploads are buffered,
validated and ACK-paced by Rust before complete text is forwarded to guacd.
That ACK proves gateway buffer acceptance, not target application acceptance.
SSH needs Ctrl+Shift+uppercase V; UTF-8 scalar boundaries are preserved between
blobs because stock SSH normalizes each blob independently. Browser encoding
uses TextEncoder/ArrayBufferWriter rather than the official StringWriter's
surrogate-half encoding. Incoming text is cached; copying into the local OS
clipboard requires an explicit user action. Toolbar and manual-editor fallbacks
are available when browser clipboard permissions are denied.

The [final browser checks](../tests/evidence_clipboard_browser.json) used a real
HTTPS Rust service, pinned guacd, OpenSSH, xrdp TLS and VNC none/password targets.
All four profiles passed target paste/file verification, copy back into the
browser, explicit copy into the system clipboard and complete recording parsing
that found no clipboard stream or client transfer ACK in the recording. SSH and
RDP uploads crossed multiple blob boundaries. SSH carried Chinese and emoji;
RDP carried BMP Chinese. The target xterm uses an explicit real CLIPBOARD paste
binding and UTF-8 mode. Files/images and audio remain prohibited. Screen output
produced by pasted text remains recorded naturally; raw clipboard transfers are
excluded, and offline playback rejects clipboard instructions.

The tests found two real upstream limitations. Stock guacd 1.6.0's UTF-16
conversion treats Unicode as UCS-2; the [candidate patch](../deploy/guacd/clipboard-unicode.py)
now handles surrogate pairs, reserves the clipboard terminator and allocates for
worst-case UTF-16/CRLF expansion at the public limit. The
[compiled checks](../tests/guacd_clipboard_unicode.c) cover roundtrips, invalid
surrogates, bounded writes and full-limit newline expansion. Debian xrdp 0.9.x
also uses UCS-2 and cannot accept emoji clipboard text; this target restriction
is shown in the UI. Standard VNC remains Latin-1, with Chinese/emoji rejected
before transmission. Neither a correct UTF-16 unit test nor xrdp TLS establishes
Windows clipboard/NLA interoperability.

[Linux application tests](../tests/evidence_clipboard_build.json),
[final app/engine build](../tests/evidence_clipboard_final_build.json) and
[target build](../tests/evidence_clipboard_target_build.json) passed. Frontend
check/build and 112 tests passed; the Rust gateway has 21 passing tests. The
final target Dockerfile hash is recorded separately from the engine source
archive. CI now runs clipboard acceptance alongside the existing real browser
fixture. Earlier failed exploratory runs remain in the local evidence cache
and are not counted as passed.

The [test deployment](../tests/evidence_clipboard_deploy.json) updates the app,
guacd and proxy, reinstalls the engine's egress rules, preserves the existing
PostgreSQL container, performs no migration and creates no backup at the user's
request. [Public browser verification](../tests/evidence_clipboard_live_browser.json)
checks native Ctrl+V on the existing SSH target and complete recording finalization.
The resulting marker was visually verified on the live display. The
[final environment check](../tests/evidence_clipboard_environment.json) confirms
the deployed image IDs, running containers, preserved PostgreSQL, installed live
egress chain, removal of all owned fixtures/rules and stopped test builder.
Windows NLA remains explicitly deferred and `production_ready=false`.

## Initial workspace sizing fix, 2026-10-10

The first ResizeObserver notification occurred before the target connection was ready. No subsequent
notification occurred for an unchanged workspace, leaving the initial 1280×720 display scaled down by
height with unused width. SSH/RDP now send the current bounded workspace dimensions after readiness
as well as on resize, with duplicate-size suppression and per-connection cancellation/reset. VNC remains
local-scale-only. The existing input test now verifies initial ready-triggered sizing, duplicate suppression,
workspace changes and VNC exclusion; all 107 frontend tests/check/build pass.

The [build](../tests/evidence_viewport_fix_build.json) and
[deployment](../tests/evidence_viewport_fix_deploy.json) update only app/proxy, preserving PG/guacd and
making no database migration or new backup. The [real browser result](../tests/evidence_viewport_fix_browser.json)
on the user's SSH asset verifies initial display/workspace dimensions match within one pixel, followed
by rapid window changes, edge mouse movement and blur release without errors. The browser screenshot
was visually checked. No new RDP/VNC target integration or Windows NLA claim follows from this SSH check.

## Pointer/resize regression fix, 2026-10-10

The user's real SSH target authenticated successfully but disconnected with INVALID_ARGUMENT during
pointer input. A real browser reproduced the failure by resizing the workspace and moving near its
edges: fractional scaling produced x=1280 on a 1280-wide framebuffer; separately, newer server sizes
crossed older browser coordinates while resize output was still in flight. The frontend now converts
coordinates once and constrains them to the displayed framebuffer for motion, presses and blur releases.
The backend validates pointer coordinates against the fixed 3840×2160 ceiling rather than the most recent
server dimensions, which the browser may not yet have received. Negative coordinates, above-ceiling
coordinates and invalid button masks still fail closed. Display allocation limits are unchanged.

[The fix build](../tests/evidence_pointer_fix_build.json) passed Linux workspace tests;
local gateway 19 tests, frontend 107 tests/build and Rust clippy passed. The
[deployment](../tests/evidence_pointer_fix_deploy.json) updated only app/proxy, without database migration
or backup, preserving PG and guacd container identities. The
[real browser regression](../tests/evidence_pointer_fix_browser.json) on the user's SSH target passed
three rapid workspace sizes, edge movement and blur release with no page/connection error. This is a
connection/input regression check; it does not establish Windows NLA or native OS IME acceptance.

## Test target network policy, 2026-10-10

The user explicitly requested opening the target allowlist. The live test production/maintenance
configuration now allows `0.0.0.0/0` and `::/0`, while preserving all configured sensitive-address deny
rules. The application was restarted and public HTTPS readiness verified. A TCP probe from the actual
application container to the user's asset `100.101.102.9:62548` succeeded; this is transport reachability,
not target authentication acceptance. New SSH/RDP assets no longer require a separate per-IP allow
entry. VNC still requires explicitly trusted CIDRs, and guacd's isolated bridge/egress rules are unchanged.

## Latest test refresh, 2026-10-09 10:22 UTC

At the user's request, the current worktree was rebuilt and directly deployed without making another
backup. The [refresh evidence](../tests/evidence_test_service_refresh.json) records application image
`sha256:934faaf876a75870b40472f8693853530f3d41a7328740980fe9e1e71c896f1a` and engine image
`sha256:6867984082292f6b363d53554b005e286a811544067f8d777ea1fe7242a065fc`.
The PostgreSQL container and existing users/assets/credentials/recording files were preserved;
family-2 incremental migration 2 was applied explicitly. No initialization, database reset or old-data
conversion was performed, and prior backups were not deleted.

This version adds explicit administrator confirmation for pending SSH host keys and engine negotiation
of the approved host-key algorithm. Scanning discovers keys without authentication or trust writes;
administrator confirmation is required before a missing pin can issue a connection ticket. The
existing-session pin check still occurs on the actual target connection before authentication.
New assets can leave the SSH public-key field empty until confirmation.

Rust fmt/check/clippy and 65 unit/CLI tests passed; frontend check/build and 107 tests passed.
The [Linux builds](../tests/evidence_test_service_refresh_build.json),
[six real PostgreSQL suites](../tests/evidence_test_service_refresh_pg.json) and
[external browser login/form check](../tests/evidence_test_service_refresh_browser.json) passed.
The [new engine integration matrix](../tests/evidence_test_service_refresh_engine.json) also passed
real SSH/RDP-TLS/VNC, wrong-pin-before-authentication, redirect-denial and egress-isolation checks.
Two test adaptations were needed: cache the protected stdin fixture for binaries containing multiple
tests, and update the idempotent migration-count assertion for the new second migration. The Docker
build whitelist also now includes the new C host-key-method test. No production validation was removed.

The public address and admin credentials remain unchanged. `production_ready=false` remains required;
Windows NLA remains deferred. The prior manual startup/egress requirements are unchanged.

## Live test service update, explicitly requested 2026-10-09

The user subsequently authorized updating the existing test service. The public origin
`https://3.129.249.195` now serves the verified family-2 application image listed below, under the new
project `zeroterm-test-guac-v2` and directory `/opt/zeroterm-test-guac-v2`. This is a fresh independent
database, not a conversion of the original family-1 database. Administrator credentials are reused
from the protected test configuration; assets/accounts must be configured again. VNC stays disabled
until a trusted target CIDR is explicitly approved. Windows NLA remains deferred and readiness false.

The [deployment evidence](../tests/evidence_test_service_guac_v2.json) records staging on a loopback
HTTPS port, consistent legacy backup after stopping the old application, and public cutover.
The original application/proxy containers are stopped but retained with unchanged IDs; original PG,
two target containers and all old volumes remain. pg_dump, compressed volume archives and their
checksums were verified. No old data, ticket, user record or recording was imported into family 2.
The native application SSH port 2222 is stopped; host management SSH is unchanged.

The [external browser check](../tests/evidence_test_service_guac_v2_browser.json) verifies CA/hostname,
actual admin login/logout, built frontend and the SSH/RDP/VNC asset form. Live deployment probes also
prove an app ephemeral canary is reachable from guacd while direct target SSH, app HTTP and a live
host canary are denied. Only the new proxy publishes HTTPS 443.

`/opt/zeroterm-test/compose.sh` now points to the new project's wrapper. Rollback is available at
`/opt/zeroterm-test-guac-v2/rollback.sh`; it stops the new project and resumes old containers without
removing either family's volumes. Deployment-only artifacts and credentials stay in protected server
files and ignored local paths. A tool-policy rejection blocked the proposed system-level boot service;
no systemd unit was installed. After host/Docker restart, explicitly run
`python3 /opt/zeroterm-test-guac-v2/deploy.py start` to establish egress rules before exposing HTTPS.

The isolation and unchanged-original-container claims in the earlier acceptance sections below describe
those completed test runs, before this separately authorized live update.

## Current result: recovery and fault acceptance, 2026-10-09 UTC

The [final build](../tests/evidence_guac_ingress_build.json) uses application image
`sha256:9e2153250baec10a90ebca92c304b953d6d26275fd4645a3efff73d770ab4f64` and Linux test image
`sha256:49df34f4daa62cbf5b918df9fd099a4b82280c429ea1e8b9d96336398eb9cf91`.
The v4 engine remains `sha256:63926f22592fad15ee841e8e7488020a6b0f17a257205f06a725718415c01e1e`.
Only new `zt-guac-v2-next-20261009-a93f6e1b-*` fixture projects were modified. Original services and
databases were not stopped, changed or migrated.

Three concrete problems were found and corrected:

1. Recording creation synced file contents without syncing the new directory entry. The writer now
   fsyncs the anchored directory before activation; a real syscall-injected directory-fsync failure
   produces a failed recording and sends zero display blocks to the browser.
2. Ten mixed sessions exceeded guacd's 128 PID limit. The bounded limit is now 256; the final run
   measured 158 processes/threads and `pids.events` reported zero denials. The
   [128-limit failure](../tests/evidence_guac_recovery_pid128_failed.json) is preserved.
3. SIGKILL/restart of Rust left a proxy sharing its namespace unable to reach the restarted API.
   The [failed run](../tests/evidence_guac_recovery_shared_namespace_failed.json) led to separate
   proxy/Rust namespaces. Only the proxy publishes 443. It uses a dedicated ingress network and fixed
   upstream address; Rust binds an explicit private address and trusts only the proxy IP. The
   [fresh deployment](../tests/evidence_guac_ingress_deployment.json) passed HTTPS/role/permission checks
   and rejected spoofed forwarding headers from an untrusted source with HTTP 403.

The [final recovery/browser run](../tests/evidence_guac_recovery_final.json) passed without resuming
earlier results. It executed the following on the final image and ingress layout:

| Gate | Executed result |
|---|---|
| Cold backup and restore | Real pg_dump/pg_restore into a second isolated PostgreSQL cluster; encrypted files copied back from backup; manifest verifies 7 credentials, 3 recordings and 5 target pins |
| Restored identity | All restored login families and issued tickets revoked; the old browser cookie receives 401; SSH/RDP/VNC recordings replay after new login |
| KEK rotation | Credential ciphertext/nonces, recording nonce prefixes and file hashes unchanged; new-KEK-only backup verification, three-protocol replay and real SSH authentication pass; missing KEK rejected |
| Startup recording faults | Injected open, directory fsync, write, partial write then error, and file fsync each fail closed with zero browser display blocks and recording state failed |
| Active recording faults | Write, partial write, file fsync and terminal fsync failures close with partial recordings; controlled eight-second blocked writes/fsync close in about 8.3/8.8 seconds, with no complete state |
| Full recording filesystem | Dedicated 512 MiB ext4 loop image reaches real ENOSPC after 499220480 filler bytes; the active session closes partial. Production minimum-free-space validation remains enabled; this proves full-filesystem protection, rather than claiming the recorder necessarily reaches its own ENOSPC syscall before preflight |
| DB finalization | A controlled DB trigger rejects complete finalization; the recording closes partial |
| SIGKILL and restart | Rust container killed and restarted; HTTPS/management recover without restarting the proxy; active connection becomes interrupted and recording partial |
| Tamper and truncation | AEAD tamper cannot reach clean EOF and marks corrupt; independent truncation returns 503 and marks corrupt |
| Recording retention | Only selected expired file removed; unexpired file still replays; connection and audit history retained |
| Final browser interaction | [Six authentication profiles](../tests/evidence_guac_browser_final.json) pass keyboard/target-byte checks, scaled mouse, focus, fullscreen and verified offline replay under the new KEK; permission/checkpoint failures close partial, and guacd outage leaves management/replay available |
| Local quality | Rust fmt/check/clippy and 61 workspace tests pass; Linux release workspace tests executed during the exact test-image build. Frontend remains at the previously verified 96 tests and successful build |

Faults are supplied by a separately compiled test-only LD_PRELOAD shim, scoped to this fixture's
recording descriptors. It is not included in application/engine images and logs only the operation and
error, never payloads or credentials. Generic write/flush and final-flush failures also have codec tests;
File::flush itself has no separate filesystem syscall to inject. Earlier periodic-checkpoint acceptance
is retained and the final interaction runner covers it again. The loop image reserves at most 512 MiB
on the host; no host-wide disk fill or security-validation bypass was used.

The final interaction evidence aggregates two explicit phases on the same fixture/image. All six
profiles and mixed smoke completed first. That runner then injected its checkpoint trigger into the
obsolete original database instead of the restored instance, so its
[raw result failed](../tests/evidence_guac_browser_obsolete_cluster_failed.json). The corrected fault
phase ran against the restored instance with autonomous target output; completed profile checks were
not replayed or counted twice. The recovery/fault/capacity runner above is a separate full successful run.
The [final environment](../tests/evidence_guac_ingress_environment.json) records exact images, network
membership, published ports, deployment source hashes and original container IDs.
Independent [xrdp OS authentication](../tests/evidence_guac_final-xrdp-auth.txt) and
[OpenSSH authentication](../tests/evidence_guac_final-ssh-auth.txt) logs accompany these results.
The [cleanup evidence](../tests/evidence_guac_cleanup_final.json) confirms test containers, restored PG,
owned egress chains, loop mounts and local forwarding processes are removed; the builder is stopped and
original five IDs remain unchanged. The temporary SSH authorization remains available for unfinished
acceptance work, with its private key only in the ignored local working directory.

Ten simultaneous sessions (4 SSH, 3 RDP, 3 VNC) remained active for 194855 ms with five resource samples;
the eleventh connection was rejected by the global limit and all ten recordings completed. Three
independent RDP target accounts have actual PAM grants and OS-session-start logs. Reusing one xrdp login
had previously replaced old sessions; that [fixture failure](../tests/evidence_guac_recovery_shared_rdp_failed.json)
is preserved and is not counted as ten-session acceptance.

At sampled instants, app memory was 13.83–14.12 MiB, guacd 79.29–99.88 MiB and the target
106.1–125.1 MiB. The controlled Chromium process private-memory sum was approximately 688–720 MiB.
Working-set sums are also recorded but can double-count shared pages. This is initial display,
periodic mouse movement and protocol sync over a short period, not a throughput benchmark, soak test
or a production hardware sizing promise.

`production_ready=false` remains required. Real Windows NLA/CredSSP, native operating-system IME,
simultaneous hostile cross-child pending-bridge races, indefinite I/O stalls and sustained high-output
capacity remain unverified. Linux xrdp TLS and synthetic composition events cannot substitute for them.
The user explicitly deferred Windows NLA on 2026-10-09; it remains an unverified release gate,
not a failed test and not a successful or waived security claim.

## Earlier authorized follow-up, 2026-10-08 UTC

The follow-up used the user-provided SSH endpoint and a temporary key, rather than the unavailable
`test` alias. All work used `zt-guac-v2-followup-7b819270feb1` and its independent fixture projects.
No existing database was migrated, reset or removed, and the original five container IDs stayed unchanged.
The [measured environment](../tests/evidence_guac_environment_followup.json) had 962268 KiB RAM and
2578280 KiB pre-existing swap. This run did not change swap or existing service limits. The independent
builder used 384 MiB memory, 1536 MiB total memory-plus-swap and one CPU. The old run's OOM below is
historical; [the current application and Linux test builds succeeded](../tests/evidence_guac_build_followup.json).
The v4 engine raw JSON inherited an inaccurate static "no swap" label; use the measured environment
for this run. The runner now reads actual MemTotal/SwapTotal instead of hardcoding host specifications.

Exact images tested:

| Artifact | Image ID |
|---|---|
| v4 strict engine | `sha256:63926f22592fad15ee841e8e7488020a6b0f17a257205f06a725718415c01e1e` |
| Browser/API application | `sha256:7e9c8cc266a1e4e7a5f6817d37f8872c4eddd89c8f500113c501d5bf8104b83f` |
| Compiled Linux acceptance tests | `sha256:74fce52c24bcd125dcce71827ace30607fa02f6230d1e7c7569ac51e9d050ac9` |

### Fixes established by real interoperability tests

- SSH's official terminal emitted outgoing font/color `argv` streams, conflicting with display-only policy.
  The engine disables those producers and the input handler, and Rust requires the new
  `zt-ssh-display-only=true` capability. The policy still rejects parameter streams.
- Modern OpenSSH rejected the pinned libssh2 RSA signature path. No SHA-1 fallback was enabled.
  Credential ingestion now accepts only OpenSSH Ed25519, unencrypted or AES-256-CTR encrypted with a
  valid passphrase. Real password, plaintext Ed25519 and encrypted Ed25519 authentications succeeded;
  genuine RSA credentials were rejected before storage.
- Official display streams use zero-size non-root layers and four-argument server mouse instructions.
  The filter now validates those forms while retaining framebuffer, layer, coordinate and stream limits.
  EOF with an unfinished image stream cannot produce a complete recording.
- A split image replay could wait for display flush before feeding the stream's end, causing deadlock.
  Replay now feeds the bounded image stream through end before waiting for flush.
- Periodic recording failure now proactively closes the connection even without subsequent user input.
  Recording readiness and safe replay-directory readability are reported independently.
- Safe asset accounts expose credential kind, including VNC none via LEFT JOIN. Recordings can be
  filtered by connection_id with cursor scope binding. Auditor disconnect mutation is denied.
- Fullscreen includes the session toolbar. Connection revocation diagnostics preserve the authenticated
  management session; actual HTTP 401 and login revocation still clear identity.

### Executed checks

| Check | Actual result and evidence |
|---|---|
| Real engine, same-socket trust and isolation | [v4 matrix](../tests/evidence_guacd_v4_followup.json): SSH password/plain/encrypted Ed25519, xrdp TLS, VNC none/password; wrong SSH key and wrong RDP pin before authentication; CA-valid wrong leaf receives zero TLS application bytes; redirect PDU and unauthorized egress denied |
| PostgreSQL | [Six suites passed](../tests/evidence_guac_pg_followup.json): server schema, ticket identity/expiry/replay/revision races, lifecycle/recovery, implicit admin/exact grants, user deletion/history and audit retention |
| Actual API and WebSocket identity | [Passed](../tests/evidence_guac_ws_followup.json): Origin, cookie/login binding, wrong identity/secret, query rejection, one-time use, public-only subprotocol, binary-only and removed routes; this suite uses the app's trusted-proxy loopback HTTP boundary, rather than claiming browser WSS |
| Fresh deployment | [Latest image passed](../tests/evidence_guac_deployment_followup.json): family-2 initialization, independent secrets, owner/runtime role split, 0700/0600 modes, repeat initialization refusal, HTTPS cookie login, removed routes, non-root/read-only runtime and directory-permission degradation/restoration |
| Real headless browser over HTTPS/WSS | [Run 17 passed](../tests/evidence_guac_browser_followup.json), Chromium 149.0.7827.55: six profiles, target input bytes checked independently, scaled mouse, focus release, fullscreen and encrypted read-only replay; replay opens no target socket |
| Required recording and outage | Same browser run: revocation closes in 1952 ms with partial recording; permission failure closes partial; periodic DB checkpoint failure closes partial without user input; guacd outage disables connections while authenticated management and replay remain available |
| Mixed protocol resource smoke | Same run: three simultaneous SSH/RDP/VNC sessions and fourth per-user connection rejected with 429; app 12.17 MiB and guacd 70.87 MiB at one sampled instant. This is not ten-connection or sustained capacity acceptance |
| Local quality | Rust fmt/check/clippy and workspace tests passed (59 tests); frontend check/build and 96 tests passed. Linux release workspace tests also ran during the exact test-image build; six opt-in PG suites and the opt-in WS suite were executed separately |

Independent [OpenSSH authentication](../tests/evidence_guacd_v4_ssh_auth.txt) and
[xrdp/PAM](../tests/evidence_guacd_v4_xrdp_auth.txt) logs accompany the engine assertions.
The [PostgreSQL execution log](../tests/evidence_guac_pg_followup.txt) and
[WebSocket execution log](../tests/evidence_guac_ws_followup.txt) record opt-in tests actually running,
rather than only compiling. The final deployment probe initially encountered the owned browser
fixture's fixed bridge subnet; it made no target connection, cleaned its own failed project, then passed
after the completed browser fixture was removed. Evidence contains no fixture login secret or target keys.
The [cleanup evidence](../tests/evidence_guac_cleanup_followup.json) confirms the owned fixture volumes,
disposable PG and egress rules were removed, the independent builder was stopped, local tunnels were
closed and the temporary SSH authorization/private key were removed. Candidate images and stopped
builder cache remain for reproducibility; the original five container IDs are unchanged.

Browser composition tests dispatch composition events through the official keyboard component and verify
target bytes. They do **not** exercise a native operating-system IME. SSH passed Chinese BMP input;
VNC passed Chinese plus emoji. The official SSH and RDP paths cannot safely send non-BMP keysyms,
so the whole unsupported composition is rejected before sending any of it and the UI states the limit.
The xrdp target ignored Chinese Unicode keyboard events: its passed RDP input checks are ASCII only.
The UI explicitly describes the target-dependent RDP input limitation.

### Remaining release gates

`production_ready=false` remains required. Real Windows NLA/CredSSP, native OS IME, full recording
open/write/flush/fsync/finalize/disk-exhaustion fault and cold-restore/rewrap/retention matrices, simultaneous
cross-child pending-bridge races and sustained ten-connection mixed resource measurements are not
established by these results. Linux xrdp TLS cannot substitute for Windows NLA. A Windows test target
must supply its connection/account configuration and independently approved certificate pin through
protected files; no password or private key belongs in the evidence or chat.

The following sections retain earlier executed results and failures as history; they do not supersede
the current images or expand the current acceptance claims.

## Authorized test host and isolation

- SSH alias `test`: Debian 13 root, Docker 26.1.5, Compose 2.26.
- Approximately 939 MiB RAM, no swap; `/tmp` is 470 MiB tmpfs. Use `/var/tmp`, with about 30 GiB free disk.
- Original five running `zeroterm-test-*` containers are untouched. No down/rebuild/delete against that project,
  no global prune and no original builder image modification. All new resources use project
  `zt-guac-v2-5da26cf3-8ac8-428b-8be7-e3f877a7c44a` and the matching `/var/tmp` directory.
- Heavy compile uses one job; source download/build and real-engine fixture runs are serialized.

## Source / patch identity

| Input | Official tag | SHA-256 archive |
|---|---|---|
| Guacamole server | 1.6.0 | `913b05d19beabed4a3066e6e2be3078783048f55c7a9d2e3a012897a8766c245` |
| FreeRDP | 2.11.7 | `22dbeeaad065e93f152d70e04ec8eeab08aa32c406a96be64f252526623625a4` |

[Engine Dockerfile](../deploy/guacd/Dockerfile) verifies these hashes before extraction. The guarded
[source delta](../deploy/guacd/apply-strict-pin.py) changes only known official source anchors.
The [strict leaf helper](../deploy/guacd/zt-strict-pin.h) is compiled directly by the
[runnable C check](../tests/guacd_pin_unit.py). The `zt-pin-v2` startup delta adds mandatory
`zt-target-ready=true` to all three protocol args and a private no-arg success marker that core consumes,
never displays or records. SSH emits after same-socket host identity/user authentication and successful PTY/shell;
VNC emits after successful RFB initialization (None has intentionally no user authentication). RDP TLS emits after
identity-verified TLS/RDP interactive protocol establishment, not proof of remote OS account login. TLS may display
a legitimate server logon screen. Positive xrdp acceptance separately requires target PAM/account authentication
logs plus display; real Windows NLA/CredSSP interoperability is not inferred from TLS.

Actual FreeRDP header and implementation were read: `pVerifyX509Certificate` returns int with PEM bytes,
size_t length, hostname, UINT16 port and DWORD flags; return 2 means session-only acceptance, return 0
rejects. ExternalCertificateManagement uses that callback before CA/hostname fallback. Stock accepted
fingerprints have an earlier successful short-circuit and therefore are cleared, not reused as a strict gate.
The callback hashes the first PEM certificate's DER with OpenSSL X509_digest(EVP_sha256), rejects missing/
invalid/wrong approved pins and redirect/gateway flags, and returns 2 only for exact match.

## Actual commands and intermediate results

Executed in the authorized isolated directory:

```sh
docker build --progress plain -t zt-guac-v2:5da26cf3 -f deploy/guacd/Dockerfile .
python3 -u tests/docker_guacd_acceptance.py --engine-image zt-guac-v2:5da26cf3 \
  --project zt-guac-v2-5da26cf3-8ac8-428b-8be7-e3f877a7c44a \
  --directory /var/tmp/zt-guac-v2-5da26cf3-8ac8-428b-8be7-e3f877a7c44a
```

- Original build failed on FreeRDP's default USB redirection channel lacking libusb. Fixed by disabling
  CHANNEL_URBDRC, a product-forbidden feature, not weakening TLS or trust validation.
- The strict RDP callback and plugin compiled against actual FreeRDP 2.11.7; guacd reports 1.6.0.
- The exact C digest unit passed: exact leaf DER pin, absent/invalid/wrong/uppercase pin, malformed PEM,
  leaf-first certificate chain and changed leaf rejection. This is not same-socket/network acceptance.
- Initial runtime failed because guacd's official `-p` means PID file, not port. Corrected to official `-l 4822`.
- Initial fixture exposed that Guacamole `ready` is emitted before argument validation/target connection;
  SSH also emits terminal drawing even after host-key refusal. Neither `ready` nor first drawing proves
  successful authentication. Added the explicit private startup marker at true success points.
- SSH fixture initially exposed multiple host-key algorithm negotiation selecting a different algorithm
  from the approved key. The positive fixture now provides only the approved Ed25519 key. Mismatched
  selected keys fail closed; the pin must match the actually negotiated host key, not merely another key
  offered by that server. Broad multi-key interoperability is not claimed, and no SHA-1 fallback was enabled.
- Runs 5/6 exposed an x11vnc fixture that accepted TCP but never sent an RFB banner, including direct
  localhost probes. Replaced that faulty fixture with independent native TigerVNC None/password servers.
- Run 8 compiled the combined v3 engine and sent a real redirect PDU, but failed the denial-log assertion:
  official Guacamole maps all FreeRDP WLog messages, even ERROR, to Guac DEBUG. The isolated fixture now
  uses `-L debug` plus `WLOG_LEVEL=INFO`; the production-candidate default remains `-L info`.
- Runs 7/9 used a superseded display criterion that counted initial/default cursor drawing. Those raw
  results are historical, not final display acceptance. Run 10's literal layer-zero test was too narrow for
  SSH's visible terminal child layer (the official terminal implementation allocates it under root 0).
  The final check accepts only post-marker painting of nonnegative visible layers or complete PNG streams;
  cursor, size, rect and pre-marker drawing never satisfy it. Negative offscreen/cursor buffers are excluded.

## Final component result: run 11

The [final raw JSON](../tests/evidence_guacd_v3_run11.json) reports `passed-engine-only`, exit 0.
The exact production-candidate image is:

`sha256:bc862448d8a62015d995024c7e9e8cdee12522438faeab88ecdb7d276821ee90`

The actual isolated guacd runtime used its test-only trusted-CA derivative:
`sha256:b2f3a52a5b6836e07a9ef8854c9b7e2f506d94b1ddb956de1ed0fde960d1bc7a`.
That derivative adds only the fictional public CA needed to disprove CA fallback; the engine binaries
are from the candidate above. Neither image contains target private keys or an app database/recording mount.

| Actual fixture | Executed result |
|---|---|
| SSH password | Approved Ed25519 host key, exactly one real Accepted password, PTY/shell and post-marker visible terminal paint |
| SSH private key | Unencrypted OpenSSH Ed25519, exactly one real Accepted publickey, PTY/shell and post-marker visible terminal paint |
| xrdp TLS positive | Same-socket approved leaf, marker then complete visible PNG stream (570 bytes); separately real account access granted and OS session started |
| VNC None / password | Independent real RFB servers, marker then post-marker visible paint; None intentionally has no user authentication |
| Wrong SSH host key | No success marker and no target password/key authentication; pre-auth drawing is not success |
| Wrong xrdp leaf pin | No marker and no negative-account authentication log |
| CA-valid same-socket wrong pin | Trusted chain plus hostname/IP verification pass; one accepted TLS connection, zero application bytes after TLS; matching-pin control sends 415 bytes |
| Missing/false startup capability | All three protocols fail before target contact |
| Missing/invalid RDP pin, insecure mode | Fail before bridge target contact |
| Real redirect PDU | Approved primary receives ClientInfo, peer sends real PDU, no success marker, actual client protocol-denial log |
| Egress | Live app 8080 and host gateway canaries proved reachable from their allowed side, denied from guacd; target SSH/RDP, app metrics/SSH and Internet denied |

The [OpenSSH log](../tests/evidence_guacd_v3_run11_ssh_auth.log),
[xrdp/PAM log](../tests/evidence_guacd_v3_run11_xrdp_auth.log), and
[isolated debug protocol log](../tests/evidence_guacd_v3_run11_protocol.log) preserve independent evidence.
The final cleanup left only the original five containers with unchanged IDs and no owned ZTGUAC rule chain.
Unencrypted Ed25519 is the actually tested private-key path; RSA/encrypted OpenSSH interoperability is not
inferred from it. Unsupported PKCS/ECDSA private-key formats remain rejected at the application boundary.

### TLS wrong-password diagnostic, not positive OS login

A separate existing fictional `badpassfixture` account receives an intentionally wrong password over its
approved TLS connection. A marker and actual logon/failure UI paint are allowed and were observed, but
PAM logs `pam_authenticate failed` and `AUTHFAIL`; there is no access grant or OS session start for that
account. This is a concrete counterexample to treating TLS activation/painting as OS login success.
No SaveSessionInfo/pixel heuristic is added to block legitimate logon or expired-password screens.

## Redirect / reconnect guard

The host's app ephemeral range and one-use bridge do not distinguish guacd child processes. These controls
alone are **not** a redirect proof: a child must never switch toward another pending bridge. The combined
candidate is `zt-pin-v3-no-redirect`. Its [FreeRDP source guard](../deploy/guacd/freerdp-no-redirect.py)
rejects every enhanced server-redirection packet with **-1** before parsing routing/credential fields and
rejects both redirect/reconnect execution entry points with FALSE before any new network operation.
All three packet receive paths converge on that guarded int-returning receiver. Returning FALSE/0 there
would not be an equivalent error, hence -1 is intentional.

A separate [native FreeRDP TLS peer fixture](../tests/guacd-fixture/redirect.c) sends a real redirect PDU
at ClientCapabilities, after ClientInfo but before interactive finalization. The acceptance runner requires
proof the approved primary received ClientInfo, the peer actually sent the PDU, no success marker, and the
client's protocol-denial log. The helper is present only in the explicit `redirect-fixture` Docker stage,
never in the default production-candidate image. Run 11 proved the real PDU denial with the
[protocol log](../tests/evidence_guacd_v3_run11_protocol.log); a separate read-only image check confirmed
the default image has no helper executable and runs UID/GID 10002.

## Main application build: controlled resource failure

The frozen source archive SHA-256 was verified as
`7a577cdf17bf9f37979a3119e0be14d7798c8b5e56013d9dd7dc169dd23bd0ac` and safely extracted only into
`/var/tmp/zt-guac-v2-52d7796f-7a9f-401a-b859-218d8970d75d/source`. A new explicit docker-container
builder `zt-guac-v2-52d7796f-builder` left the original default builder selected. Actual Docker inspect
and cgroup files proved memory.max 335544320 (320 MiB), memory.swap.max 0 and cpu.max 100000/100000.
The web stage completed; the unmodified release/locked/one-job Rust build was OOM-killed while compiling
syn 3.0.6. Build exit was 1, with cgroup oom=1 and oom_kill=1. No application image exists, so fresh
HTTPS/deployment/chmod-degradation smoke was **not executed**, not passed. No optimization, RAM, swap
or old-service settings were changed to manufacture acceptance. The builder and isolated cache remain
for the parent agent's authorized next step; original five IDs/statuses remain unchanged.

[Raw build failure evidence](../tests/evidence_main_build_oom.json) records the actual limits and statuses.
The full build log remains in the isolated remote project and local evidence cache; this failure does not
invalidate the separately executed engine component checks above.

## Acceptance not implied by engine checks

Not yet verified by these engine checks: full new Rust/API deployment, authorization/ticket/revision races,
recording failure/recovery/retention/backup matrices, real browser Canvas/IME/input/resize, Windows NLA
interoperability, simultaneous cross-child pending-bridge race/load, full performance/resource acceptance
and production readiness. A working xrdp TLS
fixture cannot stand in for Windows NLA. Unavailable environments,
ignored tests, mock streams or a boolean configuration flag must not be counted as successful acceptance.
