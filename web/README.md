# ZeroTerm browser workbench

Vanilla TypeScript + Vite. SSH uses official xterm.js; RDP/VNC use the locally
vendored Apache Guacamole 1.6.0 client. The common console route dispatches to the
appropriate renderer; offline replay uses authenticated stream metadata.
See [SSH framing and security](../docs/ssh-xterm.md). There is no file/exec
workbench, native login, channel multiplexing or selectable operation permission.

## Build and checks

```sh
cd web
npm ci
npm test
npm run check
npm run build
```

Node >=22.18 is required. Official xterm packages are pinned in package-lock.json;
their licenses are published under `/xterm/`. Build tools are TypeScript and Vite.
The classic `/guacamole/all.js` script loads before the application module;
there is no external runtime CDN or third-party Guacamole npm wrapper.
`public/guacamole/LICENSE` and `NOTICE` are included in the built site.

## Contracts and lifecycle

- Asset “连接” opens a separate console window with no management navigation.
  It selects the exact asset/account from the route and automatically requests one
  session after identity/target loading. Targets outside the first page load from
  the existing authorized asset-detail endpoint; route disposal cancels that read.
  Manual reconnect still requests a new ticket and never replays input.
- Assets have one optional flat group. Both lists support folding and filtering;
  administrators create, rename and delete groups and select membership in asset
  forms. Deletion returns members to ungrouped. Operators see only groups present
  in their authorized asset rows; groups do not grant access. Group writes use
  Cookie/CSRF/If-Match and never replay unknown results or confirmed writes after
  a refresh error.
- Account display names are optional in create/edit forms. Blank names use the
  SSH username, RDP `domain\username`, or VNC authentication mode. Explicit custom
  names are preserved; clearing one restores automatic naming. Existing default
  names appear blank while editing so login edits update the generated name.
  The API continues to receive a nonempty `label`; no database change is needed.
- `/info` must advertise schema/protocol v2 and `bastion.guac.v1`. Connect controls
  honor `web_ssh`, `web_rdp` and `web_vnc` independently. No engine availability is
  invented by the UI. Stock RDP pinning is **not** strict certificate validation;
  an unverified deployment must keep RDP unavailable and `production_ready=false`.
- A session submits only `{asset_id,account_id,display:{width,height,dpi}}`, using
  1280×720 at 96 dpi initially; ceilings are 3840×2160 and dpi 48–192.
- A WebSocket uses the same-origin login Cookie and exact configured Origin, with
  `['bastion.guac.v1', ws_token]`. Only the public protocol may be echoed. The secret
  is cleared from the response object immediately after constructing the socket.
  Tokens never go in URLs, application storage or logs. Transport upgrade alone
  is shown as establishing the target, not authenticated readiness; key/mouse/resize
  input starts only after the first backend-approved target display instruction.
  No automatic reconnect, ticket retry or input replay occurs.
- Both directions are binary UTF-8 chunks <=32 KiB. A fatal streaming decoder
  continuously feeds the **official** parser. Serialized element lengths count
  Unicode scalars; the instruction ceiling is 8 MiB. Send/render queues are bounded.
  Bidirectional text/plain clipboard is enabled; files, pipes, audio and video remain
  disabled. Stream ownership/size bounds preserve display image/blob/ack/end.
- Route disposal releases keys and mouse buttons, queues the official Guacamole
  disconnect, normally closes the WebSocket with code 1000 **before** invalidating
  the route, cancels pending requests/timers and guards stale callbacks by generation.
  Failed streams close with browser-permitted private code 4000, not a normal close.
  A manual reconnect creates a fresh official client/display.
- Keyboard input is attached to the local official InputSink, not the document.
  Guacamole's single shared InputSink has its native document *focus-only* listener;
  it is detached from the DOM outside the session route. The Keyboard never binds
  globally. Composition is committed once through the official input path; intermediate
  pinyin is not sent. Invalid surrogate keysyms from the 1.6.0 typing loop are dropped.
  Blur releases held keys/buttons; orphan composition-end events after blur/reconnect
  cannot type into a newer target. Ctrl+V and toolbar paste/copy use explicit clipboard
  streams, separate from IME. The text editor provides manual copy/paste when browser
  clipboard permissions are unavailable. Limit is 256 KiB; old xrdp clipboard
  implementations may not support emoji. Standard VNC allows
  Latin-1 only and explicitly rejects Chinese/emoji. Clipboard data is not recorded.
- The Canvas supports zoom and fullscreen. SSH/RDP remote resize is bounded and
  debounced; VNC never sends remote resize and uses display-scale coordinate mapping.

## DOM controls retained

`#/assets`, `#/users`, `#/admin-assets`, `#/grants`, `#/connections`, `#/audit`,
`#/recordings` and `#/profile` retain the same DOM-only login/admin layout.
Users are soft-deleted with identity/revision confirmation and current-user protection.
Enabled administrators have implicit access to enabled asset/accounts; operators need
an exact valid grant; auditors cannot connect.

Assets require immutable `ssh|rdp|vnc` protocol. RDP security is top-level `nla|tls`,
default `nla`. SSH public-key input is optional: save the asset, then confirm a discovered SHA-256
fingerprint on first administrator connection or through asset management. The system
saves the selected public key after explicit confirmation. Sessions without approved
trust are denied; a changed key still blocks authentication. Manual OpenSSH host-key
import remains available. Discovery requires server-side `ssh-keyscan`, included in Docker. RDP requires pre-approved leaf-certificate DER SHA-256,
64 lowercase hexadecimal characters. Scanning, TOFU, test-login and auto-approval
are not offered. Account labels are required; SSH/RDP require username; VNC sends
null username; domain is RDP-only. VNC alone supports `{type:'none'}`; password works
for all protocols; private-key input is SSH-only and the backend currently accepts
OpenSSH-format Ed25519 keys (unencrypted or AES-256-CTR with a passphrase).
RSA failed real authentication with the pinned engine and is rejected; arbitrary PKCS PEM is also rejected. Responses expose only
`credential_kind` and revisions, never secrets.

Grouped asset/account editing still uses separate acknowledged API stages. Partial
success does not duplicate an acknowledged asset; subsequent account/credential
updates use the fresh `If-Match` revision. Unknown outcomes and revision conflicts
block resubmission until state is reread. Secret fields and temporary credential
objects are cleared on submit, mode changes, cancellation and route disposal.

## Offline recordings

`/api/v1/recordings/{id}/content` remains, but each recording directly references
its unique connection, without an intermediate channel. NDJSON v2 consists of:

- `meta`: seq 0, elapsed_us 0, format_version 2, connection_id, target_protocol,
  width, height and dpi.
- `output`: contiguous seq, monotonic elapsed_us and canonical data_base64 containing
  <=32 KiB of the same Guacamole display stream.
- `end`: contiguous seq, monotonic elapsed_us and reason.

The player opens **no target WebSocket**, has no input bindings and uses the same
fatal UTF-8 decoder/official parser. It streams with `display.flush` backpressure,
play/pause/stop/from-start controls, no full-file buffer and no seeking. Reads have
no five-minute total timeout and are canceled by route/stop signals. Unknown formats,
partial metadata, sequence faults, invalid/truncated UTF-8 or Guacamole instructions,
missing end, extra events and EOF tails are visible failures. Complete is shown only
for server `state=complete`, a valid end and clean EOF; file checksum/byte verification
remains the server's responsibility.

The page is a rail plus stage, using the console's visual language rather than a
stacked form. The rail lists `id`, server `state` as a toned tag, protocol, size and
the state in words, filters on id/connection/state/protocol, and pre-selects the
first row so `#/recordings/<connection_id>` (arriving from a connection) is never
blank. **Selecting a row never streams**; the identity bar and the stage say so.
Playback is explicit, through `播放 / 从头重播`. A `录制 ID` field with the loaded ids
as suggestions still opens a recording directly, so deep links and pasted ids work.
A stage-sized progress strip, a phase dot and the `seq`/`elapsed` detail run while
streaming, and pause/stop stay disabled until a replay is actually running.

## Vendor provenance and acceptance boundary

`public/guacamole/SOURCE.json` records the official Maven URL, pinned hashes and the
Apache guacamole-client 1.6.0 tag used for LICENSE/NOTICE. SHA-256 matched the supplied
review handoff; SHA-512 is a locally measured review digest, **not** a claimed ASF
signed/released checksum. The delegated worker's direct HTTPS download was blocked
by TLS resets; the parent provided the verified official archive extraction. No TLS
chain/domain verification was disabled.

Unit tests exercise the actual official parser and Keyboard with deterministic
DOM/client doubles, including fragmented UTF-8/astral Unicode, IME event order,
mouse scaling, stale tickets/callbacks, recording EOF/errors, admin partial success
and user deletion. These are **not real-browser acceptance**. Real Chrome/Edge Canvas,
focus/IME/fullscreen behavior and live SSH/RDP/VNC targets, strict RDP pinning, display
rendering, revocation and recorded replay still require integrated deployment tests.
