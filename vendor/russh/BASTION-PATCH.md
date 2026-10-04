# Bastion server corrections

This directory is a self-contained snapshot of ZeroTerm's vendored russh
0.62.4 as found on 2026-10-04. It preserves the client certificate, agent,
channel-close, data-bytes and event-loop changes already in that checkout.
The snapshot has ssh-key pinned to 0.7.0-rc.11 in its Cargo.toml; the root
Cargo.lock is authoritative. Build artifacts were excluded.

Additional changes for asynchronous channel proxying:

1. Request events sent to `Channel::wait()` preserve the wire `want_reply`
   value. The original implementation always set it to true.
2. PTY events include only parsed terminal modes, without the padded array.
3. Agent-forward requests receive channel failure/success, rather than a
   global request response.
4. `server::Handle::channel_request_reply(id, success)` sends a reply to one
   captured request without consulting the channel's latest mutable
   `wants_reply` bit. The gateway captures the original flag, processes each
   channel's requests in order, and calls this exactly once only when requested.
   This prevents a later pipelined no-reply request from suppressing an earlier
   reply. Existing synchronous `Session::channel_success/failure` are unchanged.

These corrections are exercised by the real OpenSSH integration suite and its
russh client tests, including pipelined requests and no-reply requests. They are
server-side additions; client wire behavior remains compatible with ZeroTerm.

Upstream licensing is Apache-2.0 (see `LICENSE-APACHE`).
