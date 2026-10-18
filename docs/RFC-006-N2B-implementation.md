# RFC-006 N2-B 实施清单：多通道网关与 exec 转发

| 项目 | 内容 |
|---|---|
| 状态 | 服务端已实现，N3 同时接入；当前实现与验证说明见 RFC-006 §14.6 |
| 日期 | 2026-10-18 |
| 契约 | [RFC-006](./RFC-006-native-ssh-entry.md) §14.2、§14.3、§14.5（与前文冲突时以 §14 为准） |
| 前置 | N1、N2-A 已完成并通过测试；ZeroTerm 客户端已按 §14 适配 |
| 范围 | 只做网关多通道和 exec。SFTP（§14.4）是 N3，本阶段 `subsystem` 仍拒绝，但要留好接入点 |

## 1. 已有的、直接调用的接口（N2-A）

- `bastion_domain::NATIVE_CAPABILITIES = ["shell","exec"]`。票据可以是任意非空子集，`consume_native_ticket` 返回 `NativeSession { connection, capabilities }`，网关侧对应 `NativeTicket { connection, capabilities, target }`。
- `GatewayBackend`（`crates/bastion-gateway/src/protocol.rs`）：
  - `activate_native_connection(&Connection)`：`connecting → active`，不需要录制。幂等，每个被接受的通道都可以调用。
  - `exec_completed(&Connection, &[u8], &ExecOutcome)`、`exec_rejected(&Connection, &[u8], ErrorCode)`：写审计。失败按 best-effort 处理（`let _ =`），与现有 `native_auth_failure` 一致。
  - 这三个方法的默认实现返回 `Err(TargetProtocolUnavailable)`。`protocol/native_tests.rs` 的测试 backend 用的是默认实现，要在那里补上实现。
- `bastion_domain::ExecOutcome { exit_status, exit_signal, stdin_bytes, stdout_bytes, stderr_bytes, duration_ms }`。

## 2. 要先解决的两个存储层约束

这两点不处理，多通道做出来也会在运行时失败。

1. **只能在 `connecting` 时激活录制。** `PgStore::activate_recording`（`bastion-store/src/recordings.rs`）要求连接状态为 `connecting`。如果连接先开了 exec（已经被 `activate_native_connection` 置为 `active`），之后再开 shell，录制激活就会返回 `RECORDING_UNAVAILABLE`。
   - 建议：新增一个仅限 `native_ssh` 的录制激活路径，允许连接已经是 `active` 时把 `preparing` 的录制置为 `active`，并写 `recording.active` 审计；授权和 revision 检查走 `runtime_connection`。
   - 另一种做法：规定 shell 必须是连接上的第一个通道，否则拒绝。实现简单，但 OpenSSH 的 ControlMaster 和 ZeroTerm 都可能先开 exec，不推荐。
2. **一个连接最多一条录制。** `recordings.connection_id` 是 UNIQUE，所以"最多一个 shell"指的是**整个连接生命周期内**最多一个，不只是同时最多一个。shell 结束后再开第二个 shell 必须拒绝。请在 RFC §14.2 里写明这一点。

## 3. 拆分 `ssh.rs::run`

现状：`run()` 第 91–238 行的 `startup` 块依次做授权、解析固定 IP、校验已批准的 host key（含 rekey）、凭据认证、开 session 通道、pty、shell、录制激活、发出初始尺寸帧和 ready 帧。

改法：

- 抽出 `connect_target(connection, target, backend, limits) -> Result<(client::Handle<PinnedHost>, SocketGuard), ErrorCode>`，内容是从 `authorize` 到认证成功为止（现在的第 92–194 行），不改任何校验逻辑。
- 抽出"在已有 handle 上打开 shell"：开通道、`request_pty`、`request_shell`、`accepted`、`authorize`、`recording.activate`、发初始帧和 ready 帧，然后进入现有的 `pump`。`NativeLink`、录制、ACK 和背压逻辑保持不变。
- `run()` 改成依次调用这两步，签名和行为不变，浏览器路径（`web::run_session → ssh::run`）的全部测试应该不用改就能通过。
- 目标连接的断开（现在第 268–272 行的 `session.disconnect`）移到连接级：最后一个通道结束、或连接被撤销时执行一次。`SocketGuard` 跟着 handle 走，保证取消或中止时 TCP 也会关闭。

## 4. 连接级生命周期（`native.rs` 的 `session()` 和 `connection()`）

现状：`session()` 直接调用 `run_session`，而后者负责 registry 租约、无条件准备录制、调用 `ssh::run`、结束录制、状态迁移，一个连接只对应一个 shell。

改为原生连接自己持有连接级状态：

- **租约**：认证成功后调用 `registry.reserve(&connection, stop)`，持有到连接结束。撤销（设备、用户、凭据、Grant、管理员断开）通过 `stop` 关闭所有通道。
- **目标连接**：第一个被接受的 shell 或 exec 请求触发 `connect_target`，结果放进一个共享的 `OnceCell`/`watch`。后续通道等待并复用同一个 handle；如果建立失败，该通道和后续通道都回复 failure，连接记为 `failed`。启动超时沿用 `limits.startup_timeout`。
- **激活**：第一个通道是 exec 时调用 `activate_native_connection`；shell 走录制激活（见第 2 节第 1 点）。
- **录制**：只在 shell 请求时才 `SessionRecording::prepare`，不能像现在这样无条件准备，否则只跑 exec 的连接会留下空录制。
- **授权轮询**：现在每秒一次的 `authorize` 在 `pump` 里，只覆盖 shell。改为连接级一个定时任务，失败就取消 `stop`。
- **空闲计时**：改为连接级的"最后活动时间"。shell 输入、exec 请求、exec 的 stdin 都要刷新它；输出不刷新。绝对时长 8 小时也在连接级计算。
- **结束**：shell 结束后其他通道继续运行。所有通道都结束、并且客户端关闭连接（或撤销）时，结束录制（如果有），然后状态迁移 `closing → closed`；异常结束迁移到 `failed`。具体规则写进 RFC 的"N2 实现说明"。
- **Drop**：`NativeHandler` 的 Drop 目前会把"已消费但没开始会话"的票据记为 failed。改造后要保证这一逻辑只在没有任何通道被接受时生效。

## 5. 通道分发（`NativeHandler`）

- 去掉 `channel_tx` 一次性 oneshot 和 `channel: Option<ChannelId>`，改成 `HashMap<ChannelId, ChannelKind>`，`ChannelKind` 取值为未定、Shell、Exec，以及留给 N3 的 Sftp。
- `channel_open_session`：已打开的 session 通道达到 16 个时，丢弃 `reply`（客户端收到 administratively prohibited）；否则接受，并把 `Channel` 交给连接任务。
- `auth_password` 第 283 行：删除"票据必须含 shell"的检查，改为在各个通道请求里逐个检查能力。
- `pty_request` / `shell_request`：票据没有 `shell`，或者这个连接已经开过 shell（整个生命周期），都回复 `channel_failure`，不关闭连接。其余逻辑沿用 N1。
- `exec_request`：票据没有 `exec` → `exec_rejected(PermissionDenied)` 并回复 failure。命令超过 64 KiB 或含 NUL → `exec_rejected(InvalidArgument)` 并回复 failure。否则交给 exec 任务，等目标端确认后再回复 success。
- `subsystem_request`：N2 中一律 failure。在这里留一个分发点：`name == "sftp"` 且票据含 `sftp` 时，交给 N3 的处理函数，传入客户端通道和共享的目标 handle。请在注释里写明文件和函数名，方便 N3 接入。
- `window_change_request`、`signal`、`env`、`x11`、各类转发和全局请求：沿用 N1 的处理。

**与客户端的约定**（ZeroTerm 已按此实现）：拒绝 exec 或子系统请求时回复 channel failure，通道和连接都保持打开。

## 6. exec 通道转发

- 在共享 handle 上开一个新的 session 通道，`exec(true, command)`，等目标的 Success；目标拒绝就 `exec_rejected(TargetRequestRejected)`，并向客户端回复 failure。
- 双向转发：
  - 客户端 data → 目标 stdin。客户端 EOF → 目标 EOF。
  - 目标 data → 客户端 data，目标 extended data（stderr, ext=1）→ 客户端 extended data。
  - 背压靠 SSH 窗口，中间缓冲有上限（参考 shell 的 `queue_bytes`），不能无界排队。
- 目标的 EOF、exit-status、exit-signal 在输出全部写给客户端之后再转发，然后关闭客户端通道。
- 统计 stdin、stdout、stderr 的字节数和耗时，结束时调用 `exec_completed`。被撤销或超时中断的命令也要写 `exec_completed`，这时 exit_status 和 exit_signal 都为空。
- exec 不录制。

## 7. 测试（`protocol/native_tests.rs`，进程内目标服务器）

- exec：输出、退出码、退出信号透传；stdin 透传到目标；超长和含 NUL 的命令被拒，并且有 `exec.rejected`；多个 exec 并发；`exec_completed` 的计数正确。
- 能力：票据没有 exec 时 exec 被拒，没有 shell 时 pty/shell 被拒，两种情况连接都还能继续用。
- 只有 exec 的票据：能用，连接被激活，没有录制。
- 多通道：同一连接上同时跑 shell 和多个 exec，录制里只有 shell 的输出；第 17 个通道被拒；第二个 shell（包括第一个 shell 结束之后再开）被拒。
- 先 exec 后 shell：录制能正常激活（验证第 2 节第 1 点）。
- 生命周期：exec 运行中撤销会断开整个连接；shell 结束后 exec 仍可用；服务端 drain 时所有通道都关闭。
- 浏览器路径和 N1 的现有测试全部通过，不改测试代码。
- PostgreSQL 套件：如果新增了存储函数，在 `crates/bastion-store/tests/native_sessions.rs` 补用例，并在临时集群上跑 `tests/pg_acceptance.py`（macOS 上要 `LC_ALL=C`，TMPDIR 放在 `/private/tmp` 下）。

## 8. 真实环境验证

环境：临时 PostgreSQL、在回环高端口运行的非特权 sshd 目标、开启 `BASTION_NATIVE_SSH_LISTEN` 的 `serve`、本机 TLS 前置。注意两点：TLS 前置必须给每个请求都加 `X-Forwarded-*`，或者强制 `Connection: close`；macOS 有系统代理，命令要加 `--noproxy '*'` 或 `-o ProxyCommand=none`。

1. 只有 exec 的票据：`ssh zt1:<id>@… 'echo hi; exit 5'`，输出正确，退出码为 5。
2. shell 加 exec 的票据：先用 `-o ControlMaster=yes -o ControlPath=…` 打开 shell，再用 `ssh -S <path> x uname` 在同一条连接上执行，结果正确。
3. 审计中有 `exec.completed`，字段完整；录制里只有 shell 的输出。
4. ZeroTerm CLI：`zeroterm exec '<资产名> · <账号>' 'uname -a'` 成功。
5. 结束后清理所有临时进程和目录。

## 9. 收尾

- 在 RFC-006 §14 下追加"N2 实现说明"，记录第 2 节和第 4 节的取舍；更新 RFC 状态行。
- `API.md`、`docs/openapi-web.json` 如有变化一并更新。
- Web 审计列表给 `exec.completed`、`exec.rejected`、`native.auth_failure` 加中文标签（`web/src/main.ts`），然后跑 `cd web && npm test`。
- 完成后进入 N3：把 `"sftp"` 加入 `NATIVE_CAPABILITIES`，在第 5 节留好的分发点上实现 §14.4 的 SFTP 代理。
