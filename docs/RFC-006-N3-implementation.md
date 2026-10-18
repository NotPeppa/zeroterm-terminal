# RFC-006 N3 实施清单：原生 SSH 入口的 SFTP

| 项目 | 内容 |
|---|---|
| 日期 | 2026-10-18 |
| 实施状态 | D1–D7 已落实，三项大文件门槛通过；验证记录见第 10 节，`production_ready` 仍为 false |
| 契约 | [RFC-006](./RFC-006-native-ssh-entry.md) §14.1、§14.2、§14.4、§14.5（与前文冲突时以 §14 为准） |
| 前置 | N1、N2-A、N2-B 已在工作区（[N2-B 清单](./RFC-006-N2B-implementation.md)）；ZeroTerm 客户端已按 §14 适配，不改 |
| 范围 | `sftp` 子系统代理、SFTP 审计、`sftp` 能力开放、验收。shell 与 exec 不动 |
| 基准 | 工作区里已经有一版 N3 实现：`protocol/sftp.rs`、`GatewayBackend::sftp_audit`、`PgStore::sftp_audit`、`NATIVE_CAPABILITIES` 含 `sftp`、Web 审计标签，RFC §14.6 写的是"已实现"。本清单以这版代码为准（行号按 2026-10-18 的工作区，可能有偏移），分为可直接复用、需要修改和尚未完成三类 |
| 决定 | D1–D7 已于 2026-10-18 全部拍板，见第 9 节；正文已按结论改写 |

## 0. 修复前的核对结论（历史记录）

- `cargo test -p bastion-gateway --lib`：45 个通过，2 个忽略。
- 可选测试 `real_openssh_exec_and_sftp_roundtrip`（一次性回环 sshd）：用现有 700 KB 载荷时通过。
- **历史阻断问题（本次已修复）**：把这个测试的载荷改成 8 MB 后，OpenSSH `sftp put` 失败。网关在第 6 个左右的 WRITE 之后关闭了 SFTP 通道（客户端报 `Control master terminated unexpectedly`）。同一测试加上 `sftp -R 3`（最多 3 个待响应请求）就能通过。
  - 原因：`sftp.rs` 把每个 WRITE 的数据保留到收到响应为止，用来计算"已确认数据"的哈希，保留总量超过 `4 × MAX_PACKET`（1 MiB）就当作畸形包关闭通道（`sftp.rs:392`、`:548`）。OpenSSH `sftp` 在目标通过 `limits@openssh.com` 告知 261120 字节的 write_len 后，默认最多保持 64 个待响应请求。对本机 sftp-server 实测，同时待响应的 WRITE 最多有 30 个，约 7.5 MiB。
  - ZeroTerm 的 FAST 档是 32 个并发写 × 128 KiB，约 4 MiB，按代码推断也会超过上限（没有实测）。
  - 现有测试只用 700 KB，低于阈值，所以发现不了这个问题。
- 结论：§14.5 要求的"上传"在常规文件大小下还不成立。`sftp` 已经提前加进了 `NATIVE_CAPABILITIES`。
- **已定（D1）：`sftp` 能力保持开放，不撤回；§3.3 的修复是 N3 的必做项。** 修复合入并通过第 6、7 节的大文件用例之前，这一版不得部署给用户使用（`production_ready` 本来就是 false）。
- **历史缺陷（本次已修复，以下为修复前现象）**：经网关的 SFTP 上传，只要客户端同时有超过约 1 MiB 的 WRITE 未确认，通道就会被关闭。OpenSSH `sftp` 默认参数下上传大于约 1 MiB 的文件即会触发；ZeroTerm FAST 档（32 × 128 KiB）按代码推断也会触发。临时绕过：OpenSSH 加 `-R 3`。小文件、列目录、下载、重命名、删除不受影响。

## 1. 直接复用的已有接口

- **共享目标连接**：`NativeContext::target()`（`native.rs:171`）。连接上第一个被接受的通道调用 `ssh::connect_target` 建立目标连接，之后所有通道复用。host key（含 rekey）、固定地址、凭据认证都不需要重写。
- **通道分发与启动**：`subsystem_request`（`native.rs:584`）只接受 `name == "sftp"` 且票据含 `sftp` 的请求，否则回复 channel failure，连接不断。通过的请求交给 `start_plain(channel, None)`（`:274`），再进入 `plain_session`（`:891`），依次 `authorize` → 在共享 handle 上开 session 通道 → `request_subsystem(true, "sftp")` → `ssh::accepted` → `activate_native_connection`。目标确认之后才回复客户端 success。启动失败时客户端通道交还给 handler，可以重新请求（符合客户端约定）。
- **连接级生命周期**：租约、每秒授权轮询、空闲（`ctx.activity`）和绝对时长、撤销与 drain 的 `stop`、16 个通道的上限、最后的 `closing → closed / failed`，全部沿用 N2-B。
- **激活**：`GatewayBackend::activate_native_connection`（`protocol.rs:75`）→ `PgStore::activate_native_connection`（`sessions.rs:221`）。幂等，只写一次 `connection.active`，不创建录制。
- **审计写入骨架**：`PgStore::exec_audit`（`sessions.rs:316`）。它从连接行读取 actor 和 login，拒绝非 `native_ssh` 连接，用 `bounded` 限制在 2 秒内，写入失败时记错误日志。`exec_completed` / `exec_rejected` 在它之上组装 payload。
- **文本清洗**：`audit_text`（`sessions.rs:509`）和 `EXEC_AUDIT_PREVIEW_BYTES` 的写法。jsonb 不能存 U+0000，所以 NUL 显示为 U+FFFD。
- **能力校验**：`validate_native_capabilities`（`bastion-domain/src/lib.rs:141`）。`/info.native.features` 和目录中的 `capabilities` 都由 `NATIVE_CAPABILITIES` 推导（`bastion-api/src/control/native.rs:70`、`:181`），不需要单独开关。
- **数据库**：`0001_control_plane.sql:34` 的 CHECK 已经允许 `sftp`。审计只写 `audit_events`，不需要改表结构。

## 2. 领域类型、存储函数、`GatewayBackend` 方法

现状：`GatewayBackend::sftp_audit(connection, action: &str, payload: Value)`（`protocol.rs:89`）由网关拼好 JSON。`PgStore::sftp_audit`（`sessions.rs:289`）只核对 action 白名单和"payload 是对象"，再注入 `connection_id`。这和 exec 的模式不一致：exec 由领域类型 `ExecOutcome` 携带数据，存储层负责组装和清洗 payload。按 exec 的模式改为：

- **领域类型**（`bastion-domain`，放在 `ExecOutcome` 旁边）：

  ```rust
  /// One SFTP audit row (RFC-006 §14.4); never carries file contents.
  pub enum SftpAudit {
      /// Mutations: setstat fsetstat remove mkdir rmdir rename symlink posix-rename hardlink.
      /// fsync is not a mutation (D6): it is only counted in `Session`.
      Operation { op: SftpOp, path: Vec<u8>, target_path: Option<Vec<u8>>, status: u32 },
      /// One file handle at CLOSE (status = Some(0)) or channel end (status = None), or a
      /// write-intent OPEN the target refused (status = Some(non-zero), zero bytes, no hashes; D7).
      File { path: Vec<u8>, flags: u32, status: Option<u32>, read_bytes: u64, write_bytes: u64,
             sha256: Option<String>, read_sha256: Option<String>, write_sha256: Option<String> },
      /// Channel end: per-request counts and channel bytes.
      Session { requests: BTreeMap<String, u64>, input_bytes: u64, output_bytes: u64 },
  }
  ```

  `SftpOp` 是枚举，`as_action()` 返回 `sftp.<op>`，不含 `fsync`。路径以原始字节传给存储层，由存储层清洗。

- **存储**：`PgStore::sftp_audit(&Connection, &SftpAudit)`。负责组装 payload（`connection_id`、`transport`、各字段），路径用 `audit_text(&String::from_utf8_lossy(..), 4096)` 处理，复用 `exec_audit` 写入。删除字符串白名单，改由类型保证（`sftp.fsync` 随之消失）。顺带把 `exec_audit` 失败日志里的 "exec audit not recorded" 改成带 action 的通用文案。
- **存储（D7）**：新增 `PgStore::sftp_rejected(&Connection, ErrorCode)`，动作 `sftp.rejected`，payload `{connection_id, transport, reason_code}`，写法与 `exec_rejected` 相同。
- **`GatewayBackend`**：
  - `sftp_audit(&Connection, &SftpAudit)` 替换现有签名。
  - 新增 `sftp_rejected(&Connection, ErrorCode)`。
  - 两者默认实现都返回 `Err(TargetProtocolUnavailable)`。需要同步修改 `bastion-server/src/control.rs:350` 附近的转发实现，以及 `native_tests.rs` 测试 backend 的记录结构（现在是 `(String, Value)`）。

## 3. SFTP v3 代理结构（`protocol/sftp.rs`）

### 3.1 接入

通道分发在第 1 节。`plain_session` 的 subsystem 分支调用 `sftp::run(connection, backend, client, upstream, stop, activity, stall)`（`native.rs:947`），返回后由 `plain_session` 关闭客户端通道。`run` 内部：

- 客户端和目标两个方向各开一个读取任务，用同一个 `Mutex<Proxy>` 保存协议状态。锁只在解析时持有，任何 await 期间都不持有。
- 写给客户端的数据（目标的响应和本地生成的 STATUS）走同一把 `tokio::sync::Mutex`，保证两个 SFTP 帧不会在 SSH 数据包层面交错。
- 结束条件：`stop` 被取消，或者任一方向出错或 EOF。客户端 EOF 后再等目标最多 `stall`（30 秒）把剩余响应送完。之后关闭上游通道，写 `finish()` 汇总的 `sftp.file`（未关闭的句柄，status 为 null）和 `sftp.session`。

**被拒的子系统请求（D7）**：以下情况调用 `sftp_rejected`，然后照旧回复 channel failure、保留客户端通道：

| 位置 | 情况 | `reason_code` |
|---|---|---|
| `subsystem_request`（`native.rs:584`） | `name == "sftp"` 但票据没有 `sftp` | `PERMISSION_DENIED` |
| `plain_session` 的启动失败分支（`native.rs` 中 `exec_rejected` 旁） | 授权失败、目标拒绝开通道或子系统、启动超时、撤销 | 对应的 `ErrorCode`（如 `TARGET_REQUEST_REJECTED`、`TARGET_TIMEOUT`） |

`name != "sftp"` 的其他子系统名仍按 N1 直接拒绝，不写审计（与 x11、agent 等请求一致）。

### 3.2 转发与解析

- **分帧（D3）**：`packet()` 读 4 字节长度 `n`，`n == 0` 或 `n > 262144` 判为畸形，即 256 KiB 上限**不含**长度前缀，与 OpenSSH `SFTP_MAX_MSG_LENGTH` 一致。帧缓冲最大 256 KiB + 4 字节。在包边界上 EOF 是正常结束，读到半包是畸形。现在的判断是 `n + 4 > MAX_PACKET`（`sftp.rs:590`），改为 `n > MAX_PACKET`。
- **请求**：`Proxy::request` 先要求 INIT 版本为 3，再要求已收到目标的 VERSION。然后校验请求 ID 不重复、未完成请求不超过 128 个、字段完整且没有多余字节，并为 OPEN/CLOSE/READ/WRITE/修改类/元数据/扩展各记一条待响应记录。§14.4 白名单之外的扩展由网关直接回复 `SSH_FX_OP_UNSUPPORTED`（状态码 8），不转发给目标。其他合法包原样转发。
- **VERSION 过滤（D2）**：目标的 VERSION 包是唯一被网关改写的包。网关解析扩展列表，只保留 §14.4 白名单里的 6 个：`posix-rename@openssh.com`、`statvfs@openssh.com`、`fstatvfs@openssh.com`、`fsync@openssh.com`、`hardlink@openssh.com`、`limits@openssh.com`，名字和版本数据原样保留、顺序不变，然后重新计算长度发给客户端。目标没有公告的扩展，网关也不会补上。客户端如果仍然发送未公告的白名单扩展，照常转发给目标，由目标回复。改写后的长度不会超过原包。
- **响应**：`Proxy::response` 先要求版本为 3，然后按 ID 找到对应请求，校验响应类型与请求是否匹配（例如 STAT 只能返回 ATTRS 或 STATUS），再更新句柄表和 I/O 账目，产生审计条目。除 VERSION 外，响应包原样转发。
- **审计时机（D4：best-effort）**：响应先写审计（每批最多 2 秒，`sftp.rs:601`），再转发给客户端。这样审计顺序和响应顺序一致，存储慢时也会自然限速。审计写入失败只记错误日志，不影响转发，也不改变返回给客户端的状态。
- **畸形处理**：只关闭这个 SFTP 通道，连接和其他通道不受影响（RFC §14.6 的偏差说明，已有测试覆盖）。

### 3.3 必须修复：WRITE 数据不再保留

问题见第 0 节。这是 N3 完成的前提（D1 已定：能力保持开放，由本项修复兜底）。改法：

- WRITE 的数据在**请求转发时**就按请求顺序更新 `write` 哈希、偏移连续性和字节数，不再保留数据本身。`File` 只记录 `issued`、`acked_ok`、`failed` 三个计数和偏移是否连续。
- 收到 WRITE 的 STATUS 时只记成功或失败。`write_sha256` 只在所有 WRITE 都被确认成功、并且从偏移 0 连续写入时才给出，否则为 null。这和"已确认数据的哈希"等价：哈希只在全部成功时才声明，而顺序上传时请求顺序就是偏移顺序。
- `write_bytes` 仍然只统计确认成功的字节数（每个 WRITE 的长度在请求时记下，响应时按状态累加）。
- READ 的数据在响应里，乱序时仍然需要缓冲。保留 1 MiB 的乱序缓冲，**超出时把 read 哈希标为不连续并丢弃缓冲，不关闭通道**：传输本身没有问题，不应该因为审计记账而中断。OpenSSH sftp-server 按顺序回复，实际很少触发。
- 改完后 `retained` 只统计乱序 READ。每个通道的内存上限变为 2 个 256 KiB 帧缓冲、1 MiB 乱序缓冲，再加 128 条待响应记录和 1024 个句柄（句柄不超过 256 字节、路径不超过 4096 字符）的元数据。

### 3.4 背压

- **客户端到目标**：读取任务一次只解析一个包，然后 `to_target.data_bytes(..)` 等待目标窗口（最长 `stall`）。在此期间不再读取客户端通道。
- **目标到客户端**：先写审计，再 `to_client.data_bytes(..)` 受客户端窗口和 `stall` 约束。
- **已知限制（D5：N3 接受）**：russh 服务端在数据**到达时**就补充接收窗口（`server/encrypted.rs`，`adjust_window_size`），再 `await` 投递到每通道容量为 16 的 mpsc。所以 SSH 窗口无法把压力传回客户端：一个 SFTP 通道写目标写得慢，会占满自己的 mpsc，进而阻塞整个 SSH 连接的入站处理，同一连接上的 shell 和 exec 都会停顿，最长到 `stall`（30 秒）后该 SFTP 通道被关闭。内存始终有界。exec 通道有同样的问题。N3 不修，写进 RFC §14.6；第 7 节第 5 步测量实际延迟并记录。如果延迟明显，另外立项做每通道接收配额，exec 一起改。

### 3.5 限制汇总

| 项 | 值 | 超出时 |
|---|---|---|
| 单包 | 长度字段 ≤ 256 KiB，不含 4 字节前缀（D3） | 关闭该 SFTP 通道 |
| 待响应请求 | 128 / 通道 | 关闭该通道 |
| 打开句柄 | 1024 / 通道，句柄 ≤ 256 B | 关闭该通道 |
| 乱序 READ 缓冲 | 1 MiB / 通道 | 修复后：read 哈希置 null，通道继续 |
| READ 请求长度 | ≤ 256 KiB；响应数据不得超过请求长度 | 关闭该通道 |
| OPEN 标志 / 属性标志 | `flags & !63 == 0`；`attrs & !0x8000000f == 0` | 关闭该通道 |
| 审计批次 | 2 秒 | 记错误日志，继续（D4） |
| 单次写停滞 | `stall_timeout`（30 秒） | 关闭该通道 |
| 通道数 | 每连接 16 个 session 通道（含 shell/exec） | 第 17 个通道打开被拒 |

## 4. 审计（逐项对应 §14.4）

| §14.4 条款 | 实现 | 状态 |
|---|---|---|
| 动作 `sftp.<op>`，含 `connection_id`、路径、目标状态码 | 存储层注入 `connection_id`；修改类和 `sftp.file` 带 `status` | 已有；按第 2 节改为类型化，并补 `transport` 字段与 exec 对齐 |
| 修改类每次一条：`SETSTAT FSETSTAT REMOVE MKDIR RMDIR RENAME SYMLINK` | `Request::Mutation`，收到响应时写，`status` 取目标的值。FSETSTAT 的路径从句柄表反查；RENAME/SYMLINK 另带 `target_path` | 已有 |
| 修改类扩展 | `posix-rename@openssh.com`、`hardlink@openssh.com`（path + target_path），逐条审计 | 已有 |
| `fsync@openssh.com`（D6） | 不是修改类：只计入 `sftp.session` 的 `requests["fsync@openssh.com"]`，不写单条 | **要改**：`sftp.rs:357-370` 的 fsync 分支改为 `Request::Extension`，删掉 `sftp.fsync` 动作 |
| `sftp.file`：CLOSE（或通道结束）时一条，含路径、打开标志、读/写字节数 | CLOSE 返回成功时写，status 为 0；通道结束时未关闭的句柄写一条，status 为 null。CLOSE 失败时句柄保留，到通道结束再写 | 已有 |
| 写类 OPEN 被目标拒绝（D7） | OPEN 标志含 `WRITE(0x02)`、`APPEND(0x04)`、`CREAT(0x08)`、`TRUNC(0x10)` 中任意一个，且目标回复非 0 STATUS 时，写一条 `sftp.file`：`status` 为目标状态码，字节数为 0，三个哈希均为 null。只读 OPEN 和 OPENDIR 失败不写，只计数 | **要加**：`sftp.rs:472` 一带的 OPEN 失败分支 |
| 读写都从偏移 0 连续进行时附 SHA-256，否则为 null | `sha256` 遵循此规则；另有 `read_sha256` / `write_sha256` | 已有；要做 §3.3 的修复。读写混用的句柄 `sha256` 取写侧（`sftp.rs:163`），写进 RFC |
| 只读元数据不逐条审计，通道结束时汇总为 `sftp.session`（请求计数、通道字节数） | `counts` 统计所有请求（包括修改类和扩展名），`input_bytes` / `output_bytes` 是整帧字节数 | 已有。`fstatvfs` 不在 §14.4 的只读列表里，目前计入 session；目录句柄只计数 |
| 其他扩展回复 OP_UNSUPPORTED，不转发 | 本地 STATUS 8；不计入 `counts`。VERSION 只公告白名单扩展（D2） | 本地回复已有；**VERSION 过滤要加**（§3.2） |
| 被拒的 `sftp` 子系统请求（D7，§14.4 未要求，按 exec 对齐） | `sftp.rejected`，见 §3.1 | **要加** |
| 不做路径白名单 | 不做 | 已有 |

补充要点：

- 不记录文件内容，也不录制 SFTP。
- **D4：审计为 best-effort。** 写入失败不影响传输，错误日志带 connection id 和 action。丢审计的窗口是有界的：连接级每秒做一次授权检查（`authorize` → `store.authorize_connection`，同样限时 2 秒），数据库不可用时这次检查失败，整个连接被关闭。所以存储故障时，最多约 3 秒内的 SFTP 操作可能没有审计记录。这一点写进 RFC §14.6。如果以后合规要求 fail-closed，单独立项，exec 一起改。
- 审计里的路径是显示用文本（lossy UTF-8，最多 4096 字符，NUL 替换为 U+FFFD）；线上数据包保持原样。

## 5. 把 `"sftp"` 加入 `NATIVE_CAPABILITIES`

现状：已经加上了（`bastion-domain/src/lib.rs:138`），而且 `/info.native.features.sftp` 和目录中的 `capabilities` 会随之自动打开。

**已定（D1）：保持开放，不撤回。** 常量、`0001` 的 CHECK、相关测试和文档都不动。代价是"网关真正能用时才加"这一条暂时不成立，由以下发布门槛补上，三项都通过之前这一版不交付使用：

1. §3.3 的修复合入。
2. 第 6 节新增的 ≥ 8 MB 上传/下载用例（进程内和真实 OpenSSH 两种）通过，且 OpenSSH 使用默认的 `-R` 并发。
3. 第 7 节的 ZeroTerm CLI `put` / `get` ≥ 8 MB 通过。

备查（如果之后改主意要撤回）：把常量改回 `["shell","exec"]`；`0001` 的 CHECK 不动；同步回退 `bastion-domain` 能力子集用例（`lib.rs:445-459`）、`bastion-store/tests/native_sessions.rs:233-236` 与 `:803`、`bastion-api/src/control/tests.rs:255-257`、`web/tests/asset-create.mjs:405`，以及 `API.md:158-160`、`:172-173` 和 `openapi-web.json` 中的 `["shell","exec","sftp"]`。网关不用改。

## 6. 测试

### 6.1 单元测试（`sftp.rs` 内）

已有：顺序上传/下载哈希与乱序响应、随机偏移/失败写入/中断不声明哈希、修改类与元数据审计、OP_UNSUPPORTED 与支持的扩展、畸形版本/属性/ID/响应类型、分帧（超长、截断、碎片）、待响应请求与保留上限。

需要调整的已有用例：

- `outstanding_request_and_retained_payload_limits_are_enforced`（`sftp.rs:863`）：4 个大 WRITE 后第 5 个被拒的断言，按 §3.3 改为"不被拒"，保留上限只针对乱序 READ。
- `frame_reader_rejects_oversize_truncation_and_accepts_fragmentation`：按 D3 的新口径调整边界。

新增：

- 64 个待响应的 261120 字节 WRITE，依次确认后哈希正确、通道不关闭（**修复前应失败**）。
- 中途有一个 WRITE 失败：`sha256` 为 null，`write_bytes` 只计成功的部分。
- 乱序 READ 超过 1 MiB：read 哈希为 null，不返回错误。
- CLOSE 返回非 0：句柄保留，`finish()` 输出 status 为 null 的 `sftp.file`。
- D3 包长边界：长度字段等于 262144 通过；262145 判为畸形。
- D2 VERSION 过滤：输入本机 sftp-server 的 11 个扩展，输出只剩白名单里的 6 个，名字、版本数据、顺序不变，长度字段正确；没有扩展的 VERSION 原样通过；扩展字段截断判为畸形。
- D6：`fsync@openssh.com` 请求和成功响应不产生审计，`finish()` 的 `requests` 里有它的计数。
- D7：写类 OPEN（`CREAT|WRITE|TRUNC`）收到 STATUS 3 时产生 `sftp.file`，`status` 为 3、字节数为 0、哈希为 null；只读 OPEN 收到 STATUS 2 时不产生审计。
- 类型化之后：`SftpAudit` 到 payload 的字段映射（这部分可以放到存储层单元测试）。

### 6.2 进程内目标服务器（`protocol/native_tests.rs`）

现在测试目标的 SFTP 桩（`native_tests.rs:129-170`）只会回 VERSION，其余请求一律回 STATUS OK，无法验证文件内容。把它扩展成最小的内存文件系统：OPEN/WRITE/READ/CLOSE/STAT/REMOVE/RENAME/MKDIR，READ 支持 EOF；VERSION 公告几个白名单内外的扩展（用于 D2）；可以按路径配置 OPEN 返回 PERMISSION_DENIED（用于 D7）。不引入新依赖。

已有：shell + exec + sftp 同连接（`:1116`）、畸形包只关闭该通道 + 无 sftp 能力被拒且通道可继续用（`:1506`）、真实 OpenSSH 往返（`:1248`，忽略测试）。`:1116` 里对 VERSION 字节的精确断言要随 D2 调整。

新增：

- 只有 sftp 的票据：连接被激活，没有录制，`connection.active` 只写一次。
- 网关上 8 MiB 流水线上传（64 个待响应请求）和顺序下载，`sha256` 与内容一致，且 `sftp.file` 的字节数正确。
- 客户端收到的 VERSION 只含白名单扩展（D2）。
- 上传到目标拒绝写的路径：客户端收到原样的 PERMISSION_DENIED，审计有一条 `sftp.file`，status 为 3（D7）。
- 传输中撤销：通道关闭，写出 status 为 null 的 `sftp.file` 和 `sftp.session`，连接进入 `failed`。
- 传输中 drain：所有通道在 `serve_native` 的 9 秒内结束。
- 审计 backend 很慢（`sftp_audit` 睡 5 秒）：每批最多耗时 2 秒，通道和 drain 仍能按时结束。
- 审计 backend 返回错误：传输照常完成，客户端收到的状态不变（D4）。
- SFTP 请求刷新空闲计时（参照 `exec_stdin_activity_refreshes_connection_idle_deadline`）。
- 16 个通道里含 SFTP 时，第 17 个被拒；关掉一个 SFTP 通道后可以再开。
- `sftp.rejected`（D7）：无 sftp 能力时 reason 为 `PERMISSION_DENIED`；测试目标拒绝子系统时 reason 为 `TARGET_REQUEST_REJECTED`；两种情况下客户端通道都还能继续用；`name="foo"` 的子系统请求不写审计。
- `real_openssh_exec_and_sftp_roundtrip`：载荷从 700 KB（`:1377`）提高到 ≥ 8 MB；批处理里加上 `reput` / `reget`（续传从非 0 偏移开始，`sha256` 应为 null）和 `ls -l`。D2 之后客户端不会再发 `users-groups-by-id@openssh.com`，断言 stderr 里没有 `Operation unsupported`；断言审计里没有 `sftp.fsync`（D6）。注意：macOS 的 ControlPath 长度上限是 104 字节，TMPDIR 要短（例如 `/private/tmp/zt3`），否则 ControlMaster 起不来。

运行：

```sh
TMPDIR=/private/tmp cargo test --workspace
BASTION_NATIVE_OPENSSH_FIXTURE=<fixture.json> TMPDIR=/private/tmp/zt3 \
  cargo test -p bastion-gateway --lib real_openssh_exec_and_sftp_roundtrip -- --ignored --nocapture
```

### 6.3 PostgreSQL 套件（`crates/bastion-store/tests/native_sessions.rs`）

现在只有一条 `sftp.file`（`:847`）。补充：

- 每种 `SftpAudit` 变体各写一条，核对 action、`connection_id`、`transport`、字段和 `resource_type=connection`。`File` 覆盖三种 status：0、null、非 0（D7）。
- `sftp_rejected`：payload 为 `{connection_id, transport, reason_code}`（D7）。
- 路径含 NUL、非 UTF-8 或超过 4096 字符时被清洗，写入不失败（jsonb 不能存 U+0000）。
- payload 不能伪造 `connection_id`：即使传入别的值，最终也以连接 id 为准。
- websocket 连接被拒（`InvalidArgument`）；连接不存在返回 `ResourceNotFound`。
- 用户被删除后仍能写，actor 取连接行上的值。

在临时集群上跑全部八套（`tests/pg_acceptance.py` 已包含 `native_sessions`）：

```sh
export LC_ALL=C
initdb -D /private/tmp/zt-pg/data -U postgres --auth=trust
pg_ctl -D /private/tmp/zt-pg/data -o "-p 55432 -k /private/tmp/zt-pg -c listen_addresses=''" -l /private/tmp/zt-pg/log start
umask 077; echo 'postgres://postgres@%2Fprivate%2Ftmp%2Fzt-pg:55432/postgres' > /private/tmp/zt-pg/url
TMPDIR=/private/tmp python3 tests/pg_acceptance.py --database-url-file /private/tmp/zt-pg/url
pg_ctl -D /private/tmp/zt-pg/data stop && rm -rf /private/tmp/zt-pg
```

## 7. 真实环境联调

环境与 [N2-B 第 8 节](./RFC-006-N2B-implementation.md) 相同：临时 PostgreSQL、在回环高端口运行的非特权 sshd 目标（`Subsystem sftp /usr/libexec/sftp-server`）、开启 `BASTION_NATIVE_SSH_LISTEN` 的 `serve`、本机 TLS 前置。注意事项：

- TLS 前置必须给每个请求都加 `X-Forwarded-*`，或者强制 `Connection: close`。
- macOS 有系统代理：`curl` 加 `--noproxy '*'`，`ssh` / `sftp` 加 `-o ProxyCommand=none`。
- ControlPath 放在短路径下。
- 票据通过 `curl --noproxy '*' -H 'Authorization: Bearer …' POST /api/v1/native/connection-tickets` 申请，30 秒内使用；`ticket_secret` 通过 `SSH_ASKPASS` 提供。

系统 `sftp` 客户端：

1. 只有 sftp 的票据：`sftp -o ProxyCommand=none -o User=zt1:<id> -P <port> <host>`，依次执行 `ls`、`put` 一个 8 MB 和一个 1 KB 文件、`get`、`rename`、`rm`、`mkdir`、`rmdir`，全部使用默认 `-R`。用 `shasum -a 256` 比对 `sftp.file.sha256`。
2. `reput` / `reget` 续传：`sha256` 为 null，`read_bytes` / `write_bytes` 只计续传部分。
3. 扩展（D2）：`sftp -vv` 的输出里只出现 6 个白名单扩展；`ls -l` 显示数字 uid，没有 `Operation unsupported`；`cp a b` 由客户端在本地提示服务器不支持 copy-data，连接不断。
4. 权限拒绝（D7）：`put` 到目标账号没有写权限的目录，客户端报 Permission denied，审计里有一条 status 为 3 的 `sftp.file`。
5. 只有 exec 的票据：`sftp` 报 subsystem request failed，审计里有 `sftp.rejected`（`PERMISSION_DENIED`）。用 ControlMaster 确认同一连接上 exec 仍可用。
6. ControlMaster 下 shell + exec + sftp 同时使用：录制里只有 shell 输出。传 8 MB 期间在 shell 里敲字，**记录回显延迟**，写进 RFC §14.6（D5）。
7. 传输中由管理员断开：sftp 客户端报错，审计里有 status 为 null 的 `sftp.file` 和 `sftp.session`，连接为 failed。

ZeroTerm CLI（`zeroterm bastion` 导入配置、登录、选资产，收藏名为 `<资产名> · <账号>`）：

8. `zeroterm sftp ls '<名>' .`、`put '<名>' ./8mb.bin /tmp/8mb.bin`、`get '<名>' /tmp/8mb.bin ./back.bin`、`mv`、`rm`、`mkdir`，全部成功，`back.bin` 与原文件一致，审计中的 `sha256` 与文件一致，审计里没有 `sftp.fsync`（D6）。
9. 只有 exec 能力的账号，CLI 隐藏 sftp 提示（`no_shell_hint`）；强行执行 `zeroterm sftp` 时得到明确错误，不重试。
10. 结束后清理所有临时进程和目录（sshd、serve、TLS 前置、PostgreSQL、ControlPath）。

已知干扰项：macOS 自带的 sftp-server 上，`cd ~` 不经过网关也会失败（`stat remote: No such file or directory`），不要算作网关问题。

## 8. 收尾

- **RFC-006**：
  - 状态行和 §14.6 目前写的是"N3 已实现"，以及"700 KB 验证"。在第 0 节的问题修复、第 7 节通过之前，改成"N3 实现中"。
  - §14.4 修订：VERSION 只公告白名单扩展，这是"不改写合法数据包"的唯一例外（D2）；单包 256 KiB 不含长度前缀（D3）；`fsync@openssh.com` 不算修改类扩展，只计入 `sftp.session`（D6）；新增 `sftp.rejected`，以及写类 OPEN 被拒时的 `sftp.file`（D7）。
  - §14.6 补充：§3.3 的做法；审计为 best-effort，存储故障时最多约 3 秒的丢审计窗口（D4）；慢 SFTP 写会拖慢同连接其他通道的已知限制和第 7 节第 6 步的实测延迟（D5）；读写混用句柄的 `sha256` 取写侧。
- **`crates/bastion-api/API.md`**：`:196-199` 补充 `sftp.file` 的 `read_sha256` / `write_sha256`、三种 status 的含义、乱序 READ 超限时哈希为 null、VERSION 过滤、包长口径、fsync 只计数、`sftp.rejected`、best-effort 审计。
- **`docs/openapi-web.json`**：没有审计动作枚举，能力描述也不变（D1 保持开放），无需修改。
- **Web**：`web/src/main.ts:865-867`：新增 `'sftp.rejected': 'SFTP 被拒绝'`，删除 `'sftp.fsync'`。然后跑 `cd web && npm test && npm run check`。
- **README.md:23**：仍写着"明确不做：原生 SSH 入口、SFTP/文件管理"，与 RFC-006 冲突，需要改。`deploy/docker.md` 的原生入口段落顺带写上 SFTP。
- 全部测试通过后，确认第 5 节的三项发布门槛都已满足。

## 9. 已定事项（2026-10-18）

| # | 问题 | 结论 | 落实位置 |
|---|---|---|---|
| D1 | `sftp` 已在 `NATIVE_CAPABILITIES` 里，但 >1 MiB 的上传会失败 | 保持开放，不撤回。§3.3 必须修复，第 5 节三项门槛通过前不交付使用 | §0、§3.3、§5 |
| D2 | 目标 VERSION 公告了网关会拒绝的扩展 | 过滤 VERSION，只保留 §14.4 白名单里的 6 个扩展；这是唯一被改写的包，RFC 写明例外 | §3.2、§4、§6、§7 第 3 步、§8 |
| D3 | 256 KiB 单包上限是否含 4 字节长度前缀 | 不含，与 OpenSSH `SFTP_MAX_MSG_LENGTH` 一致 | §3.2、§3.5、§6.1 |
| D4 | 审计写不进去时怎么办 | best-effort，与 exec、`native.auth_failure` 一致；丢审计窗口约 3 秒，写进 RFC。fail-closed 如有需要另行立项，exec 一起改 | §3.2、§4、§6.2、§8 |
| D5 | 慢 SFTP 写会拖慢同连接的 shell 和 exec | N3 接受，写进 RFC 作为已知限制；联调时实测延迟并记录，明显时再立项，exec 一起改 | §3.4、§7 第 6 步、§8 |
| D6 | `fsync@openssh.com` 是否逐条审计 | 不逐条审计，只计入 `sftp.session`；删除 `sftp.fsync` 动作和 Web 标签。`posix-rename`、`hardlink` 仍逐条审计 | §2、§4、§6、§8 |
| D7 | 被拒的子系统请求和失败的写类 OPEN 没有审计 | 新增 `sftp.rejected`（`reason_code`）；写类 OPEN 被目标拒绝时写一条 status 非 0、字节数为 0 的 `sftp.file`；只读 OPEN 失败只计数；非 `sftp` 的子系统名不审计 | §2、§3.1、§4、§6、§7 第 4–5 步、§8 |

## 10. 实现与验收结果（2026-10-18）

D1–D7 已落实，保留 `sftp` 能力开放；未修改客户端或新增迁移。类型化 `SftpAudit` / `SftpOp` 贯穿网关、Backend 和存储，路径清洗、连接/transport/actor 绑定由存储负责。WRITE 不再保留载荷；64 个 261120 B WRITE 同时待确认的回归通过，ACK 失败或未完成时哈希为 null。乱序 READ 超过 1 MiB 时继续传输并放弃读哈希。VERSION 仅公告六个白名单扩展，256 KiB 不含长度前缀。fsync 只计数；缺少能力、目标拒绝子系统和写类 OPEN 失败均有约定审计。

额外修复 CLOSE / disconnect 竞态：目标 CLOSE 响应已经从句柄表移除文件、但正在写审计时，SSH 关闭曾会取消该审计。现在在关闭 I/O 后等待正在执行的审计批次在两秒预算内完成，再写最终 file/session 汇总；新增确定性回归验证审计顺序和不丢文件事件。

| 验证 | 结果 |
|---|---|
| Rust 工作区 | 全部非 ignored 用例通过；网关 54 通过、2 ignored。环境依赖用例另行执行，不将 ignored 算作通过 |
| 严格 lint | `cargo clippy -p bastion-gateway -p bastion-store --all-targets -- -D warnings` 通过 |
| Web | 166 项测试及 `npm run check` 通过；新增 sftp.rejected 中文标签，删除 sftp.fsync |
| PostgreSQL | 临时集群八套隔离测试通过；包含类型化 payload、三种 file status、路径清洗、错误 transport/缺失连接、用户删除后的审计 |
| 进程内 SFTP | 8 MiB、64 请求上传和下载，正确哈希/计数；能力/版本过滤、权限拒绝、撤销/drain、慢审计/失败审计、空闲、通道上限与 CLOSE 收尾竞态通过 |
| 真实 OpenSSH | 默认请求并发的 8 MiB 上传/下载、1 KiB 文件、reput/reget、ls -l、rename/rm/mkdir/rmdir、拒绝写路径均通过；顺序传输的哈希正确，续传只计续传字节且哈希 null，无 Operation unsupported |
| 真实 ZeroTerm CLI | 独立临时 Vault，私有 CA 严格校验，通过 bastion 导入/登录/选账号及 sftp ls/put/get/mv/rm/mkdir；8 MiB 上传/下载文件及独立的两条读/写文件审计哈希一致，无 sftp.fsync |
| 连接级拒绝与撤销 | exec-only 票据的 sftp 被拒且写 sftp.rejected，同一 ControlMaster 仍能 exec；上传中管理员断开后连接 failed，unfinished file 与 session 审计存在 |
| 清理 | 所有自建 sshd、serve、TLS 前置、PostgreSQL、临时 Vault、密钥、测试文件和 ControlPath 均清理；用户已有 Vault/配置/信任与桌面会话未改动 |

D5 回显测量：健康回环目标上，混合 shell + exec + SFTP 上传 8 MiB，9 次样本，中位数 29.516 ms、最大 35.674 ms，整个传输 0.479 秒。未模拟慢目标，不能据此推导最坏延迟；russh 的跨通道停顿限制仍保留。

8 MiB 载荷的 SHA-256：`bdf23837181f5808331800c1ae2b4f7d7a839536b10d58491471c50dde23833a`。第 5 节三项门槛（修复、进程内与默认 OpenSSH 大文件、真实 ZeroTerm CLI put/get 大文件）均通过。

当前 Grant 全有或全无且服务端同时公告三种能力，无法创建“只授 exec 的账号”；因此第 7 节第 9 项由真实 exec-only 票据的拒绝/复用验证及现有 CLI `no_shell_hint` 单元用例覆盖，不增加能力授权字段。未进行桌面手工、两个目标及浏览器并行等整体发布验收，`production_ready=false`。

复跑（本地需 PostgreSQL/OpenSSH/OpenSSL，以及已构建的客户端）：

```sh
cargo build -p bastion-server
TMPDIR=/private/tmp cargo test --workspace
python3 tests/native_sftp_acceptance.py --zeroterm /path/to/zeroterm --gateway-test --pg-suites
```

可复用的一次性联调器为 `tests/native_sftp_acceptance.py`。它通过 HTTPS/Cookie/CSRF 创建资产及账号、Bearer 申请票据，再运行真实客户端。输出 `target/native-sftp-evidence.json`（含 CLI 独立读写审计）和可选的 `--evidence` 路径；日志不记录密码、票据 secret 或 token。每次运行创建独立临时目录，成功和失败均清理自建服务与私密文件。补充的 OpenSSH 扩展/混合通道结果保存在 `target/native-sftp-openssh-evidence.json`，均为本次本地生成产物。
