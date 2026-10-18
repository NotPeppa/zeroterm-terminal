# RFC-006：ZeroTerm 原生 SSH 入口

| 项目 | 内容 |
|---|---|
| 状态 | N1 / N2 / N3 服务端已实现，N3 大文件门槛已通过（实现说明见第 13、14.6 节；`production_ready` 仍为 false） |
| 日期 | 2026-10-18 |
| 适用对象 | 堡垒机后端、ZeroTerm 客户端、运维与测试人员 |
| 修订 | [RFC-005](./RFC-005-guacamole-browser.md)、[SSH 终端契约](./ssh-xterm.md) 中“无原生 SSH 监听、无 native client_type、无 transport 枚举”的条款 |
| 不修订 | 浏览器登录、Cookie/Origin/CSRF、`POST /sessions`、WebSocket 流、RDP/VNC、录制格式 ZTREC002 |

## 1. 目标

堡垒机的主要用途是让 ZeroTerm 通过标准 SSH 使用授权资产：

```
浏览器  ── HTTPS/WebSocket (bastion.ssh.v1) ──┐
                                              ├─ 同一准入事务 ─ ssh.rs ─ 目标 SSH
ZeroTerm ── SSH (zt1:<ticket_id>) ───────────┘
```

两个入口共用一条准入和审计链路：精确 Grant、revision 快照、网络策略、目标 host key 校验、强制录制、撤销与连接数限制。区别只在客户端到堡垒机这一段，以及认证令牌的载体。浏览器入口保持不变。

非目标：ProxyJump、端口转发、SOCKS、Agent/X11 转发、目标直连、端到端加密、多节点。网关终止 SSH，能读取和录制会话，这一点与浏览器入口相同。

## 2. 分阶段

| 阶段 | 能力 | 录制/审计 | 发布门槛 |
|---|---|---|---|
| N1 | 交互 shell（pty-req + shell） | 复用现有 SSH 录制，Web 回放可直接播放 | 本 RFC 第 9 节验收 |
| N2 | exec | 每条命令审计 command、退出码、字节数，不录输出 | 第 14 节 |
| N3 | SFTP | 文件操作审计（路径、操作、字节数、SHA-256） | 第 14 节 |

N1 契约见第 3–9 节，N2/N3 契约见第 14 节；第 14 节与前文冲突处以第 14 节为准。

## 3. 原生认证

### 3.1 路由隔离

新增前缀 `/api/v1/native/`，与浏览器路由互不放宽：

- `/api/v1/native/*` 只接受 `Authorization: Bearer <access_token>`，忽略所有 Cookie，不要求 Origin/CSRF，不返回 CORS 头。
- 浏览器路由保持现状：只认 Cookie，携带 `Authorization` 一律拒绝。
- 不在同一路由上按请求头分支。`browser.rs` 中“API has no native/Bearer branch”的约束继续对浏览器路由成立。

| 路由 | 认证 | 说明 |
|---|---|---|
| `GET /info` | 无 | 共用，新增 `native` 块（第 6 节） |
| `POST /native/auth/login` | 无 | `{username,password,device_label}`，严格字段 |
| `POST /native/auth/refresh` | 无 | `{refresh_token}` |
| `POST /native/auth/logout` | Bearer | 撤销当前 login family |
| `GET /native/assets`、`GET /native/assets/{id}` | Bearer | 第 5 节 |
| `POST /native/connection-tickets` | Bearer | 第 4 节 |
| `GET /native/connections/{id}` | Bearer | 仅本人连接，用于读取 `failure.code` |

### 3.2 令牌

- 登录响应 `{access_token,refresh_token,access_expires_at}`，access 10 分钟，refresh 最长 7 天，与浏览器登录同一策略。令牌只出现在响应体里，服务端只存哈希（现有 `access_tokens`/`refresh_tokens`）。
- `login_sessions` 增加 `client_type`（`web | native`）。原生令牌不能用于浏览器路由，浏览器 Cookie 不能用于原生路由，`binding()` 校验类型一致。
- refresh 轮换与重放检测沿用现有 login family 语义：旧 refresh 被重放时撤销整个 family。
- 登录失败计数、用户名限流与浏览器登录共享。
- `/me/sessions` 同时列出两类设备，浏览器端可以撤销原生设备，撤销立即断开该 login 绑定的原生连接。

## 4. 连接票据

### 4.1 签发

`POST /api/v1/native/connection-tickets`

```json
{"asset_id":"UUID","account_id":"UUID","capabilities":["shell"]}
```

- 复用 `issue_web_session` 的事务：`binding()`、待用票据上限、`connection_limits()`、revision 冻结、`ticket.issued` 审计。实现上抽出 `issue_ticket(transport, …)`，Web 与原生各自包装。
- 只允许 `protocol=ssh` 的资产，其他返回 `PERMISSION_DENIED`。
- `capabilities` 必填，N1 只接受 `["shell"]`；未知或尚未开放的能力返回 `INVALID_ARGUMENT`。不接受 `purpose` 字段。
- 并发与待用票据上限与浏览器连接合并计算，不另开额度。

响应（字段沿用 ZeroTerm 现有 `Ticket` 结构）：

```json
{
  "protocol_version": 1,
  "ticket_id": "UUID",
  "ticket_secret": "<≥32 字节随机数的 base64url>",
  "connection_id": "UUID",
  "gateway": {"host": "bastion.example.com", "port": 2222, "username": "zt1:<ticket_id>"},
  "capabilities": ["shell"],
  "expires_at": "RFC3339"
}
```

票据 30 秒有效、一次性，与浏览器票据相同。请求失败或结果不明时客户端不得自动重放 POST。

### 4.2 消费

SSH 网关在 `auth_password` 中处理 `zt1:<ticket_id>` + `ticket_secret`：

- 新增 `consume_native_ticket(id, secret, peer_ip)`。没有 Cookie 身份可比对，用户与 login 从票据行读取，然后执行与 `consume_web_session_with_stream` 相同的检查：login 未撤销且未过期、`client_type=native`、用户 revision、资产/账号/凭据 revision、gateway_id、过期时间、`transport=native_ssh`。
- 错误 secret 不改变票据状态（不能烧掉合法票据），与现有规则一致。
- 每个 SSH 连接只允许一次 password 尝试，失败即断开。`none`、`publickey`、`keyboard-interactive` 一律拒绝。
- 同一来源 IP 的认证失败计入限流。未认证连接握手超时 10 秒，未认证并发上限可配置（默认 64）。

### 4.3 数据库（并入基线 `0001_control_plane.sql`，schema family 保持 2）

- `login_sessions.client_type text NOT NULL DEFAULT 'web' CHECK (client_type IN ('web','native'))`
- `connection_tickets.transport` 与 `connections.transport`：`text NOT NULL DEFAULT 'websocket' CHECK (transport IN ('websocket','native_ssh'))`，并约束连接的 transport 与其票据一致。
- `connection_tickets.capabilities text[]`：websocket 为 NULL，native_ssh 必填。
- `connections.width/height/dpi` 改为可空，加 `CHECK ((transport='websocket') = (width IS NOT NULL))`；原有范围约束保留。
- 不保留已有部署的数据，字段与约束直接写入 0001 的建表语句，不另设升级迁移；已初始化的数据库需重新初始化。

## 5. 资产目录

`GET /native/assets` 与 `/assets` 共用分页、游标和授权过滤（`ASSET_METADATA`、`visible_groups_sql()`），有三点差异：

- 只返回 `protocol=ssh` 的资产。
- 每个账号增加 `capabilities`：当前 Grant 授权该账号时取 `/info.native.features` 中已开放的能力（N1 为 `["shell"]`），网关不可用时为 `[]`。Grant 仍为全有或全无；N2 起的能力级授权见第 10 节。
- `groups` 字段保持现状（含 `parent_id`、`sort_order`）。

账号字段为 `id,label,username,domain,credential_kind,capabilities`。SSH 账号的 `username` 必然非空。

## 6. `/info` 扩展

在现有 schema 2 响应上增加 `native` 块，浏览器字段不变：

```json
"native": {
  "protocol_version": 1,
  "minimum_client_protocol_version": 1,
  "available": true,
  "gateway": {"id": "main", "host": "bastion.example.com", "port": 2222,
              "public_key": "ssh-ed25519 AAAA…"},
  "features": {"shell": true, "exec": false, "sftp": false}
}
```

- 监听未启用时 `native` 缺省；启用但录制或目标引擎不可用时 `available=false`、全部 features 为 false。可用性必须真实反映，规则与 `web_ssh` 相同。
- `gateway.public_key` 只在 HTTPS 下发布。客户端按此计算 SHA256 指纹并固定，变化时拒绝，不自动替换。
- `production_ready` 仍为 false，直到第 9 节验收和现有发布门槛全部通过。

## 7. SSH 网关（N1）

### 7.1 监听与密钥

- 配置 `BASTION_NATIVE_SSH_LISTEN`（如 `0.0.0.0:2222`），未设置即不监听，这是默认值。`BASTION_NATIVE_SSH_PUBLIC_HOST`/`PORT` 用于 `/info` 和票据响应中的公开地址（NAT/端口映射场景）。
- 网关 host key：单把 Ed25519，存放在配置目录，权限 0600，由 `docker-init.sh` 首次生成，之后不再自动生成。缺失或权限不对时拒绝启动监听。轮换需手动操作，并要求所有客户端重新核验。
- compose 在启用时暴露该端口；[docker.md](../deploy/docker.md) 中“No SSH listener/2222”的说明随之更新。

### 7.2 通道规则

- 每个 SSH 连接对应一张票据、一个目标 SSH 连接、一个录制。
- 只允许一个 `session` 通道，且必须先 `pty-req` 再 `shell`。`env` 忽略；`exec`、`subsystem`、`x11-req`、`auth-agent-req@openssh.com` 拒绝。
- `direct-tcpip`、`tcpip-forward`、`streamlocal` 等全局或通道请求一律拒绝。
- 目标的 EOF、`exit-status`、`exit-signal` 透传给客户端，然后关闭。
- 不支持断线续连。重连必须申请新票据，获得新的 `connection_id`。

### 7.3 复用 `ssh.rs`

目标侧 `protocol/ssh.rs::run` 已实现授权检查、固定 IP、approved host key 核对（含 rekey）、录制和限额，原生入口不再写第二份目标逻辑。新增一个适配层，把 SSH 通道事件翻译成 `run` 已理解的帧：

| 原生 SSH 事件 | 转换为 |
|---|---|
| `pty-req` 的 cols/rows | 首帧 type 2（尺寸） |
| `shell` 请求 | 等待 `run` 发出 type 3 后回复成功 |
| 客户端 channel data | type 1 输入，并附带一帧 type 5（交互） |
| `window-change` | type 2 |
| `run` 输出的 type 1 | 写入 SSH 通道；写入完成（受 SSH 窗口约束）后合成 type 4 ACK |

这样输出背压由 SSH 窗口承担，256 KiB 预算、空闲 30 分钟、绝对 8 小时、周期性授权和 `RuntimeRegistry` 撤销全部沿用。区别是：原生客户端发来的任何字节都算交互，因为它无法区分终端自动应答和用户输入。

### 7.4 录制

- 格式不变：ZTREC002，`stream_protocol=bastion.ssh.v1`，事件仍是 type 1/2 输出帧，不记录输入和凭据。Web 回放页无需修改即可播放。
- 先完成加密写入和 flush ACK，再把输出交付给客户端，与浏览器入口相同。录制故障关闭会话，录制状态标为 partial/failed。
- 录制 meta 的 width/height/dpi：原生连接没有像素尺寸，取固定名义值 1280×720@96。终端几何以 type 2 帧为准（见第 10 节待确认项）。

## 8. 审计与管理界面

- `ticket.issued`、`ticket.consumed`、`ticket.rejected` 的 payload 增加 `transport`；原生签发额外记录 `capabilities`。
- 连接列表和详情显示 transport（“浏览器 / ZeroTerm”），管理员断开对两类连接同样有效。
- 原生 SSH 认证失败记录来源 IP，但不记录 secret 和用户名之外的输入。

## 9. N1 验收

自动化测试：

- 原生登录、refresh 轮换、refresh 重放撤销 family；原生令牌访问浏览器路由被拒、Cookie 访问原生路由被拒。
- 票据：30 秒过期、一次性、错误 secret 不烧票、错误 transport 被拒、revision 变化后 `TICKET_STALE`、待用上限与并发上限与 Web 合并计算。
- 网关：多余 password 尝试断开；publickey/none 拒绝；exec/subsystem/转发/agent 被拒；第二个 session 通道被拒；未认证握手超时。
- 生命周期：PTY/resize、EOF 后 exit-status、退出信号透传；会话中撤销设备、禁用用户、修改凭据、移除 Grant 后断开；服务端 drain 时关闭。
- 录制：原生会话产生的录制通过现有 Reader 校验，并能在 Web 回放中播放；录制写入故障关闭会话。

真实环境：

- 系统 `ssh` 客户端用 `zt1:` 票据连接成功（证明是标准 SSH），错误网关 host key 时客户端拒绝。
- ZeroTerm 桌面端和 CLI 走完整链路：读取并核验、登录、资产树、打开终端、注销。
- 两个 OpenSSH 目标、真实 PostgreSQL、浏览器与原生会话同时运行，互不影响。

## 10. 待确认事项

1. **N2/N3 的能力授权。** 已定（2026-10-18）：Grant 仍为全有或全无，拥有 Grant 即可使用服务端已开放的全部原生能力，不增加能力字段。
2. **录制 meta 的名义尺寸。** 需核实 Web 回放的 SSH 渲染器是否只依赖 type 2 帧。如果依赖 meta 尺寸，改为在 meta 中写入 `cols/rows`，并同步修订 Reader。
3. **是否允许同一 SSH 连接多通道。** 已定：一个连接多通道（第 14.2 节）。ZeroTerm 在同一连接上同时使用终端、周期性 exec（服务器监控每 10 秒一次）和 SFTP，每次 exec 一张票据会导致频繁握手；改为逐通道审计。
4. **网关监听是否默认开启。** 本稿默认关闭，部署时显式开启。

## 11. ZeroTerm 客户端需要的修改

`core/crates/zeroterm-app/src/bastion.rs` 中的票据、指纹固定、串行 refresh 和 `failure.code` 查询逻辑基本保留，需要修改的是：

- API 前缀改为 `/api/v1/native/`；登录请求去掉 `client_type`，refresh 仍在请求体中发送 `refresh_token`。
- `Info` 解析改为读取 `native` 块：`native.protocol_version`、`minimum_client_protocol_version`、`gateway`、`features`；录制检查改为 `recording.required && format_version == 2`。
- 签发请求去掉 `purpose`；N1 只申请 `["shell"]`，SFTP、服务器工具入口在 `features` 未开放时隐藏。
- 账号显示改用 `label`，`username` 仍作为目标账号名。
- 同步更新 ZeroTerm 的 `docs/bastion-client.md` 与 README 中的服务端契约描述。

## 12. 可参考的历史实现

`1f33414`（RFC-004 M3-M5 candidate server）在 `253dfdf` 中被删除，可参考的部分：

- `crates/bastion-gateway/src/protocol.rs` 中的 `GatewayHandler`（`auth_password` 解析 `zt1:`、`auth_succeeded` 后再建立上游、Drop 时的关闭顺序）。
- `protocol/native_close_tests.rs`、`crates/bastion-server/tests/openssh.rs`、`tests/release_native_*.py` 的测试结构。
- `migrations/0002_ticket_transport.sql` 的 transport 一致性约束写法。

旧实现基于 schema family 1、旧录制格式和能力数组，不能直接 revert。

## 13. N1 实现说明与偏差

实现：存储/基线迁移 0001 中的原生字段与 `/api/v1/native/*`（`crates/bastion-api/src/control/native.rs`、`bastion-store/src/sessions.rs`），SSH 网关 `crates/bastion-gateway/src/protocol/native.rs`（驱动与浏览器相同的 `web::run_session` → `ssh::run`），`serve` 在设置 `BASTION_NATIVE_SSH_LISTEN` 时启动监听。

与正文的差异或补充：

1. 未配置原生入口时 `/api/v1/native/*` 一律 404，`/info` 无 `native` 块；配置但监听未运行、录制或停机中，签发返回 503 `TARGET_PROTOCOL_UNAVAILABLE`（录制不可用时 503 `RECORDING_UNAVAILABLE`）。
2. 原生路由的 401 带 `WWW-Authenticate: Bearer`。
3. `/me/sessions` 每项增加 `client_type`。
4. 原生 SSH 认证失败写审计动作 `native.auth_failure`（来源 IP、ticket_id、reason_code，不含 secret）；同一来源 IP 60 秒内失败 10 次后直接拒绝（与登录共用限流表），仍写审计。
5. `/connections` 列表中原生连接的 `display` 为 `null`；单条读取返回录制用的名义值 1280×720@96。
6. 环境变量默认值：`BASTION_NATIVE_SSH_PUBLIC_HOST` 默认 HTTPS origin 的主机名，`BASTION_NATIVE_SSH_PUBLIC_PORT` 默认监听端口；主机密钥默认 `secrets/ssh_host_ed25519_key`（配置文件同级），可用 `BASTION_NATIVE_SSH_HOST_KEY_FILE` 覆盖；`BASTION_NATIVE_SSH_MAX_UNAUTHENTICATED` 默认 64（1..1024）。
7. 认证：OpenSSH 先探测 `none`/`publickey`，这些探测被拒绝但不断开（否则标准 `ssh` 无法走到 password）；第一次 password 尝试之后的任何认证请求都断开连接，password 失败立即断开。
8. `env` 请求回复失败（不生效），等同忽略；`pty-req` 必须在 `shell` 之前，目标 PTY 固定 `xterm-256color`、不透传终端模式；尺寸裁剪到浏览器契约范围 2..500 列、1..200 行。客户端 `signal` 请求被拒绝。
9. 客户端 channel EOF 不转发给目标（目标 shell 自行结束）；客户端关闭通道等同浏览器正常关闭：已排队输入写完后会话正常结束，录制为 complete。
10. 输入缓冲上限为 4×256 KiB；超出时按浏览器过载处理关闭会话（`INVALID_ARGUMENT`），不截断、不重放。目标侧输入仍受 `ssh.rs` 原有 256 KiB 预算约束，由适配层的信用计数提供背压。
11. 交互帧 type 5 按“每秒至多一次”合并发送。
12. `ssh.rs::run` 增加可选 `NativeLink`：记录目标的 EOF/exit-status/exit-signal 供原生入口在输出全部写出后转发；浏览器路径忽略 EOF/exit-status，exit-signal 仍按未知消息关闭（与此前一致）。
13. Docker：`init` 首次初始化时用 `ssh-keygen` 生成主机密钥；已初始化的旧安装在下次 `up` 时若缺失则补生成一次，已存在则永不覆盖。端口发布通过可选覆盖文件 `deploy/compose.native-ssh.yaml`（`.env` 中 `COMPOSE_FILE` 启用）。

## 14. N2 exec 与 N3 SFTP

决定（2026-10-18）：有 Grant 即全开；exec 只审计命令与结果，不录制输出；一个 SSH 连接可承载多个通道。

### 14.1 能力与目录

- `NATIVE_CAPABILITIES` 扩为 `shell, exec, sftp`。票据请求的 `capabilities` 为其非空子集，不允许重复或未知值；响应回显请求的集合。
- `/native/assets` 中每个账号的 `capabilities` 为当前开放的全部原生能力（网关不可用时为 `[]`）。`/info.native.features` 的 exec/sftp 与 shell 使用同一可用性判断。
- 网关逐通道校验票据的 capabilities：没有 `shell` 不能 `pty-req`/`shell`，没有 `exec` 不能 `exec`，没有 `sftp` 不能打开 `sftp` 子系统。

### 14.2 通道模型

- 一个 SSH 连接对应一张票据、一个 `connection_id`、一个到目标的 SSH 连接；第一个被接受的通道请求才建立目标连接，之后所有通道复用它。
- 每个连接最多 16 个同时打开的 session 通道，其中整个连接生命周期最多一个 shell（PTY）通道（含已结束的 shell；每个连接最多一条录制）。shell 的规则、帧适配和录制与 N1 相同；没有 shell 通道的连接不产生录制。
- exec 与 sftp 通道可与 shell 并存、可并发、可反复打开。`x11`、agent、所有转发、`env`（忽略）、`signal` 仍按 N1 处理；`subsystem` 只接受 `sftp`。
- 授权检查、撤销、`RuntimeRegistry`、绝对时长 8 小时在连接级生效，撤销关闭所有通道。打开 exec / SFTP 通道本身不算客户端活动（周期性监控不能让空闲连接一直存活）；shell 输入、exec 的 stdin 和 SFTP 请求包刷新空闲计时。
- 连接计数与并发上限仍按连接计算，通道不另计。

### 14.3 exec（N2）

- 命令以字节透传给目标 `exec`，长度上限 64 KiB，含 NUL 拒绝。stdin、stdout、stderr 双向透传，背压由 SSH 窗口承担；目标的 EOF、exit-status、exit-signal 透传后关闭通道。
- 不录制输入输出。每条命令在结束时写一条审计 `exec.completed`（失败启动为 `exec.rejected`）：`connection_id`、命令前 4 KiB 文本（非 UTF-8 时以替换字符显示）、完整命令的 SHA-256、`truncated`、退出码或信号、stdin/stdout/stderr 字节数、耗时。
- 监控等周期性命令同样逐条审计。

### 14.4 SFTP（N3）

- 网关对 SFTP v3 做透明代理：客户端与目标之间逐包转发，网关解析请求与响应以做审计和限制；唯一改写是 VERSION 扩展列表，只保留下一条的六个白名单扩展，保留名字、版本数据及顺序，不补充目标未公告的扩展。其他合法数据包原样转发。单包长度字段上限 256 KiB，不含 4 字节长度前缀；畸形包、版本不是 3 关闭通道。
- 允许的请求：`OPEN CLOSE READ WRITE LSTAT FSTAT SETSTAT FSETSTAT OPENDIR READDIR REMOVE MKDIR RMDIR REALPATH STAT RENAME READLINK SYMLINK`，以及扩展 `posix-rename@openssh.com`、`statvfs@openssh.com`、`fstatvfs@openssh.com`、`fsync@openssh.com`、`hardlink@openssh.com`、`limits@openssh.com`；其他扩展直接回复 `SSH_FX_OP_UNSUPPORTED`，不转发。
- 审计（动作 `sftp.<op>`，含 `connection_id`、路径、目标返回的状态码）：
  - 修改类每次一条：`SETSTAT/FSETSTAT REMOVE MKDIR RMDIR RENAME SYMLINK` 及修改类扩展（posix-rename、hardlink；fsync 仅计入会话请求计数）。
  - `sftp` 子系统请求因无能力或启动失败被拒时写 `sftp.rejected`（connection_id、transport、reason_code），保留客户端通道；其他子系统名不审计。写类 OPEN（WRITE / APPEND / CREAT / TRUNC 任一标志）被目标拒绝时，写 status 为目标非零状态、字节数为 0、哈希为 null 的 `sftp.file`；只读 OPEN / OPENDIR 失败仅计数。
  - 文件句柄在 `CLOSE`（或通道结束）时一条 `sftp.file`：路径、打开标志、读/写字节数；读写都从偏移 0 连续进行时附内容 SHA-256，否则为 null。
  - 只读元数据请求（`STAT LSTAT FSTAT REALPATH READLINK OPENDIR READDIR statvfs limits`）不逐条审计，在通道结束时汇总为一条 `sftp.session`（各类请求计数、通道字节数）。
- 目标账号的文件系统权限是唯一的访问边界；网关不做路径白名单。

### 14.5 验收

- exec：输出/退出码/信号透传、stdin 透传、超长与 NUL 命令被拒、并发 exec、没有 exec 能力被拒、审计字段完整、撤销时运行中的命令被断开。
- SFTP：OpenSSH `sftp` 客户端与 ZeroTerm 均能列目录、上传、下载、重命名、删除；顺序上传/下载的 SHA-256 与文件一致；随机偏移读写的 SHA-256 为 null；不支持的扩展返回 OP_UNSUPPORTED；畸形包关闭通道；没有 sftp 能力被拒。
- 多通道：shell + exec + sftp 同时在一个连接上运行，录制只覆盖 shell；第 17 个通道和第二个 shell 被拒。
- 真实环境：系统 `ssh`/`sftp` 与 ZeroTerm CLI（`zeroterm exec`、`zeroterm sftp`）走完整链路。

### 14.6 N2 / N3 实现说明（2026-10-18）

- 客户端连接规划（ZeroTerm 桌面，2026-10-18）：服务器工具的 exec 复用该资产已打开终端的原生连接，不再另占一条；SFTP 始终单独一条按需建立、空闲回收的连接。原因是同一连接上的 SFTP 大量传输会让终端排队（N3 的 D5），分开后互不影响。同一资产的第二个终端仍需新连接（每条连接只有一个 shell）。

- 原生连接自行持有一个 `RuntimeRegistry` 租约、一个惰性初始化的目标 SSH 连接、连接级授权轮询、空闲和绝对时长。目标连接的 host key（含 rekey）、固定地址和凭据认证抽到 `ssh::connect_target`，浏览器共用；shell 的开通和录制泵也共用。
- 认证后允许最多 16 个同时打开的 session 通道，空通道也计数；整个连接生命周期最多接受一个 shell。exec / SFTP 可先于 shell，也可在 shell 结束后继续使用。被拒绝的 exec / subsystem 请求保留客户端通道，可重新请求。
- exec / SFTP 首次启动通过 `activate_native_connection` 激活连接，不创建录制。原生连接已 active 时允许准备和激活唯一的 shell 录制；浏览器仍必须从 connecting 激活。只写一次 `connection.active`，录制激活另写 `recording.active`。
- shell 正常结束时立即封存 complete 录制，其他通道继续运行；客户端断开后连接进入 closing → closed。未启动任何被接受的请求即断开、网络错误、撤销、授权失效或超时使连接 failed。撤销与 drain 取消所有通道；运行中的 exec 仍写 `exec.completed`，未报告退出码或信号时字段为 null。shell 录制失败中断整个连接。
- exec 命令最多 64 KiB，含 NUL 拒绝；stdin / stdout / stderr 由独立的有界 SSH 通道读写转发，写入受 SSH 窗口和 stalled deadline 约束。命令审计沿用 N2-A 的 4 KiB 预览和完整 SHA-256；命令输出不录制。
- SFTP 在 `protocol/sftp.rs` 中代理 v3，长度字段最多 256 KiB（不含前缀）。支持正文列出的请求和扩展；未知扩展本地返回 OP_UNSUPPORTED。版本、字段、响应关联、属性、重复请求 ID 或长度不合法时只关闭该 SFTP 通道，其他通道可继续使用。
- 每个 SFTP 通道最多 128 个待响应请求、1024 个句柄（句柄最多 256 字节）；WRITE 在请求转发时更新哈希和连续性，只保留长度，所有写请求均确认成功才声明写哈希；write_bytes 仅统计成功 ACK。乱序 READ 缓冲最多 1 MiB，超出时丢弃缓冲并把读哈希置 null，传输继续。随机偏移、失败或未完成的 I/O 不声明完整 SHA-256。读写混用句柄的 sha256 取写侧，但任一侧不连续或未确认时整体为 null。`sftp.file` 另提供 `read_sha256` / `write_sha256`，目录句柄仅计入 `sftp.session`。成功 CLOSE 的 status 为 0；通道结束时未关闭文件的 status 为 null，失败写类 OPEN 的 status 为非零。fsync 只计入 sftp.session。
- exec、认证失败、SFTP 审计写入失败采用 best-effort，并记录服务端错误日志；SFTP 批次写审计总预算 2 秒，避免存储故障阻塞 drain。关闭或撤销不会取消已开始写入的响应审计，先让该批次在预算内结束，再封存未关闭文件和 session 汇总，避免 CLOSE 与 SSH 断开的竞态丢失健康存储下的文件审计。存储层从领域类型 SftpAudit 组装 payload，包含 connection_id 和 transport；路径以最多 4096 字符的 lossy UTF-8 展示，NUL 替换为 U+FFFD。连接级每秒授权检查最多等待 2 秒，存储不可用时约 3 秒内关闭连接，因此可能存在约 3 秒的未审计操作窗口；更严格的 fail-closed 策略需另行设计，exec 同步考虑。
- 已知限制（D5）：russh 在数据到达时补充窗口，再 await 投递每通道有界 mpsc。目标写入慢时，一个 SFTP 或 exec 通道可阻塞同连接的入站处理，拖慢其他 shell / exec，最长到 stalled deadline。内存有界，N3 接受此限制；每通道接收配额另立项。健康回环目标的混合通道回显延迟见 N3 验证记录，不代表慢目标的最坏延迟。
- 录制 meta 沿用 1280×720@96；Reader 和 Web 离线 SSH 渲染器以 type 2 帧恢复终端几何，无需修改格式。

验证：工作区 Rust 回归、Web 测试与 TypeScript 检查、临时真实 PostgreSQL 八套隔离测试；进程内测试覆盖混合通道、单目标认证、能力限制、撤销、通道上限、exec 计数/退出码/信号、SFTP 畸形包与哈希。可选 `real_openssh_exec_and_sftp_roundtrip` 测试使用显式一次性 sshd fixture，验证系统 ssh / sftp、ControlMaster 下 shell + exec + SFTP 复用、≥8 MiB 二进制上传下载与续传、SHA-256 与修改审计。N3 的三项大文件门槛已通过，详见 [N3 实施清单 §10](./RFC-006-N3-implementation.md#10-实现与验收结果2026-10-18)。生产发布仍需 ZeroTerm 桌面、两个目标和浏览器并行等完整环境验收；本次未修改 ZeroTerm 客户端代码。

复跑命令（PostgreSQL 和 OpenSSH 均需显式的一次性环境）：

```sh
TMPDIR=/private/tmp cargo test --workspace
cd web && npm test && npm run check
# 在仓库根目录运行：URL 文件权限必须是 0600
LC_ALL=C TMPDIR=/private/tmp python3 tests/pg_acceptance.py --database-url-file <postgres-url-file>
BASTION_NATIVE_OPENSSH_FIXTURE=<fixture.json> TMPDIR=/private/tmp cargo test -p bastion-gateway real_openssh_exec_and_sftp_roundtrip -- --ignored --nocapture
```

OpenSSH fixture 字段：`address`（回环地址及高端口）、`username`、`approved_key`（目标公钥 OpenSSH 文本）、`private_key_file`（一次性目标认证私钥路径）。测试仅访问回环目标，在临时私有目录内上传、下载、重命名和删除测试文件；不使用用户已有 SSH 配置或密钥。默认测试不运行该环境依赖用例。

N3 实测（真实 PostgreSQL、私有 CA 校验的 TLS、serve、回环 sshd）：系统 sftp 默认并发和 ZeroTerm CLI 均完成 8 MiB 上传/下载，文件与两条独立读/写审计的 SHA-256 一致；OpenSSH 续传哈希为 null，计数只含续传部分；写 OPEN 权限拒绝、exec-only 票据的 sftp.rejected、管理员断开及完整清理均通过。混合 shell + exec + SFTP 连接上传 8 MiB 时，健康回环目标 9 次回显的中位数 29.516 ms、最大 35.674 ms，传输耗时 0.479 秒。该值不代表慢目标的最坏延迟；D5 限制仍保留。
