# Web Bastion

面向浏览器的自托管 Web 堡垒机。管理员托管目标账号凭据；浏览器通过 HTTPS 和
WebSocket 申请会话并访问目标的终端、exec 和 SFTP。目标凭据不会下发给浏览器。
系统自身完整提供用户、资产、授权、SSH 代理、审计和管理能力；ZeroTerm 作为额外
接入端，通过集成 API 和标准 SSH 入口使用同一批资产。

当前代码包含 RFC-004 M3–M5 候选实现：PostgreSQL 控制面、多用户/设备会话、grant、凭据与录制加密、Host Key 审批、一次性票据、Cookie/CSRF/Origin 与 Bearer 隔离、Web 多通道 shell/exec/SFTP、服务端文件流、required shell recording、受控回放、审计离线分区维护，以及 ZeroTerm 标准 SSH 双入口。旧 M0 固定资产原型仍由 `dev-prototype` 开关隔离，默认构建不包含开发 Bearer 文件入口。

**尚不能生产发布**：`production_ready=false` 是有意保持的候选状态。真实 required 录制故障矩阵、备份恢复全链路、浏览器人工验收、1 GiB/50 终端性能验收和长期审计分区运营仍未全部完成。生产 `serve` 不会自动迁移，也不能通过反向代理把候选入口伪装成正式版本。

```text
Browser ── HTTPS / WebSocket ──> Bastion ── managed credential ──> Target SSH
ZeroTerm ── integration API + SSH ticket ──> Bastion
```

M0 的 API 使用本机 HTTP 和文件 Bearer 代替生产登录，仅用于协议验证。
生产阶段必须按 RFC 接入 HTTPS、数据库授权与持久化单次消费。

## 工程

需要 Rust 1.95+，目前支持 macOS / Linux 开发和 Linux 服务端部署。

| crate | 当前职责 |
|---|---|
| bastion-domain | 能力、票据请求、连接状态与错误码 |
| bastion-secrets | 随机秘密、哈希比较、脱敏与受限文件读取 |
| bastion-store | PostgreSQL 身份/授权/票据/审计事务；隔离的开发内存存储 |
| bastion-gateway | 共享目标 SSH 校验与连接、SSH/浏览器多 channel shell/exec/SFTP、required recorder 与受控文件流 |
| bastion-api | 原生 Bearer 与浏览器 Cookie 登录、管理/设备/录制/文件 API、WebSocket 会话 |
| bastion-server | CLI 初始化、生产配置校验、单进程启动、维护/恢复/审计离线命令、同源静态资源托管 |
| web | TypeScript + Vite + xterm.js 登录、授权资产、终端 |

`vendor/russh` 固定 ZeroTerm 的补丁版本，独立克隆即可构建，无需相邻仓库。
增补的服务端修正见 [BASTION-PATCH.md](vendor/russh/BASTION-PATCH.md)。
依赖版本由已提交的 `Cargo.lock` 固定。

## 当前进度（2026-10）

- **M1/M2：已实现并通过隔离回归。** PostgreSQL、真实 OpenSSH、凭据加密、Host Key、grant、票据竞态、撤销、重启恢复、Cookie/CSRF/Origin、WebSocket PTY 和 ZeroTerm managed connection 均有测试证据。
- **M3–M5 候选实现：已完成代码收口。** 多 channel、exec、SFTP 文件流、required recording、录制回放、设备撤销、生产配置、恢复/备份 CLI、离线审计分区维护及 Web/ZeroTerm 能力门控均已接入。
- **隔离 y189 验收：已通过候选自动化。** 0001–0005 migration/lifecycle/recovery、审计升级/保留命令、双目标 HTTPS/WSS smoke 均完成；详情见 [M3 验证记录](docs/M3-verification.md)。
- **生产发布：未就绪。** RFC 第 18 节的人工浏览器、故障矩阵、备份恢复全链路和长期性能门槛仍是发布阻断项。


生产候选入口必须使用 [production.example.toml](config/production.example.toml) 并显式执行 schema migration、创建管理员和 preflight；录制目录、KEK、Host Key、数据库 URL 均使用 owner-only 受限文件。服务启动命令为 `bastion-server serve --config /etc/zeroterm-bastion/production.toml`，不自动迁移。

审计分区升级和保留只允许网关完全停止、专用 owner 数据库连接和显式 `--offline`：`bastion-server partition-audit --config ... --offline`、`bastion-server retain-audit --config ... --offline --days 180`。这些命令不会删除 default 分区，也不会关闭 append-only trigger。

接口见 [OpenAPI](docs/openapi-web.json) 与 [WebSocket v1](docs/websocket-v1.md)。
Windows 可以运行纯逻辑检查，但本地秘密文件与初始化明确拒绝非 Unix 主机，不降低
文件所有者/0600 权限要求来换取可运行性。

## 启动 M0 开发原型

```sh
cargo build --locked -p bastion-server --features dev-prototype
target/debug/bastion-server init --directory .local
cp config/prototype.example.toml .local/prototype.toml
# 配置真实测试目标的地址、账号、已核验公钥和受限凭据文件。
target/debug/bastion-server prototype --config .local/prototype.toml
```

初始化生成持久服务端密钥和 32 字节随机开发 API token；文件权限 0600，目录 0700。
已有身份文件会拒绝覆盖。目标私钥、密码、口令文件同样必须是当前用户拥有的
0600 普通文件。密码和口令文件不自动去除换行。

通过受信任的本地程序在内存读 `.local/api-token`，作为
`Authorization: Bearer ...` 调用当前开发 API。不要把 token 或 SSH 票据放在命令行参数。

| API | 用途 |
|---|---|
| GET /api/v1/info | 服务入口、公钥、协议版本与开发状态 |
| GET /api/v1/assets | 固定授权资产与能力 |
| POST /api/v1/connection-tickets | 30 秒、单次使用的连接票据 |
| GET /api/v1/connections/{id} | pending / connecting / active / 终态 |
| GET /health/live | 进程存活 |

API 票据请求字段为 `asset_id`、`account_id`、`capabilities` 和 `purpose`。
当前开发契约见 [openapi-prototype.json](docs/openapi-prototype.json)。
SSH 用户名为 `zt1:<ticket_id>`，password 为 `ticket_secret`。
目标初始化失败通过 `connection_id` 查询；票据消费后永不恢复，重连需要新票据。
标准 SSH 客户端必须校验网关公钥；浏览器则校验 HTTPS/WSS 同源与 Origin，
不取得目标 SSH 凭据或密钥。Web 会话不复用原生 SSH 票据。

## 已支持的协议行为

- 独立目标 SSH 连接，目标主机公钥先校验，之后才加载和提交目标凭据。
- shell / PTY / terminal modes / resize，exec 原始字节、独立 stdout/stderr 和退出信息。
- SFTP 目录/元数据、受控文件操作和有界 download/upload；跨主机安全复制因标准 SFTPv3 不满足 no-follow 原子保证而明确禁用。
- shell required recording 使用 `ZTREC001` 加密事件流；输出先取得 recorder ACK 再发送给客户端。回放仅展示完整校验的 recording。
- EOF 半关闭继续排空输出；取消和关闭按通道处理。
- 空 RTT 通道不建立目标 session，不占用目标 MaxSessions。
- 32 KiB SSH 包、8 条有界通道事件队列，双向独立转发遵循 SSH 窗口背压。
- 单开发身份最多 10 条目标连接、20 个待消费票据，每连接最多 16 通道；
  总计最多 100 个入站 SSH 会话，开发存储最多 1024 条历史记录。

缓冲参数不等于已证明的进程内存上限；M5 仍需测量协议内部缓冲和长期压力。
开发身份没有多用户隔离、权限撤销与录制，不能部署给生产用户。

## 验证

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cd web && npm test && npm run build
# y189/Unix non-root only: python3 tests/m3_pg_smoke.py
# y189/Unix non-root only: python3 tests/m3_https_smoke.py
```

普通 cargo test 中的 ignored 真实集成用例不算通过；必须使用隔离 PostgreSQL、虚构凭据、两个 loopback OpenSSH 目标和明确的 TLS CA。

OpenSSH 测试脚本在临时目录生成虚构密钥，启动独立测试 sshd 和网关，执行
标准 ssh/sftp 客户端及 Rust 多通道验证，最后结束进程并清理临时文件。
需要 `ssh`、`sshd`、`sftp`、`ssh-keygen` 和 Python 3；不需要 Docker。
sshd 可在 macOS 以当前用户运行；部分 Linux 环境需要配置测试用户/容器权限。
脚本遇到环境限制会失败并说明原因，不将跳过当作验证通过。
远程公网 PostgreSQL 验收曾因 RTT 超过既有 2 秒事务预算失败；随后在 `y189`
使用本机隔离 PostgreSQL/OpenSSH fixture，真实事务、WebSocket、PTY/resize 和
Chrome Cookie 登录/中文输出/新会话重连/注销均通过，生产预算未放宽。
证据与未完成边界见 [M1/M2 验收记录](docs/M2-verification.md)；这不是生产发布。

### 当前边界

M0 固定资产原型、M1/M2 兼容路径继续保留用于开发回归；正式候选路径必须使用生产配置、HTTPS/WSS、required recording 和 ZeroTerm Bearer/SSH ticket。M3–M5 代码已接入，但 RFC 第 18 节人工浏览器、故障、恢复和性能阻断条件尚未全部通过，不能作为生产许可。
