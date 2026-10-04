# Web Bastion

面向浏览器的自托管 Web 堡垒机。管理员托管目标账号凭据；浏览器通过 HTTPS 和
WebSocket 申请会话并访问目标的终端、exec 和 SFTP。目标凭据不会下发给浏览器。
系统自身完整提供用户、资产、授权、SSH 代理、审计和管理能力；ZeroTerm 作为额外
接入端，通过集成 API 和标准 SSH 入口使用同一批资产。

当前实现是 **M0 开发协议原型**：单个固定资产、内存票据、开发 Bearer 身份和
SSH 多通道代理。尚未实现 PostgreSQL、用户登录、生产授权、凭据加密、审计录制、
Web 前端或浏览器 WebSocket 数据面。原型只能监听本机，默认构建不包含开发认证入口。

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
| bastion-store | 编译开关隔离的开发内存存储；PostgreSQL 待 M1 |
| bastion-gateway | SSH 双端连接、主机校验、通道流式代理 |
| bastion-api | 开发资产、票据、连接状态 API |
| bastion-server | CLI 初始化、配置校验、单进程启动 |

`vendor/russh` 固定 ZeroTerm 的补丁版本，独立克隆即可构建，无需相邻仓库。
增补的服务端修正见 [BASTION-PATCH.md](vendor/russh/BASTION-PATCH.md)。
依赖版本由已提交的 `Cargo.lock` 固定。

## 启动开发原型

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
当前 M0 的标准 SSH 客户端必须校验网关主机密钥；未来浏览器版本改为校验 HTTPS/WSS
同源和 Origin，不把 SSH 主机密钥交给前端。

## 已支持的协议行为

- 独立目标 SSH 连接，目标主机公钥先校验，之后才加载和提交目标凭据。
- shell / PTY / terminal modes / resize，exec 原始字节、独立 stdout/stderr 和退出信息。
- SFTP subsystem 原始字节代理；不承诺文件级审计或目录限制。
- 每个通道最多一次成功启动；不支持的 subsystem、转发、Agent、X11 均拒绝。
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
python3 tests/openssh_smoke.py
# 可选：验证标准 SSH 客户端；浏览器 WebSocket 测试在 M2 加入。
```

OpenSSH 测试脚本在临时目录生成虚构密钥，启动独立测试 sshd 和网关，执行
标准 ssh/sftp 客户端及 Rust 多通道验证，最后结束进程并清理临时文件。
需要 `ssh`、`sshd`、`sftp`、`ssh-keygen` 和 Python 3；不需要 Docker。
sshd 可在 macOS 以当前用户运行；部分 Linux 环境需要配置测试用户/容器权限。
脚本遇到环境限制会失败并说明原因，不将跳过当作验证通过。
当前验收结果与覆盖边界见 [M0 验收记录](docs/M0-verification.md)。

## 后续阶段

设计基线见 [RFC-004](docs/RFC-004-bastion-design.md) 和根目录 [design.md](design.md)。
本仓库负责服务端与同源 Web 前端，浏览器是主入口；ZeroTerm 通过独立集成入口接入，
两条入口共享用户、资产、授权、审计和撤销逻辑。

1. M1：PostgreSQL 迁移、Web 登录、资产账号、凭据加密、主机密钥审批、grant、事务票据。
2. M2：WebSocket 数据面、xterm.js 浏览器终端、会话状态与断线处理。
3. M3：SFTP 文件管理、exec 工具、管理后台、required shell 录制、审计和撤销。
4. M4 / M5：ZeroTerm 集成、备份恢复、部署运维、浏览器安全和双入口负载验收。

M0 的通过结果仅证明开发协议路径；RFC 的生产发布条件尚未满足。
