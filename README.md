# ZeroTerm Browser Bastion

自托管 browser-only SSH / RDP / VNC 工作台。浏览器只使用同源 HTTPS/WSS；SSH 使用 Rust SSH
通道和 xterm.js，RDP/VNC 使用 Rust 定向单次 TCP bridge 和私有 guacd。目标凭据不进入浏览器。没有原生 SSH 入口、exec API、
SFTP 文件管理、跨主机复制或旧版多 channel 协议。

**候选实现，不能生产发布：`production_ready=false`。** 当前合同是
[RFC-005](docs/RFC-005-guacamole-browser.md) 和 [SSH xterm 更新](docs/ssh-xterm.md)，schema/protocol family 均为 2。
旧数据库和旧录制没有自动转换；启动/迁移遇到旧 family 必须拒绝，绝不自动 DROP 数据。

```text
Browser ─ HTTPS/WSS ─ Rust API + encrypted recorder
                          ├─ Rust SSH/PT​​Y ─ SSH target (xterm.js)
                          │ private one-use TCP bridge
                          │                       ▲
                          └─ guacd control ─ guacd┘ ─ target RDP/VNC
```

## 安全边界

- Cookie-only 登录、CSRF、exact Origin、30 秒单次 WSS token；无 Bearer/原生 ticket 兼容入口。
- SSH 在同一目标 socket 上校验已审批完整 host key，之后才能认证。
- RDP 仅 NLA/TLS。固定 guacd 1.6.0 + FreeRDP 2.11.7，并使用最小严格 leaf-DER SHA-256 patch。
  stock `cert-fingerprints` 不是 strict pin；缺少 `zt-strict-cert-pin` engine 参数时 fail closed。
  NLA 的 Windows 验收独立于 xrdp-TLS；没有 Windows 证据不得宣称通过。
- VNC none/password 只允许管理员显式信任的 CIDR；经典密码最多 8 bytes，不能声称等价加密/身份保证。
- guacd 没有 DB/KEK/录制挂载、public 4822 或 target network。专用 bridge 之外，还必须安装并
  实测宿主机精确 project/source-IP egress 规则；`internal: true` 本身不算隔离证据。
- 每连接一条 Guacamole stream 和一个 `ZTREC002` 加密录制；只记录 display output，不记录键盘/凭据。
  录制 write+flush ACK 后才转发输出；只在完整 EOF/integrity 验证后将回放显示为已验证。

## 开发与部署

Rust 1.95+、Node 24、Linux Docker/Compose。配置和 CLI 的 secrets 要求 Unix owner-only `0700/0600`；
不通过放宽权限来兼容 Windows 服务部署。依赖锁定在 lockfiles；Guacamole 浏览器 JS 官方发布物
本地 vendored、同源加载并保留 LICENSE/NOTICE。

部署只发布 HTTPS。首次初始化生成独立 KEK、owner DB 密码和 runtime DB 密码；显式 owner migration、
受限 runtime grants，非 root/read-only 运行，录制与 secrets 持久卷保留。
完整步骤与 egress 安装顺序见 [Docker runbook](deploy/docker.md)。

```sh
cargo fmt --all -- --check
cargo check --locked --workspace
cargo test --locked --workspace
cd web && npm ci && npm test && npm run build
```

真实隔离 Docker engine 检查必须在获准的测试主机执行（不操作既有服务）：

```sh
docker build -t zeroterm-guacd:1.6.0-strict-pin -f deploy/guacd/Dockerfile .
python3 -u tests/docker_guacd_acceptance.py
```

检查结果和未验证项目见 [Guacamole execution evidence](docs/guacamole-execution.md)。
ignored/mock/编译检查不能替代真实目标、真实浏览器 Canvas/IME、Windows NLA、故障恢复、备份和容量验收。
[RFC-004](docs/RFC-004-bastion-design.md) 与旧 M1–M5 证据仅为历史记录，不是 family-2 支持声明。
