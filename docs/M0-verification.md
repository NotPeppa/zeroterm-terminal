# M0 验收记录

日期：2026-10-04。实现范围是固定资产的开发协议原型，生产功能按 RFC 后续阶段交付。

## 环境与执行

- macOS / Apple Silicon；Rust 1.95.0，Cargo 1.95.0。
- OpenSSH 10.3p1 / LibreSSL 3.3.6；本机真实 sshd，目标 `MaxSessions=2`。
- ZeroTerm CLI 0.1.11，来自本机 ZeroTerm 主项目已有构建产物。
- 网关与目标均使用临时生成的 Ed25519 主机密钥；目标使用测试私钥认证。
- 所有测试凭据和票据在临时文件或内存中处理，不作为命令行秘密传递。
- 测试结束停止网关、sshd、ZeroTerm CLI 并清理临时目录。

命令：

```sh
cargo fmt --all -- --check
cargo check --locked --workspace
cargo test --locked --workspace --all-features
cargo test --locked -p bastion-server --test cli
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
python3 tests/openssh_smoke.py --zeroterm-cli /absolute/path/to/zeroterm
```

普通 Cargo 测试中的 OpenSSH 集成用例为 opt-in；Python 脚本创建真实环境后
显式执行该用例。这里的真实协议结果来自实际执行，不是将 ignored 视为通过。

## 验证结果

| 项目 | 结果 |
|---|---|
| 工作区默认构建、fmt、Clippy | 通过；默认 CLI 不含 prototype 命令 |
| 秘密脱敏、未知能力拒绝、连接终态 | 通过 |
| 同一票据 20 个并发消费者 | 恰好一个成功 |
| 错票据秘密 | 拒绝，之后正确秘密仍可消费 |
| 过期、消费后断开和重放 | 拒绝；关闭后的票据不复活 |
| 无 Bearer、请求未授权能力 | API 拒绝 |
| 初始化权限与重复初始化 | 目录 0700、秘密文件 0600；不覆盖原身份 |
| 开发配置尝试监听 0.0.0.0 | 读取凭据、打开监听之前拒绝 |
| 标准 OpenSSH exec | 中文、emoji、独立 stderr 和退出码 7 正确 |
| stdin 原始字节与 EOF | 1 MiB 随机数据不改写，EOF 后输出继续到达 |
| 标准 OpenSSH PTY shell | 启动和退出正常，接受合法零尺寸初始 PTY |
| ZeroTerm CLI | 校验网关公钥、票据认证并打开目标 shell，通过 |
| 标准 sftp 上传与下载 | 4 MiB 随机文件，SHA-256 一致 |
| Rust SFTP 客户端 | 1 MiB 包含零字节和非 UTF-8 字节的文件一致 |
| 16 个 allocated 通道 | 不耗用目标 MaxSessions；第 17 个拒绝 |
| 同连接慢 exec 与快 exec | 快通道独立完成，输出和退出码不串用 |
| PTY modes 和 resize | ECHO 设置、40×100 终端尺寸由目标确认 |
| env / exec 管道化请求 | 只回复原始 want_reply=true 的请求，顺序正确 |
| exec want_reply=false | 无额外 success/failure |
| 同通道再次启动程序 | 第二次请求失败，第一条程序继续正常完成 |
| 仅 sftp 能力尝试 shell / exec | 拒绝 |
| 未知 subsystem、TCP 转发 | 拒绝 |
| 目标公钥错误 | TARGET_HOST_KEY_CHANGED；sshd 无新增认证成功记录 |
| 日志秘密泄露检查 | 测试 Bearer、票据和私钥文本未出现在网关日志 |

## 尚未验收

目标 password 认证与加密私钥配置已提供，但本轮真实目标只验证了未加密
Ed25519 私钥。生产用户名／设备登录、PostgreSQL 原子消费、权限撤销竞态、
required 录制和备份恢复均未实现，本轮结果不能覆盖这些能力。

ZeroTerm 桌面和 Android 的资产 API、共享连接编排及连接池尚未改动；CLI 的验证
只证明现有 SSH 核心能使用本方案的票据及代理协议。客户端不具备堡垒机登录 UI。

本轮没有 1 GiB 文件、50 条连接持续一小时、吞吐比、权限撤销延迟或内存峰值
报告。M5 的负载与生产发布条件继续保留在 RFC 中。

## 下一阶段 M1

1. PostgreSQL schema 和版本化迁移，资产／账号复合外键、状态和哈希唯一索引。
2. Argon2id 用户认证、登录设备、opaque access/refresh token 及轮换重放检测。
3. 凭据 envelope encryption、持久 KEK、目标主机密钥扫描与审批。
4. grant 与 revision，按固定锁顺序消费票据、撤销登录和授权。
5. 将本阶段通过的 SSH 代理接入生产服务层，保留开发模式的编译隔离。

生产 serve 入口应在生产认证和存储装配可用后增加，不能把 M0 的文件 Bearer
作为正式用户登录。
