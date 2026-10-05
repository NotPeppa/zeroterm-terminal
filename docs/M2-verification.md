# M1 收口 / M2 开发实现验收记录

此记录区分“代码实现”“本机检查”“真实目标验收”。本批不是 RFC-004 的生产发布。
旧 M0 的历史验收见 [M0-verification.md](M0-verification.md)，不重写或扩大其结论。

## 当前进度摘要

- M1 本地隔离 PostgreSQL + 真实 OpenSSH：已在 `y189` 通过。
- M2 Cookie/CSRF/Origin + WebSocket PTY + 用户 Chrome：已在 `y189` 通过。
- Web 第一版视觉控制台：已完成并通过前端 9/9、TypeScript 和 Vite build 检查。
- 管理后台：未实现；当前 Web 仅展示已授权资产，资产/账号/凭据/host key/grant 通过管理 API 或测试脚本创建。
- 生产就绪：未满足；required 录制、回放、负载、备份恢复和 HTTPS built bundle 等仍在范围外。


| 任务 | 已交付代码 |
|---|---|
| T1：协议、持久化票据 | Web/SSH transport + v1 绑定；WebSessionResponse；6-byte 二进制帧；共享签发/消费事务；Web/native 登录域隔离；新增 0002 迁移与真实 PG opt-in 测试 |
| T2：共享数据面 | 复用目标 SSH 连接、NetworkPolicy、host key 检查和凭据认证；单 shell；真实 PTY/shell 确认；原始字节、stderr、EOF/exit、resize；有界背压、授权复查、idle/absolute/write 超时 |
| T4：前端 | TypeScript/Vite/xterm；Cookie+CSRF 登录、授权资产/账号、终端与状态、显式新票据重连；无目标凭据、无 localStorage/IndexedDB 票据 |
| T3：lead 集成 | Cookie/CSRF/Origin API；once-only WS upgrade；共享 backend；同源静态托管与 CSP；可恢复/不可恢复认证错误区分 |
| T5：lead 验证 | 协议、凭据、前端检查；新增真实 WebSocket/SSH fixture 用例；M1 fixture 串行执行旧 PG、新 Web PG 与 WebSocket 测试；CI 前端及 Linux 真实 fixture 配置（远端 CI 尚未运行） |

未修改用户已有的 RFC/design 设计变更；本轮剩余集成修改未执行 git commit，未启动替代服务器。

## 本机环境与验证

Windows；Rust/Cargo 1.95.0，Node 24.18.0，npm 11.16.0，Python 3.12。
机器未安装可用 WSL 发行版、Docker、PostgreSQL 或 sshd，仅有 ssh 客户端。

| 检查 | 当前结果 |
|---|---|
| `cargo test -p bastion-domain` | 6/6 通过 |
| `cargo test --locked -p bastion-secrets --lib` | 3/3 通过；凭据 AAD/篡改、脱敏、Argon2id |
| Web `npm test` | 9/9 通过；包括 HTTPS-before-request、8192 UTF-8 字节边界、二进制方向、UTF-8 跨帧、握手状态与背压 |
| Web `npm run build` | TypeScript check 与 Vite production build 通过 |
| OpenAPI JSON / 内部 `$ref` | 87 个引用解析通过 |
| Python `py_compile` | M1/M2 fixture 脚本语法通过 |
| Rust `cargo check --locked --workspace --all-targets --all-features` | 通过（本机临时构建环境见下） |
| Rust `cargo clippy --locked --workspace --all-targets --all-features -- -D warnings` | 通过 |
| `cargo fmt --all -- --check` / `git diff --check` | 通过 |
| Rust workspace test (`cargo test --locked --workspace --all-features`) | 通过：unit/domain 6、gateway 6、secrets 3、API 4、CLI 3；M0/M1/M2真实fixture共4项 ignored，未伪称通过 |
| `cargo test --locked -p bastion-server --test cli` | 通过：3/3（Windows fail-closed与loopback安全检查） |
| 真实 PostgreSQL / OpenSSH / 浏览器 UI | Windows 本机未运行；已在 y189 隔离环境运行并通过，详见后文 |
| 负载、50 会话、撤销延迟、1 GiB、备份恢复 | 未执行 |

Windows sandbox 的 Cargo HTTPS 下载曾因 schannel `SEC_E_NO_CREDENTIALS` 失败，
npm/esbuild/Node test runner 曾因子进程 `EPERM` 失败，rustfmt/Python 缓存替换曾被文件
权限拒绝；仅对精确命令申请一次较宽访问后完成相关检查。目录权限诊断备份保存在
项目忽略的 `.dsh-permission-recovery/`。没有移除 deny、修改所有者或关闭加密校验。

MSVC 14.50/14.44 原生依赖的调试记录构建曾报 D8050。仅为本次本机检查设置
`CARGO_PROFILE_DEV_DEBUG=0` / `CARGO_PROFILE_TEST_DEBUG=0`；缺 NASM 时使用依赖随包提供的
`AWS_LC_SYS_PREBUILT_NASM=1`。随后原生打包报系统 Temp 下 `LNK1104`，仅在检查进程
中将 `TEMP`/`TMP` 指向项目忽略的 `target/native-tmp`，完整原生依赖构建及所有目标
类型检查才成功。这些环境设置不写入项目生产配置，也不修改系统 Temp 权限。

## 远程 PostgreSQL 验收（用户授权的临时库）

使用用户提供的 PostgreSQL 17.11 实例，在 `postgres` 维护库上仅执行连接能力检查、
创建一个随机命名临时数据库；所有迁移、写入和测试都在该临时库中。TLS 连接已确认
加密，但该实例使用自签名且名称不匹配的证书；本次按用户明确确认使用 TLS 加密、
不验证服务器证书。生产配置没有关闭证书校验。

每次运行结束都通过数据库 OID、owner、唯一 comment marker 核对目标身份后删除临时库，
并复核数据库不存在。三次运行均完成清理，未修改 `postgres` 业务表；密码只经 stdin
进入进程，临时输入文件随后删除，未写入源码、argv 或日志。

实际结果：

- PostgreSQL 17.11 连接/TLS：通过。
- 0001、0002 迁移及重复迁移：通过。
- 审计写入检查：通过（12 条测试产生的事件）。
- `transaction_races_and_revocation`：失败，`issue_ticket` 约 2015ms 后触发既有
  2000ms 事务预算。
- `web_transport_owner_replay_expiry_and_login_domains`：失败，`issue_web_session`
  约 2002ms 后触发既有 2000ms 事务预算。
- 非敏感 `SELECT 1` 探针约 196–1140ms；两个事务都包含多次顺序数据库往返。

因此这不是通过结果，也没有通过修改预算来掩盖。结论是：当前远程公网数据库链路
不满足本实现为本地/低延迟部署设定的 2 秒策略事务预算。若要继续验收，应在同地域
低延迟网络或本机/内网 PostgreSQL 上复测；是否设计独立的部署级预算必须另行评审，
不能由测试参数静默放宽。由于没有目标 OpenSSH、浏览器或 SSH 隧道，本次仍不构成
真实 SSH/Web 浏览器端到端通过。

## y189 本机隔离真实验收（2026-10-05）

用户授权 SSH 别名 `y189` 为测试机。环境：Debian 13、PostgreSQL 17.11、
OpenSSH、Rust 1.95、Node 24.18、Python 3.13。用户明确同意安装缺少的
`build-essential/pkg-config` 并创建无 sudo 的 `bastion-acceptance` 测试用户；
Rust/Node 安装在该用户目录中，没有更改现有服务配置或生产证书设置。

源码在唯一隔离目录 `/var/tmp/bastion-acceptance-20261005-a6f8d2/source-b`；
每次 fixture 自动创建新的临时 PostgreSQL 数据目录与 target sshd，随机端口且
仅监听 loopback。未连接现有 5432 业务数据库。浏览器使用 SSH 隧道转发到
隔离 Vite DEV，浏览器 Origin 与后端 `public_origin` 精确一致；没有对公网
开放 Bastion/API/WS。此验收的本地 PostgreSQL fixture 使用 loopback trust，
仅适用于隔离测试，不作为生产连接安全方案。

### 自动化真实目标结果

- `cargo fmt --all -- --check`、workspace/all-targets/all-features clippy（`-D warnings`）、
  workspace/all-features tests：通过。真实 ignored 测试另由 fixture 显式执行。
- 前端 `npm test`：9/9；TypeScript/Vite build：通过。
- `tests/openssh_smoke.py`：通过；exec、Unicode、独立 stderr、exit、原始二进制
  stdin/EOF、标准 SSH PTY、SFTP 随机数据/SHA-256、多 channel、resize、host-key
  错配在认证前拒绝、票据重放及日志脱敏。
- `tests/m1_smoke.py`：通过；迁移、身份/资产/凭据/host key/grant、SFTP、原生
  活跃连接撤销/refresh replay 关闭 <3 秒断言、重启不复活。
- `transaction_races_and_revocation`：通过（约 7.7 秒整套运行时间，不是事务预算）；
  单次消费、锁后过期、策略 revision、撤销、2 秒事务上限断言。
- `web_transport_owner_replay_expiry_and_login_domains`：通过（约 5.6 秒）。
- `browser_cookie_origin_tickets_and_real_shell`：通过（约 5.0 秒）；Cookie/CSRF/
  Origin/query/ticket replay、原始输出、无 PTY 独立 stderr、PTY resize、logout。
- 2 秒生产事务总预算保持不变；先前公网 RTT 失败没有通过放宽超时来掩盖。

首次 M1 暴露 native logout 幂等 bug：Axum nested router 剥离 URI 前缀导致
middleware 的全路径匹配失效。改为匹配 `OriginalUri` 且限定 POST 后，现有
双次注销断言通过；没有接受其他受保护接口的 revoked token。

### 用户真实 Chrome / xterm 结果

通过已获用户许可的 DSH Browser Bridge 在独立测试标签页验收：

- Cookie 登录 operator，加载真实授权资产及目标账号（未使用 mock）。
- JS 只能看到 CSRF cookie，不能看到 session/refresh HttpOnly cookie；注销后
  Bastion cookie 消失。`localStorage` 无条目；`sessionStorage` 只见浏览器扩展
  插入的 `__imt_handshake_page_id`，未见应用票据。未直接验收 IndexedDB。
- 真实 WS response subprotocol 为 `bastion.v1`，URL 无 query；启动消息顺序为
  `session_ready → opened → pty_ready → ready`。
- xterm paste/Enter 经二进制输入帧进入真实 shell，执行返回 `BROWSER-中文🙂`、
  `BROWSER-ERR`；PTY 合流为正常语义，独立 stderr 由上述无 PTY Rust 用例验证。
- `stty size` 初始 `22 111`；改变终端宽度后返回 `22 69`，验证 resize 到达目标。
- `exit 7` 收到 `exit_code:7` 和 `closed`，页面保留终端历史；点击重新连接产生
  新 connection，重新完成四阶段启动。此正常 exit 的浏览器关闭码是 1005
  （无 close status），不是宣称所有正常完成路径均返回 1000。
- 从活跃新终端注销后 WS 关闭码 1000，页面显示已注销并移除 Bastion cookie。

测试捕获通过页面级 observer，仅记录本次 WS 控制类型、response protocol 和
虚构 shell 输出，不记录 ws_token、Cookie 值、连接凭据或用户其他页面数据。
Browser Bridge 合成 Enter 需要完整 legacy keyCode；只发送普通 key 的辅助工具
第一次未执行命令，补齐后核对了真实命令结果，不把命令回显算执行成功。

- 视觉重设计：登录与终端工作区改为深色安全控制台布局，保留原有认证、Cookie、WS、PTY 和测试用控件 ID；`npm test` 9/9、TypeScript 检查与 Vite build 通过。


两轮浏览器 hold 正常 stop 后退出码 0，临时 PG/sshd/gateway/Vite 全部退出，
临时数据目录和 ready/config 文件消失；已关闭本地 SSH 隧道。复核专用测试用户
无残留进程，服务器只剩原有 PostgreSQL 5432 与 sshd 22，原 PID 未变。
隔离源码/构建缓存/验收日志与批准安装的工具链、专用用户暂保留以便复测；不是
保留运行服务或测试密钥。开发 fixture 通过 `--browser-control-dir` 显式保留，
写 stop 或 30 分钟到期才收尾，默认 CI 模式行为不变。

尚未验收：HTTPS/WSS built bundle 的 Secure/SameSite 跨站浏览器场景、vim/top
全屏交互、浏览器 IME 手工输入（此次使用 paste）、浏览器撤销 <=3 秒量测、
50 会话/1 GiB/背压内存、备份恢复与 required 录制；不是生产就绪。

## 可重复的真实验收入口

Unix 测试主机需要 PostgreSQL（`BASTION_PG_BIN` 可指定 bin 目录）、OpenSSH
`ssh`/`sshd`/`sftp`/`ssh-keygen`、Python 3、Rust 1.95+。

```sh
cargo fmt --all -- --check
cargo check --locked --workspace
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
python3 tests/m1_smoke.py
```

脚本创建隔离 PG 与目标 sshd，显式迁移、建立批准主机密钥与 grant，在受限临时
fixture 文件中保存虚构测试凭据，并串行运行：

- `bastion-server/tests/postgres.rs`：既有 M1 竞态/撤销；
- `bastion-store/tests/web_sessions.rs`：20 消费者、transport/client_type/owner/login
  隔离、错秘密不消费、锁后真实时间、配置修订、撤销与 refresh replay；
- `bastion-server/tests/websocket.rs`：真实 Cookie 登录、CSRF/Origin/query 拒绝、
  ticket 重放拒绝、无 PTY 的独立 stdout/stderr/exit、PTY resize、注销与日志秘密检查。

这些是 **opt-in 真实集成用例**，已在上述 y189 隔离环境执行；Windows 本机没有
执行它们。原生 WebSocket 客户端不能代替真实浏览器行为，Chrome/xterm 结果另列。

## 明确边界

- `serve-m1` 两个 listener 必须 loopback；`public_origin` 明确配置才开放浏览器路径。
  Vite DEV 的 HTTP 仅允许 loopback；built bundle 所有 API 请求都要求 HTTPS。
  本地 HTTPS 代理可用于验收，但不得把没有 required 录制的入口作为生产部署。
- `/info` 固定 `production_ready:false`、`output_recording:not_implemented`。
  本批没有 `.ztrec`、SFTP Web UI、exec/工具 UI、管理 UI、回放、ZeroTerm 新集成路径。
- 每方向应用数据队列最多 8 × 32 KiB，协议库缓冲另计；不是已测进程内存上限。
- 30 分钟业务 idle、8 小时绝对期限；ping 不延长 idle；目标写入 30 秒超时后关闭
  会话，不继续可能丢数据的 shell。持续背压下的 JSON close 可能等到写入超时，
  不能宣称极端窗口阻塞下的所有关闭路径都在 3 秒完成。
- 正常授权复查每秒一次，DB 查询有预算、故障 5 秒宽限；撤销 <=3 秒仍需真实测量。
- API 为 gateway 预留 8 秒收尾，协议通道 RAII close 任务及现有 russh 初始 KEX
  取消生命周期仍有边界；不宣称所有内部 task 都结构化 join。
- 未录制 shell、凭据泄露、票据重放、串身份、host key 绕过、无界缓冲、数据破坏或
  状态复活都阻断生产发布。下一批应先完成真实 M2 验收与 required 录制。
