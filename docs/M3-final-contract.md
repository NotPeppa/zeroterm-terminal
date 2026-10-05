# RFC-004 首版最终实现契约（M3–M5）

状态：实施冻结草案。本文只记录本轮实现中已决定的增量契约；M1/M2 旧路径保持兼容，生产就绪仍由 required recording、恢复和负载验收决定。

## 1. 范围与不变量

- 单组织、单 gateway 进程、PostgreSQL；不引入 Redis、outbox、多副本或 HA。
- Web Cookie 域与 ZeroTerm Bearer/SSH ticket 域保持隔离；目标凭据只在服务端内存短暂解密。
- 目标 SSH 由 gateway 建立；浏览器只访问同源 HTTPS/WSS/受控文件流，不能选择目标地址或取得凭据。
- 每个连接绑定 user、login_session、asset、target account、transport、protocol version；Web/SSH 入口共享全局连接与 channel 限额。
- 数据库事务总预算继续为 2 秒。文件/网络/录制 I/O 不持有策略锁，也不每帧访问数据库。
- `production_ready=false` 直到 required shell recording、回放、恢复和发布验收全部通过。

## 2. 能力发现

`GET /api/v1/info` 在不泄露资产或密钥的前提下返回：

```json
{
  "protocol_version": 1,
  "websocket_protocol_version": 1,
  "ssh_protocol_version": 1,
  "minimum_client_protocol_version": 1,
  "production_ready": false,
  "recording": {"required": true, "available": true, "format_version": 1},
  "features": {
    "ssh_terminal": true,
    "ssh_exec": true,
    "ssh_sftp": true,
    "web_terminal": true,
    "web_exec": true,
    "web_sftp": true,
    "recording_replay": true,
    "copy_jobs": false,
    "device_sessions": true
  }
}
```

字段必须反映真实装配能力；客户端不能根据静态导航假设功能存在。

## 3. Web/管理 API 增量

现有用户、资产、账号、凭据、Host Key、Grant CRUD 与 If-Match 语义不变。新增或补齐：

- `GET /me/sessions`、`DELETE /me/sessions/{id}`：仅返回设备标签、当前标记、创建/到期/撤销状态；本人只能撤销本人设备。
- `GET /connections` 与 `GET /audit-events`：服务端支持时间范围、actor、resource、action、state、transport 过滤；过滤器纳入 cursor scope。
- `GET /recordings/{id}` 与 `GET /recordings/{id}/content`：所有者/admin/auditor 读取；当前用户必须仍启用且 login session 有效，但不要求历史目标 Grant。内容是服务端鉴权、解密、校验后的 `application/x-ndjson`，`no-store`、无 Range、无公开文件路径、无 KEK/DEK 下发。
- `POST /integrations/zeroterm/connection-tickets`：正式路由到现有 SSH ticket 事务；保留旧兼容路径。响应字段为 `protocol_version,ticket_id,ticket_secret,connection_id,gateway,capabilities,expires_at`。
- Web `POST /sessions` 允许 `shell|exec|sftp` 能力；purpose 仍只用于审计，不用于授权决策。
- 浏览器文件操作使用服务端 SFTP：目录/元数据 JSON；download GET、upload PUT 流式；上传服务端随机临时文件成功关闭后 rename，默认 no-overwrite，无自动重试。
- exec 保留原始 command bytes，最大 64 KiB，拒绝 NUL；控制消息允许约 96 KiB 的 exec-start，普通控制帧保持 8192 UTF-8 bytes；返回 stdout/stderr 原始 bytes 与 exit/exit-signal。
- 最小 copy job 的 API 形状已冻结，但首版能力发现为 `copy_jobs:false`：标准 SFTPv3 没有原子 no-follow open，无法满足本项目安全保证时必须拒绝并返回稳定的 `TARGET_REQUEST_REJECTED`/unsupported 状态；不能以 lstat 后 open 的竞态实现冒充安全复制。

## 4. WebSocket channel v1 增量

- 兼容旧 `open`（没有 kind 时为 shell）；新 `open.kind` 为 `shell|exec|sftp`。
- 新增 `exec_start`、`sftp_open`；每个 channel 独立状态、取消和目标 channel 映射；一个 channel 的 close/error 不关闭同连接其他 channel。
- 二进制 6-byte header 与 32 KiB payload 不变：input=1、output=2、stderr=3。channel id 非零、同一连接不复用；16/channel connection、64/channel user 限额跨 Web/SSH 入口合并。
- shell recording 仅记录 target output/stderr、meta、resize、exit、end；不录输入、不录 exec/SFTP 输出。输出进入客户端前必须收到 recorder write ACK。
- disconnect、授权撤销、DB grace、绝对时长、stall/idle 或 shutdown 可关闭连接；重连必须重新申请票据，不重放副作用。

## 5. Required recording

使用 RFC-004 `ZTREC001`，不压缩。文件由服务端生成的相对路径保存，权限 0600；header 最大 16 KiB。每个 shell 独立 DEK，nonce 为随机 16-byte prefix + u64 chunk sequence，AAD 绑定 header hash、recording UUID、chunk sequence。chunk sequence 与 event seq 独立且连续；未知尾部/序号/认证错误立即 partial/corrupt，重启不续写未知序号。

shell 启动顺序：短事务创建 channel + recording(preparing) + audit → 事务外 create-new 文件并写 header → 短事务复核授权并置 active → 才请求目标 shell。任一步失败则拒绝 shell。

每 shell 一个有界 recorder queue（8×32 KiB 起步）和 writer ACK。sequencer 对 output/stderr/resize/exit/end 排序；最多 250ms/256 KiB 批次，每秒 fsync，正常结束 fsync+checksum+seal；写入错误、低磁盘、ACK/写超时 5 秒或 metadata 不可维护时 fail closed。没有 ACK 的字节绝不发送到 Web/SSH 客户端。

## 6. 运维与恢复

- `serve` 生产配置必须显式 recording directory、required、retention、free-space、limits、trusted proxy、metrics listener；目录 owner/mode、KEK、schema、free space、gateway lock 不满足即不 ready。
- shutdown 停止新 ticket/channel，最多 10 秒 finalize recording/audit 后退出；gateway lease 丢失即 shutdown。
- retention 不删除 active；missing/corrupt 告警；audit 应保持应用层 append-only，过期清理由受控维护 CLI/分区完成，不能关闭 trigger。
- `verify-backup` 校验 DB manifest、全部在用 KEK、凭据解密、Host Key、代表性 recording replay；恢复标记活动连接 interrupted、撤销历史 login family/未消费 ticket，不复活任何票据。

## 7. ZeroTerm 客户端

相邻 `ZeroTerm` 已有 `BastionManager`、`ManagedConnection/ManagedSession`、Tauri profile/catalog UI、HostAuth::Bastion 与 CLI bastion 流程。本轮只收口兼容：正式 `/info` feature gate、正式 SSH ticket、严格 server_id/HTTPS/CA/SSH fingerprint、能力检查和 reconnect 新 ticket。ticket/token 不进入 Vault、sync、argv、日志或 IPC 返回值；用户手动输入的登录密码仅允许一次瞬时 JS→Rust 输入 IPC，前端立即清空，Rust 使用 Zeroizing，禁止缓存、日志或响应回传；Managed 连接禁止 ProxyJump、forward、agent、direct-copy 逃逸；Android/iOS 不改。

## 8. 发布阻断

录制只有数据库 `complete`、存在并可安全打开、Reader 验证连续 chunk/event、首个 meta、最终 end、干净 EOF，且 checksum/bytes 与 metadata 一致时才显示完整；partial/failed/corrupt/missing/expired 一律不是完整录制。录制路径是服务端生成的扁平 `.ztrec` basename，不接受嵌套相对路径。审计表仍为 append-only，分区/受控 180 天清理尚未实现，不能在 production_ready 门控中宣称已完成。


串身份/串目标、凭据下发或日志泄露、ticket replay、Host Key bypass、网关本机执行、数据损坏、撤销失效、无界内存、recording 静默丢数据、恢复复活 ticket，任一出现即阻断发布。