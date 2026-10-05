# 原生 SSH shell 正常关闭录制封存回归

> 这是候选版的确定性进程内协议回归，不是生产发布声明。测试使用真实 russh TCP 客户端、Gateway、固定测试公钥校验和真实加密录制文件；目标为进程内 SSH 测试 peer，元数据 backend 为可控 ACK 延迟的测试实现，不是真实 OpenSSH/PostgreSQL。`production_ready` 仍为 false。

## 根因与最小修复

旧的目标 `ChannelMsg::Close` 分支先发送上游 SSH Close，再由 bridge 调用录制 finish。客户端收到 Close 后立即断开，会触发 [GatewayHandler::drop](<../crates/bastion-gateway/src/protocol.rs#L399-L430>) 取消连接并 abort channel task；尚未完成的录制 finish ACK 被丢弃，actor 因而可能将正常结束的录制封存为 Partial / RECORDING_UNAVAILABLE。

修复只调整 [目标 Close 分支](<../crates/bastion-gateway/src/protocol.rs#L1162-L1169>)：

- 没有 recording 的 exec/SFTP/开发 shell 保持原有 `writer.close()` 路径。
- 有 recording 的 shell 不提前发布 Close；继续复用 [bridge 的既有 finish](<../crates/bastion-gateway/src/protocol.rs#L960-L989>) 和 [channel worker 的既有最终 close](<../crates/bastion-gateway/src/protocol.rs#L528-L544>)，只有录制封存 ACK 成功返回后才发布正常 Close。
- 无新增运行时抽象、依赖或 actor/store 状态回退逻辑。Web 路径、限额和安全验证未改动。

Complete 表示目标完整输出与 end 已校验封存、同步并生成 checksum；目标正常结束后，客户端晚到的传输断开不要求追溯撤销一个已提交的 Complete。这里不声称所有“正常目标结束之后、数据库提交期间”的取消竞态都会变成 Partial。

## 输入快照

隔离测试账号 `bastion-acceptance`（UID 1000）；唯一目录 owner0700；全新 Cargo target，不复用其他源码目录的构建 fingerprint。

```text
root: /var/tmp/bastion-native-close-regression-cab52b81
base release ZIP SHA-256:
bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9
```

基线 ZIP 之后仅覆盖下面三项输入；第三项为 lead 的 Unix 字段宽度 lint 修正，保留宽化乘法，仅对该转换添加有理由的 scoped allow，不改录制 actor 语义。

| 输入 | SHA-256 |
|---|---|
| [原生协议](<../crates/bastion-gateway/src/protocol.rs>) | `06cdab09562a9cda9c12a71c9faf04410a00d9811e77fc8807cfe59de31c58f1` |
| [新增回归测试](<../crates/bastion-gateway/src/protocol/native_close_tests.rs>) | `0c3a92e16f4936c4f46f638be118080ee43bfeebd69c1d4a62d5b5655a1c0259` |
| [录制目录容量检查](<../crates/bastion-gateway/src/protocol/recording.rs#L589-L595>) | `b631437000a8d857ad96d6d6197a315211b468345039ba6758f6c10b4e932110` |

## 确定性测试与负对照

[健康关闭测试](<../crates/bastion-gateway/src/protocol/native_close_tests.rs#L372-L377>) 通过 semaphore 阻塞元数据 finish ACK，断言客户端至少在该门控期间收不到 Close；放行后立即断开客户端，并检查：

- 原始输出 `native-close-output\0\xff` 不改写，exit status 为 7。
- 恰好一次封存，Complete、无 failure。
- checksum 非空且等于实际加密录制文件 SHA-256。

[取消测试](<../crates/bastion-gateway/src/protocol/native_close_tests.rs#L378-L383>) 在目标尚未发 Close 时取消 Gateway，断言录制最终为 Partial，不将中断当作 Complete。

负对照只在独立远端测试副本中恢复旧的提前 `writer.close()`；健康关闭测试以退出码 101 失败，断言恰为 `SSH Close exposed before recorder metadata ACK`，不是编译或环境错误。负对照结束后，patched 源文件按字节恢复，随后全部 Gateway 回归再次通过。详见 [负对照日志](<../target/native-close-evidence/old-close.log>)。

## 验证结果

| 环境与检查 | 结果 |
|---|---|
| Linux `cargo fmt --all -- --check` | 通过 |
| Linux Gateway all-targets/all-features strict clippy `-D warnings` | 通过，5.62 s |
| Linux Gateway all-features 单元测试 | 13/13 通过，0.29 s；含两项新增 Unix 录制关闭回归 |
| Windows MSVC 14.44、DEV/TEST debug0、预编译 NASM strict Gateway clippy | 通过，10.23 s |
| Windows Gateway all-features 单元测试 | 11/11 通过，0.03 s；两项新增 Unix 测试按 cfg 排除，不能算作 Windows 通过 |
| Linux 全工作区 all-targets/all-features check | 通过，25.21 s |
| Linux 全工作区 all-targets/all-features strict clippy `-D warnings` | 通过，13.27 s |
| Linux 全工作区 all-features test | 65 项通过、6 项真实 fixture 用例 ignored；ignored 不算通过 |

完整工作区记录：[check 日志](<../target/native-close-evidence/workspace-check.log>)、[strict clippy 日志](<../target/native-close-evidence/workspace-clippy.log>)、[test 日志](<../target/native-close-evidence/workspace-test.log>)。

保留的公开证据：[机器可读摘要](<../target/native-close-evidence/summary.json>)、[最终 Gateway 测试](<../target/native-close-evidence/gateway-final.log>)、[最终 strict clippy](<../target/native-close-evidence/clippy-final.log>)、[format 输出](<../target/native-close-evidence/fmt-final.log>)。这些日志无 token、密码或真实目标凭据。

## 可复现命令

在已准备候选输入的独立 Unix 目录执行：

```sh
export CARGO_TARGET_DIR=/var/tmp/bastion-native-close-regression-cab52b81/target
export CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0
cargo fmt --all -- --check
cargo test --locked --offline -p bastion-gateway native_close_ -- --nocapture
cargo clippy --locked --offline -p bastion-gateway --all-targets --all-features -- -D warnings
cargo test --locked --offline -p bastion-gateway --all-features
```

## 发布边界

此前 canonical 快照的真实 CLI、恢复和一小时负载结果不能自动代表此补丁版本。还需用新快照重跑真实 PostgreSQL/OpenSSH 原生 shell 正常关闭、录制 metadata/replay 与双入口回归，并按总验收记录判定剩余故障/恢复/负载门槛。不得仅凭本回归将 `production_ready` 改为 true。
