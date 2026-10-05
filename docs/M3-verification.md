# RFC-004 候选版验收状态

> 发布门槛未全部通过，`production_ready=false`。代码实现收口不等于发布批准；历史失败、未测项和不同源码快照不得合并成一次“全部通过”。

## 冻结范围与源码

- Web 与 ZeroTerm desktop/CLI 双入口；不包含 Android/iOS、HA、Redis、端口/Agent/X11 转发。
- 保留 2 秒数据库事务预算、严格 HTTPS/CA/Origin/CSRF 与 SSH Host Key pin。
- 普通 SFTPv3 无法保证原子 no-follow，跨主机复制明确禁用：`copy_jobs=false`。
- 本轮统一候选 ZIP SHA256：`bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9`。每个隔离环境独立解包、使用全新 target，并记录 binary/runner/source identity。
- 契约见 [M3-final-contract](M3-final-contract.md)、[WebSocket v1](websocket-v1.md)。

## 已建立的证据

| 验收范围 | 实际结果 | 仍不等同于 |
|---|---|---|
| 本地 Rust 全工作区 | Windows format、all-targets/all-features check、严格 clippy、workspace test 通过；gateway11、secrets15；真实 fixture 用例默认 ignored | Linux严格clippy或真实环境验收全部通过 |
| Web 与 native 分包 | Web24项与build；ZeroTerm app26/CLI2/SSH3/desktop Node4项通过 | 桌面实机交互、最终浏览器管理闭环 |
| y189 PostgreSQL/OpenSSH | 0001–0005与重复迁移、lifecycle/revision/device/recovery、M1票据竞态/Web登录域/真实shell回归通过 | 最终负载和故障矩阵 |
| y189 HTTPS/WSS | 双目标候选自动化smoke通过，required recording available，设备撤销、Exec/SFTP/回放 | 用户真实浏览器与桌面同时操作 |
| 真实 ZeroTerm CLI | Managed profile/login/asset/shell、原始stdout/stderr、exit7、EOF、不同正式票据、1MiB SFTP校验、错误CA/SSH pin与转发拒绝通过 | native进程内重连、desktop注销关闭 |
| 备份/恢复/KEK | 独立pg_dump/pg_restore、凭据认证、相同录制回放、Host Key不变、旧登录/票据失效、重包裹数据密文/nonce/录制文件不变、新KEK-only验证通过 | 尚未执行的真正ENOSPC/阻塞写入 |
| 录制与运行故障 | 损坏/截断标Corrupt、权限/低空间拒绝、SIGKILL恢复Interrupted、DB fast-stop shell0.671s关闭；设备撤销0.029s | 正常shell录制封存竞态已经部署解决 |
| 审计离线分区 | 升级幂等、过期分区单次删除、default保留、运行时UPDATE/DELETE/TRUNCATE/DROP拒绝、重复迁移通过 | 长期180天分区运营、所有catalog/registry漂移覆盖 |

详细结果与输入身份分别见 [native报告](evidence-native.md)、[恢复报告](evidence-recovery.md)、[负载报告](evidence-load.md)。恢复的 [canonical阶段JSON](../tests/release_recovery-evidence-canonical.json)保留独立断言和时间戳。

## 进行中 / 明确未通过

1. **Native正常shell关闭竞态：真实历史失败已定位。** 客户端观察SSH Close后立刻断线，可能在录制Complete封存ACK之前取消桥接任务，导致正常exit7却记录Partial/RECORDING_UNAVAILABLE。canonical相关代码与失败快照相同，单次恢复验收通过不能证明消失。最小修复复用channel_worker已有“bridge完成后关闭”路径，录制shell不提前发送Close。Linux确定性正例通过；只恢复旧Close的负对照以“SSH Close exposed before recorder metadata ACK”断言失败。局部statvfs跨平台lint修正完成后，补丁版本Linux全工作区all-targets/all-features check、严格clippy及all-features测试通过：65项通过、6项真实fixture ignored；Windows Gateway严格clippy与11项测试通过。证据见 [native关闭竞态回归](evidence-native-close.md)。修复版本真实PostgreSQL/OpenSSH关闭/回放复验仍待完成。
2. **完整一小时负载：原canonical运行完成。** 50条基础终端及20条混合终端从`2026-10-05T17:36:42.532Z`持续3625.161s；70条正常记录Complete、10条刻意撤销记录Partial，活动connection/channel/recording最终为0，自有进程与7个监听均清理。4路1GiB上传/下载SHA匹配；gateway RSS峰值46.54MB、FD255→32停机前，回显P95=16.099ms。该小时只覆盖原canonical backend，不冒充后续native关闭修复或SFTP流水线版本通过。
3. **严格匹配吞吐未通过，不能发布。** 原canonical“四路对四路、总字节/完整wallclock”直连331.99/308.70MB/s，Web HTTP文件代理148.05/161.32MB/s，即44.593%/52.258%，低于70%。原70.714%/90.146%是四路代理对单路直连，仅保留诊断用途；非canonical历史27.53%/29.97%失败也保留。正实施固定有界bulk流水线，元数据与文件共享预算，不以降低直连并发或无界缓冲伪造通过；补丁需另行测试。
4. **真实浏览器与桌面核心人工链路通过，剩余UI问题修复中。** 用户确认ZeroTerm桌面注销后终端断开；Chrome154原生fetch错误已实际重现并通过共享transport单行绑定修复，25项Web测试与build通过、同URL部署后用户确认登录/资产/终端/注销正常。用户又反馈“选择回放”无反应、上传入口难懂，已定位真实点击处理与布局根因，修复和实机复验进行中。详细范围见 [双入口实机证据](evidence-browser-desktop.md)，不把尚未完成的管理CRUD、重连、新connection ID或上传SHA记为通过。
5. **真正磁盘满与阻塞写入已执行。** 512MiB独立ext4 loop内实际ENOSPC/free0，未转发marker，录制Partial且0.003060s关闭；实际fsfreeze、内核write等待与7.606783s独立watchdog解冻，未转发marker，最终Partial而非Complete。外部marker发送到客户端Close严格≤5s的额外断言以5.005028s失败并保留exit1，不圆整为通过、不修改ACK预算遮盖测量；RFC写入等待5s与端到端观测需明确区分。两个postfix真实PG/native关闭环境各20次Complete/seq/checksum/回放通过。管理资源全清理，见 [真实录制故障证据](evidence-recording-faults.md)。实际ZeroTerm CLI补丁后复验由新独立健康fixture继续，原故障前150s交接超时明确未测。
6. **审计运行时ACL需受控DBA配置。** 离线升级新parent默认owner-only，运行时角色须显式授予SELECT/INSERT；不自动扩大ACL、不关闭append-only trigger、不删除default。

## 隔离与发布规则

所有服务端验收使用y189的`bastion-acceptance` UID1000、唯一0700目录、虚构凭据和动态loopback监听；现有PostgreSQL5432/SSH22及其他服务不变。root只用于明确受控的测试资源管理，不运行gateway/PG目标工作流。Tokens、tickets、密码、私钥不进入argv、公开证据或工具输出。

不同修复版本的证据必须区分来源。只有RFC第18节安全、required recording、恢复、两入口及性能阻断条件全部通过，并有可复现实测证据，才允许发布审批；当前目标保持进行中。
