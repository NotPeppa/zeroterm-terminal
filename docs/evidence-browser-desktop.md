# 真实浏览器与 ZeroTerm desktop 验收

`production_ready=false`。以下区分用户实际观察、自动化结果和未完成项，不用Node模拟浏览器或Tauri WebView。

## 环境与严格TLS

- y189 canonical ZIP：`bd7248cd95214007b7bb3e4f31387c6070788a80d947cd75df7b7459f32035f9`；共享native fixture运行UID1000，独立PG/OpenSSH/gateway，未使用既有5432/22服务。
- HTTPS入口`https://localhost:52345`，SSH入口`127.0.0.1:51569`；本地loopback SSH隧道，不开放公网测试监听。
- 本机UTC时钟比测试服务器慢约8小时，初次新证书在本机判为尚未生效。用户选择另建显式有效期覆盖两端的测试CA/leaf；未改任一系统时钟、未关闭TLS/Host Key验证。
- [测试TLS辅助脚本](../tests/release_browser_tls.py)使用OpenSSL CA签发，SAN为localhost/127.0.0.1，有效期UTC2026-10-04至2026-10-08。额外TLS代理PID691217只转发既有隔离API33815。
- 用户明确允许仅在Windows当前用户Root存储临时导入该测试CA，验收结束精确移除。旧CA指纹`B00AB396EEC4A2A5E5ED78A69E07F6F50C02DFB6`已删除；当前临时指纹`5DA4FB569635161F203BEEB972DA5D046D111B49`尚待结束清理。
- 原生profile内含公共CA PEM与SSH pin；临时用户名/密码仅0600远端文件和收紧ACL的本机临时文件。对话与公开证据不记录其值。

## 用户桌面实际反馈

- 已提供临时profile的7项公共配置，CA使用实际换行PEM而非JSON中的反斜杠转义。
- 用户表示其余操作正常，并随后明确确认：在ZeroTerm自己的“堡垒机”弹窗找到“注销”，注销后保持打开的终端断开连接。
- 因未收到逐项hash/connection ID截图，不额外推断桌面文件SHA-256、进程内重连新ID、错误CA/pin实机负例或全部工具闭环均通过。正式CLI的独立实测见 [native证据](evidence-native.md)。

## 真实Chrome页面故障与根因

用户Chrome154的实际检查：

- `AbortSignal.any`与`AbortSignal.timeout`均为function，`isSecureContext=true`，故不存在缺失这两个API导致本次错误的问题；未增加不必要兼容层。
- 直接导航`/api/v1/info`可读JSON；本机严格TLS的公开info及csrf请求各返回HTTP200和request ID（未输出Cookie/CSRF值）。
- 首页即使强刷仍显示`NETWORK_OR_TIMEOUT`、request_id不可用。用户看到页面“不安全”指示但证书有效；尚未据此推断所有浏览器安全状态正常。
- 直接`fetch('/api/v1/info',...)`能完成；用户按对象方法调用原生fetch的对照实验准确得到：`TypeError: Failed to execute 'fetch' on 'Window': Illegal invocation`。
- [共享API入口](../web/src/api.ts)保存未绑定的原生fetch，并通过`this.transport(...)`调用，接收者变为ApiClient而非Window。Node/mock fetch不校验Window接收者，既有测试因此未捕获此浏览器错误。

最小修复已完成：共享transport绑定到globalThis，生产代码只改一行；接收者回归在旧版本失败、修复后通过，Web25/25测试、typecheck与Vite build通过。没有增加Abort兼容层或副作用自动重试。

新静态包只更新观察到的隔离web_root，未重启gateway或改动用户桌面会话：静态ZIP SHA256`f2e93a2f804a72796553a58e8c56090a79d7ab4addbf4fe8a7c48bf30e57b1ca`；JS`index-B8N_4Pts.js` SHA256`b650d47a964b89f353052b7342be2881e151c8f0b26e0d4188bff03a0ce09ed4`；index SHA256`9f71c27bbaf3912f867accc8d0565834cb20916bf6915c64eed638baa2aed0eb`。远端hash匹配，本机严格TLS请求首页HTTP200并确认引用新bundle。

用户强刷后明确选择确认：“登录和资产正常，终端标记正确，注销关闭”。这建立了真实Chrome核心登录/资产/终端/注销链路通过证据。浏览器文件SHA、Exec原始两流、回放、管理员CRUD/授权修订闭环尚未逐项人工确认，不能据此记为全部Web验收通过。用户先前看到“不安全”指示但证书有效，需结束前明确核对浏览器安全UI；未进行任何证书校验绕过操作。

## 清理与尚未完成

- 浏览器桥不稳定，出现扩展断连/注入超时；没有截图证据时不得冒充自动化浏览器通过。
- 共享fixture、额外TLS代理及HTTPS/SSH隧道仅在用户验收时保留，分别有最长2小时TTL；结束后须通过自有stop文件收集进程，精确删除临时CA、受限登录副本及临时profile，不动用户旧会话。
- 原生关闭竞态的后续三文件补丁与此运行中的原始backend快照不同，需单独记录修复后录制/回放实测，见 [关闭竞态证据](evidence-native-close.md)。
