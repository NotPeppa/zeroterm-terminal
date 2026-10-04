# Bastion Web

最小 TypeScript + Vite + xterm.js 浏览器客户端，提供同源登录、授权资产/目标账号选择和一个真实 WebSocket PTY 终端。页面不模拟目标连接：登录、CSRF、资产、会话票据和二进制终端数据均走后端契约。

## 构建与检查

```sh
cd web
npm install
npm run check
npm test
npm run build
```

`package-lock.json` 固定依赖；已安装环境/CI 用 `npm ci`。需要 Node >=22.18（协议测试直接运行原生 TypeScript，不引入测试框架）。开发模式用 `npm run dev`，Vite 将同源 `/api` 与 WebSocket 代理到 `http://127.0.0.1:8080`。**后端 `public_origin` 必须设置为浏览器实际开发地址（默认 `http://127.0.0.1:5173`）**，不要关闭 CSRF/Origin 校验来适配代理；仅明确开发的 loopback HTTP 可以使用非 Secure Cookie。生产必须 HTTPS/WSS，由 bastion-server 同源提供 `dist/`，不要单独启动第二个服务。**构建出的 `dist/` 即使部署在本机 `http://127.0.0.1:8080` 也会在发送任何 API（包括登录密码）前拒绝 HTTP；loopback HTTP 联调必须使用 Vite DEV，不能使用 built bundle 或 `vite preview`。**

依赖仅有 TypeScript、Vite、xterm 与 fit addon；没有 React、状态管理、测试框架或持久浏览器数据库。

## 协议边界

- 登录只发送 `client_type: "web"`，认证依赖同源 Cookie；CSRF token 只在内存中保存，状态变更使用 `X-Bastion-CSRF`。HTTP 请求 15 秒超时、禁止跨源重定向、无隐藏重试。
- 刷新只能用户主动触发，每次登录在本标签页至多提交一次，用原生 Web Locks 阻止跨标签页并发轮换；不支持 Web Locks 时要求重新登录。刷新失败清除内存，不自动重试或重放 mutation。
- WebSocket 握手失败只执行一次 `GET /connections/{connection_id}` 诊断；错误显示阶段、稳定 code 与 request_id（服务端未提供时明确标为不可用）。
- WebSocket ticket 只在内存中保存；握手成功后清除引用。断线只能手动重新申请新票据，绝不重放输入或其他 mutation。
- channel 固定为 `1`。JSON 控制帧使用 `v: 1`；二进制帧是 6 字节大端 header（version、kind、channel_id）加最多 32 KiB 原始负载。输出直接交给 xterm，不自行 UTF-8 解码。
- 背压超过 256 KiB 时显示错误并断开，避免静默丢输入。resize 做 100ms debounce；连接状态按 session_ready → opened → pty_ready → ready 推进。

## 验收

`npm test` 覆盖帧头/通道/版本、32 KiB 分块、跨 UTF-8 边界字节无损、stdout/stderr、非法长度、背压及启动状态机。真实浏览器 + OpenSSH 集成需等待同源后端装配：登录后读取授权资产，验证 PTY/中文/全屏应用/resize，断线后显式申请新票据，注销关闭 WS。前端单测不代替票据原子消费、目标主机密钥、权限撤销或真实 SSH 输出验收。

这是第一批终端纵切：未加入 SFTP、工具或管理按钮，避免展示未实现授权能力。
