# ZeroTerm Browser Bastion

自托管的**纯浏览器** SSH / RDP / VNC 工作台。用户只需要浏览器：不用装客户端、不用拿目标密码、不用开 VPN。
目标凭据只在服务端内存里短暂解密，永远不会下发到浏览器。

> **候选版本，请勿直接上生产：`production_ready=false`。**
> 这是可以部署、可以试用的候选实现；发布验收还没全部通过，依据见
> [验收状态](docs/M3-verification.md) 和 [执行证据](docs/guacamole-execution.md)。

---

## 1. 它能做什么

| 协议 | 浏览器里跑什么 | 说明 |
|---|---|---|
| SSH | Rust SSH/PTY + xterm.js | 文本终端，支持复制粘贴、搜索、字号调整，10000 行回滚缓冲 |
| RDP | 私有 guacd + Guacamole 前端 | 仅 NLA / TLS，证书指纹强校验 |
| VNC | 同上 | none / password，且只允许管理员显式信任的网段 |

每个连接都会写一份加密录制（`ZTREC002`）。只录屏幕输出，**不录键盘、不录凭据**。录制只有在完整结束、
校验通过后才显示为"完整"，可离线回放。

**明确不做**：原生 SSH 入口、SFTP/文件管理、跨主机复制、端口转发、Android/iOS 客户端、多副本 HA。

---

## 2. 部署（Docker，约 5 分钟）

### 2.1 前置条件

- Linux 服务器，Docker 26 + Compose 2.26（实测版本）
- **1 核 1 GB 可以支撑 10 路正常交互**：全部服务硬限制在 1 CPU / 1 GiB / 不许 swap 的环境里实测，
  同时在线 4 路 SSH + 3 路 RDP + 3 路 VNC（默认上限），内存峰值 264 MiB，CPU 占单核 8–14%，
  SSH 按键回显 p50 约 350 ms。空闲时约 85 MiB。
  **多路同时持续大量输出**（例如几个终端一起刷屏）在 1 核下**没有在独立环境验证过**：
  测试机自身内存不够，结果不可信。这类场景建议 2 核起步
- 一个域名和证书，或者用自签证书做内网测试
- 一个非 root 的运行用户

### 2.2 获取部署文件

从仓库 main 分支下载 `compose.yaml`、`.env` 模板和配置模板：

```sh
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/compose.yaml -o compose.yaml
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/.env.example -o .env.example
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/config/production.example.toml -o production.example.toml
# 用自带的 proxy 容器才需要；已有 nginx / Caddy 可以不下
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/deploy/nginx.example.conf -o nginx.example.conf
# 可选：磁盘维护脚本，见第 5 节
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/deploy/maintenance.sh --create-dirs -o deploy/maintenance.sh
```

### 2.3 检查网段不冲突

默认占用的 Docker 网段：

```
172.30.61.0/29   api ↔ guacd 专用 bridge
172.30.62.0/24   内部 app 网络
172.30.63.0/29   proxy ↔ api ingress
```

先确认这些网段在你机器上没有被别的容器或主机路由占用。如果冲突，需要同时改 `compose.yaml` 的固定 IP、
`production.toml` 里的 `bridge_bind` / `allowed_source_ips` / `api_listen`，以及 `nginx.conf` 的上游地址。

### 2.4 准备配置和证书

```sh
cp .env.example .env && chmod 600 .env    # 部署用的变量都写在这里，见 2.5
mkdir -p .local/docker/tls
cp production.example.toml .local/docker/production.toml
cp nginx.example.conf       .local/docker/nginx.conf

# 维护用配置只差数据库连接串（owner 权限）
sed 's|^database_url_file = .*|database_url_file = "/run/bastion-db/database-url"|' \
    .local/docker/production.toml > .local/docker/maintenance.toml

chmod 644 .local/docker/*.toml .local/docker/nginx.conf
```

必须改的地方（`production.toml`）：

| 配置项 | 改成什么 |
|---|---|
| `server_id` | 一个固定的标识串，**建好之后不要再改** |
| `public_origin` | 你实际访问的地址，如 `https://bastion.example.com`（必须与浏览器地址完全一致） |
| `[network] allow` | 只放你真正要连的目标网段，默认的 `0.0.0.0/0` 太宽 |
| `[guacd] vnc_trusted_cidrs` | 要用 VNC 才填，否则留空 |

证书放两个文件，文件名固定：

```sh
# .local/docker/tls/bastion-chain.pem   证书链
# .local/docker/tls/bastion-key.pem     私钥
```

`.local/docker/nginx.conf` 里的 `server_name` 也要改成你的域名。

> **想把配置放在别处？** 默认目录是 `.local/docker`（相对 `compose.yaml`），整个 `.local/` 已被 git 忽略，
> 适合 git clone 部署。只下载了 `compose.yaml` 的话，可以在 `.env` 里写 `BASTION_CONFIG_DIR=.`，
> 配置直接平铺在同目录；也可以写绝对路径，如 `/etc/zeroterm-bastion`。上面命令里的 `.local/docker` 换成同一个目录。

> **服务器上已经有 nginx / Caddy？** 证书和 `nginx.conf` 都只给自带的 `proxy` 容器用，可以不准备：
> 不建 `.local/docker/tls/`，不复制 `nginx.example.conf`，`chmod` 那行去掉 `nginx.conf`。
> 只需要 `production.toml` 和 `maintenance.toml`，证书在你自己的反代上配。具体看 [2.7](#27-已经有-nginx-或-caddy)。

### 2.5 启动应用（拉取镜像、初始化、建表、授权都自动完成）

先改 `.env`（2.4 里从 `.env.example` 复制的）：

| 变量 | 说明 |
|---|---|
| `COMPOSE_PROJECT_NAME` | Compose 项目名，自己取，代替每条命令的 `-p`。**定了之后不要改**，改了就是另起一套空的部署 |
| `BASTION_ADMIN_PASSWORD` | 可选。不设就自动生成，打印到日志里，见下面"管理员密码" |
| 其他 | 配置目录、镜像版本、端口、最小密码长度，模板里有注释和默认值，不改就用默认值 |

所有 `docker compose` 命令都要在 `compose.yaml` 所在目录执行，Compose 会自动读同目录的 `.env`。

```sh
# 拉取镜像后直接启动（已有 nginx / Caddy 的话，末尾加上 bastion guacd，不起自带代理，见 2.7）
docker compose pull
docker compose up -d --wait
curl --fail https://你的域名/health/ready      # 期望输出 ok
```

这一条命令会按顺序跑完几个一次性步骤，每步成功后才进入下一步，任何一步失败应用都不会启动：

| 一次性服务 | 做什么 |
|---|---|
| `init` | 首次部署时生成 KEK 和两套数据库密码；已经初始化过就直接跳过。如果发现密钥卷只初始化了一部分，会拒绝继续，不会覆盖 |
| `migrate` | 用 owner 账号建表；升级时执行新增的迁移 |
| `grant-runtime` | 刷新运行账号的最小权限 |
| `bootstrap-admin` | 还没有管理员时创建 `admin`；已经有管理员就跳过 |

应用本身用的运行账号**没有改表权限，也改不了审计记录**；只有上面这几个一次性步骤拿得到 owner 账号。
哪一步失败了，`docker compose logs init migrate grant-runtime bootstrap-admin` 能直接看到原因。

#### 管理员密码

| 你怎么设 | 结果 |
|---|---|
| 什么都不设 | 自动生成一个 43 位随机密码，**只打印这一次**：`docker compose logs bootstrap-admin` |
| `BASTION_ADMIN_PASSWORD=...` | 用这个密码，日志里不会出现它 |
| `BASTION_ADMIN_PASSWORD_FILE=/容器内路径` | 从文件读第一行，需要你自己把文件挂进 `bootstrap-admin` 容器 |
| 密码短于最小长度 | 直接失败，应用不启动，不会悄悄改用生成的密码 |

- 用户名默认 `admin`，可用 `BASTION_ADMIN_USERNAME` 改。
- **最小密码长度**默认 12 字节，可用 `BASTION_PASSWORD_MIN_LENGTH` 改（允许 8–32）。它对所有密码都生效：
  首个管理员、新建用户、重置密码、自己改密码。超出范围时服务直接启动失败，不会悄悄回退到 12。
  中文等字符按 UTF-8 计算，一个汉字算 3 字节。
- **只在第一次生效。** 已经有管理员之后，这些变量会被忽略，以后再 `up` 也不会重置密码。
  忘了密码用 `reset-user` 命令，不是改这个变量。
- 写在 `.env` 里的密码会留在磁盘上，也会留在容器配置里（`docker inspect` 能看到），日志里的生成密码在删掉
  `bootstrap-admin` 容器前也一直在。所以**首次启动后把 `.env` 里的 `BASTION_ADMIN_PASSWORD` 删掉，
  首次登录后到"个人设置"里改掉密码**。

### 2.6 guacd 的出站隔离（自动，不用操作）

guacd 负责解析 RDP/VNC 目标发来的数据，按"它可能被攻破"来设计：它只能回应应用、连回应用，
碰不到宿主机、目标机和公网。

这由 `guacd-net` 容器自动完成：它持有 guacd 的网络命名空间，每次启动都在里面写好防火墙规则，
规则写好之前 guacd 不会启动。宿主机重启、容器重建都会自动重新生效，**不需要 sudo，也不改宿主机防火墙**。
guacd 本身没有任何权限，改不了这些规则。

### 2.7 已经有 nginx 或 Caddy

自带的 `proxy` 容器是可选的。服务器上已经有 nginx / Caddy 占着 443，启动时就**只起应用和 guacd**：
`docker compose up -d --wait bastion guacd`，
让你自己的反代指向应用的固定地址 `172.30.63.2:8080`（宿主机能直接访问这个地址，不需要映射端口）。
这种情况下 2.4 里的证书和 `nginx.conf` 都不用准备，TLS 证书在你自己的反代上配。

**1. 把反代的来源 IP 加进 `production.toml` 的 `trusted_proxies`**

应用只接受白名单 IP 发来的转发头，其他请求一律返回 403。

| 你的反代跑在哪 | `trusted_proxies` 填什么 |
|---|---|
| 宿主机上（apt 装的 nginx / Caddy） | `["172.30.63.1/32"]`，这是 Docker 网桥的网关地址 |
| 另一个 Docker 容器里 | 把那个容器接到 `<项目名>_ingress` 网络并固定一个 IP（如 `172.30.63.4`），填这个 IP |

改完重启应用：`docker compose up -d --wait bastion`。

**2. 反代要满足这几条**，否则请求会被拒绝：

- `X-Forwarded-For` 只能有一个值，必须**覆盖**，不能在客户端传来的值后面追加
- `X-Forwarded-Proto` 必须是 `https`
- 不能带 `Forwarded` 头
- 支持 WebSocket，并保留客户端原始的 `Host`

**nginx**：把 [deploy/nginx.example.conf](deploy/nginx.example.conf) 里 `location /` 那一整段复制进你的
server 块，它已经满足上面所有要求。顺手把 `location = /metrics { return 404; }` 也带上。

**Caddy**：

```caddy
bastion.example.com {
    reverse_proxy 172.30.63.2:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up -Forwarded
        flush_interval -1
    }
}
```

Caddy 默认会把客户端发来的 `Forwarded` 头原样转发，应用会因此拒绝请求，所以要用 `-Forwarded` 删掉；
`flush_interval -1` 让录制回放不被缓冲。

不管用哪种反代，`production.toml` 里的 `public_origin` 都要和浏览器地址栏完全一致。

### 2.8 完整走一遍

上面全部命令连起来就是 [deploy/docker.md](deploy/docker.md) 的 Fresh setup 一节；
生产值班、备份恢复、KEK 轮换、审计清理等操作看 [deploy/README.md](deploy/README.md)。

---

## 3. 部署之后的日常使用

### 3.1 首次登录要做的事

1. 用管理员账号登录 `https://你的域名`。
2. **系统管理 → 用户管理**：给使用者建账号（`operator`），需要只读审计的建 `auditor`。
3. **系统管理 → 资产管理 → 新建资产**，填名称、地址、端口：
   - **SSH**：主机公钥留空即可，首次连接时确认指纹。
   - **RDP**：证书指纹留空即可，首次连接时确认，安全模式（NLA/TLS）由扫描自动识别。
   - **VNC**：确认目标网段已加进 `vnc_trusted_cidrs`。
   顺带建"目标账号"，填用户名和密码（或 SSH 私钥）。
4. **系统管理 → 资源授权**：给 `operator` 授权"哪个用户可以连哪个资产的哪个账号"。
   管理员不需要授权，默认能连所有启用资产。
5. 把地址和账号密码发给使用者。

### 3.2 使用者怎么连

左侧 **可用资产** → 找到资产 → 点 **连接**。SSH 会打开终端页签；RDP/VNC 会打开远程画面页签。
可以同时开多个页签，也可以全屏。断开就是关掉页签或点工具栏的 **断开**。

首次连接的管理员会看到一个"确认主机身份"的弹窗——把显示的指纹和目标机器上查到的值核对一下再确认。
确认之前任何人都连不上这台资产。

- SSH 上用 **Ctrl+Shift+C / Ctrl+Shift+V** 复制粘贴，**Ctrl+Shift+F** 搜索。
- 录制回放在 **日志审计 → 录制回放**，只读，不能控制目标。

### 3.3 出问题先看哪里

| 现象 | 看这里 |
|---|---|
| 页面打不开 | `docker compose logs proxy bastion` |
| 登录提示"服务不可用" | `docker compose logs bastion`，多半是迁移失败，看 `logs migrate grant-runtime` |
| 连不上目标 | `logs bastion`，注意是"网络策略拒绝"还是"主机指纹未确认" |
| RDP 报安全模式错误 | 目标是否只支持 NLA；用资产页的"重新核验主机指纹"重新扫描 |
| RDP 证书变化被拒 | Windows 自签名证书通常半年一换，重新扫码确认即可 |

---

## 4. 升级

```sh
# 先下载新的 compose.yaml，然后：
docker compose pull
docker compose up -d --wait     # 迁移和授权自动先跑；已有反代的话末尾加 bastion guacd
```

从使用 `egress.py` 的旧版本升级：先 `sudo python3 deploy/guacd/egress.py remove 项目名`（`.env` 里的 `COMPOSE_PROJECT_NAME`）
（用旧版仓库里的脚本）清掉宿主机上的旧规则，再按上面升级。之后就不再需要它了。

迁移不需要手动执行：`up` 会先跑 `migrate` 和 `grant-runtime`，成功后才启动新版本的应用。
迁移失败时应用不会启动，旧数据保持原样，用 `logs migrate` 查原因。
有不可逆迁移的版本，升级前先做一次备份（见第 6 节）。

**永远不要用 `docker compose down -v`**：那会删掉数据库、密钥和全部录制。

---

## 5. 磁盘维护（可选，手动）

录像和审计事件**不会自动删除**，`production.toml` 里的 `retention_days` 只决定录像多久之后*可以*被清理。
用量不大的部署可以一直不管；需要腾空间时，在 `compose.yaml` 所在目录手动执行
[deploy/maintenance.sh](deploy/maintenance.sh)，它不会自己定时运行：

```sh
sh deploy/maintenance.sh status                    # 只读：磁盘占用、可清理的录像、审计月份
sh deploy/maintenance.sh partition-audit           # 一次性：让审计可以按月清理
sh deploy/maintenance.sh clean --audit-days 180    # 删除过期录像和 180 天前的审计月份
```

- `status` 随时可以跑，不影响服务。
- `partition-audit` 和 `clean` 会先停 `bastion`（**所有在线会话断开**），做完再把原来在跑的服务拉起来，通常几十秒。
  执行前会列出要删什么并要求确认，加 `--yes` 跳过确认。删除不可恢复，需要保留的话先备份（第 6 节）。
- **想用审计清理，就尽早跑一次 `partition-audit`。** 它要在 2 秒内把现有审计复制一遍，日志越大越可能超时失败
  （失败会整体回滚，不丢数据，只是转不过去）。转换后已有记录按月归档，并预建未来 12 个月的分区；
  如果超过 12 个月没跑过 `clean`，之后的新记录会落进 default 分区，那部分**永远不会被删**，所以一年至少跑一次。
- 不跑 `partition-audit` 也能用 `clean`，只是只清录像。
- 录像所在磁盘剩余空间低于 `minimum_free_bytes`（默认 1 GiB）时，新连接会被拒绝，这是提醒你该清理了，不会把系统写坏。
- 容器日志已在 `compose.yaml` 里限制为每个服务最多 3 × 10 MB。

## 6. 备份与恢复

要一起备份的东西（少一样都恢复不完整）：PostgreSQL、`secrets`、`database-auth`、`runtime-auth`、
`recordings` 五个卷，以及所有还在用的 KEK 和一份 manifest。

```sh
docker compose run --rm --no-deps maintenance verify-backup \
    --config /etc/zeroterm-bastion/maintenance.toml --manifest /path/manifest.json
```

恢复到**新的隔离项目**里验证过再切流量，不要原地覆盖。录制文件是加密的，失去 KEK 就打不开了。
细节见 [deploy/README.md](deploy/README.md) 第 4、5 条。

---

## 7. 本地开发

需要 Rust 1.95+、Node 24。secrets 目录必须是 Unix 权限 `0700/0600`，不通过放宽权限来兼容 Windows 服务部署。

```sh
cargo fmt --all -- --check
cargo check --locked --workspace
cargo test  --locked --workspace

cd web && npm ci && npm test && npm run build
```

**用 Compose 跑本地构建的镜像**：

```sh
# 先构建本地镜像
docker build -t zeroterm-bastion:local .
docker build -t zeroterm-guacd:1.6.0-strict-pin -f deploy/guacd/Dockerfile .

# 在仓库根目录的 .env 里指定本地镜像
cat >> .env <<'EOF'
COMPOSE_PROJECT_NAME=test-local
BASTION_IMAGE=zeroterm-bastion:local
GUACD_IMAGE=zeroterm-guacd:1.6.0-strict-pin
EOF
docker compose up -d
```

真实引擎验收要在获准的独立测试主机上跑，需要先构建 guacd：

```sh
docker build -t zeroterm-guacd:1.6.0-strict-pin -f deploy/guacd/Dockerfile .
python3 -u tests/docker_guacd_acceptance.py
```

`tests/` 下还有真实浏览器的 SSH/RDP/VNC、故障恢复、无限 I/O 卡死、高输出压力等 runner，
用法见各自文件头部注释。

---

## 8. 安全边界（上线前请读完）

- 登录走 Cookie + CSRF + 严格 Origin 校验，没有 Bearer/长期 token 入口；WSS 票据 30 秒一次性。
- SSH 在**同一个目标 socket 上**校验已批准的完整 host key，通过后才发认证。
- RDP 只允许 NLA / TLS，并且强校验 leaf 证书 DER 的 SHA-256；缺少 `zt-strict-cert-pin` 参数时直接拒绝。
  证书链验证通过但指纹不符也会被拒（不会因为 CA 可信就放行）。
- VNC 经典密码最多 8 字节，只有显式信任的网段可用，不要当作有加密或身份保证。
- guacd 容器没有数据库、KEK、录制卷，也没有目标网络出口，只有一条通往应用的专用 bridge。
- guacd 的出站规则由 `guacd-net` 写在它自己的网络命名空间里，随容器自动生效；只把网络标成 `internal`
  不算隔离证据，隔离要用实际连接测试证明（见 `tests/docker_guacd_acceptance.py`）。
- 录制在写入并 flush 得到确认后才向浏览器转发画面；录制失败会断开连接而不是静默丢录制。

## 9. 文档地图

| 文件 | 内容 |
|---|---|
| [deploy/docker.md](deploy/docker.md) | 完整部署 runbook：拓扑、初始化、guacd 隔离与验证 |
| [deploy/README.md](deploy/README.md) | 运维：备份恢复、KEK 轮换、审计保留 |
| [docs/RFC-005-guacamole-browser.md](docs/RFC-005-guacamole-browser.md) | 当前实现合同（schema/protocol family 2） |
| [docs/ssh-xterm.md](docs/ssh-xterm.md) | SSH 改用 xterm.js 的合同与验收门槛 |
| [docs/guacamole-execution.md](docs/guacamole-execution.md) | 执行证据与未通过项 |
| [crates/bastion-api/API.md](crates/bastion-api/API.md) | HTTP API |
| [docs/openapi-web.json](docs/openapi-web.json) | OpenAPI 契约 |

历史文档（[RFC-004](docs/RFC-004-bastion-design.md)、M1–M5 证据）只是记录，不代表当前版本的能力。
