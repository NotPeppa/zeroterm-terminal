# 部署：服务器上已经有 nginx 或 Caddy

适用于 443 端口已经被你自己的 nginx / Caddy 占用、证书也由它管理的服务器。这种部署不启动自带的 `proxy`
容器，也不需要 `nginx.conf` 和 `tls/`。没有现成反代的话，按 [README 第 2 节](../README.md#2-部署docker约-5-分钟) 的普通流程部署。

```
浏览器 ──HTTPS──> 你的 nginx / Caddy ──HTTP──> 172.30.63.2:8080（bastion 容器，不映射端口）
```

## 1. 前置条件

- 和普通部署一样：Linux、Docker 26 + Compose 2.26、一个非 root 运行用户，容量说明见 README 2.1。
- 反代已经在跑，并且已经给要用的域名（下文用 `bastion.example.com`）配好了证书。
- 确认 `172.30.61.0/29`、`172.30.62.0/24`、`172.30.63.0/29` 三个网段没有被其他容器或主机路由占用。

## 2. 获取部署文件

```sh
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/compose.yaml -o compose.yaml
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/.env.example -o .env.example
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/config/production.example.toml -o production.example.toml
# 可选：磁盘维护脚本，见 README 第 5 节
curl -fL https://raw.githubusercontent.com/NotPeppa/zeroterm-terminal/main/deploy/maintenance.sh --create-dirs -o deploy/maintenance.sh
```

用 `git clone` 部署的话，模板在仓库的 `config/production.example.toml`，下面 `cp` 时换成这个路径。

## 3. 准备 `.env`

```sh
cp .env.example .env && chmod 600 .env
```

编辑 `.env`：

- **删掉 `COMPOSE_PROFILES=bundled-proxy` 这一行。** 只要它还在，`up` 就会启动自带代理去抢 443。
- `COMPOSE_PROJECT_NAME` 改成你要的项目名，**定了之后不要改**。
- 管理员密码等其他变量和普通部署一样，见 README 2.5。

## 4. 准备应用配置

```sh
mkdir -p .local/docker
cp production.example.toml .local/docker/production.toml
```

编辑 `.local/docker/production.toml`：

| 配置项 | 改成什么 |
|---|---|
| `server_id` | 一个固定的标识串，**建好之后不要再改** |
| `public_origin` | `https://bastion.example.com`，必须和浏览器地址栏完全一致 |
| `trusted_proxies` | 你的反代访问应用时的来源地址，见下表 |
| `[network] allow` | 只放真正要连的目标网段，默认的 `0.0.0.0/0` 太宽 |
| `[guacd] vnc_trusted_cidrs` | 要用 VNC 才填，否则留空 |

| 你的反代跑在哪 | `trusted_proxies` |
|---|---|
| 宿主机上（apt / dnf 装的 nginx、Caddy） | `["172.30.63.1/32"]`，Docker 网桥的网关地址 |
| 另一个 Docker 容器里 | `["172.30.63.4/32"]`，配合第 5 节里给那个容器固定的 IP |

应用只接受这个白名单发来的转发头，其他来源一律返回 403。

再生成维护用配置，它和 `production.toml` 只差数据库连接串：

```sh
sed 's|^database_url_file = .*|database_url_file = "/run/bastion-db/database-url"|' \
    .local/docker/production.toml > .local/docker/maintenance.toml
chmod 644 .local/docker/*.toml
```

以后改了 `production.toml`，要重新执行这条 `sed`，让两份配置保持一致。

## 5. 配置反代

反代必须满足下面几条，否则请求会被拒绝：

- `X-Forwarded-For` 只能有一个值，必须**覆盖**成客户端地址，不能在客户端传来的值后面追加
- `X-Forwarded-Proto` 必须是 `https`
- 不能带 `Forwarded` 头
- 支持 WebSocket，并保留客户端原始的 `Host`
- 不要把 `/metrics` 暴露出去

### nginx

在你的 `server` 块里加上这两段（证书、`listen` 用你自己现有的）：

```nginx
server {
    listen 443 ssl;
    server_name bastion.example.com;
    # ssl_certificate / ssl_certificate_key：用你现有的证书
    client_max_body_size 1g;
    # 不记访问日志：WebSocket 握手里的票据和路径不应落盘
    access_log off;

    location / {
        proxy_pass http://172.30.63.2:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # 覆盖，不要用 $proxy_add_x_forwarded_for
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Forwarded "";
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_buffering off;
        proxy_request_buffering off;
        proxy_read_timeout 3600s;
        proxy_send_timeout 30s;
    }
    location = /metrics { return 404; }
}
```

检查并重载：`sudo nginx -t && sudo systemctl reload nginx`。

### Caddy

```caddy
bastion.example.com {
    reverse_proxy 172.30.63.2:8080 {
        header_up X-Forwarded-For {remote_host}
        header_up -Forwarded
        flush_interval -1
    }
    respond /metrics 404
}
```

Caddy 默认会把客户端发来的 `Forwarded` 头原样转发，应用会因此拒绝请求，所以要用 `-Forwarded` 删掉；
`flush_interval -1` 让录制回放不被缓冲。重载：`sudo systemctl reload caddy`。

### 反代本身也在 Docker 里

宿主机能直接访问 `172.30.63.2`，容器里的反代不行，要把它接进本项目的 ingress 网络并固定 IP。
网络名是 `<COMPOSE_PROJECT_NAME>_ingress`，第 6 节启动之后才会存在。在反代自己的 compose 文件里：

```yaml
services:
  nginx:                      # 你的反代服务
    networks:
      default:
      zt_ingress:
        ipv4_address: 172.30.63.4
networks:
  zt_ingress:
    external: true
    name: zeroterm-bastion_ingress   # 换成你的 COMPOSE_PROJECT_NAME + _ingress
```

ingress 网段是 `/29`，`.2` 是应用，`.3` 留给自带代理，可用的是 `.4`–`.6`。`trusted_proxies` 填同一个 IP。

## 6. 启动

所有 `docker compose` 命令都在 `compose.yaml` 所在目录执行：

```sh
docker compose pull
docker compose up -d --wait
```

`init`、`migrate`、`grant-runtime`、`bootstrap-admin` 会依次自动执行，说明和管理员密码的取法见 README 2.5。
`docker compose ps` 里不应该出现 `proxy`。

逐段验证：

```sh
curl --fail http://172.30.63.2:8080/health/ready        # 宿主机直连应用，期望 ok
curl --fail https://bastion.example.com/health/ready    # 经过你的反代，期望 ok
```

然后用浏览器打开 `https://bastion.example.com` 登录，再连一台资产，确认 WebSocket 正常。
首次登录之后的操作见 README 第 3 节。

## 7. 常见问题

| 现象 | 原因 |
|---|---|
| 浏览器拿到 403，响应里是 `Untrusted proxy request` | `trusted_proxies` 不对，或反代追加了 `X-Forwarded-For` / 带了 `Forwarded` 头 / `X-Forwarded-Proto` 不是 `https` |
| 502 Bad Gateway | 反代连不到 `172.30.63.2:8080`：应用没起来（`docker compose ps`），或容器里的反代没接入 ingress 网络 |
| 能登录，连接资产时一直转圈或立刻断开 | WebSocket 没透传：检查 `Upgrade` / `Connection` 两个头和 `proxy_http_version 1.1` |
| 页面能打开，但登录提示权限不足 | `public_origin` 和浏览器地址栏不一致（协议、域名、端口都要一样），或反代改写了 `Host` / `Origin` |
| `up` 时 443 端口被占用 | `.env` 里的 `COMPOSE_PROFILES=bundled-proxy` 没删 |

应用日志：`docker compose logs bastion`。

## 8. 升级

```sh
docker compose pull
docker compose up -d --wait
```

和普通部署一样，迁移会自动先跑，其余说明见 README 第 4 节。反代配置不用动。
