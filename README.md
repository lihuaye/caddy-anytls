# caddy-anytls

`caddy-anytls` 是一个 Caddy listener wrapper，用来把 AnyTLS 接入现有的 Caddy `443` 入口。

它适合已经用 Caddy 托管 HTTPS 站点，但不想再单独维护 AnyTLS 服务端、证书和额外监听端口的场景。

## 核心能力

- 网站和 AnyTLS 共用同一个 `443` 入口
- TLS 握手、证书申请和续期继续由 Caddy 负责
- AnyTLS 识别发生在 TLS 解密之后、HTTP 解析之前
- 非 AnyTLS 流量无损回落到原网站链路
- HTTP/1 与 HTTP/2 网站首包快速回落，减少普通请求探测等待
- 支持多用户、基础 TCP 转发和 `UDP over TCP v2`
- 默认拒绝私网目标，并支持端口、域名和 CIDR 出站策略
- 输出结构化审计日志

## 工作方式

```text
client
  -> Caddy :443
    -> TLS handshake
      -> caddy-anytls 探测 TLS 后首包
        -> AnyTLS：认证并转发
        -> 非 AnyTLS：交还给网站处理链路
```

这个项目不是独立代理程序。它不自己管理证书，不替代 Caddy 的 HTTP 站点能力，只负责在 Caddy listener 层完成 AnyTLS 接入、识别、策略校验和转发。

## 快速开始

### 1. 构建带模块的 Caddy

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

### 2. 准备 Caddyfile

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                user phone-1 replace-with-strong-password
                log_node_info true
                node_host example.com
            }
        }
    }
}

example.com {
    respond "server is running"
}
```

使用前至少修改：

- `example.com`：替换为真实域名
- `replace-with-strong-password`：替换为强密码

Caddy 启动或重载成功后会在日志里输出 `event=anytls_node` 的节点信息，其中包含当前启用用户可用的 AnyTLS URI。URI 格式遵循 `anytls-go` 文档：`anytls://[auth@]hostname[:port]/?[key=value]&...`，常用参数包括 `sni` 和 `insecure`。

### 3. 离线生成客户端节点信息

```sh
ANYTLS_SERVER=example.com \
ANYTLS_PASSWORD=replace-with-strong-password \
ANYTLS_NAME=phone-1 \
scripts/print-node-info.sh
```

脚本会输出上游 AnyTLS URI，以及 Mihomo、Surfboard 和 sing-box outbound 配置片段。URI 格式遵循 `anytls-go` 文档：`anytls://[auth@]hostname[:port]/?[key=value]&...`，常用参数包括 `sni` 和 `insecure`。

## Docker

可以直接使用预构建镜像：

```sh
docker pull ghcr.io/evaneonf/caddy-anytls:latest
```

本地构建镜像：

```sh
docker build -t caddy-anytls:local .
```

使用 Compose 启动：

```sh
docker compose up -d --build
```

默认挂载：

- `./Caddyfile -> /etc/caddy/Caddyfile`
- `caddy_data -> /data`
- `caddy_config -> /config`

## 配置

最小配置只需要一个站点域名和至少一个用户：

```caddyfile
anytls {
    user phone-1 replace-with-strong-password
}
```

常用配置项：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `probe_timeout` | `5s` | TLS 后首包探测超时 |
| `idle_timeout` | `2m` | AnyTLS 会话空闲超时，会随读写活动刷新 |
| `connect_timeout` | `10s` | 出站拨号超时 |
| `max_concurrent` | `128` | 最大并发 AnyTLS 会话数 |
| `fallback` | `true` | 非 AnyTLS 流量是否回落网站 |
| `allow_private_targets` | `false` | 是否允许访问私网、回环、链路本地等目标 |
| `allow_cidr` / `deny_cidr` | 无 | 按目标解析后的 IP CIDR 放行或拒绝 |
| `allow_port` / `deny_port` | 无 | 按目标端口放行或拒绝 |
| `allow_domain` / `deny_domain` | 无 | 按域名或域名后缀放行或拒绝 |
| `padding_scheme` | `sing-anytls` 默认值 | AnyTLS padding 策略 |
| `log_node_info` | `false` | 启动或重载时把当前可用节点 URI 输出到 Caddy 日志 |
| `node_host` | 从站点 host matcher 推断 | 节点 URI 使用的服务端域名或地址，可写多个 |
| `node_port` | 从 server listen 推断，默认 `443` | 节点 URI 使用的端口 |
| `node_sni` | 同 `node_host` | 节点 URI 的 `sni` 参数 |
| `node_insecure` | `false` | 节点 URI 是否输出 `insecure=1` |
| `user <name> <password>` | 无 | 添加一个启用状态的用户 |

策略规则：

- `deny_*` 优先于 `allow_*`
- 配置了 `allow_*` 后，未命中的目标会被拒绝
- `allow_private_targets false` 时，域名会先解析再检查所有返回地址
- `allow_cidr` 可以精确放行特定 CIDR，包括默认私网保护下的受控内网段
- `log_node_info true` 会把用户密码编码进 URI 并写入日志，只应在你能控制日志访问权限时开启

更多示例见 [docs/examples.md](docs/examples.md)。

## 当前行为

- 普通 HTTPS 请求照常进入网站
- AnyTLS 客户端连接会在 TLS 后被模块接管
- `sp.v2.udp-over-tcp.arpa` 按 `UDP over TCP v2` 处理
- 已禁用用户命中 AnyTLS 首包时会被直接拒绝，不会回落到网站
- 配置 reload 或卸载时，现有 AnyTLS 会话会被主动终止
- 默认拒绝私网目标，包括域名解析后的私网地址
- TCP 出站域名若解析出多个可用地址，会按顺序尝试拨号

## 日志

模块输出结构化审计日志。常见字段包括：

- `connection_id`
- `event`
- `outcome`
- `reason`
- `protocol`
- `uot_is_connect`
- `user`
- `source`
- `destination`
- `duration`
- `bytes_from_client`
- `bytes_to_client`
- `bytes_from_target`
- `bytes_to_target`

典型事件包括认证成功、网站 fallback、禁用用户拒绝、策略拒绝、私网目标拒绝、relay 关闭和配置卸载导致的会话终止。

## 文档

- [产品说明](docs/product.md)
- [技术设计](docs/technical-design.md)
- [配置示例](docs/examples.md)
- [容器说明](docs/container.md)
- [发布说明](docs/release.md)

## License

本项目采用 `GPL-3.0-or-later`。
