# 配置示例

## 构建

使用 `xcaddy` 构建包含 `caddy-anytls` 模块的 Caddy：

```sh
xcaddy build --with github.com/evaneonf/caddy-anytls=.
```

## 最小 Caddyfile 配置

以下示例适用于常见的 HTTPS 站点接入场景：

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                user phone-1 replace-with-strong-password
                user laptop-1 replace-with-another-password
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

该配置的行为如下：

- Caddy 继续负责 HTTPS 站点和证书生命周期
- `anytls` 在 TLS 解密后识别协议
- 非 AnyTLS 流量继续进入网站链路
- AnyTLS 命中后进入认证与转发流程

对于 `user <name> <password>`：

- `name` 是模块侧的运维标识
- 该字段主要用于设备区分、日志记录和用户管理
- 协议认证仍以密码为核心

## 带出站策略的 Caddyfile 配置

以下示例展示更接近生产环境的边界控制：

```caddyfile
{
    servers :443 {
        listener_wrappers {
            anytls {
                probe_timeout 5s
                idle_timeout 2m
                connect_timeout 10s
                max_concurrent 128
                fallback true
                allow_private_targets false

                deny_port 25
                deny_cidr 127.0.0.0/8 169.254.0.0/16
                deny_domain .blocked.example

                user phone-1 replace-with-strong-password
                user laptop-1 replace-with-another-password
            }
        }
    }
}

example.com {
    respond "server is running"
}
```

策略规则：

- `deny_*` 优先于 `allow_*`
- 配置了任意 `allow_*` 后，未命中的目标会被拒绝
- `allow_private_targets false` 时，域名目标会先解析再检查所有返回地址
- `allow_cidr` 可用于精确放行受控内网段，例如 `allow_cidr 10.10.0.0/16`

## JSON 配置片段

如果使用 JSON 配置，模块需要挂载在 HTTP server 的 `listener_wrappers` 下。示例如下：

```json
{
  "wrapper": "anytls",
  "probe_timeout": "5s",
  "idle_timeout": "2m",
  "connect_timeout": "10s",
  "max_concurrent": 128,
  "fallback": true,
  "allow_private_targets": false,
  "allow_cidrs": [],
  "deny_cidrs": ["127.0.0.0/8", "169.254.0.0/16"],
  "allow_ports": [],
  "deny_ports": [25],
  "allow_domains": [],
  "deny_domains": [".blocked.example"],
  "users": [
    {
      "name": "phone-1",
      "password": "replace-with-strong-password",
      "enabled": true
    },
    {
      "name": "laptop-1",
      "password": "replace-with-another-password",
      "enabled": true
    }
  ]
}
```

## 默认值

在未显式配置时，当前版本会采用以下默认值：

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `probe_timeout` | `5s` | TLS 后首包探测超时 |
| `idle_timeout` | `2m` | AnyTLS 会话空闲超时 |
| `connect_timeout` | `10s` | 出站拨号超时 |
| `max_concurrent` | `128` | 最大并发 AnyTLS 会话数 |
| `fallback` | `true` | 非 AnyTLS 流量回落网站 |
| `allow_private_targets` | `false` | 默认拒绝常见私网目标 |
| `allow_cidr` / `allow_cidrs` | 无 | 只允许访问指定 CIDR |
| `deny_cidr` / `deny_cidrs` | 无 | 拒绝访问指定 CIDR |
| `allow_port` / `allow_ports` | 无 | 只允许访问指定端口 |
| `deny_port` / `deny_ports` | 无 | 拒绝访问指定端口 |
| `allow_domain` / `allow_domains` | 无 | 只允许访问指定域名或后缀 |
| `deny_domain` / `deny_domains` | 无 | 拒绝访问指定域名或后缀 |
| `padding_scheme` | `sing-anytls` 默认值 | 复用上游协议实现的默认策略 |
| `log_node_info` | `false` | 启动或重载时输出当前启用用户的 AnyTLS 节点 URI 到 Caddy 日志 |
| `node_host` / `node_hosts` | 从站点 host matcher 推断 | 节点 URI 使用的域名或地址，可写多个 |
| `node_port` | 从 server listen 推断，默认 `443` | 节点 URI 使用的端口 |
| `node_sni` | 同 `node_host` | 节点 URI 使用的 `sni` 参数 |
| `node_insecure` | `false` | 是否在节点 URI 中输出 `insecure=1` |

默认值的代码来源分别位于：

- [anytls.go](../anytls.go) 中的 `Provision()`
- `github.com/anytls/sing-anytls/padding.DefaultPaddingScheme`

## 行为说明

当前版本对以下行为有明确约束：

- `sp.v2.udp-over-tcp.arpa` 会按 `UDP over TCP v2` 保留目标处理
- 已禁用用户命中新连接时会被拒绝，不回落到网站
- 配置重载或卸载时，现有 AnyTLS 会话会被终止
- 网站请求链路不参与 AnyTLS 会话清理
- HTTP/1 与 HTTP/2 网站首包会快速回落，不需要等待完整 AnyTLS 哈希探测
- 域名目标会先解析再执行私网和 CIDR 策略
- TCP 域名目标解析出多个地址时，会按顺序尝试可用地址
- `allow_cidr`、`deny_cidr`、`allow_port`、`deny_port`、`allow_domain`、`deny_domain` 可组合限制出站目标

## 节点信息输出

推荐在 Caddyfile 中显式打开启动日志输出：

```caddyfile
anytls {
    user phone-1 replace-with-strong-password
    log_node_info true
    node_host example.com
}
```

Caddy 启动或重载成功后会输出 `event=anytls_node` 的结构化日志。每个启用用户、每个 `node_host` 会各输出一条，字段包含 `user`、`host`、`port`、`sni`、`insecure` 和 `uri`。

示例 URI：

```text
anytls://replace-with-strong-password@example.com/
```

注意：URI 中包含用户密码。只有在日志访问权限可控时才开启 `log_node_info`。

如果没有配置 `node_host`，模块会尝试从 Caddy 站点的 host matcher 推断具体域名；通配符或 placeholder host 不会被用于节点 URI。

仓库内脚本仍可用于离线生成常见客户端配置片段：

```sh
ANYTLS_SERVER=example.com \
ANYTLS_PASSWORD=replace-with-strong-password \
ANYTLS_NAME=phone-1 \
scripts/print-node-info.sh
```

输出包含上游 AnyTLS URI、Mihomo、Surfboard 和 sing-box outbound 配置。URI 格式遵循 `anytls-go` 文档：`anytls://[auth@]hostname[:port]/?[key=value]&...`。

可用环境变量：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `ANYTLS_SERVER` | `example.com` | 服务端域名或地址 |
| `ANYTLS_PORT` | `443` | 服务端端口 |
| `ANYTLS_NAME` | `caddy-anytls` | 节点名称 |
| `ANYTLS_PASSWORD` | `change-this-password` | AnyTLS 用户密码 |
| `ANYTLS_SNI` | 同 `ANYTLS_SERVER` | TLS SNI |
| `ANYTLS_SKIP_CERT_VERIFY` | `false` | 是否跳过证书校验 |

URI 规则：

- 密码放在 URI auth 位置，特殊字符会进行百分号编码
- 端口省略时默认为 `443`
- `ANYTLS_SNI` 与服务端地址不同时会输出 `sni` 参数
- `ANYTLS_SKIP_CERT_VERIFY=true` 时会输出 `insecure=1`

## 已知限制

当前示例覆盖的是首版可用配置，范围仍然有限：

- 尚未提供管理接口或动态用户 API
- 会话不会跨配置代际保活

仓库内测试当前已覆盖网站 fallback、AnyTLS 转发以及 `UDP over TCP v2` 的主要路径。
