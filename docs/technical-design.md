# 技术设计

## 设计目标

`caddy-anytls` 的首版实现需要满足以下技术约束：

- 复用 Caddy 的 `:443` 监听与自动 HTTPS 能力
- 在 TLS 握手完成后识别 AnyTLS 首包
- AnyTLS 命中时接管连接并完成认证与转发
- 非 AnyTLS 流量无损回落到现有网站链路

## 模块形态

当前实现采用 Caddy `listener_wrapper` 形态，模块 ID 为 `caddy.listeners.anytls`。

之所以不采用 HTTP handler，原因在于 AnyTLS 识别必须发生在 HTTP 解析之前。HTTP handler 只能处理已经被解释为 HTTP 请求的流量，无法覆盖非 HTTP 的 AnyTLS 首包探测场景。`listener_wrapper` 则可以直接接触 TLS 解密后的 `net.Conn`，满足协议识别所需的接入点要求。

## 数据路径

### 网站流量

1. 客户端连接 `:443`。
2. Caddy 完成 TLS 握手与证书选择。
3. 模块对解密后的连接进行首包窥探。
4. 若判定为非 AnyTLS，则将连接返回给 Caddy 的网站处理链路。
5. HTTP server 按既有站点路由继续处理请求。

### AnyTLS 流量

1. 客户端连接 `:443`。
2. Caddy 完成 TLS 握手与证书选择。
3. 模块对解密后的连接进行首包识别。
4. 若判定为 AnyTLS，则模块接管该连接。
5. 连接进入认证、出站策略校验、目标地址解析、出站建立与双向转发流程。

## 关键设计点

### 连接分流

包装 listener 使用后台接收循环和有界探测并发池完成分流。TLS 握手与首包探测不会阻塞 Caddy 调用 `Accept()` 的单一 goroutine；网站流量通过结果通道返回上游 HTTP server，AnyTLS 流量则在模块内部启动会话处理。`max_pending_probes` 限制同时处于握手或探测阶段的连接数量。

这一设计意味着模块需要自行维护以下运行时状态：

- AnyTLS 会话生命周期
- 探测、会话和子流三级并发数量控制
- 认证和转发相关日志

### 首包窥探与无损回落

网站回落的前提是不能丢失任何已经读取的字节。为此，模块通过可回放连接包装实现首包窥探：

- 以带缓冲的 reader 包装底层 `net.Conn`
- 使用 `Peek()` 获取首包特征而不消费数据
- 回落到网站时，后续处理链仍能读取完整请求内容

这一点直接决定了回落链路的正确性，是接入设计中的硬性要求。

### 协议实现复用

AnyTLS 协议处理复用 `github.com/anytls/sing-anytls`，模块本身只保留接入层所需的控制逻辑，包括：

- 网站回落控制
- 首包识别入口
- 用户配置与策略边界
- 目标连接桥接
- Caddy 生命周期对接

首包识别使用与 `sing-anytls` 一致的密码哈希前缀规则，以避免模块侧识别与上游协议实现出现偏差。

普通网站流量支持快速回落路径：模块会优先识别 HTTP/2 preface 和常见 HTTP/1 方法前缀，命中后无需等待完整 32 字节 AnyTLS 哈希探测即可返回网站链路。这避免了合法网站首包较短时被 `probe_timeout` 放大延迟。

### 出站目标策略

AnyTLS 命中后，模块会在建立出站连接前执行策略校验：

1. 检查目标地址和端口是否合法。
2. 执行端口和域名策略。
3. 必要时解析域名，得到一个或多个 IP 地址。
4. 对解析后的所有地址执行私网和 CIDR 策略。
5. TCP 目标按解析结果顺序尝试拨号，直到成功或全部失败。

策略优先级如下：

- `deny_*` 优先于 `allow_*`
- 配置了 `allow_*` 后，未命中的目标会被拒绝
- `allow_private_targets = false` 时，私网、回环、链路本地、未指定和组播目标默认拒绝
- `allow_cidr` 可以精确放行指定 CIDR，即使该 CIDR 属于默认私网保护范围

### 生命周期与配置重载

模块通过 Caddy 标准的 `Provision()`、`Validate()` 和取消回调参与配置生命周期。

当前策略如下：

- 新配置对新连接立即生效
- 网站链路不参与 AnyTLS 会话清理
- 旧 AnyTLS 会话在配置卸载时主动终止

这一行为是有意为之。对于用户禁用、删除或策略收紧等场景，旧会话继续存活会导致安全边界模糊，因此当前实现选择在配置代际切换时清理存量 AnyTLS 会话。

### 安全默认值

当前默认值围绕保守接入策略设定：

- `fallback = true`
- `probe_timeout = 5s`
- `idle_timeout = 2m`
- `connect_timeout = 10s`
- `max_concurrent = 128`
- `max_pending_probes = 256`
- `max_streams_per_session = 256`
- `max_concurrent_streams = 1024`
- `allow_private_targets = false`
- `padding_scheme` 使用 `sing-anytls` 默认值

除上述默认值外，当前实现还遵循以下安全行为：

- 默认审计日志不输出密码
- `log_node_info` 需要显式开启，开启后会输出包含密码的 AnyTLS URI，适合日志访问权限可控的部署环境
- 用户被禁用后，新命中的连接不会回落到网站
- 默认拒绝访问常见私网目标地址
- 域名目标会在解析后检查所有返回地址，解析到私网地址时默认拒绝
- `deny_*` 出站策略优先于 `allow_*` 策略
- `allow_cidr` 可精确放行指定 CIDR，包括默认私网保护下的受控内网段

## 配置模型

当前配置模型聚焦于接入层能力，典型 JSON 结构如下：

```json
{
  "probe_timeout": "5s",
  "idle_timeout": "2m",
  "connect_timeout": "10s",
  "max_concurrent": 128,
  "max_pending_probes": 256,
  "max_streams_per_session": 256,
  "max_concurrent_streams": 1024,
  "fallback": true,
  "allow_private_targets": false,
  "allow_cidrs": [],
  "deny_cidrs": [],
  "allow_ports": [],
  "deny_ports": [],
  "allow_domains": [],
  "deny_domains": [],
  "log_node_info": false,
  "node_hosts": ["example.com"],
  "node_port": 443,
  "node_sni": "example.com",
  "node_insecure": false,
  "users": [
    {
      "name": "device-1",
      "password": "redacted",
      "enabled": true
    }
  ]
}
```

该模型有两个明确边界：

- 不提供独立证书配置
- 不提供独立 TLS 监听配置

这部分能力继续由 Caddy 负责。

## 可观测性

当前实现输出结构化日志，用于记录连接识别、认证、转发与会话结束等事件。主要字段包括：

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

典型事件包括：

- 启动或重载后的节点 URI 输出，事件名为 `anytls_node`
- AnyTLS 会话认证成功
- 网站 fallback
- 禁用用户拒绝
- 私网目标拒绝
- 出站策略拒绝
- TCP relay 关闭及字节计数
- 配置卸载导致的会话终止

## 已知约束

当前设计中需要持续关注以下约束：

### listener wrapper 接入点依赖 Caddy 版本语义

模块行为与 Caddy `listener_wrapper` 的实际接口契约相关，升级 Caddy 版本时需要继续校验接入点行为。

### fallback 正确性依赖零字节丢失

任何首包探测逻辑都必须建立在非消费式读取之上。只要发生字节丢失，网站回落链路就会受到影响。
