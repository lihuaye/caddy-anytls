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

模块通过 Caddy 标准的 `Provision()`、`Validate()` 和 `Cleanup()`（`caddy.CleanerUpper`）参与配置生命周期。配置卸载时由 wrapper 的 `Cleanup()` 主动关闭全部活跃 AnyTLS 会话。

> 注：不使用 `ctx.OnCancel` 注册清理回调。caddy v2.11.4 中模块 `Provision` 以值接收 `caddy.Context`，`OnCancel` 只会把回调追加到 Context 副本上，配置卸载时永不执行；模块自身的 `Cleanup()` 则可靠触发。

当前策略如下：

- 新配置对新连接立即生效
- 网站链路不参与 AnyTLS 会话清理
- 旧 AnyTLS 会话在配置卸载时经 `Cleanup()` 主动终止

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
  "outbounds": {
    "wg-home": {"dialer": "wireguard", "tunnel": "home"}
  },
  "default_outbound": "wg-home",
  "users": [
    {
      "name": "device-1",
      "password": "redacted",
      "enabled": true,
      "outbound": "direct"
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
- `outbound`
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

## 出站扩展点

出站（egress）通过 Caddy guest module 机制可插拔，命名空间为 `caddy.listeners.anytls.outbounds`，inline key 为 `dialer`。模块需实现 `Outbound` 接口（`LookupNetIP` + `DialContext` + `ListenPacket`，见 `outbound.go`）。未配置或配置为 `null` 时回退到内置 `direct` 出站（本地网络栈直连）。

### 按用户选择出站

一个 wrapper 可以在 `outbounds`（JSON 为 `map[string]模块对象`，Caddyfile 为 `outbound <name> <module>`）中声明任意多个具名出站，`users[].outbound` 按名引用其中之一。选择发生在拨号时：handler 从连接上下文读取认证用户名，查只读映射得到该用户的出站，TCP（`dialResolved`）与 UDP over TCP（`listenPacketContext`）同源选择。

默认出站解析顺序（向后兼容硬规则）：

1. `default_outbound` 非空 → 该具名出站；
2. 否则单 `outbound` 模块非空 → 它（日志中出站名为哨兵 `default`）；
3. 否则 → 内置 `direct`。

保留名 `direct` 与 `default` 不可在 `outbounds` 中声明：`direct` 始终指向内置直连出站、无需声明即可被引用；`default` 是旧式无名默认档的日志哨兵。引用未声明的出站名在 `Provision` 阶段报错。

运行期映射（名→出站、用户→出站）在 `Provision` 内一次性构建、之后只读，拨号路径并发读取无需加锁。

### 职责边界

域名解析由认证用户实际选中的出站执行。`direct` 使用宿主机解析器；隧道出站必须通过隧道内可达的 DNS 服务器解析，不能静默回落到宿主机 DNS。解析结果返回 wrapper 后，再执行私网/端口/域名/CIDR 策略校验；只有全部地址通过检查，才会将已解析的 `ip:port` 交给同一个出站拨号。这样既保证 DNS 与目标连接使用同一出口，也不会牺牲 SSRF 防护。

WireGuard 等物理隧道资源应由对应插件在全局 App 中集中定义；AnyTLS 出站只保存对隧道名的引用。这样同一 device 可以被多个 AnyTLS 逻辑出口或 `reverse_proxy` transport 共享，不会因为重复内联同一密钥而创建互相抢占 endpoint 的设备。

### 实现契约

- 三个方法会被多个 handler goroutine 并发调用（每条 AnyTLS 连接一个），实现必须并发安全。
- `LookupNetIP` 必须通过该出站的网络路径解析，并遵循 `ctx` 的截止时间和取消信号；不得为了兼容性回落到宿主机 DNS。
- 返回的 `net.Conn` / `net.PacketConn` 由 relay 负责关闭；每次调用必须返回独立连接，不得返回共享或缓存的连接。
- `ctx` 携带 `connect_timeout` 的截止时间与取消信号，建连期间必须遵守。
- `ListenPacket` 返回的连接按非 connected 方式使用：relay 会用 `WriteTo` 发往任意已解析的 UDP 目标。
- TCP 目标解析出多个候选地址时，wrapper 会在同一条连接内对**同一个出站**并发调用 `DialContext` 最多 N 次（happy-eyeballs），胜者保留、落败连接由调用方关闭。隧道型出站要为这种瞬时拨号扇出预留连接数/速率预算。
- 出站必须容忍 `Cleanup` 时仍有在用连接：Caddy 对各模块 `Cleanup` 的遍历没有跨模块顺序保证，出站的 `Cleanup` 可能先于 wrapper 关闭活跃会话执行。届时在用连接报错即可，由 relay 负责关闭，不会泄漏。

### 生命周期

出站模块的生命周期完全交给 Caddy 模块系统：经 `ctx.LoadModule` 加载并 Provision（具名出站同理，逐个加载）；配置卸载时 Caddy 调用各模块的 `Cleanup`。wrapper 在自己的 `Cleanup()` 中主动关闭全部活跃会话，但 Caddy 不保证 wrapper 与出站模块的 `Cleanup` 先后顺序，因此出站模块须按上文契约容忍清理时仍存在使用中的连接。

参考实现：内置 `direct`（`outbound.go`）；外部 WireGuard 出站 `github.com/lihuaye/caddy-wireguard`。

## 已知约束

当前设计中需要持续关注以下约束：

### listener wrapper 接入点依赖 Caddy 版本语义

模块行为与 Caddy `listener_wrapper` 的实际接口契约相关，升级 Caddy 版本时需要继续校验接入点行为。

### fallback 正确性依赖零字节丢失

任何首包探测逻辑都必须建立在非消费式读取之上。只要发生字节丢失，网站回落链路就会受到影响。
