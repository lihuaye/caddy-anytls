# AnyTLS 按用户选择出站

## Goal

让同一个 AnyTLS 监听端口能按 **认证用户（密码）** 选择不同出站：一部分账号走家宽（如 WireGuard 出站），一部分账号直连（内置 direct），并支持任意多个具名出站。客户端通过在 App 里配置多个「节点」（同 IP、同端口、同 SNI、单证书，仅密码不同）来切换出口。

## Background / 现状（confirmed from code）

- 出站每个 wrapper 只能配一个：`config.go:195-196` 拒绝重复 `outbound`，一个 `:443` server 只挂一个 anytls wrapper，认证后流量走哪个出口全局固定。这是「一个端口无法满足」的根因。
- 出站已通过 `Outbound` 接口（`DialContext` + `ListenPacket`，`outbound.go:30`）与 Caddy guest module 机制（namespace `caddy.listeners.anytls.outbounds`，inline key `dialer`）解耦；内置 `direct`（`outbound.go:51`），外部 `wireguard`（`github.com/lihuaye/caddy-wireguard`）。
- 认证用户在拨号时可靠可得：`userFromContext(ctx)` 用 sing 的 `auth.UserFromContext[string]`（`auth.go:13`），认证后由 sing-anytls 注入，值等于 `User.Name`（`anytls.go:252` 在 `anyTLSUsers()` 内用 `Name` 建 sing user）。TCP 经 `h.outbound().DialContext`（`handler.go:271`，在 `dialResolved` 内）、UDP-over-TCP 经 `h.outbound().ListenPacket`（`handler.go:278`，在 `listenPacketContext` 内），当前 `outbound()`（`handler.go:284`）返回全局唯一出站。
- **主线 201aad3 已把 `dialContext` 改为并发 happy-eyeballs 拨号器**（`handler.go:139-217`）：单目标解析出的多候选地址交错 IPv4/IPv6、250ms 回退，在同一 `connect_timeout` 内**并发**拨号，每次拨号走 `h.dialResolved(dialCtx, addr)`（`handler.go:157`）。因此按 user 选出站的 TCP 选择点在一次连接内会被**同一 user 并发调用多次**——查表幂等、结果一致，但同一 per-user 出站会在该连接内被并发 `DialContext` 最多 N 次（落败连接由 `drainDialResults` 关闭，`handler.go:219`）。UDP 路径 `listenPacketContext` 不受并发拨号影响，仍单次调用。
- 目标策略（allow/deny cidr/port/domain、private target）与宿主机域名解析在调用出站前完成，出站只搬字节（`docs/technical-design.md`）。
- Caddy 2.11.4（`go.mod:7` 锁定 `v2.11.4`）支持 `map[string]json.RawMessage` + `inline_key` 形式的 `ctx.LoadModule`（`context.go:272` 处理 `reflect.Map`、`:318` `loadModulesFromRegularMap` 返回 `map[string]any`），named-map 可直接用模块系统加载。
- 出站模块经 `ctx.LoadModule(lw, "OutboundRaw")` 加载并 Provision（`anytls.go:147`，块 146-159），配置卸载时 Caddy 自动 Cleanup 各模块。
- **生命周期缺陷（开工评审实证，2026-07-16）**：caddy v2.11.4 中，模块 Provision 内 `ctx.OnCancel` 注册的回调在 config 卸载时**永不执行**（`cleanupFuncs` 为 Context 值字段，Provision 值传递接收 Context，append 丢在副本上；最小程序实证 OnCancel fired=false、module Cleanup fired=true）。现有 `anytls.go:136-138` 注册的 `closeActiveSessions("config_unload")` 在生产中是死代码；`TestReloadStyleClosesExistingSessions`（anytls_test.go:1252）直调该函数、未覆盖真实钩子，测试绿≠机制生效。本任务连带修复（见 R7），细节见 design「生命周期与清理」与 research G4。

## 设计决策（已确认）

- **分流信号 = 用户/密码**（per-user outbound）。客户端两个节点仅密码不同，同 IP / 同 443 / 同 SNI / 单证书；选择在服务端拨号时按认证 user 完成。
  - 已排除：多端口（占两端口，与「单端口」诉求冲突）、按 SNI（需多域名/证书）、服务端按目标自动分流（需路由规则引擎，工程量最大且偏离本模块极简接入层定位）。
- **通用 named-outbounds 模型**（非最小两出站特例）：声明任意多个具名出站，内置 `direct` 永远以保留名 `direct` 可用，`user` 按名引用。
- **默认出站解析（向后兼容，非选择题）**：user 未标注出站时按序解析——① `default_outbound` 具名（若配）→ ② 现有单 `outbound`（若配）→ ③ 内置 `direct`。这保证老部署 `outbound wireguard` 仍让全员走家宽，不产生回归。

## Requirements

- R1: wrapper 支持声明多个具名出站（map：名→出站模块），并支持每个 `user` 按名引用其中一个。
- R2: user 未标注出站时走「默认出站」，解析顺序 = `default_outbound` → 单 `outbound` → 内置 `direct`（向后兼容）。
- R3: 保留名 `direct` 与 `default` 均不得在 `outbounds` 中声明（显式声明 → Provision 校验报错）。`direct` 始终指向内置直连出站，无需声明即可被 user 引用；`default` 为旧式无名默认档的日志哨兵（见 AC8），保留以杜绝「具名 default 出站」与哨兵的语义歧义，且不可被引用（属未声明名，自然命中 R6 报错）。
- R4: 按用户选出站对 **TCP 与 UDP-over-TCP 均生效**（`dialResolved` 与 `listenPacketContext` 同源选择）。
- R5: Caddyfile 与 JSON 两种配置都能表达该模型，且现有单 `outbound` 配置语义不变。
- R6: 配置校验：user/`default_outbound` 引用的出站名必须已声明或为 `direct`，否则 Provision 内校验报错（校验须在 `namedOutbounds` 构建后执行，见 design）；具名出站重名报错（仅 Caddyfile 路径可检，见 AC5）；Caddyfile 中 `default_outbound` 指令重复出现报错（与 `outbound` 对齐，不沿用标量指令静默覆盖的旧例）。
- R7: 多出站的 Provision/Cleanup 生命周期正确、无连接泄漏。**连带修复**：`closeActiveSessions` 的触发点由已证实不生效的 `ctx.OnCancel`（见 Background）改为 `ListenerWrapper` 实现 `caddy.CleanerUpper` 的 `Cleanup()`，使配置卸载时活跃会话被真实地主动关闭。边界如实声明：caddy 对模块 Cleanup 的遍历（`moduleInstances` 为 map）**无跨模块顺序保证**，出站模块 Cleanup 时可能仍有在用连接——后果有界（该连接报错并由 relay 关闭，不泄漏），出站扩展点文档（docs/technical-design.md）须写明第三方出站需容忍此情形。
- R8: 可观测性：连接建立日志（Info 级 `anytls connection established`，`handler.go:92` TCP / `handler.go:125` UDP）与 node_info 日志标注该连接/该 user 实际使用的出站名；出站名在 `NewConnectionEx` 顶层解析一次并复用，避免并发拨号 goroutine 重复打印。（`anytls relay closed` 为 Debug 级且条件触发，`handler.go:53`，不作为出站名的默认可见来源。）
- R9: 并发拨号安全——`outboundForUser` 读取的运行期映射（`namedOutbounds`/`userOutbound`/`defaultOutbound`）在 Provision 后只读、服务启动前构建完毕，运行期零写入；并发 happy-eyeballs goroutine + 高并发子流下并发 map 读无需加锁（与现有 `h.config.outbound` 字段读同构）。同一 per-user 出站被并发 `DialContext` 多次时不得泄漏连接。

## Acceptance Criteria

- [x] AC1: 两个账号（家宽/直连）连同一 `:443`，出口 IP 分别为家宽出口与本机直连出口（集成测试：按 user 选到不同 `Outbound`，记录 dial 地址来源）。
- [x] AC2: 声明 ≥2 个具名出站 + 各自 user 引用时，各 user 命中各自出站（单元测试覆盖 name→outbound 映射）。
- [x] AC3: 未配置 `outbounds`/`default_outbound` 时，现有配置（含单 `outbound wireguard`、无 `outbound`）行为完全不变（回归测试）。
- [x] AC4: UDP-over-TCP 会话按 user 走对应出站（`listenPacketContext` 路径测试）。
- [x] AC5: 引用未声明出站名 → 配置报错（Caddyfile 与 JSON 两路径）；具名出站重名 → 报错（**仅 Caddyfile 路径**——JSON `map[string]json.RawMessage` 对重复键由 encoding/json 静默取后者、无法检测）；显式声明保留名 `direct` 或 `default` → 报错；Caddyfile 中 `default_outbound` 指令重复出现 → 报错。
- [x] AC6: `direct` 保留名可被 user 引用且无需声明。
- [x] AC7: 配置重载/卸载经 `ListenerWrapper.Cleanup()`（生产真实钩子，替代已证实不生效的 OnCancel）主动关闭全部活跃会话，多出站资源正确清理、无泄漏；测试须经 `Cleanup()` 方法触发（扩展 `TestReloadStyleClosesExistingSessions`，anytls_test.go:1252，不再直调 `closeActiveSessions`），并覆盖 ≥2 个具名出站。
- [x] AC8: Info 级 `anytls connection established` 日志包含 `outbound` 字段，值为实际使用的出站名（具名引用→其名、`default_outbound` 命中→其名、`direct` 引用或兜底→`direct`、旧式单 `outbound` 无名默认→哨兵 `default`；`default` 已列保留名（R3），哨兵无撞名歧义）；每连接一条，不因并发拨号重复。
- [x] AC9a（命中确定性）: 集成断言用 **IP 字面量目标**（`interleaveAddressFamilies` 对单地址原样返回、`fallbackTimerC=nil` → 恰好一次 `DialContext`），断言该次拨号命中该 user 对应的出站——dial 次数确定、无并发干扰。
- [x] AC9b（并发无泄漏）: 多候选地址目标下，同一 per-user 出站在单连接内被并发 `DialContext` 多次时不泄漏连接；落败连接由 `drainDialResults` 关闭（`handler.go:219`）。注意 250ms fallback 延迟硬编码带来的时序敏感，测试须防 flaky（如 sync-gated fake outbound）。
- [x] AC10: node_info 日志每 user 标注其出站名（显式标注→其名；未标注→默认档名：`default_outbound` 名 / 哨兵 `default` / `direct`），有单元断言覆盖（node_info_test.go 模式）。

## Out of Scope

- 按目标域名/IP 的自动路由分流（方案③，可作后续）。
- 每出站独立的目标策略（allow/deny per outbound）：v1 沿用全局策略，标记为可能的后续。
- 多端口 / 多 SNI 方案。
- 动态用户/出站管理 API。

## Open Questions

- 无。Caddyfile 语法（行尾引用名 + 嵌套 `NextArg` 消歧）已经开工评审对照 caddy v2.11.4 源码确认（2026-07-16）；生命周期修复方向已定（Cleanup 钩子，见 R7）；哨兵 `default` 已定为保留名（R3）。
