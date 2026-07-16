# 技术设计 — AnyTLS 按用户选择出站

## 架构与边界

在现有「单出站 per wrapper」之上引入 **具名出站集合 + 每用户引用**，选择点落在 handler 拨号时（此时已知认证 user）。不改动入口/回落/协议识别/目标策略/域名解析链路——只把「用哪个 `Outbound` 搬字节」从全局唯一改为按 user 解析。

选择信号来自认证 user 字符串（`auth.UserFromContext`，= `User.Name`），在 `NewConnectionEx` 全程可得，TCP 与 UDP-over-TCP 共用同一解析函数。

## 数据模型

### 配置字段（`ListenerWrapper`，anytls.go）

| 字段 | JSON | 说明 |
|---|---|---|
| `OutboundRaw` | `outbound` | 现有单出站；语义变为「设置默认出站」（向后兼容） |
| `OutboundsRaw` | `outbounds` | 新增；`map[string]json.RawMessage`，键=出站名，值=出站模块对象 |
| `DefaultOutbound` | `default_outbound` | 新增；显式指定默认出站名 |
| `User.Outbound` | `users[].outbound` | 新增；引用出站名，空=默认 |

`OutboundsRaw` 的 struct tag：
```go
OutboundsRaw map[string]json.RawMessage `json:"outbounds,omitempty" caddy:"namespace=caddy.listeners.anytls.outbounds inline_key=dialer"`
```
Caddy 2.11.4 `LoadModule` 对 `reflect.Map` + `inline_key` 返回 `map[string]any`（`context.go:272`/`:318`），每个 value 是一个 `Outbound`。

### 运行期解析（Provision 内一次性构建）

```
namedOutbounds      map[string]Outbound  // 来自 OutboundsRaw + 保留名 "direct"（内置）
defaultOutbound     Outbound             // 按解析顺序确定
defaultOutboundName string               // default_outbound 名 / 哨兵 "default"（旧式单 outbound）/ "direct"
userOutbound        map[string]Outbound  // User.Name -> 解析后的 Outbound（仅显式标注者）
userOutboundName    map[string]string    // 与 userOutbound 键集严格一致（仅显式标注者，双 map 同步写入）
```

拨号时：`outboundForUser(user)` 回退链：`userOutbound[user]` → `defaultOutbound` → `config.outbound` → `&DirectOutbound{}`（末两档为 Provision 未跑的手搓单测兜底，详见「数据流」与「兼容与迁移」）。`user` 为空串（认证后不应为空）也走此链，安全兜底。名字与档位一一对应、来源单一：显式标注 → `userOutboundName[user]`；默认档 → `defaultOutboundName`；`config.outbound` 档 → `"default"`；`DirectOutbound` 兜底 → `"direct"`。

### 默认出站解析顺序（向后兼容硬规则）

1. `DefaultOutbound` 非空 → `namedOutbounds[DefaultOutbound]`，`defaultOutboundName` = 该名；
2. 否则 `OutboundRaw` 非空且非 `null` → 加载它（现有 `anytls.go:146-159` 逻辑），`defaultOutboundName` = 哨兵 `"default"`；
3. 否则内置 `DirectOutbound`，`defaultOutboundName` = `"direct"`。

保留名 `direct` 与 `default`（**均不可占用**）：`direct` 在 Provision 时注入 `namedOutbounds["direct"] = new(DirectOutbound)`，user 引用 `direct` 直接命中、无需在 `outbounds` 里写；`default` 是旧式无名默认档的日志哨兵（见「可观测性」），保留以杜绝「具名 default 出站」与哨兵的语义歧义。用户在 `outbounds` 显式声明任一保留名 → Provision 校验报错。**检测顺序硬约束**：占用检测必须在注入内置 `direct` **之前**、对 LoadModule 的加载结果键（或 raw 键）执行——否则注入会遮蔽用户声明、无从检测。

## 配置形态（Caddyfile）

推荐语法（**行尾引用名**，最简洁，向后兼容）：

```caddyfile
anytls {
    # 具名出站：outbound <name> <module> { ...module config... }
    outbound wg-home wireguard {
        private_key     <base64>
        peer_public_key <base64>
        endpoint        home.example.com:51820
        address         10.7.0.2
        allowed_ips     0.0.0.0/0 ::/0
    }

    # 默认出站（可选）：不写则按解析顺序落到单 outbound 或内置 direct
    default_outbound wg-home

    # user <name> <password> [outbound-name]；省略 = 默认
    user phone-home  <pw1>            # -> 默认（wg-home）
    user phone-direct <pw2> direct    # -> 内置 direct
    user laptop      <pw3> wg-home    # 显式引用
}
```

向后兼容形态（现状不变）：
```caddyfile
anytls {
    outbound wireguard { ... }   # 1 参数 = 默认出站
    user a <pw>                  # 全员走它
}
```

### 语法消歧（config.go `outbound` 分支）

用**嵌套 `d.NextArg()`** 按参数个数区分具名/默认形态（`NextArg` 只在同一行前进、遇 `{` 回滚、行尾返回 false 且不前进）：
- 第一次 `NextArg()` 取 tok1。
- 第二次 `NextArg()` **成功** ⇒ 具名形态 `outbound <name> <module> {...}`：tok1=name、tok2=module，游标停在 module token → `UnmarshalModule` 写入 `OutboundsRaw[name]`；名重复报错。
- 第二次 `NextArg()` **失败** ⇒ 默认形态 `outbound <module> {...}`：tok1=module，游标仍停在 module token → 复用现有 `UnmarshalModule` 路径，仍限一次。

两种情况游标都停在 module-name token 上，`UnmarshalModule` → `NewFromNextSegment` 的 segment 含当前 token（caddy `dispenser.go:359` `Segment{d.Token()}`），定位正确。

> 选 `NextArg` 的理由是**意图清晰、免切片**、直接表达 1-vs-2 分支——**不是**因为 `RemainingArgs` 会破坏定位。经核对 caddy 源码，`RemainingArgs` 后游标同样停在最后一个 arg（module token）上、`UnmarshalModule` 定位不受影响；此处不采用它仅出于可读性（早前「会误吃 `{`」的说法有误，已更正）。

**既有重复检测须下移**：`outbound` 重复报错现位于 case 顶部（`config.go:195-196`），消歧改造后必须移入**默认形态分支**内、仅约束无名形态一次——否则第二条具名 `outbound <name> <module>` 行会被误拒。具名形态的重名由 `OutboundsRaw` 键重复检测负责。

新增 `default_outbound <name>` 指令：恰一个参数；**重复出现报错**（与 `outbound` 对齐，不沿用标量指令静默覆盖的旧例）。

`user` 分支（现状已用 `RemainingArgs`，`config.go:183-192`）：长度 2（现状）或 3（第 3 个 = 出站名）；其他长度报错。

## 配置形态（JSON）

```json
{
  "outbound": {"dialer": "wireguard", "endpoint": "..."},
  "outbounds": {
    "wg-home":  {"dialer": "wireguard", "endpoint": "home.example.com:51820"},
    "wg-node2": {"dialer": "wireguard", "endpoint": "node2.example.com:51820"}
  },
  "default_outbound": "wg-home",
  "users": [
    {"name": "phone-home",  "password": "..", "outbound": "wg-home"},
    {"name": "phone-direct","password": "..", "outbound": "direct"},
    {"name": "laptop",      "password": ".."}
  ]
}
```
`UnmarshalJSON`（config.go:222）匿名 struct 需新增 `Outbounds map[string]json.RawMessage`、`DefaultOutbound string` 字段并透传（`OutboundRaw` 已在该匿名 struct，`config.go:246`）；`User` 结构（`anytls.go:82-86`）新增 `Outbound string`（其 `UnmarshalJSON` 在 `config.go:289-305`，用 `type userAlias User` 别名整体反序列化 + 仅补 `enabled` 默认，新字段自动透传，加字段即可）。

## 数据流（拨号选择）

```
NewConnectionEx(ctx, ...)                 handler.go:29
  user := userFromContext(ctx)
  _, obName := h.outboundForUser(ctx)     // 名字在此顶层解析一次，供日志复用
  ...
  dialContext(handler.go:139)
    -> 并发 launchDial -> dialResolved     定义 handler.go:262 / 并发调用 handler.go:157
      ob, _ := h.outboundForUser(ctx)     // 新：替代 handler.go:271 的 h.outbound()；名字此处弃用（顶层已解析）
      ob.DialContext(ctx, "tcp", ip:port) // 保留 dialResolved 内 connect_timeout 包装（handler.go:266-269）不动
  handleUDPOverTCP(handler.go:105)
    -> listenPacketContext                 定义 handler.go:274 / 调用 handler.go:115
      ob, _ := h.outboundForUser(ctx)     // 新：替代 handler.go:278 的 h.outbound()，同源选择
      ob.ListenPacket(ctx, "udp", "")
```

`h.outbound()` 方法（`handler.go:284`）的两个调用点 `handler.go:271`（TCP，dialResolved 内）与 `handler.go:278`（UDP，listenPacketContext 内）改为 `h.outboundForUser(ctx)`：读 `userFromContext(ctx)`，查 `config.userOutbound`，**回退链 = `userOutbound[user]` → `defaultOutbound` → `config.outbound` → `&DirectOutbound{}`**。回退链必须含 `config.outbound`：现有 handler 单测用无-user 的 `context.Background()` 直调 `dialResolved`/`listenPacketContext` 且手搓 wrapper 只设了 `config.outbound`（见「兼容与迁移」），漏掉这一档会回归。

## 与主线并发拨号器的交互（201aad3）

主线把 `dialContext`（`handler.go:139-217`）改为并发 happy-eyeballs：单目标解析出的多候选地址由 `launchDial`（`handler.go:155-163`）交错并发拨号，各 goroutine 共享同一 `dialCtx`（派生自携带 user 的连接 ctx）。对 per-user 出站选择的影响：

- **幂等**：N 个并发 `dialResolved` 读到同一 user，`outboundForUser` 纯查表 → 全部命中同一出站；无「同连接分裂到不同出站」隐患。
- **连接扇出**：单连接内同一 per-user 出站被并发 `DialContext` 最多 N 次；胜者保留，其余由 `cancel()`（`handler.go:182`/`:211`）+ `drainDialResults`（`handler.go:219`）关闭。对内置 `direct` 无碍；对 WireGuard 等隧道型出站意味着每连接瞬时 N 倍拨号扇出（多数随即取消）。`Outbound` 接口契约（`outbound.go:24-27`）已要求并发安全 + 每次返回独立连接 + 落败连接由调用方关闭，因此合法、无泄漏。→ 见 R9/AC9a/AC9b，并在 `docs/technical-design.md` 出站扩展点章节提示第三方作者：单连接可能收到并发多拨、须为此设计连接数/速率预算。
- **connect_timeout 双层**：`dialContext` 顶层（`handler.go:140-144`）与 `dialResolved` 内层（`handler.go:266-269`）各包一次同值 `connect_timeout`（主线既有行为，外层 deadline 主导，无副作用）。实现时只替换 `handler.go:271` 那一行 `h.outbound()`→`outboundForUser`，**勿动** `:266-269` 的 timeout 包装。

## 校验（Provision 内、`namedOutbounds` 构建后）

> 引用∈键集类校验必须在 **Provision 构建完 `namedOutbounds` 之后**执行，读 `namedOutbounds` 而非 `OutboundsRaw`：`ctx.LoadModule` 加载后会清零 raw 字段（caddy `context.go:283-284`），且 Caddy 在 Provision 之后才跑 `Validate`（`context.go:426→441`）——若在 Validate 读 raw 会静默全过。

- 每个 `User.Outbound`（非空）∈ `namedOutbounds` 键集（含已注入的 `direct`），否则报错。**空串 = 默认**，不视为引用、不报错（JSON `"outbound":""` 与省略等价）。
- `DefaultOutbound`（非空）同上。
- 保留名：`outbounds` 中显式声明 `direct` 或 `default` → 报错；检测先于内置 `direct` 注入（见「数据模型」检测顺序硬约束）。
- Caddyfile 中 `default_outbound` 指令重复出现 → 报错（解析期，config.go）。
- 具名出站不得为空名。**重名检测仅 Caddyfile 路径**：Caddyfile 手工建 map 时查重报错；JSON 路径 `map[string]json.RawMessage` 对重复键由 `encoding/json` 静默取后者、无法感知重名，故 JSON 侧只保留「引用未声明名」校验（AC5 据此按路径拆分）。
- 复用现有 `outbound` 的「非 anytls outbound 模块」类型检查（config.go:207、anytls.go:151）对每个具名出站执行。

## 兼容与迁移

- 不写 `outbounds`/`default_outbound`/`users[].outbound` 时，字段全空，`defaultOutbound` 落到现有 `OutboundRaw` 或内置 direct，`userOutbound` 空 → 所有连接走 default，行为与现状逐字节一致。
- **文法窄化（无实际回归）**：旧语法把 `outbound <module> <extra>` 的行内 `<extra>` 交给模块的 `UnmarshalCaddyfile` 处置；新语法把任意 2-arg `outbound` 行重解释为 `<name> <module>`。现存出站模块无一接受行内参数（`DirectOutbound` 明确拒绝，`outbound.go:78-80`），故无实际回归，但这是文法层面的行为变化，在此声明。
- 现有测试（fixtures `newTestWrapper` `fixtures_test.go:37`/`:51` 设 `outbound: new(DirectOutbound)` 或 `recordingOutbound`）不受影响：`outboundForUser` 在 `user==""` 且 `userOutbound`/`defaultOutbound` 为 nil 时**必须回退 `config.outbound`**。硬约束：`outbound_test.go` 的 dial/listen/timeout/cancel 用例用 `context.Background()`（无 user）直调 `dialContext`/`dialResolved`/`listenPacketContext`（`outbound_test.go:301,319,339,352`），只有回退链含 `config.outbound` 才继续绿。注意这些单测直调 dial 函数、不走 `NewConnectionEx`，故不触发主线新增的 `acquireStream`（`limits.go:28`）；若新增走 `NewConnectionEx` 的集成测试，则需先在 `sessionRegistry` 注册会话，否则 `acquireSessionStream`（`session_registry.go:63`）返回 false、连接在 `handler.go:33` 被拒。

## 生命周期与清理

- Provision：`ctx.LoadModule(lw, "OutboundsRaw")` 得 `map[string]Outbound`；连同默认出站一并持有。Caddy 自动 Provision/Cleanup 经 LoadModule 加载的模块。
- **⚠️ OnCancel 机制在 caddy v2.11.4 不生效（开工评审实证，2026-07-16）**：模块 Provision 以值接收 `caddy.Context`（caddy `context.go:426`），`OnCancel`（`context.go:99-101`）只 append 到副本的 `cleanupFuncs`（Context 值字段，`context.go:52`），而 cancel 闭包遍历的是原 slice（`context.go:78`）——回调**永不执行**（最小程序实证，真实 `caddy.Run`→`Stop` 生命周期：OnCancel fired=false、module Cleanup fired=true）。因此现有 `anytls.go:136-138` 注册的 `closeActiveSessions("config_unload")` 在生产中是死代码；此前「cleanupFuncs 先于模块 Cleanup、卸载顺序结构性保证」的论证**撤回**。
- **修复（本任务范围）**：移除 OnCancel 注册，`ListenerWrapper` 实现 `caddy.CleanerUpper`，`Cleanup()` 内调 `closeActiveSessions("config_unload")`（`session_registry.go:85`：对每个活跃会话 `cancel()`+`conn.Close()`，经 relay 的 `ctx.Done()`（`relay.go:57-63`）关闭 outbound 连接）。模块 Cleanup 经实证确认会执行。
- **顺序边界（如实声明）**：caddy 对 `moduleInstances`（map）的 Cleanup 遍历**无跨模块顺序保证**——出站模块的 Cleanup 可能先于 wrapper 的 Cleanup 执行。后果有界：届时在用连接报错并由 relay 关闭，不泄漏；但无法承诺「出站 Cleanup 时无使用中连接」。因此出站扩展点文档（docs/technical-design.md）须要求第三方出站**容忍 Cleanup 时仍有在用连接**（R7 据此措辞）。
- 上游跟进（任务外）：OnCancel 值拷贝丢失疑似 caddy 缺陷，可另行向上游报告；若未来上游修复，可再评估恢复 OnCancel 以获得「先关会话再 Cleanup」的确定顺序。

## 可观测性

- 出站名加在 **Info 级** `anytls connection established`（TCP `handler.go:92` / UDP `handler.go:125`）上：`zap.String("outbound", name)`。为此 `outboundForUser` 返回 `(Outbound, name string)`；name 来源单一（`userOutboundName` / `defaultOutboundName` / 兜底规则，见「运行期解析」）。**名字在 `NewConnectionEx`（`handler.go:29`）顶层解析一次并复用**，不要在每个并发 `dialResolved` goroutine 里打印，否则一次连接会出现多条重复出站日志。
- `name` 取值规则（确保 AC8 可断言）：user 显式引用 → 该引用名；`default_outbound` 命中 → 其名；引用 `direct` 或保留兜底 `&DirectOutbound{}` → `"direct"`；**默认档来自旧式单 `outbound`（无名）→ 哨兵 `"default"`**。`default` 已列保留名（不可声明），哨兵无撞名歧义。
- 注意 `anytls relay closed`（`handler.go:53`）为 **Debug 级且条件触发**（仅计数器非空、即 DebugLevel 时打印），不作为出站名的默认可见来源；R8/AC8 的稳定可见性靠 established(Info)。
- node_info 日志（`logNodeInfo`）每 user 增加其出站名字段（显式标注→其名；未标注→`defaultOutboundName`），便于运维核对哪个账号走哪个出口（AC10）。
- （顺手项，非 AC 门槛）`anytls outbound dial failed`（`logOutboundFailure`，handler.go:344 附近）可一并加 `outbound` 字段——拨号失败恰是最需要出站名的排障场景。

## 关键权衡

- **通用 map vs 最小两出站**：选通用。代价仅「加载 map 而非单模块 + 一层名解析」，换来任意多出站与和已落地的可插拔出站扩展点一致的方向。
- **默认解析含现有单 `outbound`**：为零回归，宁可解析顺序多一档，也不改老配置语义。
- **选择粒度 = per-user 而非 per-destination**：贴合本模块「极简接入层」定位；per-destination 路由显式列为 out of scope。将来若扩展，`outboundForUser` 签名可演进为携带 destination，named-outbounds map 是天然基础，本设计不构成障碍。
- **返回名用于日志**：`outboundForUser` 返回名字，避免二次反查；轻微增加签名复杂度，换可观测性。
- **生命周期修 Cleanup 而非等上游**：OnCancel 缺陷修复周期不可控；Cleanup 钩子实证有效、改动极小，顺序边界如实降级声明。

## 风险与回滚

- 风险点集中在 `config.go`（语法消歧——**最高风险**，用嵌套 `NextArg` 表达 1-vs-2 分支 + 重复检测下移）、`anytls.go`（多出站加载/解析/校验 + 生命周期修复）、`handler.go`（选择点替换，注意回退链含 `config.outbound`、勿动 `dialResolved` 内 timeout 包装）。
- 回滚：`handler.go` 的 `outboundForUser` 依赖 `anytls.go` 新字段，功能三处**不可单独回滚**，回滚 = 整体 revert（可行，改动集中）；已采用新语法（具名 `outbound`/`default_outbound`/user 第 3 参数）的用户配置在回滚后会解析失败，属预期，发布说明须提示。生命周期修复（Cleanup 钩子）独立于功能改动，回滚功能时可单独保留。
- 需重点回归：现有 `outbound_test.go` 全绿（默认/单出站/重复/未知/类型检查/timeout/cancel 路径）。并发拨号 × per-user 出站的无泄漏（R9/AC9b）与 Cleanup 钩子真实触发（AC7）作为新增回归项。
