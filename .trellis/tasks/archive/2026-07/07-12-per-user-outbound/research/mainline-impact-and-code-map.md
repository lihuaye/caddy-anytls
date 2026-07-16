# Research: 主线 201aad3 对 per-user-outbound 的影响 + 当前代码锚点图

> 快照基线：变基后 HEAD `8091bd3`（可插拔出站 commit 重放在主线 `201aad3` 之上）。
> 来源：系统架构师 + Caddy 模块 Go 工程师两轮复查（2026-07）+ 开工门禁双代理复核（2026-07-16，Go 工程师源码级实证 + 架构师一致性核查）。
> ⚠️ 行号为快照；实现一旦开始编辑这些文件即会漂移，仅供起步定位。

## 结论

方案架构成立。开工门禁复核（2026-07-16）对全部锚点复验**零漂移**、基线 `gofmt/vet/build/test` 全绿，但**证伪了一条关键断言（G4：OnCancel 在 v2.11.4 是死钩子）**——生命周期机制已在工件中改挂 `ListenerWrapper.Cleanup()`。主线的并发 happy-eyeballs 拨号器、三级限流/`sessionRegistry` 与 per-user 出站选择**正交**，选择点仍单点可替换。实现须遵守下列 4 条陷阱。

## 关键代码锚点图（当前 HEAD）

| 实体 | 当前位置 | 备注 |
|---|---|---|
| `Outbound` 接口 | `outbound.go:30` | `DialContext`/`ListenPacket`，签名不变；契约要求并发安全 + 每次返回独立连接（`outbound.go:24-27`） |
| `DirectOutbound` | `outbound.go:51` | 保留名 `direct` 的内置实现 |
| `DirectOutbound.UnmarshalCaddyfile` | `outbound.go:77` | `d.Next()` 消费自己的 module-name token（消歧机制依据） |
| `userFromContext` | `auth.go:13` | `auth.UserFromContext[string]`，= `User.Name` |
| sing user 由 `Name` 建 | `anytls.go:252` | 在 `anyTLSUsers()`（245-257）内 |
| `User` struct | `anytls.go:82-86` | 加 `Outbound string` 字段处 |
| `NewConnectionEx` | `handler.go:29` | user 在此顶层可得；出站名应在此解析一次复用 |
| `acquireStream`/`acquireSessionStream` | `limits.go:28` / `session_registry.go:63` | 主线新增；`NewConnectionEx` 在 `handler.go:33` 调用，无 session 记录返回 false 会拒连 |
| `dialContext`（并发拨号器） | `handler.go:139-217` | happy-eyeballs：多候选交错、250ms 回退、共享 connect_timeout |
| 顶层 connect_timeout | `handler.go:140-144` | dialContext 入口 |
| `launchDial` 并发拨号 | `handler.go:155-163` | 每候选一个 goroutine，调 `dialResolved(handler.go:157)` |
| `drainDialResults`（关落败连接） | `handler.go:219` | 无泄漏依据 |
| `dialResolved` 定义 | `handler.go:262` | 内层 connect_timeout 包装在 `:266-269`，**勿动** |
| **TCP 出站调用点** | `handler.go:271` | `h.outbound().DialContext` → 改 `outboundForUser` |
| `listenPacketContext` 定义 | `handler.go:274` | UDP，调用点在 `handleUDPOverTCP` `handler.go:115` |
| **UDP 出站调用点** | `handler.go:278` | `h.outbound().ListenPacket` → 改 `outboundForUser` |
| `outbound()` 方法本体 | `handler.go:284` | 待替换/改写 |
| established 日志（Info） | `handler.go:92`（TCP）/`:125`（UDP） | R8/AC8 的出站名加此处 |
| relay closed 日志（Debug，条件） | `handler.go:53` | 仅 DebugLevel 可见，非默认可见来源 |
| dial failed 日志（Warn） | `handler.go:344` 附近 `logOutboundFailure` | 顺手项：可加 `outbound` 字段 |
| `outbound` Caddyfile 分支 | `config.go:194-210` | 重复检测 `:195-196`（**须下移进默认形态分支**，见 G1）；类型检查 `:207` |
| `user` Caddyfile 分支 | `config.go:183-192` | 现用 `RemainingArgs`，硬编码 len==2 |
| `UnmarshalJSON` 匿名 struct | `config.go:222` | `OutboundRaw` 已在 `:246`；加 `Outbounds`/`DefaultOutbound` |
| `User.UnmarshalJSON` | `config.go:289-305` | `type userAlias User` 别名，新字段自动透传 |
| OutboundRaw 加载 | `anytls.go:146-159` | `ctx.LoadModule(lw,"OutboundRaw")` `:147`；类型断言 `:151` |
| OnCancel 注册（**待移除，死代码**） | `anytls.go:136-138` | v2.11.4 下永不执行（G4）；改由 wrapper `Cleanup()` 触发 |
| `closeActiveSessions` 函数体 | `session_registry.go:85` | 主动 cancel+close 每会话 |
| 直调 `closeActiveSessions` 的测试 | `anytls_test.go:1252` `TestReloadStyleClosesExistingSessions` | 绕过真实钩子；AC7 要求改经 `Cleanup()` 触发 |
| established 日志字段断言模式 | `anytls_test.go:1240` | AC8 observer 断言可复用 |
| 测试脚手架 | `fixtures_test.go:37`(`newTestWrapper`)/`:51`(设 outbound) ; `outbound_test.go:23`(`recordingOutbound`) | 直调 dial 用例：`outbound_test.go:301,319,339,352` |
| caddy 版本 | `go.mod:7` = `v2.11.4` | LoadModule map 支持依据 |
| caddy LoadModule map | `context.go:272`(`reflect.Map`)/`:318`(`loadModulesFromRegularMap`) | 返回 `map[string]any`，每值一 Outbound |

## 4 条关键陷阱（实现必须遵守）

### G1 — Caddyfile `outbound` 消歧：用嵌套 `NextArg` 表达 1-vs-2 分支
第一次 `NextArg` 取 tok1；第二次成功=具名(tok1=name,tok2=module)、失败=默认(tok1=module)；两种情况游标都停在 module-name token 上，`UnmarshalModule`→`NewFromNextSegment` 的 segment 含当前 token（caddy `dispenser.go:359` `Segment{d.Token()}`）供其定位。
> ⚠️ 更正（Go 规格审查）：早前「`RemainingArgs` 会让模块误吃 `{` / 破坏 `UnmarshalModule` 定位」的说法**有误**。经核对 caddy 源码，`RemainingArgs` 后游标同样停在最后一个 arg（module token）上、定位不受影响。选 `NextArg` 仅因**意图清晰、免切片**，非正确性所迫。
> ⚠️ 附带硬约束：既有重复检测（`config.go:195-196`）位于 case 顶部，须**下移进默认形态分支**，否则第二条具名 `outbound <name> <module>` 行会被误拒。

### G2 — `outboundForUser` 回退链**必须含 `config.outbound`**
顺序：`userOutbound[user]` → `defaultOutbound` → `config.outbound` → `&DirectOutbound{}`。
原因：现有 handler 单测用无-user 的 `context.Background()` 直调 `dialResolved`/`listenPacketContext`，且手搓 wrapper 只设 `config.outbound`；漏这一档 → `outbound_test.go` dial/listen/timeout/cancel 用例回归。

### G3 — 并发拨号 × per-user 出站
`dialResolved` 被同连接多候选地址**并发调用**（同 user → 查表幂等，安全）。同一 per-user 出站单连接内被并发 `DialContext` 最多 N 次，落败连接由 `drainDialResults` 关闭（无泄漏，见 R9/AC9b）。
- 运行期映射 Provision 后只读 → 并发读无需加锁。
- 命中断言的集成测试目标**须用 IP 字面量**（→ `interleaveAddressFamilies` 单地址原样返回、`fallbackTimerC=nil` → 恰好一次 `DialContext`），否则 dial 次数不确定、flaky（AC9a）。
- 若集成测试经 `NewConnectionEx`，须先在 `sessionRegistry` 注册会话，否则 `acquireSessionStream` 返回 false、连接在 `handler.go:33` 被拒；注入认证 user 用 sing 的 `auth.ContextWithUser[string]`（sing v0.8.11 `common/auth/context.go`）。
- 出站名在 `NewConnectionEx` 顶层解析一次并复用，勿在每个并发 goroutine 打印。

### G4 — OnCancel 在 caddy v2.11.4 对模块 Provision 注册**永不执行**（开工门禁实证证伪，2026-07-16）
`cleanupFuncs` 是 `caddy.Context` 值字段（caddy `context.go:52`）；Provision 以值接收 Context（`context.go:426`），`OnCancel`（`:99-101`）append 到副本；cancel 闭包遍历原 slice（`:78`）。最小程序实证（真实 `caddy.Run`→`Stop` 生命周期）：**OnCancel fired=false、module Cleanup fired=true**。
- `anytls.go:136-138` 的注册是死代码；`TestReloadStyleClosesExistingSessions`（anytls_test.go:1252）直调 `closeActiveSessions` 绕过钩子——测试绿 ≠ 机制生效。
- 修复（已写入工件）：wrapper 实现 `caddy.CleanerUpper`，`Cleanup()` 调 `closeActiveSessions("config_unload")`；模块 Cleanup 实证会执行。
- 边界：跨模块 Cleanup **无顺序保证**（`moduleInstances` 为 map），出站扩展点文档须要求第三方出站容忍 Cleanup 时仍有在用连接。
- 原「cleanupFuncs 先于模块 Cleanup、卸载顺序结构性保证、比被动等待更强」的结论**撤回**。
- 上游跟进（任务外）：疑似 caddy 缺陷，可向上游报告。

## 已证实的可行性

- named-map 加载：`OutboundsRaw map[string]json.RawMessage` + tag `caddy:"namespace=caddy.listeners.anytls.outbounds inline_key=dialer"` → `ctx.LoadModule(lw,"OutboundsRaw")` 得 `map[string]any`（caddy v2.11.4，`context.go:318`），Caddy 自动 Provision/Cleanup 每个具名出站。
- LoadModule 后 raw 字段被清零（`context.go:283-284`）、Validate 在 Provision 之后（`context.go:426→441`）→「引用校验放 Provision、读 `namedOutbounds` 不读 raw」成立。
- `NextArg` 语义（同行前进/遇 `{` 回滚/行尾不前进，`dispenser.go:89-118`）与 `UnmarshalModule` 定位（`dispenser.go:359`）→ G1 消歧方案成立。
- encoding/json 对 map 重复键静默取后者（实证）→ AC5 重名检测按路径拆分的前提成立。
- ~~卸载顺序结构性保证（OnCancel 先于模块 Cleanup）~~ **撤回**（见 G4）：改为 wrapper `Cleanup()` 主动关会话，顺序边界如实降级声明。
