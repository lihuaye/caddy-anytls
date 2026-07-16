# 执行计划 — AnyTLS 按用户选择出站

## 有序实现清单

1. **生命周期修复（anytls.go）**——独立于功能改动，先行落地
   - 移除 `ctx.OnCancel` 注册（`anytls.go:136-138`）：caddy v2.11.4 下该回调永不执行，是死代码（实证见 design「生命周期与清理」/research G4）。
   - `ListenerWrapper` 实现 `caddy.CleanerUpper`：`Cleanup() error` 内调 `lw.closeActiveSessions("config_unload")`；加 `var _ caddy.CleanerUpper = (*ListenerWrapper)(nil)` 接口断言。
   - 注意：caddy 跨模块 Cleanup **无顺序保证**（`moduleInstances` 为 map），勿在此假设出站模块尚未/已经 Cleanup。

2. **数据结构（anytls.go）**
   - `ListenerWrapper` 新增：`OutboundsRaw map[string]json.RawMessage`（tag: namespace + inline_key=dialer）、`DefaultOutbound string`。
   - 运行期字段：`namedOutbounds map[string]Outbound`、`defaultOutbound Outbound`、`defaultOutboundName string`、`userOutbound map[string]Outbound`、`userOutboundName map[string]string`。后两者**仅存显式标注的 user、双 map 同步写入**（键集严格一致）；未标注 user 不建条目，名字走 `defaultOutboundName`。
   - `User` 新增 `Outbound string`（json `outbound,omitempty`）。

3. **加载与解析（anytls.go `Provision`）**
   - 保留现有 `OutboundRaw` 加载（作为默认候选）。
   - `ctx.LoadModule(lw, "OutboundsRaw")` → 断言每值实现 `Outbound`，填入 `namedOutbounds`。
   - **保留名检测先于注入**：先检查加载结果键（或 raw 键）是否含 `direct`/`default` → 报错；然后才注入 `namedOutbounds["direct"] = new(DirectOutbound)`（顺序反了会被注入遮蔽、无从检测）。
   - 按序解析 `defaultOutbound` + `defaultOutboundName`：`DefaultOutbound` 非空 →（`namedOutbounds[名]`，该名）；否则单 `OutboundRaw` →（它，哨兵 `"default"`）；否则 →（`DirectOutbound`，`"direct"`）。
   - 构建 `userOutbound`/`userOutboundName`：遍历 `Users`，仅 `Outbound` 非空者解析到 `namedOutbounds` 并同步写两 map。

4. **校验（Provision 内、`namedOutbounds` 构建后）**
   - ⚠️ **读 `namedOutbounds` 不读 raw**：`ctx.LoadModule` 加载后清零 raw 字段（caddy `context.go:283-284`）、且 Caddy 在 Provision 之后才跑 `Validate`（`context.go:426→441`）；若在 `Validate` 读 `OutboundsRaw` 会静默全过。故引用校验放 Provision 内、`namedOutbounds` 构建之后。
   - `User.Outbound`、`DefaultOutbound` **非空**值必须 ∈ `namedOutbounds` 键集（含已注入的 `direct`），否则 error；**空串=默认**，不视为引用、不报错。
   - 具名出站不得空名；**重名报错仅 Caddyfile 路径**（JSON `map[string]json.RawMessage` 由 encoding/json 静默取后者，无法感知重复键）。
   - 每个具名出站模块类型检查（非 `Outbound` 报错，复用现有断言 `anytls.go:151` 模式）。

5. **Caddyfile 语法（config.go）**
   - `outbound` 分支：**用嵌套 `d.NextArg()` 消歧**。第一次 `NextArg` 取 tok1；第二次成功=具名（tok1=name、tok2=module，游标停 module token）写入 `OutboundsRaw[name]`、键重名报错；第二次失败=默认（tok1=module，游标停 module token）复用现有路径。
   - **既有重复检测下移**：`config.go:195-196` 的重复报错现位于 case 顶部，须移入**默认形态分支**内、仅约束无名形态一次——否则第二条具名 `outbound <name> <module>` 行会被误拒。
   - 新增 `default_outbound <name>` 分支：恰一参；**重复出现报错**（与 `outbound` 对齐）。
   - `user` 分支（现 `config.go:183-192`，已用 `RemainingArgs`）：允许 2 或 3 个参数，第 3 个=出站名。
   - `UnmarshalJSON`（config.go:222）匿名 struct 加 `Outbounds map[string]json.RawMessage`、`DefaultOutbound string` 并透传（`OutboundRaw` 已在，`config.go:246`）；`User.UnmarshalJSON`（config.go:289-305）别名整体反序列化，新字段自动透传。

6. **选择点替换（handler.go）**
   - 新增 `(h *directTCPHandler) outboundForUser(ctx) (Outbound, string)`：**回退链严格为 `userOutbound[user]`（名=`userOutboundName[user]`）→ `defaultOutbound`（名=`defaultOutboundName`）→ `config.outbound`（名=`"default"`）→ `&DirectOutbound{}`（名=`"direct"`）**。必须含 `config.outbound` 档，否则现有无-user 单测回归（research G2）。
   - `dialResolved`（定义 `handler.go:262`）内的调用点 `handler.go:271` 与 `listenPacketContext`（定义 `handler.go:274`）内的 `handler.go:278` 改用它；dial 路径丢弃名字（`ob, _ :=`，名字已在顶层解析）。**勿动** `dialResolved` 内 `connect_timeout` 包装（`handler.go:266-269`）。
   - 删除或改写 `h.outbound()` 方法（`handler.go:284`）。

7. **可观测性（handler.go / node_info.go）**
   - 出站名在 `NewConnectionEx`（`handler.go:29`）顶层经 `outboundForUser` 解析一次并复用；Info 级 `anytls connection established`（TCP `handler.go:92` / UDP `handler.go:125`）增加 `outbound` 字段；每连接恰一条，不在并发 `dialResolved` goroutine 内打印。（`anytls relay closed` 为 Debug 级且条件触发 `handler.go:53`，不作默认可见来源。）
   - `name` 取值（与 design 一致）：具名引用→其名、`default_outbound` 命中→其名、`direct` 引用或兜底→`"direct"`、**旧式单 `outbound` 无名默认→哨兵 `"default"`**（`default` 已列保留名，无撞名）。
   - node_info 日志每 user 输出出站名（显式标注→其名；未标注→`defaultOutboundName`）。
   - （顺手项，非门槛）`anytls outbound dial failed`（`logOutboundFailure`）加 `outbound` 字段。

8. **文档（docs/ + README）**
   - `docs/examples.md`：新增按用户多出站示例（家宽+直连）。
   - `docs/technical-design.md`：出站扩展点章节补「按用户选择」「默认解析顺序」「并发多拨扇出提示（连接数/速率预算）」以及**「出站须容忍 Cleanup 时仍有在用连接」契约**（design 生命周期顺序边界）。
   - `docs/product.md`：产品能力描述同步 per-user 出站。
   - `README.md`：同步能力说明。

## 测试计划（*_test.go）

- `outbound_test.go`（单元/配置）：
  - Caddyfile：`outbound <name> <module>` 具名解析 → `OutboundsRaw` 键正确；`user a pw name` 第 3 参数解析到 `User.Outbound`。
  - 报错路径：具名重名（Caddyfile）；引用未声明名（Caddyfile + JSON 两路径）；**显式声明保留名 `direct` / `default`**；`default_outbound` 指令重复。
  - `direct` 保留名可被引用且无需声明。
  - `default_outbound` 解析顺序（named > 单 outbound > direct）与 `defaultOutboundName` 取值（其名 / `"default"` / `"direct"`）。
  - 回归：现有默认/单出站/重复/未知/类型检查/timeout/cancel 用例保持全绿（回退链含 `config.outbound` 的保证）。
- 集成（anytls_test.go / 新增）：
  - AC9a 命中确定性：两 user 各引用一个 `recordingOutbound`（借 `outbound_test.go:23` 模式），**目标须用 IP 字面量**（`interleaveAddressFamilies` 对单地址原样返回、`fallbackTimerC=nil` → 恰好一次 `DialContext`），断言各自命中各自出站；否则并发拨号使 dial 次数非确定、测试 flaky。
  - AC9b 并发无泄漏：多候选地址目标下落败连接由 `drainDialResults`（`handler.go:219`）关闭；250ms fallback 延迟硬编码、时序敏感，用 sync-gated fake outbound 防 flaky。
  - UDP-over-TCP：按 user 选到对应出站的 `ListenPacket`；未标注 user 走 default。
  - AC8 日志：observer 断言 `anytls connection established` 含 `outbound` 字段且每连接恰一条（复用 anytls_test.go:1240 的字段断言模式）。
  - AC7 生命周期：经 `ListenerWrapper.Cleanup()` 触发会话关闭（扩展 `TestReloadStyleClosesExistingSessions`，anytls_test.go:1252，**改为经 `Cleanup()` 而非直调 `closeActiveSessions`**），覆盖 ≥2 个具名出站。
  - AC10 node_info：每 user 出站名断言（node_info_test.go 模式）。
  - 前提：经 `NewConnectionEx` 的用例须先在 `sessionRegistry` 注册会话（`session_registry.go:63`，否则 `handler.go:33` 拒连）；注入认证 user 用 sing 的 `auth.ContextWithUser[string]`（sing v0.8.11 `common/auth/context.go`）。
- fixtures：需要时扩展 `newTestWrapper`（fixtures_test.go:37）以注入 `userOutbound`/`userOutboundName`/`namedOutbounds`/`defaultOutboundName`。

## 验证命令

```sh
gofmt -l .            # 期望无输出
go vet ./...
go build ./...
go test ./...         # 全绿，重点 outbound_test.go 回归
```
（可选）端到端：`xcaddy build --with github.com/evaneonf/caddy-anytls=. --with github.com/lihuaye/caddy-wireguard`，用两账号连同一 :443 核对出口 IP。

## 风险文件与回滚点

- `config.go`（语法消歧 + 重复检测下移，最易引入回归）——改前后跑全套 `outbound_test.go`。
- `anytls.go`（生命周期修复 + 多出站加载/解析/校验）。
- `handler.go`（选择点替换，影响所有转发路径）。
- 回滚：功能三处相互依赖（handler 依赖 anytls 新字段），**整体 revert**、不可单独回滚；已用新语法的配置回滚后解析失败属预期，发布说明提示。步骤 1 生命周期修复独立，回滚功能时可单独保留。

## task.py start 前检查

- [x] prd.md 通过 convergence pass（AC9 拆分为可独立验证的 a/b、AC10 补齐 node_info 验收、无遗留 open question；锚点经 2026-07-16 双代理核验零漂移）。
- [x] design.md / implement.md 与 prd.md 一致（哨兵 `default` 列为保留名、生命周期改挂 Cleanup 钩子、回退链与日志取值规则多处对齐）。
- [ ] 用户已评审规划或明确批准实现。
- [x] 语法/默认解析/保留名规则三者在 design 中定义无冲突（经交叉情形核验：`outbound direct` 单参合法、`default_outbound direct` 合法、具名声明 `direct`/`default` 报错）。
