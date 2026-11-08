# 日志巡检（P0）

> 通过 MCP **只读**查询 Graylog 三流日志，用确定性规则找出 Graylog 告警规则漏掉的攻击源。
> P0 阶段只产出报告，**不创建黑名单、不下发封禁**——目的是先让"漏了什么"看得见，再谈自动处置。

## 1. 为什么要这一步

Graylog 的 Event Definition 是"已知模式"的匹配，写得再全也会漏：新攻击手法、跨流关联（同一 IP 在 IPS 被记录、在 WAF 被放行）、阈值差一点没触发。
这一类漏封不会告警，只会在日志里静静躺着。

日志巡检就是补这个缝：**每 5 分钟把最近一段窗口的日志重新看一遍**，用规则把可疑源筛出来。

| | Graylog 告警规则 | 日志巡检（本模块） |
|---|---|---|
| 延迟 | 秒级（Webhook 直推） | ≤ 5 分钟 |
| 依据 | 预设条件 | 窗口内重新聚合 + 跨流关联 |
| 作用 | 主链路，命中即封 | 补漏，产出候选与建议 |
| 失败模式 | 漏、阈值不当 | 慢、依赖日志字段质量 |

两者不是替代关系：巡检长期目标是**把反复补封的模式反哺成 Graylog 规则**，让补封量逐月下降。

## 2. 五个设计约束

1. **只读**：P0 的代码路径里没有任何 `create_ioc` / 任务下发调用，`blocked` 恒为 0；
2. **可降级**：MCP 超时、协议不兼容、返回结构变化，都只让本轮变成 `degraded / failed`，不抛异常、不影响告警主链路；
3. **窗口重叠**：起点 = 上一轮 `window_end - PATROL_OVERLAP_SECONDS`，防止日志入库延迟导致窗口缝隙；最多回看 6 小时，避免断流后一次拉爆 Graylog；
4. **非公网地址不落候选**：内网/环回/保留地址本就禁止封禁，只计入 `ignored_non_public`，避免内部扫描把候选表刷满；
5. **候选上限 200**：异常日志（如误配的高频源）不会把表撑爆。

## 3. 处理流程

```
Celery Beat（默认 300s）
      │
      ▼
PATROL_MCP_URL + tools/call → 三流日志（IPS / WAF / ZTNA）
      │
      ▼
字段归一（多候选字段名）→ L1 规则 → 候选 IP（按严重度/权重/条数排序）
      │
      ▼
安全闸门预判（白名单 / 已封 / 24h 重复）→ decision
      │
      ▼
patrol_run + patrol_candidate 落库 → 页面与接口
```

## 4. L1 规则表

| key | 名称 | 判据 | 权重 |
|---|---|---|---|
| `ips_observed` | IPS 告警未阻断 | `action` 属于 alert/allow/pass 且严重度不是 1–2 | 3 |
| `waf_observed` | WAF 放行/仅记录 | `action` 属于 pass/log/monitor | 2 |
| `ztna_burst` | 零信任认证爆破 | 同源失败 ≥ 10 次/窗口 | 3 |
| `high_freq` | 高频访问 | 同源 ≥ 50 条/窗口 | 2 |
| `multi_stream` | 跨流命中 | 同一 IP 出现在 ≥ 2 条流 | 2 |
| `intel_hit` | 情报命中 | `tags` 含 intel/netpolice/malicious 或 `ti_score ≥ 60` | 4 |

字段名通过 `FIELD_ALIASES`（`backend/app/services/patrol.py`）匹配，例如源 IP 依次尝试
`src_ip / source_ip / client_ip / remote_addr / srcaddr / attacker_ip / sip / ip`。
新设备字段不一致时**只改这张表**，不动规则逻辑。

## 5. 处置预判（decision）

| decision | 含义 |
|---|---|
| `would_block` | 通过全部闸门；P0 只标记，不执行 |
| `skipped_whitelist` | 命中 IP 白名单（附匹配条目） |
| `skipped_existing` | 该 IP 已在生效黑名单中 |
| `skipped_repeat` | 24h 内已被本巡检标记过（`PATROL_REPEAT_HOURS`） |

P1 打开 `assist` / `auto` 后，`would_block` 会走已有 policy 链路（白名单优先、内网拒绝、
单次 ≤5 / 日 ≤20 配额、熔断开关、审计留痕），本模块不另写封禁路径。

## 6. 配置

```bash
PATROL_ENABLED=true                    # 关闭时定时任务直接跳过
PATROL_INTERVAL_SECONDS=300            # 5 分钟
PATROL_OVERLAP_SECONDS=60              # 窗口重叠
PATROL_MODE=dry-run                    # dry-run / assist / auto（后两者为 P1 预留）
PATROL_MCP_URL=https://graylog.example.com/api/mcp
PATROL_MCP_TOKEN=<Graylog 用户 API Token>
PATROL_MCP_AUTH=token                  # Graylog 用 Token；其它平台可 bearer / basic / raw
PATROL_MCP_TOOL=search_messages        # MCP 工具名
PATROL_MCP_STREAM_TOOL=list_streams    # 用于在页面上拉取流清单
PATROL_MCP_ARGS=                       # 留空 = 按工具 inputSchema 自动映射
PATROL_STREAMS=[{"name":"IPS","label":"IPS","stream_id":"<graylog-stream-id>","query":""}, ...]
PATROL_MAX_RECORDS=2000
PATROL_MCP_TIMEOUT=30
PATROL_REPEAT_HOURS=24
```

- **参数自动映射**：`PATROL_MCP_ARGS` 留空时，客户端先 `tools/list` 读目标工具的 `inputSchema`，
  再按角色匹配字段名（`query`/`search_query`、`stream_id`/`streams`、`from`/`start`、`to`/`end`、`limit`/`size`），
  **只传服务端声明过的字段**——多传未知参数会被严格实现直接拒绝。填了模板则按模板渲染：
  `${limit}` 按数字替换，其余按字符串替换，因此字符串占位符**必须自带引号**；
- `PATROL_STREAMS` 里既没有 `stream_id` 也没有 `query` 的流会被跳过（计入 `skipped`）；
- 三流全部没配置时，本轮记为 `skipped`，不会报错。

## 6.1 接真实 Graylog（原生 MCP）

### 服务端三步

1. **建只读账号 + API Token**：Graylog 里新建用户，只给读权限（能看 stream 与 message 即可，
   不要给删改告警的权限）；在该用户设置里生成 API Token，作为 MCP 鉴权凭证；
2. **打开开关**：`System → Configurations → MCP` → 勾选 `Enable MCP` 并保存，
   端点即为 `https://<graylog-host>/api/mcp`；
3. **记住权限语义**：MCP 调用完全继承该用户 RBAC，每次调用都会写 Graylog 审计日志，可溯源。

### 客户端这边已经适配的形态

| 项 | 实现 |
|---|---|
| 鉴权 | `Authorization: Token <token>`（`PATROL_MCP_AUTH=token`）；换平台可改 `bearer`/`basic`/`raw` |
| 传输 | 先走 Streamable HTTP；若 POST 被 404/405/406 拒绝，自动降级为旧版 HTTP+SSE（GET 拿 `endpoint` → POST，响应从事件流按 `id` 收回） |
| 工具 | `search_messages` 取日志；`list_streams` 取流清单；其它工具（`list_inputs`/`list_events`/`list_pipelines`）只在连通性弹窗里展示 |
| 参数 | 默认按 `inputSchema` 自动映射，Graylog 改参数名不用改代码 |
| 响应 | 兼容 `structuredContent`、`content[].text`（JSON 字符串）、JSON 与 SSE 两种传输体 |

### 页面上的「MCP 连通性」现在能看到什么

- 服务端名称/版本、协议版本、**实际使用的传输方式**、鉴权方式与 token 尾号（便于核对用错 token）；
- 可用工具清单；
- **Graylog 流清单**：直接列出 `stream id + 标题`，点 id 复制即可填进 `PATROL_STREAMS`，
  并按标题关键词（IPS/WAF/零信任）给出建议角色；
- **当前配置核对**：配置里的 `stream_id` 若在流清单中不存在，会标红提示「流不存在」——
  这是最容易被忽略的错配（改完 Graylog 流后忘了同步配置，`fetched` 会一直是 0）。

## 7. 接口与权限

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| POST | `/api/v1/patrols/run` | `inspection:run` | 立即跑一轮（同步返回候选） |
| GET | `/api/v1/patrols/latest` | `inspection:read` | 最近一轮含明细 |
| GET | `/api/v1/patrols` | `inspection:read` | 历史批次分页 |
| GET | `/api/v1/patrols/{id}` | `inspection:read` | 指定批次明细 |
| GET | `/api/v1/patrols/mcp/status` | `inspection:read` | MCP 连通性与工具清单 |

页面入口：左侧菜单 **日志巡检**（`/patrol`）。

## 8. 接真实 MCP 时先做这三件事

1. 点页面「MCP 连通性」——能列出工具名与流清单，才说明握手、鉴权、会话都正常；
2. 在流清单里对照 `PATROL_STREAMS`：`流不存在` 的红标会直接指出配错的那个；
3. 先用一个宽查询跑一次，看 `日志流状态` 里的 `fetched` 是否有数据；为 0 说明 `stream_id`/`query` 不对，
   或返回结构与 `extract_records` 的预期不符（把一条真实返回贴给我即可加别名）。

### 常见报错对照

| 现象 | 原因 | 处理 |
|---|---|---|
| `MCP HTTP 401 Unauthorized` | token 错、或用了 Bearer 前缀 | Graylog 只认 `Authorization: Token xxx`，确认 `PATROL_MCP_AUTH=token` |
| `MCP HTTP 404` | 端点写错，或 Graylog 没开 MCP 开关 | 端点是 `/api/mcp`（不是 `/api/mcp/` 或 `/mcp`），并确认 `Enable MCP` 已保存 |
| `MCP HTTP 403` | 该用户没有对应 stream 的读权限 | 给账号加 stream 读权限，或换只读管理员账号 |
| 传输显示 `sse` | 服务端只实现了旧版 SSE | 正常，客户端已自动降级；如长期使用可留意服务端升级 |
| `fetched` 一直为 0 | `stream_id` 配错 / 时间窗内确无日志 / 参数名不匹配 | 先点「MCP 连通性」看流清单，再用最长 6 小时的窗口验证 |
| `MCP 握手失败：protocolVersion` | 服务端协议版本更老 | 客户端已按 `2025-06-18 → 2024-11-05` 依次回退，仍失败请贴报错 |

返回值结构兼容：`messages` / `data` / `records` / `items` / `results` / `hits` / `documents`，
以及 Graylog 原生 `{"message": {...}}` 包装；也支持 JSON 字符串与 SSE 两种响应体。

## 9. 已知限制与下一步

| 项目 | 现状 | 计划 |
|---|---|---|
| 研判 | 仅确定性规则（L1） | P2 加 LLM 归并研判（只喂候选摘要，且校验返回 IP 必须在候选内） |
| 处置 | dry-run | P1 接 policy：置信度分级 + 配额 + 熔断 + 飞书通知 |
| 跨日累计 | 只看单窗口 | P2 引入 24h/7d 累计视角（对应 Graylog 设计文档 R5） |
| 规则反哺 | 未做 | P2 输出「漏封模式 → 建议的 Graylog 条件」周报 |
| 情报验证 | 只读日志里的情报标记 | P2 接微步 / netpolice 二次确认（带缓存，避免拖慢 5 分钟一次的节奏） |
