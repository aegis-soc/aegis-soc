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
PATROL_MCP_URL=http://graylog-mcp:9100/mcp
PATROL_MCP_TOKEN=                      # 可选，Bearer Token
PATROL_MCP_TOOL=search_messages        # MCP 工具名
PATROL_MCP_ARGS={"stream_id":"${stream_id}","query":"${query}","from":"${from}","to":"${to}","limit":${limit}}
PATROL_STREAMS=[{"name":"IPS","label":"IPS","stream_id":"<graylog-stream-id>","query":"action:alert"}, ...]
PATROL_MAX_RECORDS=2000
PATROL_MCP_TIMEOUT=30
PATROL_REPEAT_HOURS=24
```

- `${limit}` 按数字替换，其余占位符按字符串替换，因此模板里的字符串占位符**必须自带引号**；
- `PATROL_STREAMS` 里既没有 `stream_id` 也没有 `query` 的流会被跳过（计入 `skipped`）；
- 三流全部没配置时，本轮记为 `skipped`，不会报错。

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

1. 点页面「MCP 连通性」——能列出工具名才说明握手与会话正常；
2. 确认 `PATROL_MCP_TOOL` 与 `PATROL_MCP_ARGS` 的参数名一致（不同实现的工具签名不一样）；
3. 先用一个宽查询跑一次，看 `日志流状态` 里的 `fetched` 是否有数据；为 0 说明 `stream_id` 或 `query` 不对，或返回结构与 `extract_records` 的预期不符。

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
