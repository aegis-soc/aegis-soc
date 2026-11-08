# 人机对话（自然语言查询）

用中文提问，自动判断该查**平台数据**还是**Graylog 日志**，给出结论、明细与编译后的查询。
只读、可审计、不依赖大模型。

```
"分析黑名单中来源 top10 和 top 国家、按时间分布"
  → 黑名单按来源 / 国家 / 天三个维度各出一张表 + 结论

"最近 3 天各设备有未拦截的 IP 日志告警"
  → 走 Graylog MCP 读三流日志，按源 IP 聚合，标出哪些已在黑名单、哪些是内网
```

## 为什么不直接用 text2SQL

| 方案 | 问题 |
|---|---|
| 大模型直接生成并执行 SQL | 可扫全表、可读 `system_user` 口令、不可解释、方言差异 |
| 大模型自由生成 Graylog 查询 | 可绕开三流限制、无时间窗约束、字段名猜错时静默返回 0 条 |
| **本方案：模型只出 DSL，代码编译** | 只能落到枚举范围，非法值直接拒绝，可测试、可审计 |

当前版本连 DSL 都由**规则**产出（不需要模型接口），所以离线可用、结果稳定。
接了大模型之后，模型只是多一条产出 DSL 的路径，白名单与编译逻辑不变。

## 三层结构

| 层 | 文件 | 职责 | 是否可执行 SQL |
|---|---|---|---|
| 语义层 | `services/chat/catalog.py` | 数据源 / 维度 / 指标 / 词表 / 排除表 | 否 |
| 路由层 | `services/chat/router_intent.py` | 中文问句 → `Intent`（DSL） | 否 |
| 编译层 | `services/chat/compiler_db.py`、`compiler_log.py` | DSL → SQLAlchemy 查询 / MCP 检索 | 是（仅 SELECT） |
| 叙述层 | `services/chat/narrative.py` | 结果 → 中文结论（模板 + 阈值判断） | 否 |
| 编排 | `services/chat/pipeline.py` | 限流、调度、组块、trace | 否 |

`dsl.py` 是路由与编译之间唯一的契约：`DbItem` / `LogSpec` 用 Pydantic 校验，
维度、指标、过滤项都必须在 `catalog` 里存在，否则在校验阶段就被拒。

## DSL 示例

```json
// 库：黑名单按来源 Top10
{"route": "db", "items": [
  {"source": "ioc", "metric": "count", "group_by": "source_type",
   "filters": {"status": ["active"], "ioc_type": ["IP"]},
   "time": {"last_days": 7, "bucket": "day"}, "limit": 10, "order": "desc"}
]}

// 日志：近 3 天未拦截的 IP
{"route": "log", "log": {
  "streams": ["IPS", "WAF", "ZTNA"], "time": {"last_days": 3},
  "action": "pass", "severity_min": 0, "group_by": "src_ip", "limit": 50
}}
```

`bucket` 由编译器按跨度决定（≤2 天按小时，否则按天），模型/用户不需要指定。

## 语义目录（P0）

| 数据源 | 表 | 维度 | 指标 |
|---|---|---|---|
| 黑名单 | `ioc_indicator` | 来源、国家、省份、城市、指标类型、状态、风险等级、指标值、时间桶 | 数量、去重值数、平均置信度 |
| 告警 | `alert_event` | 来源系统、严重级别、状态、去重键、时间桶 | 数量、去重值数 |
| 封禁下发 | `device_task` | 设备、任务状态、插件、操作、指标类型、时间桶 | 数量、去重值数 |
| 设备 | `security_device` | 厂商、状态、区域、插件、时间桶 | 数量 |
| 三流日志 | Graylog | 源 IP、规则、日志流 | 记录数 |

**永不作为数据源**：`system_user`、`system_role`、`patrol_setting`、`operation_audit`、
`approval_record`、`workflow_definition`（口令、Token、审计详情）。

## 护栏

| 护栏 | 实现 |
|---|---|
| 只读 | 编译器只生成 `SELECT`；测试断言 SQL 以 `SELECT` 开头且不含 DML 关键字 |
| 白名单 | 表/维度/指标/过滤项取自 `catalog`；未知值抛 `ValidationError` |
| 绑定参数 | 过滤值走 `in_` / `==` / `like` 参数位，无字符串拼接 |
| 上限 | `LIMIT ≤ 200`、子查询 ≤ 3、日志时间窗 ≤ 7 天、MySQL 尝试 `MAX_EXECUTION_TIME=10s` |
| 敏感字段 | 见上「永不作为数据源」 |
| 限流 | 单用户 20 次/分钟（`aegis:chat:rl:*`，内存/Redis 均可） |
| 审计 | 每次提问写 `CHAT_ASK`：问题原文、路由、置信度、查询数、耗时 |
| 答不上就明说 | 映射不到返回 `clarify` + 推荐问法，不猜数据 |

## 已覆盖问法（回归用例即 12 条）

| 问法 | 路由 | 结果 |
|---|---|---|
| 分析黑名单中来源 top10 和 top 国家、top 时间 | db | 来源 / 国家 / 天 三张表 |
| 最近 3 天各设备有未拦截的 IP 日志告警 | log | 三流 + `action=pass` + 按源 IP |
| 近 7 天 WAF 拦截了多少条 | log | 单流 WAF + `action=block` |
| 黑名单 top 国家分布 / 各省份黑名单数量 | db | `geo_country` / `geo_province` |
| 近 7 天封禁趋势 | db | 时间桶 + 环比 |
| 下发失败的任务有多少 | db | `task_status=FAILED` 计数 |
| 哪个设备封禁量最大 | db | 按设备分组，取第 1 名 |
| 高风险 IP 有多少 | db | `risk_level=high` 计数（不分组） |
| 帮我看看 / 明天天气 | clarify | 引导问法，不编数据 |

## 扩展一种问法

1. 只是新词：往 `router_intent.py` 的 `DIM_WORDS` / `SOURCE_WORDS` / 时间表里加词条；
2. 新维度或新表：改 `catalog.SOURCES`（模型属性名只出现在这里），
   `compiler_db` 自动按白名单映射，不需要写 SQL；
3. 加完把问句补进 `tests/test_chat.py` 的 `ROUTE_CASES`，跑一次 pytest 即可。

## 接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/v1/chat/ask` | `{question, session_id?}` → `answer / blocks / trace / suggestions` |
| GET | `/api/v1/chat/sessions` | 我的会话列表（最多 50） |
| GET | `/api/v1/chat/sessions/{id}` | 会话消息（刷新/换设备可续） |
| DELETE | `/api/v1/chat/sessions/{id}` | 删除会话 |
| GET | `/api/v1/chat/catalog` | 能力清单 + 推荐问法 |

权限 `chat:ask`（operator / auditor 默认具备，只读）。消息落 `chat_session` / `chat_message`：
`blocks` 存渲染块，`dsl` 存当次解析结果——复盘"为什么这么答"靠它。

## 渲染块协议

前端只实现四种块，后端新增问法不用改前端：

```json
{"type": "kpi",   "items": [{"label": "黑名单总数", "value": 19}]}
{"type": "table", "columns": [{"key": "label", "label": "国家"}], "rows": [{"label": "美国", "value": 10}]}
{"type": "bar",   "categories": ["美国", "巴西"], "values": [10, 3]}
{"type": "note",  "lines": ["未指定时间范围，按近 7 天统计"]}
```

`trace` 里带编译后的 SQL 或 MCP 检索说明（流、时间窗、扫描条数），页面折叠展示，
让人能自己判断结论可不可信。

## 口径约定

- **黑名单默认只看 `status=active`**：把已到期/已解封混进 Top 榜没有意义；
- **时间窗未指定时默认 7 天，并写进 `assumptions`** 在结论下方明示；
- **日志检索在内存里过滤**：三流字段名差异大（`action`/`act`/`disposition`），
  拼错字段 Graylog 不报错、只静默返回 0 条，比查错更难发现；所以按单流上限抓取后本地归一，
  并在结果里如实标注"扫描了 N 条"；
- **内网/保留地址不计入漏封**：内部扫描与健康检查本来就会出现在放行日志里，与巡检同口径；
- **当天/当时段数据未走完不计入环比**，避免得出"断崖下跌"的假结论。

## 排错顺序

1. 结论里出现"没听懂"→ 看 `trace.matched`，说明词表没命中，补词条；
2. 查库有结果但数字为 0 → 看 `trace.queries[0].sql` 里的时间窗与过滤条件；
3. 日志路径报 "Graylog MCP 未就绪" → 去「日志巡检 → MCP 配置」看地址/Token；
4. 日志扫描到但命中 0 条 → 先换成"全部动作"再问一次，区分"真没有"与"字段口径不匹配"。
