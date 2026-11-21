# LBA：零信任 7 层网关行为分析系统设计

> LBA = L7 Behavior Analysis。数据源：Graylog 上的零信任 7 层网关日志（username / src_ip / url / user_agent / method / status_code / app_id / gateway_node 等）。
> 上层能力：IP / 账号 / UA / 应用画像、风险策略引擎、风险事件、告警、日志溯源。
> **本文结论先行：LBA 不另起炉灶，作为 AegisSoc 的一个域（`lba`）集成，只新增一个 `lba-collector` 采集容器。**

---

## 0. 集成 vs 独立：为什么做成模块

独立方案（单独的 FastAPI + Vue3 + MySQL + Redis + 前端）会重复建设 AegisSoc 已有的东西：

| 能力 | 独立方案要重建 | AegisSoc 现状 | 结论 |
|---|---|---|---|
| Graylog MCP 客户端 | 要写一套 | 已有（巡检在用，含错误处理） | 复用 |
| MCP 地址 / Token / Stream 配置 | 要做配置页 | 已有 MCP 配置界面，ZTNA 流已映射 | 复用，零新配置 |
| 登录 / JWT / RBAC | 要做一套 | admin / operator / auditor 三角色 | 复用，加 `lba:*` 权限位 |
| 操作审计 | 要做一套 | 全链路审计已有 | 复用 |
| MySQL / Redis | 要部署两套 | 已有 | 复用，新增 4 张 `lba_` 表 |
| Vue3 前端骨架 | 要做一套 | 已有（含 i18n、菜单、路由守卫） | 复用，加菜单组 |
| 告警输出 | 要对接飞书 | 已有飞书 Webhook 卡片体系 | 复用 |
| 处置闭环 | 只能告警 | 黑名单 API + 6 级封禁规则 + 白名单优先 + 熔断 | **LBA 风险事件一键封禁——独立方案给不了的最大增益** |
| 部署 | 多一套 compose | install.sh / 升级文档齐全 | 只加一个 collector 容器 |

唯一值得独立出去的是**采集层**：采集节奏、并发、故障域都和业务引擎不同，未来 MCP 撑不住要换 Kafka 时只动采集层。所以最终形态是「**一个新容器 + 后端一个新域**」。

---

## 1. 整体架构

```
┌──────────────────────────────────────────────────────────────┐
│ AegisSoc 前端（复用）                                          │
│   行为分析大盘 · 风险事件 · 画像查询 · 风险策略 · 日志溯源       │
└──────────────────────────┬───────────────────────────────────┘
                           │ /api/v1/lba/*
┌──────────────────────────▼───────────────────────────────────┐
│ AegisSoc 后端（FastAPI，新增 lba 域）                          │
│   lba engine（事件消费·规则匹配·画像·窗口）                     │
│   lba api（事件/画像/策略/大盘）                                │
│   溯源转发（复用 MCP client，查原始日志）                        │
│   告警分发（复用飞书 Webhook）                                  │
│   一键封禁（复用 blacklist API / 6 级规则 / 白名单优先 / 熔断）   │
└─────────┬──────────────────────────────┬─────────────────────┘
          │                              │
┌─────────▼─────────┐          ┌─────────▼────────────────────┐
│ Redis（复用）       │          │ MySQL（复用，新增 4 张表）      │
│ lba:stream:event   │          │ lba_policy                    │
│ 滑动窗口/画像/去重  │          │ lba_risk_event                │
│ 检查点×3           │          │ lba_profile_snapshot          │
│                    │          │ lba_collect_state             │
└─────────┬─────────┘          └──────────────────────────────┘
          │ Redis Stream
┌─────────▼────────────────────────────────────────────────────┐
│ lba-collector（新增独立容器，asyncio 三协程）                   │
│   Task-1min   近实时检测（窗口 120s，重叠 60s）                 │
│   Task-5min   补偿+对账（窗口 10min，重叠 2min）                │
│   Task-30min  完整性兜底（窗口 60min，重叠 10min）              │
│   共用：MCP client · 标准化 · 全局 _id 去重 · 检查点 · sink      │
└─────────┬────────────────────────────────────────────────────┘
          │ MCP Protocol
┌─────────▼──────────┐
│ Graylog 7.1 MCP     │  stream = 零信任 7 层网关日志流（复用现有 ZTNA 映射）
└────────────────────┘
```

---

## 2. 采集层设计（lba-collector）

### 2.1 三个任务（采纳修订版方案，参数不变）

| 任务 | 周期 | 窗口 | 重叠 | limit | 职责 |
|---|---|---|---|---|---|
| Task-1min | 60s | 120s | 60s | 1000 | 近实时风险：账号高频访问、连续 401、异常 UA |
| Task-5min | 300s | 10min | 2min | 2000 | 补 1min 漏读；`aggregate_messages` 对账；5min 维度画像 |
| Task-30min | 1800s | 60min | 10min | 3000 | 完整性兜底；长缺口补拉；长周期统计 |

- 重叠窗口防分页漂移丢数；重复日志靠全局 `_id` 去重丢弃，不会重复进引擎
- 三个任务**独立检查点**：`lba:graylog:mcp:checkpoint:task_{1min,5min,30min}`
- 全局去重：Redis Set `lba:collector:dedup:msg_id`，TTL 90min（覆盖最长窗口，防内存膨胀）
- 5min / 30min 任务先 `aggregate_messages` 取窗口总数，与实拉数比对，差值超阈值记 `count_gap` 并触发补偿——这是解决 MCP 分页黑盒丢数的核心手段

### 2.2 与 AegisSoc 的衔接点

| 项 | 做法 |
|---|---|
| MCP 地址 / Token | **复用现有 MCP 配置**（`system_setting` 里那套），collector 启动时从后端拉取，MCP 配置页改了能感知（轮询或改配置时后端写一个版本号，collector 比对版本热更新） |
| Stream | 复用现有 ZTNA 流映射；字段清单以 `list_fields` 实测为准，配置文件里做映射表 |
| 投递 | Redis Stream `lba:stream:event`，MAXLEN 上限（如 100 万条）防内存失控 |
| 部署 | 新容器 `aegis-soc-lba-collector`，compose 里独立 service，4vCPU/8G |
| 未来换 Kafka | 只改 collector 的 sink，上游引擎不动 |

### 2.3 标准化事件结构

```json
{
  "event_id": "uuid",
  "source": "graylog_zero_trust",
  "graylog_msg_id": "_id 原值",
  "timestamp": 1763891234000,
  "username": "zhangsan | null（匿名保留空值，可做策略）",
  "src_ip": "10.1.2.3",
  "user_agent": "Mozilla/xxx | null",
  "url": "/internal/api/user",
  "method": "GET",
  "status_code": 200,
  "request_length": 120,
  "response_length": 1450,
  "app_id": "app-finance",
  "gateway_node": "zt-gw-01",
  "collect_task": "1min",
  "ext_fields": {}
}
```

规则：字段缺失置 `null` 不丢整批（计数 `field_missing_total`）；`status_code` 转数字；时间戳统一毫秒。

---

## 3. 风险引擎（后端 lba 域）

### 3.1 消费与匹配流程

```
消费 lba:stream:event
  → 提取实体（src_ip / username / user_agent / app_id）
  → 更新 Redis 滑动窗口（1min/5min/15min）与实时画像（Hash + TTL）
  → 遍历 lba:policy:cache 中启用策略，JSON 条件匹配
  → 命中 → 写 lba_risk_event → 告警去重（lba:alert:dedup）→ 飞书推送
```

一期只做 JSON 条件表达式规则引擎（确定性、可测试、运营可控），不接模型；AI 研判放二期，走 AegisSoc 现有插件接口。

### 3.2 零信任网关专属策略维度

- `username` 为空（匿名访问内部应用）
- `status_code IN (401,403)` 频次 > N / 1min
- 同一 `src_ip` 短时间访问多个不同 `app_id`
- `user_agent` 为空 / 爬虫 UA 访问核心应用
- 单 `gateway_node` 异常请求量

内置 4 条模板策略（启用即可用）：
1. 匿名账号访问内部应用
2. 同一账号 1 分钟内连续 5 次 401
3. 陌生 IP 短时间批量访问多个内部应用
4. 异常爬虫 UA 访问核心应用

### 3.3 与现有 SOAR 能力的联动（本方案核心增益）

`lba_risk_event` 详情页提供**一键封禁**：调用现有黑名单 API，自动走白名单优先、内网/保留地址保护、IOC 类型与设备能力匹配、全局熔断、6 级封禁规则、任务审计——LBA 发现的异常行为源可以直接落地成封禁动作，形成「发现 → 处置」闭环。封禁动作写现有审计，LBA 侧不重复记录。

---

## 4. 数据模型（MySQL 新增 4 张表）

```
lba_policy
  id, name, desc, status, priority, condition_json, risk_level, tag,
  action(仅记录/告警/推送SOC), create_time, update_time

lba_risk_event
  id, event_id, graylog_msg_id, src_ip, username, user_agent, url,
  method, status_code, app_id, gateway_node,
  risk_policy_id, risk_level, risk_tag, raw_fields_json,
  occur_time, status(未处置/已忽略/已处置), handle_user, handle_comment,
  block_task_id(一键封禁生成的黑名单任务ID，可空)

lba_device
  id, device_key, owner_username, ua_raw, ua_normalized,
  device_type(pc/mobile/tablet/unknown), managed(managed/unmanaged/unknown),
  first_seen, last_seen
  -- device_key 生成优先级：网关设备指纹字段 > sha1(username + ua_normalized)
  -- managed 来源：零信任平台受管设备标记（日志字段或受管清单接口），拿不到置 unknown

lba_device_ip
  id, device_key, ip, country, city, asn, asn_org,
  first_seen, last_seen
  -- IP→(国家/城市) 走 ip2region；ASN 走 GeoLite2-ASN 离线库（见 11.2）

lba_profile_snapshot
  id, entity_type(ip/username/ua/device/app_id), entity_value,
  stats_json(请求数、URL集合、终端分布、响应码分布、应用分布、最近访问),
  snapshot_time

lba_collect_state
  task(1min/5min/30min), last_window_end_ts, last_msg_id,
  last_run_success, last_run_time, fetched, dedup_hit, count_gap
  （检查点的 MySQL 镜像，页面展示采集状态用；运行时以 Redis 为准）
```

复用表：`system_user`（账号）、`audit_log`（操作审计）、MCP 配置（`system_setting`）。

### Redis 键规划（`lba:` 前缀与现有键隔离）

| 键 | 结构 | 说明 |
|---|---|---|
| `lba:stream:event` | Stream | collector 投递，engine 消费，MAXLEN 限幅 |
| `lba:profile:{type}:{key}` | Hash + TTL | 实时画像 |
| `lba:window:{w}:{entity}` | 计数器 | 1min/5min/15min 滑动窗口 |
| `lba:policy:cache` | Hash | 启用策略缓存，热更新 |
| `lba:collector:dedup:msg_id` | Set + TTL 90min | 全局 `_id` 去重 |
| `lba:alert:dedup` | Set + TTL | 告警去重（同 IP+同策略静默期内不重复轰炸） |
| `lba:graylog:mcp:checkpoint:task_*` | String(JSON) | 三任务独立检查点 |

---

## 5. 接口清单（挂在 `/api/v1/lba/*`，即前端 mock 的契约依据）

> 前端先行开发时，本节接口的**响应结构要先行定死**（字段名、分页结构 `{items,total,page,page_size}`、枚举值英 code），mock 按契约造数，后端按契约实现——切真实接口前端零改动。

| 模块 | 接口 |
|---|---|
| 大盘 | `GET /lba/dashboard/overview`（总量、等级分布、时序）；`GET /lba/dashboard/top`（TOP IP/账号/UA/应用/401 来源） |
| 登录行为中心 | `GET /lba/login/overview`（4 KPI：今日活跃用户 / 识别设备数 / 待核查异常用户 / 高风险用户）；`GET /lba/login/anomaly-users`（用户异常行为列表：用户、设备台数与类型、IP 变化摘要、当前风险） |
| 用户详情 | `GET /lba/profile/user/{username}`：24h 访问时间线、设备列表（每台：UA、类型、受管标记、关联 IP 含国家/城市/ASN、最近活跃）、风险变化历史（时间点 + 等级变化 + 触发原因=命中策略与条件值快照） |
| 风险事件 | `GET /lba/event/list`（分页多条件）；`GET /lba/event/{id}`；`PUT /lba/event/{id}/handle`；`POST /lba/event/export`；`POST /lba/event/{id}/block`（一键封禁，走黑名单 API） |
| 策略 | `GET/POST/PUT/DELETE /lba/policy`；`POST /lba/policy/test`（模拟事件测命中）；`POST /lba/policy/{id}/toggle` |
| 画像 | `GET /lba/profile/{type}/{value}`；`GET /lba/profile/search` |
| 溯源 | `POST /lba/trace/search`（后端转发 MCP `search_messages`，支持按 username/app_id/网关节点/响应码筛） |
| 采集状态 | `GET /lba/collect/status`（三任务独立状态：上次执行、成功/失败、拉取条数、对账差值） |
| 配置 | `GET/PUT /lba/settings`（SOC webhook、告警开关、静默期、保留天数） |

权限位：`lba:read`（auditor 可）、`lba:handle`（operator）、`lba:policy:*`（operator）、`lba:settings`（admin）。封禁动作额外要求现有封禁权限。

---

## 6. 前端页面（在现有 AegisSoc 前端加菜单组「行为分析」）

| 页面 | 内容 |
|---|---|
| **登录行为分析中心**（用户/设备维度看板，新需求） | 4 张 KPI 卡：**今日活跃用户**（24h distinct username）、**识别设备数量**（库内累计 device 数）、**待核查异常用户**（存在未处置中/高风险事件的用户数）、**高风险用户**（当前风险等级为高的用户数）；下方**用户异常行为列表**：用户 / 设备（台数+类型，如「2台设备」「1台手机」）/ IP 变化（如「3个IP」「2个国家」「2个城市」）/ 风险等级；行点击进入用户详情页；支持按风险等级、时间范围筛选 |
| **用户详情页**（从登录行为中心/事件/画像均可跳转） | ① **最近 24h 访问时间线**（时间、应用、URL、方法、响应码、当时 IP）；② **设备卡片列表**：每台设备的 UA 原文、设备类型（PC/手机/平板）、**是否企业受管设备**（managed/unmanaged/unknown）、关联过的 IP（每 IP 标注国家、城市、ASN/运营商、最近活跃）、设备最近一次活跃时间；③ **风险变化历史**：风险等级升降时间点 + 触发原因（命中策略名 + 条件命中值快照，如「1min 内 401×7」）；④ 快捷动作：按该用户任一 IP 一键封禁、跳转该用户风险事件列表 |
| 行为分析大盘 | 卡片（今日接入量、风险事件数、高风险数、待处置）+ 事件时序 + 等级/标签饼图 + TOP 排行（IP/账号/UA/应用/401 来源）+ 待处置列表快捷处置 |
| 风险事件 | 多条件筛选（时间/等级/IP/账号/UA/策略/状态/应用）；表格含 method、status_code、app_id、gateway_node；详情弹窗含命中策略说明、**一键溯源**、画像快捷跳转、**一键封禁** |
| 画像查询 | 实体类型：IP / 用户名 / UA / **应用** / **设备**；画像卡片：访问统计、终端分布、响应码分布、访问应用/URL 列表、历史命中、趋势 |
| 风险策略 | 列表 + 表单；**ConditionBuilder 可视化条件构建器**（字段下拉为零信任网关字段，运算符 + 窗口选择，产出 condition_json，不手写 JSON）；策略测试工具；启停 |
| 日志溯源 | 轻量 Graylog 检索面板（时间/Stream/查询语句/字段/分页），底层转发 MCP；运营不用切 Graylog 页面 |
| 采集状态 | 三个任务卡片：上次执行时间、成功/失败、拉取条数、去重命中、对账差值、缺口补偿记录 |

配套：全局右下角通知（一期轮询，二期 WebSocket）、Excel 导出、按钮级权限（auditor 无处置/编辑按钮）。**所有新页面文案走语言包（`lba.*` 命名空间，zh-CN/en-US 双侧同步）**，沿用刚落地的 i18n 体系与 `pick()` 未知值兜底约定。

---

## 7. 监控指标（Prometheus，`task` 标签隔离）

| 指标 | 说明 |
|---|---|
| `lba_collector_fetch_total{task}` | 拉取总条数 |
| `lba_collector_dup_total{task}` | 去重丢弃条数 |
| `lba_collector_mcp_error_total{task}` | MCP 调用失败 |
| `lba_collector_mcp_duration_seconds{task}` | MCP 查询耗时 |
| `lba_collector_count_gap{task}` | 对账差值（aggregate − 实拉），**核心告警指标** |
| `lba_collector_field_missing_total{task,field}` | 字段缺失 |
| `lba_engine_consume_tps` / `lba_engine_policy_hit_total` | 引擎吞吐与命中 |
| `lba_pending_high_risk_events` | 待处置高风险数（业务告警） |

告警规则：task_1min 连续 2 次 MCP 失败；task_5min `count_gap > 200`；task_30min 超过 2 个周期未运行。

---

## 8. 与现有日志巡检（Patrol）的边界

两者都读零信任/三流日志，必须划清边界避免重复建设：

| | 日志巡检 Patrol（已有） | LBA（本设计） |
|---|---|---|
| 问题域 | Graylog 规则**漏报的攻击源**（IPS 未阻断、WAF 放行等） | **行为画像与异常行为**（频次、匿名、异常 UA、跨应用扫描） |
| 维度 | 以 IP / 告警为主 | 账号 / IP / UA / 应用多维 |
| 输出 | 巡检报告 + 飞书卡片（dry-run） | 风险事件 + 处置 + 一键封禁 |
| 数据处理 | 每 5 分钟批量拉取分析，不留行为状态 | 持续消费事件流，维护滑动窗口与画像 |
| 关系 | Patrol 的结论（漏封 IP）可以作为 LBA 的富化输入 | LBA 的高风险 IP 走一键封禁进入现有黑名单流程 |

---

## 9. 开发路径与里程碑

### 9.0 开发路径：前端先行（UI 驱动，mock 数据）

**结论：前端先做、collector 不急。** 理由：

1. **ConditionBuilder 是全项目风险最高的组件**——策略条件的字段、运算符、窗口交互必须先在真实界面上定下来，`condition_json` 的 schema 由它反推，而不是先定 schema 再憋 UI
2. **LBA 是新需求，需求未定型**——事件详情放什么字段、画像卡片长什么样，先出界面快速试错；改界面的成本远低于改已入库的表
3. **collector 天然要等**——真实零信任日志字段靠 `list_fields` 实测，还要碰生产 Graylog；不能让它阻塞前端

两条护栏（否则 mock 会变成第二套真相）：

- **先冻结 API 契约，再写页面**：响应结构（字段名、分页结构、枚举值）按第 5 节接口清单定死成文档，mock 只是契约的一个实现；切真实接口时前端一行不改
- **mock 收在 api 层一个开关里**：`VITE_LBA_MOCK=true` 时 `src/api/lba.js` 返回本地 mock 数据（含分页、筛选、时间序列的仿真生成），组件里不出现任何 if(mock)；开关一关即接真后端

页面开发顺序（按价值排序，用户已确认前端先行）：

1. **登录行为分析中心 + 用户详情页**——用户/设备/IP 三维看板是 LBA 的门面，先定「设备」「IP 变化」等关键口径
2. **风险事件列表 + 详情**（含溯源弹窗、一键封禁按钮、处置流程）
3. **风险策略 + ConditionBuilder**——schema 定型就锁死后端表设计
4. **行为分析大盘**——依赖事件数据结构，最后做刚好
5. 画像查询、采集状态页——结构简单，随手补

### Phase 1：最小可用（前端先行 → 后端按契约实现 → collector 收尾）

- **1a 前端先行（mock）**：API 契约文档 → 风险事件 + ConditionBuilder + 策略页 → 大盘 → 画像/采集状态；全部零信任语义 + `lba.*` i18n；走通 mock 下完整交互（筛选/处置/测策略/封禁按钮）
- **1b 后端按契约实现**：4 张表迁移脚本、`/api/v1/lba/*` 接口、简单规则引擎（先支持 401 连发、匿名访问两类）、消费 `lba:stream:event`（此时可先用脚本灌模拟事件验证引擎）
- **1c collector 接真**：`list_fields` 实测字段映射 → 三任务调度、独立检查点、全局 `_id` 去重、对账补偿 → 真实零信任日志跑一周，验证 1min 低延迟告警、5min 兜底、30min 对账补数

### Phase 2：运营闭环
1. 策略 CRUD + ConditionBuilder + 策略测试
2. 画像查询 + 快照落盘 + TOP 统计
3. 一键封禁联动、告警去重调优、RBAC 权限位
4. Excel 导出、全局通知（轮询版）

### Phase 3：压测与架构演进
1. 日千万级压测：验证 MCP 在三任务并发下的吞吐上限
   - 达标 → 加固采集链路 + 监控告警
   - 不达标 → collector sink 换 Kafka，上游零改动（这正是 collector 独立成容器的意义）
2. WebSocket 实时告警、批量处置、大屏视图
3. Grafana 大盘全量接入

---

## 10. 风险与取舍

1. **MCP 是实验接口**：所有 MCP 返回做结构校验，Schema 变动直接告警不静默；溯源功能在 MCP 故障时降级提示，不影响风险主链路（事件流是 collector 缓冲的）
2. **滑动窗口只放 Redis 不持久化**：重启丢失窗口统计属可接受降级，画像快照在 MySQL 有底
3. **一期不做图计算 / 机器学习**，只做规则引擎；AI 研判二期走 AegisSoc 插件接口
4. **Graylog 资源保护**：collector 控制并发与查询频率，错峰执行 30min 任务；对账优先用 `aggregate_messages` 计数而非全量拉取
5. **事件流的可靠性**：Redis Stream 有 MAXLEN 限幅 + consumer group ACK，引擎挂掉重启从上次 ACK 继续，不丢事件
6. **字段映射以实测为准**：零信任网关日志真实字段名以 `list_fields` 为准，collector 配置里做显式映射表，不做隐式猜测

---

## 11. 待确认的数据源问题（决定界面能不能落地，需先对齐）

### 11.1 设备身份从哪来（影响「识别设备数量」「每台设备」整套能力）

零信任网关日志的标准字段里没有设备指纹，三个方案按优先级：

| 方案 | device_key 来源 | 受管设备标记 | 前提 |
|---|---|---|---|
| A（最优） | 网关日志自带 `device_id` / 主机名 / 零信任客户端上报字段 | 日志自带 `device_managed` 字段 | **需实测 `list_fields` 确认网关日志有这些字段** |
| B | 零信任平台管理接口拉受管设备清单，与日志 username 关联 | 清单自带 | 平台有 API 且授权可行 |
| C（兜底） | `sha1(username + UA 规范化)` 近似设备——同 UA 视为同设备 | 全部 `unknown` | 会把「同人换浏览器」误判成多设备，看板口径要标注为「终端指纹（近似）」 |

**结论：先拿一条真实网关日志做 `list_fields` 实测再定**；界面先用 C 的口径开发 mock，字段一确认即切 A。

### 11.2 ASN 数据源

ip2region 只有国家/省市/运营商（ISP），**没有 ASN**。两个选择：

| 方案 | 成本 | 效果 |
|---|---|---|
| A（推荐） | MaxMind GeoLite2-ASN 离线库（免费、mmdb 约 6MB、每周更新），接入方式复用现有 geoip 离线加载机制 | 真正的 ASN + 组织名（如 AS4134 Chinanet） |
| B | 用 ip2region 的 ISP 字段近似展示为「运营商」 | 零成本，但没有 ASN 号 |

界面列名可做成兼容的：有 ASN 库显示「ASN」，没有就显示「运营商」。

### 11.3 「IP 变化」的口径

示例里出现「3个IP」「2个国家」「2个城市」三种写法，建议统一口径：**统计窗口默认 7 天**（可调），显示 `N个IP / M个国家`，城市只在同国家多城市时展开——避免口径不一致导致运营看不懂数字怎么来的。
