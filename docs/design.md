# AegisSoc（宙斯盾）系统设计文档

> 版本：v1.2 文档基线 ｜ 更新日期：2026-11-28 ｜ 配套用户手册见 `docs/user-manual.md`
>
> 本文档描述系统的整体架构、核心流程、数据模型与设计取舍。接口字段级细节见 `docs/api.md` 与各专项文档（§12 文档索引）。

---

## 1. 系统定位

AegisSoc 是一个**通用安全运营自动化 AI+SOC 平台**：不改造 Graylog，接收其告警，统一管理 IOC（失陷指标），通过插件化设备网关向 WAF / 防火墙 / IPS 下发封禁与解封，并叠加 AI 巡检、Graylog 日志巡检、登录行为分析（LBA）与人机对话四类运营能力。

### 1.1 职责边界（与 Graylog 的分工）

| 系统 | 负责 |
|---|---|
| **Graylog** | 日志采集、检索、分析、告警判定（产生 Event 并回调本平台） |
| **AegisSoc** | IOC 管理、策略编排、设备 API 联动、任务与审批、审计、巡检与行为分析 |

平台**不重复做日志采集与存储**——日志类能力全部通过 Graylog MCP 接口按需拉取（只读），聚合结果落本地 MySQL。

### 1.2 核心设计原则

1. **无侵入接入**：Graylog 只需配置一个 Alert Webhook 指向本平台，不需要装任何 Agent。
2. **白名单优先**：任何封禁动作前先过白名单检查（CIDR 级），内网/保留地址永不封禁。
3. **人机协同**：默认 dry-run / 需审批模式，AI 只提建议，下发动作始终可追溯、可撤销、可熔断。
4. **插件化设备接入**：新接一种安全设备 = 增加一个插件类，平台主体零改动。
5. **全链路审计**：所有写操作落 `operation_audit`，凭据永不入审计与日志。
6. **规则确定性优先**：巡检/对话/行为分析全部用确定性规则引擎，不依赖大模型（LLM 仅作可选的总结增强，失败自动回退）。

---

## 2. 总体架构

### 2.1 组件拓扑（docker compose 7 容器）

```
                    ┌──────────────────────────────────────────────┐
                    │                 宿主机 / WSL                  │
                    │                                              │
 Graylog ──Webhook──▶  nginx(:8080) ──▶ frontend (Vue3 静态资源)    │
 (IPS/WAF/零信任)    │      │                                        │
                    │      └─/api─▶ api (FastAPI, :8000) ─┐          │
 ElastAlert/Suricata│                                     │          │
 等通用告警 ─────────▶                                     ▼          │
                    │              ┌────── MySQL 8 (29 张表)        │
                    │              ├────── Redis 7 (队列/缓存/锁)    │
                    │              └────── worker (Celery, 并发 4)   │
 Graylog ──MCP──▶ [巡检/LBA/对话取数，只读]        └── beat (定时调度) │
                    └──────────────────────────────────────────────┘
```

| 服务 | 职责 |
|---|---|
| nginx | 统一入口（默认 8080），反代前端静态资源与 `/api` |
| api | FastAPI 应用（2 workers），REST 接口 + 告警接收 + MCP 客户端 |
| worker | Celery worker（队列 `aegis`），任务下发/到期解封/补偿/巡检/LBA 采集 |
| beat | Celery beat，定时调度（见 §7） |
| mysql | 业务库（utf8mb4），`sql/init.sql` 首次初始化 |
| redis | Celery broker、结果后端、告警去重、限流、幂等锁、LBA 结果缓存 |
| frontend | Vue3 构建产物（Nginx 镜像） |

另有 `docker-compose.2g.yml` 低内存裁剪档（≤2.5GB 环境）。

### 2.2 核心数据流

```
① 告警封禁链路（实时）
Graylog/ElastAlert ──▶ POST /alerts/* ──▶ engines/policy.py 处置引擎
  去重 → 熔断检查 → 白名单优先 → 校验 → 策略匹配(阈值) → IOC 入库
  → 设备能力匹配 → 幂等任务(device_task) → 异步派发(worker) → 插件 → 设备
  → 全链路审计

② 日志巡检链路（定时只读）
beat(60s 唤醒) ──▶ run_patrol ──▶ 按配置间隔真跑 ──▶ mcp_client 拉三流日志
  ──▶ 字段归一(field_mapping→value_mapping→内置别名) ──▶ L1 规则聚合(11 条)
  ──▶ 闸门预判(白名单>已封>重复>would_block) ──▶ PatrolRun/Candidate 落库

③ LBA 行为分析链路（定时预聚合 + 页面秒开）
beat(每 5 分钟) ──▶ run_lba_collect ──▶ 水位增量(重叠 2min+事件键去重)
  ──▶ lba_user_hourly 小时桶合并 ──▶ 页面读本地表(store)；采集器不健康时
  回落实时聚合(live)，window_desc.source 标明来源

④ AI 巡检链路（每天 08:30）
beat ──▶ run_inspection ──▶ 12 检查项只读体检 ──▶ 加权健康分
  ──▶ (可选)LLM 总结(失败回退规则总结) ──▶ inspection_report 落库

⑤ 人机对话链路（同步）
POST /chat/ask ──▶ 规则意图路由 ──▶ DSL(护栏校验) ──▶ 编译
  ├─ 库数据 ─▶ SQLAlchemy SQL(强制 LIMIT/时间必选)
  └─ 日志数据 ─▶ Graylog MCP 检索(口径与巡检完全共用)
  ──▶ 模板结论 ──▶ answer+blocks+trace 落库
```

---

## 3. 技术选型（拍板记录）

| 层 | 选型 | 理由摘要 |
|---|---|---|
| 后端 | FastAPI + Python 3.12 | 原生 async 适合告警吞吐；Pydantic 做契约 |
| ORM | SQLAlchemy 2.0 (Mapped 风格) | 逻辑外键（不建物理 FK），便于分表演进 |
| 任务 | Celery + Redis | 成熟稳定；指数退避重试；beat 定时 |
| 前端 | Vue3 + Element Plus + vue-i18n | 中英文双语，枚举存英文 code 仅显示层翻译 |
| 库 | MySQL 8 (utf8mb4) | 运维熟悉；JSON 列存明细快照 |
| 归属地 | ip2region 离线 xdb | 纯离线、可降级、按 mtime 热加载 |

完整选型论证见 `docs/architecture-baseline.md`。

---

## 4. 核心业务流程设计

### 4.1 告警接入与自动封禁

**两个入口**：

| 入口 | 路径 | 鉴权 | 适用 |
|---|---|---|---|
| Graylog Event Webhook | `POST /alerts/graylog` | Secret + 可选 Bearer + 时间戳防重放（容差 300s）+ 来源 IP 白名单 | Graylog Event Definition |
| 通用告警 | `POST /alerts/generic` | 同上 | ElastAlert / Suricata 等任意系统 |

**处置引擎**（`app/engines/policy.py`）按固定管线执行：

```
告警去重(TTL 3600s) → 全局熔断检查 → 白名单优先(命中直接拒封)
→ IOC 校验(格式/去重) → 策略匹配(按 priority)
→ 阈值判断(threshold_count × window_minutes × min_confidence)
→ IOC 入库(ioc_indicator 流水) → 设备能力匹配(capability=BLOCK)
→ 幂等任务生成(同 ioc+device+operation+request_id 唯一)
→ 异步派发(celery) → 插件执行 → 结果留痕(device_task_log) → 审计
```

关键约束：
- 单告警封禁上限 `MAX_BLOCK_PER_ALERT=20`（防告警风暴打爆设备）；
- 任务失败按 `60s×2^n` 指数退避重试，最多 3 次；broker 抖动漏投递由补偿扫描每 2 分钟兜底；
- IOC 到期自动生成解封任务（beat 每分钟扫）；
- 删除黑名单记录自动联动解封同值兄弟记录。

### 4.2 IOC 生命周期

`ioc_indicator` 是**流水表**——同一 IP 被封多次不合并记录，每次都是独立一行（可追溯每次告警来源、每次解封原因）。状态机：

```
active ──到期──▶ expired(自动解封任务)
   ├──白名单命中──▶ whitelisted
   ├──人工删除──▶ (删除+联动解封)
   └──校验拒绝──▶ rejected(留痕不入黑名单，reject_reason 记原因)
```

来源枚举：IPS / WAF / ZTNA / TI / AV / FW / NTA / GRAYLOG / MANUAL / API。IP 归属地写入时用 ip2region 快照落库，后台任务对缺失记录回填。

### 4.3 设备插件网关

**注册式插件 + Manifest 能力声明**：

```python
class BasePlugin:            # backend/plugins/base.py
    plugin_code: str
    capabilities: {BLOCK, UNBLOCK, QUERY}
    manifest: {...}          # 配置字段声明，设备表单据此渲染
```

8 个内置插件：

| plugin_code | 设备 | 接入方式 |
|---|---|---|
| mock | 演示 | 只记录不下发（测试链路用） |
| http_generic | 通用 REST | 模板化 HTTP 调用 |
| ssh_firewall | H3C / 华为防火墙 | SSH CLI |
| sangfor_ips | 深信服 IPS | API |
| palalto_fw | PaloAlto PAN-OS | DAG Tag |
| qiming_fw | 启明天清汉马 USG | API |
| qiming_ips | 启明天清 IPS | REST v3 |
| aliyun_waf_v3 | 阿里云 WAF 3.0 | 读-改-写整表回写（200 条分片） |

设备凭据经 `credential_ref` 引用环境变量注入（`apply_credential`），**代码与配置文件中无真实凭据**。开发新插件见 `docs/plugin-dev.md`。

### 4.4 AI 巡检（平台体检）

每天 08:30 + 手动触发，12 个检查项加权健康分（ok=100 / warn=55 / fail=0），**安全效果层权重更高**：

| 层 | 检查项（权重） |
|---|---|
| 安全效果 | gap 封禁缺口(2.0)、detection 处置率(2.0)、persistent 跨日持续攻击(1.0)、attacks 攻击态势(0.5) |
| 平台健康 | devices 设备连通(1.5)、expire 到期解封(1.5)、sources 三流覆盖(1.0)、blacklist 黑名单健康(1.0)、tasks 任务队列(1.0)、policies 策略覆盖(1.0)、system 系统风险(1.0)、whitelist(0.5) |

「设计内豁免不算缺口」原则：如白名单命中、内网地址等按设计被跳过的，不计入处置率缺口。详见 `docs/ai-inspection.md`。

### 4.5 日志巡检（Graylog MCP，确定性规则）

**取数层**：最小 MCP 客户端（`mcp_client.py`），Streamable HTTP 与旧版 HTTP+SSE 双传输自动降级，Graylog token 鉴权。四级流发现（显式配置 → list_streams 工具 → 约定名匹配 → 环境变量兜底）。

**字段归一三层**（规则层零厂商感知）：

```
Graylog 原始列 → ① field_mapping(平台字段→厂商列, 页面可配)
              → ② 内置别名兜底(FIELD_ALIASES: ip/url/action/timestamp/domain...)
              → ③ value_mapping(厂商枚举值→标准动作词表, 页面可配)
标准动作词表: observe / audit / block / ban / pass / reject / unknown
```

> 设计要点：**数字枚举（如绿盟 IPS action 1/3/8）必须显式配置 value_mapping，不做启发式猜测**；时间列解析与巡检/LBA 同口径（ts → FIELD_ALIASES['timestamp'] 别名兜底），避免列名出入导致全部记录兜底成当前时间。

**L1 规则表（11 条，`RULES`）**：

| key | 名称 | 触发条件 |
|---|---|---|
| ips_observed | IPS 告警未阻断 | IPS 动作=observe/audit 且 severity∉(1,2) |
| waf_observed | WAF 放行/仅记录 | WAF 动作=observe/pass |
| waf_reject | WAF 拒绝高频 | 同 IP REJECT ≥ 5 |
| bruteforce_login | 登录爆破 | 同 IP 登录页 REJECT ≥ 10 |
| zt_multi_domain | 零信任多域名扫描 | 同 IP 不同 dst_domain ≥ 4（dst_domain 缺失时从 URI 派生） |
| zt_dir_scan | 零信任目录扫描 | 不同 URI ≥ 20 且不同路径前缀 ≥ 15 |
| waf_spoofed | WAF 伪造源 IP | XFF 链尾 ≠ 直连 IP |
| ztna_burst | 零信任认证爆破 | redirect_auth 次数 ≥ 10（**不依赖 status_code**——网关对认证失败也回 200） |
| high_freq | 高频访问 | 同 IP 日志条数 ≥ 50 |
| multi_stream | 跨流命中 | 同 IP 出现在 ≥ 2 条流 |
| intel_hit | 情报命中 | 情报标签/威胁分 ≥ 60 |

**闸门预判顺序**：白名单 → 已封存在 → 重复（repeat_hours 默认 24h）→ would_block。内网/保留地址（`ipaddress.is_global`）不计候选仅计数。单轮候选上限 200。

**模式**：`dry-run`（默认，只出建议）/ `assist` / `auto`。P0 阶段 blocked 恒 0，不实际下发。

> 注：封禁分级规则（如 R0–R7）定义在 Graylog 脚本侧，平台只迁移判断口径（如 R5 跨日持续攻击）；平台自身的字段硬规范为 R1–R8（见 `docs/log-source-spec.md`）。

### 4.6 LBA 登录行为分析

**两套读数路径，自动切换**：

| 路径 | 条件 | 特点 |
|---|---|---|
| store（预聚合） | 采集器 15 分钟内跑过 | 读 `lba_user_hourly` 本地表，秒开，不受单次拉取 5000 条上限约束 |
| live（实时） | 采集器未运行/失败/刚部署 | 实时拉 Graylog 聚合，window_desc.source=live 标明 |

**采集器**（`lba_collector.py`，beat 每 5 分钟）：
- 水位增量：`[watermark - 2min, now]`，重叠 2 分钟兜迟到记录，事件键去重保证不重复计数；
- 空轮也推进水位，防扫描窗口膨胀；首轮无水位回填 7 天；
- 小时桶合并：requests/fails 计数 + ips(封顶 500)/devices(100)/domains(200)/events(200)/event_keys(1000) 明细快照——**防 TEXT 64KB 列被 NAT 出口型重度用户撑爆**；
- 状态与水位在 `lba_collect_state`（按源一行），`GET /lba/collect/status` 可查。

**风险分级**（启发式，仅提示不下结论）：

| 级别 | 条件（7d 窗口） |
|---|---|
| high | 跨 IP ≥ 5 或 跨国家 ≥ 2 或 窗口内失败 ≥ 10 |
| medium | 跨 IP ≥ 3 或 设备数 ≥ 3 |
| low | 其余 |

关键约束：内网 IP 不参与跨 IP/跨国风险（只留轨迹明细标 internal）；认证失败判定用 `l7_app_request_type=redirect_auth` 计数而非 status_code；匿名消息不进用户聚合；设备类型优先 `ua_is_pc` 布尔换算，false 时交 UA 派生（mobile/feishu 等）避免压平成 other。

### 4.7 人机对话（受控 DSL，不用大模型）

设计目标：运营人员用自然语言查「数据里有什么」，**确定性、可审计、不产生幻觉**。

管线：`POST /chat/ask` → 规则意图路由（router_intent，纯规则打分，低分转 clarify）→ DSL（Pydantic 模型，护栏：limit≤200、日志窗≤7 天、库窗≤365 天、单问句≤3 子查询）→ 编译（compiler_db→SQLAlchemy / compiler_log→MCP，全链路唯一生成 SQL 处）→ 模板结论（narrative，只说数据里有的）→ 落库+审计。

护栏要点：敏感表（system_user/patrol_setting 等）永不可查；限流 20 次/分/用户；日志查询口径与巡检**完全共用**同一套客户端/字段别名/动作判定，保证「对话查出的未拦截数」与「巡检说漏封的数」一致。详见 `docs/chat-nlq.md`。

---

## 5. 数据模型（29 张表）

### 5.1 分组

| 组 | 表 | 说明 |
|---|---|---|
| 认证与权限 | system_role / system_user | 三角色 RBAC，权限 JSON |
| 告警 | security_event / alert_event | 原始事件 + 告警（dedupe_key 去重） |
| IOC | ioc_indicator / ioc_ip_detail / ioc_domain_detail / ioc_source / ioc_device_binding | 流水表 + 类型详情 + 来源追溯 + 设备绑定 |
| 白名单 | ip_whitelist | CIDR 级，ip_bin+prefix_len |
| 设备 | security_device / device_plugin / device_capability | 设备 + 插件 Manifest + 能力三元组 |
| 策略 | automation_policy / policy_device_rel | 条件/阈值/目标插件/审批要求 |
| 任务 | device_task / device_task_log / approval_record | 幂等任务 + 执行留痕 + 审批 |
| 巡检（AI） | inspection_report | 健康分 + 检查项 JSON |
| 巡检（日志） | patrol_setting / patrol_run / patrol_candidate | 配置单行 + 批次 + 候选 |
| 对话 | chat_session / chat_message | 会话 + 消息（blocks/dsl/trace） |
| 系统 | system_setting / operation_audit | 运行期配置 + 审计 |
| LBA | lba_user_hourly / lba_collect_state | 用户×小时预聚合 + 采集水位 |

### 5.2 建表与升级机制

- 全新部署：`sql/init.sql` + `sql/seed.sql` 初始化；
- **老库升级**：api 启动时 bootstrap 执行**幂等 `create_all` 自动补建新增表**（v1.2 加入；此前新表只写 init.sql 导致老库缺表 500）。已知边界：该机制只解决「新增表」，**已有表加列仍需手工迁移**（迁移文件放 `sql/migrate_*.sql`）；
- bootstrap 还幂等播种：角色权限（只加不减）、插件 Manifest、演示设备/策略/白名单、admin 账号（首登强制改密）。

---

## 6. API 设计

- 统一前缀 `/api/v1`，统一返回 `{code, message, data}`（code=0 成功）；Swagger 在 `/api/docs`；
- 14 个路由模块：auth / alerts / ioc（含 whitelist）/ devices（含 plugins）/ policies / tasks / audit / dashboard / inspections / patrols / log_sources / lba / chat / system；
- 鉴权：JWT（HS256，默认 480 分钟），接口级 `require_perms` 权限点（如 `lba:read`、`system:*`）；
- 告警接收接口不走 JWT（机器对机器），用 Secret + 防重放 + 来源 IP 白名单；
- 完整端点清单见 `docs/api.md`。

---

## 7. 定时任务（Celery beat）

| 计划 | 任务 | 周期 | 说明 |
|---|---|---|---|
| expire-iocs | aegis.expire_iocs | 60s | 过期 IOC 生成解封任务 |
| compensate-pending | aegis.compensate_pending | 120s | 补偿 broker 抖动漏投递的任务 |
| daily-ai-inspection | aegis.run_inspection | 每天 08:30 | AI 巡检 |
| graylog-patrol | aegis.run_patrol | 60s 唤醒 | 内部按页面配置间隔真跑（改间隔无需重启 beat） |
| lba-collect | aegis.run_lba_collect | 300s | LBA 预聚合采集 |

---

## 8. 安全设计

| 机制 | 实现 |
|---|---|
| 认证 | JWT；首登强制改密；密码强度校验 |
| 授权 | RBAC 三角色（admin `*` / operator 运营 / auditor 只读）+ 接口级权限点 |
| 告警接口 | Secret + Bearer + 时间戳防重放（300s 容差）+ 来源 IP 白名单（system_setting 运行期可改，开启+空列表被拒绝） |
| 封禁安全 | 白名单优先 → 内网禁封 → 全局熔断 kill-switch → 单告警封禁上限 → 任务幂等 → 审批门（策略可要求人工 approve） |
| 审计 | 所有写操作落 operation_audit（操作人/角色/类型/目标/IP）；凭据与 token 永不入审计与日志 |
| 凭据管理 | credential_ref 引用环境变量，运行时注入 |
| 脱敏 | 配置返回 token 只回掩码尾号，留空=不修改；开源自查清单见 `docs/security.md` |

---

## 9. 部署与环境变量

- 7 容器 compose，入口 8080；一键脚本 `scripts/install.sh`；冒烟验收 `scripts/smoke_test.py`（18 项）；
- MySQL 连接**二选一**：`DB_HOST/DB_USER/DB_PASSWORD/DB_NAME` 分量式（推荐，密码特殊字符自动 URL 编码）或 `DATABASE_URL` 显式串（特殊字符须自行编码）；
- 关键环境变量分组：镜像源（AEGIS_PIP_INDEX 等，境内加速）、JWT、告警（GRAYLOG_WEBHOOK_SECRET）、策略（GLOBAL_KILL_SWITCH / DEFAULT_BLOCK_DURATION）、巡检（PATROL_*）、更新检查（AEGIS_UPDATE_CHECK）——全量见 `.env.example`；
- CI（ci.yml）：compileall + pytest + 前端 build + compose 校验；release.yml：tag 触发 amd64/arm64 镜像发布 ghcr。

## 10. 版本机制

版本信息单源（version_info.py）：构建注入 → 本地 git → 文件时间回退；`GET /system/update/check` 只读检查 GitHub Releases（超时 5s 降级、缓存 10 分钟、可换镜像 `AEGIS_GITHUB_API_BASE`）。

## 11. Roadmap

- v1.0（已发布）：告警接入/IOC/插件下发/任务审批/审计/AI 巡检/日志巡检/对话
- v1.1：AI 巡检插件化、审批流增强、DAG 工作流
- v1.2：域名/URL/Hash 真实下发、插件市场
- v2.0：报表、威胁情报

## 12. 文档索引

| 主题 | 文档 |
|---|---|
| 用户操作 | `docs/user-manual.md`（本设计文档的姊妹篇） |
| API 字段 | `docs/api.md`、`docs/lba-api.md` |
| 安装部署 | `docs/install.md`、`docs/deploy-cloud.md` |
| 日志源与字段规范 | `docs/log-source-spec.md` |
| 日志巡检 | `docs/graylog-patrol.md`、`docs/graylog-config-guide.md` |
| LBA 设计 | `docs/lba-design.md` |
| AI 巡检 | `docs/ai-inspection.md` |
| 对话 DSL | `docs/chat-nlq.md` |
| 插件开发 | `docs/plugin-dev.md` 及 plugins-*.md |
| 其他 | `docs/geoip.md`、`docs/i18n.md`、`docs/blacklist-history.md`、`docs/security.md`、`docs/verify.md` |
