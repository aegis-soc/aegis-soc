# 宙斯盾 AegisSoc 架构对齐基线 V1.0（已拍板实施）

> 状态：**已拍板并实施完成**｜编制：2026-11-03｜实施：2026-11-03
> 决策结果：**D1 = Python FastAPI + Celery + Vue3**（用户拍板 A）；D2/D3/D4 按本文推荐默认执行。
>
> 输入材料：`通用安全运营自动化平台需求说明书与架构方案V1.0.docx`、`readme.md.txt`、`部分代码.txt`，以及 `FW.txt` / `Block2.0.txt` / `新建文本文档.txt`（现有生产脚本）
>
> 本文件是施工前的架构对照与决策记录，v1.0 代码已按此基线落地；实际交付见仓库根目录 README.md 与 CHANGELOG.md。

---

## 0. 一句话结论

以**需求说明书 V1.0（评审基线版）为唯一需求与技术基线**，落地一个可 Docker Compose 一键启动、覆盖「告警 → 策略 → 异步任务 → 插件下发 → 审计 → 到期解封」全链路的 v1.0 MVP；`readme.md.txt` 作为开源门面草案修正后沿用，`部分代码.txt` 的 Go 骨架与现有生产 Python 脚本**仅作接口/逻辑参考，不直接采用**。

**唯一需要你拍板的分歧点：后端用 Python FastAPI 还是 Go/Gin**（见 §8 D1）—— 已拍板 **A：Python FastAPI + Celery + Vue3**，其余分歧均按本文默认执行。实施结果见 §10。

---

## 1. 三份材料一致性分析

| 维度 | 需求说明书 V1.0 | readme.md.txt | 部分代码.txt | 冲突判定 |
|---|---|---|---|---|
| 文档性质 | 评审基线版、需求+架构+附录A 全量 DDL | 开源 README 草案，含「要不要我继续输出 B」等未完成语句 | 另一个 AI 输出的分批 MVP 骨架，末尾停在「你回复 A/B/C」 | 前者为准 |
| 后端 | Python **FastAPI** | Go / React（徽章） | **Go + Gin v1.9.1** | 🔴 实质冲突 |
| 任务调度 | **Celery + Celery Beat** | 未提 | 自写 `time.NewTicker(10s)` 轮询 | 🔴 实质冲突 |
| ORM | MySQL8（附录A 18 表 DDL） | MySQL8 | GORM + 简化 7 表 | 🟡 表模型冲突 |
| 前端 | **Vue3 + Element Plus** | React（徽章） | **Vue3 + Element Plus** | 🟡 README 笔误 |
| 缓存 | Redis | Redis | go-redis/v8 | ✅ 一致 |
| 认证 | RBAC + JWT | RBAC + JWT | JWT（中间件省略） | ✅ 一致 |
| 插件 | 独立进程/容器 + Manifest 能力声明 + 签名校验 | 插件热加载 | Go 注册式 registry（先做注册式，规避 plugin 跨平台坑） | 🟢 思路一致 |
| 部署 | Docker Compose + Nginx | Docker Compose（生产/Demo 双模式） | Dockerfile 待补 | ✅ 一致 |
| API 前缀 | `/api/v1/` | `/api/v1/` | `/api/v1/` | ✅ 一致 |

> README 里的 `language-Go/React` 徽章与文档、代码骨架均不一致，判定为**早期草案笔误**，拍板后统一修正。

---

## 2. 技术选型最终对照表（建议方案）

| 层 | 建议技术 | 版本/说明 | 采纳理由 | 被舍弃方案及原因 |
|---|---|---|---|---|
| 后端框架 | **Python FastAPI** | 0.115+ / Uvicorn | 文档 14.1 明确选型并说明理由；Graylog Webhook、阿里云 SDK、PA XML API、后续 AI 巡检均为 Python 生态；自带 OpenAPI 直接满足文档 Swagger 要求；与现有 SOAR/生产脚本同语言 | `Gin`：文档未选，且 PA/阿里云 SDK 需自行封装 |
| 任务队列 | **Celery + Celery Beat** | Redis 作 broker/backend | 文档 12.2 要求指数退避重试、失败重试、到期自动解封、5 分钟定时巡检；Celery 原生支持，任务可持久化 | `10s ticker`：无持久化、无幂等、无退避、无定时表达式 |
| ORM / DB | **SQLAlchemy 2.0 + MySQL 8** | utf8mb4 | 附录A 的 18 张表 DDL 可直接落地，无需改造 | `GORM + 7 表`：不支持 IPv6/CIDR/Domain 分类与设备能力矩阵 |
| 缓存 | **Redis 7** | 告警去重、限流、幂等锁、全局熔断开关、Celery broker | 三份材料一致 | — |
| 前端 | **Vue 3 + Element Plus + Vite** | 管理后台 SPA | 文档与代码骨架一致 | `React`：仅 README 徽章出现 |
| 插件机制 | **Python 注册式 + Manifest 能力声明** | `plugins/base.py` 抽象 + `registry.py` + 4 个内置插件 | 文档 6.3/6.4 要求声明 `ioc_types` / `capabilities` 与统一接口；注册式规避 Go plugin 跨平台坑，开源项目优先稳定 | 独立进程/容器、签名校验：文档 6.5 要求，但 v1.0 先留接口，v1.1 落地 |
| 认证授权 | **JWT + RBAC** | `admin / operator / auditor`，接口级依赖注入 | 三份一致；白名单 API 独立业务权限（文档 11.3 硬性约束） | — |
| 反向代理 | **Nginx** | 前端静态资源 + `/api` 反代 + HTTPS 卸载位 | 文档 14.1 | `gin.Static`：不利于前后端分离与独立扩容 |
| API 文档 | **FastAPI 自动生成 `/docs`** | OpenAPI 3 | 零额外代码 | `gin-swagger` 需注解维护 |
| 部署 | **Docker Compose** | api / worker / beat / frontend / mysql / redis / nginx 七容器 | 用户目标「后续 docker 发布开源」 | — |
| 协议 | **Apache 2.0** | LICENSE + 每文件头注释 | README 已定 | — |

### 2.1 若改选 Go/Gin 的代价（供决策参考）

| 项 | 影响 |
|---|---|
| 附录A 18 表 | 需把 MySQL DDL 反译为 GORM model，IPv6/CIDR `VARBINARY(16)` 网段比对需自行实现 |
| Celery 能力 | 需引入 `asynq` / `machinery` 或自写 worker + 定时调度，等同重写文档 M1/M5 |
| 设备插件 | 阿里云 SDK、PA `pan-os-python` 生态优势消失，SSH/签名逻辑需 Go 重写 |
| AI 巡检（v1.1） | 文档第 16 章的 WorkBuddy / MCP 接入为 Python 生态，Go 侧需额外适配层 |
| 现有资产复用 | `FW.txt` / `Block2.0.txt` 的 Python 逻辑无法直接复用 |

---

## 3. 仓库目录结构（最终）

仓库根：`C:\SOAR\aegis-soc\`（现有 6 个参考文件保持在 `C:\SOAR\` 原地，不搬动、不入库）

```
aegis-soc/
├── LICENSE                        # Apache 2.0
├── README.md                      # 由 readme.md.txt 修正技术栈后落地
├── CONTRIBUTING.md
├── CHANGELOG.md
├── .gitignore                     # 显式排除 .env、*.pem、凭据、真实IP清单、_doc_extract 等
├── .env.example                   # 全部占位值，无真实凭据
├── docker-compose.yml             # 生产模式：7 容器
├── docker-compose-demo.yml        # Demo 模式（v1.1，见 §8 D3）
├── Makefile                       # up / down / logs / test / lint 快捷命令
│
├── sql/
│   ├── init.sql                   # 附录A 全部 18 张表，原样落地 + 注释补充
│   └── seed.sql                   # 3 角色、初始管理员、1 条默认策略、1 台 mock 设备、示例白名单
│
├── backend/
│   ├── Dockerfile                 # python:3.12-slim 多阶段
│   ├── requirements.txt
│   ├── app/
│   │   ├── main.py                # FastAPI 入口、CORS、统一异常、健康检查 /healthz
│   │   ├── core/                  # config / security(JWT,bcrypt) / deps(RBAC) / response(code,msg,data) / audit
│   │   ├── db/                    # session.py / base.py / models/（18 表 ORM）
│   │   ├── schemas/               # Pydantic v2 请求响应模型
│   │   ├── api/v1/                # auth / alerts / ioc / whitelist / devices / plugins /
│   │   │                          # policies / tasks / dashboard / audit / system(kill-switch)
│   │   ├── engines/               # policy_engine / dispatch_engine / workflow_engine(线性轻量版)
│   │   ├── security/              # whitelist / ioc_validation(IPv4,IPv6,CIDR,内网过滤) / capability_match
│   │   └── services/              # 业务服务层，供 api 与 worker 共用
│   ├── plugins/
│   │   ├── base.py                # 统一接口 + Manifest 能力声明（文档 6.3/6.4）
│   │   ├── registry.py            # 注册/发现/调用
│   │   └── builtin/
│   │       ├── mock.py            # 只记日志不下发
│   │       ├── http_generic.py    # 低代码通用 REST 插件（文档 6.5）
│   │       ├── ssh_firewall.py    # 由 FW.txt 提炼，H3C / 华为 CLI
│   │       ├── sangfor_ips.py     # 由 Block2.0.txt 提炼，签名 + 配置生效
│   │       ├── paloalto_fw.py     # PAN-OS 9.1+，user-id + DAG Tag
│   │       ├── qiming_fw.py       # 天清汉马 Web API，路径/报文参数化
│   │       └── aliyun_waf_v3.py   # WAF 3.0 IP 黑名单，整表回写 + 分片
│   ├── workers/
│   │   ├── celery_app.py
│   │   ├── tasks.py               # 下发 / 指数退避重试 / 状态回写 / 到期解封
│   │   └── beat_schedule.py       # 到期解封、设备状态核对、健康检查
│   ├── agent/                     # DMZ 中转 Agent（v1.1 占位 + README 说明）
│   └── tests/                     # test_alert_flow / test_whitelist / test_policy / test_plugins / test_idempotency
│
├── frontend/
│   ├── Dockerfile                 # node:20 构建 → nginx:alpine 运行
│   ├── nginx.conf
│   ├── package.json / vite.config.ts / index.html
│   └── src/
│       ├── api/  router/  store/  layouts/
│       └── views/
│           ├── dashboard/         # 首页总览（文档 4.1 统计区）
│           ├── alerts/            # 告警列表 / 详情
│           ├── ioc/               # blacklist-ip / blacklist-domain / whitelist-ip
│           ├── devices/           # 设备资产 / 连接测试 / 能力
│           ├── plugins/           # 插件列表 / 配置 / 测试
│           ├── policies/          # 策略配置
│           ├── tasks/             # 任务中心 / 重试 / 取消
│           ├── audit/             # 操作审计
│           └── system/            # 用户 / 全局熔断开关
│
├── deploy/
│   ├── nginx/nginx.conf
│   └── mysql/my.cnf
│
└── docs/
    ├── architecture-baseline.md   # 本文件
    ├── install.md                 # 快速部署、环境变量、首次改密
    ├── graylog-config-guide.md    # Event Definition + Webhook 配置模板 + 告警样例
    ├── plugin-dev.md              # 插件 SDK / Manifest / 能力声明 / 提交规范
    ├── api.md                     # 统一返回格式与接口清单（FastAPI /docs 补充说明）
    └── security.md                # 凭据管理、脱敏规范、开源前自查清单
```

---

## 4. 数据库表结构映射（核心）

**结论：文档附录A 18 张表全部落地；`部分代码.txt` 的 7 张表被覆盖/升级，不保留。**

| # | 文档附录A 表 | 部分代码.txt 对应表 | MVP 落地 | 说明 |
|---|---|---|---|---|
| 1 | `security_event` | — | ✅ 全实现 | 标准化安全事件，`uk_source_id` 去重 |
| 2 | `alert_event` | `alert_record` | ✅ 合并实现 | 用 `alert_event.uk_alert_id` 承担去重，`alert_record` 丢弃 |
| 3 | `ioc_indicator` | `ioc_ip`（单表） | ✅ 升级拆分 | 主表统一 IOC；原单表黑名单无法区分 IPv6/CIDR/Domain/Hash |
| 4 | `ioc_ip_detail` | — | ✅ 全实现 | `ip_bin VARBINARY(16)` 支持网段包含比对 |
| 5 | `ioc_domain_detail` | — | ✅ 全实现 | `exact / subdomain / wildcard` 匹配语义（文档 5.1.2） |
| 6 | `ioc_source` | — | ✅ 全实现 | 多告警来源；防止某来源失效误删其他来源的封禁依据 |
| 7 | `ioc_device_binding` | — | ✅ 全实现 | IOC ↔ 设备绑定，支撑「每设备独立执行状态」 |
| 8 | `ip_whitelist` | `ioc_ip(type=white)` | ✅ 独立建表 | **白名单独立存储、禁止下发**（文档 18-1 硬性边界） |
| 9 | `security_device` | `plugin_device` | ✅ 升级 | 增加厂商/型号/区域/凭据引用/在线状态/`auto_dispatch` |
| 10 | `device_plugin` | — | ✅ 全实现 | `manifest JSON` 存能力声明 |
| 11 | `device_capability` | — | ✅ 全实现 | 能力矩阵，只向支持对应 IOC 类型的设备下发 |
| 12 | `automation_policy` | — | ✅ 全实现 | 阈值、时间窗、置信度、封禁时长、审批开关 |
| 13 | `policy_device_rel` | — | ✅ 全实现 | 策略 → 目标设备列表 |
| 14 | `workflow_definition` | — | 🟡 建表 + 占位 | v1.0 用线性策略链，可视化 DAG 编排放 v1.1 |
| 15 | `device_task` | `block_task` | ✅ 升级 | 增加 `uk_task(ioc_id,device_id,operation)` **幂等约束** |
| 16 | `device_task_log` | — | ✅ 全实现 | 请求/响应报文留痕，满足等保追溯 |
| 17 | `approval_record` | — | 🟡 建表 + 最简审批 | 「待审批 → 通过 / 拒绝」两态，支撑文档 7.1 审批分支 |
| 18 | `operation_audit` | `audit_log` | ✅ 升级 | 增加 `role_code / target_type / target_id / client_ip` |
| 19 | `system_role` | — | ✅ 全实现 | 3 角色 + `permission_json` |
| 20 | `system_user` | `sys_user` | ✅ 升级 | `password_hash` bcrypt，去掉硬编码哈希依赖 |

> 注：附录A 清单为 18 张，加上 `policy_device_rel`（§A.5 内）与 `system_role`（§A.7 内）实际 DDL 共 20 张，全部落地。
>
> **不落地的原表**：`ioc_ip`、`alert_record`、`plugin_device`、`block_task`、`audit_log`、`sys_user` —— 均被上表升级替代。

### 4.1 关键业务约束在表结构上的体现

| 文档约束 | 落地方式 |
|---|---|
| 白名单优先、禁止下发 | `ip_whitelist` 独立表；策略引擎在生成 `device_task` 前强制检查 |
| 白名单新增触发已下发黑名单解除 | 白名单写操作 → 扫描 `ioc_device_binding` → 生成 `operation=DELETE` 任务 |
| 黑名单状态 ≠ 设备执行状态 | `ioc_indicator.status` 与 `device_task.task_status` 分离；多设备各自独立记录 |
| 任务幂等 | `device_task.uk_task` 唯一键 + `request_id` |
| IOC 类型隔离 | `ioc_type` 枚举 + `device_capability` 矩阵 |
| 特殊地址禁止封禁 | `ioc_validation` 过滤内网 / 环回 / 组播 / 保留地址，CIDR 限制最大网段（禁 /8） |

---

## 5. API 映射（文档第 11 章 → MVP）

统一返回格式 `{ "code": 0, "msg": "success", "data": {} }`；`code`：0 成功 / 400 参数非法 / 401 鉴权失败 / 403 白名单拦截 / 500 内部异常。

| 文档 API | MVP | 补充说明 |
|---|---|---|
| `POST /api/v1/alerts/graylog` | ✅ | Secret + Bearer 双校验、时间戳防重放、`uk_alert_id` 去重、**快速返回 accepted** |
| `POST /api/v1/alerts/generic` | ✅ | 通用告警源（ElasticAlert / Suricata 预留） |
| `GET /api/v1/alerts`、`/{id}` | ✅ | 保留 `raw_payload` 索引，原始日志仍留 Graylog |
| `GET/POST /api/v1/ioc/ips`、`/domains` | ✅ | 追加 `PUT / DELETE`、详情、`/sources` `/devices` `/tasks` |
| `GET/POST/PUT/DELETE /api/v1/whitelist/ips` | ✅ | 独立业务权限，**不调用任何封禁动作** |
| `POST /api/v1/whitelist/ips/import` | ✅ | CSV/Excel 批量导入、冲突与网段包含检测 |
| `GET /api/v1/whitelist/ips/check` | ✅ | 供策略引擎与 AI 插件调用 |
| `/api/v1/devices`、`/{id}/test`、`/{id}/capabilities` | ✅ | 连接测试、能力检测、状态同步 |
| `/api/v1/plugins`、`/{id}/test` | ✅ | 插件清单、启停、配置向导 |
| `/api/v1/tasks`、`/{id}/retry`、`/cancel`、`/status` | ✅ | 失败重试、取消、状态查询 |
| `/api/v1/policies`（文档第 7 章） | ✅ | CRUD + 启停 + 审批开关 |
| `/api/v1/dashboard`（文档 4.1） | ✅ | 今日告警 / IOC / 封禁 / 设备 / 任务 / 风险分布 |
| `/api/v1/system/kill-switch`（文档 15 章） | ✅ | **全局自动封禁熔断开关** |
| `POST /api/v1/ai-inspections`（文档 16 章） | 🟡 | 仅插件接口 + Finding Schema + 页面占位，v1.1 实现 |

---

## 6. 现有生产脚本 → 设备插件映射（🔴 脱敏红线）

| 现有文件 | 可提炼能力 | 落地插件 | 脱敏处理 |
|---|---|---|---|
| `FW.txt` | paramiko SSH 交互式 CLI；等待 `>` / `]` 提示符；H3C `blacklist ip <ip> timeout 7200`、华为 `firewall blacklist item source-ip <ip>`；多设备依次执行 | `ssh_firewall.py` | 设备地址、账号、口令全部改为 `config_json` 配置项与 `credential_ref` 引用；**无任何硬编码**；超时时间可配置 |
| `Block2.0.txt` | 深信服 IPS 5.6.11：登录取 `security_key/api_key/cookie` → `sha256(security-key;api-key;time;rest-uri)` 签名 → `/api/policy/globalList/black/manual` 插入黑名单 → `applyconfig` 生效 → 登出；`blocked=0` 轮询、`>20` 阈值熔断 | `sangfor_ips.py` + 策略引擎阈值/熔断思想 | 移除全部真实设备 IP、账号、口令哈希、DB 连接口令；`logfile` 路径改为配置项；DB 轮询逻辑由平台 `device_task` 取代 |
| `新建文本文档.txt` | 无（仅一段含 Bearer Token 的 curl 示例） | **不纳入仓库** | 含真实 Token，仅作为「开源前脱敏自查」反面示例列入 `docs/security.md` 检查项 |

**开源前强制自查（`docs/security.md`）**：
1. 全仓库扫描 `10.` / `192.168.` / 内网域名 / `password` / `api_key` / `Bearer ` 等字样；
2. `.env`、`.pem`、`.key`、真实 IP 清单加入 `.gitignore`；
3. 所有凭据通过环境变量注入，插件不持久化密钥（文档 6.4 约束）；
4. `git log` 全历史检查，确认无敏感信息残留后再公开仓库。

---

## 7. MVP 范围与验收对照（文档 17.3 的 19 项）

| 验收项 | 本次 | 验收项 | 本次 |
|---|---|---|---|
| Graylog 告警接入 | ✅ | 云防火墙插件（真实地址簿） | 🟡 通用 HTTP 插件可配，真实联调需凭据 |
| 告警去重 | ✅ | PA 插件（真实 Tag） | 🟡 通用 HTTP 插件可配，真实联调需凭据 |
| IP 黑名单 | ✅ | 异步执行 | ✅ |
| 域名黑名单 | ✅ | 失败重试（指数退避） | ✅ |
| IP 白名单（单 IP/CIDR/导入） | ✅ | 到期解封（调用设备 API） | ✅ |
| 白名单保护（禁止自动封禁） | ✅ | 设备状态（成功/失败/部分成功） | ✅ |
| 白名单新增触发解除任务 | ✅ | 审计全链路 | ✅ |
| 设备能力匹配 | ✅ | 权限控制（3 角色） | ✅ |
| WAF 插件（真实封禁） | 🟡 插件框架 + mock，真实联调需凭据 | 熔断机制 | ✅ |

> 🟡 = 框架与接口就绪，因缺少真实设备凭据/环境，用 `mock` 插件做端到端闭环验证；真实 API 联调需你提供测试设备。

### 7.1 本次明确不做（v1.1 Roadmap）

- AI 巡检插件实现（WorkBuddy + Graylog MCP、5 分钟多 Stream 巡检、AI 发现中心）—— 保留插件类型 `ai_inspection`、Finding JSON Schema、页面入口占位
- 可视化 DAG 工作流编排、审批流高级配置
- DMZ 中转 Agent 完整实现、Demo 模式全套 Graylog 编排
- 插件独立进程 / 签名校验 / 插件市场
- 域名/URL/Hash 的设备真实下发（表模型与 API 就绪）
- 报表导出、威胁情报平台联动、更多厂商官方插件

---

## 8. 待你拍板的决策点

| 编号 | 决策 | 推荐 | 说明 |
|---|---|---|---|
| **D1** | 后端技术栈 | ✅ **已定：Python FastAPI + Celery + Vue3** | 用户 2026-11-03 拍板「A」；Go/Gin 骨架与生产脚本仅作接口/逻辑参考，不采用 |
| **D2** | 初始管理员口令 | `admin / Admin@123456` + **首次登录强制改密** | 与 README 草案一致；或改为启动时生成随机口令打印到容器日志 |
| **D3** | Demo 模式（compose 拉起 Graylog+ES+Mongo） | **放 v1.1** | 镜像大、启动慢、仅演示用；本次只交付生产模式 `docker-compose.yml` |
| **D4** | 真实设备插件联调 | 本次用 `mock` 跑通闭环 | 真实 WAF/PA/云防火墙凭据到位后再单独批次联调 |

> D2～D4 若你不特别说明，按推荐默认执行；**只有 D1 需要明确回复**。

---

## 9. 拍板后的施工顺序（一次交付，不再中途打断）

| 批次 | 内容 | 产出 |
|---|---|---|
| B1 | 仓库骨架 + 开源四件套 | LICENSE / README / CONTRIBUTING / CHANGELOG / .gitignore / .env.example / Makefile |
| B2 | 数据层 | `sql/init.sql`（20 表）、`seed.sql`、SQLAlchemy models |
| B3 | 后端底座 | config / JWT+RBAC / 统一响应 / 审计 / FastAPI 入口 / `/healthz` |
| B4 | 业务闭环 | 告警接入（签名+去重）→ IOC → 白名单 → 策略引擎 → 能力匹配 → 任务生成 |
| B5 | 插件与执行 | 4 个内置插件 + Manifest + Celery worker/beat（重试、退避、到期解封、状态回写） |
| B6 | 前端 | Vue3 + Element Plus，10 个页面 + 全局熔断开关 |
| B7 | 容器化 | 2 个 Dockerfile、nginx conf、`docker-compose.yml`（7 容器） |
| B8 | 文档与验证 | `docs/` 5 篇、单元测试、`python -m compileall` + 前端 `npm run build` 冒烟、端到端 `mock` 链路验证 |

---

## 10. 实施结果（2026-11-03）

B1～B8 已一次性施工完成，交付物位于 `C:\SOAR\aegis-soc\`：

| 批次 | 实际产出 |
|---|---|
| B1 | LICENSE(Apache 2.0) / README / CONTRIBUTING / CHANGELOG / .gitignore / .env.example / Makefile / docker-compose-demo.yml 占位 |
| B2 | `sql/init.sql`（20 张表）、`sql/seed.sql`、`app/models.py`（SQLAlchemy 2.0 全量 ORM）、`database.py` |
| B3 | config / common / security(JWT+bcrypt) / deps(RBAC) / schemas / bootstrap（管理员口令由代码生成并强制改密）/ services.audit / cache |
| B4 | 告警解析、白名单优先校验、能力匹配、策略引擎、11 组 API 路由、FastAPI 入口与 `/api/healthz`、`/api/docs` |
| B5 | 插件 SDK + Manifest + 注册式框架，4 个内置插件（全部脱敏）；Celery Worker / Beat（退避重试、到期解封、补偿扫描） |
| B6 | Vue3 + Element Plus 管理界面：登录、大盘、告警、IP/域名黑名单、白名单、设备、插件、策略、任务、审计、系统设置共 12 个视图 |
| B7 | 两个多阶段 Dockerfile、两层 nginx 配置、`docker-compose.yml`（mysql/redis/api/worker/beat/frontend/nginx 七容器） |
| B8 | `docs/` 六篇文档、18 项单元与端到端测试、`compileall` / `pytest` / `vite build` / Compose YAML 校验全部通过 |

**验证结论**：
- 后端 `pytest`：**18 passed**（含告警去重、白名单豁免、策略阈值、插件下发、审批、熔断、到期解封、权限）
- 前端 `npm run build`：1681 modules，产物完整
- `docker-compose.yml`：7 服务，YAML 语法校验通过（本机无 Docker，未做 `up` 实测）
- 敏感信息扫描：**0 命中**（原生产脚本的内网地址、账号口令、API Key、Bearer Token 均未进入仓库）
- 现有 6 个参考文件保持在 `C:\SOAR\` 原地，未搬动、未入库

> 未完成项（按约定归入 v1.1）：AI 巡检插件实现、DAG 编排、DMZ 中转 Agent、Demo 模式全套 Graylog 编排、插件独立进程/签名校验；4 项真实设备联调待凭据到位后进行。
