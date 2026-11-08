# 宙斯盾 AegisSoc

[English](README.md) | 简体中文

> **通用安全运营自动化 AI+SOC 平台**（Universal AI-driven Security Operations & Automation）—— 对接 Graylog 等日志平台，接收告警、统一管理 IOC 黑名单/白名单、插件化向 WAF / 防火墙 / IPS 下发封禁与解封。

[![CI](https://github.com/aegis-soc/aegis-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/aegis-soc/aegis-soc/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/aegis-soc/aegis-soc/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-FastAPI%20%2F%20Python%203.12-orange)]()
[![Frontend](https://img.shields.io/badge/frontend-Vue3%20%2F%20Element%20Plus-brightgreen)]()
[![Queue](https://img.shields.io/badge/queue-Celery%20%2B%20Redis-red)]()

**一句话定位：不改造日志平台，接收 Graylog 等多源告警，统一管理 IOC，插件化向各类安全设备执行封禁/解封，自带异步任务调度、全链路审计与 AI 巡检扩展能力。**

> 区别于重型商业 SOAR：通用化、开箱即用、Docker Compose 一键部署，AI 研判能力以插件方式渐进接入。
> 职责边界清晰：**Graylog 负责日志采集、分析、告警判定；宙斯盾 AegisSoc 负责 IOC 管理、策略编排、设备 API 联动、任务与审计**。

---

## ✨ 核心亮点

- ✅ **无侵入对接 Graylog**：仅使用原生 Alert Webhook，不改 Graylog 源码，任意已有集群均可接入
- ✅ **通用告警接入**：除 Graylog 外提供 `generic` 告警入口，可接 ElastAlert、Suricata 等
- ✅ **插件化设备网关**：统一接口 + Manifest 能力声明，新增设备只写插件，平台主体不改
- ✅ **IOC 生命周期**：IP / 域名黑名单、IP 白名单（单 IP / CIDR / 批量导入）、过期自动解封、来源标记、标签备注
- ✅ **黑名单流水**：同一 IP 每次命中独立成条（同值不合并），各自保留添加时间 / 过期时间 / 来源告警；来自 IPS / WAF / 零信任 / 威胁情报 自动分类；被拦截的地址以 `rejected` 留痕，可回答「为什么没封」
- ✅ **AI 巡检**：两层体检——先看防护是否生效（三流覆盖、**封禁缺口归因**、处置率 7 日趋势、跨日持续攻击），再看平台是否健康（设备、黑名单、任务、到期解封、白名单、策略、系统）；输出加权健康分、KPI 快照与可执行建议，每天 08:30 自动巡检，报告可回看；可选接入大模型生成总结
- ✅ **日志巡检（P0，只读）**：每 5 分钟通过 **MCP** 读取 Graylog 三流日志（IPS / WAF / 零信任），用确定性规则（IPS 未阻断、WAF 放行、认证爆破、高频访问、跨流命中、情报命中）找出 Graylog 规则漏掉的攻击源；当前 dry-run，只出报告不封禁
- ✅ **IP 归属地**：黑名单直接显示国家 / 省·市（如「中国 · 广东省·深圳市」），来自 ip2region 离线库（11 MB，无需联网、无需 ipip 授权），写入时快照落库、支持按国家筛选
- ✅ **硬性安全边界**：白名单优先、内网/环回/保留地址禁止封禁、IOC 类型与设备能力匹配、全局熔断开关
- ✅ **可靠异步任务**：Celery + Beat，幂等约束、指数退避重试、超时控制、到期自动解封
- ✅ **全链路审计**：人工操作、自动封禁、设备请求/响应报文全留痕，满足等保追溯
- ✅ **RBAC 权限**：`admin` / `operator` / `auditor` 三角色，接口级鉴权
- ✅ **AI+SOC 就绪**：预留 AI 巡检/研判插件接口与 Manifest 能力位，v1.1 起接入 LLM 辅助研判与多 Stream 日志巡检
- ✅ **开源友好**：Apache 2.0，可商用、可二开，欢迎社区贡献设备插件

## 🖼 界面预览

> 以下截图来自本地运行实例（演示数据），均在「自动封禁运行中」状态截取。

### 首页大盘

告警 / IOC / 设备与任务的实时状态总览，含风险分布与最近告警：

![首页大盘](docs/screenshots/dashboard.png)

### IP 黑名单（流水记录 · 来源 · 归属地）

同一 IP 多次命中独立成条、不合并；来源自动识别（WAF / IPS / 零信任 / 威胁情报…）；
内网 / 保留地址被拦截时同样留痕（状态「被拦截」，备注栏直接给出原因）：

![IP 黑名单](docs/screenshots/blacklist-ip.png)

### 设备管理（可视化配置表单）

选择插件后自动出现该设备的可视化配置界面——设备地址、业务参数、凭据环境变量分组展示，
无需手写 JSON（高级模式仍保留 JSON 编辑）：

![设备管理](docs/screenshots/device-form.png)

### 插件管理

8 个内置插件统一声明支持的 IOC 类型与能力（BLOCK / UNBLOCK / QUERY）：

![插件管理](docs/screenshots/plugins.png)

---

## 🧱 系统架构

```
各类日志源：WAF / IPS / 防火墙 / NDR / EDR / Nginx / 应用日志
                          │
                          ▼
        Graylog：Pipeline 标准化 · Event Definition · Alert
                          │ Webhook（Secret + 时间戳防重放）
                          ▼
┌─────────────────────────────────────────────────────────┐
│                 宙斯盾 AegisSoc · AI+SOC               │
│  ┌───────────┐  ┌────────────┐  ┌───────────────────┐  │
│  │  FastAPI  │  │  Vue3 UI   │  │ Celery Worker/Beat│  │
│  │  API 服务 │  │  管理后台   │  │  异步任务/定时解封 │  │
│  └─────┬─────┘  └────────────┘  └─────────┬─────────┘  │
│        │          策略引擎 · IOC · 白名单 · 审计          │
│        └──────────────┬───────────────────┘              │
│                 插件网关（Manifest 能力匹配）              │
└───────────────────────┬─────────────────────────────────┘
                        ▼
     mock / 通用 HTTP / SSH 防火墙 / 深信服 IPS / WAF / PA
                        │
                        ▼
              MySQL 8（业务）+ Redis 7（去重/限流/队列/熔断）
```

> 🔒 告警判定逻辑留在 Graylog；平台提供阈值、抑制、审批与熔断，避免误封泛滥。
> 完整架构对照见 [docs/architecture-baseline.md](docs/architecture-baseline.md)。

---

## 📦 快速部署（Docker Compose）

**前置条件**：Docker 24+ / Docker Compose v2

```bash
git clone https://github.com/aegis-soc/aegis-soc.git
cd aegis-soc
cp .env.example .env
# 务必修改：JWT_SECRET / GRAYLOG_WEBHOOK_SECRET / 数据库口令 / BOOTSTRAP_ADMIN_PASSWORD
docker compose up -d
```

| 项 | 值 |
|---|---|
| 访问地址 | `http://127.0.0.1:8080` |
| 后端 API 文档 | `http://127.0.0.1:8080/api/docs` |
| 健康检查 | `http://127.0.0.1:8080/api/healthz` |
| 默认账号 | `admin / Admin@123456`（**首次登录强制改密**） |

启动 7 个容器：`mysql` · `redis` · `api` · `worker` · `beat` · `frontend` · `nginx`。

**Graylog 告警 Webhook 配置地址**：

```
http://<平台地址>/api/v1/alerts/graylog?secret=你的GRAYLOG_WEBHOOK_SECRET
```

👉 详见 [docs/graylog-config-guide.md](docs/graylog-config-guide.md)

> 无 Graylog 也能完整体验：内置 `mock` 插件 + `docs/graylog-config-guide.md` 里的 `curl` 样例即可跑通「告警 → 策略 → 任务 → 下发 → 到期解封」闭环。
> Demo 模式（一键拉起 Graylog + ES + MongoDB）规划于 v1.1，见 `docker-compose-demo.yml`。
> 🗂️ 黑名单为什么按「流水」存、被拦截的地址在哪看：见 [docs/blacklist-history.md](docs/blacklist-history.md)。
> ☁️ 部署到云服务器？另见 [docs/deploy-cloud.md](docs/deploy-cloud.md)：资源基线、安全组与端口、HTTPS 启用、定时备份、磁盘与日志治理、上线自检清单。
> ✅ **部署完怎么验？** 一条命令跑完 18 项闭环检查：`python scripts/smoke_test.py --secret <SECRET> --password <口令>`，详见 [docs/verify.md](docs/verify.md)。

---

## 📁 目录结构

```
aegis-soc/
├── sql/                  # init.sql（20 张表）、seed.sql（角色/策略/示例设备）
├── backend/
│   ├── app/              # FastAPI：config / models / schemas / api / engines / services
│   ├── plugins/          # 插件抽象 + Manifest + 4 个内置插件
│   ├── workers/          # Celery Worker / Beat
│   └── tests/            # 单元测试 + 端到端 mock 链路
├── frontend/             # Vue3 + Element Plus + Vite
├── deploy/               # nginx.conf / my.cnf
├── scripts/              # smoke_test.py（部署后一键冒烟验收，仅标准库）
├── docs/                 # install / deploy-cloud / verify / graylog / plugin-dev / api / security / architecture / blacklist-history / geoip / ai-inspection
├── .github/workflows/    # ci.yml（编译+测试+构建+编排校验）、release.yml（tag 触发多架构镜像发布）
├── docker-compose.yml
├── .env.example
└── LICENSE               # Apache 2.0
```

---

## ⚙️ 关键配置（`.env.example`）

| 变量 | 说明 | 默认值 |
|---|---|---|
| `DATABASE_URL` | MySQL 连接串 | `mysql+pymysql://aegis:...@mysql:3306/aegis_soc?charset=utf8mb4` |
| `REDIS_URL` | 去重 / 熔断 / 幂等锁 | `redis://redis:6379/0` |
| `CELERY_BROKER_URL` | 任务队列 | `redis://redis:6379/1` |
| `JWT_SECRET` | JWT 签名密钥，**必须修改** | `change-me-...` |
| `GRAYLOG_WEBHOOK_SECRET` | Webhook 校验密钥 | `change-me-...` |
| `BOOTSTRAP_ADMIN_PASSWORD` | 初始管理员口令 | `Admin@123456` |
| `GLOBAL_KILL_SWITCH` | 全局自动封禁熔断 | `false` |
| `TASK_EAGER` | 同步执行任务（本地调试/测试用） | `false` |
| `ALERT_DEDUPE_TTL` | 告警去重窗口（秒） | `3600` |

完整清单见 [`.env.example`](.env.example) 与 [docs/install.md](docs/install.md)。

---

## 🔌 内置插件（v1.0）

| code | 说明 | 真实下发 |
|---|---|---|
| `mock` | 只记录任务与日志，不调用设备 | 否（默认，用于闭环演示） |
| `http_generic` | 低代码通用 REST 插件，URL/方法/请求体模板可配 | 是 |
| `ssh_firewall` | SSH CLI 下发 H3C / 华为防火墙黑名单（由现有生产脚本抽象，全参数化） | 是 |
| `sangfor_ips` | 深信服 IPS 全局黑名单 API（登录 → 签名 → 插入 → 配置生效） | 是 |
| `paloalto_fw` | Palo Alto PAN-OS：user-id 注册 IP 到 DAG Tag，即时生效免 commit（9.1+） | 是 |
| `qiming_fw` | 启明星辰天清汉马 USG Web API：登录鉴权 → 黑名单 → 可选保存生效 | 是 |
| `qiming_ips` | 启明星辰天清IPS REST v3：SHA256 口令登录 → JWT → `block_policy` 封堵，到期由设备自行失效 | 是 |
| `aliyun_waf_v3` | 阿里云 WAF 3.0 IP 黑名单：取全量 → 合并 → 整表回写，单规则 200 条自动分片（模板需预建，插件只推 IP） | 是 |

> ⚠️ 所有设备地址、账号、口令、API Key **均通过插件配置或环境变量注入，代码中无任何真实凭据**。
> 开发新插件见 [docs/plugin-dev.md](docs/plugin-dev.md)；PA / 启明防火墙见 [docs/plugins-paloalto-qiming.md](docs/plugins-paloalto-qiming.md)，
> 启明 IPS 见 [docs/plugins-qiming-ips.md](docs/plugins-qiming-ips.md)，阿里云 WAF 3.0 见 [docs/plugins-aliyun-waf.md](docs/plugins-aliyun-waf.md)。

---

## 🛠 本地开发

```bash
# 后端
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python ../scripts/fetch_geoip.py                   # 可选：下载 IP 归属地库（约 11 MB），不装则国家/地区留空
export DATABASE_URL="sqlite:///./aegis_dev.db"    # 可先用 SQLite 快速起
export TASK_EAGER=true
uvicorn app.main:app --reload --port 8000

# 前端
cd frontend
npm install
npm run dev

# 测试
cd backend && pytest -q
```

> 生产请使用 MySQL 8；SQLite 仅用于本地快速体验（部分 MySQL 特性会降级）。

---

## 🔄 CI / CD

| 工作流 | 触发 | 内容 |
|---|---|---|
| `ci.yml` | push 到 main/master、PR、手动 | 后端 `compileall` + `pytest`；前端 `npm ci` + `npm run build`；两份 Compose 配置校验 |
| `release.yml` | 推送 `v*` tag、手动 | 构建 `linux/amd64` + `linux/arm64` 双架构镜像，推送 ghcr 并自动生成 GitHub Release |

镜像地址（tag 形如 `v1.0.0`）：

```
ghcr.io/aegis-soc/aegis-soc-backend:1.0.0
ghcr.io/aegis-soc/aegis-soc-frontend:1.0.0
```

```bash
git tag v1.0.0 && git push origin v1.0.0   # 打 tag 即触发发布
```

---

## 📌 Roadmap

| 版本 | 内容 |
|---|---|
| ✅ v1.0.0 | RBAC/JWT、IP/域名黑名单、IP 白名单+导入、Graylog/通用告警接入、策略引擎、插件网关、异步任务与到期解封、审计、熔断、Swagger、Docker Compose |
| 📅 v1.1.0 | AI 安全巡检插件（WorkBuddy + Graylog MCP 多 Stream 巡检）、审批流增强、可视化 DAG 编排、DMZ 中转 Agent、Demo 模式全套编排 |
| 📅 v1.2.0 | 域名/URL/Hash 真实下发、告警抑制与 IP 分组、插件独立进程与签名校验、插件市场 |
| 📅 v2.0 | 报表导出、威胁情报联动、更多厂商官方插件 |

---

## 🤝 贡献

欢迎贡献设备插件、Bug 修复、文档完善。请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 与 [docs/plugin-dev.md](docs/plugin-dev.md)，提交 PR 前确保 `pytest` 与 `npm run build` 通过。

---

## ⚠️ 风险与免责声明

1. 自动封禁属于高风险操作，请在测试环境充分验证规则，合理配置 Graylog 告警条件，避免误封业务 IP；
2. 本平台仅提供自动化编排能力，**不保证无漏报、无误报**，不替代人工安全运营；
3. 因使用本平台造成业务中断、封禁误判等损失，开发者不承担相关责任；
4. 禁止用于未经授权的网络攻击、恶意封禁等违法场景；
5. 开源前请按 [docs/security.md](docs/security.md) 完成凭据脱敏自查。

---

## 👤 作者与联系

- **维护者**：宙斯盾 AegisSoc 团队
- **邮箱**：[30002811@qq.com](mailto:30002811@qq.com)
- **问题反馈**：[GitHub Issues](https://github.com/aegis-soc/aegis-soc/issues)
- 欢迎通过邮件联系设备插件合作与二次开发事宜。

---

## 📄 License

[Apache License 2.0](LICENSE) · Copyright 2026 AegisSoc contributors
