# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)。

## [Unreleased]

### Added

- **阿里云 WAF 3.0 插件** `aliyun_waf_v3`：`DefenseScene=ip_blacklist`，`DescribeDefenseRules` 取全量 → 合并 → `ModifyDefenseRule` 整表回写；单规则 200 条上限（官方限制）自动分片为 `aegis-block-N`；已存在 IP 幂等跳过；写入后回读确认，避免并发覆盖导致漏封；空规则自动停用；RAM 最小权限，AK 只走 `credential_ref`，签名用 RPC HMAC-SHA1 不引入 SDK
- **插件不建模板，只推 IP**：模板由人工在 WAF 控制台预建，插件只往 `template_id` 下的 `ip_blacklist` 规则写 IP；连通性测试新增 `DescribeDefenseTemplate` 校验模板存在且场景为 `ip_blacklist`，模板 ID 填错会明确失败；新增 `auto_create_rule`（默认 `true`），设为 `false` 后连分片规则也不自动建，全部由人工建好再推
- **接入指南** `docs/plugins-aliyun-waf.md`：容量与分片规则、RAM 权限策略、模板 ID 获取、配置示例与五步验证
- **启明星辰 天清IPS 插件** `qiming_ips`：REST API v3，`POST /api/v3/login` 口令 SHA256 摘要登录取 JWT，`POST /api/v3/block_policy` 按 `type`（IP=4 / 域名=2 / URL=3 / 五元组=1 / XFF=5）封堵，`end_time` 以分钟计（0=永久）；token 按设备+账号缓存并支持 401 自动重登；只声明 BLOCK 能力，解封依赖设备端 `end_time` 到期，不伪造解封成功
- **接入指南** `docs/plugins-qiming-ips.md`：接口对应表、SHA256 与明文口令说明、设备侧准备、配置项、报文示例、五步验证与排错表
- **Palo Alto 插件** `paloalto_fw`：PAN-OS 9.1+ XML API，user-id 把 IP 注册到 DAG Tag，即时生效无需 commit；严格解析 `<response status>`，避免 200 假成功；连通性测试使用只读 `show system info`
- **启明星辰插件** `qiming_fw`：天清汉马 USG Web API，登录支持 Token / Cookie 双模式，登录路径、黑名单路径与请求体、保存生效接口全部参数化，换型号只改配置；配置保存失败整单判失败
- **接入指南** `docs/plugins-paloalto-qiming.md`：PA 侧 Tag / DAG / 策略 / API Key 四步配置与验证方法，启明 curl 三步打通法与成功判定规则
- **一键冒烟验收脚本** `scripts/smoke_test.py`：仅用 Python 标准库，覆盖界面静态资源、健康检查、登录、白名单豁免、告警接入、幂等去重、IOC 落库、插件下发、任务日志、熔断、审计与大盘共 18 项检查，退出码可直接用于发布流水线
- **验证与验收指南** `docs/verify.md`：三层验证模型（CI / 冒烟脚本 / 界面人工验收）、GitHub 上可见范围说明、三种「看到界面」的落地方式（本地 Docker / 云服务器 / Codespaces）、常见失败对照表
- **CI 工作流** `.github/workflows/ci.yml`：后端 `compileall` + `pytest`、前端 `npm ci` + `npm run build`、两份 Compose 配置校验
- **发布工作流** `.github/workflows/release.yml`：推送 `v*` tag 自动构建 `linux/amd64` / `linux/arm64` 双架构镜像并推送 `ghcr.io`，同时自动生成 GitHub Release
- **依赖自动升级** `.github/dependabot.yml`：pip / npm / GitHub Actions / Docker 基础镜像分组周更
- **云上部署与运维指南** `docs/deploy-cloud.md`：资源基线（2C4G 起）、主机初始化与安全加固、安全组与端口、HTTPS 启用、定时备份与恢复演练、Docker 日志轮转、审计表归档清理、上线自检清单、故障速查
- HTTPS 参考配置 `deploy/nginx/nginx-https.conf`（可选启用，默认仍用 HTTP 配置；证书目录不入库）
- `docs/install.md` 新增「使用预构建镜像」章节，云主机可跳过前端本地构建

### Changed

- **插件层不再"假成功"**：`BasePlugin.query_status()` 默认由返回成功改为返回失败（未实现即失败）；SSH 插件改为校验设备回显，命中 `% Invalid input` / `Unrecognized command` / `Permission denied` 等特征或提示符超时时判失败；深信服插件校验 `applyconfig` 生效结果，接口成功但配置未生效时判失败
- **插件配置统一校验**：新增 `required_config` 与 `BasePlugin.validate_config()`，`execute()` 与连通性测试前统一校验必填项与 `credential_ref` 注入结果，缺项返回「插件配置错误」而非设备侧报错
- **连通性测试不再 500**：新增 `BasePlugin.safe_test_connection()`，`POST /plugins/test` 与设备连通性测试遇到的任何异常都收敛为结构化失败结果
- 插件注册时校验能力声明：`capabilities` 出现未知动作直接拒绝启动，避免 manifest 与实现不一致
- 布尔/整数配置统一走 `as_bool()` / `as_int()`，修复字符串 `"false"` 被当成 True（自签证书设备 SSL 校验失效）的问题
- `docs/plugin-dev.md` 补充 `required_config` 用法与"不得假成功"硬性规范；新增 `backend/tests/test_plugins.py` 12 项回归测试
- 前端镜像构建改为 `npm ci`（严格按 `package-lock.json`），镜像构建可复现
- 项目正式命名为「宙斯盾 AegisSoc」，定位升级为**通用安全运营自动化 AI+SOC 平台**
- 仓库名、Compose 项目名、数据库名 / 用户名、Celery 队列与任务名、Redis 键前缀、logger 名、npm 包名中的旧项目标识统一迁移为 `aegis*`
- 外部日志平台 `Graylog` 的 Webhook 接口、`GRAYLOG_*` 变量与文档表述保持原名，未受影响

## [1.0.0] - 2026-11-03

首发版本，对应《通用安全运营自动化平台需求说明书与架构方案 V1.0》的 MVP 闭环。

### Added

- **平台底座**：FastAPI + SQLAlchemy 2.0 + Pydantic v2，统一响应格式与全局异常处理，JWT + RBAC（`admin` / `operator` / `auditor`）
- **数据层**：20 张业务表（附录 A 全量 DDL），首次启动自举角色、管理员、默认策略、示例设备与白名单
- **告警接入**：`POST /api/v1/alerts/graylog`（Secret + 时间戳防重放 + `uk_alert_id` 去重）与 `POST /api/v1/alerts/generic`，快速返回 `accepted`
- **IOC 管理**：IP / 域名黑名单 CRUD、来源标记、标签备注、过期时间；IP 白名单 CRUD、CIDR 批量导入与包含检查
- **硬性安全边界**：白名单优先豁免、内网/环回/保留地址禁止封禁、CIDR 最小网段约束、IOC 类型与设备能力矩阵匹配
- **策略引擎**：阈值、置信度、风险等级、时间窗、审批开关、封禁时长、全局熔断
- **异步执行**：Celery Worker + Beat，幂等任务、指数退避重试、状态回执与请求/响应报文留痕、到期自动解封
- **插件网关**：Manifest 能力声明 + 注册式插件框架，内置 `mock` / `http_generic` / `ssh_firewall` / `sangfor_ips`
- **管理界面**：Vue3 + Element Plus，登录、大盘、告警、黑名单、白名单、设备、插件、策略、任务、审计、系统设置（熔断开关）
- **可观测与审计**：全链路 `operation_audit`、`device_task_log`、健康检查 `/api/healthz`、Swagger `/api/docs`
- **交付**：Apache 2.0、两套 Dockerfile、7 容器 Docker Compose、`docs/` 六篇文档、单元测试与端到端 mock 链路测试

### 暂未包含（规划 v1.1）

AI 安全巡检插件实现、可视化 DAG 工作流编排、审批流增强、DMZ 中转 Agent、Demo 模式全套 Graylog 编排、插件独立进程/签名校验。详见 README Roadmap。
