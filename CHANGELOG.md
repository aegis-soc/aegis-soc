# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)。

## [Unreleased]

### Added

- **一键冒烟验收脚本** `scripts/smoke_test.py`：仅用 Python 标准库，覆盖界面静态资源、健康检查、登录、白名单豁免、告警接入、幂等去重、IOC 落库、插件下发、任务日志、熔断、审计与大盘共 16 项检查，退出码可直接用于发布流水线
- **验证与验收指南** `docs/verify.md`：三层验证模型（CI / 冒烟脚本 / 界面人工验收）、GitHub 上可见范围说明、三种「看到界面」的落地方式（本地 Docker / 云服务器 / Codespaces）、常见失败对照表
- **CI 工作流** `.github/workflows/ci.yml`：后端 `compileall` + `pytest`、前端 `npm ci` + `npm run build`、两份 Compose 配置校验
- **发布工作流** `.github/workflows/release.yml`：推送 `v*` tag 自动构建 `linux/amd64` / `linux/arm64` 双架构镜像并推送 `ghcr.io`，同时自动生成 GitHub Release
- **依赖自动升级** `.github/dependabot.yml`：pip / npm / GitHub Actions / Docker 基础镜像分组周更
- **云上部署与运维指南** `docs/deploy-cloud.md`：资源基线（2C4G 起）、主机初始化与安全加固、安全组与端口、HTTPS 启用、定时备份与恢复演练、Docker 日志轮转、审计表归档清理、上线自检清单、故障速查
- HTTPS 参考配置 `deploy/nginx/nginx-https.conf`（可选启用，默认仍用 HTTP 配置；证书目录不入库）
- `docs/install.md` 新增「使用预构建镜像」章节，云主机可跳过前端本地构建

### Changed

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
