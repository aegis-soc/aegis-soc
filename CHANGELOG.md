# Changelog

本项目遵循 [Semantic Versioning](https://semver.org/)。

## [Unreleased]

### 一键安装（Linux / Docker）

- **新增 `scripts/install.sh`**：一条命令完成「检查 Docker → 生成随机密钥的 `.env` → 构建并启动 → 轮询 `/api/healthz` → 打印访问地址、初始口令、Graylog 回调地址」；支持 `--port` / `--admin-password` / `--install-docker` / `--no-build`，可重复执行（已存在的 `.env` 不覆盖）
- **修复 CRLF 部署坑**：`.env.example`、`docker-compose.yml`、`Makefile`、`deploy/nginx/nginx.conf`、`sql/*.sql` 原先以 CRLF 入库，Linux 上克隆后 `.env` 的值会带 `\r`，导致 `DATABASE_URL` 解析失败、api 反复重启；新增 `.gitattributes` 强制这些运行期文件使用 LF，脚本额外做一次去 CR 兜底
- **修复反代超时**：nginx `/api/` 的 `proxy_read_timeout` 由 60s 放宽到 180s——人机对话与日志巡检会同步等 MCP，单流 30s × 三流会超过 60s 被 504
- **文档**：`docs/install.md` 第 2 节拆为 2.1 一键安装 / 2.2 手动分步 / 2.3 预构建镜像；中英 README 快速部署各补一条命令说明

### 人机对话（自然语言查询）

- **新增「人机对话」主菜单**：中文提问自动路由——查平台数据（黑名单 / 告警 / 下发 / 设备）走 MySQL，查攻击日志走 Graylog MCP 三流；返回结论 + 明细表 + 柱图 + 编译后的查询
- **不做 text2SQL**：路由层只产出受控 DSL（`app/services/chat/dsl.py`），由 `compiler_db` / `compiler_log` 翻译成 SQLAlchemy 查询或 MCP 检索；模型/规则拿不到任何表对象，也拼不出字符串 SQL
- **纯规则、无模型依赖**：六类词表（数据源 / 指标 / 维度 / 时间 / 动作 / 数字）+ 最长优先匹配 + 缺省补全 + 置信度；12 条例句进回归用例，`帮我看看` 这类直接转澄清并给推荐问法
- **语义目录** `app/services/chat/catalog.py`：数据源 / 维度 / 指标 / 词表 / 排除表集中一处，新增问法大多只加词条；`system_user`、`patrol_setting` 等敏感表被显式排除
- **护栏**：只生成 `SELECT`（测试断言无 DML 关键字）、过滤值全走绑定参数、`LIMIT ≤ 200`、子查询 ≤ 3、日志时间窗 ≤ 7 天、MySQL 尝试 `MAX_EXECUTION_TIME=10s`、单用户 20 次/分钟、审计 `CHAT_ASK`
- **结论用模板拼**：事实句 + 阈值判断句（集中度 ≥50%、环比 ±10%），当天未走完的数据不计入环比；日志路径把「已在黑名单」「内网地址」「疑似漏封」分开说，不把内网扫描算成漏封
- **会话落库** `chat_session` / `chat_message`（`blocks` 存渲染块、`dsl` 存当次解析、`trace` 存编译后的查询）；接口 `POST /chat/ask`、`GET/DELETE /chat/sessions[/{id}]`、`GET /chat/catalog`；权限新增 `chat:ask`（operator / auditor 补齐）
- **页面**：左侧会话列表、气泡对话、KPI / 表格 / 柱图 / 口径说明四种块、推荐问法 chips、`查看查询详情` 折叠显示路由与 SQL；MySQL 老库执行 `sql/migrate_20261110_chat.sql`
- **文档** `docs/chat-nlq.md`：DSL 示例、语义目录、护栏、已覆盖问法、扩展步骤与排错顺序

### 日志巡检 P0（读 Graylog 日志补漏）

- **新增「日志巡检」主菜单**：通过 MCP 只读查询 Graylog 三流日志（IPS / WAF / 零信任），每 5 分钟一轮，用确定性规则找出 Graylog 告警规则漏掉的攻击源；本轮只出报告，不创建黑名单、不下发封禁（`blocked` 恒为 0）
- **MCP 客户端**（`app/services/mcp_client.py`）：Streamable HTTP + JSON-RPC，握手/会话维持/tools.list/tools.call，兼容 JSON 与 SSE 两种响应，纯标准库无额外依赖
- **适配 Graylog 原生 MCP**：鉴权用 `Authorization: Token <API_TOKEN>`（`PATROL_MCP_AUTH` 可改 bearer/basic/raw）；POST 被 404/405 拒绝时自动降级为旧版 HTTP+SSE；参数按工具 `inputSchema` 自动映射（只传服务端声明过的字段）；新增 `list_streams` 流发现，页面上可直接看流 id 并核对配置是否指向已不存在的流
- **L1 规则**：IPS 未阻断、WAF 放行、零信任认证爆破、高频访问、跨流命中、情报命中；字段名按常见候选名自动匹配，换设备只改映射表
- **窗口游标与重叠**：起点取上一轮终点减重叠秒数，最多回看 6 小时；非公网地址只计数不落候选，单轮候选上限 200
- **处置预判**：白名单 / 已封 / 24h 重复分别标记为 `skipped_*`，其余为 `would_block`，为 P1 接自动封禁做准备
- **新表** `patrol_run` / `patrol_candidate`（SQLite 启动自动建表；MySQL 执行 `sql/migrate_20261108_patrol.sql`），接口 `POST /patrols/run`、`GET /patrols[/latest|/{id}]`、`GET /patrols/mcp/status`，权限沿用 `inspection:read|run`
- **页面**：KPI 条、日志流状态与规则命中、候选明细（原因标签 + 处置预判）、历史批次抽屉；「MCP 连通性」按钮可直接看到服务端信息与工具清单
- **文档** `docs/graylog-patrol.md`：规则表、配置项、字段映射与接真实 MCP 的排查顺序

### 日志巡检配置界面（页面维护，无需改 .env）

- **新增「MCP 配置」抽屉**：地址、API Token、鉴权方式、三流映射、巡检间隔/重叠/重复标记/单轮上限、高级工具名与参数模板一次配齐；保存后下一轮即生效，不重启后端与 Beat
- **配置落库** `patrol_setting`（单行；SQLite 自动建表，MySQL 执行 `sql/migrate_20261109_patrol_setting.sql`），优先级 **数据库 > 环境变量**，首次无库行时页面提示「当前值来自环境变量」
- **token 只写不读**：接口仅回 `token_set` 与尾号（如 `abcd***7890`）；保存时留空=保持原值，需勾选「清除」才清空；每次保存写审计 `PATROL_CONFIG_UPDATE`（不记明文）
- **保存前试连** `POST /patrols/mcp/test`：用表单草稿真实握手，回传服务端/传输方式/工具清单，并把流清单灌进下拉框，不落库
- **流清单直接选**：配置页可「从 Graylog 拉取流清单」，三流下拉选择 stream id，选中的 id 不在清单里会提示
- **Beat 改为每分钟唤醒**，实际间隔由任务按「距上轮时间」判断，所以页面改间隔立即生效
- **权限**：查看 `inspection:read`；保存与试连限管理员 `system:*`；默认角色补齐 operator `inspection:read/run`、auditor `inspection:read`

### 安全效果巡检（v2，两层 12 项）

- **AI 巡检（新主菜单）**：从「平台体检」深化为「安全效果 + 平台运行」两层 12 项检查——新增三流覆盖（IPS/WAF/ZTNA）、封禁缺口归因（该封未封及原因分布）、处置率（24h/7d 含趋势）、持续攻击源（跨 ≥3 天重复出现，给出建议封禁时长）4 个安全效果项
- **加权评分**：封禁缺口与处置率权重 2.0、设备连通与到期解封 1.5、白名单与攻击态势 0.5——设备全在线但该封的没封，健康分不再是满分
- **KPI 快照落库**：`inspection_report` 新增 `metrics` JSON 列（处置率、缺口 IP、豁免数、持续攻击、核心三流覆盖、封禁节奏峰值、较上次分数变化），报告可横向对比
- **巡检报告落库可回看**：历史报告分页与详情弹窗，历史表带处置率与分数环比；MySQL 建表见 `sql/init.sql`，老库执行 `sql/migrate_20261107_inspection.sql`（含角色权限与 `metrics` 列补充）
- **AI 总结（增强而非依赖）**：配置 OpenAI 兼容接口（`AI_LLM_BASE_URL` / `AI_LLM_API_KEY` / `AI_LLM_MODEL`）后总结由大模型生成（提示词带缺口语境），失败或未配置自动回退内置规则总结
- **说明文档** `docs/ai-inspection.md`：12 项检查表、缺口归因口径（白名单/内网豁免不计入分母）、权重表与 metrics 示例

### 黑名单导入导出

- **IP / 域名黑名单批量导入**：粘贴文本或上传 txt/csv（UTF-8/GBK 兼容，单次 ≤5000 行），支持 `值,备注` / `值 # 备注` / `#注释` 三种写法；新增、已存在跳过、白名单豁免分别计数，内网与非法格式逐行给出原因；整批共用一个 request_id 生成封禁任务，一次提交一次下发
- **按当前筛选条件导出 CSV**：状态/来源/国家/关键词筛选原样生效，UTF-8 BOM 编码 Excel 直接打开不乱码，IP 导出含归属地四列

### Added

- **归属地异步回填，不阻塞入库**：告警处置与手工新增不再同步查 geo——记录先落库并返回，`geoip.schedule_fill()` 把 ID 交给后台线程补齐（同批去重、异常只记日志），`scripts/backfill_geo.py` 可随时兜底
- **取消独立归属地接口**：移除 `GET /ioc/geo/countries`，国家筛选复用 `GET /ioc/ips?country=`；前端国家下拉改为内置常用列表（可输入任意国家名过滤）
- **README 界面预览**：新增「界面预览」章节，展示首页大盘、IP 黑名单（流水/来源/归属地）、设备可视化配置表单、插件管理四张截图（`docs/screenshots/`）
- **IP 归属地（国家 / 省·市）**：黑名单新增「国家」「地区」两列，数据来自 ip2region 离线库（`backend/data/ip2region_v4.xdb`，约 11 MB），国内城市级中文、境外 ISO 码映射中文国名；内网地址直接标「内网」，RFC5737 保留段标「保留地址」
- **归属地快照落库**：`ioc_indicator` 新增 `geo_country` / `geo_province` / `geo_city` / `geo_isp`，写入时查一次并固化，库更新不改写历史记录；老记录由 `scripts/backfill_geo.py` 幂等回填
- **归属地运维工具**：`scripts/fetch_geoip.py` 多镜像下载 xdb（jsdelivr / ghfast / GitHub，直连与代理都试，校验文件头与体积后才替换）；服务按 mtime 热加载，换库不重启
- **按国家筛选**：`GET /ioc/ips?country=中国`，关键字搜索覆盖国家/省/市（同版本内取消了独立国家接口，筛选复用列表参数）
- **文档** `docs/geoip.md`：为什么放弃 ipip.net、数据格式、更新节奏、精度局限与排障；`GET /api/healthz` 增加 `geoip` 就绪状态

- **黑名单改为流水表（同值不合并）**：去掉 `ioc_indicator` 上的 `uk_ioc(ioc_type, normalized_value)` 唯一键，同一 IP 每次命中都新增一条记录，各自保留添加时间、过期时间、来源告警；解决「设备不支持按 IP 解封、只能等到期失效」场景下无法判断哪次下发还在生效的问题
- **来源字段** `source_type` / `source_detail` / `alert_id`：从 Graylog 告警的 `device_type` / `device_name` / `product` / `vendor` / `stream` 等字段识别来源，统一归类为 `IPS` / `WAF` / `ZTNA` / `TI` / `NTA` / `AV` / `FW` / `GRAYLOG`，界面「来源」列展示分类，悬浮显示设备名与告警 ID
- **被拦截 IOC 留痕**：内网/保留地址、白名单命中的 IOC 以 `status=rejected` / `whitelisted` 写入黑名单表并记录 `reject_reason`，不下发任务；列表与看板（新增 `ioc_rejected` 统计）可直接回答「为什么这个攻击 IP 没被封」
- **迁移脚本** `sql/migrate_20261105_ioc_history.sql`：MySQL 可重复执行，补字段 → 删唯一键改 `idx_ioc_value` → 回填历史来源；SQLite 由 `app/migrations.py` 在启动时自动升级，分步可重入，中途失败下次启动自动补齐
- **说明文档** `docs/blacklist-history.md`：为什么不再合并、状态机、解封去重规则、升级步骤与常见问题

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

- **配置项** 新增 `GEOIP_ENABLED`（默认 true）与 `GEOIP_DB_PATH`；库缺失或依赖未安装时归属地留空，**不影响告警入库与封禁**
- **依赖** 增加 `py-ip2region>=3.0.6`（纯 Python，约 10 KB）；`docker` / 部署环境需执行一次 `python scripts/fetch_geoip.py`
- **黑名单界面**：新增「添加时间」「来源」列，状态增加 `rejected` / `whitelisted` 筛选项，拦截原因以状态悬浮提示展示；`GET /ioc/ips`、`GET /ioc/domains` 支持 `source_type` 过滤，`keyword` 扩展到来源明细与告警 ID；看板活跃黑名单卡片补充「被拦截」数量
- **解封链路按 IP 去重**：同 IP 多条流水记录时，到期扫描与白名单批量解封只对该 IP 下发一次 `UNBLOCK`；若同 IP 仍有更晚到期的记录在生效，则只标记过期、不解封；手动解封一条记录会同步把该 IP 其它 `active` 记录置为 `disabled`
- **设备配置改成可视化表单**：选择插件后，界面按插件的 `config_schema` 自动生成表单——地址类字段置顶为「① 设备连接」，业务参数归「② 业务参数」，`int` 渲染数字框、`bool` 渲染开关、`a | b` 渲染下拉、`object` 渲染 JSON 输入；说明里的「必填」「默认 xxx」自动转成校验与预填值；保留「高级模式」可切回原始 JSON 双向同步；设备列表新增「设备地址」列与「编辑」按钮；弹窗内新增「测试连接」，保存前即可验证地址与凭据
- **后端新增结构化字段描述** `build_config_fields()`（`plugins/base.py`）：由 `config_schema` + `required_config` 推导 `key / label / group / type / required / options / default / description`，`/api/v1/plugins` 直接返回，新增插件无需改前端；凭据类字段（`credential_ref`/`password`/`api_key`/`access_key_secret`）从表单中剔除
- **凭据解析抽出 `apply_credential()`**：`/plugins/test` 支持在设备保存前按 `credential_ref` 读取环境变量，未设置时返回「凭据环境变量 XXX 未设置」而不是 500
- `DeviceUpdateIn` 支持修改 `vendor` / `model`
- **插件执行接口升级为「设备 + 请求」**（v1.1 P1）：新增 `DeviceTarget`（一台具体设备：`code`/`address`/三层配置/`limits`）与 `ActionRequest`（IOC 与动作），插件方法统一为 `block(target, req)` / `unblock(target, req)` / `query_status(target, req)`；`registry.execute(target, req)` 为推荐入口，旧签名 `execute(code, op, ioc, ioc_type, config)` 仍兼容
- **设备配置分三层**：`connection`（地址/端口/TLS/超时）、`params`（业务参数）、`secrets`（凭据），支持 `{"connection":{...},"params":{...}}` 分层写法与历史扁平写法混用；合并优先级 `params < connection < secrets`，凭据永远最后覆盖
- 8 个内置插件全部迁移到新签名；worker 执行时按设备构造 `DeviceTarget`，日志输出 `task / device / plugin / op / ioc / 结果`，排查可直接定位到设备
- `docs/plugin-dev.md` 更新插件模板与设备配置章节，说明「插件是类型、设备是实例」与分层配置规则
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
