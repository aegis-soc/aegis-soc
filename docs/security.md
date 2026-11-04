# 安全与脱敏规范

> 本项目用于安全运营自动化，会自动向网络设备下发封禁动作。**误封可能造成业务中断**，且仓库一旦公开，历史中的敏感信息无法真正"撤回"。请严格执行本规范。

## 1. 开源前脱敏自查清单（发布前必须逐项确认）

- [ ] 全仓库搜索内网地址：`10.`、`172.16.`~`172.31.`、`192.168.`、`127.0.0.1`、内部域名后缀
- [ ] 全仓库搜索口令与密钥字样：`password`、`passwd`、`api_key`、`apikey`、`secret`、`token`、`Bearer `、长哈希串
- [ ] 检查 `.env`、`*.pem`、`*.key`、`*.pfx`、`credentials*.json`、`secrets/` 是否被 `.gitignore` 排除
- [ ] 检查 `sql/seed.sql` 与 `.env.example` 中是否只有占位值或 RFC5737 文档地址
- [ ] 检查插件代码：`config_json` 示例与 `credential_ref` 中无真实设备地址/账号
- [ ] 检查 `docs/` 中的 curl / 配置示例，确认无真实 IP、主机名、Token
- [ ] 检查 `git log -p` 全历史（含已删除文件），必要时用 `git filter-repo` 清理后重新初始化
- [ ] 确认 `FW.txt` / `Block2.0.txt` / `新建文本文档.txt` 等**原始生产脚本未进入仓库**
- [ ] 确认 `GRAYLOG_WEBHOOK_SECRET`、`JWT_SECRET`、`BOOTSTRAP_ADMIN_PASSWORD` 已全部改为随机值

示例地址请统一使用 RFC5737 文档网段：`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`。

## 2. 凭据管理

| 规则 | 说明 |
|---|---|
| 不落库 | `security_device.credential_ref` 只存**环境变量名**，不存口令明文 |
| 不入代码 | 插件中任何 `host` / `username` / `password` / `api_key` 均来自 `config` |
| 不写日志 | `device_task_log.request_payload` 只记录任务号、操作、插件、IOC，不记录配置与凭据 |
| 不进镜像 | `.env`、`*.pem`、`*.key` 已在 `.dockerignore` 与 `.gitignore` 中排除 |
| 注入方式 | Compose 通过 `env_file: .env` 注入；生产建议改用 Docker Secret / K8s Secret |

配置示例（宿主机 `.env`，**不提交**）：

```bash
FW_HQ_PASSWORD='{"username":"svc_soar","password":"<真实口令>"}'
```

设备表中「凭据环境变量」填 `FW_HQ_PASSWORD`。

## 3. 平台内置安全边界

| 边界 | 实现 |
|---|---|
| 白名单优先 | 白名单独立表；告警与手动新增黑名单前先检查，命中即豁免并写 `WHITELIST_HIT` 审计 |
| 特殊地址禁止封禁 | 内网 / 环回 / 链路本地 / 组播 / 保留 / 未指定地址一律拒绝 |
| 大网段保护 | IPv4 CIDR 最大 `/16`、IPv6 最大 `/64`，避免一次封禁整个业务网段 |
| IOC 类型隔离 | 能力矩阵 `device_capability` 决定任务去向 |
| 全局熔断 | `POST /system/kill-switch` 一键暂停所有自动封禁，告警仍留痕 |
| 审批 | 策略 `require_approval=true` 时任务进入 `APPROVING`，人工通过后才下发 |
| 幂等 | `device_task.uk_task_idempotent` + Redis 去重，防止告警风暴打爆设备 API |
| 审计 | 人工操作、自动封禁、设备请求/响应报文全留痕（`operation_audit`、`device_task_log`） |
| 权限 | JWT + RBAC 三角色，接口级鉴权；仅 admin 可改熔断与查看用户 |
| 防重放 | Webhook 支持 Secret + 可选 Bearer + 时间戳窗口 |

## 4. 生产加固建议

1. **改掉所有默认值**：`JWT_SECRET`、`GRAYLOG_WEBHOOK_SECRET`、`MYSQL_*`、`BOOTSTRAP_ADMIN_PASSWORD`；
2. **HTTPS**：在 nginx 前加 TLS 终止（或 Ingress），管理界面与 Webhook 均走 HTTPS；
3. **网络隔离**：MySQL / Redis / 后端不暴露公网；管理界面限制来源 IP；
4. **最小权限**：设备侧为 SOAR 建专用账号，仅授予黑名单读写权限，禁止全量配置权限；
5. **先用 mock 演练**：新规则先在测试环境用 `mock` 插件跑通，再切真实设备；
6. **阈值与审批**：高危策略开启 `require_approval`，并调高 `min_confidence` / `threshold_count`；
7. **监控与备份**：监控 `worker` 存活、失败任务数、熔断状态；定期备份 MySQL 数据卷；
8. **日志留存**：按等保要求保留 `operation_audit` 与 `device_task_log`，配置日志轮转。

## 5. 禁止事项

- ❌ 禁止将本平台用于未经授权的网络攻击、恶意封禁等违法场景；
- ❌ 禁止在仓库、Issue、PR、截图、日志片段中粘贴真实内网资产与凭据；
- ❌ 禁止绕过白名单与内网校验逻辑（如需变更，须经评审并补充测试）；
- ❌ 禁止在生产环境使用 `docker-compose-demo.yml`（v1.1 前为占位）或 `mock` 插件承担真实封禁。

## 6. 风险与免责

1. 自动封禁属于高风险安全操作，请在测试环境充分验证规则；
2. 平台仅提供自动化编排能力，**不保证无漏报、无误报**，不替代人工安全运营；
3. 因使用本平台造成业务中断、封禁误判等损失，开发者不承担相关责任；
4. 发现安全漏洞请通过项目维护者私下反馈，不要公开提 Issue。
