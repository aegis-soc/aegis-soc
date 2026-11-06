# API 参考

交互式文档：`http://<host>:8080/api/docs`（FastAPI 自动生成 OpenAPI 3）。
所有业务接口前缀：`/api/v1`。

## 1. 统一返回格式

```json
{ "code": 0, "msg": "success", "data": { } }
```

| code | HTTP | 含义 |
|---|---|---|
| 0 | 200 | 成功 |
| 400 | 400 | 参数非法 / 业务校验失败（如内网 IP 禁止封禁、IP 格式错误） |
| 401 | 401 | 未登录、凭证过期、用户名或口令错误 |
| 403 | 403 | 权限不足、Webhook Secret 无效、**命中白名单禁止封禁** |
| 404 | 404 | 资源不存在 |
| 500 | 500 | 服务内部异常（详情见服务端日志） |

列表接口统一返回：

```json
{ "code": 0, "data": { "items": [], "total": 0, "page": 1, "page_size": 20 } }
```

分页参数：`page`（默认 1）、`page_size`（默认 20，最大 200）。

## 2. 鉴权

| 方式 | 适用 |
|---|---|
| `Authorization: Bearer <JWT>` | 除登录、Graylog Webhook、健康检查外的所有接口 |
| `?secret=<GRAYLOG_WEBHOOK_SECRET>` 或 `X-Graylog-Secret` | `POST /alerts/graylog` |
| 无鉴权 | `POST /auth/login`、`GET /api/healthz`、`GET /system/status`、`GET /api/docs` |

JWT 有效期由 `JWT_EXPIRE_MINUTES` 控制（默认 480 分钟）。

RBAC 角色：

| 角色 | 权限 |
|---|---|
| `admin` | 全部（含用户管理、熔断开关、改密） |
| `operator` | 告警、IOC、白名单、设备、插件、策略、任务的读写；审计只读 |
| `auditor` | 全部只读 |

## 3. 接口清单

### 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/auth/login` | 登录，返回 `access_token` / `must_change_password` |
| POST | `/auth/password/change` | 修改口令（首次登录强制） |
| GET | `/auth/me` | 当前用户信息 |

### 告警

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/alerts/graylog` | Graylog Webhook（Secret 校验、去重、快速 `accepted`） |
| POST | `/alerts/generic` | 通用告警入口（需 JWT） |
| GET | `/alerts` | 告警列表（`status` / `source_system` / `keyword`） |
| GET | `/alerts/{id}` | 告警详情 |

`POST /alerts/graylog` 响应示例：

```json
{
  "code": 0,
  "data": {
    "status": "accepted",
    "alert_id": "demo-001",
    "duplicated": false,
    "ioc_count": 1,
    "task_count": 1,
    "message": "命中策略 default-auto-block，生成 1 个任务"
  }
}
```

### IOC 黑名单

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/ioc/ips` | IP 黑名单列表 |
| POST | `/ioc/ips` | 新增 IP 黑名单（白名单命中返回 403；`dispatch` 控制是否立即下发） |
| GET | `/ioc/ips/{id}` | 详情 |
| PUT | `/ioc/ips/{id}` | 更新置信度/风险/过期/标签/备注/状态 |
| DELETE | `/ioc/ips/{id}` | 删除并自动生成 `UNBLOCK` 任务 |
| GET | `/ioc/domains` | 域名黑名单列表 |
| POST | `/ioc/domains` | 新增域名黑名单 |
| GET | `/ioc/domains/{id}` | 详情 |
| DELETE | `/ioc/domains/{id}` | 删除并生成解封任务 |

`POST /ioc/ips` 请求示例：

```json
{
  "ioc_value": "8.8.8.8",
  "confidence": 85,
  "risk_level": "high",
  "duration_seconds": 7200,
  "tags": ["bruteforce"],
  "remark": "Graylog 告警联动",
  "dispatch": true
}
```

`GET /ioc/ips` 支持 `status`（`active` / `rejected` / `whitelisted` / `expired` / `disabled`）、
`source_type`（`IPS` / `WAF` / `ZTNA` / `TI` / `GRAYLOG` / `MANUAL` / `API` …）、
`country`（归属国家精确匹配，如 `中国`）、
`keyword`（匹配 IP、备注、来源明细、告警 ID、国家/省/市）四个过滤条件。

列表项在原有字段外新增：

| 字段 | 说明 |
|---|---|
| `created_at` | 添加时间（每次入库固定，界面「添加时间」列） |
| `source_type` | 来源分类，如 `WAF`、`IPS`、`ZTNA`、`TI` |
| `source_detail` | 来源原始标识：设备名 / stream / vendor |
| `alert_id` | 触发该记录的告警 ID |
| `reject_reason` | 被拦截/豁免的原因，或到期未解封的说明 |
| `geo_country` | 归属国家（中文，如 `中国` / `美国`；内网地址为 `内网`） |
| `geo_province` / `geo_city` | 归属省 / 市，境外为英文原文 |
| `geo_isp` | 运营商（如 `电信`、`Google LLC`），库中无则为 `null` |
| `geo_region` | `geo_province` 与 `geo_city` 合成的展示字段（直辖市去重） |

> 归属地来自 ip2region 离线库，**入库后由后台线程异步回填**（通常亚秒级完成），
> 记录创建接口会立即返回，不等 geo 查询；库未安装时该组字段保持 `null`，
> 不影响入库与封禁。**没有独立的归属地查询接口**——列表接口的 
> `country` 参数与 `keyword`（覆盖国家/省/市）即可满足筛选。详见 `docs/geoip.md`。

> 黑名单是**流水表，同值不合并**：同一 IP 多次命中会生成多条记录，
> 各自带添加时间与过期时间。规则细节见 `docs/blacklist-history.md`。

### 白名单

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/whitelist/ips` | 白名单列表 |
| POST | `/whitelist/ips` | 新增（单 IP / CIDR），`unblock_existing=true` 时自动解封网段内已下发黑名单 |
| POST | `/whitelist/ips/import` | 批量导入（`text`，每行一条，支持 `#` 注释） |
| GET | `/whitelist/ips/check?ip=` | 检查 IP 是否命中白名单 |
| DELETE | `/whitelist/ips/{id}` | 删除白名单 |

### 设备与插件

| 方法 | 路径 | 说明 |
|---|---|---|
| GET / POST | `/devices` | 设备列表 / 新增 |
| PUT / DELETE | `/devices/{id}` | 更新 / 删除 |
| POST | `/devices/{id}/test` | 连通性测试并同步状态 |
| GET | `/plugins` | 插件清单（含 Manifest） |
| POST | `/plugins/test` | 插件连通性测试 |

### 策略

| 方法 | 路径 | 说明 |
|---|---|---|
| GET / POST | `/policies` | 策略列表 / 新增 |
| GET / PUT / DELETE | `/policies/{id}` | 详情 / 更新 / 删除 |
| POST | `/policies/{id}/toggle` | 启停 |

关键字段：`priority`、`min_confidence`、`threshold_count` + `window_minutes`、`risk_levels`、`target_plugins`、`block_duration`、`require_approval`、`auto_dispatch`。

### 任务

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/tasks` | 任务列表（`task_status` / `operation` / `keyword`） |
| GET | `/tasks/{id}` | 任务详情 + `device_task_log` 请求/响应留痕 |
| POST | `/tasks/{id}/retry` | 人工重试 |
| POST | `/tasks/{id}/cancel` | 取消 |
| POST | `/tasks/{id}/approve?approve=true|false&reason=` | 审批通过 / 拒绝 |
| GET | `/tasks/metrics/summary` | 状态汇总 |

任务状态：`PENDING` / `RUNNING` / `SUCCESS` / `FAILED` / `RETRY` / `CANCELED` / `APPROVING` / `REJECTED`。

### 审计、大盘、系统

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/audit` | 审计日志（`op_type` / `operator`） |
| GET | `/dashboard` | 首页统计与最近告警 |
| GET | `/system/status` | 版本、环境、缓存、熔断、插件数 |
| GET / POST | `/system/kill-switch` | 读取 / 设置全局自动封禁熔断 |
| GET | `/system/users` | 用户列表（仅 admin） |
| GET | `/api/healthz` | 健康检查（非 `/api/v1` 前缀） |

## 4. 关键业务规则（调用方需知）

1. **白名单优先**：命中白名单的地址一律豁免，手动加入黑名单返回 `403`；
2. **内网/保留地址禁止封禁**：`10./172.16-31./192.168./127./169.254./224./RFC5737 文档地址` 等一律拒绝，CIDR 最大 `/16`（IPv6 `/64`）；被拒绝的 IOC 仍会以 `status=rejected` 留在黑名单表（`reject_reason` 记录原因），只是不下发任务；
3. **IOC 类型隔离**：任务只下发给在能力矩阵中声明了对应 `ioc_type` 的设备；
4. **幂等**：同一 `request_id` + IOC + 设备 + 操作只生成一个任务；重复告警返回 `duplicated: true`；
5. **熔断**：开启后新告警只留痕，`task_count = 0`；
6. **异步**：告警接口不等设备返回，任务结果查 `/tasks/{id}`。
