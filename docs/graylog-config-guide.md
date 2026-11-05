# Graylog 告警 Webhook 配置指南

平台**不改造 Graylog**，只使用其原生 Alert / Event Definition 的 HTTP Notification。任意已有 Graylog 5.x / 6.x 集群均可接入。

## 1. 接入原理

```
Graylog Event Definition（判定逻辑留在 Graylog）
        │ HTTP POST application/json
        ▼
POST http://<soar>/api/v1/alerts/graylog?secret=<GRAYLOG_WEBHOOK_SECRET>
        │  Secret 校验 →（可选）Bearer 校验 →（可选）时间戳防重放
        ▼
告警去重 → 白名单优先 → IP 校验 → 策略匹配 → 异步封禁任务
```

告警接口**只做校验与入库，立即返回 `accepted`**，设备下发在 Celery Worker 中异步完成，避免 Graylog 通知超时。

## 2. 配置步骤

### 2.1 创建 / 确认 Event Definition

在 Graylog 中：`Alerts → Event Definitions → Create event definition`。

示例（WAF 暴力破解）：

| 项 | 值 |
|---|---|
| Title | `WAF 暴力破解告警` |
| Condition | Aggregation：`count(src_ip) > 20`，时间窗 5 分钟 |
| Group by | `src_ip` |
| Fields | 建议输出 `src_ip`、`severity`、`confidence` |
| Priority | `High`（对应 priority = 3） |

> 告警判定、阈值、聚合全部在 Graylog 完成；平台侧的策略再做二次门槛（置信度、阈值、风险等级、审批）。

### 2.2 创建 HTTP Notification

`Alerts → Notifications → Create notification`：

| 项 | 值 |
|---|---|
| Type | `HTTP Notification` |
| URL | `http://<soar地址>:8080/api/v1/alerts/graylog?secret=你的SECRET` |
| HTTP Method | `POST` |
| Content Type | `application/json` |
| (可选) Headers | `Authorization: Bearer <GRAYLOG_BEARER_TOKEN>` |
| Body | 使用 Graylog 默认 Event 模板（见下） |

Graylog 默认推送的 JSON 大致如下（平台按字段容错解析，不依赖固定结构）：

```json
{
  "event_definition_id": "xxxx",
  "event_definition_title": "WAF 暴力破解告警",
  "event": {
    "id": "01H...",
    "timestamp": "2026-11-03T10:00:00.000Z",
    "priority": 3,
    "message": "攻击源 8.8.8.8 触发规则",
    "fields": {
      "src_ip": "8.8.8.8",
      "confidence": 90,
      "risk_level": "high"
    }
  },
  "backlog": []
}
```

### 2.3 关联到 Event Definition

在 Event Definition 的 `Notifications` 中选中上一步创建的通知并保存。

## 3. 平台解析哪些字段

| 用途 | 优先读取的字段（按优先级） | 缺省 |
|---|---|---|
| 告警唯一 ID（去重） | `event.id` → `id` → `alert_id` → `event_id` | 由 `event_definition_id` + `timestamp` + 报文哈希生成 |
| 标题 | `event_definition_title` → `title` → `event.message` | 空 |
| 严重度 | `severity` / `risk_level` / `event.severity` → `event.priority` 映射 | `medium` |
| 风险等级 | `risk_level` → `event.risk_level` → 由严重度映射 | `medium` |
| 置信度 | `confidence` / `threat_confidence` / `event.confidence` | `80.0` |
| IP IOC | 键名 `src_ip` `source_ip` `attack_ip` `attacker_ip` `client_ip` `ip` `src` 等；同时从 `message` 文本正则提取 | 无 |
| 域名 IOC | 键名 `domain` `hostname` `host` `fqdn` `dns_name` | 无 |
| 来源分类 | `source_type` / `event_source` / `log_type` / `device_type` / `product` / `vendor` / `device_name` / `syslog_appname` / `stream` / `collector` / `source`，最后才看标题与 message | `GRAYLOG` |
| 来源明细 | 命中的那个值；优先取 `device_name` → `product` → `vendor` → `stream` → `log_source` | 空 |

**优先级映射**：`1→low`、`2→medium`、`3→high`、`4→critical`。
**排除键**：`dst_ip` / `dest_ip` / `destination_ip` / `target_ip` / `dip` / `server_ip` 不会被当作攻击源封禁。
**被拦截也留痕**：内网/保留地址、白名单命中的 IOC 不下发任务，但会在黑名单表留一条
`status=rejected` / `whitelisted` 的记录，界面可直接看到拦截原因。

**来源分类识别规则**（关键词命中即归类，大小写不敏感，英文按词边界匹配）：

| 分类 | 命中关键词（示例） |
|---|---|
| `IPS` | `ips`、入侵防御、天清、ngips、suricata |
| `WAF` | `waf`、web应用防火墙、modsecurity、雷池 |
| `ZTNA` | 零信任、`ztna`、`sdp`、`atrust` |
| `TI` | 威胁情报、`threat_intel`、微步、`threatbook`、`virustotal` |
| `NTA` | 态势感知、态感、`nta`、全流量、`ndr` |
| `AV` | 防病毒、`antivirus`、`edr`、终端检测 |
| `FW` | 防火墙、`firewall`、`fortigate`、`paloalto` |

> 想让黑名单里的「来源」列准确，最省事的做法是在 Graylog 的 Event Definition 里
> 补一个 `device_type` 或 `device_name` 字段（如 `WAF` / `天清IPS-01` / `零信任网关`），
> 平台会翻译成统一分类并保留明细；识别不到时记为 `GRAYLOG`。

## 4. 安全校验

| 机制 | 说明 |
|---|---|
| Secret | URL query `?secret=` 或请求头 `X-Graylog-Secret`，常量时间比较 |
| Bearer（可选） | 配置 `GRAYLOG_BEARER_TOKEN` 后强制校验 `Authorization` 头 |
| 时间戳防重放（可选） | 请求头 `X-Graylog-Timestamp`（Unix 秒），偏差超过 `ALERT_REPLAY_TOLERANCE`（默认 300s）拒绝 |
| 去重 | `alert_event.uk_alert_id` 唯一键 + Redis `aegis:alert:<id>` 窗口（`ALERT_DEDUPE_TTL`，默认 3600s） |

> Graylog 原生 HTTP Notification 不支持动态时间戳头；如需防重放，可在 Graylog 前加一层转发代理，或使用 `generic` 入口自行构造。

## 5. 快速验证（无需 Graylog）

> 下面示例使用 `.env.example` 的默认占位 Secret，便于原样复制验证；正式部署请替换为 `.env` 中自己的 `GRAYLOG_WEBHOOK_SECRET`。

```bash
curl -X POST "http://127.0.0.1:8080/api/v1/alerts/graylog?secret=change-me-graylog-webhook-secret" \
  -H "Content-Type: application/json" \
  -H "X-Graylog-Timestamp: $(date +%s)" \
  -d '{
    "event_definition_title": "WAF 暴力破解告警",
    "event_definition_id": "ed-demo",
    "event": {
      "id": "demo-001",
      "priority": 3,
      "message": "攻击源 8.8.8.8 触发规则",
      "fields": {"src_ip": "8.8.8.8", "confidence": 90}
    }
  }'
```

预期返回：

```json
{"code":0,"msg":"success","data":{"status":"accepted","alert_id":"demo-001","duplicated":false,"ioc_count":1,"task_count":1,"message":"命中策略 default-auto-block，生成 1 个任务"}}
```

重复发送同一 `event.id` 会返回 `"duplicated": true`，不会产生新任务。

## 6. 其他告警源

`POST /api/v1/alerts/generic`（需 JWT）用于接入 ElastAlert、Suricata、自研检测等：

```json
{
  "alert_id": "suricata-001",
  "title": "Suricata ET SCAN",
  "source_system": "suricata",
  "severity": "high",
  "risk_level": "high",
  "confidence": 85,
  "src_ips": ["8.8.8.8"],
  "domains": [],
  "payload": {"signature": "ET SCAN ..."}
}
```

后续 v1.2 会提供更多官方适配器，参考 `backend/app/engines/alert_parser.py` 新增解析函数即可。

## 7. 排错清单

| 现象 | 检查 |
|---|---|
| Graylog 通知显示失败 / 403 | `secret` 是否与 `.env` 一致；是否配置了 Bearer 但未带 |
| 告警 accepted 但 `task_count=0` | 熔断开关、白名单命中、IP 为内网/保留地址、未命中策略、未达阈值、无支持该 IOC 类型的设备 |
| 只想看告警不下发 | 在系统设置开启「全局自动封禁熔断」，告警仍会留痕 |
| 担心误封业务 IP | 先把业务网段加入 IP 白名单；再调高策略 `min_confidence` 与 `threshold_count`；必要时开启 `require_approval` |

> ⚠️ 自动封禁属于高风险操作，请先在测试环境用 `mock` 插件演练，确认规则后再接入真实设备。
