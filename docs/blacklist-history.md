# 黑名单流水表（同值不合并）

## 1. 为什么不再按 IP 合并

旧版 `ioc_indicator` 上有唯一键 `uk_ioc(ioc_type, normalized_value)`：同一个 IP 第二次命中时，
只会把原有那条记录的状态和过期时间"续一下"，**谁加的、什么时候加的、由哪台设备报的、由哪条告警触发**
全都被覆盖掉。

实际处置里这行不通：

- 部分封禁设备（如只提供"增加黑名单"接口的 IPS/WAF）**不支持按 IP 覆盖式解封**，
  一条封禁下发后只能等设备端到期或 5 天自然失效；
- 同一 IP 今天被封、明天又命中，是两次独立的处置动作，需要各自的时间线和过期时间，
  否则无法判断"哪一次下发还在生效"；
- 出问题时最常见的问题是"这个 IP 到底什么时候被封的、为什么还没解"，
  合并记录后这个问题无法回答。

现在每次命中都**新增一条记录**，表变成流水（history），列表按添加时间倒序。

## 2. 新增字段

| 字段 | 说明 |
|---|---|
| `created_at` | 添加时间，每次入库即固定，界面「添加时间」列 |
| `source_type` | 来源分类：`IPS` / `WAF` / `ZTNA` / `TI` / `NTA` / `AV` / `FW` / `GRAYLOG` / `MANUAL` / `API` / `UNKNOWN` |
| `source_detail` | 来源原始标识：设备名 / stream / vendor，用于回溯到具体哪台设备 |
| `alert_id` | 触发这条记录的告警 ID，可直接对回 `alert_event` |
| `reject_reason` | 被拦截或豁免的原因；到期但未解封的说明也记在这里 |
| `expire_at` | 保留语义：`NULL` = 永久；到期由 Celery Beat 生成解封任务 |

来源分类的识别规则与 Graylog 侧字段建议见 `docs/graylog-config-guide.md` 第 3 节。

## 3. 状态机

| 状态 | 含义 | 是否下发任务 |
|---|---|---|
| `active` | 已入库并下发（或等待下发） | 是 |
| `rejected` | 校验未通过（内网/保留地址、网段过大、非法值），只留痕 | 否 |
| `whitelisted` | 命中 IP 白名单，豁免封禁 | 否 |
| `expired` | 到期，已生成解封任务（或同 IP 仍有生效记录，见下文） | 生成 `UNBLOCK` |
| `disabled` | 手动解封，或随同 IP 的其它记录一并解封 | 生成 `UNBLOCK` |

被拦截的记录同样会出现在黑名单列表里，只是状态不是 `active`，
这样"为什么这个攻击 IP 没被封"在界面上就能直接回答，不用翻审计日志。

## 4. 解封链路如何处理重复记录

设备侧的黑名单是"一个 IP 集合"，同一个 IP 有多条流水记录时，解封必须按 IP 去重：

| 场景 | 行为 |
|---|---|
| 到期扫描（`expire_iocs_and_unblock`） | 按 `(ioc_type, normalized_value)` 分组，每组只下发一次 `UNBLOCK`，组内所有记录置 `expired` |
| 同 IP 还有更晚到期的记录仍生效 | 只把到期记录置 `expired`，**不生成解封任务**，`reject_reason` 记为"同 IP 仍有生效封禁，未重复下发解封" |
| 新增白名单（`unblock_existing_for_whitelist`） | 同样按 IP 去重后下发解封 |
| 手动删除一条 `active` 记录 | 下发解封，并把该 IP 其它 `active` 记录一并置 `disabled`（设备侧已解封，避免界面显示假在封禁） |
| 手动删除 `rejected` / `whitelisted` 记录 | 只删留痕，不产生任务 |

## 5. 升级已有环境

### MySQL（生产）

```bash
mysql -u aegis -p aegis_soc < sql/migrate_20261105_ioc_history.sql
```

脚本可重复执行：先补 4 个字段，再删 `uk_ioc` 唯一键改普通索引 `idx_ioc_value`，
最后按 `remark LIKE '由告警%'` 回填 `source_type`（`GRAYLOG` / `MANUAL`）。

### SQLite（本地开发）

后端启动时 `init_db()` 自动调用 `app/migrations.py` 完成等价升级：
重命名旧表 → 释放旧索引名 → 建新表 → 搬数据 → 删旧表。
DDL 在 SQLite 下会隐式提交，所以每一步都可重入；中途失败时旧表会以
`ioc_indicator_legacy` 留在库里，下次启动自动补齐后清理。

升级会保留全部历史行，不会删数据。稳妥起见升级前先备份：

```bash
cp backend/_local.db backend/_local.db.bak
```

## 6. 常见问题

**Q：同一 IP 出现多条 `active` 记录，正常吗？**
正常。说明该 IP 在多次告警中被重复封禁，每条记录对应一次独立的处置与过期时间。

**Q：为什么这条记录到期了却没有解封任务？**
看 `reject_reason`。若同 IP 还有更晚到期的记录仍在生效，平台会跳过这次解封，避免把后来那次有效封禁一起解掉。

**Q：怎么知道某个 IP 现在到底封没封？**
看该 IP 是否存在 `status=active` 且 `expire_at` 为 `NULL` 或大于当前时间的记录；
也可以到任务页按 IP 查最近一次 `BLOCK` / `UNBLOCK` 的执行结果。
