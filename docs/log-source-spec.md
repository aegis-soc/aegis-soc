# 日志源、规则与字段规范

> 平台**只与 Graylog 对接**，不直接对接任何安全设备厂商。
> 本文件定义：有哪些日志源、每个源必须产出什么字段、Graylog 侧怎么归一化、平台侧怎么消费、质量怎么验收、字段怎么变更。
> 目标一句话：**换设备只改 Graylog 规则，平台代码零改动。**

## 1. 三层职责：谁该干什么

```
安全设备（IPS / WAF / 态感 / 零信任网关）
        │ syslog / kafka / filebeat
        ▼
Graylog  ── 接入、解析、归一化、路由、留存      ← 厂商差异只在这一层消化
        │ MCP 只读（search_messages / aggregate_messages）
        ▼
平台      ── 只读消费：SOAR 封禁、LBA 行为分析   ← 只认标准字段名，不解析原始日志
```

| 层 | 负责 | 明确不负责 |
|---|---|---|
| 设备 | 产出日志 | —— |
| Graylog | 字段改名、类型转换、必填校验打标、分流入流、原始留存 | 业务判断（谁该封、谁有风险） |
| 平台 | 按 `stream + 字段清单` 拉取、聚合、判定、处置 | 兼容厂商字段差异、猜测字段含义 |

**唯一解耦点 = 标准字段名 + `schema_version`。** 只要这条守住，加设备、换厂商、换品牌都不动平台代码。

### 1.1 为什么现在必须立这个规范

平台代码里已经出现了本不该存在的厂商耦合，这是实证：

| 位置 | 现状 | 问题 |
|---|---|---|
| `backend/app/services/patrol.py:42` | `FIELD_ALIASES` 7 组、40+ 别名，源 IP 依次试 `src_ip / source_ip / client_ip / remote_addr / srcaddr / attacker_ip / source_address / sip / src / ip` | 平台在替 Graylog 擦屁股；每接一家新设备就要加别名 |
| `backend/app/engines/alert_parser.py:30` | `SOURCE_FIELDS` 14 个候选字段判断来源 | 来源分类靠猜，`source` 这种通用字段极易误判 |
| `backend/app/engines/alert_parser.py:18` | `SOURCE_PATTERNS` 8 类、含"天清/雷池/长亭/启明星辰/深信服AF"等厂商词 | 厂商名硬编码进平台正则，等于没解耦 |

这些不是 bug——是**Graylog 侧没有强制规范时，平台侧的必然退化**。规范落地后它们应逐步退化为"过渡期兜底"并最终删除（见 §7.3）。

## 2. 日志源清单

四类源，两个用途，互不混用：

| source_code | 中文名 | 用途 | 消费方 | 归一化流 | 量级 |
|---|---|---|---|---|---|
| `ztna` | 零信任 7 层网关 | 用户访问行为 | **LBA**（用户×设备×IP）、巡检（认证爆破） | `norm-ztna` | 高 |
| `ips` | 入侵防御 | 攻击事件 | SOAR 封禁、巡检、告警 | `norm-ips` | 中 |
| `waf` | Web 应用防火墙 | Web 攻击事件 | SOAR 封禁、巡检、告警 | `norm-waf` | 高 |
| `nta` | 态势感知 / 全流量 | 全流量威胁 | SOAR、告警 | `norm-nta` | 高 |

补充约定：

- **`ztna` 是 LBA 的唯一数据源。** LBA 不得读取 `ips/waf/nta`；需要攻击上下文时通过风险事件的 `src_ip` 反查，不直接拉别家日志。
- **`ztna` 同时被巡检使用**，但两者读的字段子集不同：LBA 读 `username / ua_* / app_id / url`，巡检只读 `src_ip / status_code / ts` 做爆破计数。同一份数据、两份契约，不重复采集。
- 新增源（如 EDR、邮件安全）**必须先在本文档登记**，再在 Graylog 建流、在平台加 `log_source` 记录；顺序不能颠倒。

## 3. 标准字段规范

分三组：**信封字段**（所有源都有）、**攻击字段**（ips/waf/nta）、**访问字段**（ztna）。字段名一旦发布不得更改，只能新增（见 §8）。

### 3.1 命名与格式硬规则

| # | 规则 | 反例 |
|---|---|---|
| R1 | 全小写 + 下划线（snake_case），不加前缀 | `SrcIP`、`gl2_src_ip` |
| R2 | IP 只用 `src_ip` / `dst_ip`，禁止同义字段并存 | `source_ip`、`client_ip`、`remote_addr`、`sip` |
| R3 | 时间统一 `ts`，**UTC 毫秒整数**；另存 `ingest_ts` | `timestamp: "2026-11-22 10:33:01"` |
| R4 | 一字段一值，禁止逗号拼接多值 | `src_ip: "1.1.1.1,2.2.2.2"` |
| R5 | 缺失用 `null`，禁止空字符串 / `-` / `unknown` / `N/A` | `username: "-"` |
| R6 | 枚举值英文小写，取值必须来自受控词表（§3.5） | `action: "已阻断"` |
| R7 | 原始值与派生值分离，原始字段只追加不改写 | 直接把 `ua_raw` 改写成解析结果 |
| R8 | 单位写进字段名：`_ms`、`_bytes`、`_count` | `duration: 30`（秒还是毫秒？） |

### 3.2 信封字段（所有源必填）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ts` | long | ✅ | 事件发生时间，UTC 毫秒。设备时间，非入库时间 |
| `ingest_ts` | long | ✅ | Graylog 接收时间，UTC 毫秒。用于算入库延迟 |
| `source_code` | string | ✅ | `ztna` / `ips` / `waf` / `nta` |
| `vendor` | string | ✅ | 厂商标识，小写无空格：`sangfor` / `qiming` / `chaitin` / `hillstone` |
| `product` | string | ✅ | 产品名：`af` / `ips` / `safeline` / `atrust` |
| `device` | string | 建议 | 设备实例标识（主机名或管理 IP），多台同型号时用于定位 |
| `graylog_msg_id` | string | ✅ | Graylog 原生 `_id`，**全局去重主键** |
| `schema_version` | string | ✅ | 该源当前遵守的规范版本，如 `1.0` |

> `event_id` 不要求设备提供——由平台消费时用 `uuid4` 生成，保证跨源唯一、可用于溯源。

### 3.3 攻击字段（`ips` / `waf` / `nta`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `src_ip` | string | ✅ | 攻击源 IP，**单值、不带掩码、不带端口** |
| `dst_ip` | string | 建议 | 受害 IP；NAT 后为内网地址时保留原值 |
| `src_port` | int | 可选 | |
| `dst_port` | int | 可选 | |
| `proto` | string | 可选 | `tcp` / `udp` / `icmp` |
| `action` | string | ✅ | 受控词表 `block/deny/drop/reset/alert/allow/log/monitor`。**统一到"是否已阻断"语义**，见 §3.5 |
| `severity` | string | ✅ | `low/medium/high/critical`（设备原始 1–4 或 1–10 由 Graylog 折算，平台不再折算） |
| `threat_type` | string | 建议 | `webshell` / `sqli` / `xss` / `bruteforce` / `c2` / `scan` / `exploit` / `other` |
| `rule_id` | string | 建议 | 设备规则/签名 ID |
| `rule_name` | string | 建议 | 规则名或签名名（平台展示用，不参与判定） |
| `url` | string | waf 必填 | 原始请求 URI（含 path，query 见 R7） |
| `http_method` | string | 可选 | 大写 `GET/POST/...` |
| `http_status` | int | 可选 | 响应码 |
| `bytes` | long | 可选 | 请求体大小，用于大包攻击识别 |

### 3.4 访问字段（`ztna`）

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `username` | string | ✅（可空值） | 登录账号。**匿名访问时为 `null`，不是空串**——匿名访问本身是高价值风险信号，必须能与"字段丢失"区分 |
| `src_ip` | string | ✅ | 用户出口 IP |
| `url` | string | ✅ | 完整 path，保留原始大小写 |
| `url_query` | string | 可选 | 查询串单独存，便于脱敏（§9.3） |
| `method` | string | ✅ | 大写 |
| `status_code` | int | ✅ | 网关返回码。401/403 是行为分析主特征 |
| `ua_raw` | string | ✅ | User-Agent 原文，**不截断** |
| `ua_class` | string | ✅ | 受控词表：`pc` / `mobile` / `tablet` / `feishu` / `other` |
| `ua_browser` | string | 建议 | `chrome` / `edge` / `safari` / `firefox` / `feishu` / `other` |
| `ua_browser_ver` | string | 建议 | 主版本号，`"131"` 而非 `"131.0.6778.86"`（设备指纹按主版本聚合） |
| `ua_os` | string | 建议 | `windows` / `macos` / `ios` / `android` / `linux` / `other` |
| `app_id` | string | 建议 | 被访问的内部应用标识（零信任侧的应用 ID） |
| `app_name` | string | 可选 | 应用显示名 |
| `gateway_node` | string | 建议 | 网关节点标识，用于定位"某节点异常" |
| `req_bytes` | long | 可选 | 请求大小 |
| `resp_bytes` | long | 可选 | 响应大小 |

> `ua_class` / `ua_browser` / `ua_browser_ver` 是设备指纹的**唯一依据**（`device_key = sha1(username + ua_class + ua_browser + ua_browser_ver)`）。这三个字段缺失时设备数会失真，属高优先级缺失。
> 若网关原生提供 `ua_pc` / `ua_mobile` / `ua_feishu` 这类布尔分类字段，由 Graylog 换算成 `ua_class` 单值，平台不读原始布尔字段。

### 3.5 受控词表

| 词表 | 取值 | 说明 |
|---|---|---|
| `action` | `block` `deny` `drop` `reset` `alert` `allow` `log` `monitor` | 前 4 个 = 已阻断；后 4 个 = 仅记录。平台只按"已阻断/未阻断"二分，不做设备语义翻译 |
| `severity` | `low` `medium` `high` `critical` | 设备 1–4 → 直接映射；设备 5 级或 1–10 分由 Graylog 折算 |
| `ua_class` | `pc` `mobile` `tablet` `feishu` `other` | `feishu` 单列，因为企业受管终端的唯一可靠信号 |
| `threat_type` | `webshell` `sqli` `xss` `bruteforce` `c2` `scan` `exploit` `other` | 未覆盖的先归 `other`，**不新增值**；确需新增走 §8 |

## 4. Graylog 侧落地规范

### 4.1 流的分层

每个源建**两条流**，职责不同：

| 流命名 | 内容 | 保留期 | 谁读 |
|---|---|---|---|
| `raw-<vendor>-<product>` | 解析后的原始字段，不改名 | 7–30 天 | 只用于排障、回溯，平台**不读** |
| `norm-<source_code>` | 严格遵循本规范的标准化字段 | 与业务一致 | **平台唯一读取入口** |
| `norm-<source_code>-reject` | 必填字段缺失的日志 | 7 天 | 平台不读，用于质量看板与规则修复 |

混合品牌同源（如两台不同厂商 WAF）时，`raw-` 流分开建，`norm-waf` 合并——平台的 `source_code` 只有一个 `waf`，靠 `vendor` 字段区分。

### 4.2 pipeline 三阶段

```
Stage 1  rename    设备字段 → 标准字段（只做映射，不做加工）
Stage 2  cast      类型转换：ts → UTC ms long、status_code → int、severity → 词表
Stage 3  validate  必填校验 → 打标；缺必填 → 路由到 reject 流
```

Stage 3 打标字段（由 Graylog 写入，平台可读，用于质量统计）：

| 字段 | 取值 | 说明 |
|---|---|---|
| `_schema_ok` | `true` / `false` | 必填校验结果 |
| `_schema_missing` | 逗号分隔字段名 | 缺失的必填字段，便于批量修规则 |
| `_schema_version` | 如 `1.0` | 该条日志按哪个版本归一化 |

> 为什么不用 `set_field` 直接补默认值：**补齐会让缺失变得不可见**。缺 `username` 补成 `""`，匿名访问和字段丢失就再也分不开——而这两者的风险含义完全不同。

### 4.3 pipeline 规则示例（ztna）

```
rule "ztna: rename"
when has_field("ua_pc") OR has_field("ua_mobile") OR has_field("ua_feishu")
then
  // 三个布尔字段 → 单值 ua_class，优先级：feishu > mobile > pc
  let cls = "other";
  when to_bool(to_string($message.ua_feishu)) == true then let cls = "feishu"; end
  when to_bool(to_string($message.ua_mobile)) == true then let cls = "mobile"; end
  when to_bool(to_string($message.ua_pc)) == true then let cls = "pc"; end
  set_field("ua_class", cls);
  set_field("source_code", "ztna");
  set_field("vendor", "sangfor");
  set_field("product", "atrust");
end
```

```
rule "ztna: cast + validate"
when has_field("src_ip")
then
  set_field("ts", to_long(to_string($message.timestamp)));       // 已是 UTC ms 时可直接赋值
  set_field("status_code", to_int(to_string($message.status_code)));
  // 匿名访问：username 缺失 → 显式置 null，不写空串
  set_field("username", to_string($message.username));            // 缺失即 null
  let missing = "";
  when !has_field("src_ip") then let missing = concat(missing, "src_ip,"); end
  when !has_field("url") then let missing = concat(missing, "url,"); end
  when !has_field("ua_raw") then let missing = concat(missing, "ua_raw,"); end
  set_field("_schema_missing", missing);
  set_field("_schema_ok", missing == "");
end
```

> 规则要写成**按 `source_code` 分文件**（`pipeline/ztna.rules`、`pipeline/waf.rules`），避免一条巨型规则互相影响；改一家设备只动一个文件。

## 5. 厂商字段映射表（持续补充）

| 厂商 / 产品 | 设备原字段 | 标准字段 | 备注 |
|---|---|---|---|
| 深信服 AF / IPS | `src` / `sip` | `src_ip` | |
| 深信服 AF | `dst` / `dip` | `dst_ip` | |
| 深信服 AF | `attack_name` / `threat_name` | `threat_type`（折算） / `rule_name` | 中文威胁名需映射到词表，映射不到归 `other` |
| 启明星辰 IPS | `SRC_IP` / `DST_IP` | `src_ip` / `dst_ip` | 大写字段，rename 时 lowercase |
| 启明星辰 IPS | `SEVERITY`（1–10） | `severity` | 按 1–3 low / 4–6 medium / 7–8 high / 9–10 critical |
| 长亭雷池 SafeLine | `remote_addr` | `src_ip` | |
| 长亭雷池 | `request_uri` | `url` | |
| 长亭雷池 | `attack_type` | `threat_type` | |
| 零信任网关（深信服 aTrust） | `ua_pc` / `ua_mobile` / `ua_feishu` | `ua_class` | 三布尔合一，优先级 feishu > mobile > pc |
| 零信任网关 | `user_name` / `account` | `username` | 匿名时设备可能给 `anonymous` 字符串 —— **需在 Graylog 转成 null**，否则与真实账号混淆 |
| 零信任网关 | `app` / `app_name` | `app_id` / `app_name` | 若网关只给名字，`app_id` 用名字的稳定哈希或直接复用名字，**上线前定死** |
| 零信任网关 | `gateway` / `node` | `gateway_node` | |

新增设备时，这张表必须先补一行，再写 pipeline 规则——表是规则的唯一依据，避免"规则里改了但没人知道"。

## 6. 平台侧消费规范

### 6.1 日志源注册（配置化，不硬编码）

平台不新建第二套配置：**扩展现有 `patrol_setting.streams`**（现在结构是 `[{name,label,stream_id,query}]`，注释里已写明"避免两处维护"）。

```json
[
  {
    "source_code": "ztna",
    "name": "ZTNA",
    "label": "零信任接入",
    "stream_id": "6xxxxxxxxxxxxxxx",
    "query": "",
    "purpose": ["lba", "patrol"],
    "schema_version": "1.0",
    "required_fields": ["ts", "src_ip", "url", "method", "status_code", "ua_raw", "ua_class"],
    "enabled": true
  }
]
```

向后兼容：旧配置没有 `source_code` 时，按 `name` 推导（`IPS`/`WAF`/`ZTNA` → `ips`/`waf`/`ztna`），`schema_version` 默认 `"1.0"`，缺字段不影响启动。

### 6.2 读取规则

| 场景 | 做法 |
|---|---|
| 取字段 | `record.get("src_ip")` 直读。**不再多候选尝试** |
| 字段缺失 | 该条记录跳过并计入 `log_source_field_missing{source,field}`，不抛异常、不整批失败 |
| 未知字段 | 忽略（Graylog 可能新增字段，平台必须宽容读） |
| 类型不符 | 按契约类型转换一次，失败即视为缺失并计数（**不做二次猜测**） |
| 契约版本 | 每轮拉取带上 `schema_version`，与注册表不一致时记 `log_source_schema_drift` 并告警 |

### 6.3 消费方与用途隔离

- LBA 只读 `purpose` 含 `lba` 的源（当前仅 `ztna`）；
- SOAR 巡检读 `purpose` 含 `patrol` 的源（`ips` / `waf` / `ztna` / `nta`）；
- 一个源可被多个消费方读，但**字段子集各自声明**，互不依赖对方新增的字段。

## 7. 质量规范

### 7.1 准入验收（接新源 / 改规则后必须全过）

| # | 检查 | 通过标准 |
|---|---|---|
| A1 | 必填字段完整性 | 抽样 1000 条，`_schema_ok=true` 占比 ≥ 99.5% |
| A2 | 时间可解析 | `ts` 为整数毫秒 100%，无字符串时间 |
| A3 | 时间合理性 | `ts ≤ ingest_ts`，且 `ingest_ts - ts < 24h` 的占比 ≥ 99% |
| A4 | IP 合法 | `src_ip` 通过 IPv4/IPv6 校验 ≥ 99%，无 CIDR、无端口 |
| A5 | 枚举合规 | `action` / `severity` / `ua_class` 100% 在词表内 |
| A6 | 主键唯一 | 同一窗口内 `graylog_msg_id` 重复率 < 0.1% |
| A7 | 匿名可辨 | `ztna` 中 `username` 为 `null` 的记录数 > 0 时，能确认是真实匿名（对照原始流抽样） |

### 7.2 运行监控（Prometheus + 数据源健康页）

| 指标 | 含义 | 告警阈值 |
|---|---|---|
| `log_source_fetch_total{source}` | 拉取条数 | 环比 7 天同时段 ±50% 告警（断流/爆发） |
| `log_source_field_missing_total{source,field}` | 缺失计数 | 缺失率 > 0.5% 持续 10 分钟 |
| `log_source_schema_drift_total{source}` | 版本不一致 | > 0 立即告警（有人在改规则未通知） |
| `log_source_count_gap{source}` | `aggregate` 总量 − 实际拉取量 | > 200 持续 2 轮（采集缺口，需补拉） |
| `log_source_ingest_delay_seconds{source}` | `ingest_ts - ts` 分位 | P95 > 60s 告警（设备/网络时钟或积压） |
| `log_source_reject_ratio{source}` | reject 流占比 | > 1% 告警（归一化规则失效） |

### 7.3 去别名的迁移路径

`FIELD_ALIASES` 不立刻删——它有过渡价值，但要**可观测、可退出**：

1. 加指标 `field_alias_hit_total{field,alias}`，记录每次靠别名兜底命中；
2. 直读命中（`src_ip` 存在）优先，别名仅在其后兜底；
3. 某别名连续 7 天命中为 0 → 从表里删除；
4. 全部别名清零后删除整张表，平台进入"严格契约模式"。

这样不会因为某台设备还没改 pipeline 就导致线上丢数据，也不会让兜底永久留存。

## 8. 变更管理

`schema_version` 语义化，`major.minor`：

| 变更类型 | 版本 | 流程 |
|---|---|---|
| 新增可选字段 | minor +1 | 文档登记 → Graylog 加字段 → 平台按需读 |
| 新增必填字段 | minor +1 | 先双写（新字段上线但暂不校验）7 天 → 再改 `required_fields` |
| 字段改名 / 改类型 / 删字段 | **major +1** | ① Graylog 同时写新旧字段 ② 平台切读新字段 ③ 观察 7 天 ④ 删旧字段 ⑤ 版本号更新 |

硬约束：

- **禁止**不经登记直接改 pipeline 字段名——平台会静默丢字段，且只在指标上表现为缺失率上升，很难定位；
- **禁止**在平台代码里出现厂商名分支（`if vendor == "sangfor"`）——同类差异一律回 Graylog；
- 每次 major 变更需在 `CHANGELOG.md` 记一条，写明影响哪些消费方。

## 9. 安全与隔离

| 项 | 规范 |
|---|---|
| 账号 | 平台使用**只读** Graylog 账号，仅授 `norm-*` 流读权限；`raw-*` 与 `reject` 不对平台开放 |
| 拉取约束 | 必须带 `stream_id` + 时间窗，禁止无 stream 全量检索；单轮条数上限按任务配置（见 LBA 采集设计） |
| 并发 | 每源独立限流，避免多消费方同时大窗口查询拖垮 Graylog |
| 敏感字段 | `url_query` 落库前对 `token/session/password/ticket/code/auth` 等键做掩码；`username` 属 PII，仅在有权限的页面展示，导出走审计 |
| 留存 | 原始日志留 Graylog（7–30 天）；平台只存事件、画像、快照，不存原始日志副本 |
| 溯源 | 平台"一键溯源"通过 MCP 回查 Graylog，不在平台侧重建日志存储 |

## 10. 落地清单

### 运维侧（接一台新设备）

1. 设备日志接入 Graylog，建 `raw-<vendor>-<product>` 流，确认能收到
2. 写 `pipeline/<source_code>.rules`：rename → cast → validate
3. 建 `norm-<source_code>` 与 `-reject` 流，配好 pipeline 连接
4. 跑 §7.1 七项准入检查，全过再继续
5. 在本文档 §5 映射表补行，在平台 `log_source` 登记 `stream_id` 与 `schema_version`
6. 观察 24 小时指标，无异常即完成

### 开发侧（消费一个新源）

1. 读注册表拿 `stream_id` / `required_fields` / `schema_version`，不写死
2. 按字段名直读，缺失计数、类型转换失败即降级
3. 补该源对应用例（含"缺必填字段"与"类型不符"两个负例）
4. 在健康页暴露该源指标
5. 更新 `docs/lba-api.md` 或相应接口文档中的数据来源说明

## 11. 与现有模块的关系

| 模块 | 关系 |
|---|---|
| 日志巡检（Patrol） | 读 `norm-ips/waf/ztna/nta`，用 L1 规则找漏封；规范落地后 `FIELD_ALIASES` 逐步退出 |
| 告警归一化（`alert_parser`） | Graylog Webhook 推送的告警也应遵守 §3 字段；`source_code` 由 Graylog 直接给出，平台不再靠正则猜厂商 |
| LBA | 只读 `norm-ztna`，按 §3.4 字段契约消费；设备指纹依赖 `ua_class`/`ua_browser`/`ua_browser_ver` 三字段 |
| 系统设置页 | 现有三流配置升级为"数据源"Tab：显示 `source_code`、`stream_id`、`schema_version`、近 24h 缺失率与延迟（只读为主，改流需管理员） |

## 12. 分期

| 阶段 | 内容 | 产出 |
|---|---|---|
| P0（本文档） | 规范定稿、映射表初版、四源清单 | 文档 + 词表 |
| P1 | Graylog 侧 `norm-*` 流与 pipeline 规则落地（先 `ztna`，LBA 需要） | 可读的标准流 |
| P2 | 平台侧注册表扩展、字段直读、缺失/漂移指标 | 数据源健康可观测 |
| P3 | `reject` 流质量看板、去别名、严格契约模式 | 厂商耦合清零 |

> 顺序理由：`ztna` 先做（LBA 与巡检都要），`ips/waf` 跟随（巡检已在用，风险最高），`nta` 最后（消费方少）。
