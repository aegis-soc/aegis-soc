# LBA 前后端接口契约（v0.1，前端 mock 与后端实现的共同依据）

> 本文件是**契约**：字段名、结构、枚举值以此为准。前端 mock（`VITE_LBA_MOCK`）按此造数，后端按此实现，切换时前端零改动。
> 通用约定：响应包一层 `{code:0, msg:"success", data:...}`（与 AegisSoc 现有口径一致，下文只写 `data` 部分）；分页结构 `{items, total, page, page_size}`；枚举值一律英文 code（`low/medium/high`、`pc/mobile/feishu/unknown`、`managed/unknown`），显示层由前端 i18n 翻译。
> 路由前缀：`/api/v1/lba/*`。

## 1. 登录行为分析中心

### GET /lba/login/overview?range=1h|24h|7d

`range` 可空（默认 `24h`），非法值返回 400。响应字段按所选窗口统计：

```json
{
  "range": "24h",
  "active_users": 87,
  "devices_total": 89,
  "pending_anomaly_users": 0,
  "high_risk_users": 0,
  "requests_total": 12653,
  "window_desc": {
    "window": "24h",
    "window_start": "2026-11-27 18:30:00",
    "window_end": "2026-11-28 18:30:00",
    "fetched": 12653,
    "records": 12653,
    "data_first_seen": "2026-11-27 18:42:11",
    "data_last_seen": "2026-11-28 18:29:57"
  }
}
```

口径：`active_users` = 窗口内 distinct username；`devices_total` = 窗口内去重设备指纹数（无累计表，v1 降级口径）；`pending_anomaly_users` = 窗口内中/高风险用户数；`requests_total` = 窗口内总请求量。`window_desc` 是取数诊断：`fetched/records` 为实际从 Graylog 取回并参与聚合的条数，`data_first_seen/data_last_seen` 为数据自身时间跨度——三个窗口结果接近时先看它：跨度 < 窗口说明日志本身就只有这么久（流刚接入），跨度异常则查时间字段映射。

### GET /lba/login/anomaly-users?risk_level=&page=&page_size=

`risk_level` 可空（全部）/ `low|medium|high`。默认按风险降序、最近活跃降序。

```json
{
  "items": [
    {
      "username": "lisi",
      "risk": "high",
      "device_count": 2,
      "device_types": ["pc", "feishu"],
      "ip_count_7d": 4,
      "country_count_7d": 2,
      "pending_events": 3,
      "last_active": "2026-11-21 22:31:05"
    }
  ],
  "total": 16, "page": 1, "page_size": 20
}
```

## 2. 用户详情

### GET /lba/profile/user/{username}

```json
{
  "username": "lisi",
  "risk": "high",
  "requests_24h": 128,
  "ip_count_7d": 4,
  "country_count_7d": 2,
  "device_count": 2,

  "timeline": [
    { "ts": 1763720465000, "app_id": "app-finance", "url": "/api/report/list",
      "method": "GET", "status_code": 200, "src_ip": "1.2.3.4" }
  ],

  "devices": [
    {
      "device_key": "a1b2c3...",
      "ua_class": "pc",
      "browser": "chrome",
      "browser_ver": "120",
      "managed": "unknown",
      "ua_raw": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0.0.0",
      "last_active": "2026-11-21 22:31:05",
      "ips": [
        { "ip": "1.2.3.4", "country": "中国", "city": "广东省·深圳市",
          "isp": "电信", "first_seen": "2026-11-15 08:12:33", "last_seen": "2026-11-21 22:31:05" }
      ]
    }
  ],

  "risk_history": [
    { "ts": 1763720000000, "from": "low", "to": "high",
      "policy": "同一账号 1 分钟内连续 5 次 401",
      "reason": "1min 内 401×7（app-finance）" }
  ]
}
```

约定：`timeline` 按时间倒序、默认最近 24h、最多 200 条；`devices.ips` 按 `last_seen` 倒序；`risk_history` 按时间倒序、`reason` 是条件命中值快照文本。

## 3. 后续接口（本契约下一版补全响应结构）

风险事件（`/lba/event/*`）、策略（`/lba/policy/*`）、大盘（`/lba/dashboard/*`）、画像（`/lba/profile/*`）、溯源（`/lba/trace/search`）、采集状态（`/lba/collect/status`）——结构在各自页面开发前补入本文件，避免边写边改。

## 4. Mock 开关

`src/api/lba.js`：`import.meta.env.DEV && VITE_LBA_MOCK !== 'false'` 时走本地 mock（生产构建永远走真实接口，`VITE_LBA_MOCK=false` 可在 dev 强制关掉）。组件内不出现任何 mock 判断。

## 4.1 时间范围参数（2026-11-28 修订）

三个接口统一新增 ``range=1h|24h|7d`` 查询参数（默认 ``24h``）：页面按钮
按需触发——进入页面不自动取数，点击「近 1 小时 / 近 24 小时 / 近 7 天」
才从 Graylog 拉该窗口的日志分析。缓存键按 range 隔离。

字段随窗口语义改名：``active_users_24h → active_users``、
``requests_24h → requests``、``fail_24h → fails_window``（窗口内计数）；
响应新增 ``range`` 回显。用户详情页同样提供范围切换（默认 7d）。

设备/用户信息修正（2026-11-28）：``ua_is_pc=false`` 不再写 ``ua_class=other``
（会把手机/平板全部压平），留空交给 UA 文本派生 mobile/feishu/tablet。

## 5. v1 实现口径（2026-11-26 后端落地说明）

后端按需从零信任流聚合（复用巡检 MCP 基建，单次最多回看 7 天 / 5000 条，
Redis 缓存：overview/列表 120s、详情 60s）。lba-collector 落地前的降级口径：

| 字段 | v1 行为 |
|---|---|
| `pending_events` | 恒 `0`（风险事件引擎未实现，契约字段保留） |
| `risk_history` | 恒 `[]`（同上） |
| `devices_total` | 7d 设备指纹去重数（无累计表，暂代替「累计」口径） |
| `risk` | 启发式：7d 跨 IP ≥5 或跨国家 ≥2 或 24h 401/403 ≥10 → `high`；跨 IP ≥3 或设备 ≥3 → `medium`；否则 `low`。**网关对认证失败也回 200，status_code 不可靠，风险判定不依赖它** |
| 匿名消息 | `username` 缺失/`-`/`anonymous` 的记录不进用户维度聚合 |
| UA 派生 | `ua_class` 缺失时从 `ua_raw` 弱派生（feishu/mobile 关键字，否则 pc）；browser/主版本/OS 同 pipeline ztna.rules 口径 |
| 设备指纹 | `sha1(username|ua_class|browser|browser_ver)`，spec §3.4 口径 |
