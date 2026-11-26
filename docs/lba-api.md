# LBA 前后端接口契约（v0.1，前端 mock 与后端实现的共同依据）

> 本文件是**契约**：字段名、结构、枚举值以此为准。前端 mock（`VITE_LBA_MOCK`）按此造数，后端按此实现，切换时前端零改动。
> 通用约定：响应包一层 `{code:0, msg:"success", data:...}`（与 AegisSoc 现有口径一致，下文只写 `data` 部分）；分页结构 `{items, total, page, page_size}`；枚举值一律英文 code（`low/medium/high`、`pc/mobile/feishu/unknown`、`managed/unknown`），显示层由前端 i18n 翻译。
> 路由前缀：`/api/v1/lba/*`。

## 1. 登录行为分析中心

### GET /lba/login/overview

```json
{
  "active_users_24h": 2386,
  "devices_total": 4820,
  "pending_anomaly_users": 16,
  "high_risk_users": 3,
  "window_desc": { "ip_change_days": 7 }
}
```

口径：`active_users_24h` = 24h 内 distinct username；`devices_total` = `lba_device` 累计数；`pending_anomaly_users` = 存在未处置中/高风险事件的用户数；`high_risk_users` = 当前风险等级为 high 的用户数。

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
