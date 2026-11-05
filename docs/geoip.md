# IP 归属地（国家 / 省 / 市）

黑名单列表里的「国家」「地区」两列来自 **ip2region 离线库**，不再依赖 ipip.net。

## 1. 为什么换掉 ipip.net

| 方案 | 现状 | 结论 |
|---|---|---|
| ipip.net 免费离线库 | 免费版多年未更新，只剩商用授权 | 拿不到可用数据 |
| 纯真 qqwry | 已转收费，GBK 编码、社区维护质量波动 | 不适合生产 |
| MaxMind GeoLite2 | 需注册 License Key，国内省市是英文，授权限制多 | 备选 |
| DB-IP / IP2Location LITE | 免费版精度低或只到国家 | 备选 |
| **ip2region（本方案）** | 开源、xdb 单文件约 11 MB、国内城市级中文、查询约 100 微秒 | ✅ 采用 |

数据由 ip2region 社区维护、随开源仓库发布，代码 Apache-2.0；内部生产使用免费。
若要把数据本身对外分发，请自行再确认其数据条款。

## 2. 数据格式

xdb 返回固定五段：`国家|省份|城市|运营商|ISO两位码`。

```
中国|广东省|深圳市|电信|CN        → 国家 中国   地区 广东省·深圳市
United States|California|0|US     → 国家 美国   地区 California
Reserved|Reserved|Reserved|0|0    → 国家 保留地址（RFC5737 等文档/保留段）
```

- 中国境内为中文；境外为英文，**国家**用 ISO 码映射成中文（美国/日本/德国…），
  未收录的国家回退英文原名；**省/市**保留库里的原文。
- `0` 视为未知，不展示。
- 内网地址（10/8、172.16/12、192.168/16、127/8、169.254/16）不查库，直接标 **内网**，
  比库里的 `Reserved` 更好排查横向移动。

## 3. 安装与升级

```bash
# 1) Python 依赖（已写进 backend/requirements.txt）
pip install py-ip2region

# 2) 下载库文件（约 11 MB，默认 backend/data/ip2region_v4.xdb）
python scripts/fetch_geoip.py
python scripts/fetch_geoip.py --force     # 强制更新到最新
python scripts/fetch_geoip.py --path D:/geoip/ip2region_v4.xdb
```

下载脚本按顺序尝试 jsdelivr（国内通常最快）、ghfast、GitHub 原站，
每个镜像先直连再走系统代理；下载后校验文件头与体积才替换正式文件，
不会把半截文件留给服务加载。

库文件不进 Git（`.gitignore` 已忽略 `backend/data/*.xdb`），换机器需要执行一次下载。

### 配置项

| 环境变量 | 默认 | 说明 |
|---|---|---|
| `GEOIP_ENABLED` | `true` | 置 `false` 关闭归属地，写入时留空 |
| `GEOIP_DB_PATH` | `backend/data/ip2region_v4.xdb` | 自定义库路径 |

更换库文件后**无需重启**：服务按文件 mtime 自动热加载（最多每 60 秒检查一次）。

## 4. 什么时候查、存在哪

归属地在**写入黑名单时查一次并落库**（`ioc_indicator.geo_country/geo_province/geo_city/geo_isp`），
理由：

1. 库每月更新，历史记录应保留当时的归属，便于复盘；
2. 列表接口不依赖库文件，库没下载/被删时旧记录照样能看；
3. 分页查询不用为每行做一次查询。

三条写入路径都会填：告警自动处置（`active`）、被拦截留痕（`rejected` / `whitelisted`）、
手工新增（老记录缺归属地时顺手补）。

### 存量数据回填

```bash
cd backend
DATABASE_URL="mysql+pymysql://..." python ../scripts/backfill_geo.py
python ../scripts/backfill_geo.py --all      # 换库后全量重算
python ../scripts/backfill_geo.py --dry-run  # 只统计
```

脚本默认只补空值，可反复执行。生产 MySQL 需先执行 `sql/migrate_20261105_ioc_geo.sql`；
本地 SQLite 由 `app/migrations.py` 在启动时自动加列。

## 5. 界面与接口

- 列表新增「国家」「地区」两列，地区列悬浮显示运营商；`中国` 用红色标签、境外用灰色。
- 顶部新增「国家/地区」下拉（带记录数），数据来自 `GET /api/v1/ioc/geo/countries`。
- 关键字搜索已覆盖国家/省/市，直接搜「深圳」「美国」即可。
- `GET /api/v1/ioc/ips?country=中国` 精确筛选。
- `GET /api/healthz` 的 `geoip` 字段可判断库是否就绪：`{"enabled": true, "db_exists": true}`。

## 6. 精度与局限

- 国内到**地级市**，不到区县；海外城市精度一般（免费库通病），跨境 CDN/云出口常定位到机房所在城市。
- 只支持 **IPv4**；IPv6 归属地留空（需要另加 37 MB 的 `ip2region_v6.xdb` 与 v6 查询分支）。
- 库有滞后：新分配的网段可能落在相邻段，表现为城市偏差。
- 归属地只作研判参考，**不参与封禁判定**——是否封禁只看白名单 / 内网 / 网段大小等硬规则。

## 7. 排障

| 现象 | 原因与处理 |
|---|---|
| 列表国家/地区全是 `-` | 库文件不存在：`python scripts/fetch_geoip.py`；或 `GEOIP_ENABLED=false` |
| 启动日志 `IP 归属地库不存在` | 同上，仅告警一次，不影响封禁 |
| 日志 `IP 归属地库加载失败` | 文件损坏，重新 `--force` 下载 |
| 结果明显偏差 | 库版本旧，`--force` 更新后 `backfill_geo.py --all` 重算 |
| 想看某 IP 解析成什么 | `cd backend && python -c "from app.services import geoip; print(geoip.lookup('8.8.8.8'))"` |

## 8. 验收样本

装上库后可用这几个地址快速验证（2026-11 版数据）：

| IP | 预期 |
|---|---|
| `113.92.157.29` | 中国 · 广东省·深圳市 · 电信 |
| `223.5.5.5` | 中国 · 浙江省·杭州市 · 阿里 |
| `8.8.8.8` | 美国 · California · Google LLC |
| `45.7.7.7` | 巴西 · Alagoas |
| `10.20.30.40` | 内网 |
| `203.0.113.9` | 保留地址 |

`python -m pytest tests/test_geoip.py -q` 覆盖解析、降级、写入快照、按国家筛选。
