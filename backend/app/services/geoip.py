"""IP 归属地查询：ip2region 离线库（xdb）封装。

设计要点：
- **纯离线**：只读本地 xdb 文件，不联网、不依赖第三方 API，封禁链路里不新增故障点；
- **可降级**：库文件缺失、依赖未安装、IP 非法、IPv6 地址，一律返回 None，
  调用方照常入库，只是归属地留空——绝不因为查不到归属地而阻断告警处置；
- **热加载**：按文件 mtime 自动重建 searcher（最多每 60 秒检查一次），
  换库后不用重启服务；
- **线程安全**：searcher 的查询不保证并发安全，这里统一加锁（单次约 100 微秒）。

数据格式（ip2region v4 xdb）：`国家|省份|城市|运营商|ISO两位码`，
中国境内为中文（`中国|广东省|深圳市|电信|CN`），境外为英文
（`United States|California|0|Google LLC|US`）。

数据文件来源与更新方式见 `docs/geoip.md`、脚本 `scripts/fetch_geoip.py`。
"""
from __future__ import annotations

import ipaddress
import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from app.config import settings

logger = logging.getLogger("aegis")

# backend/app/services/geoip.py -> backend
DEFAULT_DB_PATH = Path(__file__).resolve().parents[2] / "data" / "ip2region_v4.xdb"

_STAT_INTERVAL = 60.0  # 秒：mtime 检查间隔，避免每次查询都 stat
_UNKNOWN = {"", "0", "none", "null"}
_RESERVED_COUNTRIES = {"reserved", "unknown"}


@dataclass(frozen=True)
class GeoInfo:
    """一条归属地结果；字段为空表示库里没有更细的信息。"""

    country: str | None = None
    province: str | None = None
    city: str | None = None
    isp: str | None = None
    iso_code: str | None = None

    @property
    def region(self) -> str | None:
        """省·市 拼装，供列表「地区」列直接展示。"""
        parts = [p for p in (self.province, self.city) if p]
        if not parts:
            return None
        # 直辖市常见「北京市|北京市」，去重后只显示一次
        if len(parts) == 2 and parts[0] == parts[1]:
            return parts[0]
        return "·".join(parts)


# ISO 3166-1 alpha-2 → 中文国家名。只覆盖常见攻击来源国，未收录的回退英文名。
_COUNTRY_ZH: dict[str, str] = {
    "CN": "中国", "HK": "中国香港", "MO": "中国澳门", "TW": "中国台湾",
    "US": "美国", "CA": "加拿大", "MX": "墨西哥", "BR": "巴西", "AR": "阿根廷",
    "CL": "智利", "CO": "哥伦比亚", "PE": "秘鲁", "VE": "委内瑞拉",
    "GB": "英国", "IE": "爱尔兰", "FR": "法国", "DE": "德国", "NL": "荷兰",
    "BE": "比利时", "LU": "卢森堡", "CH": "瑞士", "AT": "奥地利", "IT": "意大利",
    "ES": "西班牙", "PT": "葡萄牙", "GR": "希腊", "SE": "瑞典", "NO": "挪威",
    "DK": "丹麦", "FI": "芬兰", "IS": "冰岛", "PL": "波兰", "CZ": "捷克",
    "SK": "斯洛伐克", "HU": "匈牙利", "RO": "罗马尼亚", "BG": "保加利亚",
    "UA": "乌克兰", "BY": "白俄罗斯", "RU": "俄罗斯", "LT": "立陶宛",
    "LV": "拉脱维亚", "EE": "爱沙尼亚", "MD": "摩尔多瓦", "RS": "塞尔维亚",
    "HR": "克罗地亚", "SI": "斯洛文尼亚", "BA": "波黑", "AL": "阿尔巴尼亚",
    "TR": "土耳其", "IL": "以色列", "SA": "沙特阿拉伯", "AE": "阿联酋",
    "QA": "卡塔尔", "KW": "科威特", "BH": "巴林", "OM": "阿曼", "JO": "约旦",
    "LB": "黎巴嫩", "IQ": "伊拉克", "IR": "伊朗", "SY": "叙利亚", "YE": "也门",
    "AF": "阿富汗", "PK": "巴基斯坦", "IN": "印度", "BD": "孟加拉国",
    "LK": "斯里兰卡", "NP": "尼泊尔", "KZ": "哈萨克斯坦", "UZ": "乌兹别克斯坦",
    "KG": "吉尔吉斯斯坦", "TJ": "塔吉克斯坦", "TM": "土库曼斯坦",
    "MN": "蒙古", "JP": "日本", "KR": "韩国", "KP": "朝鲜", "VN": "越南",
    "LA": "老挝", "KH": "柬埔寨", "TH": "泰国", "MM": "缅甸", "MY": "马来西亚",
    "SG": "新加坡", "ID": "印度尼西亚", "PH": "菲律宾", "BN": "文莱",
    "AU": "澳大利亚", "NZ": "新西兰", "PG": "巴布亚新几内亚", "FJ": "斐济",
    "ZA": "南非", "EG": "埃及", "NG": "尼日利亚", "KE": "肯尼亚",
    "ET": "埃塞俄比亚", "GH": "加纳", "TZ": "坦桑尼亚", "UG": "乌干达",
    "MA": "摩洛哥", "DZ": "阿尔及利亚", "TN": "突尼斯", "LY": "利比亚",
    "SD": "苏丹", "SN": "塞内加尔", "CM": "喀麦隆", "ZW": "津巴布韦",
    "MZ": "莫桑比克", "AO": "安哥拉", "MU": "毛里求斯", "SC": "塞舌尔",
}


def country_zh(iso_code: str | None, fallback: str | None = None) -> str | None:
    """优先用 ISO 码映射中文名，未收录则保留库里的英文名。"""
    code = (iso_code or "").strip().upper()
    if code and code in _COUNTRY_ZH:
        return _COUNTRY_ZH[code]
    name = (fallback or "").strip()
    if not name or name.lower() in _UNKNOWN:
        return None
    return name


def db_path() -> Path:
    """库文件路径：GEOIP_DB_PATH 优先，否则 backend/data/ip2region_v4.xdb。"""
    custom = (getattr(settings, "geoip_db_path", "") or "").strip()
    return Path(custom).expanduser() if custom else DEFAULT_DB_PATH


def is_enabled() -> bool:
    return bool(getattr(settings, "geoip_enabled", True))


# ---------------------------------------------------------------- 查询实现

_lock = threading.RLock()
_searcher = None
_searcher_mtime = 0.0
_last_stat = 0.0
_warned: set[str] = set()


def _warn_once(key: str, message: str, *args) -> None:
    if key in _warned:
        return
    _warned.add(key)
    logger.warning(message, *args)


def _close_searcher() -> None:
    global _searcher, _searcher_mtime
    if _searcher is not None:
        try:
            _searcher.close()
        except Exception:  # noqa: BLE001 - 关闭失败不影响主流程
            pass
    _searcher = None
    _searcher_mtime = 0.0


def _get_searcher():
    """懒加载 + 按 mtime 热加载；不可用时返回 None（只告警一次）。"""
    global _searcher, _searcher_mtime, _last_stat

    if not is_enabled():
        return None

    with _lock:
        path = db_path()
        now = time.monotonic()
        if _searcher is not None and now - _last_stat < _STAT_INTERVAL:
            return _searcher

        _last_stat = now
        if not path.exists():
            _warn_once(
                f"missing:{path}",
                "IP 归属地库不存在（%s），黑名单将继续入库但国家/地区留空；"
                "执行 python scripts/fetch_geoip.py 下载，详见 docs/geoip.md",
                path,
            )
            _close_searcher()
            return None

        try:
            mtime = path.stat().st_mtime
        except OSError:
            return _searcher

        if _searcher is not None and mtime == _searcher_mtime:
            return _searcher

        try:
            import ip2region.searcher as xdb
            import ip2region.util as util
        except ImportError:
            _warn_once(
                "no-lib",
                "未安装 py-ip2region，IP 归属地不可用（pip install py-ip2region）",
            )
            return None

        try:
            _close_searcher()
            _searcher = xdb.new_with_vector_index(util.version_from_name("v4"), str(path), None)
            _searcher_mtime = mtime
            logger.info("IP 归属地库已加载：%s（%d KB）", path, path.stat().st_size // 1024)
        except Exception as exc:  # noqa: BLE001 - 库损坏不能拖垮服务
            _warn_once(f"load:{path}", "IP 归属地库加载失败：%s（%s）", exc, path)
            _close_searcher()
        return _searcher


def _parse_region(region: str) -> GeoInfo | None:
    fields = (region or "").split("|")
    if len(fields) < 4:
        return None
    country_raw, province_raw, city_raw, isp_raw = fields[0], fields[1], fields[2], fields[3]
    iso_raw = fields[4] if len(fields) > 4 else ""

    def clean(value: str) -> str | None:
        value = (value or "").strip()
        return None if value.lower() in _UNKNOWN else value

    iso_code = clean(iso_raw)
    iso_code = iso_code.upper() if iso_code else None

    if (country_raw or "").strip().lower() in _RESERVED_COUNTRIES:
        # 保留/未分配网段：给个中文提示，比空白更有排查价值
        return GeoInfo(country="保留地址", iso_code=None)

    country = country_zh(iso_code, country_raw)
    if not country:
        return None
    return GeoInfo(
        country=country,
        province=clean(province_raw),
        city=clean(city_raw),
        isp=clean(isp_raw),
        iso_code=iso_code,
    )


def lookup(value: str | None) -> GeoInfo | None:
    """查询单个 IP / CIDR 的归属地；任何异常都返回 None。

    CIDR 统一取网络地址查询（如 45.7.7.0/24 按 45.7.7.0 定位）。
    """
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        network = ipaddress.ip_network(raw, strict=False)
    except ValueError:
        return None
    if network.version != 4:  # 当前只加载了 IPv4 库
        return None

    address = network.network_address
    # 内网地址在库里通常落在 Reserved 段，直接标「内网」比「保留地址」更好排查
    if address.is_private or address.is_loopback or address.is_link_local:
        return GeoInfo(country="内网")

    searcher = _get_searcher()
    if searcher is None:
        return None

    try:
        import ip2region.util as util

        with _lock:
            region = searcher.search(util.parse_ip(str(address)))
    except Exception as exc:  # noqa: BLE001 - 查询失败降级为空
        logger.debug("IP 归属地查询失败 %s: %s", raw, exc)
        return None
    return _parse_region(region)


def geo_fields(value: str | None) -> dict[str, str | None]:
    """返回可直接展开进 IocIndicator 的四个归属地字段。

    写入时调用（快照），保证历史记录不随库更新而改写。
    """
    info = lookup(value)
    if info is None:
        return {"geo_country": None, "geo_province": None, "geo_city": None, "geo_isp": None}
    return {
        "geo_country": info.country,
        "geo_province": info.province,
        "geo_city": info.city,
        "geo_isp": info.isp,
    }


# ---------------------------------------------------------------- 异步回填

_pending_lock = threading.Lock()
_pending: set[int] = set()


def fill_geo_sync(db, ioc_ids: list[int]) -> int:
    """在给定会话上同步回填指定记录的归属地（供测试与 backfill 脚本复用）。

    只补空值：已有归属地的记录不覆盖——快照一旦写入就是历史事实。
    """
    from app.models import IocIndicator

    if not ioc_ids:
        return 0
    rows = db.query(IocIndicator).filter(IocIndicator.id.in_(list(ioc_ids))).all()
    changed = 0
    for row in rows:
        if row.ioc_type != "IP" or row.geo_country:
            continue
        for key, value in geo_fields(row.normalized_value).items():
            setattr(row, key, value)
        changed += 1
    return changed


def schedule_fill(ioc_ids) -> None:
    """入库后异步回填归属地：主流程只登记 ID，查询在后台线程完成。

    - **绝不阻塞入库**：告警处置（生成封禁任务）不等归属地查询；
    - 同一批 ID 去重，高频告警下不会堆积线程；
    - 后台线程任何异常只记日志，可用 scripts/backfill_geo.py --all 兜底补齐。
    """
    if not is_enabled():
        return
    try:
        ids = [int(i) for i in (ioc_ids or []) if i]
    except (TypeError, ValueError):
        return
    if not ids:
        return

    with _pending_lock:
        fresh = [i for i in ids if i not in _pending]
        _pending.update(fresh)
    if not fresh:
        return

    def _worker() -> None:
        try:
            from app.database import SessionLocal

            with SessionLocal() as db:
                if fill_geo_sync(db, fresh):
                    db.commit()
        except Exception as exc:  # noqa: BLE001 - 回填失败不影响主流程
            logger.warning("异步回填归属地失败（可用 scripts/backfill_geo.py 兜底）：%s", exc)
        finally:
            with _pending_lock:
                _pending.difference_update(fresh)

    threading.Thread(target=_worker, name="aegis-geoip-fill", daemon=True).start()


def wait_pending(timeout: float = 5.0) -> bool:
    """等待全部异步回填完成（测试用）。"""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _pending_lock:
            if not _pending:
                return True
        time.sleep(0.02)
    return False


def health() -> dict[str, object]:
    """用于 /api/healthz 之外的自检接口或排查脚本。"""
    path = db_path()
    exists = path.exists()
    return {
        "enabled": is_enabled(),
        "db_path": str(path),
        "db_exists": exists,
        "db_size_kb": path.stat().st_size // 1024 if exists else 0,
        "db_mtime": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(path.stat().st_mtime))
        if exists
        else None,
        "loaded": _searcher is not None,
    }


def reset_cache() -> None:
    """测试用：强制下次查询重新加载库文件。"""
    global _last_stat
    with _lock:
        _close_searcher()
        _last_stat = 0.0
        _warned.clear()
