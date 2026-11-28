"""LBA 登录行为分析（v1）：按需从零信任流聚合，契约见 docs/lba-api.md。

与巡检的关系：复用同一套 MCP 取数基建（客户端、拼参、列式解析、字段映射），
LBA 只消费 ``source_code=ztna`` 的流，按用户/设备/IP 维度聚合，不落新表。

v1 口径（契约里依赖事件引擎的字段先给安全默认值，lba-collector 落地后替换）：
- ``pending_events`` 恒 0（风险事件引擎未实现）；
- ``risk_history`` 恒空列表；
- ``devices_total`` 用 7d 去重口径代替「累计」（无累计表）；
- 风险等级是**启发式**：跨 IP / 跨国家 / 多设备 → medium/high，只做提示不下结论；
- 真机约束：网关对认证失败也回 200，status_code 不能区分认证成败，风险判定
  不依赖它；``employee_*`` 仅部分消息携带，匿名消息不进用户维度聚合。
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.cache import cache
from app.common import BizError
from app.database import utcnow
from app.config import settings as default_settings
from app.services import geoip, patrol

import ipaddress
from app.services.patrol_settings import PatrolConfig, load as load_config

logger = logging.getLogger("aegis")

RISK_LEVELS = ("low", "medium", "high")
UA_CLASSES = {"pc", "mobile", "tablet", "feishu", "other", "unknown"}

# 窗口与限额：页面按需选 1 小时 / 24 小时 / 7 天，点击后才取数分析；
# 单次聚合最多拉 5000 条，配合缓存控制 MCP 压力
RANGE_WINDOWS: dict[str, timedelta] = {
    "1h": timedelta(hours=1), "24h": timedelta(hours=24), "7d": timedelta(days=7),
}
DEFAULT_RANGE = "24h"
WINDOW_24H = timedelta(hours=24)
WINDOW_7D = timedelta(days=7)
FETCH_LIMIT = 5000
TIMELINE_MAX = 200
CACHE_TTL_OVERVIEW = 120
CACHE_TTL_PROFILE = 60

# 风险启发阈值：口径与 docs/lba-design.md §风险策略对齐（v1 无事件引擎的降级版）
HIGH_IP_COUNT = 5          # 7d 内跨 ≥5 个 IP → high
HIGH_COUNTRY_COUNT = 2     # 7d 内跨 ≥2 个国家 → high
MEDIUM_IP_COUNT = 3        # 7d 内跨 ≥3 个 IP → medium
MEDIUM_DEVICE_COUNT = 3    # 同账号 ≥3 台设备 → medium

_MOBILE_UA_WORDS = ("iphone", "ipad", "android", "mobile")


# ---------------------------------------------------------------- UA 派生
def parse_ua(ua_raw: str | None) -> dict[str, str]:
    """从 UA 文本派生 (browser, browser_ver, os)；与 pipeline ztna.rules 同口径。"""
    text = (ua_raw or "").strip()
    lowered = text.lower()
    browser = "other"
    ver = ""
    for token in ("feishu", "lark"):
        if token in lowered:
            browser = "feishu"
            break
    if browser == "other":
        for name, marker in (("edge", "edg/"), ("chrome", "chrome/"),
                             ("firefox", "firefox/"), ("safari", "safari/")):
            if marker in lowered:
                browser = name
                break
    if browser != "other":
        match = re.search(re.escape(browser.replace("edge", "edg")) + r"/(\d+)", lowered)
        if browser == "safari":
            match = re.search(r"version/(\d+)", lowered) or match
        if match:
            ver = match.group(1)
    if "windows" in lowered:
        os_name = "windows"
    elif "macintosh" in lowered or "mac os" in lowered:
        os_name = "macos"
    elif "iphone" in lowered or "ipad" in lowered:
        os_name = "ios"
    elif "android" in lowered:
        os_name = "android"
    elif "linux" in lowered:
        os_name = "linux"
    else:
        os_name = "other"
    return {"browser": browser, "browser_ver": ver, "os": os_name}


def ua_class_of(record: dict[str, Any]) -> str:
    """ua_class 优先取配置值（映射/归一流），缺失时从 ua_raw 弱派生。"""
    value = str(record.get("ua_class") or "").strip().lower()
    if value in UA_CLASSES and value != "unknown":
        return value
    ua_raw = str(record.get("ua_raw") or "")
    if not ua_raw:
        return "unknown"
    lowered = ua_raw.lower()
    if "feishu" in lowered or "lark" in lowered:
        return "feishu"
    if any(word in lowered for word in _MOBILE_UA_WORDS):
        return "mobile"
    return "pc"


def device_key_of(username: str, ua_class: str, browser: str, browser_ver: str) -> str:
    """设备指纹：sha1(username + ua_class + browser + 主版本)，口径同 spec §3.4。"""
    raw = f"{username}|{ua_class}|{browser}|{browser_ver}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------- 取数
def _ztna_stream(cfg: PatrolConfig) -> dict[str, Any]:
    for stream in cfg.streams:
        if stream.get("source_code") == "ztna" and stream.get("enabled", True):
            return stream
    raise BizError("行为分析数据源未配置（零信任流缺失或已停用）", 503, 503)


def _fetch_window(cfg: PatrolConfig, start: datetime, end: datetime) -> list[dict[str, Any]]:
    """拉取窗口内的零信任记录（已套字段映射）；失败抛 503 让前端显示明确错误。"""
    stream = _ztna_stream(cfg)
    client = patrol.build_client(cfg)
    records, status = patrol._fetch_stream(client, stream, start, end, FETCH_LIMIT, cfg=cfg)
    if status.get("error"):
        raise BizError(f"行为分析数据源暂不可用：{status['error']}", 503, 503)
    return records


def _cached(key: str, ttl: int, producer) -> dict[str, Any]:
    cached_value = cache.get(key)
    if cached_value:
        try:
            return json.loads(cached_value)
        except (ValueError, TypeError):
            cache.delete(key)
    data = producer()
    cache.set(key, json.dumps(data, ensure_ascii=False, default=str), ex=ttl)
    return data


# ---------------------------------------------------------------- 聚合
def _ts_ms(seen_at: datetime) -> int:
    return int(seen_at.replace(tzinfo=timezone.utc).timestamp() * 1000)


def _fmt(seen_at: datetime) -> str:
    return seen_at.strftime("%Y-%m-%d %H:%M:%S")


def _record_username(record: dict[str, Any]) -> str | None:
    """username 缺失/空串 = 匿名访问，不进用户维度聚合（真机 employee_* 是消息级字段）。"""
    value = str(record.get("username") or "").strip()
    if not value or value in {"-", "anonymous", "null"}:
        return None
    return value[:64]


def _is_public_ip(ip: str) -> bool:
    """公网地址判定：内网/环回/保留地址不参与异常判定（与巡检口径一致）。"""
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _norm_records(records: list[dict[str, Any]], fallback: datetime) -> list[dict[str, Any]]:
    """取回记录 → LBA 视图：补时间、UA 派生、IP 归属；坏行跳过不毁整体。"""
    out: list[dict[str, Any]] = []
    for record in records:
        ip_value = str(patrol._first(record, patrol.FIELD_ALIASES["ip"]) or "").strip()
        # 时间列与巡检同口径：先看平台字段 ts，再按别名表兜底（event_time/@timestamp/…）。
        # 只认 timestamp 一个名字时，真机流时间列稍有出入，全部记录都会被打上
        # 「当前时间」兜底——三个时间窗口的数据就会一模一样（2026-11-28 排查）。
        time_text = str(record.get("ts") or "") or patrol._first(
            record, patrol.FIELD_ALIASES["timestamp"])
        seen_at = patrol._parse_time(time_text, fallback)
        ua = parse_ua(record.get("ua_raw"))
        try:
            status_code = int(str(record.get("status_code") or "").strip() or 0)
        except ValueError:
            status_code = 0
        info = geoip.lookup(ip_value) if ip_value else None
        out.append({
            "username": _record_username(record),
            "display_name": str(record.get("display_name") or "").strip()[:64],
            "internal": not _is_public_ip(ip_value) if ip_value else True,
            "src_ip": ip_value,
            "seen_at": seen_at,
            "url": str(record.get("url") or "")[:255],
            "domain": str(patrol._first(record, patrol.FIELD_ALIASES["domain"]) or "")[:255],
            "method": str(record.get("method") or "").upper()[:8],
            "status_code": status_code,
            "app_id": str(record.get("app_id") or ""),
            "ua_raw": str(record.get("ua_raw") or "")[:255],
            "ua_class": ua_class_of(record),
            "browser": ua["browser"],
            "browser_ver": ua["browser_ver"],
            "os": ua["os"],
            "country": (info.country if info else None) or "",
            "city": (info.city if info else None) or "",
            "isp": (info.isp if info else None) or "",
        })
    return out


def _classify_risk(stats: dict[str, Any]) -> str:
    if (stats["ip_count_7d"] >= HIGH_IP_COUNT
            or stats["country_count_7d"] >= HIGH_COUNTRY_COUNT
            or stats["fails_window"] >= 10):
        return "high"
    if (stats["ip_count_7d"] >= MEDIUM_IP_COUNT
            or stats["device_count"] >= MEDIUM_DEVICE_COUNT):
        return "medium"
    return "low"


def _aggregate(db: Session | None, cfg: PatrolConfig, now: datetime,
               username: str | None = None,
               window: timedelta = WINDOW_7D) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """窗口内记录 → 按用户聚合的基础统计（含设备与 IP 明细，供列表与详情共用）。

    返回 ``(users, meta)``：meta 带取数诊断信息（取回条数、数据时间跨度），
    供前端展示「实际统计范围」，三个窗口数据一样时一眼能看出是窗口没生效
    还是日志本身跨度就短。
    """
    raw = _fetch_window(cfg, now - window, now)
    records = _norm_records(raw, now)
    meta: dict[str, Any] = {
        "fetched": len(raw), "records": len(records),
        "data_first_seen": min((r["seen_at"] for r in records), default=None),
        "data_last_seen": max((r["seen_at"] for r in records), default=None),
    }
    if username is not None:
        records = [r for r in records if r["username"] == username]
    users: dict[str, dict[str, Any]] = {}

    for rec in records:
        name = rec["username"]
        if name is None:
            continue
        user = users.setdefault(name, {
            "username": name, "display_name": "", "last_active": rec["seen_at"],
            "requests_window": 0, "fails_window": 0, "ip_7d": {}, "devices": {},
            "timeline": [],
        })
        if not user["display_name"] and rec["display_name"]:
            user["display_name"] = rec["display_name"]
        if rec["seen_at"] > user["last_active"]:
            user["last_active"] = rec["seen_at"]
        if rec["seen_at"] >= now - window:
            user["requests_window"] += 1
            if rec["status_code"] in (401, 403):
                user["fails_window"] += 1
            if len(user["timeline"]) < TIMELINE_MAX:
                user["timeline"].append(rec)
        if rec["src_ip"]:
            ip_entry = user["ip_7d"].setdefault(rec["src_ip"], {
                "first_seen": rec["seen_at"], "last_seen": rec["seen_at"],
                "internal": rec["internal"],
                "country": rec["country"], "city": rec["city"], "isp": rec["isp"]})
            ip_entry["first_seen"] = min(ip_entry["first_seen"], rec["seen_at"])
            ip_entry["last_seen"] = max(ip_entry["last_seen"], rec["seen_at"])
        dkey = device_key_of(name, rec["ua_class"], rec["browser"], rec["browser_ver"])
        device = user["devices"].setdefault(dkey, {
            "device_key": dkey, "ua_class": rec["ua_class"], "browser": rec["browser"],
            "browser_ver": rec["browser_ver"], "managed": "unknown",
            "ua_raw": rec["ua_raw"], "last_active": rec["seen_at"], "ips": {}})
        device["last_active"] = max(device["last_active"], rec["seen_at"])
        if rec["src_ip"]:
            device["ips"][rec["src_ip"]] = user["ip_7d"][rec["src_ip"]]

    for user in users.values():
        user["device_count"] = len(user["devices"])
        # 内网 IP 不参与异常判定：跨 IP / 跨国家只统计公网地址（2026-11-26 真机
        # 反馈：零信任日志里内网占比极高，混入后全员误报）。内网地址仍保留在
        # ip_7d / 设备轨迹明细里，供用户详情展示。
        public_ips = {ip: v for ip, v in user["ip_7d"].items() if not v["internal"]}
        user["ip_count_7d"] = len(public_ips)
        user["country_count_7d"] = len({v["country"] for v in public_ips.values() if v["country"]})
        user["risk"] = _classify_risk(user)
    return list(users.values()), meta


def _device_payload(device: dict[str, Any]) -> dict[str, Any]:
    ips = sorted(device["ips"].items(), key=lambda kv: kv[1]["last_seen"], reverse=True)
    return {
        "device_key": device["device_key"], "ua_class": device["ua_class"],
        "browser": device["browser"], "browser_ver": device["browser_ver"],
        "managed": device["managed"], "ua_raw": device["ua_raw"],
        "last_active": _fmt(device["last_active"]),
        "ips": [{
            "ip": ip, "internal": meta.get("internal", False),
            "country": ("内网" if meta.get("internal") else None) or meta["country"] or "未知",
            "city": "" if meta.get("internal") else (meta["city"] or ""),
            "isp": meta["isp"] or "", "first_seen": _fmt(meta["first_seen"]),
            "last_seen": _fmt(meta["last_seen"]),
        } for ip, meta in ips],
    }


# ---------------------------------------------------------------- 对外入口
def _range_of(range_key: str | None) -> str:
    """校验时间范围参数：``1h/24h/7d``，非法值直接 400。"""
    key = (range_key or DEFAULT_RANGE).strip().lower()
    if key not in RANGE_WINDOWS:
        raise BizError(f"range 需为 {'/'.join(RANGE_WINDOWS)}", 400, 400)
    return key


def login_overview(db: Session | None = None, range_key: str = "") -> dict[str, Any]:
    range_key = _range_of(range_key)
    cfg = load_config(db, base=default_settings)
    window = RANGE_WINDOWS[range_key]

    def produce() -> dict[str, Any]:
        now = utcnow()
        users, meta = _aggregate(db, cfg, now, window=window)
        device_keys = {d["device_key"] for u in users for d in u["devices"].values()}
        pending = [u for u in users if u["risk"] in ("medium", "high")]
        return {
            "range": range_key,
            "active_users": len({u["username"] for u in users}),
            "devices_total": len(device_keys),
            "pending_anomaly_users": len(pending),
            "high_risk_users": len([u for u in users if u["risk"] == "high"]),
            "requests_total": sum(u["requests_window"] for u in users),
            "window_desc": {
                "window": range_key,
                "window_start": _fmt(now - window), "window_end": _fmt(now),
                "fetched": meta["fetched"], "records": meta["records"],
                "data_first_seen": _fmt(meta["data_first_seen"]) if meta["data_first_seen"] else "",
                "data_last_seen": _fmt(meta["data_last_seen"]) if meta["data_last_seen"] else "",
            },
        }

    return _cached(f"lba:overview:{range_key}", CACHE_TTL_OVERVIEW, produce)


def anomaly_users(db: Session | None = None, risk_level: str = "",
                  page: int = 1, page_size: int = 20, range_key: str = "") -> dict[str, Any]:
    if risk_level and risk_level not in RISK_LEVELS:
        raise BizError(f"risk_level 需为 {'/'.join(RISK_LEVELS)} 或留空", 400, 400)
    page = max(1, page)
    page_size = min(max(1, page_size), 100)
    range_key = _range_of(range_key)
    window = RANGE_WINDOWS[range_key]
    key = f"lba:anomaly:{risk_level or 'all'}:{range_key}:{page}:{page_size}"

    def produce() -> dict[str, Any]:
        cfg = load_config(db, base=default_settings)
        now = utcnow()
        users, _meta = _aggregate(db, cfg, now, window=window)
        items = []
        for u in users:
            if risk_level and u["risk"] != risk_level:
                continue
            items.append({
                "username": u["username"], "display_name": u["display_name"],
                "risk": u["risk"],
                "device_count": u["device_count"],
                "device_types": sorted({d["ua_class"] for d in u["devices"].values()}),
                "ip_count_7d": u["ip_count_7d"],
                "country_count_7d": u["country_count_7d"],
                "pending_events": 0,          # 事件引擎未落地，v1 恒 0
                "last_active": _fmt(u["last_active"]),
            })
        risk_order = {"high": 0, "medium": 1, "low": 2}
        # 先按最近活跃倒序，再按风险稳定排序——同风险内保持活跃度倒序
        items.sort(key=lambda x: x["last_active"], reverse=True)
        items.sort(key=lambda x: risk_order[x["risk"]])
        total = len(items)
        start = (page - 1) * page_size
        return {"items": items[start:start + page_size], "total": total,
                "page": page, "page_size": page_size}

    return _cached(key, CACHE_TTL_OVERVIEW, produce)


def user_profile(db: Session | None = None, username: str = "",
                 range_key: str = "") -> dict[str, Any]:
    username = (username or "").strip()[:64]
    if not username:
        raise BizError("username 不能为空", 400, 400)
    range_key = _range_of(range_key)
    window = RANGE_WINDOWS[range_key]
    key = f"lba:profile:{username}:{range_key}"

    def produce() -> dict[str, Any]:
        cfg = load_config(db, base=default_settings)
        now = utcnow()
        matches, _meta = _aggregate(db, cfg, now, username=username, window=window)
        if not matches:
            raise BizError(f"用户 {username} 在所选时间范围内无行为记录", 404, 404)
        user = matches[0]
        timeline = sorted(user["timeline"], key=lambda r: r["seen_at"], reverse=True)
        return {
            "username": user["username"], "display_name": user["display_name"],
            "range": range_key, "risk": user["risk"],
            "requests": user["requests_window"],
            "ip_count_7d": user["ip_count_7d"],
            "country_count_7d": user["country_count_7d"],
            "device_count": user["device_count"],
            "timeline": [{
                "ts": _ts_ms(r["seen_at"]), "app_id": r["app_id"], "url": r["url"],
                "domain": r["domain"],
                "method": r["method"], "status_code": r["status_code"], "src_ip": r["src_ip"],
            } for r in timeline],
            "devices": [_device_payload(d) for d in
                        sorted(user["devices"].values(),
                               key=lambda d: d["last_active"], reverse=True)],
            "risk_history": [],            # 事件引擎未落地，v1 恒空
        }

    return _cached(key, CACHE_TTL_PROFILE, produce)
