"""安全运营指标：把「检测到但没封」的缺口、处置率、跨日持续攻击量化出来。

设计来源是 ``graylog-security`` 设计文档：三流（IPS / WAF / ZTNA）视角、
R0-R7 规则体系、「该封未封」缺口分析、跨日持续攻击（R5）、封禁配额与
优先级队列（5 次/轮、20 次/日）。那个体系跑在 Graylog 脚本里，本模块把
同样的判断口径搬到平台自己的告警 / 黑名单流水上，供 AI 巡检复用。

模块**只读**，不产生任何处置动作。

两个关键口径约定：

1. **设计内豁免不算缺口**。命中白名单、内网/保留地址被硬性拒绝，是刻意的
   安全边界；如果把它们算成「该封未封」，内网扫描会把处置率永久拖低，
   指标就失去意义。所以单独计入 ``exempt_ips``。
2. **处置率 = 已封 / (已封 + 可处置缺口)**，分母不含豁免项。这才对齐
   「检测率 70% → 90%」的目标口径：说的是「该封的封掉了多少」。
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, time, timedelta
from typing import Any

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.database import utcnow
from app.models import AlertEvent, IocIndicator

# graylog 设计文档里的三条核心日志流
CORE_SOURCES = ("IPS", "WAF", "ZTNA")

# 缺口归因：key 与展示文案、以及给运营的处理提示
GAP_REASONS: dict[str, dict[str, str]] = {
    "no_policy": {
        "label": "未命中策略",
        "hint": "告警进了平台但没有策略接住：补策略或放宽现有策略条件，否则这批攻击永远不处置",
    },
    "dispatch_failed": {
        "label": "下发未生效",
        "hint": "策略命中了但没有生效黑名单：查设备连通性、凭据与任务日志失败明细",
    },
    "kill_switch": {
        "label": "熔断期间留痕",
        "hint": "全局自动封禁熔断开启时所有告警只留痕：恢复后人工复核这段时间的攻击源",
    },
    "below_threshold": {
        "label": "未达阈值",
        "hint": "单次告警没达到策略阈值：攻击频次高但阈值过大时，考虑降阈值或缩短统计窗口",
    },
    "ignored_other": {
        "label": "其他未处置",
        "hint": "未归类原因，需人工看告警详情确认是否漏处置",
    },
    "pending": {
        "label": "待处理",
        "hint": "告警仍处于 pending，确认阈值累计窗口是否卡住",
    },
    "whitelist": {
        "label": "白名单豁免",
        "hint": "设计内豁免：受保护地址不封禁；若攻击确实来自这些地址，需复核白名单范围",
    },
    "invalid_ioc": {
        "label": "地址校验拒绝",
        "hint": "内网 / 保留地址 / 非法格式被硬性拒绝：属安全边界，不视为缺口",
    },
}

# 设计内豁免：不计入「该封未封」
EXEMPT_REASONS = {"whitelist", "invalid_ioc"}


def _alert_ips(alert: Any) -> list[str]:
    """取告警涉及的源 IP：优先 src_ips，退化到 dedupe_key。"""
    raw = alert.src_ips if isinstance(alert.src_ips, list) else []
    ips = [str(ip).strip() for ip in raw if str(ip or "").strip()]
    if not ips and alert.dedupe_key:
        ips = [str(alert.dedupe_key).strip()]
    return ips


def _classify(alert: Any) -> str:
    """把告警的处置结果归类成缺口原因。"""
    status = (alert.status or "").lower()
    msg = alert.process_msg or ""
    if status == "whitelisted":
        return "whitelist"
    if "熔断" in msg:
        return "kill_switch"
    if status == "pending":
        return "below_threshold" if "阈值" in msg else "pending"
    if status == "processed":
        # 走到这里说明策略命中却没产出生效黑名单（设备下发失败等）
        return "dispatch_failed"
    if "未命中" in msg:
        return "no_policy"
    if "校验" in msg or "无可执行" in msg:
        return "invalid_ioc"
    return "ignored_other"


def gap_breakdown(db: Session, hours: int = 24) -> dict[str, Any]:
    """窗口内「检测到 vs 实际封禁」的缺口归因。

    返回 ``block_rate``（处置率）与按原因分组的缺口明细，
    用于回答运营最关心的问题：这个 IP 明明在攻击，为什么没封？
    """
    since = utcnow() - timedelta(hours=hours)
    alerts = (
        db.query(AlertEvent.status, AlertEvent.process_msg, AlertEvent.src_ips,
                 AlertEvent.dedupe_key, AlertEvent.title)
        .filter(AlertEvent.created_at >= since)
        .all()
    )
    ioc_rows = (
        db.query(IocIndicator.normalized_value, IocIndicator.status,
                 IocIndicator.geo_country)
        .filter(IocIndicator.ioc_type == "IP", IocIndicator.created_at >= since)
        .all()
    )

    blocked: set[str] = {v for v, status, _ in ioc_rows if status == "active" and v}
    exempt_status: dict[str, str] = {
        v: ("whitelist" if status == "whitelisted" else "invalid_ioc")
        for v, status, _ in ioc_rows
        if status in ("whitelisted", "rejected") and v and v not in blocked
    }
    geo = {v: c for v, _, c in ioc_rows if c}

    # IP → 命中次数 / 首次出现时的处置原因
    per_ip: dict[str, dict[str, Any]] = {}
    for alert in alerts:
        reason = _classify(alert)
        for ip in _alert_ips(alert):
            entry = per_ip.setdefault(
                ip, {"ip": ip, "count": 0, "reason": reason, "title": alert.title})
            entry["count"] += 1
            if entry["reason"] in ("ignored_other", "pending") and reason not in (
                    "ignored_other", "pending"):
                entry["reason"] = reason  # 有更具体的归因就用更具体的

    buckets: dict[str, dict[str, Any]] = {}
    gap_ips = 0
    exempt_ips = 0
    blocked_ips = 0
    top_gaps: list[dict[str, Any]] = []

    for ip, entry in per_ip.items():
        if ip in blocked:
            blocked_ips += 1
            continue
        reason = exempt_status.get(ip) or entry["reason"]
        bucket = buckets.setdefault(reason, {
            "key": reason,
            "label": GAP_REASONS.get(reason, {}).get("label", reason),
            "hint": GAP_REASONS.get(reason, {}).get("hint", ""),
            "exempt": reason in EXEMPT_REASONS,
            "ip_count": 0, "alert_count": 0, "samples": [],
        })
        bucket["ip_count"] += 1
        bucket["alert_count"] += entry["count"]
        if reason in EXEMPT_REASONS:
            exempt_ips += 1
        else:
            gap_ips += 1
            top_gaps.append({
                "ip": ip, "count": entry["count"], "country": geo.get(ip),
                "reason": reason,
                "label": GAP_REASONS.get(reason, {}).get("label", reason),
                "title": entry["title"],
            })
        if len(bucket["samples"]) < 5:
            bucket["samples"].append({
                "ip": ip, "count": entry["count"],
                "country": geo.get(ip), "title": entry["title"],
            })

    top_gaps.sort(key=lambda item: item["count"], reverse=True)
    denom = blocked_ips + gap_ips
    return {
        "window_hours": hours,
        "alerts": len(alerts),
        "detected_ips": len(per_ip),
        "blocked_ips": blocked_ips,
        "gap_ips": gap_ips,
        "exempt_ips": exempt_ips,
        "block_rate": round(blocked_ips / denom, 4) if denom else None,
        "reasons": sorted(buckets.values(), key=lambda b: b["ip_count"], reverse=True),
        "top_gaps": top_gaps[:8],
    }


def detection_trend(db: Session, days: int = 7) -> dict[str, Any]:
    """近 N 天处置率趋势（按自然日切片，跨日累计口径）。"""
    today = utcnow().date()
    series: list[dict[str, Any]] = []
    for offset in range(days - 1, -1, -1):
        day = today - timedelta(days=offset)
        start = datetime.combine(day, time.min)
        end = start + timedelta(days=1)
        detected = (
            db.query(func.count(func.distinct(AlertEvent.dedupe_key)))
            .filter(AlertEvent.created_at >= start, AlertEvent.created_at < end,
                    AlertEvent.dedupe_key.isnot(None), AlertEvent.dedupe_key != "")
            .scalar() or 0
        )
        blocked = (
            db.query(func.count(func.distinct(IocIndicator.normalized_value)))
            .filter(IocIndicator.ioc_type == "IP", IocIndicator.status == "active",
                    IocIndicator.created_at >= start, IocIndicator.created_at < end,
                    IocIndicator.normalized_value != "")
            .scalar() or 0
        )
        exempt = (
            db.query(func.count(func.distinct(IocIndicator.normalized_value)))
            .filter(IocIndicator.ioc_type == "IP",
                    IocIndicator.status.in_(("whitelisted", "rejected")),
                    IocIndicator.created_at >= start, IocIndicator.created_at < end)
            .scalar() or 0
        )
        actionable = max(detected - exempt, 0)
        denom = max(actionable, blocked)
        rate = min(blocked / denom, 1.0) if denom else None
        series.append({
            "date": day.strftime("%Y-%m-%d"),
            "detected": detected,
            "blocked": blocked,
            "exempt": exempt,
            "rate": round(rate, 4) if rate is not None else None,
        })

    valid = [s["rate"] for s in series if s["rate"] is not None]
    return {
        "days": days,
        "series": series,
        "avg_rate": round(sum(valid) / len(valid), 4) if valid else None,
        "latest_rate": series[-1]["rate"] if series else None,
    }


def persistent_attackers(db: Session, days: int = 7, min_days: int = 3,
                         limit: int = 6) -> dict[str, Any]:
    """跨日持续攻击源：对应 graylog 规则 R5（同一 IP 多日反复出现）。

    当前封禁时长通常是 2 小时，长期「打点型」攻击源会在解封后反复回来；
    跨日出现 ≥3 天的 IP 应当直接拉长封禁窗口，而不是每天重新封一遍。
    """
    since = utcnow() - timedelta(days=days)
    date_col = func.date(IocIndicator.created_at)
    days_col = func.count(func.distinct(date_col))
    rows = (
        db.query(IocIndicator.normalized_value,
                 days_col.label("day_count"),
                 func.count(IocIndicator.id).label("hits"),
                 func.max(IocIndicator.created_at).label("last_seen"))
        .filter(IocIndicator.ioc_type == "IP", IocIndicator.created_at >= since,
                IocIndicator.normalized_value != "")
        .group_by(IocIndicator.normalized_value)
        .having(days_col >= min_days)
        .order_by(days_col.desc(), func.count(IocIndicator.id).desc())
        .all()
    )
    ips = [row[0] for row in rows]
    geo: dict[str, str] = {}
    active: Counter = Counter()
    if ips:
        for value, country, status in (
            db.query(IocIndicator.normalized_value, IocIndicator.geo_country,
                     IocIndicator.status)
            .filter(IocIndicator.ioc_type == "IP",
                    IocIndicator.normalized_value.in_(ips))
            .order_by(IocIndicator.created_at.desc())
            .all()
        ):
            if country and value not in geo:
                geo[value] = country
            if status == "active":
                active[value] += 1

    items = [{
        "ip": value,
        "days": int(day_count),
        "hits": int(hits),
        "day_count": int(day_count),
        "active": active.get(value, 0),
        "country": geo.get(value),
        "last_seen": last_seen.strftime("%Y-%m-%d %H:%M") if last_seen else None,
        "suggest_hours": 168 if day_count >= 5 else 24,
    } for value, day_count, hits, last_seen in rows[:limit]]

    return {
        "window_days": days,
        "min_days": min_days,
        "total": len(rows),
        "items": items,
    }


def source_coverage(db: Session, hours: int = 24,
                    lookback_days: int = 30) -> dict[str, Any]:
    """三流覆盖：哪几路日志真正在投递，哪一路断了。"""
    since = utcnow() - timedelta(hours=hours)
    rows = (
        db.query(IocIndicator.source_type,
                 func.count(IocIndicator.id).label("total"),
                 func.sum(case((IocIndicator.status == "active", 1), else_=0)).label("blocked"),
                 func.sum(case((IocIndicator.status.in_(("whitelisted", "rejected")), 1),
                               else_=0)).label("exempt"))
        .filter(IocIndicator.created_at >= since)
        .group_by(IocIndicator.source_type)
        .all()
    )
    last_seen = dict(
        db.query(IocIndicator.source_type, func.max(IocIndicator.created_at))
        .filter(IocIndicator.created_at >= utcnow() - timedelta(days=lookback_days))
        .group_by(IocIndicator.source_type)
        .all()
    )
    items = [{
        "source": source or "UNKNOWN",
        "alerts": int(total or 0),
        "blocked": int(blocked or 0),
        "exempt": int(exempt or 0),
        "last_seen": last_seen[source].strftime("%Y-%m-%d %H:%M")
        if last_seen.get(source) else None,
    } for source, total, blocked, exempt in rows]
    items.sort(key=lambda item: item["alerts"], reverse=True)
    seen = {item["source"] for item in items}
    return {
        "window_hours": hours,
        "items": items,
        "active_sources": len(seen),
        # 核心三流实际覆盖几路（GRAYLOG / TI 等其他来源不计入这个分母）
        "core_active": len([s for s in CORE_SOURCES if s in seen]),
        "missing_core": [s for s in CORE_SOURCES if s not in seen],
    }


def block_rhythm(db: Session, hours: int = 24) -> dict[str, Any]:
    """封禁节奏：总量、峰值小时、同一 IP 的重复下发。

    对应 graylog 文档的单次 5 个 / 每日 20 个配额思路：峰值小时明显偏离
    常态时，说明某段攻击集中爆发，或策略阈值设置让同一批 IP 反复下发。
    """
    since = utcnow() - timedelta(hours=hours)
    rows = (
        db.query(IocIndicator.created_at)
        .filter(IocIndicator.ioc_type == "IP", IocIndicator.status == "active",
                IocIndicator.created_at >= since)
        .all()
    )
    hourly = [0] * 24
    for (created_at,) in rows:
        if created_at:
            hourly[created_at.hour] += 1
    peak_hour = max(range(24), key=lambda h: hourly[h]) if rows else None
    repeat = (
        db.query(IocIndicator.normalized_value, func.count(IocIndicator.id))
        .filter(IocIndicator.ioc_type == "IP", IocIndicator.status == "active",
                IocIndicator.created_at >= since)
        .group_by(IocIndicator.normalized_value)
        .having(func.count(IocIndicator.id) > 1)
        .order_by(func.count(IocIndicator.id).desc())
        .limit(5)
        .all()
    )
    return {
        "window_hours": hours,
        "blocked": len(rows),
        "hourly": hourly,
        "peak_hour": f"{peak_hour:02d}:00" if peak_hour is not None else None,
        "peak_count": max(hourly) if rows else 0,
        "repeat": [{"ip": ip, "count": int(count)} for ip, count in repeat],
    }
