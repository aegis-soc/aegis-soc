"""AI 巡检引擎：对整个 SOAR 平台做一次「体检」，输出健康分、逐项结论与总结。

设计要点：
- **只读体检**：巡检不改变任何封禁状态；唯一写操作是把设备连通性结果
  回写到 ``security_device.status / last_check_at``（与手动「测试连接」一致）；
- **可降级**：任何单项检查异常都降级为该项 ``fail`` 并附原因，绝不中断整场巡检；
- **AI 增强，非 AI 依赖**：总结默认由内置规则生成；配置 ``AI_LLM_BASE_URL`` /
  ``AI_LLM_API_KEY``（OpenAI 兼容接口）后调用大模型生成更贴合语境的总结，
  调用失败自动回退规则总结——巡检结果永远可用。

检查项分两层（见 ``CHECKS`` / ``CHECK_WEIGHTS``）：

- **安全效果层**（参考 graylog-security 设计文档的口径）：三流覆盖、
  封禁缺口（该封未封）、处置率、跨日持续攻击——回答「防护到底有没有生效」；
- **平台运行层**：设备连通、黑名单健康、任务队列、到期解封、白名单、
  策略覆盖、攻击态势、系统风险——回答「平台自身是否健康」。

安全效果层权重更高：设备全在线但该封的一律没封，健康分不应是满分。
"""
from __future__ import annotations

import inspect
import json
import logging
import time
from datetime import timedelta
from typing import Any, Callable

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.cache import cache
from app.config import settings
from app.database import utcnow
from app.models import (
    AlertEvent,
    AutomationPolicy,
    DevicePlugin,
    DeviceTask,
    InspectionReport,
    IocIndicator,
    IpWhitelist,
    SecurityDevice,
)
from app.services import security_metrics as metrics
from plugins import registry
from app.engines.validation import resolve_device_config

logger = logging.getLogger("aegis")

STATUS_WEIGHT = {"ok": 100, "warn": 55, "fail": 0}

# 加权评分：安全效果层（缺口/处置率/来源覆盖/持续攻击）权重更高，
# 避免「设备都在线、任务都成功，但该封的一个没封」也能拿到高分。
CHECK_WEIGHTS: dict[str, float] = {
    "devices": 1.5,
    "sources": 1.0,
    "gap": 2.0,
    "detection": 2.0,
    "persistent": 1.0,
    "blacklist": 1.0,
    "expire": 1.5,
    "tasks": 1.0,
    "policies": 1.0,
    "whitelist": 0.5,
    "attacks": 0.5,
    "system": 1.0,
}


class CheckResult(dict):
    """单个检查项结果：key/name/status/summary/data/advice。"""

    def __init__(self, key: str, name: str, status: str, summary: str,
                 data: dict[str, Any] | None = None, advice: str = ""):
        super().__init__(
            key=key, name=name, status=status,
            score=STATUS_WEIGHT.get(status, 0),
            summary=summary, data=data or {}, advice=advice,
        )


def _shared(ctx: dict[str, Any] | None, key: str, factory: Callable[[], Any]) -> Any:
    """同一次巡检内复用指标计算：缺口/趋势/来源等查询只跑一遍。

    直接调用单项检查（测试场景）时 ctx 为 None，此时退化为即用即算。
    """
    if ctx is None:
        return factory()
    if key not in ctx:
        ctx[key] = factory()
    return ctx[key]


def _pct(value: float | None) -> str:
    return "—" if value is None else f"{value:.0%}"


def _invoke(fn: Callable[..., CheckResult], db: Session,
            ctx: dict[str, Any]) -> CheckResult:
    """兼容只接受 db 的检查函数（自定义检查项/测试替身）。"""
    params = inspect.signature(fn).parameters
    return fn(db, ctx) if len(params) >= 2 else fn(db)


# ---------------------------------------------------------------- 检查项

def check_devices(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """设备连通性：逐台调用插件 test_connection，并回写设备状态。"""
    devices = db.query(SecurityDevice).all()
    if not devices:
        return CheckResult(
            "devices", "设备连通性", "warn",
            "尚未接入任何设备，自动封禁无法落地",
            advice="在「设备管理」添加防火墙 / WAF / IPS 设备并完成连通性测试",
        )
    online, offline = [], []
    for device in devices:
        result = registry.test_plugin(device.plugin_code, resolve_device_config(device))
        device.status = "online" if result.get("success") else "offline"
        device.last_check_at = utcnow()
        (online if result.get("success") else offline).append(
            {"device": device.name, "code": device.device_code,
             "plugin": device.plugin_code, "message": result.get("message", "")}
        )
    data = {"total": len(devices), "online": len(online), "offline": offline}
    if not offline:
        return CheckResult(
            "devices", "设备连通性", "ok",
            f"{len(online)}/{len(devices)} 台设备全部连通", data,
        )
    status = "fail" if not online else "warn"
    names = "、".join(d["device"] for d in offline[:5])
    return CheckResult(
        "devices", "设备连通性", status,
        f"{len(online)}/{len(devices)} 台在线，{len(offline)} 台不可达：{names}", data,
        advice="检查不可达设备的地址 / 凭据环境变量 / 网络策略；凭据缺失会直接导致下发失败",
    )


def check_sources(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """三流覆盖：IPS / WAF / ZTNA 哪几路真正在投递，哪一路断了。

    断流的隐蔽性很强——平台一切正常、任务全部成功，只是那一类攻击再也没进来。
    """
    coverage = _shared(ctx, "sources", lambda: metrics.source_coverage(db))
    items = coverage["items"]
    detail = "、".join(f"{item['source']} {item['alerts']} 条" for item in items[:5])
    missing = coverage["missing_core"]
    if not items:
        return CheckResult(
            "sources", "三流覆盖", "warn",
            "24 小时内没有任何来源记录，告警链路可能整体中断", coverage,
            advice="检查 Graylog Notification 是否投递到平台 webhook、后端是否收到告警",
        )
    if len(items) == 1:
        return CheckResult(
            "sources", "三流覆盖", "warn",
            f"仅 {items[0]['source']} 一路有记录（{items[0]['alerts']} 条），跨流关联失效", coverage,
            advice="确认另外两路是否接入 Graylog stream 并配置 Notification 投递",
        )
    if missing:
        return CheckResult(
            "sources", "三流覆盖", "warn",
            f"{len(items)} 路在投递（{detail}），但 {'、'.join(missing)} 24 小时无记录", coverage,
            advice=f"优先确认 {'、'.join(missing)} 的 stream 与 Notification：断流时这一类攻击完全不可见",
        )
    return CheckResult("sources", "三流覆盖", "ok", f"三流齐全：{detail}", coverage)


def check_gap(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """封禁缺口：24 小时「检测到但没封」的 IP 按原因归因。

    对应 graylog 设计文档里的「该封未封」分析：结论不是「封了几个」，
    而是「没封的那些为什么没封」，以及能不能立刻补上。
    """
    gap = _shared(ctx, "gap", lambda: metrics.gap_breakdown(db))
    data = gap
    if gap["detected_ips"] == 0:
        return CheckResult(
            "gap", "封禁缺口", "warn", "24 小时内没有可评估的检测记录", data,
            advice="先确认告警是否正常进入平台，再评估封禁效果",
        )
    rate = gap["block_rate"]
    summary = (
        f"24h 检出 {gap['detected_ips']} 个 IP，封禁 {gap['blocked_ips']} 个，"
        f"可处置缺口 {gap['gap_ips']} 个（处置率 {_pct(rate)}）"
    )
    if gap["exempt_ips"]:
        summary += f"，另有 {gap['exempt_ips']} 个属设计内豁免（白名单/内网地址）"

    actionable = [b for b in gap["reasons"] if not b["exempt"]]
    top_hint = ""
    if actionable:
        top = actionable[0]
        top_hint = f"{top['label']} {top['ip_count']} 个 IP——{top['hint']}"

    if rate is None:
        return CheckResult("gap", "封禁缺口", "warn", summary, data, advice=top_hint)
    if rate >= 0.9:
        return CheckResult("gap", "封禁缺口", "ok", summary, data,
                           advice=f"{top_hint}（占比不大，可继续观察）" if top_hint else "")
    if rate >= 0.7:
        return CheckResult("gap", "封禁缺口", "warn", summary, data, advice=top_hint)
    return CheckResult(
        "gap", "封禁缺口", "fail", summary, data,
        advice=top_hint or "近三成以上的检出 IP 没有落地封禁，先看缺口归因再补策略",
    )


def check_detection(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """处置率与封禁节奏：近 7 日趋势 + 24h 封禁量/峰值小时/重复下发。

    这是「检测率 70% → 90%」目标的日常度量口径：口径见
    ``app.services.security_metrics`` 的模块注释（豁免项不进分母）。
    """
    trend = _shared(ctx, "trend", lambda: metrics.detection_trend(db))
    rhythm = _shared(ctx, "rhythm", lambda: metrics.block_rhythm(db))
    avg, latest = trend["avg_rate"], trend["latest_rate"]
    data = {**trend, "rhythm": rhythm}

    rhythm_text = f"24h 封禁 {rhythm['blocked']} 次"
    if rhythm["peak_hour"]:
        rhythm_text += f"，峰值 {rhythm['peak_hour']}（{rhythm['peak_count']} 次）"
    if rhythm["repeat"]:
        rhythm_text += f"，{len(rhythm['repeat'])} 个 IP 被重复下发"

    if avg is None:
        return CheckResult(
            "detection", "处置率", "warn", f"近 7 日无可评估数据；{rhythm_text}", data,
            advice="没有检出记录时无法计算处置率，先确认告警接入",
        )

    summary = f"近 7 日处置率 {_pct(avg)}（今日 {_pct(latest)}）；{rhythm_text}"
    advice = ""
    if latest is not None and latest < avg - 0.15:
        advice = (f"今日处置率比 7 日均值低 {(avg - latest):.0%}："
                  "优先看「封禁缺口」里的未命中策略与下发未生效两类原因")
    if avg >= 0.85:
        return CheckResult("detection", "处置率", "ok" if not advice else "warn",
                           summary, data, advice)
    if avg >= 0.6:
        return CheckResult("detection", "处置率", "warn", summary, data,
                           advice or "处置率低于 85%：按缺口归因逐类收敛，目标是 90%+")
    return CheckResult("detection", "处置率", "fail", summary, data,
                       advice or "处置率低于 60%：大批检出 IP 未落地封禁，先查策略与设备下发")


def check_persistent(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """跨日持续攻击源：对应 graylog 规则 R5。

    封禁时长通常只有 2 小时，长期打点的攻击源解封后还会回来；
    这类 IP 应该直接拉长封禁窗口，而不是每天重新封一遍。
    """
    per = _shared(ctx, "persistent", lambda: metrics.persistent_attackers(db))
    if per["total"] == 0:
        return CheckResult(
            "persistent", "持续攻击源", "ok",
            "近 7 天没有跨 3 天以上反复出现的攻击源", per,
        )
    head = per["items"][0]
    advice = (
        f"对这类 IP 单独拉长封禁时长（建议 ≥{head['suggest_hours']} 小时，"
        "当前策略默认 2 小时）：在策略里按「7 天内命中 ≥3 天」加一条长封禁规则"
    )
    return CheckResult(
        "persistent", "持续攻击源", "warn",
        f"近 7 天 {per['total']} 个 IP 跨 ≥3 天反复出现，最高 {head['ip']} 出现 {head['days']} 天",
        per, advice,
    )


def check_blacklist(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """黑名单健康：存量、新增、留痕与永久封禁占比。"""
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    total = db.query(IocIndicator).filter(IocIndicator.ioc_type == "IP").count()
    active = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "active").count()
    new_24h = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.created_at >= day_ago).count()
    rejected = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "rejected").count()
    whitelisted = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "whitelisted").count()
    forever = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "active",
        IocIndicator.expire_at.is_(None)).count()
    data = {"active": active, "new_24h": new_24h,
            "rejected": rejected, "whitelisted": whitelisted, "forever": forever}
    if active == 0:
        return CheckResult(
            "blacklist", "黑名单健康", "warn", "当前无生效中的黑名单", data,
            advice="确认告警链路是否正常投递（Graylog → 平台），或策略阈值是否设置过严",
        )
    status, advice = "ok", ""
    summary = f"生效 {active} 条，24h 新增 {new_24h} 条，拦截留痕 {rejected + whitelisted} 条"
    if forever > 0:
        status = "warn"
        summary += f"，{forever} 条永久封禁（无过期时间）"
        advice = "永久封禁会一直占用设备黑名单额度，确认是否有意为之（可设置较长的固定时长）"
    return CheckResult("blacklist", "黑名单健康", status, summary, data, advice)


def check_tasks(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """任务队列：卡住的任务与 24h 失败率。"""
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    stuck = db.query(DeviceTask).filter(
        DeviceTask.task_status.in_(["PENDING", "RETRY"])).count()
    failed_24h = db.query(DeviceTask).filter(
        DeviceTask.task_status == "FAILED", DeviceTask.created_at >= day_ago).count()
    total_24h = db.query(DeviceTask).filter(DeviceTask.created_at >= day_ago).count()
    success_24h = db.query(DeviceTask).filter(
        DeviceTask.task_status == "SUCCESS", DeviceTask.created_at >= day_ago).count()
    data = {"stuck": stuck, "failed_24h": failed_24h,
            "total_24h": total_24h, "success_24h": success_24h}
    if total_24h == 0:
        return CheckResult(
            "tasks", "任务队列", "warn", "24h 内没有下发过任务", data,
            advice="若预期应有封禁动作，检查告警接入与策略命中情况",
        )
    fail_rate = failed_24h / max(total_24h, 1)
    summary = f"24h 任务 {total_24h} 个，成功 {success_24h}，失败 {failed_24h}（{fail_rate:.0%}）"
    if fail_rate >= 0.5:
        status, advice = "fail", "过半任务失败：优先检查设备连通性与凭据；持续失败看「任务中心」错误详情"
    elif fail_rate > 0.1 or stuck > 20:
        status, advice = "warn", "存在失败或积压任务：查看任务中心 RETRY/FAILED 明细，必要时手动重试"
    else:
        status, advice = "ok", ""
    return CheckResult("tasks", "任务队列", status, summary, data, advice)


def check_expire(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """到期解封风险：已过期仍 active（解封链路失灵）与 24h 内即将到期。"""
    now = utcnow()
    in_24h = now + timedelta(hours=24)
    overdue = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "active",
        IocIndicator.expire_at.isnot(None), IocIndicator.expire_at < now).count()
    expiring = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "active",
        IocIndicator.expire_at.isnot(None),
        IocIndicator.expire_at >= now, IocIndicator.expire_at <= in_24h).count()
    data = {"overdue": overdue, "expiring_24h": expiring}
    if overdue > 0:
        return CheckResult(
            "expire", "到期解封风险", "fail",
            f"{overdue} 条黑名单已过期但仍为 active，解封扫描未正常工作", data,
            advice="检查 Celery Beat 与 worker 是否在运行（到期解封依赖 aegis.expire_iocs 每分钟扫描）",
        )
    summary = "解封链路正常"
    if expiring:
        summary += f"，{expiring} 条将在 24h 内到期并自动解封"
    return CheckResult("expire", "到期解封风险", "ok", summary, data)


def check_whitelist(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """白名单风险：网段过宽会放过大片攻击源。"""
    rows = db.query(IpWhitelist).filter(IpWhitelist.status == 1).all()
    too_wide: list[str] = []
    for row in rows:
        # 单 IP 的 prefix_len=32（v6 为 128），只有显式 CIDR 才可能过宽
        if not row.cidr_flag or row.cidr is None:
            continue
        min_prefix = 16 if row.ip_bin and len(row.ip_bin) <= 4 else 32
        if row.prefix_len < min_prefix:
            too_wide.append(row.cidr)
    data = {"total": len(rows), "too_wide": too_wide}
    if too_wide:
        return CheckResult(
            "whitelist", "白名单风险", "warn",
            f"{len(too_wide)} 条白名单网段过宽（小于 /16）：{', '.join(too_wide[:3])}", data,
            advice="过宽的白名单会让攻击源逃过封禁，建议收敛到具体业务出口网段",
        )
    return CheckResult(
        "whitelist", "白名单风险", "ok", f"白名单 {len(rows)} 条，未发现过宽网段", data,
    )


def check_policies(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """策略覆盖：无启用策略为严重问题；ignored 占比过高说明策略没接住。"""
    now = utcnow()
    day_ago = now - timedelta(hours=24)
    enabled = db.query(AutomationPolicy).filter(AutomationPolicy.enabled == 1).count()
    total = db.query(AlertEvent).filter(AlertEvent.created_at >= day_ago).count()
    by_status = dict(
        db.query(AlertEvent.status, func.count(AlertEvent.id))
        .filter(AlertEvent.created_at >= day_ago)
        .group_by(AlertEvent.status).all()
    )
    ignored = by_status.get("ignored", 0)
    data = {"enabled_policies": enabled, "alerts_24h": total, "by_status": by_status}
    if enabled == 0:
        return CheckResult(
            "policies", "策略覆盖", "fail", "没有任何启用中的处置策略，告警将全部留痕不处置", data,
            advice="在「策略配置」启用至少一条策略（或恢复默认策略）",
        )
    if total == 0:
        return CheckResult(
            "policies", "策略覆盖", "warn", f"{enabled} 条策略启用中，但 24h 内无告警进入平台", data,
            advice="检查 Graylog Notification 是否投递到平台 webhook",
        )
    ignored_rate = ignored / max(total, 1)
    summary = f"{enabled} 条策略启用中；24h 告警 {total} 条，其中 {ignored} 条未命中策略（{ignored_rate:.0%}）"
    if ignored_rate >= 0.6:
        return CheckResult(
            "policies", "策略覆盖", "warn", summary, data,
            advice="大量告警未被策略命中：考虑放宽条件或补充新策略，否则攻击会漏掉",
        )
    return CheckResult("policies", "策略覆盖", "ok", summary, data)


def check_attacks(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """攻击态势：7 天 top 来源国与重复命中 IP（同样的 IP 反复来，建议拉长封禁）。"""
    now = utcnow()
    week_ago = now - timedelta(days=7)
    countries = (
        db.query(IocIndicator.geo_country, func.count(IocIndicator.id))
        .filter(IocIndicator.ioc_type == "IP", IocIndicator.created_at >= week_ago,
                IocIndicator.geo_country.isnot(None))
        .group_by(IocIndicator.geo_country)
        .order_by(func.count(IocIndicator.id).desc())
        .limit(5).all()
    )
    repeat_rows = (
        db.query(IocIndicator.normalized_value,
                 func.count(IocIndicator.id))
        .filter(IocIndicator.ioc_type == "IP", IocIndicator.created_at >= week_ago)
        .group_by(IocIndicator.normalized_value)
        .having(func.count(IocIndicator.id) >= 3)
        .order_by(func.count(IocIndicator.id).desc())
        .limit(5).all()
    )
    data = {
        "top_countries": [{"country": c, "count": n} for c, n in countries],
        "repeat_offenders": [{"ip": ip, "count": n} for ip, n in repeat_rows],
    }
    parts = []
    if countries:
        parts.append("7 天攻击源 top：" + "、".join(f"{c}({n})" for c, n in countries))
    advice = ""
    if repeat_rows:
        parts.append("反复出现：" + "、".join(f"{ip}×{n}" for ip, n in repeat_rows))
        advice = "同一 IP 一周内命中 3 次以上，建议在策略里对该类攻击源拉长封禁时长"
    if not parts:
        return CheckResult("attacks", "攻击态势", "ok", "7 天内无新增攻击记录", data)
    return CheckResult("attacks", "攻击态势", "ok", "；".join(parts), data, advice)


def check_system(db: Session, ctx: dict[str, Any] | None = None) -> CheckResult:
    """系统风险：熔断开关、归属地库、插件注册一致性。"""
    from app.services import geoip

    problems: list[str] = []
    advice: list[str] = []
    if cache.kill_switch:
        problems.append("自动封禁熔断已开启，所有告警只留痕不处置")
        advice.append("确认后在「系统设置」关闭熔断恢复自动封禁")
    geo_health = geoip.health()
    geo_ready = bool(geo_health.get("enabled")) and bool(geo_health.get("db_exists"))
    if not geo_ready:
        problems.append("IP 归属地库未安装，黑名单国家/地区列为空")
        advice.append("执行 python scripts/fetch_geoip.py 下载归属地库")
    builtin_codes = {m["plugin_code"] for m in registry.list_manifests()}
    stored_codes = {row.plugin_code for row in db.query(DevicePlugin).all()
                    if row.enabled}
    missing = builtin_codes - stored_codes
    if missing:
        problems.append(f"以下内置插件未同步到数据库：{', '.join(sorted(missing))}")
        advice.append("重启后端触发插件注册同步")

    data = {"kill_switch": cache.kill_switch, "geoip_ready": geo_ready,
            "missing_plugins": sorted(missing)}
    if problems:
        return CheckResult(
            "system", "系统风险", "fail" if cache.kill_switch else "warn",
            "；".join(problems), data, " ".join(advice),
        )
    return CheckResult(
        "system", "系统风险", "ok", "熔断关闭、归属地库就绪、插件注册一致", data,
    )


# 兜底异常项的中文名（检查函数本身异常时无法从 docstring 取名）
CHECK_NAMES = {
    "devices": "设备连通性", "sources": "三流覆盖", "gap": "封禁缺口",
    "detection": "处置率", "persistent": "持续攻击源", "blacklist": "黑名单健康",
    "tasks": "任务队列", "expire": "到期解封风险", "whitelist": "白名单风险",
    "policies": "策略覆盖", "attacks": "攻击态势", "system": "系统风险",
}


CHECKS: list[Callable[..., CheckResult]] = [
    # 安全效果层：先看防护有没有真的生效
    check_sources, check_gap, check_detection, check_persistent,
    # 平台运行层
    check_devices, check_blacklist, check_expire, check_tasks,
    check_policies, check_whitelist, check_attacks, check_system,
]


# ---------------------------------------------------------------- 总结生成

def _rule_summary(checks: list[CheckResult]) -> str:
    """规则拼接的中文总结：没有 LLM 也能给出可执行的结论。"""
    failed = [c for c in checks if c["status"] == "fail"]
    warned = [c for c in checks if c["status"] == "warn"]
    ok = [c for c in checks if c["status"] == "ok"]
    parts: list[str] = []
    if not failed and not warned:
        parts.append("各项检查全部通过，平台处于健康运行状态。")
    else:
        if failed:
            parts.append("存在必须处理的问题：" + "；".join(
                f"{c['name']}（{c['summary']}）" for c in failed) + "。")
        if warned:
            parts.append("需要关注：" + "；".join(
                f"{c['name']}——{c['summary']}" for c in warned) + "。")
    advices = [c["advice"] for c in checks if c.get("advice")]
    if advices:
        parts.append("建议：" + " ".join(advices[:4]))
    if ok:
        parts.append(f"正常项：{('、'.join(c['name'] for c in ok))}。")
    return "".join(parts)


def _llm_summary(checks: list[CheckResult], score: int,
                 report_metrics: dict[str, Any] | None = None) -> str | None:
    """调用 OpenAI 兼容接口生成总结；未配置或失败返回 None（回退规则总结）。"""
    base = (settings.ai_llm_base_url or "").strip().rstrip("/")
    key = (settings.ai_llm_api_key or "").strip()
    if not base or not key:
        return None
    digest = [
        {"name": c["name"], "status": c["status"], "summary": c["summary"],
         "advice": c.get("advice", "")}
        for c in checks
    ]
    prompt = (
        f"这是一个 SOAR 安全运营平台的日巡检结果，加权健康分 {score}/100。"
        "平台接入 IPS / WAF / 零信任三路日志，按策略自动下发防火墙黑名单。"
        "请用不超过 220 字的中文给出一段面向安全运营工程师的总结："
        "先给总体结论（防护是否真的生效，而不是设备是否在线），"
        "再指出最需要处理的 1-3 件事，能落到具体动作（补策略/修下发/缩白名单/拉长封禁时长）。"
        "不要使用 markdown 标题。\n"
        f"核心指标：{json.dumps(report_metrics or {}, ensure_ascii=False)}\n"
        f"巡检明细：{json.dumps(digest, ensure_ascii=False)}"
    )
    try:
        import urllib.error
        import urllib.request

        body = json.dumps({
            "model": settings.ai_llm_model or "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.3,
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{base}/chat/completions", data=body, method="POST",
            headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
        )
        with urllib.request.urlopen(req, timeout=20) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        content = (payload.get("choices") or [{}])[0].get("message", {}).get("content", "")
        return content.strip() or None
    except Exception as exc:  # noqa: BLE001 - LLM 失败不影响巡检结果
        logger.warning("AI 总结生成失败，回退规则总结：%s", exc)
        return None


# ---------------------------------------------------------------- 主入口

def _collect_metrics(db: Session, ctx: dict[str, Any]) -> dict[str, Any]:
    """把各检查项已经算好的指标汇总成前端 KPI 条用的扁平结构。"""
    gap = _shared(ctx, "gap", lambda: metrics.gap_breakdown(db))
    trend = _shared(ctx, "trend", lambda: metrics.detection_trend(db))
    per = _shared(ctx, "persistent", lambda: metrics.persistent_attackers(db))
    sources = _shared(ctx, "sources", lambda: metrics.source_coverage(db))
    rhythm = _shared(ctx, "rhythm", lambda: metrics.block_rhythm(db))
    return {
        "detection_rate_24h": gap["block_rate"],
        "detection_rate_7d": trend["avg_rate"],
        "detected_ips_24h": gap["detected_ips"],
        "blocked_ips_24h": gap["blocked_ips"],
        "gap_ips_24h": gap["gap_ips"],
        "exempt_ips_24h": gap["exempt_ips"],
        "alerts_24h": gap["alerts"],
        "persistent_ips": per["total"],
        "active_sources": sources["active_sources"],
        "core_sources": sources["core_active"],
        "missing_sources": sources["missing_core"],
        "blocked_24h": rhythm["blocked"],
        "peak_hour": rhythm["peak_hour"],
        "peak_count": rhythm["peak_count"],
        "trend": trend["series"],
    }


def run_inspection(db: Session, *, trigger: str = "manual",
                   created_by: str = "system") -> InspectionReport:
    """执行一次全量巡检并落库；任何单项异常降级为 fail，不中断整场巡检。"""
    started = time.monotonic()
    ctx: dict[str, Any] = {}  # 同一次巡检内复用指标查询
    checks: list[CheckResult] = []
    for fn in CHECKS:
        try:
            checks.append(_invoke(fn, db, ctx))
        except Exception as exc:  # noqa: BLE001 - 单项失败不能拖垮巡检
            logger.warning("巡检项 %s 执行失败：%s", fn.__name__, exc)
            checks.append(CheckResult(
                fn.__name__.replace("check_", ""),
                CHECK_NAMES.get(fn.__name__.replace("check_", ""), fn.__name__), "fail",
                f"检查执行异常：{exc}",
                advice="查看后端日志定位该项检查失败原因",
            ))

    weight_sum = sum(CHECK_WEIGHTS.get(c["key"], 1.0) for c in checks)
    score = round(
        sum(c["score"] * CHECK_WEIGHTS.get(c["key"], 1.0) for c in checks) / weight_sum
    ) if weight_sum else 0
    overall = "fail" if any(c["status"] == "fail" for c in checks) else (
        "warn" if any(c["status"] == "warn" for c in checks) else "ok")

    try:
        report_metrics = _collect_metrics(db, ctx)
    except Exception as exc:  # noqa: BLE001 - 指标汇总失败不影响报告本身
        logger.warning("巡检指标汇总失败：%s", exc)
        report_metrics = {}
    previous = (
        db.query(InspectionReport)
        .order_by(InspectionReport.created_at.desc(), InspectionReport.id.desc())
        .first()
    )
    if previous is not None:
        report_metrics["previous_score"] = previous.score
        report_metrics["score_delta"] = score - previous.score

    summary = _rule_summary(checks)
    ai_summary = _llm_summary(checks, score, report_metrics)
    ai_enhanced = 0
    if ai_summary:
        summary = ai_summary
        ai_enhanced = 1

    report = InspectionReport(
        score=score,
        overall=overall,
        trigger=trigger,
        duration_ms=int((time.monotonic() - started) * 1000),
        checks=[dict(c) for c in checks],
        metrics=report_metrics,
        summary=summary,
        ai_enhanced=ai_enhanced,
        created_by=created_by,
    )
    db.add(report)
    db.commit()
    logger.info("AI 巡检完成：score=%s overall=%s duration=%sms ai=%s",
                score, overall, report.duration_ms, bool(ai_enhanced))
    return report
