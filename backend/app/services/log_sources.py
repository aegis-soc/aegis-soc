"""日志源视图：把巡检配置里的 streams 呈现为「数据源」，并带上最近一轮的健康度。

设计取舍：
- **不新建表**。日志源就是巡检配置里的 ``streams``（模型注释里写的"避免两处维护"），
  这里只做读视图与局部更新，不引入第二份配置。
- **健康度不另跑查询**。巡检每轮已经在 ``patrol_run.summary.streams`` 里记了
  每流的条数、错误、字段缺失与 schema 打标，直接复用，避免为了看板再压一遍 Graylog。
- 状态判定集中在 ``_state()``：未配置 / 已禁用 / 未跑过 / 失败 / 降级 / 正常，
  前端只按这个枚举上色，不自己算阈值。
"""
from __future__ import annotations

import logging
from typing import Any

from sqlalchemy.orm import Session

from app.common import BizError
from app.database import utcnow
from app.models import PatrolRun
from app.services import patrol, patrol_settings

logger = logging.getLogger("aegis")

# 契约告警阈值：与 docs/log-source-spec.md §7.2 一致
SCHEMA_BAD_RATIO = 0.01      # 打标不合规占比 > 1% → 降级
MISSING_RATIO = 0.005        # 必填字段缺失率 > 0.5% → 降级


def _ratio(part: int, total: int) -> float:
    if not total:
        return 0.0
    return round(part / total, 4)


def _state(item: dict[str, Any], stat: dict[str, Any] | None) -> str:
    """六态归一：前端只认这六个值。"""
    if item.get("enabled") is False:
        return "disabled"
    if not item.get("stream_id") and not item.get("query"):
        return "unconfigured"
    if not stat:
        return "unknown"
    if stat.get("error"):
        return "failed"
    if stat.get("skipped"):
        return "skipped"
    fetched = int(stat.get("fetched") or 0)
    if fetched == 0:
        return "empty"
    bad = _ratio(int(stat.get("schema_bad") or 0), fetched)
    missing = _ratio(int(stat.get("missing_total") or 0), fetched * max(1, len(stat.get("required_fields") or [])))
    if bad > SCHEMA_BAD_RATIO or missing > MISSING_RATIO:
        return "degraded"
    return "ok"


def _health(stat: dict[str, Any] | None, run: PatrolRun | None) -> dict[str, Any]:
    if not stat:
        return {
            "state": "unknown", "fetched": 0, "missing": {}, "missing_total": 0,
            "missing_ratio": 0.0, "schema_ok": 0, "schema_bad": 0, "schema_bad_ratio": 0.0,
            "ts_fallback": 0, "error": "", "skipped": "", "last_run_at": None,
        }
    fetched = int(stat.get("fetched") or 0)
    missing_total = int(stat.get("missing_total") or 0)
    required_count = max(1, len(stat.get("required_fields") or []))
    return {
        "state": "",
        "fetched": fetched,
        "missing": stat.get("missing") or {},
        "missing_total": missing_total,
        "missing_ratio": _ratio(missing_total, fetched * required_count),
        "schema_ok": int(stat.get("schema_ok") or 0),
        "schema_bad": int(stat.get("schema_bad") or 0),
        "schema_bad_ratio": _ratio(int(stat.get("schema_bad") or 0), fetched),
        "ts_fallback": int(stat.get("ts_fallback") or 0),
        "error": stat.get("error") or "",
        "skipped": stat.get("skipped") or "",
        "last_run_at": run.created_at.isoformat() if run is not None else None,
    }


def latest_run(db: Session) -> PatrolRun | None:
    return (
        db.query(PatrolRun)
        .order_by(PatrolRun.created_at.desc(), PatrolRun.id.desc())
        .first()
    )


def list_sources(db: Session) -> dict[str, Any]:
    """数据源清单 + 最近一轮健康度。只读，不触发任何 Graylog 查询。"""
    cfg = patrol_settings.load(db)
    # 老库只有 ips/waf/ztna 三条：把规范里定义、但配置里还没有的源补成占位行，
    # 页面才能看到「NTA 未接入」而不是干脆不显示。占位行不入库，编辑时才落。
    present = {str(s.get("source_code") or "") for s in cfg.streams}
    for spec in patrol_settings.DEFAULT_STREAMS:
        if spec["source_code"] not in present:
            cfg.streams.append(dict(spec))

    run = latest_run(db)
    stats: dict[str, dict[str, Any]] = {}
    if run is not None and isinstance(run.summary, dict):
        for stat in run.summary.get("streams") or []:
            if isinstance(stat, dict) and stat.get("name"):
                stats[str(stat["name"]).upper()] = stat

    items: list[dict[str, Any]] = []
    for stream in cfg.streams:
        stat = stats.get(str(stream.get("name", "")).upper())
        health = _health(stat, run)
        health["state"] = _state(stream, stat)
        items.append({
            **stream,
            "health": health,
            "configured": bool(stream.get("stream_id") or stream.get("query")),
        })

    total_fetched = sum(item["health"]["fetched"] for item in items)
    bad = sum(1 for item in items if item["health"]["state"] in {"failed", "degraded"})
    return {
        "mcp": {
            "configured": cfg.configured,
            "url": patrol_settings.public(cfg)["mcp_url"],
            "enabled": cfg.enabled,
            "source": cfg.source,
            "interval_seconds": cfg.interval,
            "mode": cfg.mode,
        },
        "items": items,
        "summary": {
            "total": len(items),
            "configured": sum(1 for item in items if item["configured"]),
            "abnormal": bad,
            "fetched": total_fetched,
            "last_run_at": run.created_at.isoformat() if run is not None else None,
            "run_status": run.status if run is not None else None,
        },
        "spec": {
            "schema_bad_ratio": SCHEMA_BAD_RATIO,
            "missing_ratio": MISSING_RATIO,
            "doc": "docs/log-source-spec.md",
        },
    }


def probe_source(db: Session, source_code: str, minutes: int | None = None,
                 limit: int = 20) -> dict[str, Any]:
    """对单个源立即取一次数，返回实际发送的参数与服务端原始返回。

    与巡检的区别：**不受巡检间隔约束、也不落库**，纯粹是排查「为什么显示无数据」。
    """
    code = (source_code or "").strip().lower()
    cfg = patrol_settings.load(db)
    target = next((s for s in cfg.streams if s.get("source_code") == code), None)
    if target is None:
        target = next((s for s in patrol_settings.DEFAULT_STREAMS
                       if s["source_code"] == code), None)
    if target is None:
        raise BizError(f"未找到日志源 {code}", 404, 404)
    if not cfg.configured:
        raise BizError("尚未配置 Graylog MCP 地址", 400, 400)
    result = patrol.probe_stream(
        target, cfg=cfg,
        minutes=minutes or patrol.PROBE_WINDOW_MINUTES, limit=limit,
    )
    result["source_code"] = code
    result["label"] = target.get("label") or target.get("name")
    logger.info("试取日志源 %s：fetched=%s error=%s（对照组 %s）", code,
                result.get("fetched"), result.get("error") or "-",
                (result.get("control") or {}).get("fetched"))
    return result


UPDATABLE = {"stream_id", "query", "enabled", "required_fields", "schema_version",
             "label", "purpose", "field_mapping"}


def update_source(db: Session, source_code: str, data: dict[str, Any],
                  operator: str = "system") -> dict[str, Any]:
    """局部更新一个源：只改传进来的字段，其余保留。

    流配置是数组，改一项要整体回写；这里先基于当前配置改数组，再交给
    ``patrol_settings.save`` 做校验与落库，保证与「巡检配置」页同一条写路径。
    """
    code = (source_code or "").strip().lower()
    cfg = patrol_settings.load(db)
    target = next((s for s in cfg.streams if s.get("source_code") == code), None)
    if target is None:
        # 配置里还没有这个源（如首次接入 NTA）：按规范默认值补一条再更新，
        # 否则「先启用再配 stream_id」这个正常动作会被 404 挡住。
        default = next((s for s in patrol_settings.DEFAULT_STREAMS
                        if s["source_code"] == code), None)
        if default is None:
            raise BizError(f"未找到日志源 {code}", 404, 404)
        cfg.streams.append(dict(default))

    streams: list[dict[str, Any]] = []
    for stream in cfg.streams:
        item = dict(stream)
        if item.get("source_code") == code:
            for key, value in data.items():
                if key in UPDATABLE:
                    item[key] = value
        streams.append(item)

    saved = patrol_settings.save(db, {"streams": streams}, operator=operator)
    updated = next((s for s in saved.streams if s.get("source_code") == code), None)
    logger.info("日志源 %s 已更新（by %s）：stream_id=%s enabled=%s",
                code, operator, (updated or {}).get("stream_id"), (updated or {}).get("enabled"))
    return {
        "source": updated,
        "updated_at": utcnow().isoformat(),
    }
