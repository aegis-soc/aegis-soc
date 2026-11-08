"""日志查询编译器：``dsl.LogSpec`` → Graylog MCP 检索 → 结构化结果。

口径上刻意与「日志巡检」共用同一套东西，不另起一套：

- 客户端与三流配置直接取 ``patrol.load_config`` / ``patrol.build_client``，
  页面里配的地址、Token、流映射改了，这里立刻生效；
- 字段归一用 ``patrol.FIELD_ALIASES``，动作判定用 ``patrol.classify_action``，
  避免"自然语言查出来的未拦截数"和"巡检说漏封的数"对不上；
- 抓取走 ``patrol._fetch_stream``，参数映射/SSE 兼容/降级逻辑都不重写。

**为什么在内存里过滤而不是拼 Graylog 查询串**：三流字段名差异极大
（``action`` / ``act`` / ``disposition`` …），拼错字段名 Graylog 不报错、
只会静默返回 0 条，比查错更难发现。所以按单流上限抓取后在本地做归一过滤，
并在结果里如实标注"本次扫描了 N 条"。代价是采样上限，换来的是口径一致。
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.database import utcnow
from app.engines.validation import validate_ioc
from app.services.chat import catalog
from app.services.chat.dsl import LogSpec
from app.services.patrol import (
    FIELD_ALIASES,
    _fetch_stream,
    _first,
    build_client,
    classify_action,
    load_config,
    load_streams,
    parse_severity,
)

logger = logging.getLogger("aegis")


class LogQueryError(RuntimeError):
    """Graylog 侧不可用（未配置 / 连不上 / 工具报错）。由 pipeline 转成人话。"""


def _stream_filter(streams: list[dict[str, str]], wanted: list[str]) -> list[dict[str, str]]:
    if not wanted:
        return streams
    chosen = [s for s in streams if s.get("name") in wanted]
    return chosen or streams


def run(db: Session, spec: LogSpec) -> dict[str, Any]:
    """执行一次三流检索并聚合。异常统一转 ``LogQueryError``。"""
    try:
        cfg = load_config(db)
        client = build_client(cfg, db)
    except Exception as exc:                # noqa: BLE001
        raise LogQueryError(f"Graylog MCP 未就绪：{exc}") from exc

    streams = _stream_filter(load_streams(cfg, db), spec.streams)
    end = utcnow()
    start = end - timedelta(days=spec.time.last_days)
    limit = min(spec.limit, catalog.MAX_LIMIT)

    records: list[dict[str, Any]] = []
    stream_stats: list[dict[str, Any]] = []
    errors: list[str] = []
    try:
        for stream in streams:
            items, status = _fetch_stream(client, stream, start, end, limit, cfg)
            stream_stats.append(status)
            if status.get("error"):
                errors.append(f"{stream.get('name')}: {status['error'][:120]}")
            for record in items:
                record.setdefault("_stream", stream.get("name", ""))
            records.extend(items)
    except Exception as exc:                # noqa: BLE001 - 传输层抖动
        raise LogQueryError(f"读取 Graylog 失败：{exc}") from exc

    if not records and errors and len(errors) == len(streams):
        raise LogQueryError("三流均读取失败：" + "；".join(errors[:2]))

    matched = [r for r in records if _keep(r, spec)]
    result = _aggregate(db, matched, spec, len(records))
    result["stream_stats"] = stream_stats
    result["errors"] = errors
    result["window"] = {
        "start": start.strftime("%Y-%m-%d %H:%M"),
        "end": end.strftime("%Y-%m-%d %H:%M"),
        "days": spec.time.last_days,
    }
    result["action"] = spec.action
    result["sql"] = ""                      # 日志路径没有 SQL，前端统一按 trace 展示
    result["query_desc"] = _describe(spec, streams)
    return result


def _keep(record: dict[str, Any], spec: LogSpec) -> bool:
    if not _first(record, FIELD_ALIASES["ip"]):
        return False                        # 没有源 IP 的记录进不了 Top 榜
    if spec.action != "any":
        action = classify_action(_first(record, FIELD_ALIASES["action"]))
        expected = "observe" if spec.action == "pass" else "block"
        if action != expected:
            return False
    if spec.severity_min:
        if parse_severity(_first(record, FIELD_ALIASES["severity"])) < spec.severity_min:
            return False
    if spec.keyword and spec.keyword.lower() not in str(record).lower():
        return False
    return True


def _describe(spec: LogSpec, streams: list[dict[str, str]]) -> str:
    action_text = {"pass": "未拦截/放行", "block": "已拦截", "any": "全部动作"}[spec.action]
    names = "、".join(s.get("name", "") for s in streams)
    return f"{names} · 近 {spec.time.last_days} 天 · {action_text}"


def _aggregate(db: Session, records: list[dict[str, Any]], spec: LogSpec,
               fetched: int) -> dict[str, Any]:
    if spec.group_by == "stream":
        counter: Counter[str] = Counter(r.get("_stream", "") for r in records)
        rows = [{"label": name or "(未知)", "value": float(count), "raw": name}
                for name, count in counter.most_common(min(spec.limit, catalog.MAX_LIMIT))]
        group_label, columns = "日志流", [{"key": "label", "label": "日志流"},
                                       {"key": "value", "label": "记录数"}]
    elif spec.group_by == "rule":
        counter = Counter(_first(r, FIELD_ALIASES["rule"]) or "(未命名规则)" for r in records)
        rows = [{"label": name, "value": float(count), "raw": name}
                for name, count in counter.most_common(min(spec.limit, catalog.MAX_LIMIT))]
        group_label, columns = "规则", [{"key": "label", "label": "规则 / 事件名"},
                                      {"key": "value", "label": "记录数"}]
    else:
        rows, group_label, columns = _by_ip(db, records, spec)

    return {
        "source": "log",
        "source_label": "三流日志",
        "group_by": spec.group_by,
        "group_label": group_label,
        "metric": "count",
        "metric_label": "记录数",
        "columns": columns,
        "rows": rows,
        "total": float(len(records)),
        "fetched": fetched,
        "matched": len(records),
        "truncated": len(records) >= min(spec.limit, catalog.MAX_LIMIT),
        "days": spec.time.last_days,
        "filters": {"action": spec.action, "severity_min": spec.severity_min},
    }


def _by_ip(db: Session, records: list[dict[str, Any]], spec: LogSpec) -> tuple[list[dict], str, list[dict]]:
    """按源 IP 聚合，并顺带标出「这个 IP 是否已在平台黑名单里」。"""
    counter: Counter[str] = Counter()
    streams_of: dict[str, Counter[str]] = defaultdict(Counter)
    last_seen: dict[str, str] = {}
    for record in records:
        ip = _first(record, FIELD_ALIASES["ip"])
        counter[ip] += 1
        streams_of[ip][record.get("_stream", "")] += 1
        stamp = _first(record, FIELD_ALIASES["timestamp"])
        if stamp and (ip not in last_seen or stamp > last_seen[ip]):
            last_seen[ip] = stamp

    top = counter.most_common(min(spec.limit, catalog.MAX_LIMIT))
    blocked = _blocked_lookup(db, [ip for ip, _ in top])
    rows = []
    for ip, count in top:
        # 内网/保留地址不参与"漏封"判断：它们本来就不该进黑名单（与巡检同口径）
        internal = not validate_ioc("IP", ip).ok
        rows.append({
            "label": ip,
            "value": float(count),
            "raw": ip,
            "streams": "、".join(name for name, _ in streams_of[ip].most_common()),
            "last_seen": last_seen.get(ip, ""),
            "blocked": blocked.get(ip, False),
            "internal": internal,
        })
    columns = [
        {"key": "label", "label": "源 IP"},
        {"key": "value", "label": "记录数"},
        {"key": "streams", "label": "来源流"},
        {"key": "last_seen", "label": "最近出现"},
        {"key": "blocked", "label": "已在黑名单"},
    ]
    return rows, "源 IP", columns


def _blocked_lookup(db: Session, ips: list[str]) -> dict[str, bool]:
    """这些 IP 是否已在生效黑名单里——一句话就能看出「是漏封还是已封」。"""
    if not ips:
        return {}
    from app.models import IocIndicator

    try:
        rows = (
            db.query(IocIndicator.normalized_value)
            .filter(IocIndicator.normalized_value.in_(ips), IocIndicator.status == "active")
            .all()
        )
        return {str(row[0]): True for row in rows}
    except Exception as exc:                # noqa: BLE001 - 只是增值信息，失败不影响主结果
        logger.debug("黑名单命中回填失败：%s", exc)
        return {}
