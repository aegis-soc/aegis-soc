"""日志巡检（P0）：通过 MCP 读 Graylog 三流日志，找 Graylog 规则漏掉的攻击源。

与「平台自检」（``inspector.py``）的分工：

* 平台自检回答"平台自己是否健康"——设备、任务、黑名单、策略，日频；
* 日志巡检回答"有没有攻击被放过"——直接读 Graylog 日志，5 分钟一轮。

P0 的边界（刻意收窄，先把"看得见"做出来）：

1. **只读**：不进封禁链路，不建 IOC、不建任务，``blocked`` 恒为 0；
2. **L1 规则**：确定性特征，便宜、可解释，先用它把日志压到少量候选；
3. **闸门预判**：白名单、已封、重复命中都会算出"如果执行会怎样"，写进报告，
   让上线前就能看清 auto 模式的真实行为；
4. **可降级**：MCP 抖动只让本轮 ``degraded / failed``，绝不抛出、绝不误封。

L2（LLM 研判）与真正下发在 P1/P2 接，接的时候复用这里已经产出的候选与摘要。
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.database import utcnow
from app.engines.validation import check_whitelist, validate_ioc
from app.models import IocIndicator, PatrolCandidate, PatrolRun
from app.services.mcp_client import McpError, McpHttpClient, mask_url, parse_tool_result

logger = logging.getLogger("aegis")

# ---------------------------------------------------------------- 字段归一
# 三流厂商字段名差异极大，这里按"常见候选名"匹配；命中优先级即列表顺序。
# 需要适配新设备时只改这里，不动规则逻辑。
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "ip": (
        "src_ip", "source_ip", "client_ip", "remote_addr", "srcaddr", "attacker_ip",
        "source_address", "sip", "src", "ip",
    ),
    "action": (
        "action", "act", "disposition", "action_type", "event_action", "verdict", "result",
    ),
    "severity": (
        "severity", "event_severity", "priority", "level", "risk_level", "threat_level",
    ),
    "rule": (
        "rule_name", "signature", "event_name", "alert_name", "threat_name",
        "rule", "title", "event_definition_title", "message",
    ),
    "message_id": ("_id", "message_id", "id", "gl2_message_id", "event_id"),
    "timestamp": ("timestamp", "event_time", "time", "@timestamp", "created_at"),
}

BLOCK_WORDS = {
    "block", "blocked", "deny", "denied", "drop", "dropped", "reject", "rejected",
    "reset", "close", "closed", "阻断", "拦截", "拒绝", "封禁", "丢弃",
}
OBSERVE_WORDS = {
    "alert", "alerted", "allow", "allowed", "pass", "passed", "permit", "permitted",
    "log", "logged", "monitor", "monitored", "detect", "detected", "report", "observe",
    "放行", "告警", "记录", "监控", "允许", "检测", "观察",
}

# L1 规则表：key -> (中文名, 权重, 说明)
RULES: dict[str, tuple[str, int, str]] = {
    "ips_observed": ("IPS 告警未阻断", 3, "IPS 侧 action 非阻断，攻击未被拦下"),
    "waf_observed": ("WAF 放行/仅记录", 2, "WAF 对攻击请求放行或仅记录"),
    "ztna_burst": ("零信任认证爆破", 3, "同源认证失败次数超过阈值"),
    "high_freq": ("高频访问", 2, "窗口内同源日志条数超过阈值"),
    "multi_stream": ("跨流命中", 2, "同一 IP 同时出现在两条以上日志流"),
    "intel_hit": ("情报命中", 4, "日志字段显示威胁情报 / 网监清单命中"),
}

ZTNA_FAIL_THRESHOLD = 10   # 同一 IP 在本窗口内的零信任失败次数
HIGH_FREQ_THRESHOLD = 50   # 同一 IP 在本窗口内的日志条数
MAX_CANDIDATES = 200       # 单轮最多落库的候选 IP，防止异常日志把表撑爆

DEFAULT_STREAMS: list[dict[str, str]] = [
    {"name": "IPS", "label": "IPS 入侵防御", "stream_id": "", "query": ""},
    {"name": "WAF", "label": "WAF 应用防火墙", "stream_id": "", "query": ""},
    {"name": "ZTNA", "label": "零信任接入", "stream_id": "", "query": ""},
]


# ---------------------------------------------------------------- 配置解析
def load_streams() -> list[dict[str, str]]:
    """读 PATROL_STREAMS；坏配置不要让巡检整体挂掉，退回内置三流。"""
    try:
        raw = json.loads(settings.patrol_streams or "[]")
    except json.JSONDecodeError:
        logger.warning("PATROL_STREAMS 不是合法 JSON，使用内置三流配置")
        return [dict(s) for s in DEFAULT_STREAMS]
    if not isinstance(raw, list) or not raw:
        return [dict(s) for s in DEFAULT_STREAMS]
    streams: list[dict[str, str]] = []
    for item in raw:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        streams.append({
            "name": str(item.get("name")).upper(),
            "label": str(item.get("label") or item.get("name")),
            "stream_id": str(item.get("stream_id") or ""),
            "query": str(item.get("query") or ""),
        })
    return streams or [dict(s) for s in DEFAULT_STREAMS]


def build_client() -> McpHttpClient:
    return McpHttpClient(
        settings.patrol_mcp_url,
        token=settings.patrol_mcp_token,
        timeout=settings.patrol_mcp_timeout,
        auth=settings.patrol_mcp_auth,
    )


# 参数角色 → 常见字段名。工具 inputSchema 里出现哪个就用哪个，
# 这样 Graylog 升级换了参数名也不用改代码。
ARG_ALIASES: dict[str, tuple[str, ...]] = {
    "query": ("query", "search_query", "query_string", "q", "search", "filter"),
    "stream": ("stream_id", "stream_ids", "streams", "stream", "streamId"),
    "from": ("from", "start", "start_time", "from_time", "since", "timerange_start"),
    "to": ("to", "end", "end_time", "to_time", "until", "timerange_end"),
    "limit": ("limit", "size", "per_page", "page_size", "count", "max_results"),
}


def map_arguments(schema: dict[str, Any] | None, *, stream_id: str, query: str,
                  start: datetime, end: datetime, limit: int) -> dict[str, Any] | None:
    """按工具 inputSchema 自动拼参数；无法映射时返回 None（由调用方走模板兜底）。

    只放 schema 声明过的字段——多传未知参数会被严格实现直接拒绝。
    """
    properties = (schema or {}).get("properties")
    if not isinstance(properties, dict) or not properties:
        return None

    values: dict[str, Any] = {
        "query": query,
        "stream": stream_id,
        "from": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "to": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": limit,
    }
    arguments: dict[str, Any] = {}
    for role, aliases in ARG_ALIASES.items():
        name = next((a for a in aliases if a in properties), None)
        if name is None:
            continue
        value = values[role]
        if isinstance(value, str) and not value.strip():
            continue          # 空查询/空流 id 不传，避免服务端当成精确过滤条件
        declared = properties.get(name) or {}
        kind = declared.get("type") if isinstance(declared, dict) else None
        if role == "stream" and kind == "array":
            arguments[name] = [value]
        elif role == "limit" and kind == "string":
            arguments[name] = str(value)
        else:
            arguments[name] = value
    return arguments or None


def render_args(template: str, *, stream_id: str, query: str, start: datetime,
                end: datetime, limit: int) -> dict[str, Any]:
    """把模板里的占位符替换成实际值，再解析为 dict。

    ``${limit}`` 按数字替换，其余按字符串替换（因此模板里字符串占位符必须自带引号）。
    模板非法时退回最朴素的参数形状，保证不同 MCP 实现都能被调到。
    """
    values = {
        "stream_id": stream_id,
        "stream": stream_id,
        "query": query,
        "from": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "to": end.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "limit": limit,
    }
    text = template or "{}"
    for key, value in values.items():
        placeholder = "${" + key + "}"
        if placeholder not in text:
            continue
        if isinstance(value, int):
            text = text.replace(placeholder, str(value))
        else:
            # 用 JSON 转义后的内容替换，避免引号/换行把模板破坏
            text = text.replace(placeholder, json.dumps(str(value), ensure_ascii=False)[1:-1])
    try:
        parsed = json.loads(text)
    except json.JSONDecodeError:
        logger.warning("PATROL_MCP_ARGS 渲染后不是合法 JSON，退回默认参数")
        return {
            "stream_id": stream_id, "query": query,
            "from": values["from"], "to": values["to"], "limit": limit,
        }
    return parsed if isinstance(parsed, dict) else {"value": parsed}


# ---------------------------------------------------------------- 记录归一
def _first(record: dict[str, Any], keys: tuple[str, ...]) -> str:
    """按候选名顺序取第一个非空标量；list 取首元素，dict 跳过。"""
    for key in keys:
        value = record.get(key)
        if isinstance(value, (list, tuple)) and value:
            value = value[0]
        if isinstance(value, dict):
            continue
        if value is None:
            continue
        text = str(value).strip()
        if text and text.lower() not in {"-", "none", "null", "n/a"}:
            return text
    return ""


def _flatten(item: Any) -> dict[str, Any]:
    """Graylog 的 message 可能是 ``{"message": {...}}`` 包装，统一拍平。"""
    if not isinstance(item, dict):
        return {}
    inner = item.get("message")
    merged: dict[str, Any] = {}
    if isinstance(inner, dict):
        merged.update(inner)
        fields = inner.get("fields")
        if isinstance(fields, dict):
            merged.update(fields)
    merged.update({k: v for k, v in item.items() if k != "message"})
    fields = merged.get("fields")
    if isinstance(fields, dict):
        merged.update(fields)
    return {str(k).lower(): v for k, v in merged.items()}


def extract_records(payload: Any, _depth: int = 0) -> list[dict[str, Any]]:
    """从 MCP 工具返回里取出消息列表，兼容常见几种包法（最多递归 3 层）。"""
    if payload is None or _depth > 3:
        return []
    if isinstance(payload, str):
        try:
            return extract_records(json.loads(payload), _depth + 1)
        except json.JSONDecodeError:
            return []
    if isinstance(payload, list):
        return [_flatten(x) for x in payload if isinstance(x, dict)]
    if isinstance(payload, dict):
        for key in ("messages", "data", "records", "items", "results", "hits", "documents"):
            value = payload.get(key)
            if isinstance(value, list):
                return [_flatten(x) for x in value if isinstance(x, dict)]
            if isinstance(value, dict):
                nested = extract_records(value, _depth + 1)
                if nested:
                    return nested
        # 单个 message 对象
        if any(k in payload for k in ("_id", "message", "fields", "timestamp")):
            return [_flatten(payload)]
    return []


def classify_action(value: str) -> str:
    text = (value or "").strip().lower()
    if not text:
        return "unknown"
    for word in BLOCK_WORDS:
        if word in text:
            return "block"
    for word in OBSERVE_WORDS:
        if word in text:
            return "observe"
    return "unknown"


def parse_severity(value: str) -> int:
    """把 1-10 数字或 low/medium/high 文本统一成 1-5。"""
    text = (value or "").strip().lower()
    if not text:
        return 0
    if text.isdigit():
        number = int(text)
        if number <= 0:
            return 0
        if number <= 5:
            return number
        return min(5, max(1, (number + 1) // 2))
    table = {
        "info": 1, "informational": 1, "debug": 1, "低": 2, "low": 2,
        "medium": 3, "moderate": 3, "warn": 3, "warning": 3, "中": 3,
        "high": 4, "高": 4, "critical": 5, "severe": 5, "emergency": 5,
        "严重": 5, "紧急": 5, "致命": 5,
    }
    for key, level in table.items():
        if key in text:
            return level
    return 0


def _parse_time(value: str, fallback: datetime) -> datetime:
    """日志时间戳尽力解析；失败用窗口时间兜底，绝不让一条脏数据毁掉整轮。"""
    text = (value or "").strip()
    if not text:
        return fallback
    candidates = [
        text.replace("Z", "+00:00"),
        text.replace("/", "-"),
        text[:19].replace("T", " "),
    ]
    for candidate in candidates:
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError:
            continue
        if parsed.tzinfo is not None:
            # 统一换算成 UTC naive，与 utcnow() 同一坐标，避免 +08:00 造成的时间漂移
            parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
        return parsed
    return fallback


def has_intel_signal(record: dict[str, Any]) -> bool:
    """情报命中：看标签/字段名与数值，不做精确判定（那是 L2 的事）。"""
    for key, value in record.items():
        if key in {"tags", "tag"}:
            text = str(value).lower()
            if any(k in text for k in ("intel", "malicious", "netpolice", "blacklist", "情报")):
                return True
        if key in {"ti_score", "intel_score", "threat_score", "reputation"}:
            try:
                if float(value) >= 60:
                    return True
            except (TypeError, ValueError):
                pass
        if key in {"threat_intel", "intel_hit", "blacklisted", "malicious"}:
            if str(value).strip().lower() in {"1", "true", "yes", "hit", "命中"}:
                return True
    return False


# ---------------------------------------------------------------- 候选聚合
@dataclass
class Candidate:
    ip: str
    hits: int = 0
    streams: set[str] = field(default_factory=set)
    rule_counts: dict[str, int] = field(default_factory=dict)
    ztna_failures: int = 0   # 零信任失败计数，达阈值才升级成规则
    severity: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    samples: list[str] = field(default_factory=list)
    decision: str = "would_block"
    decision_reason: str = ""

    @property
    def weight(self) -> int:
        return sum(RULES[k][1] * n for k, n in self.rule_counts.items() if k in RULES)

    def add_rule(self, key: str) -> None:
        if key in RULES:
            self.rule_counts[key] = self.rule_counts.get(key, 0) + 1

    def rules_payload(self) -> list[dict[str, Any]]:
        return [
            {"key": key, "name": RULES[key][0], "count": count}
            for key, count in sorted(self.rule_counts.items(), key=lambda kv: -kv[1])
            if key in RULES
        ]


def build_candidates(items: list[dict[str, Any]], window_end: datetime) -> tuple[list[Candidate], int]:
    """把归一后的日志压成「IP -> 原因」；返回 (候选列表, 被忽略的非公网条数)。"""
    bucket: dict[str, Candidate] = {}
    ignored_non_public = 0

    for record in items:
        ip_value = _first(record, FIELD_ALIASES["ip"])
        if not ip_value:
            continue
        check = validate_ioc("IP", ip_value)
        if not check.ok:
            # 内网/环回/保留地址在三流日志里占比很高（内部扫描、健康检查），
            # 它们不允许被封禁，计入摘要即可，不占候选列表。
            ignored_non_public += 1
            continue

        ip = check.normalized or ip_value
        stream = str(record.get("_stream") or record.get("stream") or "").upper()
        severity = parse_severity(_first(record, FIELD_ALIASES["severity"]))
        action = classify_action(_first(record, FIELD_ALIASES["action"]))
        rule_name = _first(record, FIELD_ALIASES["rule"])
        seen_at = _parse_time(_first(record, FIELD_ALIASES["timestamp"]), window_end)

        candidate = bucket.get(ip)
        if candidate is None:
            candidate = Candidate(ip=ip, first_seen=seen_at, last_seen=seen_at)
            bucket[ip] = candidate
        candidate.hits += 1
        candidate.severity = max(candidate.severity, severity)
        candidate.first_seen = min(candidate.first_seen or seen_at, seen_at)
        candidate.last_seen = max(candidate.last_seen or seen_at, seen_at)
        if stream:
            candidate.streams.add(stream)
        if rule_name and len(candidate.samples) < 3 and rule_name not in candidate.samples:
            candidate.samples.append(rule_name[:80])

        # IPS 侧"未阻断"本身就是缺口；严重度缺失（0）时也计入，只是排序靠后
        if stream == "IPS" and action == "observe" and severity != 1 and severity != 2:
            candidate.add_rule("ips_observed")
        if stream == "WAF" and action == "observe":
            candidate.add_rule("waf_observed")
        if stream == "ZTNA":
            candidate.ztna_failures += 1
        if has_intel_signal(record):
            candidate.add_rule("intel_hit")

    candidates: list[Candidate] = []
    for candidate in bucket.values():
        if candidate.hits >= HIGH_FREQ_THRESHOLD:
            candidate.add_rule("high_freq")
        if len(candidate.streams) >= 2:
            candidate.add_rule("multi_stream")
        # 零信任单条不构成理由，失败次数达阈值才升级为规则
        if candidate.ztna_failures >= ZTNA_FAIL_THRESHOLD:
            candidate.rule_counts["ztna_burst"] = candidate.ztna_failures
        # 一条规则都没命中（如 IPS 已阻断、单次低危访问）就不进候选，避免噪音
        if not candidate.rule_counts:
            continue
        candidates.append(candidate)

    candidates.sort(key=lambda c: (c.severity, c.weight, c.hits), reverse=True)
    return candidates[:MAX_CANDIDATES], ignored_non_public


def apply_gates(db: Session, candidates: list[Candidate], now: datetime) -> None:
    """闸门预判：把"如果 auto 会怎样"算清楚，P0 只写报告不执行。

    顺序即优先级：白名单 > 已封 > 24h 内重复 > 可封。
    """
    repeat_since = now - timedelta(hours=max(settings.patrol_repeat_hours, 1))
    for candidate in candidates:
        in_whitelist, matched = check_whitelist(db, candidate.ip)
        if in_whitelist:
            candidate.decision = "skipped_whitelist"
            candidate.decision_reason = f"命中白名单 {matched}"
            continue
        existing = (
            db.query(IocIndicator)
            .filter(
                IocIndicator.ioc_type == "IP",
                IocIndicator.normalized_value == candidate.ip,
                IocIndicator.status == "active",
            )
            .first()
        )
        if existing is not None:
            candidate.decision = "skipped_existing"
            candidate.decision_reason = "该 IP 已在生效黑名单中"
            continue
        repeated = (
            db.query(PatrolCandidate)
            .filter(
                PatrolCandidate.ip_value == candidate.ip,
                PatrolCandidate.decision == "would_block",
                PatrolCandidate.created_at >= repeat_since,
            )
            .first()
        )
        if repeated is not None:
            candidate.decision = "skipped_repeat"
            candidate.decision_reason = f"{settings.patrol_repeat_hours}h 内已被巡检标记过"
            continue
        candidate.decision = "would_block"
        candidate.decision_reason = "通过全部闸门，dry-run 未下发"


# ---------------------------------------------------------------- 主入口
def _window(db: Session, now: datetime) -> tuple[datetime, datetime]:
    """窗口起点 = 上一轮成功巡检的终点 - 重叠秒数；首轮按间隔回看。"""
    interval = max(settings.patrol_interval_seconds, 30)
    overlap = max(settings.patrol_overlap_seconds, 0)
    last = (
        db.query(PatrolRun)
        .filter(PatrolRun.status.in_(("ok", "degraded")))
        .order_by(PatrolRun.created_at.desc(), PatrolRun.id.desc())
        .first()
    )
    if last is not None and last.window_end is not None:
        start = last.window_end - timedelta(seconds=overlap)
    else:
        start = now - timedelta(seconds=interval + overlap)
    # 兜底：断流或历史窗口异常时最多回看 6 小时，避免一次拉爆日志平台
    start = max(start, now - timedelta(hours=6))
    if start >= now:
        start = now - timedelta(seconds=interval)
    return start, now


def _fetch_stream(client: McpHttpClient, stream: dict[str, str], start: datetime,
                  end: datetime, limit: int) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    status: dict[str, Any] = {
        "name": stream["name"], "label": stream.get("label") or stream["name"],
        "stream_id": stream.get("stream_id", ""), "fetched": 0, "error": "",
        "skipped": "",
    }
    if not stream.get("stream_id") and not stream.get("query"):
        status["skipped"] = "未配置 stream_id / query"
        return [], status
    template = (settings.patrol_mcp_args or "").strip()
    if template:
        arguments = render_args(
            template,
            stream_id=stream.get("stream_id", ""),
            query=stream.get("query", ""),
            start=start, end=end, limit=limit,
        )
    else:
        # 优先按工具真实 schema 自动映射；拿不到 schema 才退回默认形状
        arguments = map_arguments(
            _tool_schema(client, settings.patrol_mcp_tool),
            stream_id=stream.get("stream_id", ""),
            query=stream.get("query", ""),
            start=start, end=end, limit=limit,
        ) or render_args(
            '{"stream_id": "${stream_id}", "query": "${query}", "from": "${from}", '
            '"to": "${to}", "limit": ${limit}}',
            stream_id=stream.get("stream_id", ""),
            query=stream.get("query", ""),
            start=start, end=end, limit=limit,
        )
    try:
        result = client.call_tool(settings.patrol_mcp_tool, arguments)
    except McpError as exc:
        status["error"] = str(exc)[:300]
        return [], status
    records = extract_records(parse_tool_result(result))
    for record in records:
        record.setdefault("_stream", stream["name"])
    status["fetched"] = len(records)
    return records, status


def _tool_schema(client: McpHttpClient, name: str) -> dict[str, Any]:
    """取工具 inputSchema；测试替身或旧客户端没有这个方法时返回空（走兜底参数）。"""
    getter = getattr(client, "tool_schema", None)
    if not callable(getter):
        return {}
    try:
        return getter(name) or {}
    except McpError as exc:
        logger.debug("读取 %s 的 schema 失败：%s", name, exc)
        return {}


# 流标题里出现这些关键词，就建议把它配成对应角色（只做提示，不自动改配置）
STREAM_HINTS: dict[str, tuple[str, ...]] = {
    "IPS": ("ips", "入侵", "intrusion", "ids", "threat"),
    "WAF": ("waf", "web", "应用防火墙", "http"),
    "ZTNA": ("ztna", "零信任", "zero", "vpn", "sase", "接入"),
}


def discover_streams(client: McpHttpClient | None = None) -> list[dict[str, Any]]:
    """调 ``list_streams`` 拿 Graylog 的流清单，用于把真实的 stream id 填进配置。"""
    cli = client or build_client()
    try:
        payload = parse_tool_result(cli.call_tool(settings.patrol_mcp_stream_tool, {}))
    except McpError as exc:
        logger.warning("读取 Graylog 流清单失败：%s", exc)
        return []
    items = extract_records(payload)
    if not items and isinstance(payload, dict):
        # Graylog 的 list_streams 常见包法：{"streams": [{id, title, ...}]}
        nested = payload.get("streams")
        if isinstance(nested, list):
            items = [x for x in nested if isinstance(x, dict)]
        elif payload.get("id") or payload.get("stream_id"):
            items = [payload]
    streams: list[dict[str, Any]] = []
    for item in items:
        stream_id = str(item.get("id") or item.get("stream_id") or "").strip()
        if not stream_id:
            continue
        title = str(item.get("title") or item.get("name") or stream_id).strip()
        lowered = title.lower()
        suggested = next(
            (role for role, words in STREAM_HINTS.items()
             if any(w in lowered for w in words)), ""
        )
        streams.append({
            "id": stream_id,
            "title": title,
            "description": str(item.get("description") or "")[:120],
            "suggested": suggested,
        })
    return streams


def mcp_status(with_streams: bool = True) -> dict[str, Any]:
    """页面「测试连接」：返回服务端信息、工具清单与流清单，失败时把原因原样带回。"""
    if not settings.patrol_mcp_url:
        return {"configured": False, "error": "未配置 PATROL_MCP_URL"}
    client = build_client()
    try:
        info = client.describe()
    except McpError as exc:
        return {"configured": True, "error": str(exc), "url": mask_url(settings.patrol_mcp_url)}
    streams = discover_streams(client) if with_streams else []
    # 用发现的流反查当前配置：提示「配的 stream_id 在 Graylog 里不存在」
    known = {s["id"] for s in streams}
    current = [
        {
            "name": s["name"], "label": s["label"],
            "stream_id": s["stream_id"], "query": s["query"],
            "exists": (s["stream_id"] in known) if (streams and s["stream_id"]) else None,
        }
        for s in load_streams()
    ]
    return {"configured": True, "error": "", **info, "streams": streams, "configured_streams": current}


def run_patrol(db: Session, *, trigger: str = "cron", created_by: str = "system",
               now: datetime | None = None, client: McpHttpClient | None = None) -> PatrolRun:
    """执行一轮只读巡检并落库；任何异常都转成 run.status，不向上抛。"""
    started = time.monotonic()
    now = now or utcnow()
    mode = (settings.patrol_mode or "dry-run").strip().lower()
    start, end = _window(db, now)

    run = PatrolRun(
        trigger=trigger, mode="dry-run", status="ok",
        window_start=start, window_end=end, created_by=created_by,
    )

    # 未配置 MCP 时不报错、不刷屏：记一条 skipped，页面能看出"还没接上"
    if not settings.patrol_mcp_url:
        run.status = "skipped"
        run.error = "未配置 PATROL_MCP_URL"
        run.summary = {
            "note": "P0 dry-run：未配置 MCP，未读取任何日志",
            "streams": [], "rules": [], "decisions": {},
        }
        run.duration_ms = int((time.monotonic() - started) * 1000)
        db.add(run)
        db.commit()
        return run

    client = client or build_client()
    records: list[dict[str, Any]] = []
    stream_status: list[dict[str, Any]] = []
    configured = 0
    for stream in load_streams():
        if stream.get("stream_id") or stream.get("query"):
            configured += 1
        items, status = _fetch_stream(client, stream, start, end, settings.patrol_max_records)
        records.extend(items)
        stream_status.append(status)

    errors = [s for s in stream_status if s.get("error")]
    candidates, ignored_non_public = build_candidates(records, end)
    apply_gates(db, candidates, now)

    decisions: dict[str, int] = {}
    rule_hits: dict[str, int] = {}
    for candidate in candidates:
        decisions[candidate.decision] = decisions.get(candidate.decision, 0) + 1
        for key in candidate.rule_counts:
            rule_hits[key] = rule_hits.get(key, 0) + 1

    run.fetched = len(records)
    run.candidate_count = len(candidates)
    run.would_block = decisions.get("would_block", 0)
    run.blocked = 0  # P0 恒定：绝不产生封禁
    if not configured:
        run.status = "skipped"
        run.error = "三流均未配置 stream_id / query"
    elif len(errors) == configured:
        run.status = "failed"
        run.error = "；".join(f"{e['name']}: {e['error']}" for e in errors)[:1000]
    elif errors:
        run.status = "degraded"
        run.error = "；".join(f"{e['name']}: {e['error']}" for e in errors)[:1000]

    run.summary = {
        "note": "P0 只读巡检：不创建 IOC、不下发封禁；decision 为“如果执行会怎样”",
        "configured_mode": mode,
        "window": {
            "start": start.isoformat() + "Z",
            "end": end.isoformat() + "Z",
            "overlap_seconds": settings.patrol_overlap_seconds,
        },
        "streams": stream_status,
        "ignored_non_public": ignored_non_public,
        "rules": [
            {"key": key, "name": RULES[key][0], "count": count}
            for key, count in sorted(rule_hits.items(), key=lambda kv: -kv[1]) if key in RULES
        ],
        "decisions": decisions,
        "top_ips": [
            {
                "ip": c.ip, "hits": c.hits, "severity": c.severity,
                "streams": sorted(c.streams), "rules": c.rules_payload(),
                "decision": c.decision, "samples": c.samples,
            }
            for c in candidates[:10]
        ],
        "mcp": {"tool": settings.patrol_mcp_tool, "url": mask_url(settings.patrol_mcp_url)},
    }

    db.add(run)
    db.flush()  # 先拿到 run.id，候选才能挂上去
    for candidate in candidates:
        db.add(PatrolCandidate(
            run_id=run.id,
            ip_value=candidate.ip,
            streams=",".join(sorted(candidate.streams)) or None,
            hits=candidate.hits,
            severity=candidate.severity,
            rules=candidate.rules_payload(),
            decision=candidate.decision,
            decision_reason=candidate.decision_reason[:255] if candidate.decision_reason else None,
            first_seen=candidate.first_seen,
            last_seen=candidate.last_seen,
        ))
    run.duration_ms = int((time.monotonic() - started) * 1000)
    db.commit()

    logger.info(
        "日志巡检完成：status=%s fetched=%s candidates=%s would_block=%s duration=%sms",
        run.status, run.fetched, run.candidate_count, run.would_block, run.duration_ms,
    )
    return run
