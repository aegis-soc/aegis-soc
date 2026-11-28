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
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from sqlalchemy.orm import Session

from app.config import settings
from app.database import utcnow
from app.engines.validation import check_whitelist, validate_ioc
from app.models import IocIndicator, PatrolCandidate, PatrolRun
from app.services import patrol_settings
from app.services.mcp_client import McpError, McpHttpClient, mask_url, parse_tool_result
from app.services.patrol_settings import PatrolConfig

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
        "waf_action", "ips_action", "firewall_action",
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
    "url": ("url", "r_url", "request_uri", "uri", "http_url", "cs_uri_stem"),
    "xff": ("xforwardedfor", "x_forwarded_for", "xff", "client_ip_forwarded"),
    "request_type": ("l7_app_request_type", "request_type", "access_type", "auth_type"),
    "domain": ("dst_domain", "domain", "hostname", "host"),
}

# 平台标准动作词表：巡检规则只认这六个值，厂商差异由两级机制抹平——
# ① 数据源级 value_mapping（显式配置，如绿盟 IPS 的 1/3/6/8）；
# ② 关键词启发兜底（无配置时按字面推断）。任何一边都不得写死厂商语义。
ACTION_VOCABULARY = {"observe", "audit", "block", "ban", "pass", "reject", "unknown"}

BAN_WORDS = {
    "ban", "banned", "blacklist", "blacklisted", "black_list", "封禁", "拉黑", "黑名单",
}
BLOCK_WORDS = {
    "block", "blocked", "deny", "denied", "drop", "dropped", "reset", "close", "closed",
    "阻断", "拦截", "丢弃",
}
REJECT_WORDS = {"reject", "rejected", "refuse", "refused", "拒绝"}
PASS_WORDS = {
    "allow", "allowed", "pass", "passed", "permit", "permitted", "放行", "允许",
}
AUDIT_WORDS = {"audit", "审计"}
OBSERVE_WORDS = {
    "alert", "alerted", "log", "logged", "monitor", "monitored", "detect", "detected",
    "report", "observe", "告警", "记录", "监控", "检测", "观察",
}


def normalize_action(value: str, value_map: dict[str, str] | None = None) -> str:
    """原始动作值 → 平台标准词表。

    优先查数据源级 ``value_mapping``（厂商枚举如 1/3/6/8 必须显式配置），
    未命中走 ``classify_action`` 关键词启发；映射值不在标准词表里也原样返回，
    让规则判定自然落空而不是悄悄改语义。
    """
    if value_map:
        hit = value_map.get(str(value).strip())
        if hit:
            return hit
    return classify_action(value)

# L1 规则表：key -> (中文名, 权重, 说明)
RULES: dict[str, tuple[str, int, str]] = {
    "ips_observed": ("IPS 告警未阻断", 3, "IPS 侧动作是告警/审计，攻击未被拦下"),
    "waf_observed": ("WAF 放行/仅记录", 2, "WAF 对攻击请求放行或仅记录"),
    "waf_reject": ("WAF 拒绝高频", 3, "同一 IP 窗口内被 WAF 多次 REJECT，建议拉黑"),
    "bruteforce_login": ("登录爆破", 3, "同一 IP 高频访问登录页被 WAF 拒绝"),
    "zt_multi_domain": ("零信任多域名扫描", 4, "同一 IP 窗口内访问多个不同域名，疑似扫描器"),
    "zt_dir_scan": ("零信任目录扫描", 2, "同一 IP 大量不同 URI 与路径前缀，疑似目录爆破"),
    "waf_spoofed": ("WAF 伪造源 IP", 2, "XForwardedFor 与来源 IP 不一致，疑似伪造"),
    "ztna_burst": ("零信任认证爆破", 3, "同源认证重定向（redirect_auth）次数超过阈值"),
    "high_freq": ("高频访问", 2, "窗口内同源日志条数超过阈值"),
    "multi_stream": ("跨流命中", 2, "同一 IP 同时出现在两条以上日志流"),
    "intel_hit": ("情报命中", 4, "日志字段显示威胁情报 / 网监清单命中"),
}

ZTNA_FAIL_THRESHOLD = 10   # 同一 IP 窗口内 redirect_auth 次数
HIGH_FREQ_THRESHOLD = 50   # 同一 IP 在本窗口内的日志条数
WAF_REJECT_THRESHOLD = 5   # 同一 IP 窗口内 WAF REJECT 次数
BRUTE_LOGIN_THRESHOLD = 10 # 同一 IP 窗口内登录页 REJECT 次数
ZT_DOMAIN_THRESHOLD = 4    # 同一 IP 窗口内不同目标域名数（≥4 疑似扫描）
DIR_SCAN_URI_THRESHOLD = 20     # 目录扫描：不同 URI 数
DIR_SCAN_PREFIX_THRESHOLD = 15  # 目录扫描：不同路径前缀数（前两段）
MAX_CANDIDATES = 200       # 单轮最多落库的候选 IP，防止异常日志把表撑爆

DEFAULT_STREAMS: list[dict[str, str]] = [
    {"name": "IPS", "label": "IPS 入侵防御", "stream_id": "", "query": ""},
    {"name": "WAF", "label": "WAF 应用防火墙", "stream_id": "", "query": ""},
    {"name": "ZTNA", "label": "零信任接入", "stream_id": "", "query": ""},
]


# ---------------------------------------------------------------- 配置解析
def load_config(db=None) -> PatrolConfig:
    """有效配置：库里的页面配置优先，环境变量兜底。

    ``base=settings`` 而不是让 patrol_settings 自己取默认配置，是为了让测试里
    ``monkeypatch.setattr(patrol, "settings", replace(...))`` 依然生效。
    """
    return patrol_settings.load(db, base=settings)


def load_streams(cfg: PatrolConfig | None = None, db=None) -> list[dict[str, str]]:
    """三流配置；坏配置不要让巡检整体挂掉，退回内置三流。"""
    cfg = cfg or load_config(db)
    return [dict(s) for s in cfg.streams] or [dict(s) for s in DEFAULT_STREAMS]


def build_client(cfg: PatrolConfig | None = None, db=None) -> McpHttpClient:
    cfg = cfg or load_config(db)
    return McpHttpClient(
        cfg.url,
        token=cfg.token,
        timeout=cfg.timeout,
        auth=cfg.auth,
    )


# 参数角色 → 常见字段名。工具 inputSchema 里出现哪个就用哪个，
# 这样 Graylog 升级换了参数名也不用改代码。
ARG_ALIASES: dict[str, tuple[str, ...]] = {
    "query": ("query", "search_query", "query_string", "q", "search", "filter"),
    "stream": ("stream_id", "stream_ids", "streams", "stream", "streamId"),
    "from": ("from", "start", "start_time", "from_time", "since", "timerange_start"),
    "to": ("to", "end", "end_time", "to_time", "until", "timerange_end"),
    "limit": ("limit", "size", "per_page", "page_size", "count", "max_results"),
    # 有些实现（含 Graylog 风格）用「过去多少秒」代替绝对时间戳：
    # 只声明 range/interval 时，发绝对时间戳会被忽略，窗口就悄悄变成服务端默认值。
    "range": ("range_seconds", "range", "interval", "time_range", "time_range_seconds",
              "last_seconds", "seconds", "last"),
    # 只取这些列。不传时 Graylog 只回 source/timestamp 两列，字段契约统计会全判缺失。
    "fields": ("fields", "columns", "select_fields"),
}

# 平台内部字段名 → Graylog 原生字段名。配置里按规范写 `ts`，但真正的消息字段叫
# `timestamp`；拼 `fields` 时不换名会请求一个不存在的列。
REQUEST_FIELD_ALIASES: dict[str, str] = {"ts": "timestamp", "src": "source"}


def map_arguments(schema: dict[str, Any] | None, *, stream_id: str, query: str,
                  start: datetime, end: datetime, limit: int,
                  fields: list[str] | None = None) -> dict[str, Any] | None:
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
        "range": max(1, int((end - start).total_seconds())),
        "fields": list(fields or []),
    }
    arguments: dict[str, Any] = {}
    absolute: set[str] = set()
    for role, aliases in ARG_ALIASES.items():
        name = next((a for a in aliases if a in properties), None)
        if name is None:
            continue
        value = values[role]
        if isinstance(value, str) and not value.strip():
            continue          # 空查询/空流 id 不传，避免服务端当成精确过滤条件
        if isinstance(value, list) and not value:
            continue          # 没声明必填字段时不要发空 fields，否则可能一列都不回
        declared = properties.get(name) or {}
        kind = declared.get("type") if isinstance(declared, dict) else None
        if role == "stream" and kind == "array":
            arguments[name] = [value]
        elif role in ("limit", "range") and kind == "string":
            arguments[name] = str(value)
        else:
            arguments[name] = value
        if role in ("from", "to"):
            absolute.add(name)
    # 同时给了绝对时间窗和「过去 N 秒」时，以绝对时间窗为准，避免两个窗口互相打架
    if len(absolute) == 2:
        for name in ARG_ALIASES["range"]:
            arguments.pop(name, None)
    # query 是必填项而配置为空时补 "*"（匹配全部）：
    # 少传必填参数有些实现不报错、直接回空结果，最难排查。
    if "query" in (schema.get("required") or []):
        query_name = next((a for a in ARG_ALIASES["query"] if a in properties), None)
        if query_name and not str(arguments.get(query_name) or "").strip():
            arguments[query_name] = "*"
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


def _records_from_columns(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """把「列定义 + 行数组」还原成 dict 列表。

    Graylog 的 MCP ``search_messages`` 有一种返回是列式的::

        {"schema":  [{"field": "source", ...}, {"field": "timestamp", ...}],
         "datarows": [["10.46.255.138", "2026-11-25T15:25:00.683Z"], ...],
         "metadata": {"keys": ["effective_timerange"]}}

    消息本身在 ``datarows`` 里，按 ``schema`` 的列顺序对应取值。不认这种包法的话
    会「明明回了 20 行、平台判成 0 条」——真机上就是这么踩的。
    """
    rows = None
    for key in ("datarows", "data_rows", "rows"):
        value = payload.get(key)
        if isinstance(value, list):
            rows = value
            break
    if rows is None:
        return []
    names: list[str] = []
    columns = payload.get("schema")
    if not isinstance(columns, list):
        columns = payload.get("columns")      # 有些实现把列定义叫 columns
    if isinstance(columns, list):
        for column in columns:
            if isinstance(column, str):
                names.append(column.strip().lower())
                continue
            if not isinstance(column, dict):
                continue
            # 有的实现把列名放在 name 里、写成 "field: source"
            name = str(column.get("field") or column.get("name") or "").strip().lower()
            if name.startswith("field:"):
                name = name.split(":", 1)[1].strip()
            names.append(name)
    records: list[dict[str, Any]] = []
    for row in rows:
        if isinstance(row, dict):
            records.append(_flatten(row))
        elif isinstance(row, (list, tuple)):
            item = {names[i]: value for i, value in enumerate(row)
                    if i < len(names) and names[i]}
            if item:
                records.append(item)
    return records


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
        columns = _records_from_columns(payload)
        if columns:
            return columns
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
    """关键词启发：原始动作字符串 → 标准词表（无 value_mapping 时的兜底）。"""
    text = (value or "").strip().lower()
    if not text:
        return "unknown"
    for words, canon in (
        (BAN_WORDS, "ban"), (BLOCK_WORDS, "block"), (REJECT_WORDS, "reject"),
        (PASS_WORDS, "pass"), (AUDIT_WORDS, "audit"), (OBSERVE_WORDS, "observe"),
    ):
        for word in words:
            if word in text:
                return canon
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
    ztna_attempts: int = 0   # 零信任 redirect_auth 计数，达阈值才升级成规则
    waf_rejects: int = 0     # WAF REJECT 计数
    brute_logins: int = 0    # 登录页 REJECT 计数
    zt_domains: set[str] = field(default_factory=set)   # 零信任去重域名
    zt_uris: set[str] = field(default_factory=set)      # 零信任去重 URI
    zt_prefixes: set[str] = field(default_factory=set)  # 零信任去重路径前缀
    spoofed: bool = False    # XFF 与来源 IP 不一致
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


def _url_prefix(url: str) -> str:
    """路径前缀（前两段）：/a/b/c/d?x=1 -> /a/b，用于目录扫描的「前缀数」。"""
    path = (url or "").split("?", 1)[0].split("#", 1)[0]
    segs = [seg for seg in path.split("/") if seg]
    return "/" + "/".join(segs[:2]) if segs else "/"


def build_candidates(items: list[dict[str, Any]], window_end: datetime,
                     action_maps: dict[str, dict[str, dict[str, str]]] | None = None,
                     ip_whitelist: set[str] | None = None,
                     ) -> tuple[list[Candidate], int]:
    """把归一后的日志压成「IP -> 原因」；返回 (候选列表, 被忽略的非公网条数)。

    ``action_maps``：流名 → 数据源级值映射（``{"action": {"1": "observe"}}``），
    供厂商数字枚举翻译成标准词表；``ip_whitelist``：全流共享的 IP 白名单
    （如监控探针），命中的地址不进候选。两者都是巡检设置里的可配置项。
    """
    bucket: dict[str, Candidate] = {}
    ignored_non_public = 0
    whitelist = ip_whitelist or set()

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
        if ip_value in whitelist or ip in whitelist:
            continue    # 白名单（监控探针等）：既不进候选也不计非公网数
        stream = str(record.get("_stream") or record.get("stream") or "").upper()
        severity = parse_severity(_first(record, FIELD_ALIASES["severity"]))
        vmap = (action_maps or {}).get(stream) or {}
        action = normalize_action(_first(record, FIELD_ALIASES["action"]),
                                  (vmap or {}).get("action"))
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

        # IPS 侧"未拦截"（告警/审计）本身就是缺口；严重度缺失（0）时也计入
        if stream == "IPS" and action in {"observe", "audit"} and severity not in (1, 2):
            candidate.add_rule("ips_observed")
        if stream == "WAF":
            if action in {"observe", "pass"}:
                candidate.add_rule("waf_observed")
            elif action == "reject":
                candidate.waf_rejects += 1
                url_value = str(_first(record, FIELD_ALIASES["url"]) or "")
                if "login" in url_value.lower():
                    candidate.brute_logins += 1
            xff = _first(record, FIELD_ALIASES["xff"])
            if xff and not candidate.spoofed:
                last_hop = str(xff).split(",")[-1].strip()
                if last_hop and last_hop != ip_value:
                    candidate.spoofed = True   # XFF 链最后一个 ≠ 直连地址 → 疑似伪造
        if stream == "ZTNA":
            rtype = str(_first(record, FIELD_ALIASES["request_type"]) or "").strip().lower()
            if rtype == "redirect_auth":
                # 认证重定向才是「一次认证尝试」；网关对失败也回 200，
                # status_code 区不了成败（2026-11-26 真机确认），这里不用它
                candidate.ztna_attempts += 1
            url_value = str(_first(record, FIELD_ALIASES["url"]) or "").strip()
            domain = str(_first(record, FIELD_ALIASES["domain"]) or "").strip().lower()
            if not domain and url_value:
                domain = (urllib.parse.urlparse(url_value).hostname or "").lower()
            if domain:
                candidate.zt_domains.add(domain)
            if url_value:
                candidate.zt_uris.add(url_value.split("?", 1)[0])
                candidate.zt_prefixes.add(_url_prefix(url_value))
        if has_intel_signal(record):
            candidate.add_rule("intel_hit")

    candidates: list[Candidate] = []
    for candidate in bucket.values():
        if candidate.hits >= HIGH_FREQ_THRESHOLD:
            candidate.add_rule("high_freq")
        if len(candidate.streams) >= 2:
            candidate.add_rule("multi_stream")
        # 计数型规则：达阈值才升级，计数值写进 rule_counts 供告警详情展示
        if candidate.ztna_attempts >= ZTNA_FAIL_THRESHOLD:
            candidate.rule_counts["ztna_burst"] = candidate.ztna_attempts
        if candidate.waf_rejects >= WAF_REJECT_THRESHOLD:
            candidate.rule_counts["waf_reject"] = candidate.waf_rejects
        if candidate.brute_logins >= BRUTE_LOGIN_THRESHOLD:
            candidate.rule_counts["bruteforce_login"] = candidate.brute_logins
        if len(candidate.zt_domains) >= ZT_DOMAIN_THRESHOLD:
            candidate.rule_counts["zt_multi_domain"] = len(candidate.zt_domains)
        if (len(candidate.zt_uris) >= DIR_SCAN_URI_THRESHOLD
                and len(candidate.zt_prefixes) >= DIR_SCAN_PREFIX_THRESHOLD):
            candidate.rule_counts["zt_dir_scan"] = len(candidate.zt_uris)
        if candidate.spoofed:
            candidate.add_rule("waf_spoofed")
        # 一条规则都没命中（如 IPS 已阻断、单次低危访问）就不进候选，避免噪音
        if not candidate.rule_counts:
            continue
        candidates.append(candidate)

    candidates.sort(key=lambda c: (c.severity, c.weight, c.hits), reverse=True)
    return candidates[:MAX_CANDIDATES], ignored_non_public


def apply_gates(db: Session, candidates: list[Candidate], now: datetime,
                cfg: PatrolConfig | None = None) -> None:
    """闸门预判：把"如果 auto 会怎样"算清楚，P0 只写报告不执行。

    顺序即优先级：白名单 > 已封 > 重复标记 > 可封。
    """
    cfg = cfg or load_config(db)
    repeat_since = now - timedelta(hours=max(cfg.repeat_hours, 1))
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
            candidate.decision_reason = f"{cfg.repeat_hours}h 内已被巡检标记过"
            continue
        candidate.decision = "would_block"
        candidate.decision_reason = "通过全部闸门，dry-run 未下发"


# ---------------------------------------------------------------- 主入口
def _window(db: Session, now: datetime, cfg: PatrolConfig) -> tuple[datetime, datetime]:
    """窗口起点 = 上一轮成功巡检的终点 - 重叠秒数；首轮按间隔回看。"""
    interval = max(cfg.interval, 30)
    overlap = max(cfg.overlap, 0)
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


def build_search_arguments(client: McpHttpClient, stream: dict[str, Any], start: datetime,
                           end: datetime, limit: int, cfg: PatrolConfig | None = None,
                           schema: dict[str, Any] | None = None,
                           with_fields: bool = True) -> dict[str, Any] | None:
    """拼「取一批日志」的调用参数。

    两个来源：``cfg.args`` 显式模板优先（现场适配用），否则按工具 inputSchema
    自动映射，都映射不到才退回最常见的字段形状。抽成独立函数是为了让巡检和
    「试取」诊断共用同一条拼参逻辑——诊断里看到的参数，必须就是巡检真正发出去的。

    ``with_fields=False`` 用于重试：带了 ``fields`` 被服务端拒时，退回不指定列。
    """
    cfg = cfg or load_config()
    stream_id = str(stream.get("stream_id") or "")
    query = str(stream.get("query") or "")
    template = (cfg.args or "").strip()
    if template:
        return render_args(template, stream_id=stream_id, query=query,
                           start=start, end=end, limit=limit)
    wanted = _request_fields(stream) if with_fields else []
    return map_arguments(
        schema if schema is not None else _tool_schema(client, cfg.tool),
        stream_id=stream_id, query=query, start=start, end=end, limit=limit,
        fields=wanted,
    ) or render_args(
        '{"stream_id": "${stream_id}", "query": "${query}", "from": "${from}", '
        '"to": "${to}", "limit": ${limit}}',
        stream_id=stream_id, query=query, start=start, end=end, limit=limit,
    )


def _request_fields(stream: dict[str, Any]) -> list[str]:
    """把配置翻成要向 Graylog 请求的列名。

    顺序：``field_mapping`` 显式映射 > 内置别名（``ts``→``timestamp``）> 同名直传。
    最后强制补上时间列和来源列——真机不指定列时只回 ``source``/``timestamp``，
    而指定列后服务端就只回请求的列；漏了时间列，巡检窗口、24h 时间线、
    「最近活跃」全部失效，且不报任何错。若配置把 ``ts`` 映射到了别的列（如
    ``occurred_at``），以映射为准、不再追加 ``timestamp``。
    """
    mapping = stream.get("field_mapping") or {}
    out: list[str] = []
    has_time_col = False
    for name in stream.get("required_fields") or []:
        text = str(name).strip()
        if not text:
            continue
        if text == "ts":                      # 平台的时间字段，无论映射到哪个列都算「有时间列」
            has_time_col = True
        graylog = mapping.get(text) or REQUEST_FIELD_ALIASES.get(text, text)
        if graylog and graylog not in out:
            out.append(graylog)
    # 时间列兜底：配置里没有任何时间字段时补 timestamp——真机指定列后只回请求的列，
    # 漏时间列时巡检窗口、24h 时间线、「最近活跃」全部静默失效。
    if not has_time_col:
        out.append("timestamp")
    if "source" not in out and "src" not in out:
        out.append("source")
    return out[:32]


def _apply_field_mapping(records: list[dict[str, Any]],
                         stream: dict[str, Any]) -> list[dict[str, Any]]:
    """把按 ``field_mapping`` 取回的 Graylog 字段名反写回平台契约字段名。

    只在平台字段**不存在**时改写（不覆盖服务端本就给出的同名标准字段）；
    Graylog 侧缺列则不动，让缺失统计如实反映。值为 ``-`` 或空串时视为
    「设备用占位符表示缺失」（部分网关的习惯），不写入平台字段——否则会
    凭空多出叫 ``-`` 的用户和设备，匿名判断也失效；pipeline 清洗规则是
    根治手段，这里是未部署规则时的兜底。

    ``ua_class`` 特殊：真机网关（2026-11-26 实测）给的是 ``ua_is_pc`` 布尔
    而非词表单值，映射 ``ua_class → ua_is_pc`` 取回时按 true/false 换算成
    词表 ``pc`` / ``other``——不猜 mobile（布尔只声明「是不是 PC」）。
    """
    mapping = stream.get("field_mapping") or {}
    if not mapping:
        return records
    for record in records:
        for platform_key, graylog_name in mapping.items():
            if platform_key == graylog_name or platform_key in record:
                continue
            if graylog_name not in record:
                continue
            if str(record[graylog_name]).strip() in {"", "-"}:
                continue
            value = record.pop(graylog_name)
            if platform_key == "ua_class":
                text = str(value).strip().lower()
                if text in {"true", "1", "yes"}:
                    value = "pc"
                elif text in {"false", "0", "no"}:
                    # false 只声明「不是 PC」：可能是手机/平板/终端未识别，
                    # 写 other 会把设备类型全部压平；留空交给 UA 文本派生
                    # （ua_class_of 会从 ua_raw 识别 mobile/feishu）。
                    continue
            record[platform_key] = value
    return records


# 「试取」默认回看 30 分钟：比巡检窗口宽，用来区分「本轮恰好没消息」与「根本取不到」
PROBE_WINDOW_MINUTES = 30
PROBE_SAMPLE_FIELDS = ("timestamp", "ts", "source", "src_ip", "dst_ip", "username",
                       "action", "severity", "url", "status_code", "stream")


def _raw_preview(payload: Any, limit: int = 1500) -> str:
    """返回体摘要：顶层键、列表长度、首两条元素。

    直接 dump 整个包会被字段表吃掉——Graylog 的 search 返回首项是 ``schema`` 数组，
    每个字段一条，1200 字符全花在上面，真正想看的 ``messages`` / ``total`` 被截掉。
    """
    if isinstance(payload, dict):
        brief: dict[str, Any] = {}
        for key, value in payload.items():
            if isinstance(value, list):
                brief[key] = {"count": len(value), "first": value[:2]}
            elif isinstance(value, dict):
                brief[key] = {"keys": list(value)[:12]}
            else:
                brief[key] = value
        try:
            return json.dumps(brief, ensure_ascii=False)[:limit]
        except (TypeError, ValueError):
            return str(brief)[:limit]
    if isinstance(payload, str):
        return payload[:limit]
    try:
        return json.dumps(payload, ensure_ascii=False)[:limit]
    except (TypeError, ValueError):
        return str(payload)[:limit]


def probe_stream(stream: dict[str, Any], *, cfg: PatrolConfig | None = None, db=None,
                 minutes: int = PROBE_WINDOW_MINUTES, limit: int = 20) -> dict[str, Any]:
    """对单个源跑一次真实取数，把「发了什么参数、服务端回了什么」原样带出来。

    数据源页显示「无数据」时最需要回答两件事：参数是不是按工具真实 schema 拼的、
    服务端到底回了什么。所以这里同时跑一次**不带流过滤**的对照组：对照组有数、
    带过滤没有，说明是过滤参数名或 stream id 的问题，而不是这条流断流。
    """
    cfg = cfg or load_config(db)
    end = utcnow()
    start = end - timedelta(minutes=max(1, minutes))
    out: dict[str, Any] = {
        "tool": cfg.tool,
        "stream": {"name": stream.get("name") or "", "stream_id": stream.get("stream_id") or "",
                   "query": stream.get("query") or "",
                   "field_mapping": dict(stream.get("field_mapping") or {})},
        "window": {"minutes": minutes,
                   "from": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                   "to": end.strftime("%Y-%m-%dT%H:%M:%SZ")},
        "schema": {}, "arguments": {}, "fetched": 0, "sample": [],
        "raw": "", "error": "", "control": {"arguments": {}, "fetched": 0, "error": ""},
    }
    try:
        client = build_client(cfg)
    except Exception as exc:  # 配置缺 URL/Token 时 build_client 可能抛
        out["error"] = f"构建 MCP 客户端失败：{exc}"[:300]
        return out

    schema = _tool_schema(client, cfg.tool)
    props = schema.get("properties") if isinstance(schema, dict) else None
    if isinstance(props, dict):
        out["schema"] = {
            "properties": {str(k): str((v or {}).get("type") or "") for k, v in props.items()},
            "required": [str(x) for x in (schema.get("required") or [])],
        }

    def _run(stream_id: str) -> tuple[list[dict[str, Any]], str, dict[str, Any], str]:
        probe = dict(stream)
        probe["stream_id"] = stream_id
        args = build_search_arguments(client, probe, start, end, limit, cfg=cfg, schema=schema)
        try:
            payload = parse_tool_result(client.call_tool(cfg.tool, args or {}))
        except McpError as exc:
            if not (args or {}).get("fields"):
                return [], "", args or {}, str(exc)[:300]
            args = build_search_arguments(client, probe, start, end, limit,
                                          cfg=cfg, schema=schema, with_fields=False)
            try:
                payload = parse_tool_result(client.call_tool(cfg.tool, args or {}))
            except McpError as retry_exc:
                return [], "", args or {}, str(retry_exc)[:300]
        return _apply_field_mapping(extract_records(payload), stream), _raw_preview(payload), args or {}, ""

    records, raw, args, error = _run(str(stream.get("stream_id") or ""))
    out.update({"fetched": len(records), "raw": raw, "error": error, "arguments": args})
    out["sample"] = [
        {k: rec.get(k) for k in PROBE_SAMPLE_FIELDS if rec.get(k) not in (None, "")}
        for rec in records[:3]
    ]
    if not error:
        c_records, c_raw, c_args, c_error = _run("")
        out["control"] = {"arguments": c_args, "fetched": len(c_records),
                          "error": c_error, "raw": c_raw}
    return out


def _fetch_stream(client: McpHttpClient, stream: dict[str, Any], start: datetime,
                  end: datetime, limit: int,
                  cfg: PatrolConfig | None = None) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    status: dict[str, Any] = {
        "name": stream["name"], "label": stream.get("label") or stream["name"],
        "stream_id": stream.get("stream_id", ""), "fetched": 0, "error": "",
        "skipped": "", "source_code": stream.get("source_code") or "",
        "schema_version": stream.get("schema_version") or "",
    }
    if stream.get("enabled") is False:
        status["skipped"] = "数据源已禁用"
        return [], status
    if not stream.get("stream_id") and not stream.get("query"):
        status["skipped"] = "未配置 stream_id / query"
        return [], status
    cfg = cfg or load_config()
    schema = _tool_schema(client, cfg.tool)
    arguments = build_search_arguments(client, stream, start, end, limit, cfg=cfg, schema=schema)
    try:
        result = client.call_tool(cfg.tool, arguments)
    except McpError as exc:
        # 指定列被服务端拒（列名不在该流里、实现不认 fields 等）时退回不指定列：
        # 少几列好过整批取不到，字段缺失率会在健康度里如实反映。
        if not (arguments or {}).get("fields"):
            status["error"] = str(exc)[:300]
            return [], status
        logger.info("源 %s 指定 fields 被拒，改为不指定列重试：%s", stream["name"], exc)
        arguments = build_search_arguments(client, stream, start, end, limit,
                                           cfg=cfg, schema=schema, with_fields=False)
        try:
            result = client.call_tool(cfg.tool, arguments)
        except McpError as retry_exc:
            status["error"] = str(retry_exc)[:300]
            return [], status
    records = extract_records(parse_tool_result(result))
    _apply_field_mapping(records, stream)
    for record in records:
        record.setdefault("_stream", stream["name"])
    status["fetched"] = len(records)
    # 字段契约健康度：巡检顺手统计，前端「数据源」页直接读，不必再单独扫一遍日志
    required = stream.get("required_fields") or []
    missing: dict[str, int] = {}
    schema_ok = 0
    ts_fallback = 0
    for record in records:
        for field in required:
            value = record.get(field)
            if value is None or value == "":
                missing[field] = missing.get(field, 0) + 1
        if str(record.get("_schema_ok", "")).lower() == "true":
            schema_ok += 1
        if str(record.get("_ts_from_ingest", "")).lower() == "true":
            ts_fallback += 1
    status["required_fields"] = list(required)
    status["missing"] = missing
    status["missing_total"] = sum(missing.values())
    status["schema_ok"] = schema_ok
    status["schema_bad"] = max(0, len(records) - schema_ok) if records else 0
    status["ts_fallback"] = ts_fallback
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


# GRN = Graylog Resource Name，流资源的形如 `grn:graylog:stream:<stream_id>`
_GRN_PREFIX = "grn:graylog:stream:"
_GRN_LIMIT = 50              # describe_resource 逐条补全的上限，防止流过多拖垮测试连接


def _stream_id_from_grn(grn: str) -> str:
    """从 `grn:graylog:stream:<id>` 里取 stream id；非流 GRN 返回空串。"""
    grn = str(grn or "").strip()
    return grn.rsplit(":", 1)[-1] if grn.startswith(_GRN_PREFIX) else ""


def _collect_stream_grns(payload: Any, _depth: int = 0) -> list[str]:
    """在任意嵌套结构里收集 ``grn:graylog:stream:...`` 字符串。

    ``list_resource(type=stream)`` 与部分 ``list_streams`` 包法返回的是 GRN
    列表而不是流对象，此时 id 只能从 GRN 里解析。
    """
    if payload is None or _depth > 4:
        return []
    if isinstance(payload, str):
        if payload.strip().startswith(_GRN_PREFIX):
            return [payload.strip()]
        try:
            return _collect_stream_grns(json.loads(payload), _depth + 1)
        except json.JSONDecodeError:
            return []
    if isinstance(payload, list):
        out: list[str] = []
        for item in payload:
            out.extend(_collect_stream_grns(item, _depth + 1))
        return out
    if isinstance(payload, dict):
        out = []
        for value in payload.values():
            out.extend(_collect_stream_grns(value, _depth + 1))
        return out
    return []


def _find_stream_list(payload: Any, _depth: int = 0) -> list[dict[str, Any]]:
    """在任意嵌套结构里找出「流清单」。

    ``extract_records`` 是按消息语义写的（认 messages/data/records…），不认
    ``streams`` 这个键，所以 ``{"data": {"streams": [...]}}`` 这类包法会漏。
    这里改成结构无关的找法：递归找「元素带 id/stream_id/grn 的 dict 列表」，
    以及「GRN 字符串列表」（真实 Graylog 的一种返回形态），怎么包都能捞出来。
    """
    if payload is None or _depth > 4:
        return []
    if isinstance(payload, str):
        try:
            return _find_stream_list(json.loads(payload), _depth + 1)
        except json.JSONDecodeError:
            return []
    if isinstance(payload, list):
        hits = [x for x in payload
                if isinstance(x, dict) and (x.get("id") or x.get("stream_id") or x.get("grn"))]
        grn_items = [{"grn": s} for s in payload
                     if isinstance(s, str) and _stream_id_from_grn(s)]
        if hits or grn_items:
            return hits + grn_items
        for item in payload:
            found = _find_stream_list(item, _depth + 1)
            if found:
                return found
        return []
    if isinstance(payload, dict):
        # 先看已知包法，再看自身是不是单个流对象
        for key in ("streams", "data", "result", "items", "records", "resources"):
            if key in payload:
                found = _find_stream_list(payload[key], _depth + 1)
                if found:
                    return found
        if payload.get("id") or payload.get("stream_id") or payload.get("grn"):
            return [payload]
    return []


def _describe_grns(client: McpHttpClient, grns: list[str]) -> list[dict[str, Any]]:
    """逐个 ``describe_resource(grn)`` 补全流定义；单条失败只影响该条。"""
    items: list[dict[str, Any]] = []
    for grn in grns[:_GRN_LIMIT]:
        entry: dict[str, Any] = {"grn": grn}
        try:
            desc = parse_tool_result(client.call_tool("describe_resource", {"grn": grn}))
            if isinstance(desc, dict):
                if desc.get("id"):
                    entry["id"] = str(desc["id"])
                entry["title"] = str(desc.get("title") or "")
                entry["description"] = str(desc.get("description") or "")
        except McpError as exc:
            logger.debug("describe_resource(%s) 失败：%s", grn, exc)
        items.append(entry)
    return items


def _discover_via_grn(client: McpHttpClient) -> list[dict[str, Any]]:
    """``list_streams`` 拿不到时的兜底：MCP 标准资源接口。

    ``list_resource(type=stream)`` 返回 GRN 列表（``grn:graylog:stream:<id>``），
    再逐个 ``describe_resource(grn)`` 补 title / description 等完整定义。
    上限 :data:`_GRN_LIMIT` 条；工具不存在（老版本服务端）或单条失败都只记日志。
    """
    try:
        payload = parse_tool_result(client.call_tool("list_resource", {"type": "stream"}))
    except McpError as exc:
        logger.warning("list_resource 拿流清单失败：%s", exc)
        return []
    grns = _collect_stream_grns(payload)
    if not grns:
        return []
    logger.info("list_streams 为空，经 list_resource 拿到 %d 条流 GRN", len(grns))
    return _describe_grns(client, grns)


def _snippet(payload: Any, limit: int = 600) -> str:
    """把返回压成一段单行片段，供页面排错（超长截断）。"""
    if payload is None:
        return ""
    if isinstance(payload, str):
        text = payload
    else:
        try:
            text = json.dumps(payload, ensure_ascii=False)
        except (TypeError, ValueError):
            text = str(payload)
    return " ".join(text.split())[:limit]


def _rest_streams_url(url: str) -> str:
    """从 MCP 地址派生 Graylog REST 流清单地址。

    ``https://graylog:9000/api/mcp`` → ``https://graylog:9000/api/streams``；
    未带 ``/api/mcp`` 后缀时直接在末尾拼 ``/api/streams``。
    """
    base = str(url or "").strip().rstrip("/")
    for suffix in ("/api/mcp", "/mcp"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    return base.rstrip("/") + "/api/streams"


def _discover_via_rest(cfg: PatrolConfig) -> tuple[list[dict[str, Any]], str]:
    """最后一级兜底：直接打 Graylog REST ``GET /api/streams``。

    MCP 的 ``list_streams`` / ``list_resource`` 都可能因版本、MCP 开关或权限拿不到
    清单，但 REST API 一直存在，且鉴权与 MCP 完全同一套（Basic ``<token>:token``）。
    返回 ``(流列表, 失败说明)``，成功时说明为空串。
    """
    url = _rest_streams_url(cfg.url)
    headers = {"Accept": "application/json"}
    headers.update(McpHttpClient(cfg.url, token=cfg.token,
                                 timeout=cfg.timeout, auth=cfg.auth).auth_headers())
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=cfg.timeout) as response:
            data = json.loads(response.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = exc.read().decode("utf-8", errors="replace")[:200]
        except Exception:      # 读错误体失败不影响主流程
            pass
        hint = "（需要 Streams:read 权限）" if exc.code in (401, 403) else ""
        return [], f"HTTP {exc.code} {url}{hint} {detail}".strip()
    except Exception as exc:   # 连接失败 / 证书 / 超时
        return [], f"{type(exc).__name__}: {exc} ({url})"
    items = data.get("streams") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return [], f"返回结构不认识：{_snippet(data, 200)}"
    return [x for x in items if isinstance(x, dict)], ""


def _build_streams(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """把各种形态的流条目统一成 ``{id,title,description,suggested}``。"""
    streams: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        stream_id = str(item.get("id") or item.get("stream_id") or "").strip()
        if not stream_id:
            stream_id = _stream_id_from_grn(item.get("grn"))
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


def discover_streams_detailed(client: McpHttpClient | None = None,
                              cfg: PatrolConfig | None = None,
                              db=None) -> dict[str, Any]:
    """拿流清单，并把每一级尝试的结果一并返回，供页面排错。

    四级尝试（前面有结果就不再往下走）：

    1. MCP ``list_streams``（工具名可配）——流对象 / GRN 列表都认；
    2. 拿到的是 GRN-only 清单 → 逐条 ``describe_resource`` 补 title；
    3. 仍为空 → MCP ``list_resource(type=stream)`` → 再 describe；
    4. 仍为空 → Graylog REST ``GET /api/streams``（**不依赖 MCP**）。

    返回 ``{"streams": [...], "attempts": [{step, ok, count, detail, raw}]}``。
    任何一级失败都只记日志 + 写进 attempts，不影响巡检主链路。
    """
    cfg = cfg or load_config(db)
    cli = client or build_client(cfg)
    attempts: list[dict[str, Any]] = []
    items: list[dict[str, Any]] = []

    # ① MCP list_streams
    try:
        payload = parse_tool_result(cli.call_tool(cfg.stream_tool, {}))
        found = _find_stream_list(payload) or extract_records(payload)
        attempts.append({"step": f"MCP {cfg.stream_tool}", "ok": bool(found),
                         "count": len(found), "detail": "", "raw": _snippet(payload)})
        items = found
    except McpError as exc:
        logger.warning("读取 Graylog 流清单失败（%s）：%s", cfg.stream_tool, exc)
        attempts.append({"step": f"MCP {cfg.stream_tool}", "ok": False,
                         "count": 0, "detail": str(exc), "raw": ""})

    # ② GRN-only 清单 → describe 补全
    if items and all(
        not (it.get("id") or it.get("stream_id") or it.get("title") or it.get("name"))
        for it in items if isinstance(it, dict)
    ):
        grns = [it["grn"] for it in items if isinstance(it, dict) and it.get("grn")]
        enriched = _describe_grns(cli, grns) if grns else []
        attempts.append({"step": f"MCP describe_resource × {len(grns)}", "ok": bool(enriched),
                         "count": len(enriched), "detail": "",
                         "raw": _snippet([{k: v for k, v in e.items() if k != "grn"} for e in enriched[:3]])})
        if enriched:
            items = enriched

    # ③ MCP 资源接口兜底
    if not items:
        try:
            payload = parse_tool_result(cli.call_tool("list_resource", {"type": "stream"}))
            grns = _collect_stream_grns(payload)
            enriched = _describe_grns(cli, grns) if grns else []
            attempts.append({"step": "MCP list_resource(type=stream)", "ok": bool(grns),
                             "count": len(grns), "detail": "", "raw": _snippet(payload)})
            if enriched:
                items = enriched
        except McpError as exc:
            attempts.append({"step": "MCP list_resource(type=stream)", "ok": False,
                             "count": 0, "detail": str(exc), "raw": ""})

    # ④ REST 兜底（不依赖 MCP）
    if not items:
        rest_items, err = _discover_via_rest(cfg)
        attempts.append({"step": "REST GET /api/streams", "ok": bool(rest_items),
                         "count": len(rest_items), "detail": err,
                         "raw": _snippet(rest_items[:3]) if rest_items else ""})
        items = rest_items

    return {"streams": _build_streams(items), "attempts": attempts}


def discover_streams(client: McpHttpClient | None = None,
                     cfg: PatrolConfig | None = None, db=None) -> list[dict[str, Any]]:
    """拿 Graylog 的流清单（只返回流列表，排错信息见 :func:`discover_streams_detailed`）。"""
    return discover_streams_detailed(client, cfg=cfg, db=db)["streams"]


def _status_payload(cfg: PatrolConfig, client: McpHttpClient,
                    with_streams: bool, db=None) -> dict[str, Any]:
    """用给定配置做一次连通性自检（页面「测试连接」与「保存前试连」共用）。"""
    try:
        info = client.describe()
    except McpError as exc:
        return {"configured": True, "error": str(exc), "url": mask_url(cfg.url),
                "transport": client.transport, "auth": cfg.auth}
    streams: list[dict[str, Any]] = []
    attempts: list[dict[str, Any]] = []
    if with_streams:
        detail = discover_streams_detailed(client, cfg=cfg, db=db)
        streams = detail["streams"]
        attempts = detail["attempts"]
    # 用发现的流反查配置：提示「配的 stream_id 在 Graylog 里不存在」
    known = {s["id"] for s in streams}
    current = [
        {
            "name": s["name"], "label": s["label"],
            "stream_id": s["stream_id"], "query": s["query"],
            "exists": (s["stream_id"] in known) if (streams and s["stream_id"]) else None,
        }
        for s in cfg.streams
    ]
    return {"configured": True, "error": "", **info, "streams": streams,
            "streams_attempts": attempts, "configured_streams": current, "source": cfg.source}


def mcp_status(db=None, with_streams: bool = True,
               cfg: PatrolConfig | None = None) -> dict[str, Any]:
    """页面「测试连接」：读已保存配置做自检，失败时把原因原样带回。"""
    cfg = cfg or load_config(db)
    if not cfg.configured:
        return {"configured": False, "error": "尚未配置 Graylog MCP 地址",
                "source": cfg.source}
    return _status_payload(cfg, build_client(cfg), with_streams, db)


def mcp_probe(draft: dict[str, Any], db=None) -> dict[str, Any]:
    """保存前试连：用「已保存配置 + 表单草稿」拼一个临时配置，不落库。

    这样用户可以先确认地址/token 对不对，再决定要不要保存，避免"存错了还得回滚"。
    """
    cfg = load_config(db)
    if draft.get("mcp_url"):
        cfg.url = str(draft["mcp_url"]).strip()
    if draft.get("mcp_token"):
        cfg.token = str(draft["mcp_token"]).strip()
    if draft.get("mcp_auth"):
        cfg.auth = str(draft["mcp_auth"]).strip().lower()
    if draft.get("mcp_tool"):
        cfg.tool = str(draft["mcp_tool"]).strip()
    if draft.get("mcp_stream_tool"):
        cfg.stream_tool = str(draft["mcp_stream_tool"]).strip()
    if draft.get("streams"):
        cfg.streams = patrol_settings.normalize_streams(draft["streams"])
    if not cfg.url:
        return {"configured": False, "error": "请先填写 MCP 地址"}
    return _status_payload(cfg, build_client(cfg), True, db)


def run_patrol(db: Session, *, trigger: str = "cron", created_by: str = "system",
               now: datetime | None = None, client: McpHttpClient | None = None,
               cfg: PatrolConfig | None = None) -> PatrolRun:
    """执行一轮只读巡检并落库；任何异常都转成 run.status，不向上抛。"""
    started = time.monotonic()
    now = now or utcnow()
    cfg = cfg or load_config(db)
    mode = cfg.mode
    start, end = _window(db, now, cfg)

    run = PatrolRun(
        trigger=trigger, mode=mode, status="ok",
        window_start=start, window_end=end, created_by=created_by,
    )

    # 未配置 MCP 时不报错、不刷屏：记一条 skipped，页面能看出"还没接上"
    if not cfg.configured:
        run.status = "skipped"
        run.error = "尚未配置 Graylog MCP 地址（日志巡检 → MCP 配置）"
        run.summary = {
            "note": "P0 dry-run：未配置 MCP，未读取任何日志",
            "streams": [], "rules": [], "decisions": {},
        }
        run.duration_ms = int((time.monotonic() - started) * 1000)
        db.add(run)
        db.commit()
        return run

    client = client or build_client(cfg)
    records: list[dict[str, Any]] = []
    stream_status: list[dict[str, Any]] = []
    configured = 0
    for stream in cfg.streams:
        if stream.get("enabled") is False:
            items, status = _fetch_stream(client, stream, start, end, cfg.max_records, cfg)
            stream_status.append(status)
            continue
        if stream.get("stream_id") or stream.get("query"):
            configured += 1
        items, status = _fetch_stream(client, stream, start, end, cfg.max_records, cfg)
        records.extend(items)
        stream_status.append(status)

    errors = [s for s in stream_status if s.get("error")]
    # 值映射与白名单按流配置下发：厂商数字枚举在这里翻译成标准词表，
    # 监控探针等可信地址在这里排除。
    action_maps = {s["name"]: (s.get("value_mapping") or {})
                   for s in cfg.streams if s.get("value_mapping")}
    ip_whitelist = {ip.strip() for s in cfg.streams
                    for ip in (s.get("ip_whitelist") or []) if ip.strip()}
    candidates, ignored_non_public = build_candidates(
        records, end, action_maps=action_maps, ip_whitelist=ip_whitelist)
    apply_gates(db, candidates, now, cfg)

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
        run.error = "所有日志源均未配置 stream_id / query"
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
            "overlap_seconds": cfg.overlap,
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
        "mcp": {
            "tool": cfg.tool, "url": mask_url(cfg.url),
            "auth": cfg.auth, "config_source": cfg.source, "enabled": cfg.enabled,
        },
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
