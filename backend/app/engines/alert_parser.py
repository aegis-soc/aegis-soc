"""告警归一化解析：Graylog Webhook 与通用告警入口。"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from app.engines.validation import DOMAIN_KEYS, EXCLUDE_KEYS, IPV4_CANDIDATE_RE, IP_KEYS

PRIORITY_MAP = {1: "low", 2: "medium", 3: "high", 4: "critical"}
SEVERITY_TO_RISK = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}
MESSAGE_KEYS = {"message", "description", "title", "event_definition_title", "summary"}

# 来源识别：Graylog 各输入/stream/设备名里带的标识 → 统一来源分类。
# 列表顺序即优先级，先命中先返回（IPS/WAF 比通用 FW 更具体）。
SOURCE_PATTERNS: list[tuple[str, tuple[str, ...]]] = [
    ("ZTNA", ("零信任", "ztna", "sdp", "atrust", "sangfor-sdp", "aTrust")),
    ("WAF", ("waf", "web应用防火墙", "web application firewall", "modsecurity", "雷池", "长亭")),
    ("IPS", ("ips", "入侵防御", "intrusion", "天清", "ngips", "snort", "suricata", "启明星辰")),
    ("TI", ("威胁情报", "threat_intelligence", "threat-intel", "threat intel", "微步", "threatbook", "virustotal", "vt-intel")),
    ("AV", ("防病毒", "antivirus", "edr", "终端检测", "病毒", "火绒", "卡巴")),
    ("NTA", ("态势感知", "态感", "nta", "全流量", "流量分析", "ndr")),
    ("FW", ("防火墙", "firewall", "fortigate", "paloalto", "pan-os", "深信服af", "sangfor af")),
    ("GRAYLOG", ("graylog",)),
]

# 优先读取这些字段判断来源（按顺序覆盖：具体设备类型字段优先于 stream/vendor）
SOURCE_FIELDS = (
    "source_type", "event_source", "log_type", "device_type", "source_category",
    "attack_source", "product", "vendor", "device_name", "syslog_appname",
    "app_name", "log_source", "stream", "collector", "source",
)
SOURCE_TYPES = {"IPS", "WAF", "ZTNA", "TI", "AV", "NTA", "FW", "GRAYLOG", "MANUAL", "API", "UNKNOWN"}

# 来源明细优先取这些字段，比 device_type: "WAF" 更有信息量
DETAIL_FIELDS = (
    "device_name", "product", "vendor", "stream", "log_source",
    "syslog_appname", "collector", "source",
)


@dataclass
class ParsedAlert:
    alert_id: str
    title: str | None
    source_system: str
    severity: str | None
    risk_level: str | None
    confidence: float | None
    src_ips: list[str] = field(default_factory=list)
    ioc_candidates: list[dict[str, Any]] = field(default_factory=list)
    source_event_id: str | None = None
    raw_payload: str = ""
    # 来源分类（IPS/WAF/ZTNA/TI/AV/NTA/FW/GRAYLOG/UNKNOWN）与原始标识
    source_type: str = "GRAYLOG"
    source_detail: str | None = None


def _match_source(text: str) -> str | None:
    """把一段文本（设备名/stream/vendor/来源字段）映射成来源分类。"""
    low = str(text or "").strip().lower()
    if not low:
        return None
    # 已经是我们自己的规范取值（如 Graylog 里直接透传 source_type: "TI"）就直接用
    if low.upper() in SOURCE_TYPES and low.upper() not in {"UNKNOWN", "GRAYLOG"}:
        return low.upper()
    for code, patterns in SOURCE_PATTERNS:
        for pattern in patterns:
            if pattern.isascii():
                # 英文标识按词边界匹配，避免 "vt" 命中 "event" 这类误判
                if re.search(rf"(?<![a-z0-9]){re.escape(pattern)}(?![a-z0-9])", low):
                    return code
            elif pattern in low:
                return code
    return None


def classify_source(
    pairs: list[tuple[str, str]],
    *,
    fallback: str = "GRAYLOG",
    extra_texts: list[str] | None = None,
) -> tuple[str, str | None]:
    """从告警字段里判定来源分类，返回 (分类, 原始标识)。

    先看明确的设备类型字段，再看 vendor/product，最后才回退到 message 文本。
    """
    ordered: list[tuple[str, str]] = []
    for field_name in SOURCE_FIELDS:
        ordered.extend([(k, v) for k, v in pairs if k == field_name])
    for text in extra_texts or []:
        ordered.append(("_extra", text))
    ordered.extend([(k, v) for k, v in pairs if k in MESSAGE_KEYS])

    for key, value in ordered:
        code = _match_source(value)
        if code:
            detail_text = ""
            for detail_field in DETAIL_FIELDS:
                for k, v in pairs:
                    if k == detail_field and v.strip():
                        detail_text = v
                        break
                if detail_text:
                    break
            detail = (" ".join((detail_text or value).split()))[:128] or None
            return code, detail
    return (fallback if fallback in SOURCE_TYPES else "UNKNOWN"), None



def _walk(node: Any, key: str = "") -> list[tuple[str, str]]:
    """递归收集 (key, 字符串值)，用于从任意告警结构中抽取 IOC。"""
    found: list[tuple[str, str]] = []
    if isinstance(node, dict):
        for k, v in node.items():
            found.extend(_walk(v, str(k)))
    elif isinstance(node, list):
        for item in node:
            found.extend(_walk(item, key))
    elif isinstance(node, str):
        found.append((key.lower(), node))
    return found


def _extract_ips(pairs: list[tuple[str, str]]) -> list[str]:
    ips: list[str] = []
    for key, value in pairs:
        value = value.strip()
        if key in EXCLUDE_KEYS:
            continue
        if key in IP_KEYS:
            for match in IPV4_CANDIDATE_RE.findall(value):
                if match not in ips:
                    ips.append(match)
        elif key in MESSAGE_KEYS:
            for match in IPV4_CANDIDATE_RE.findall(value):
                if match not in ips:
                    ips.append(match)
    return ips


def _extract_domains(pairs: list[tuple[str, str]]) -> list[str]:
    domains: list[str] = []
    for key, value in pairs:
        if key in DOMAIN_KEYS:
            candidate = value.strip().lower().rstrip(".")
            if candidate and candidate not in domains:
                domains.append(candidate)
    return domains


def _first(payload: dict[str, Any], *keys: str) -> Any:
    for key in keys:
        node: Any = payload
        parts = key.split(".")
        for part in parts:
            if not isinstance(node, dict):
                node = None
                break
            node = node.get(part)
        if node not in (None, ""):
            return node
    return None


def _stringify(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def parse_graylog(payload: dict[str, Any]) -> ParsedAlert:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    event = payload.get("event") if isinstance(payload.get("event"), dict) else {}
    fields = event.get("fields") if isinstance(event.get("fields"), dict) else {}
    merged_fields = {**fields, **payload}

    alert_id = _first(payload, "event.id", "id", "alert_id", "event_id")
    if not alert_id:
        event_def_id = _stringify(_first(payload, "event_definition_id", "event_definition_title"))
        timestamp = _stringify(_first(payload, "event.timestamp", "timestamp", "created_at"))
        alert_id = f"gl-{hashlib.sha1((event_def_id + timestamp + raw).encode()).hexdigest()[:24]}"

    priority = _first(payload, "event.priority", "priority")
    severity = _first(merged_fields, "severity", "risk_level", "event.severity")
    if not severity and priority is not None:
        try:
            severity = PRIORITY_MAP.get(int(priority), "medium")
        except (TypeError, ValueError):
            severity = str(priority).lower()
    severity = str(severity).lower() if severity else "medium"
    risk_level = _first(merged_fields, "risk_level", "event.risk_level") or SEVERITY_TO_RISK.get(severity, "medium")
    confidence = _first(merged_fields, "confidence", "threat_confidence", "event.confidence")
    try:
        confidence_value = float(confidence) if confidence is not None else 80.0
    except (TypeError, ValueError):
        confidence_value = 80.0

    title = _stringify(_first(payload, "event_definition_title", "title", "event.message")) or None
    pairs = _walk(payload)
    ips = _extract_ips(pairs)
    domains = _extract_domains(pairs)
    source_type, source_detail = classify_source(
        pairs,
        extra_texts=[_stringify(_first(payload, "event_definition_title")), _stringify(title)],
    )

    candidates: list[dict[str, Any]] = [
        {"ioc_type": "IP", "value": ip, "confidence": confidence_value} for ip in ips
    ]
    candidates.extend(
        {"ioc_type": "DOMAIN", "value": domain, "confidence": confidence_value} for domain in domains
    )

    return ParsedAlert(
        alert_id=str(alert_id),
        title=title,
        source_system="graylog",
        severity=severity,
        risk_level=str(risk_level).lower(),
        confidence=confidence_value,
        src_ips=ips,
        ioc_candidates=candidates,
        source_event_id=_stringify(_first(payload, "event.id", "id")) or None,
        raw_payload=raw,
        source_type=source_type,
        source_detail=source_detail,
    )


def parse_generic(data: Any) -> ParsedAlert:
    payload = dict(data.payload or {})
    raw = json.dumps({"payload": payload, "meta": data.model_dump(exclude={"payload"})}, ensure_ascii=False, default=str)
    alert_id = data.alert_id or "generic-" + hashlib.sha1(raw.encode()).hexdigest()[:20]
    confidence = data.confidence if data.confidence is not None else 80.0
    severity = (data.severity or "medium").lower()

    ips = list(dict.fromkeys(data.src_ips or []))
    pairs = _walk(payload)
    for ip in _extract_ips(pairs):
        if ip not in ips:
            ips.append(ip)
    domains = list(dict.fromkeys(data.domains or []))
    for domain in _extract_domains(pairs):
        if domain not in domains:
            domains.append(domain)

    candidates = [{"ioc_type": "IP", "value": ip, "confidence": confidence} for ip in ips]
    candidates.extend({"ioc_type": "DOMAIN", "value": d, "confidence": confidence} for d in domains)

    source_type, source_detail = classify_source(
        pairs,
        fallback="API",
        extra_texts=[data.source_system or "", data.title or ""],
    )

    return ParsedAlert(
        alert_id=alert_id,
        title=data.title,
        source_system=data.source_system or "generic",
        severity=severity,
        risk_level=(data.risk_level or SEVERITY_TO_RISK.get(severity, "medium")).lower(),
        confidence=float(confidence),
        src_ips=ips,
        ioc_candidates=candidates,
        source_event_id=alert_id,
        raw_payload=raw,
        source_type=source_type,
        source_detail=source_detail,
    )
