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
    )
