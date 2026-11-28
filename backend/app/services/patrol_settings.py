"""日志巡检的运行时配置：数据库优先，环境变量兜底。

为什么需要这一层：MCP 地址、API Token、三流 stream_id 都属于日常运维会变的东西，
只放在 ``.env`` 里意味着每改一次就得重启后端；放到库里以后页面即可维护，
定时任务每轮读一次（一次主键查询，成本可忽略），配置改了下一轮就生效。

约定：
- 表里只有一行（``id=1``），没有行时全部取环境变量，``source`` 标 ``env``；
- **token 只出掩码**：``public()`` 返回 ``token_set`` 与尾号，绝不回明文；
- 保存时 token 留空 = 保持原值，显式 ``clear_token`` 才清空，避免"改个 URL 把 token 冲掉"。
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.orm import Session

from app.common import BizError
from app.config import settings as default_settings
from app.database import SessionLocal, utcnow
from app.models import PatrolSetting
from app.services.mcp_client import mask_token

logger = logging.getLogger("aegis")

AUTH_CHOICES = {"token", "bearer", "basic", "none", "raw"}
MODES = {"dry-run", "assist", "auto"}
TOKEN_MASK = "********"

# 零信任流「真机实测」字段映射（2026-11-26 真机 Fields 面板）：
#   request_method / request_uri / request_user_agent / response_status /
#   source_ip + src_ip(双份同值) / timestamp / ua_is_pc(布尔)，
#   employee_id(UUID) / employee_name(工号) 仅部分消息携带。
# 配了这条映射后契约字段全部落位；norm 流（pipeline 已归一）不受影响——
# 归一流里契约字段本就同名直传，映射不触发。
# WAF 真机字段映射（2026-11-27 用户口径：waf_action 承载动作枚举，r_url 为请求路径）
WAF_DEFAULT_MAPPING: dict[str, str] = {
    "url": "r_url",
    "action": "waf_action",
}

ZTNA_DEFAULT_MAPPING: dict[str, str] = {
    "url": "request_uri",
    "status_code": "response_status",
    "ua_raw": "request_user_agent",
    "ua_class": "ua_is_pc",
    "username": "employee_id",
    "display_name": "employee_name",
}

DEFAULT_STREAMS: list[dict[str, Any]] = [
    {"name": "IPS", "label": "IPS 入侵防御", "stream_id": "", "query": "",
     "source_code": "ips", "purpose": ["patrol"], "schema_version": "1.0",
     "required_fields": ["ts", "src_ip", "action", "severity"], "enabled": True},
    {"name": "WAF", "label": "WAF 应用防火墙", "stream_id": "", "query": "",
     "source_code": "waf", "purpose": ["patrol"], "schema_version": "1.0",
     "required_fields": ["ts", "src_ip", "action", "severity", "url",
                         "waf_action", "r_url", "xforwardedfor"],
     "field_mapping": dict(WAF_DEFAULT_MAPPING), "enabled": True},
    {"name": "ZTNA", "label": "零信任接入", "stream_id": "", "query": "",
     "source_code": "ztna", "purpose": ["lba", "patrol"], "schema_version": "1.0",
     "required_fields": ["ts", "src_ip", "url", "status_code", "ua_raw", "ua_class",
                         "username", "display_name", "l7_app_request_type", "dst_domain"],
     "field_mapping": dict(ZTNA_DEFAULT_MAPPING),
     "enabled": True},
    {"name": "NTA", "label": "态势感知 / 全流量", "stream_id": "", "query": "",
     "source_code": "nta", "purpose": ["patrol"], "schema_version": "1.0",
     "required_fields": ["ts", "src_ip"], "enabled": True},
]

# name / 中文名 → source_code：旧配置只有 name，靠这张表推导（规范化后写回）
SOURCE_CODE_BY_NAME = {
    "IPS": "ips", "WAF": "waf", "ZTNA": "ztna", "NTA": "nta",
    "零信任": "ztna", "态感": "nta", "态势感知": "nta",
}
SOURCE_CODES = {"ips", "waf", "ztna", "nta"}
# 未声明 required_fields 时按源给默认值，避免页面出现空契约
DEFAULT_REQUIRED = {
    "ips": ["ts", "src_ip", "action", "severity"],
    "waf": ["ts", "src_ip", "action", "severity", "url",
            "waf_action", "r_url", "xforwardedfor"],
    "ztna": ["ts", "src_ip", "url", "status_code", "ua_raw", "ua_class",
             "username", "display_name", "l7_app_request_type", "dst_domain"],
    "nta": ["ts", "src_ip"],
}
DEFAULT_PURPOSE = {"ztna": ["lba", "patrol"]}

# ---------------------------------------------------------------- 字段契约校验
# 平台契约字段的用途说明（数据源页展示，让「为什么必填」有据可查）
ROLE_LABELS: dict[str, str] = {
    "ts": "日志时间——巡检窗口、LBA 时间范围全依赖它",
    "src_ip": "来源IP——候选判定与用户/IP 聚合的主键",
    "action": "动作——规则判定（封禁/告警）的依据",
    "severity": "级别——候选排序与权重",
    "url": "请求路径——URL 类规则与时间线展示",
    "status_code": "状态码——失败计数",
    "ua_raw": "User-Agent——浏览器/系统识别",
    "ua_class": "设备类型——PC/移动/飞书 分类",
    "username": "账号——LBA 用户维度聚合（匿名不进统计）",
    "display_name": "显示名——LBA 用户列表第二列",
    "l7_app_request_type": "请求类型——零信任爆破判定口径（redirect_auth）",
    "dst_domain": "目标域名——多域名扫描规则与时间线展示",
}
# 阻断项：任何源缺了它们巡检/LBA 直接失效，保存数据源时 400 阻断
BLOCKING_ROLES: tuple[str, ...] = ("ts", "src_ip")
# 建议项：缺失不阻断，但按源给出明确提示（LBA/规则会降级）
SOURCE_SUGGESTED_ROLES: dict[str, tuple[str, ...]] = {
    "ips": ("action", "severity"),
    "waf": ("action", "url"),
    "ztna": ("username", "display_name", "ua_class", "dst_domain", "l7_app_request_type"),
}


# 平台字段 → Graylog 原生列（与 patrol.REQUEST_FIELD_ALIASES 同步维护；
# 本文件不反向 import patrol，避免循环依赖）
REQUEST_FIELD_ALIASES: dict[str, str] = {"ts": "timestamp", "src": "source"}


def resolve_field(platform_field: str, field_mapping: dict[str, str] | None) -> dict[str, str]:
    """一个平台契约字段最终会向 Graylog 请求哪个列、以什么方式解析。"""
    mapping = field_mapping or {}
    if platform_field in mapping and mapping[platform_field]:
        return {"field": platform_field, "graylog": mapping[platform_field], "how": "mapping"}
    graylog = REQUEST_FIELD_ALIASES.get(platform_field, platform_field)
    how = "alias" if platform_field in REQUEST_FIELD_ALIASES else "same"
    return {"field": platform_field, "graylog": graylog, "how": how}


def validate_required_fields(source_code: str, required_fields: list[str],
                             field_mapping: dict[str, str] | None = None) -> tuple[list[str], list[str]]:
    """必填字段校验：返回 (阻断错误, 建议提示)。

    - 阻断：``ts``/``src_ip`` 不在 required_fields——没有时间列时间窗静默失效、
      没有来源 IP 候选与聚合全空，这两个无论如何不能省；
    - 建议：按源给出缺失的影响说明（如零信任流缺 username → 行为分析恒空）。
    """
    fields = [str(f).strip() for f in (required_fields or []) if str(f).strip()]
    errors: list[str] = []
    for role in BLOCKING_ROLES:
        if role not in fields:
            errors.append(f"缺少必填字段 {role}（{ROLE_LABELS[role]}）")
    warnings: list[str] = []
    for role in SOURCE_SUGGESTED_ROLES.get(source_code, ()):
        if role not in fields:
            warnings.append(f"建议补充 {role}：{ROLE_LABELS.get(role, role)}")
    return errors, warnings


def field_status(stream: dict[str, Any]) -> list[dict[str, Any]]:
    """数据源页展示用：每个 required 字段的解析结果与状态。"""
    mapping = stream.get("field_mapping") or {}
    required = stream.get("required_fields") or []
    suggested = SOURCE_SUGGESTED_ROLES.get(stream.get("source_code") or "", ())
    out: list[dict[str, Any]] = []
    for name in required:
        info = resolve_field(name, mapping)
        info["role"] = ROLE_LABELS.get(name, "")
        info["level"] = "blocking" if name in BLOCKING_ROLES else (
            "suggested" if name in suggested else "optional")
        out.append(info)
    return out


@dataclass
class PatrolConfig:
    """一次巡检/一次连通性测试所需的全部有效配置。"""

    enabled: bool = False
    url: str = ""
    token: str = ""
    auth: str = "token"
    tool: str = "search_messages"
    stream_tool: str = "list_streams"
    args: str = ""
    streams: list[dict[str, Any]] = field(default_factory=lambda: [dict(s) for s in DEFAULT_STREAMS])
    interval: int = 300
    overlap: int = 60
    max_records: int = 2000
    timeout: float = 30.0
    repeat_hours: int = 24
    mode: str = "dry-run"
    source: str = "env"             # env / db
    updated_by: str | None = None
    updated_at: Any = None

    @property
    def configured(self) -> bool:
        return bool(self.url.strip())


def _source_code(item: dict[str, Any]) -> str:
    """source_code 优先取显式值，其次按 name 推导——旧配置只有 name 也能升级。"""
    raw = str(item.get("source_code") or "").strip().lower()
    if raw in SOURCE_CODES:
        return raw
    name = str(item.get("name") or "").strip()
    mapped = SOURCE_CODE_BY_NAME.get(name.upper()) or SOURCE_CODE_BY_NAME.get(name)
    if mapped:
        return mapped
    lowered = name.lower()
    return lowered if lowered in SOURCE_CODES else lowered[:16] or "unknown"


def _string_list(value: Any, limit: int = 16) -> list[str]:
    if isinstance(value, str):
        value = [part.strip() for part in value.split(",")]
    if not isinstance(value, (list, tuple)):
        return []
    out: list[str] = []
    for part in value:
        text = str(part).strip()[:64]
        if text and text not in out:
            out.append(text)
    return out[:limit]


def normalize_streams(raw: Any) -> list[dict[str, Any]]:
    """把任意来源的流配置收敛成固定形状；非法项丢弃，空列表回退默认。

    兼容性：老配置只有 ``name/label/stream_id/query``，这里按 name 推导
    ``source_code`` 并补齐用途与字段契约，读出来即是新结构，不需要迁移脚本。
    """
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except json.JSONDecodeError:
            raw = []
    streams: list[dict[str, Any]] = []
    seen: set[str] = set()
    for item in raw or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        code = _source_code(item)
        if code in seen:            # 同一源重复配置只保留第一条，避免页面出现两行
            continue
        seen.add(code)
        purpose = _string_list(item.get("purpose"))
        if not purpose:
            purpose = list(DEFAULT_PURPOSE.get(code, ["patrol"]))
        required = _string_list(item.get("required_fields"))
        if not required:
            required = list(DEFAULT_REQUIRED.get(code, ["ts", "src_ip"]))
        # 映射预填：配置里没写 field_mapping（老配置/新部署）时，给零信任流
        # 预填真机实测映射；显式给 {} 视为「用户清空过」，不覆盖。
        mapping_raw = item.get("field_mapping")
        if mapping_raw is None and code == "ztna":
            mapping_raw = dict(ZTNA_DEFAULT_MAPPING)
        if mapping_raw is None and code == "waf":
            mapping_raw = dict(WAF_DEFAULT_MAPPING)
        streams.append({
            "name": str(item.get("name")).upper()[:16],
            "label": str(item.get("label") or item.get("name"))[:64],
            "stream_id": str(item.get("stream_id") or "").strip()[:64],
            "query": str(item.get("query") or "").strip()[:255],
            "source_code": code,
            "purpose": [p for p in purpose if p in {"lba", "patrol", "soar"}][:4] or ["patrol"],
            "schema_version": str(item.get("schema_version") or "1.0").strip()[:16],
            "required_fields": required,
            "field_mapping": _field_mapping(mapping_raw),
            "value_mapping": _value_mapping(item.get("value_mapping")),
            "ip_whitelist": _string_list(item.get("ip_whitelist"), limit=64),
            "enabled": bool(item.get("enabled", True)),
        })
    return streams or [dict(s) for s in DEFAULT_STREAMS]


def _field_mapping(raw: Any) -> dict[str, str]:
    """收敛字段映射：``平台字段 → Graylog 实际字段``。

    真实设备的字段名（如零信任网关的 ``employee_id``）和平台契约（``username``）
    对不上时，在这里配一条映射；取数按 Graylog 名请求列，取回后反写回平台名，
    分析层永远只见契约字段。非法项（空键、空值、非 dict）丢弃。
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, str] = {}
    for key, value in raw.items():
        k = str(key).strip()[:64]
        v = str(value).strip()[:64]
        if k and v and k != v:
            out[k] = v
    return dict(list(out.items())[:24])


def _value_mapping(raw: Any) -> dict[str, dict[str, str]]:
    """收敛值映射：``平台字段 → {原始值 → 标准词表}``。

    厂商的动作枚举（绿盟 IPS 的 1/3/6/8、某 WAF 的 permit/drop/block）在
    这里翻成平台标准词表（observe/audit/block/ban/pass/reject）；规则层
    只认标准词表，换厂商只改这份配置。非法项（空键/空值/非 dict）丢弃。
    """
    if not isinstance(raw, dict):
        return {}
    out: dict[str, dict[str, str]] = {}
    for field_name, values in raw.items():
        if not isinstance(values, dict):
            continue
        key = str(field_name).strip()[:64]
        inner: dict[str, str] = {}
        for raw_value, canon in values.items():
            k = str(raw_value).strip()[:64]
            v = str(canon).strip()[:24]
            if k and v and k != v:
                inner[k] = v
        if key and inner:
            out[key] = inner
    return dict(list(out.items())[:8])


def env_defaults(base: Any = None) -> PatrolConfig:
    """环境变量给出的默认值（也是老部署的兼容路径）。"""
    base = base or default_settings
    return PatrolConfig(
        enabled=bool(getattr(base, "patrol_enabled", False)),
        url=(getattr(base, "patrol_mcp_url", "") or "").strip(),
        token=(getattr(base, "patrol_mcp_token", "") or "").strip(),
        auth=(getattr(base, "patrol_mcp_auth", "token") or "token").strip().lower(),
        tool=(getattr(base, "patrol_mcp_tool", "search_messages") or "search_messages").strip(),
        stream_tool=(getattr(base, "patrol_mcp_stream_tool", "list_streams") or "list_streams").strip(),
        args=(getattr(base, "patrol_mcp_args", "") or "").strip(),
        streams=normalize_streams(getattr(base, "patrol_streams", "[]")),
        interval=int(getattr(base, "patrol_interval_seconds", 300) or 300),
        overlap=int(getattr(base, "patrol_overlap_seconds", 60) or 0),
        max_records=int(getattr(base, "patrol_max_records", 2000) or 2000),
        timeout=float(getattr(base, "patrol_mcp_timeout", 30) or 30),
        repeat_hours=int(getattr(base, "patrol_repeat_hours", 24) or 24),
        mode=(getattr(base, "patrol_mode", "dry-run") or "dry-run").strip().lower(),
        source="env",
    )


def load(db: Session | None = None, base: Any = None) -> PatrolConfig:
    """读有效配置：有库行就用库，没有则用环境变量。

    ``base`` 允许调用方传入被 monkeypatch 过的 settings（测试用），
    默认取应用配置。
    """
    fallback = env_defaults(base)
    own_session = db is None
    if own_session:
        db = SessionLocal()
    try:
        row = db.get(PatrolSetting, 1)
        if row is None:
            return fallback
        return PatrolConfig(
            enabled=bool(row.enabled),
            url=(row.mcp_url or "").strip(),
            token=(row.mcp_token or "").strip(),
            auth=(row.mcp_auth or fallback.auth).strip().lower(),
            tool=(row.mcp_tool or fallback.tool).strip(),
            stream_tool=(row.mcp_stream_tool or fallback.stream_tool).strip(),
            args=(row.mcp_args or "").strip(),
            streams=normalize_streams(row.streams),
            interval=int(row.interval_seconds or fallback.interval),
            overlap=int(row.overlap_seconds or 0),
            max_records=int(row.max_records or fallback.max_records),
            timeout=float(row.timeout_seconds or fallback.timeout),
            repeat_hours=int(row.repeat_hours or fallback.repeat_hours),
            mode=(row.mode or fallback.mode).strip().lower(),
            source="db",
            updated_by=row.updated_by,
            updated_at=row.updated_at,
        )
    finally:
        if own_session:
            db.close()


def public(cfg: PatrolConfig) -> dict[str, Any]:
    """给前端的配置视图：不含明文 token，只给「是否已设置 + 尾号」。"""
    return {
        "enabled": cfg.enabled,
        "mcp_url": cfg.url,
        "mcp_auth": cfg.auth,
        "mcp_tool": cfg.tool,
        "mcp_stream_tool": cfg.stream_tool,
        "mcp_args": cfg.args,
        "streams": [dict(s, field_status=field_status(s)) for s in cfg.streams],
        "interval_seconds": cfg.interval,
        "overlap_seconds": cfg.overlap,
        "max_records": cfg.max_records,
        "timeout_seconds": cfg.timeout,
        "repeat_hours": cfg.repeat_hours,
        "mode": cfg.mode,
        "source": cfg.source,
        "token_set": bool(cfg.token),
        "token_hint": mask_token(cfg.token),
        "updated_by": cfg.updated_by,
        "updated_at": cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


def _clamp(value: Any, low: int, high: int, name: str, default: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = default
    if not low <= parsed <= high:
        raise BizError(f"{name} 需在 {low}~{high} 之间", 400, 400)
    return parsed


def save(db: Session, data: dict[str, Any], operator: str = "system",
         base: Any = None) -> PatrolConfig:
    """保存配置（单行 upsert）；字段缺失则保留原值，token 留空表示不修改。"""
    current = load(db, base)
    row = db.get(PatrolSetting, 1) or PatrolSetting(id=1)

    url = str(data.get("mcp_url", current.url) or "").strip()
    if url and not url.startswith(("http://", "https://")):
        raise BizError("MCP 地址需以 http:// 或 https:// 开头", 400, 400)

    auth = str(data.get("mcp_auth", current.auth) or "token").strip().lower()
    if auth not in AUTH_CHOICES:
        raise BizError(f"鉴权方式需为 {'/'.join(sorted(AUTH_CHOICES))}", 400, 400)

    mode = str(data.get("mode", current.mode) or "dry-run").strip().lower()
    if mode not in MODES:
        raise BizError("模式需为 dry-run / assist / auto", 400, 400)

    tool = str(data.get("mcp_tool", current.tool) or "search_messages").strip()
    stream_tool = str(data.get("mcp_stream_tool", current.stream_tool) or "list_streams").strip()
    if not tool or not stream_tool:
        raise BizError("工具名不能为空", 400, 400)

    # token：留空/掩码占位符 = 保持原值；clear_token=true 才清空
    token = current.token
    if data.get("clear_token"):
        token = ""
    else:
        incoming = str(data.get("mcp_token") or "").strip()
        if incoming and incoming != TOKEN_MASK:
            token = incoming

    row.enabled = 1 if bool(data.get("enabled", current.enabled)) else 0
    row.mcp_url = url
    row.mcp_token = token
    row.mcp_auth = auth
    row.mcp_tool = tool
    row.mcp_stream_tool = stream_tool
    row.mcp_args = str(data.get("mcp_args", current.args) or "").strip()
    row.streams = normalize_streams(data.get("streams", current.streams))
    # 必填字段校验：ts / src_ip 缺失会让时间窗与 IP 聚合静默失效，保存即阻断；
    # 建议项缺失不阻断，但在返回的 streams.field_status 里带 level 提示
    for stream in row.streams:
        if not stream.get("enabled", True):
            continue
        errors, _warnings = validate_required_fields(
            stream.get("source_code") or "", stream.get("required_fields") or [],
            stream.get("field_mapping"))
        if errors:
            raise BizError(f"数据源「{stream.get('label') or stream.get('name')}」"
                           + "；".join(errors), 400, 400)
    row.interval_seconds = _clamp(data.get("interval_seconds", current.interval), 60, 3600,
                                 "巡检间隔", 300)
    row.overlap_seconds = _clamp(data.get("overlap_seconds", current.overlap), 0, 600,
                                "窗口重叠", 60)
    row.max_records = _clamp(data.get("max_records", current.max_records), 1, 10000,
                             "单轮上限", 2000)
    row.timeout_seconds = _clamp(data.get("timeout_seconds", current.timeout), 5, 120,
                                 "超时时间", 30)
    row.repeat_hours = _clamp(data.get("repeat_hours", current.repeat_hours), 1, 720,
                              "重复标记窗口", 24)
    row.mode = mode
    row.updated_by = operator
    row.updated_at = utcnow()
    db.add(row)
    db.commit()
    db.refresh(row)
    logger.info("日志巡检配置已更新（by %s）：url=%s enabled=%s", operator, url, bool(row.enabled))
    return load(db, base)
