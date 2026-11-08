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

DEFAULT_STREAMS: list[dict[str, str]] = [
    {"name": "IPS", "label": "IPS 入侵防御", "stream_id": "", "query": ""},
    {"name": "WAF", "label": "WAF 应用防火墙", "stream_id": "", "query": ""},
    {"name": "ZTNA", "label": "零信任接入", "stream_id": "", "query": ""},
]


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
    streams: list[dict[str, str]] = field(default_factory=lambda: [dict(s) for s in DEFAULT_STREAMS])
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


def normalize_streams(raw: Any) -> list[dict[str, str]]:
    """把任意来源的流配置收敛成固定形状；非法项丢弃，空列表回退默认三流。"""
    if isinstance(raw, str):
        try:
            raw = json.loads(raw or "[]")
        except json.JSONDecodeError:
            raw = []
    streams: list[dict[str, str]] = []
    for item in raw or []:
        if not isinstance(item, dict) or not item.get("name"):
            continue
        streams.append({
            "name": str(item.get("name")).upper()[:16],
            "label": str(item.get("label") or item.get("name"))[:64],
            "stream_id": str(item.get("stream_id") or "").strip()[:64],
            "query": str(item.get("query") or "").strip()[:255],
        })
    return streams or [dict(s) for s in DEFAULT_STREAMS]


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
        "streams": cfg.streams,
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
