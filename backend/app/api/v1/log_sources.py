"""日志源接口：数据源清单、健康度与局部配置。

权限：
- 读 ``inspection:read``——数据源健康是"看系统有没有漏"的一部分，与巡检同权限；
- 写 ``system:*``——stream_id 与字段契约属敏感配置，只给管理员。

刻意不提供"删除源"：四类源是规范里的固定集合（ips/waf/ztna/nta），
删掉只会让 LBA 或巡检悄悄少一类数据，要停用就置 ``enabled=false``。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.common import client_ip, ok
from app.database import get_db
from app.deps import require_perms
from app.models import SystemUser
from app.schemas import LogSourceUpdate
from app.services import log_sources
from app.services.audit import write_audit

router = APIRouter(prefix="/log-sources", tags=["日志源"])


@router.get("")
def list_log_sources(
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    """四类源的配置 + 最近一轮巡检的健康度（不触发 Graylog 查询）。"""
    return ok(log_sources.list_sources(db))


@router.post("/{source_code}/probe")
def probe_log_source(
    source_code: str,
    minutes: int | None = None,
    limit: int = 20,
    db: Session = Depends(get_db),
    _=Depends(require_perms("system:*")),
):
    """对一个源立即取一次数，返回实际发送的 MCP 参数与服务端原始返回。

    用于排查数据源页「无数据」：参数拼错、stream id 不对、还是这条流真没消息，
    一次就能分清。不落库、不影响巡检检查点。
    """
    return ok(log_sources.probe_source(db, source_code, minutes=minutes, limit=limit))


@router.put("/{source_code}")
def update_log_source(
    source_code: str,
    payload: LogSourceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("system:*")),
):
    """改一个源的 stream_id / 字段契约 / 启停。

    只传要改的字段；``stream_id`` 传空串表示清空（页面上的"解绑"）。
    """
    data = payload.model_dump(exclude_unset=True, exclude_none=True)
    result = log_sources.update_source(db, source_code, data, operator=user.username)
    write_audit(
        db, "LOG_SOURCE_UPDATE", operator=user.username, role_code=user.role_code,
        target_type="log_source", target_id=source_code,
        content={
            "changed": sorted(data.keys()),
            "stream_id": (result.get("source") or {}).get("stream_id"),
            "enabled": (result.get("source") or {}).get("enabled"),
            "schema_version": (result.get("source") or {}).get("schema_version"),
            "required_fields": (result.get("source") or {}).get("required_fields"),
        },
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(result)
