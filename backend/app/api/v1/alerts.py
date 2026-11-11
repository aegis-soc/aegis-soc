"""告警接入：Graylog Webhook（Secret 校验）/ 通用告警 / 告警查询。"""
from __future__ import annotations

import hmac
import logging
import time
from typing import Any

from fastapi import APIRouter, Body, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate, source_ip
from app.config import settings
from app.database import get_db
from app.deps import require_perms
from app.engines.alert_parser import parse_generic, parse_graylog
from app.engines.policy import process_alert
from app.models import AlertEvent
from app.schemas import AlertOut, AlertReceiveOut, GenericAlertIn
from app.services import sysconf

logger = logging.getLogger("aegis")

router = APIRouter(tags=["告警"])


def _verify_source(request: Request, db: Session) -> str:
    """来源 IP 白名单（系统设置页可开关，默认关闭）。

    放在 secret 之前判：secret 对错是"你有没有钥匙"，来源 IP 是"你能不能走到
    这道门前"——先挡来源，日志里就不会被无效 secret 刷满。
    返回已判定的来源 IP，供后续复用，避免两处取值口径不一致。
    """
    ip = source_ip(request)
    networks = sysconf.allowlist_networks(db)
    if networks and not sysconf.ip_allowed(ip, networks):
        logger.warning("告警接口拒绝来源 IP %s（不在白名单内）", ip)
        raise BizError(f"来源 IP {ip} 不在 API 调用白名单内", 403, 403)
    return ip


def _verify_webhook(request: Request, db: Session) -> None:
    _verify_source(request, db)
    secret = request.query_params.get("secret") or request.headers.get("x-graylog-secret", "")
    if not secret or not hmac.compare_digest(secret, settings.graylog_webhook_secret):
        raise BizError("Webhook Secret 校验失败", 403, 403)

    if settings.graylog_bearer_token:
        expected = f"Bearer {settings.graylog_bearer_token}"
        if not hmac.compare_digest(request.headers.get("authorization", ""), expected):
            raise BizError("Bearer Token 校验失败", 403, 403)

    timestamp = request.headers.get("x-graylog-timestamp") or request.query_params.get("ts")
    if timestamp:
        try:
            drift = abs(time.time() - float(timestamp))
        except ValueError:
            raise BizError("时间戳格式非法", 403, 403)
        if drift > settings.alert_replay_tolerance:
            raise BizError("告警时间戳超出防重放窗口", 403, 403)


@router.post("/alerts/graylog")
def graylog_alert(
    request: Request,
    payload: dict[str, Any] = Body(...),
    db: Session = Depends(get_db),
):
    """Graylog Event Definition → HTTP Notification。
    校验 Secret / 可选 Bearer / 可选时间戳防重放后，快速返回 accepted，
    实际处置全部在策略引擎与异步任务中完成。
    """
    _verify_webhook(request, db)
    parsed = parse_graylog(payload)
    result = process_alert(db, parsed, client_ip=client_ip(request))
    return ok(AlertReceiveOut(**result).model_dump())


@router.post("/alerts/generic")
def generic_alert(
    body: GenericAlertIn,
    request: Request,
    db: Session = Depends(get_db),
    _=Depends(require_perms("alert:*")),
):
    parsed = parse_generic(body)
    result = process_alert(db, parsed, operator="api", client_ip=client_ip(request))
    return ok(AlertReceiveOut(**result).model_dump())


@router.get("/alerts")
def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    status: str | None = None,
    source_system: str | None = None,
    keyword: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("alert:read")),
):
    stmt = select(AlertEvent)
    if status:
        stmt = stmt.where(AlertEvent.status == status)
    if source_system:
        stmt = stmt.where(AlertEvent.source_system == source_system)
    if keyword:
        stmt = stmt.where(AlertEvent.title.like(f"%{keyword}%"))
    stmt = stmt.order_by(AlertEvent.received_at.desc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [AlertOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("alert:read")),
):
    row = db.get(AlertEvent, alert_id)
    if row is None:
        raise BizError("告警不存在", 404, 404)
    return ok(AlertOut.model_validate(row).model_dump(mode="json"))
