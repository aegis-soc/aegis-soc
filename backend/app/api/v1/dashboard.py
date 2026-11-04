"""首页大盘统计。"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.cache import cache
from app.common import ok
from app.database import get_db, utcnow
from app.deps import require_perms
from app.models import AlertEvent, DeviceTask, IocIndicator, IpWhitelist, SecurityDevice
from app.schemas import AlertOut, DashboardOut

router = APIRouter(prefix="/dashboard", tags=["大盘"])


@router.get("")
def dashboard(
    db: Session = Depends(get_db),
    _=Depends(require_perms("dashboard:read")),
):
    today = utcnow().replace(hour=0, minute=0, second=0, microsecond=0)

    def _count(model, *conditions) -> int:
        stmt = db.query(func.count(model.id))
        for condition in conditions:
            stmt = stmt.filter(condition)
        return int(stmt.scalar() or 0)

    risk_rows = (
        db.query(AlertEvent.risk_level, func.count(AlertEvent.id))
        .group_by(AlertEvent.risk_level)
        .all()
    )
    risk_distribution = {str(level or "unknown"): int(count) for level, count in risk_rows}
    recent = (
        db.query(AlertEvent).order_by(AlertEvent.received_at.desc()).limit(10).all()
    )

    return ok(
        DashboardOut(
            alerts_today=_count(AlertEvent, AlertEvent.received_at >= today),
            alerts_total=_count(AlertEvent),
            ioc_active=_count(IocIndicator, IocIndicator.status == "active"),
            ioc_expired=_count(IocIndicator, IocIndicator.status == "expired"),
            whitelist_count=_count(IpWhitelist, IpWhitelist.status == 1),
            device_online=_count(SecurityDevice, SecurityDevice.status == "online"),
            device_total=_count(SecurityDevice),
            task_pending=_count(DeviceTask, DeviceTask.task_status.in_(["PENDING", "APPROVING", "RETRY"])),
            task_success=_count(DeviceTask, DeviceTask.task_status == "SUCCESS"),
            task_failed=_count(DeviceTask, DeviceTask.task_status == "FAILED"),
            task_total=_count(DeviceTask),
            kill_switch=cache.kill_switch,
            risk_distribution=risk_distribution,
            recent_alerts=[AlertOut.model_validate(r) for r in recent],
        ).model_dump(mode="json")
    )
