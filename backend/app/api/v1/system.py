"""系统设置：全局熔断开关、运行状态、用户列表。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import __version__
from app.cache import cache
from app.common import client_ip, ok
from app.config import settings
from app.database import get_db
from app.deps import require_perms
from app.models import SystemUser
from app.schemas import KillSwitchIn, SystemStatusOut, UserOut
from app.services.audit import write_audit
from plugins import registry

router = APIRouter(prefix="/system", tags=["系统"])


@router.get("/status")
def system_status(db: Session = Depends(get_db)):
    return ok(
        SystemStatusOut(
            version=__version__,
            app_env=settings.app_env,
            kill_switch=cache.kill_switch,
            task_eager=settings.task_eager,
            database="sqlite" if settings.is_sqlite else "mysql",
            plugin_count=len(registry.list_manifests()),
        ).model_dump()
    )


@router.get("/kill-switch")
def get_kill_switch(_=Depends(require_perms("dashboard:read"))):
    return ok({"enabled": cache.kill_switch})


@router.post("/kill-switch")
def set_kill_switch(
    body: KillSwitchIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("system:*")),
):
    cache.set_kill_switch(body.enabled)
    write_audit(
        db, "KILL_SWITCH_CHANGE", operator=user.username, role_code=user.role_code,
        target_type="system", target_id="kill_switch",
        content={"enabled": body.enabled, "reason": body.reason},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok({"enabled": body.enabled})


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    _=Depends(require_perms("system:*")),
):
    rows = db.query(SystemUser).order_by(SystemUser.id.asc()).all()
    return ok({"items": [UserOut.model_validate(r).model_dump(mode="json") for r in rows]})
