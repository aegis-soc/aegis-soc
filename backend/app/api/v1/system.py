"""系统设置：全局熔断开关、运行状态、用户列表、运行期配置、版本与更新检查。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app import __version__
from app.cache import cache
from app.common import BizError, client_ip, ok
from app.config import settings
from app.database import get_db
from app.deps import require_perms
from app.models import SystemUser
from app.schemas import (
    KillSwitchIn,
    SystemSettingsIn,
    SystemStatusOut,
    UpdateCheckOut,
    UserOut,
)
from app.services import sysconf, update_check
from app.services.audit import write_audit
from app.services.version_info import get_version_info
from plugins import registry

router = APIRouter(prefix="/system", tags=["系统"])


@router.get("/status")
def system_status(db: Session = Depends(get_db)):
    info = get_version_info()
    return ok(
        SystemStatusOut(
            version=__version__,
            commit=info["commit"],
            build_time=info["build_time"],
            app_env=settings.app_env,
            kill_switch=cache.kill_switch,
            task_eager=settings.task_eager,
            database="sqlite" if settings.is_sqlite else "mysql",
            plugin_count=len(registry.list_manifests()),
        ).model_dump()
    )


@router.get("/update/check")
def check_update(force: bool = False, _=Depends(require_perms("system:*"))):
    """只读：问一次 GitHub 有没有新版。不下载、不部署、不改任何状态。"""
    return ok(UpdateCheckOut(**update_check.check(force=force)).model_dump())


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


@router.get("/settings")
def get_settings(
    db: Session = Depends(get_db),
    _=Depends(require_perms("system:*")),
):
    """运行期配置（当前用于告警接口的来源 IP 白名单）。"""
    return ok(sysconf.public(db))


@router.put("/settings")
def update_settings(
    body: SystemSettingsIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("system:*")),
):
    """保存运行期配置。保存即生效——校验读库，不需要重启容器。

    管理员专属：放开来源限制等于放开"收告警就封 IP"的入口。
    """
    try:
        data = sysconf.save(
            db,
            enforce=body.alert_ip_enforce,
            allowlist=body.alert_ip_allowlist,
            operator=user.username,
        )
    except ValueError as exc:
        raise BizError(str(exc), 400, 400) from None
    write_audit(
        db, "SYSTEM_SETTING_UPDATE", operator=user.username, role_code=user.role_code,
        target_type="system", target_id="settings",
        content={
            "alert_ip_enforce": data["alert_ip_enforce"],
            "alert_ip_entries": data["alert_ip_entries"],
        },
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(data)


@router.get("/users")
def list_users(
    db: Session = Depends(get_db),
    _=Depends(require_perms("system:*")),
):
    rows = db.query(SystemUser).order_by(SystemUser.id.asc()).all()
    return ok({"items": [UserOut.model_validate(r).model_dump(mode="json") for r in rows]})
