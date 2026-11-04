"""安全设备资产与插件管理。"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.database import get_db, utcnow
from app.deps import require_perms
from app.engines.validation import resolve_device_config
from app.models import DeviceCapability, DevicePlugin, SecurityDevice, SystemUser
from app.schemas import DeviceCreateIn, DeviceOut, DeviceUpdateIn, PluginOut, PluginTestIn
from app.services.audit import write_audit
from plugins import registry

router = APIRouter(tags=["设备与插件"])


def _ensure_plugin(code: str) -> dict[str, Any]:
    manifest = registry.get_manifest(code)
    if manifest is None:
        raise BizError(f"插件未注册: {code}", 400, 400)
    return manifest


def _sync_capabilities(db: Session, device: SecurityDevice, manifest: dict[str, Any]) -> None:
    for ioc_type in manifest.get("ioc_types", []):
        for capability in manifest.get("capabilities", []):
            row = (
                db.query(DeviceCapability)
                .filter(
                    DeviceCapability.device_id == device.id,
                    DeviceCapability.ioc_type == ioc_type,
                    DeviceCapability.capability == capability,
                )
                .first()
            )
            if row is None:
                db.add(
                    DeviceCapability(
                        device_id=device.id, plugin_code=device.plugin_code,
                        ioc_type=ioc_type, capability=capability, enabled=1,
                    )
                )
            else:
                row.enabled = 1
    device.capabilities = [
        {"ioc_type": t, "capability": c}
        for t in manifest.get("ioc_types", [])
        for c in manifest.get("capabilities", [])
    ]


@router.get("/devices")
def list_devices(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    plugin_code: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("device:read")),
):
    stmt = select(SecurityDevice)
    if plugin_code:
        stmt = stmt.where(SecurityDevice.plugin_code == plugin_code)
    if status:
        stmt = stmt.where(SecurityDevice.status == status)
    stmt = stmt.order_by(SecurityDevice.id.asc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [DeviceOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


@router.post("/devices")
def create_device(
    body: DeviceCreateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("device:*")),
):
    manifest = _ensure_plugin(body.plugin_code)
    if db.query(SecurityDevice).filter(SecurityDevice.device_code == body.device_code).first():
        raise BizError("设备编码已存在", 400, 400)
    device = SecurityDevice(
        device_code=body.device_code,
        name=body.name,
        vendor=body.vendor,
        model=body.model,
        region=body.region,
        plugin_code=body.plugin_code,
        config_json=body.config_json,
        credential_ref=body.credential_ref,
        status="unknown",
        auto_dispatch=1 if body.auto_dispatch else 0,
    )
    db.add(device)
    db.flush()
    _sync_capabilities(db, device, manifest)
    write_audit(
        db, "DEVICE_CREATE", operator=user.username, role_code=user.role_code,
        target_type="device", target_id=device.id,
        content={"device_code": device.device_code, "plugin_code": device.plugin_code},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(DeviceOut.model_validate(device).model_dump(mode="json"))


@router.put("/devices/{device_id}")
def update_device(
    device_id: int,
    body: DeviceUpdateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("device:*")),
):
    device = db.get(SecurityDevice, device_id)
    if device is None:
        raise BizError("设备不存在", 404, 404)
    for field, value in body.model_dump(exclude_none=True).items():
        if field == "auto_dispatch":
            value = 1 if value else 0
        setattr(device, field, value)
    write_audit(
        db, "DEVICE_UPDATE", operator=user.username, role_code=user.role_code,
        target_type="device", target_id=device.id,
        content=body.model_dump(exclude_none=True, mode="json"), client_ip=client_ip(request),
    )
    db.commit()
    return ok(DeviceOut.model_validate(device).model_dump(mode="json"))


@router.delete("/devices/{device_id}")
def delete_device(
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("device:*")),
):
    device = db.get(SecurityDevice, device_id)
    if device is None:
        raise BizError("设备不存在", 404, 404)
    write_audit(
        db, "DEVICE_DELETE", operator=user.username, role_code=user.role_code,
        target_type="device", target_id=device.id,
        content={"device_code": device.device_code}, client_ip=client_ip(request),
    )
    db.query(DeviceCapability).filter(DeviceCapability.device_id == device.id).delete()
    db.delete(device)
    db.commit()
    return ok({"id": device_id})


@router.post("/devices/{device_id}/test")
def test_device(
    device_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("device:*")),
):
    device = db.get(SecurityDevice, device_id)
    if device is None:
        raise BizError("设备不存在", 404, 404)
    result = registry.test_plugin(device.plugin_code, resolve_device_config(device))
    device.status = "online" if result.get("success") else "offline"
    device.last_check_at = utcnow()
    write_audit(
        db, "DEVICE_TEST", operator=user.username, role_code=user.role_code,
        target_type="device", target_id=device.id,
        content={"success": result.get("success"), "message": result.get("message")},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(result)


@router.get("/plugins")
def list_plugins(
    db: Session = Depends(get_db),
    _=Depends(require_perms("plugin:read")),
):
    stored = {row.plugin_code: row for row in db.query(DevicePlugin).all()}
    items: list[dict[str, Any]] = []
    for manifest in registry.list_manifests():
        code = manifest["plugin_code"]
        row = stored.get(code)
        items.append(
            {
                "id": row.id if row else None,
                "plugin_code": code,
                "plugin_name": manifest.get("plugin_name", code),
                "version": manifest.get("version"),
                "manifest": manifest.get("manifest", {}),
                "enabled": row.enabled if row else 1,
                "builtin": row.builtin if row else 1,
                "description": manifest.get("description"),
            }
        )
    return ok({"items": items, "total": len(items)})


@router.post("/plugins/test")
def test_plugin(
    body: PluginTestIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("plugin:*")),
):
    config = dict(body.config_json or {})
    plugin_code = body.plugin_code
    if body.device_id:
        device = db.get(SecurityDevice, body.device_id)
        if device is None:
            raise BizError("设备不存在", 404, 404)
        plugin_code = device.plugin_code
        config = resolve_device_config(device)
    if not plugin_code:
        raise BizError("请指定 plugin_code 或 device_id", 400, 400)
    result = registry.test_plugin(plugin_code, config)
    write_audit(
        db, "PLUGIN_TEST", operator=user.username, role_code=user.role_code,
        target_type="plugin", target_id=plugin_code,
        content={"success": result.get("success")}, client_ip=client_ip(request),
    )
    db.commit()
    return ok(result)
