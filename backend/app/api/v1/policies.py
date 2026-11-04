"""自动化封禁策略管理。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.database import get_db
from app.deps import require_perms
from app.models import AutomationPolicy, SystemUser
from app.schemas import PolicyCreateIn, PolicyOut, PolicyUpdateIn
from app.services.audit import write_audit

router = APIRouter(prefix="/policies", tags=["策略"])


def _get(db: Session, policy_id: int) -> AutomationPolicy:
    row = db.get(AutomationPolicy, policy_id)
    if row is None:
        raise BizError("策略不存在", 404, 404)
    return row


@router.get("")
def list_policies(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    enabled: bool | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("policy:read")),
):
    stmt = select(AutomationPolicy)
    if enabled is not None:
        stmt = stmt.where(AutomationPolicy.enabled == (1 if enabled else 0))
    stmt = stmt.order_by(AutomationPolicy.priority.asc(), AutomationPolicy.id.asc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [PolicyOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


@router.post("")
def create_policy(
    body: PolicyCreateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("policy:*")),
):
    if db.query(AutomationPolicy).filter(AutomationPolicy.policy_code == body.policy_code).first():
        raise BizError("策略编码已存在", 400, 400)
    data = body.model_dump()
    for key in ("enabled", "require_approval", "auto_dispatch"):
        data[key] = 1 if data[key] else 0
    row = AutomationPolicy(**data)
    db.add(row)
    db.flush()
    write_audit(
        db, "POLICY_CREATE", operator=user.username, role_code=user.role_code,
        target_type="policy", target_id=row.id,
        content={"policy_code": row.policy_code}, client_ip=client_ip(request),
    )
    db.commit()
    return ok(PolicyOut.model_validate(row).model_dump(mode="json"))


@router.get("/{policy_id}")
def get_policy(
    policy_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("policy:read")),
):
    return ok(PolicyOut.model_validate(_get(db, policy_id)).model_dump(mode="json"))


@router.put("/{policy_id}")
def update_policy(
    policy_id: int,
    body: PolicyUpdateIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("policy:*")),
):
    row = _get(db, policy_id)
    data = body.model_dump(exclude_none=True)
    for key in ("enabled", "require_approval", "auto_dispatch"):
        if key in data:
            data[key] = 1 if data[key] else 0
    for key, value in data.items():
        setattr(row, key, value)
    write_audit(
        db, "POLICY_UPDATE", operator=user.username, role_code=user.role_code,
        target_type="policy", target_id=row.id,
        content=body.model_dump(exclude_none=True, mode="json"), client_ip=client_ip(request),
    )
    db.commit()
    return ok(PolicyOut.model_validate(row).model_dump(mode="json"))


@router.post("/{policy_id}/toggle")
def toggle_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("policy:*")),
):
    row = _get(db, policy_id)
    row.enabled = 0 if row.enabled else 1
    write_audit(
        db, "POLICY_TOGGLE", operator=user.username, role_code=user.role_code,
        target_type="policy", target_id=row.id, content={"enabled": row.enabled},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok({"id": row.id, "enabled": bool(row.enabled)})


@router.delete("/{policy_id}")
def delete_policy(
    policy_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("policy:*")),
):
    row = _get(db, policy_id)
    write_audit(
        db, "POLICY_DELETE", operator=user.username, role_code=user.role_code,
        target_type="policy", target_id=row.id,
        content={"policy_code": row.policy_code}, client_ip=client_ip(request),
    )
    db.delete(row)
    db.commit()
    return ok({"id": policy_id})
