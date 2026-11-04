"""操作审计日志查询。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import ok, paginate
from app.database import get_db
from app.deps import require_perms
from app.models import OperationAudit
from app.schemas import AuditOut

router = APIRouter(prefix="/audit", tags=["审计"])


@router.get("")
def list_audit(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    op_type: str | None = None,
    operator: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("audit:read")),
):
    stmt = select(OperationAudit)
    if op_type:
        stmt = stmt.where(OperationAudit.op_type == op_type)
    if operator:
        stmt = stmt.where(OperationAudit.operator == operator)
    stmt = stmt.order_by(OperationAudit.created_at.desc(), OperationAudit.id.desc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [AuditOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })
