"""AI 巡检：手动触发、历史报告查询。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.database import get_db
from app.deps import require_perms
from app.models import InspectionReport, SystemUser
from app.schemas import InspectionOut
from app.services.audit import write_audit
from app.services.inspector import run_inspection

router = APIRouter(tags=["AI 巡检"])


@router.post("/inspections/run")
def run_now(
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("inspection:run")),
):
    """立即执行一次 AI 巡检（同步返回完整报告）。"""
    report = run_inspection(db, trigger="manual", created_by=user.username)
    write_audit(
        db, "INSPECTION_RUN", operator=user.username, role_code=user.role_code,
        target_type="inspection", target_id=report.id,
        content={"score": report.score, "overall": report.overall,
                 "duration_ms": report.duration_ms, "ai_enhanced": report.ai_enhanced},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(InspectionOut.model_validate(report).model_dump(mode="json"))


@router.get("/inspections/latest")
def latest_report(
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    """最近一次巡检报告；从未巡检过时返回 null，前端引导用户先跑一次。"""
    report = (
        db.query(InspectionReport)
        .order_by(InspectionReport.created_at.desc(), InspectionReport.id.desc())
        .first()
    )
    if report is None:
        return ok(None)
    return ok(InspectionOut.model_validate(report).model_dump(mode="json"))


@router.get("/inspections/reports")
def list_reports(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    stmt = (
        select(InspectionReport)
        .order_by(InspectionReport.created_at.desc(), InspectionReport.id.desc())
    )
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [InspectionOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


@router.get("/inspections/reports/{report_id}")
def get_report(
    report_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    report = db.get(InspectionReport, report_id)
    if report is None:
        raise BizError("巡检报告不存在", 404, 404)
    return ok(InspectionOut.model_validate(report).model_dump(mode="json"))
