"""任务中心：查询、重试、取消、审批、执行日志。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.config import settings
from app.database import get_db, utcnow
from app.deps import require_perms
from app.engines.policy import dispatch_tasks
from app.models import ApprovalRecord, DeviceTask, DeviceTaskLog, SystemUser
from app.schemas import TaskLogOut, TaskOut
from app.services.audit import write_audit

router = APIRouter(prefix="/tasks", tags=["任务"])


def _get(db: Session, task_id: int) -> DeviceTask:
    row = db.get(DeviceTask, task_id)
    if row is None:
        raise BizError("任务不存在", 404, 404)
    return row


@router.get("")
def list_tasks(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=200),
    task_status: str | None = None,
    operation: str | None = None,
    keyword: str | None = None,
    db: Session = Depends(get_db),
    _=Depends(require_perms("task:read")),
):
    stmt = select(DeviceTask)
    if task_status:
        stmt = stmt.where(DeviceTask.task_status == task_status)
    if operation:
        stmt = stmt.where(DeviceTask.operation == operation)
    if keyword:
        stmt = stmt.where(DeviceTask.ioc_value.like(f"%{keyword}%"))
    stmt = stmt.order_by(DeviceTask.created_at.desc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [TaskOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
    })


@router.get("/{task_id}")
def get_task(
    task_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("task:read")),
):
    task = _get(db, task_id)
    logs = (
        db.query(DeviceTaskLog)
        .filter(DeviceTaskLog.task_id == task_id)
        .order_by(DeviceTaskLog.id.asc())
        .all()
    )
    return ok({
        "task": TaskOut.model_validate(task).model_dump(mode="json"),
        "logs": [TaskLogOut.model_validate(x).model_dump(mode="json") for x in logs],
    })


@router.post("/{task_id}/retry")
def retry_task(
    task_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("task:*")),
):
    task = _get(db, task_id)
    if task.task_status in {"SUCCESS", "RUNNING", "CANCELED", "APPROVING"}:
        raise BizError(f"当前状态 {task.task_status} 不允许重试", 400, 400)
    task.task_status = "PENDING"
    task.retry_count = 0
    task.next_retry_at = None
    task.result_msg = "人工重试"
    write_audit(
        db, "TASK_RETRY", operator=user.username, role_code=user.role_code,
        target_type="task", target_id=task.id, client_ip=client_ip(request),
    )
    db.commit()
    dispatch_tasks([task.id])
    return ok({"id": task.id, "task_status": "PENDING"})


@router.post("/{task_id}/cancel")
def cancel_task(
    task_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("task:*")),
):
    task = _get(db, task_id)
    if task.task_status in {"SUCCESS", "CANCELED"}:
        raise BizError(f"当前状态 {task.task_status} 不允许取消", 400, 400)
    task.task_status = "CANCELED"
    task.finished_at = utcnow()
    task.result_msg = "人工取消"
    write_audit(
        db, "TASK_CANCEL", operator=user.username, role_code=user.role_code,
        target_type="task", target_id=task.id, client_ip=client_ip(request),
    )
    db.commit()
    return ok({"id": task.id, "task_status": "CANCELED"})


@router.post("/{task_id}/approve")
def approve_task(
    task_id: int,
    request: Request,
    approve: bool = Query(..., description="true 通过 / false 拒绝"),
    reason: str | None = None,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("task:*")),
):
    task = _get(db, task_id)
    if task.task_status != "APPROVING":
        raise BizError("任务不处于待审批状态", 400, 400)
    record = (
        db.query(ApprovalRecord)
        .filter(ApprovalRecord.task_id == task.id, ApprovalRecord.status == "PENDING")
        .first()
    )
    if record:
        record.status = "APPROVED" if approve else "REJECTED"
        record.approver = user.username
        record.reason = reason
        record.decided_at = utcnow()
    task.task_status = "PENDING" if approve else "REJECTED"
    task.result_msg = "审批通过，等待下发" if approve else f"审批拒绝: {reason or ''}"
    write_audit(
        db, "TASK_APPROVE", operator=user.username, role_code=user.role_code,
        target_type="task", target_id=task.id,
        content={"approved": approve, "reason": reason}, client_ip=client_ip(request),
    )
    db.commit()
    if approve:
        dispatch_tasks([task.id])
    return ok({"id": task.id, "task_status": task.task_status})


@router.get("/metrics/summary")
def task_metrics(
    db: Session = Depends(get_db),
    _=Depends(require_perms("task:read")),
):
    rows = db.query(DeviceTask.task_status, DeviceTask.id).all()
    summary: dict[str, int] = {}
    for status, _ in rows:
        summary[status] = summary.get(status, 0) + 1
    return ok({"summary": summary, "max_retry": settings.task_max_retry})
