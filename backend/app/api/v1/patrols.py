"""日志巡检（P0）：手动触发、历史批次、候选明细与 MCP 连通性自检。

权限沿用 AI 巡检的 ``inspection:read`` / ``inspection:run``——这本质上是同一类
"看系统有没有漏"的能力，不再新增权限点，避免角色配置变动。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.config import settings
from app.database import get_db
from app.deps import require_perms
from app.models import PatrolCandidate, PatrolRun, SystemUser
from app.schemas import PatrolCandidateOut, PatrolDetailOut, PatrolRunOut
from app.services.audit import write_audit
from app.services.patrol import mcp_status, run_patrol

router = APIRouter(tags=["日志巡检"])


def _detail(db: Session, run: PatrolRun) -> dict:
    rows = (
        db.query(PatrolCandidate)
        .filter(PatrolCandidate.run_id == run.id)
        .order_by(
            PatrolCandidate.severity.desc(),
            PatrolCandidate.hits.desc(),
            PatrolCandidate.id.asc(),
        )
        .all()
    )
    payload = PatrolDetailOut.model_validate(run).model_dump(mode="json")
    payload["candidates"] = [
        PatrolCandidateOut.model_validate(row).model_dump(mode="json") for row in rows
    ]
    return payload


@router.post("/patrols/run")
def run_now(
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("inspection:run")),
):
    """立即跑一轮只读巡检：读 Graylog 日志、出候选，不封禁任何 IP。"""
    run = run_patrol(db, trigger="manual", created_by=user.username)
    write_audit(
        db, "PATROL_RUN", operator=user.username, role_code=user.role_code,
        target_type="patrol", target_id=run.id,
        content={
            "status": run.status, "fetched": run.fetched,
            "candidates": run.candidate_count, "would_block": run.would_block,
            "duration_ms": run.duration_ms,
        },
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(_detail(db, run))


@router.get("/patrols/mcp/status")
def check_mcp(
    _=Depends(require_perms("inspection:read")),
):
    """MCP 连通性自检：返回服务端信息、协议版本与可用工具列表。"""
    return ok(mcp_status())


@router.get("/patrols/latest")
def latest_run(
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    """最近一轮巡检（含候选明细）；从未跑过时返回 null。"""
    run = (
        db.query(PatrolRun)
        .order_by(PatrolRun.created_at.desc(), PatrolRun.id.desc())
        .first()
    )
    if run is None:
        return ok(None)
    return ok(_detail(db, run))


@router.get("/patrols")
def list_runs(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    status: str | None = Query(None, description="ok / degraded / failed / skipped"),
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    stmt = select(PatrolRun)
    if status:
        if status not in {"ok", "degraded", "failed", "skipped"}:
            raise BizError("status 取值非法", 400, 400)
        stmt = stmt.where(PatrolRun.status == status)
    stmt = stmt.order_by(PatrolRun.created_at.desc(), PatrolRun.id.desc())
    rows, total = paginate(stmt, db, page, page_size)
    return ok({
        "items": [PatrolRunOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
        "mode": settings.patrol_mode,
        "enabled": settings.patrol_enabled,
        "interval_seconds": settings.patrol_interval_seconds,
    })


@router.get("/patrols/{run_id}")
def get_run(
    run_id: int,
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    run = db.get(PatrolRun, run_id)
    if run is None:
        raise BizError("巡检记录不存在", 404, 404)
    return ok(_detail(db, run))
