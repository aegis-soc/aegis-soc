"""日志巡检（P0）：手动触发、历史批次、候选明细与 MCP 连通性自检。

权限沿用 AI 巡检的 ``inspection:read`` / ``inspection:run``——这本质上是同一类
"看系统有没有漏"的能力，不再新增权限点，避免角色配置变动。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok, paginate
from app.database import get_db
from app.deps import require_perms
from app.models import PatrolCandidate, PatrolRun, SystemUser
from app.schemas import (
    PatrolCandidateOut,
    PatrolConfigIn,
    PatrolDetailOut,
    PatrolProbeIn,
    PatrolRunOut,
)
from app.services import patrol_settings
from app.services.audit import write_audit
from app.services.patrol import load_config, mcp_probe, mcp_status, run_patrol

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


@router.get("/patrols/config")
def get_patrol_config(
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    """当前生效配置（库优先、env 兜底）；token 只回掩码与尾号。"""
    return ok(patrol_settings.public(load_config(db)))


@router.put("/patrols/config")
def update_patrol_config(
    payload: PatrolConfigIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("system:*")),
):
    """保存 Graylog MCP 配置：地址、token、三流映射与巡检节奏。

    仅管理员可改（``system:*``）——token 与日志查询目标都属敏感配置；
    留空的 token 表示不修改，避免改地址顺手把凭证清空。
    """
    data = payload.model_dump(exclude_unset=True)
    cfg = patrol_settings.save(db, data, operator=user.username)
    write_audit(
        db, "PATROL_CONFIG_UPDATE", operator=user.username, role_code=user.role_code,
        target_type="patrol_config", target_id=1,
        content={
            "mcp_url": cfg.url, "auth": cfg.auth, "enabled": cfg.enabled,
            "mode": cfg.mode, "interval_seconds": cfg.interval,
            "streams": cfg.streams,
            "token_changed": bool(data.get("mcp_token") or data.get("clear_token")),
        },
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(patrol_settings.public(cfg))


@router.post("/patrols/mcp/test")
def probe_mcp(
    payload: PatrolProbeIn,
    db: Session = Depends(get_db),
    _=Depends(require_perms("system:*")),
):
    """保存前试连：用表单草稿覆盖已保存配置，不落库、不产生巡检记录。"""
    draft = payload.model_dump(exclude_unset=True, exclude_none=True)
    return ok(mcp_probe(draft, db))


@router.get("/patrols/mcp/status")
def check_mcp(
    db: Session = Depends(get_db),
    _=Depends(require_perms("inspection:read")),
):
    """MCP 连通性自检：返回服务端信息、协议版本、工具与流清单。"""
    return ok(mcp_status(db))


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
    cfg = load_config(db)
    return ok({
        "items": [PatrolRunOut.model_validate(r).model_dump(mode="json") for r in rows],
        "total": total, "page": page, "page_size": page_size,
        "mode": cfg.mode,
        "enabled": cfg.enabled,
        "interval_seconds": cfg.interval,
        "config_source": cfg.source,
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
