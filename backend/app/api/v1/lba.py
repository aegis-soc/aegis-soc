"""LBA 登录行为分析接口（v1，契约 docs/lba-api.md）。

三个接口全部只读；数据按需从零信任流聚合（复用巡检 MCP 基建），
带 Redis 缓存（overview/列表 120s、用户详情 60s），避免每次刷新都打 Graylog。
风险事件引擎落地前：``pending_events`` 恒 0、``risk_history`` 恒空（契约字段保留）。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.common import BizError, ok
from app.database import get_db
from app.deps import require_perms
from app.services import lba

router = APIRouter(prefix="/lba", tags=["行为分析"])


@router.get("/login/overview")
def login_overview(db: Session = Depends(get_db), _=Depends(require_perms("lba:read"))):
    return ok(lba.login_overview(db))


@router.get("/login/anomaly-users")
def anomaly_users(risk_level: str = "", page: int = 1, page_size: int = 20,
                  db: Session = Depends(get_db), _=Depends(require_perms("lba:read"))):
    if page < 1 or page_size < 1 or page_size > 100:
        raise BizError("page ≥ 1 且 page_size 在 1~100 之间", 400, 400)
    return ok(lba.anomaly_users(db, risk_level=risk_level.strip().lower(),
                                page=page, page_size=page_size))


@router.get("/profile/user/{username}")
def user_profile(username: str, db: Session = Depends(get_db),
                 _=Depends(require_perms("lba:read"))):
    return ok(lba.user_profile(db, username))
