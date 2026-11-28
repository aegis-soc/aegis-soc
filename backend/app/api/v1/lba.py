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
def login_overview(range: str = "", db: Session = Depends(get_db),
                   _=Depends(require_perms("lba:read"))):
    """概览指标。``range=1h/24h/7d``：页面按钮按需触发，点击才取数分析。"""
    return ok(lba.login_overview(db, range_key=range))


@router.get("/login/anomaly-users")
def anomaly_users(risk_level: str = "", page: int = 1, page_size: int = 20,
                  range: str = "", db: Session = Depends(get_db),
                  _=Depends(require_perms("lba:read"))):
    if page < 1 or page_size < 1 or page_size > 100:
        raise BizError("page ≥ 1 且 page_size 在 1~100 之间", 400, 400)
    return ok(lba.anomaly_users(db, risk_level=risk_level.strip().lower(),
                                page=page, page_size=page_size, range_key=range))


@router.get("/profile/user/{username}")
def user_profile(username: str, range: str = "", db: Session = Depends(get_db),
                 _=Depends(require_perms("lba:read"))):
    return ok(lba.user_profile(db, username, range_key=range))


@router.get("/collect/status")
def collect_status(db: Session = Depends(get_db),
                   _=Depends(require_perms("lba:read"))):
    """采集器状态：水位、最近一轮结果、预聚合行数（诊断用）。"""
    from app.services.lba_collector import collect_status as _status
    return ok(_status(db))
