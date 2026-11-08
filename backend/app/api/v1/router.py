"""API v1 路由汇总。"""
from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    alerts, audit, auth, dashboard, devices, inspections, ioc, patrols, policies, system, tasks,
)

api_router = APIRouter(prefix="/api/v1")

api_router.include_router(auth.router)
api_router.include_router(alerts.router)
api_router.include_router(ioc.router)
api_router.include_router(devices.router)
api_router.include_router(policies.router)
api_router.include_router(tasks.router)
api_router.include_router(audit.router)
api_router.include_router(dashboard.router)
api_router.include_router(inspections.router)
api_router.include_router(patrols.router)
api_router.include_router(system.router)
