"""Celery Beat 定时计划：到期解封、任务补偿与每日 AI 巡检。"""
from __future__ import annotations

from typing import Any

from celery.schedules import crontab

from app.config import settings


def build_beat_schedule() -> dict[str, Any]:
    return {
        "expire-iocs-and-unblock-every-minute": {
            "task": "aegis.expire_iocs",
            "schedule": 60.0,
            "options": {"queue": "aegis"},
        },
        "compensate-pending-tasks-every-2-minutes": {
            "task": "aegis.compensate_pending",
            "schedule": 120.0,
            "options": {"queue": "aegis"},
        },
        # 每天早上 8:30 自动巡检一次，报告落库供「AI 巡检」页面回看
        "daily-ai-inspection": {
            "task": "aegis.run_inspection",
            "schedule": crontab(minute=30, hour=8),
            "options": {"queue": "aegis"},
        },
        # 日志巡检：默认每 5 分钟读一次 Graylog 三流日志找漏封；
        # PATROL_ENABLED=false 时任务直接跳过（保留调度不影响其他任务）
        "graylog-patrol": {
            "task": "aegis.run_patrol",
            "schedule": float(settings.patrol_interval_seconds),
            "options": {"queue": "aegis"},
        },
    }
