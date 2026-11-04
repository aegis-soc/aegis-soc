"""Celery Beat 定时计划：到期解封与任务补偿扫描。"""
from __future__ import annotations

from typing import Any


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
    }
