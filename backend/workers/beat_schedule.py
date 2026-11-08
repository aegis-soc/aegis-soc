"""Celery Beat 定时计划：到期解封、任务补偿与每日 AI 巡检。"""
from __future__ import annotations

from typing import Any

from celery.schedules import crontab


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
        # 日志巡检：每分钟唤醒一次，真正的间隔由页面配置（默认 300s）决定，
        # 任务内部做「距上轮是否够间隔」的判断——改配置无需重启 Beat
        "graylog-patrol": {
            "task": "aegis.run_patrol",
            "schedule": 60.0,
            "options": {"queue": "aegis"},
        },
    }
