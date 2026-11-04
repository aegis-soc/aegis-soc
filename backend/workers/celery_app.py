"""Celery 应用配置。"""
from __future__ import annotations

from celery import Celery

from app.config import settings
from workers.beat_schedule import build_beat_schedule

celery_app = Celery(
    "aegis",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=["workers.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    result_serializer="json",
    accept_content=["json"],
    timezone="Asia/Shanghai",
    enable_utc=True,
    task_acks_late=True,
    task_reject_on_worker_lost=True,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    task_always_eager=settings.task_eager,
    task_eager_propagates=False,
    task_default_queue="aegis",
    task_routes={"aegis.*": {"queue": "aegis"}},
    beat_schedule=build_beat_schedule(),
)
