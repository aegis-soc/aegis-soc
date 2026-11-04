"""异步任务执行：下发、指数退避重试、状态回写、请求/响应留痕、到期解封。"""
from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

from app.cache import cache
from app.config import settings
from app.database import SessionLocal, utcnow
from app.engines.policy import expire_iocs_and_unblock
from app.engines.validation import resolve_device_config
from app.models import DeviceTask, DeviceTaskLog, IocDeviceBinding, SecurityDevice
from plugins import registry
from workers.celery_app import celery_app

logger = logging.getLogger("aegis")
TERMINAL = {"SUCCESS", "CANCELED", "REJECTED"}


def _safe_request_payload(task: DeviceTask, plugin_code: str) -> str:
    """审计留痕只记录动作与指标，绝不写入设备配置、口令或凭据。"""
    return json.dumps(
        {
            "task_no": task.task_no,
            "operation": task.operation,
            "plugin": plugin_code,
            "ioc_type": task.ioc_type,
            "ioc_value": task.ioc_value,
        },
        ensure_ascii=False,
    )


@celery_app.task(name="aegis.execute_task")
def execute_task(task_id: int) -> dict[str, Any]:
    db = SessionLocal()
    try:
        task = db.get(DeviceTask, task_id)
        if task is None:
            return {"skipped": "task not found"}
        if task.task_status in TERMINAL or task.task_status == "RUNNING":
            return {"skipped": f"status={task.task_status}"}

        lock_key = f"aegis:task:run:{task_id}"
        if not cache.set_nx(lock_key, ex=300):
            return {"skipped": "already running"}

        device = db.get(SecurityDevice, task.device_id)
        if device is None:
            task.task_status = "FAILED"
            task.result_msg = "设备记录不存在"
            task.finished_at = utcnow()
            db.commit()
            return {"success": False, "message": task.result_msg}

        config = resolve_device_config(device)
        result = registry.execute(task.plugin_code, task.operation, task.ioc_value, task.ioc_type, config)

        task.task_status = "RUNNING"
        task.started_at = task.started_at or utcnow()
        db.flush()

        db.add(
            DeviceTaskLog(
                task_id=task.id,
                attempt=(task.retry_count or 0) + 1,
                request_payload=_safe_request_payload(task, task.plugin_code),
                response_payload=(result.raw or "")[:60000],
                http_status=result.http_status,
                cost_ms=None,
                success=1 if result.success else 0,
                error_msg=None if result.success else result.message[:1000],
            )
        )

        if result.success:
            task.task_status = "SUCCESS"
            task.result_msg = result.message[:1000]
            task.finished_at = utcnow()
        elif (task.retry_count or 0) < (task.max_retry or 0) and not settings.task_eager:
            task.retry_count = (task.retry_count or 0) + 1
            delay = settings.task_retry_backoff * (2 ** (task.retry_count - 1))
            task.task_status = "RETRY"
            task.next_retry_at = utcnow() + timedelta(seconds=delay)
            task.result_msg = f"第 {task.retry_count} 次失败，{delay}s 后重试: {result.message}"[:1000]
            celery_app.send_task(
                "aegis.execute_task", args=[task_id], countdown=delay, queue="aegis"
            )
        else:
            task.task_status = "FAILED"
            task.finished_at = utcnow()
            task.result_msg = result.message[:1000]

        binding = (
            db.query(IocDeviceBinding)
            .filter(
                IocDeviceBinding.ioc_id == task.ioc_id,
                IocDeviceBinding.device_id == task.device_id,
            )
            .first()
        )
        if binding:
            binding.last_operation = task.operation
            binding.last_task_status = task.task_status
            binding.last_task_id = task.id
            binding.last_sync_at = utcnow()

        db.commit()
        cache.delete(lock_key)
        return {"success": result.success, "task_status": task.task_status, "message": result.message}
    except Exception as exc:  # noqa: BLE001 - worker 不允许因单任务异常退出
        logger.exception("任务 %s 执行异常", task_id)
        db.rollback()
        try:
            task = db.get(DeviceTask, task_id)
            if task and task.task_status not in TERMINAL:
                task.task_status = "FAILED"
                task.result_msg = f"执行异常: {exc}"[:1000]
                task.finished_at = utcnow()
                db.commit()
        except Exception:
            logger.exception("回写任务失败状态时再次异常")
        return {"success": False, "message": str(exc)}
    finally:
        db.close()


@celery_app.task(name="aegis.expire_iocs")
def expire_iocs() -> dict[str, Any]:
    db = SessionLocal()
    try:
        count = expire_iocs_and_unblock(db)
        return {"task_count": count}
    finally:
        db.close()


@celery_app.task(name="aegis.compensate_pending")
def compensate_pending() -> dict[str, Any]:
    """补偿扫描：broker 抖动导致 PENDING 任务未投递时重新入队。"""
    if settings.task_eager:
        return {"skipped": "eager mode"}
    db = SessionLocal()
    try:
        now = utcnow()
        tasks = (
            db.query(DeviceTask)
            .filter(
                DeviceTask.task_status.in_(["PENDING", "RETRY"]),
                (DeviceTask.next_retry_at.is_(None)) | (DeviceTask.next_retry_at <= now),
            )
            .limit(200)
            .all()
        )
        redispatched = 0
        for task in tasks:
            if cache.set_nx(f"aegis:task:compensate:{task.id}", ex=180):
                celery_app.send_task("aegis.execute_task", args=[task.id], queue="aegis")
                redispatched += 1
        return {"scanned": len(tasks), "redispatched": redispatched}
    finally:
        db.close()
