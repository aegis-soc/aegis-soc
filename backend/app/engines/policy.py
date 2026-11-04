"""策略引擎：告警处置主链路。

Graylog/通用告警 → 去重 → 熔断 → 白名单优先 → 校验 → 策略匹配 → 阈值
→ IOC 入库 → 设备能力匹配 → 幂等任务 → 异步派发 → 全链路审计。
"""
from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from datetime import timedelta
from typing import Any

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.cache import cache
from app.common import BizError
from app.config import settings
from app.database import utcnow
from app.engines.validation import check_whitelist, match_devices, validate_ioc
from app.models import (
    AlertEvent,
    ApprovalRecord,
    AutomationPolicy,
    DeviceTask,
    IocDeviceBinding,
    IocDomainDetail,
    IocIndicator,
    IocIpDetail,
    IocSource,
)
from app.services.audit import write_audit

logger = logging.getLogger("aegis")

TERMINAL_STATUS = {"SUCCESS", "CANCELED", "REJECTED"}


def _new_request_id() -> str:
    return uuid.uuid4().hex[:24]


def _new_task_no() -> str:
    return f"T{utcnow().strftime('%Y%m%d%H%M%S')}{uuid.uuid4().hex[:8]}"


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            return list(parsed) if isinstance(parsed, list) else [parsed]
        except json.JSONDecodeError:
            return [value]
    return [value]


def _match_conditions(conditions: dict[str, Any] | None, parsed: Any) -> bool:
    if not conditions:
        return True
    mapping = {
        "severity": getattr(parsed, "severity", None),
        "risk_level": getattr(parsed, "risk_level", None),
        "source_system": getattr(parsed, "source_system", None),
    }
    for key, expected in conditions.items():
        if key not in mapping:
            continue
        actual = mapping[key]
        allowed = expected if isinstance(expected, list) else [expected]
        if actual not in [str(x).lower() for x in allowed]:
            return False
    return True


def select_policy(db: Session, parsed: Any) -> AutomationPolicy | None:
    policies = (
        db.query(AutomationPolicy)
        .filter(AutomationPolicy.enabled == 1)
        .order_by(AutomationPolicy.priority.asc(), AutomationPolicy.id.asc())
        .all()
    )
    for policy in policies:
        confidence = parsed.confidence if parsed.confidence is not None else 80.0
        if confidence < float(policy.min_confidence or 0):
            continue
        levels = [str(x).lower() for x in _as_list(policy.risk_levels)]
        if levels and (parsed.risk_level or "").lower() not in levels:
            continue
        if not _match_conditions(policy.conditions, parsed):
            continue
        return policy
    return None


def _threshold_reached(db: Session, normalized: str, policy: AutomationPolicy) -> bool:
    window_start = utcnow() - timedelta(minutes=policy.window_minutes or 10)
    count = (
        db.query(func.count(AlertEvent.id))
        .filter(AlertEvent.dedupe_key == normalized, AlertEvent.received_at >= window_start)
        .scalar()
        or 0
    )
    return count >= (policy.threshold_count or 1)


def upsert_ioc(
    db: Session,
    *,
    ioc_type: str,
    validation: Any,
    confidence: float | None,
    risk_level: str | None,
    expire_at: Any,
    tags: list[str] | None,
    remark: str | None,
    created_by: str,
    source_system: str,
    source_event_id: str | None,
) -> IocIndicator:
    row = (
        db.query(IocIndicator)
        .filter(
            IocIndicator.ioc_type == ioc_type,
            IocIndicator.normalized_value == validation.normalized,
        )
        .first()
    )
    if row is None:
        row = IocIndicator(
            ioc_type=ioc_type,
            ioc_value=validation.normalized,
            normalized_value=validation.normalized,
            source_count=0,
            created_by=created_by,
        )
        db.add(row)
        db.flush()
        if ioc_type == "IP":
            db.add(
                IocIpDetail(
                    ioc_id=row.id,
                    ip_bin=validation.ip_bin,
                    prefix_len=validation.prefix_len,
                    address_family=validation.address_family,
                    cidr=validation.cidr,
                )
            )
        elif ioc_type == "DOMAIN":
            db.add(
                IocDomainDetail(
                    ioc_id=row.id,
                    match_mode=validation.match_mode,
                    root_domain=validation.root_domain,
                    is_wildcard=1 if validation.is_wildcard else 0,
                )
            )

    row.status = "active"
    if confidence is not None:
        row.confidence = max(float(row.confidence or 0), float(confidence))
    if risk_level:
        row.risk_level = risk_level
    if expire_at is not None:
        row.expire_at = max(row.expire_at, expire_at) if row.expire_at else expire_at
    if tags:
        merged = set(_as_list(row.tags)) | set(tags)
        row.tags = sorted(merged)
    if remark:
        row.remark = remark
    row.source_count = (row.source_count or 0) + 1

    existing_source = (
        db.query(IocSource)
        .filter(
            IocSource.ioc_id == row.id,
            IocSource.source_system == source_system,
            IocSource.source_event_id == source_event_id,
        )
        .first()
    )
    if existing_source:
        existing_source.hit_count = (existing_source.hit_count or 0) + 1
        existing_source.last_seen_at = utcnow()
    else:
        db.add(
            IocSource(
                ioc_id=row.id,
                source_system=source_system,
                source_event_id=source_event_id,
                hit_count=1,
                raw_ref=source_event_id,
            )
        )
    db.flush()
    return row


def create_task(
    db: Session,
    *,
    ioc: IocIndicator,
    device: Any,
    operation: str,
    request_id: str,
    expire_at: Any = None,
    require_approval: bool = False,
) -> DeviceTask | None:
    duplicate = (
        db.query(DeviceTask)
        .filter(
            DeviceTask.ioc_id == ioc.id,
            DeviceTask.device_id == device.id,
            DeviceTask.operation == operation,
            DeviceTask.request_id == request_id,
        )
        .first()
    )
    if duplicate is not None:
        return None

    task = DeviceTask(
        task_no=_new_task_no(),
        ioc_id=ioc.id,
        ioc_type=ioc.ioc_type,
        ioc_value=ioc.normalized_value,
        device_id=device.id,
        plugin_code=device.plugin_code,
        operation=operation,
        task_status="APPROVING" if require_approval else "PENDING",
        max_retry=settings.task_max_retry,
        request_id=request_id,
        expire_at=expire_at,
    )
    db.add(task)
    db.flush()

    binding = (
        db.query(IocDeviceBinding)
        .filter(IocDeviceBinding.ioc_id == ioc.id, IocDeviceBinding.device_id == device.id)
        .first()
    )
    if binding is None:
        binding = IocDeviceBinding(ioc_id=ioc.id, device_id=device.id)
        db.add(binding)
    binding.last_operation = operation
    binding.last_task_status = task.task_status
    binding.last_task_id = task.id
    binding.last_sync_at = utcnow()

    if require_approval:
        db.add(
            ApprovalRecord(
                task_id=task.id,
                ioc_id=ioc.id,
                applicant="system",
                status="PENDING",
                reason="高危封禁需人工审批",
            )
        )
    db.flush()
    return task


def dispatch_tasks(task_ids: list[int]) -> None:
    """按 TASK_EAGER 决定同步执行（本地/测试）或投递 Celery（生产）。"""
    if not task_ids:
        return
    if settings.task_eager:
        from workers.tasks import execute_task

        for task_id in task_ids:
            try:
                execute_task(task_id)
            except Exception as exc:  # pragma: no cover - 单任务失败不影响告警响应
                logger.exception("同步执行任务 %s 失败: %s", task_id, exc)
        return

    from workers.celery_app import celery_app

    for task_id in task_ids:
        try:
            celery_app.send_task("aegis.execute_task", args=[task_id], queue="aegis")
        except Exception as exc:  # pragma: no cover - broker 故障时保留 PENDING 由 Beat 补扫
            logger.warning("任务 %s 投递失败（将保留 PENDING 由补偿扫描执行）: %s", task_id, exc)


def process_alert(
    db: Session,
    parsed: Any,
    *,
    operator: str = "system",
    client_ip: str | None = None,
) -> dict[str, Any]:
    # 1) 告警去重：DB 唯一键 + Redis 短窗口，双保险
    if db.query(AlertEvent).filter(AlertEvent.alert_id == parsed.alert_id).first():
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": True,
            "ioc_count": 0, "task_count": 0, "message": "重复告警已忽略",
        }
    if not cache.set_nx(f"aegis:alert:{parsed.alert_id}", ex=settings.alert_dedupe_ttl):
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": True,
            "ioc_count": 0, "task_count": 0, "message": "重复告警已忽略（去重窗口内）",
        }

    candidates = parsed.ioc_candidates or []
    primary = str(candidates[0].get("value")) if candidates else ""
    normalized_primary = ""
    try:
        normalized_primary = str(ipaddress.ip_network(primary, strict=False).network_address)
    except ValueError:
        normalized_primary = primary.lower()

    alert = AlertEvent(
        alert_id=parsed.alert_id,
        source_system=parsed.source_system,
        source_event_id=getattr(parsed, "source_event_id", None),
        title=parsed.title,
        severity=parsed.severity,
        risk_level=parsed.risk_level,
        confidence=parsed.confidence,
        src_ips=parsed.src_ips,
        ioc_candidates=candidates,
        raw_payload=parsed.raw_payload,
        dedupe_key=normalized_primary or None,
        status="pending",
    )
    db.add(alert)
    db.flush()

    # 2) 全局熔断：只留痕，不产生任何封禁任务
    if cache.kill_switch:
        alert.status = "ignored"
        alert.process_msg = "全局自动封禁熔断已开启，告警仅留痕"
        write_audit(
            db, "ALERT_KILL_SWITCH", target_type="alert", target_id=alert.id,
            content={"alert_id": parsed.alert_id}, client_ip=client_ip,
        )
        db.commit()
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
            "ioc_count": 0, "task_count": 0, "message": "熔断开启，仅记录告警",
        }

    # 3) 白名单优先 + IOC 合法性校验（硬性边界）
    #    白名单检查必须早于 IP 合法性校验：受保护地址（含内网/文档地址）
    #    应先命中白名单并留下 WHITELIST_HIT 审计，而不是被泛化成「非法 IP」。
    valid: list[tuple[dict[str, Any], Any]] = []
    whitelist_hits: list[str] = []
    for candidate in candidates:
        ioc_type = str(candidate.get("ioc_type", "IP")).upper()
        value = str(candidate.get("value", ""))
        if ioc_type == "IP":
            try:
                addr = ipaddress.ip_network(value.strip(), strict=False).network_address
                hit, matched = check_whitelist(db, str(addr))
            except ValueError:
                hit, matched = False, None
            if hit:
                whitelist_hits.append(value)
                write_audit(
                    db, "WHITELIST_HIT", target_type="IP", target_id=value,
                    content={"matched": matched, "alert_id": parsed.alert_id, "action": "豁免封禁"},
                    client_ip=client_ip,
                )
                continue
        check = validate_ioc(ioc_type, value)
        if not check.ok:
            write_audit(
                db, "IOC_REJECTED", target_type=ioc_type, target_id=value,
                content={"reason": check.message, "alert_id": parsed.alert_id}, client_ip=client_ip,
            )
            continue
        valid.append((candidate, check))

    if not valid:
        alert.status = "whitelisted" if whitelist_hits else "ignored"
        alert.process_msg = "无可执行 IOC（白名单豁免或校验未通过）"
        write_audit(
            db, "ALERT_NO_ACTION", target_type="alert", target_id=alert.id,
            content={"whitelist_hits": whitelist_hits}, client_ip=client_ip,
        )
        db.commit()
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
            "ioc_count": 0, "task_count": 0,
            "message": f"无可执行 IOC，白名单豁免 {len(whitelist_hits)} 个",
        }

    # 4) 策略匹配与阈值
    policy = select_policy(db, parsed)
    if policy is None:
        alert.status = "ignored"
        alert.process_msg = "未命中任何启用策略"
        db.commit()
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
            "ioc_count": 0, "task_count": 0, "message": "未命中启用策略",
        }
    if not _threshold_reached(db, normalized_primary, policy):
        alert.status = "pending"
        alert.process_msg = f"未达到阈值 {policy.threshold_count} 次/{policy.window_minutes} 分钟"
        db.commit()
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
            "ioc_count": 0, "task_count": 0, "message": alert.process_msg,
        }

    duration = policy.block_duration or settings.default_block_duration
    expire_at = utcnow() + timedelta(seconds=duration) if duration > 0 else None
    target_plugins = _as_list(policy.target_plugins) or []
    request_id = _new_request_id()
    task_ids: list[int] = []
    ioc_count = 0

    for candidate, check in valid:
        ioc_type = str(candidate.get("ioc_type", "IP")).upper()
        ioc = upsert_ioc(
            db,
            ioc_type=ioc_type,
            validation=check,
            confidence=candidate.get("confidence") or parsed.confidence,
            risk_level=parsed.risk_level,
            expire_at=expire_at,
            tags=None,
            remark=f"由告警 {parsed.alert_id} 自动创建",
            created_by=operator,
            source_system=parsed.source_system,
            source_event_id=parsed.alert_id,
        )
        ioc_count += 1
        devices = match_devices(db, ioc_type, "BLOCK", target_plugins)
        for device in devices:
            task = create_task(
                db,
                ioc=ioc,
                device=device,
                operation="BLOCK",
                request_id=request_id,
                expire_at=expire_at,
                require_approval=bool(policy.require_approval),
            )
            if task is not None and task.task_status == "PENDING":
                task_ids.append(task.id)

    alert.status = "processed"
    alert.process_msg = f"命中策略 {policy.policy_code}，生成 {len(task_ids)} 个任务"
    write_audit(
        db, "ALERT_PROCESSED", operator=operator, target_type="alert", target_id=alert.id,
        content={
            "alert_id": parsed.alert_id, "policy": policy.policy_code,
            "ioc_count": ioc_count, "task_count": len(task_ids),
            "whitelist_hits": whitelist_hits,
        },
        client_ip=client_ip,
    )
    db.commit()

    dispatch_tasks(task_ids)
    return {
        "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
        "ioc_count": ioc_count, "task_count": len(task_ids), "message": alert.process_msg,
    }


def create_block_tasks_for_ioc(
    db: Session,
    ioc: IocIndicator,
    *,
    operator: str = "system",
    client_ip: str | None = None,
) -> list[int]:
    """手动新增黑名单 / 手动重试时，按能力矩阵生成封禁任务。"""
    request_id = _new_request_id()
    task_ids: list[int] = []
    for device in match_devices(db, ioc.ioc_type, "BLOCK"):
        task = create_task(
            db, ioc=ioc, device=device, operation="BLOCK",
            request_id=request_id, expire_at=ioc.expire_at,
        )
        if task:
            task_ids.append(task.id)
    write_audit(
        db, "IOC_MANUAL_DISPATCH", operator=operator, target_type=ioc.ioc_type,
        target_id=ioc.id, content={"ioc_value": ioc.normalized_value, "task_count": len(task_ids)},
        client_ip=client_ip,
    )
    db.commit()
    dispatch_tasks(task_ids)
    return task_ids


def unblock_existing_for_whitelist(
    db: Session,
    ip_value: str,
    *,
    operator: str = "system",
    client_ip: str | None = None,
) -> int:
    """白名单新增后：对网段内已下发的黑名单生成解封任务（文档硬性约束）。"""
    try:
        network = ipaddress.ip_network(ip_value, strict=False)
    except ValueError:
        raise BizError(f"非法白名单网段: {ip_value}")

    request_id = f"wl-{_new_request_id()}"
    task_ids: list[int] = []
    for ioc in db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "active"
    ).all():
        try:
            addr = ipaddress.ip_network(ioc.normalized_value, strict=False).network_address
        except ValueError:
            continue
        if addr.version != network.version or addr not in network:
            continue
        ioc_task_ids: list[int] = []
        for device in match_devices(db, "IP", "UNBLOCK"):
            task = create_task(
                db, ioc=ioc, device=device, operation="UNBLOCK", request_id=request_id,
            )
            if task:
                ioc_task_ids.append(task.id)
                task_ids.append(task.id)
        if ioc_task_ids:
            ioc.status = "disabled"

    write_audit(
        db, "WHITELIST_UNBLOCK_EXISTING", operator=operator, target_type="IP",
        target_id=ip_value, content={"task_count": len(task_ids)}, client_ip=client_ip,
    )
    db.commit()
    dispatch_tasks(task_ids)
    return len(task_ids)


def expire_iocs_and_unblock(db: Session) -> int:
    """Celery Beat 定时调用：扫描到期 IOC → 生成解封任务 → 标记 expired。"""
    expired = (
        db.query(IocIndicator)
        .filter(
            IocIndicator.status == "active",
            IocIndicator.expire_at.isnot(None),
            IocIndicator.expire_at <= utcnow(),
        )
        .all()
    )
    request_id = f"exp-{_new_request_id()}"
    task_ids: list[int] = []
    for ioc in expired:
        for device in match_devices(db, ioc.ioc_type, "UNBLOCK"):
            task = create_task(
                db, ioc=ioc, device=device, operation="UNBLOCK", request_id=request_id,
            )
            if task:
                task_ids.append(task.id)
        ioc.status = "expired"
    if expired:
        write_audit(
            db, "IOC_EXPIRE_UNBLOCK", target_type="IOC",
            content={"expired_count": len(expired), "task_count": len(task_ids)},
        )
        db.commit()
        dispatch_tasks(task_ids)
    return len(task_ids)
