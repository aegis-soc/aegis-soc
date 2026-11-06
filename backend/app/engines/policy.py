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
from app.services import geoip

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


def create_ioc_record(
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
    source_type: str = "UNKNOWN",
    source_detail: str | None = None,
    alert_id: str | None = None,
    status: str = "active",
    reject_reason: str | None = None,
) -> IocIndicator:
    """黑名单流水落库：**同值不合并**。

    同一个 IP 今天被封、明天再次命中，会生成两条独立记录，各自带
    添加时间 / 过期时间 / 来源告警，便于按时间线复盘与排查
    「设备不支持解封只能等过期」造成的记录重叠。
    """
    row = IocIndicator(
        ioc_type=ioc_type,
        ioc_value=validation.normalized,
        normalized_value=validation.normalized,
        status=status,
        confidence=confidence,
        risk_level=risk_level,
        expire_at=expire_at,
        tags=tags or None,
        remark=remark,
        source_type=source_type or "UNKNOWN",
        source_detail=source_detail,
        alert_id=alert_id,
        reject_reason=reject_reason,
        source_count=1,
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

    if source_event_id:
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


def record_rejected_ioc(
    db: Session,
    *,
    ioc_type: str,
    value: str,
    status: str,
    reason: str,
    alert_id: str | None,
    source_type: str,
    source_detail: str | None,
    created_by: str = "system",
    confidence: float | None = None,
    risk_level: str | None = None,
    source_system: str = "graylog",
) -> IocIndicator | None:
    """被拦截的 IOC 同样留痕：status=rejected / whitelisted，不下发任务。

    价值在于「为什么这个攻击 IP 没被封」可以在这张表里直接看到，
    而不是只沉在审计日志里。
    """
    raw = (value or "").strip()
    if not raw:
        return None

    detail_kwargs: dict[str, Any] = {}
    if ioc_type == "IP":
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            # 连 IP 都解析不了（如 1.2.3.999），没有明细可写，只留主表记录
            network = None
        normalized = str(network.network_address) if network else raw
        if network is not None:
            detail_kwargs = {
                "ip_bin": network.network_address.packed.ljust(16, b"\x00"),
                "prefix_len": network.prefixlen,
                "address_family": network.version,
                "cidr": str(network) if "/" in raw else None,
            }
    else:
        normalized = raw.lower().rstrip(".")

    row = IocIndicator(
        ioc_type=ioc_type,
        ioc_value=raw,
        normalized_value=normalized,
        status=status,
        confidence=confidence,
        risk_level=risk_level,
        expire_at=None,
        remark=reason,
        source_type=source_type or "UNKNOWN",
        source_detail=source_detail,
        alert_id=alert_id,
        reject_reason=reason[:255],
        source_count=1,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    if detail_kwargs:
        db.add(IocIpDetail(ioc_id=row.id, **detail_kwargs))
    if alert_id:
        db.add(
            IocSource(
                ioc_id=row.id,
                source_system=source_system,
                source_event_id=alert_id,
                hit_count=1,
                raw_ref=alert_id,
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
    #    被拦截的 IOC 一律写一条 status=rejected/whitelisted 的黑名单记录：
    #    不下发任务，但要能在黑名单列表里看到「为什么这个攻击 IP 没被封」。
    valid: list[tuple[dict[str, Any], Any]] = []
    whitelist_hits: list[str] = []
    rejected_count = 0
    geo_pending: list[int] = []  # 待异步回填归属地的记录 ID

    def flush_geo() -> None:
        """提交后把归属地查询交给后台线程，主流程不等它。"""
        if geo_pending:
            geoip.schedule_fill(geo_pending)
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
                rejected = record_rejected_ioc(
                    db, ioc_type=ioc_type, value=value, status="whitelisted",
                    reason=f"命中白名单 {matched}，豁免封禁",
                    alert_id=parsed.alert_id,
                    source_type=parsed.source_type, source_detail=parsed.source_detail,
                    confidence=parsed.confidence, risk_level=parsed.risk_level,
                )
                rejected_count += 1
                if rejected is not None and ioc_type == "IP":
                    geo_pending.append(rejected.id)
                continue
        check = validate_ioc(ioc_type, value)
        if not check.ok:
            write_audit(
                db, "IOC_REJECTED", target_type=ioc_type, target_id=value,
                content={"reason": check.message, "alert_id": parsed.alert_id}, client_ip=client_ip,
            )
            rejected = record_rejected_ioc(
                db, ioc_type=ioc_type, value=value, status="rejected",
                reason=check.message, alert_id=parsed.alert_id,
                source_type=parsed.source_type, source_detail=parsed.source_detail,
                confidence=parsed.confidence, risk_level=parsed.risk_level,
            )
            rejected_count += 1
            if rejected is not None and ioc_type == "IP":
                geo_pending.append(rejected.id)
            continue
        valid.append((candidate, check))

    if not valid:
        alert.status = "whitelisted" if whitelist_hits else "ignored"
        alert.process_msg = "无可执行 IOC（白名单豁免或校验未通过）"
        write_audit(
            db, "ALERT_NO_ACTION", target_type="alert", target_id=alert.id,
            content={"whitelist_hits": whitelist_hits, "rejected_count": rejected_count},
            client_ip=client_ip,
        )
        db.commit()
        flush_geo()
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
            "ioc_count": 0, "task_count": 0, "rejected_count": rejected_count,
            "message": f"无可执行 IOC，白名单豁免 {len(whitelist_hits)} 个，拦截留痕 {rejected_count} 个",
        }

    # 4) 策略匹配与阈值
    policy = select_policy(db, parsed)
    if policy is None:
        alert.status = "ignored"
        alert.process_msg = "未命中任何启用策略"
        db.commit()
        flush_geo()
        return {
            "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
            "ioc_count": 0, "task_count": 0, "message": "未命中启用策略",
        }
    if not _threshold_reached(db, normalized_primary, policy):
        alert.status = "pending"
        alert.process_msg = f"未达到阈值 {policy.threshold_count} 次/{policy.window_minutes} 分钟"
        db.commit()
        flush_geo()
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
        ioc = create_ioc_record(
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
            source_type=parsed.source_type,
            source_detail=parsed.source_detail,
            alert_id=parsed.alert_id,
        )
        ioc_count += 1
        if ioc_type == "IP":
            geo_pending.append(ioc.id)
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
            "whitelist_hits": whitelist_hits, "rejected_count": rejected_count,
        },
        client_ip=client_ip,
    )
    db.commit()
    flush_geo()

    dispatch_tasks(task_ids)
    return {
        "status": "accepted", "alert_id": parsed.alert_id, "duplicated": False,
        "ioc_count": ioc_count, "task_count": len(task_ids),
        "rejected_count": rejected_count, "message": alert.process_msg,
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
    # 同一 IP 可能有多条流水记录（同值不合并），解封按 IP 去重，避免重复下发
    handled: set[tuple[str, str]] = set()
    for ioc in db.query(IocIndicator).filter(
        IocIndicator.ioc_type == "IP", IocIndicator.status == "active"
    ).all():
        try:
            addr = ipaddress.ip_network(ioc.normalized_value, strict=False).network_address
        except ValueError:
            continue
        if addr.version != network.version or addr not in network:
            continue
        key = (ioc.ioc_type, ioc.normalized_value)
        if key in handled:
            ioc.status = "disabled"
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
            handled.add(key)
            ioc.status = "disabled"

    write_audit(
        db, "WHITELIST_UNBLOCK_EXISTING", operator=operator, target_type="IP",
        target_id=ip_value, content={"task_count": len(task_ids)}, client_ip=client_ip,
    )
    db.commit()
    dispatch_tasks(task_ids)
    return len(task_ids)


def _live_duplicate_exists(
    db: Session, ioc_type: str, normalized_value: str, exclude_ids: set[int]
) -> bool:
    """同一 IP 是否还有别的「仍有效」记录（未到期或永久）。"""
    query = db.query(IocIndicator).filter(
        IocIndicator.ioc_type == ioc_type,
        IocIndicator.normalized_value == normalized_value,
        IocIndicator.status == "active",
    )
    if exclude_ids:
        query = query.filter(IocIndicator.id.notin_(exclude_ids))
    for row in query.all():
        if row.expire_at is None or row.expire_at > utcnow():
            return True
    return False


def expire_iocs_and_unblock(db: Session) -> int:
    """Celery Beat 定时调用：扫描到期 IOC → 生成解封任务 → 标记 expired。

    同值不合并后同一个 IP 可能有多条到期记录，这里按 IP 去重；
    若该 IP 还有更晚到期的记录仍在生效，则只把当前记录置 expired，
    不生成解封任务，避免把后来那条有效封禁一起解掉。
    """
    expired = (
        db.query(IocIndicator)
        .filter(
            IocIndicator.status == "active",
            IocIndicator.expire_at.isnot(None),
            IocIndicator.expire_at <= utcnow(),
        )
        .all()
    )
    if not expired:
        return 0

    grouped: dict[tuple[str, str], list[IocIndicator]] = {}
    for ioc in expired:
        grouped.setdefault((ioc.ioc_type, ioc.normalized_value), []).append(ioc)

    request_id = f"exp-{_new_request_id()}"
    task_ids: list[int] = []
    for (ioc_type, value), rows in grouped.items():
        row_ids = {row.id for row in rows}
        if _live_duplicate_exists(db, ioc_type, value, row_ids):
            for row in rows:
                row.status = "expired"
                row.reject_reason = "到期，但同 IP 仍有生效封禁，未重复下发解封"
            continue
        for device in match_devices(db, ioc_type, "UNBLOCK"):
            task = create_task(
                db, ioc=rows[0], device=device, operation="UNBLOCK", request_id=request_id,
            )
            if task:
                task_ids.append(task.id)
        for row in rows:
            row.status = "expired"

    write_audit(
        db, "IOC_EXPIRE_UNBLOCK", target_type="IOC",
        content={
            "expired_count": len(expired),
            "ioc_values": len(grouped),
            "task_count": len(task_ids),
        },
    )
    db.commit()
    dispatch_tasks(task_ids)
    return len(task_ids)
