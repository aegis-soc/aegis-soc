"""SQLAlchemy 2.0 ORM 模型。

20 张表与 sql/init.sql 一一对应。采用「逻辑外键 + 显式索引/唯一约束」，
关联完整性由应用层与幂等唯一键保证，便于后续分库与数据归档。
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import (
    BigInteger,
    DateTime,
    Float,
    Index,
    Integer,
    JSON,
    LargeBinary,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from app.database import Base, utcnow

# SQLite 主键必须为 INTEGER 才能自增；MySQL 下保持 BIGINT
BigIntPK = BigInteger().with_variant(Integer, "sqlite")


class SystemRole(Base):
    __tablename__ = "system_role"

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    role_code: Mapped[str] = mapped_column(String(32), unique=True, nullable=False)
    role_name: Mapped[str] = mapped_column(String(64), nullable=False)
    permission_json: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class SystemUser(Base):
    __tablename__ = "system_user"
    __table_args__ = (Index("idx_role", "role_code"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    nickname: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role_code: Mapped[str] = mapped_column(String(32), nullable=False, default="auditor")
    status: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    must_change_password: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class SecurityEvent(Base):
    __tablename__ = "security_event"
    __table_args__ = (
        UniqueConstraint("source_system", "source_event_id", name="uk_source_event"),
        Index("idx_event_time", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    source_event_id: Mapped[str] = mapped_column(String(128), nullable=False)
    event_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    raw_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class AlertEvent(Base):
    __tablename__ = "alert_event"
    __table_args__ = (
        UniqueConstraint("alert_id", name="uk_alert_id"),
        Index("idx_dedupe_key", "dedupe_key"),
        Index("idx_alert_status", "status"),
        Index("idx_alert_received", "received_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    alert_id: Mapped[str] = mapped_column(String(128), nullable=False)
    source_system: Mapped[str] = mapped_column(String(64), nullable=False, default="graylog")
    source_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    title: Mapped[str | None] = mapped_column(String(255), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(16), nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    src_ips: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    ioc_candidates: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    raw_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="pending")
    dedupe_key: Mapped[str | None] = mapped_column(String(128), nullable=True)
    process_msg: Mapped[str | None] = mapped_column(String(500), nullable=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class IocIndicator(Base):
    """黑名单流水表：**不做同值合并**。

    同一 IP 今天被封、明天再次命中，是两条独立记录（各自有添加时间、
    过期时间、来源告警），因为部分设备不支持按 IP 覆盖式解封，
    只能依赖到期自动失效，必须保留每一次下发的完整上下文。
    """

    __tablename__ = "ioc_indicator"
    __table_args__ = (
        Index("idx_ioc_value", "ioc_type", "normalized_value"),
        Index("idx_ioc_status", "status"),
        Index("idx_ioc_expire", "expire_at"),
        Index("idx_ioc_type", "ioc_type"),
        Index("idx_ioc_source", "source_type"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False)
    normalized_value: Mapped[str] = mapped_column(String(512), nullable=False)
    # active 已下发 / rejected 校验拦截未下发 / whitelisted 白名单豁免
    # / expired 已到期 / disabled 已手动解封
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="active")
    confidence: Mapped[float | None] = mapped_column(Float, nullable=True)
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)
    expire_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    tags: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    remark: Mapped[str | None] = mapped_column(String(500), nullable=True)
    # 来源分类：IPS / WAF / ZTNA / TI / AV / FW / NTA / GRAYLOG / MANUAL / API
    source_type: Mapped[str] = mapped_column(String(24), nullable=False, default="UNKNOWN")
    # 来源原始标识（设备名 / stream / vendor 等），用于回溯到底哪台设备报的
    source_detail: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 关联告警 ID，便于从一条黑名单直接跳到原始告警
    alert_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    # 状态原因：被拦截/豁免的理由，或到期未解封的说明
    reject_reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    source_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class IocIpDetail(Base):
    __tablename__ = "ioc_ip_detail"
    __table_args__ = (
        UniqueConstraint("ioc_id", name="uk_ioc_ip"),
        Index("idx_ip_bin", "ip_bin"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    ip_bin: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    prefix_len: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=32)
    address_family: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=4)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)


class IocDomainDetail(Base):
    __tablename__ = "ioc_domain_detail"
    __table_args__ = (
        UniqueConstraint("ioc_id", name="uk_ioc_domain"),
        Index("idx_root_domain", "root_domain"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    match_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="exact")
    root_domain: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_wildcard: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)


class IocSource(Base):
    __tablename__ = "ioc_source"
    __table_args__ = (
        UniqueConstraint("ioc_id", "source_system", "source_event_id", name="uk_ioc_source"),
        Index("idx_ioc_source_ref", "source_event_id"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    source_system: Mapped[str] = mapped_column(String(64), nullable=False)
    source_event_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    hit_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    raw_ref: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class IocDeviceBinding(Base):
    __tablename__ = "ioc_device_binding"
    __table_args__ = (
        UniqueConstraint("ioc_id", "device_id", name="uk_ioc_device"),
        Index("idx_binding_device", "device_id"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    ioc_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    device_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    last_operation: Mapped[str | None] = mapped_column(String(16), nullable=True)
    last_task_status: Mapped[str | None] = mapped_column(String(24), nullable=True)
    last_task_id: Mapped[int | None] = mapped_column(BigIntPK, nullable=True)
    last_sync_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class IpWhitelist(Base):
    __tablename__ = "ip_whitelist"
    __table_args__ = (
        UniqueConstraint("ip_value", "prefix_len", name="uk_whitelist"),
        Index("idx_wl_ip_bin", "ip_bin"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    ip_value: Mapped[str] = mapped_column(String(64), nullable=False)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    ip_bin: Mapped[bytes] = mapped_column(LargeBinary(16), nullable=False)
    prefix_len: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=32)
    cidr_flag: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    remark: Mapped[str | None] = mapped_column(String(500), nullable=True)
    status: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class SecurityDevice(Base):
    __tablename__ = "security_device"
    __table_args__ = (
        UniqueConstraint("device_code", name="uk_device_code"),
        Index("idx_device_plugin", "plugin_code"),
        Index("idx_device_status", "status"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    device_code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    vendor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    model: Mapped[str | None] = mapped_column(String(64), nullable=True)
    region: Mapped[str | None] = mapped_column(String(64), nullable=True)
    plugin_code: Mapped[str] = mapped_column(String(64), nullable=False)
    config_json: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    credential_ref: Mapped[str | None] = mapped_column(String(128), nullable=True)
    capabilities: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="unknown")
    auto_dispatch: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    last_check_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class DevicePlugin(Base):
    __tablename__ = "device_plugin"
    __table_args__ = (UniqueConstraint("plugin_code", name="uk_plugin_code"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    plugin_code: Mapped[str] = mapped_column(String(64), nullable=False)
    plugin_name: Mapped[str] = mapped_column(String(128), nullable=False)
    version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    manifest: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    enabled: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    builtin: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class DeviceCapability(Base):
    __tablename__ = "device_capability"
    __table_args__ = (
        UniqueConstraint("device_id", "ioc_type", "capability", name="uk_capability"),
        Index("idx_cap_plugin", "plugin_code"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    device_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    plugin_code: Mapped[str] = mapped_column(String(64), nullable=False)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False)
    capability: Mapped[str] = mapped_column(String(16), nullable=False)
    enabled: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)


class AutomationPolicy(Base):
    __tablename__ = "automation_policy"
    __table_args__ = (
        UniqueConstraint("policy_code", name="uk_policy_code"),
        Index("idx_policy_priority", "priority"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    policy_code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(String(500), nullable=True)
    enabled: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)
    conditions: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    threshold_count: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    window_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    min_confidence: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)
    risk_levels: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    target_plugins: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    block_duration: Mapped[int] = mapped_column(Integer, nullable=False, default=7200)
    require_approval: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    auto_dispatch: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)


class PolicyDeviceRel(Base):
    __tablename__ = "policy_device_rel"
    __table_args__ = (UniqueConstraint("policy_id", "device_id", name="uk_policy_device"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    policy_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    device_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)


class WorkflowDefinition(Base):
    __tablename__ = "workflow_definition"
    __table_args__ = (UniqueConstraint("workflow_code", name="uk_workflow_code"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    workflow_code: Mapped[str] = mapped_column(String(64), nullable=False)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    dag_json: Mapped[Any | None] = mapped_column(JSON, nullable=True)
    enabled: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class DeviceTask(Base):
    __tablename__ = "device_task"
    __table_args__ = (
        UniqueConstraint("task_no", name="uk_task_no"),
        UniqueConstraint("ioc_id", "device_id", "operation", "request_id", name="uk_task_idempotent"),
        Index("idx_task_status", "task_status"),
        Index("idx_task_next_retry", "next_retry_at"),
        Index("idx_task_expire", "expire_at"),
        Index("idx_task_ioc", "ioc_id"),
        Index("idx_task_created", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    task_no: Mapped[str] = mapped_column(String(64), nullable=False)
    ioc_id: Mapped[int | None] = mapped_column(BigIntPK, nullable=True)
    ioc_type: Mapped[str] = mapped_column(String(16), nullable=False, default="IP")
    ioc_value: Mapped[str] = mapped_column(String(512), nullable=False)
    device_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    plugin_code: Mapped[str] = mapped_column(String(64), nullable=False)
    operation: Mapped[str] = mapped_column(String(16), nullable=False)
    task_status: Mapped[str] = mapped_column(String(24), nullable=False, default="PENDING")
    retry_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    max_retry: Mapped[int] = mapped_column(Integer, nullable=False, default=3)
    next_retry_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=5)
    request_id: Mapped[str] = mapped_column(String(64), nullable=False)
    result_msg: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    expire_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class DeviceTaskLog(Base):
    __tablename__ = "device_task_log"
    __table_args__ = (Index("idx_tasklog_task", "task_id"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(BigIntPK, nullable=False)
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    request_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_payload: Mapped[str | None] = mapped_column(Text, nullable=True)
    http_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cost_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    success: Mapped[int] = mapped_column(SmallInteger, nullable=False, default=0)
    error_msg: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)


class ApprovalRecord(Base):
    __tablename__ = "approval_record"
    __table_args__ = (Index("idx_approval_status", "status"),)

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    task_id: Mapped[int | None] = mapped_column(BigIntPK, nullable=True)
    ioc_id: Mapped[int | None] = mapped_column(BigIntPK, nullable=True)
    applicant: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approver: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    reason: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    decided_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class OperationAudit(Base):
    __tablename__ = "operation_audit"
    __table_args__ = (
        Index("idx_audit_operator", "operator"),
        Index("idx_audit_type", "op_type"),
        Index("idx_audit_time", "created_at"),
    )

    id: Mapped[int] = mapped_column(BigIntPK, primary_key=True, autoincrement=True)
    operator: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    role_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    op_type: Mapped[str] = mapped_column(String(64), nullable=False)
    target_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    content: Mapped[str | None] = mapped_column(Text, nullable=True)
    client_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
