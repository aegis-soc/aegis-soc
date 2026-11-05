"""Pydantic v2 请求 / 响应模型。"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

IocType = Literal["IP", "DOMAIN", "URL", "HASH"]
Operation = Literal["BLOCK", "UNBLOCK", "QUERY"]


class _Out(BaseModel):
    model_config = ConfigDict(from_attributes=True)


# ---------------- 认证 ----------------
class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)


class PasswordChangeIn(BaseModel):
    old_password: str
    new_password: str


class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    must_change_password: bool
    role_code: str


class UserOut(_Out):
    id: int
    username: str
    nickname: str | None = None
    role_code: str
    status: int
    must_change_password: int
    last_login_at: datetime | None = None


# ---------------- 告警 ----------------
class IocCandidate(BaseModel):
    ioc_type: IocType
    value: str
    confidence: float | None = None


class GenericAlertIn(BaseModel):
    alert_id: str | None = None
    title: str | None = None
    source_system: str = "generic"
    severity: str | None = None
    risk_level: str | None = None
    confidence: float | None = None
    src_ips: list[str] = Field(default_factory=list)
    domains: list[str] = Field(default_factory=list)
    payload: dict[str, Any] | None = None


class AlertReceiveOut(BaseModel):
    status: str = "accepted"
    alert_id: str
    duplicated: bool = False
    ioc_count: int = 0
    task_count: int = 0
    message: str | None = None


class AlertOut(_Out):
    id: int
    alert_id: str
    source_system: str
    title: str | None = None
    severity: str | None = None
    risk_level: str | None = None
    confidence: float | None = None
    src_ips: Any = None
    ioc_candidates: Any = None
    status: str
    process_msg: str | None = None
    received_at: datetime


# ---------------- IOC 黑名单 ----------------
class IocCreateIn(BaseModel):
    ioc_type: IocType = "IP"
    ioc_value: str = Field(min_length=1, max_length=512)
    confidence: float | None = Field(default=None, ge=0, le=100)
    risk_level: str | None = None
    expire_at: datetime | None = None
    duration_seconds: int | None = Field(default=None, ge=0, description="为空则永久")
    tags: list[str] = Field(default_factory=list)
    remark: str | None = None
    dispatch: bool = True


class IocUpdateIn(BaseModel):
    confidence: float | None = Field(default=None, ge=0, le=100)
    risk_level: str | None = None
    expire_at: datetime | None = None
    tags: list[str] | None = None
    remark: str | None = None
    status: Literal["active", "disabled", "expired"] | None = None


class IocOut(_Out):
    id: int
    ioc_type: str
    ioc_value: str
    normalized_value: str
    status: str
    confidence: float | None = None
    risk_level: str | None = None
    expire_at: datetime | None = None
    tags: Any = None
    remark: str | None = None
    source_count: int
    created_by: str | None = None
    created_at: datetime


# ---------------- 白名单 ----------------
class WhitelistCreateIn(BaseModel):
    ip_value: str = Field(min_length=1, max_length=64, description="单 IP 或 CIDR，如 198.51.100.0/24")
    remark: str | None = None
    unblock_existing: bool = Field(default=True, description="新增后自动对已下发的黑名单生成解封任务")


class WhitelistImportIn(BaseModel):
    text: str = Field(description="每行一个 IP 或 CIDR，支持 # 注释")


class WhitelistOut(_Out):
    id: int
    ip_value: str
    cidr: str | None = None
    prefix_len: int
    cidr_flag: int
    remark: str | None = None
    status: int
    created_by: str | None = None
    created_at: datetime


class WhitelistCheckOut(BaseModel):
    ip: str
    whitelisted: bool
    matched: str | None = None


# ---------------- 设备与插件 ----------------
class DeviceCreateIn(BaseModel):
    device_code: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=128)
    plugin_code: str = Field(min_length=1, max_length=64)
    vendor: str | None = None
    model: str | None = None
    region: str | None = None
    config_json: dict[str, Any] = Field(default_factory=dict)
    credential_ref: str | None = Field(default=None, description="环境变量名，禁止传明文口令")
    auto_dispatch: bool = True


class DeviceUpdateIn(BaseModel):
    name: str | None = None
    vendor: str | None = None
    model: str | None = None
    region: str | None = None
    config_json: dict[str, Any] | None = None
    credential_ref: str | None = None
    auto_dispatch: bool | None = None
    status: str | None = None


class DeviceOut(_Out):
    id: int
    device_code: str
    name: str
    vendor: str | None = None
    model: str | None = None
    region: str | None = None
    plugin_code: str
    config_json: Any = None
    credential_ref: str | None = None
    capabilities: Any = None
    status: str
    auto_dispatch: int
    last_check_at: datetime | None = None


class PluginOut(_Out):
    id: int | None = None
    plugin_code: str
    plugin_name: str
    version: str | None = None
    manifest: Any = None
    enabled: int = 1
    builtin: int = 1
    description: str | None = None


class PluginTestIn(BaseModel):
    device_id: int | None = None
    plugin_code: str | None = None
    config_json: dict[str, Any] = Field(default_factory=dict)


# ---------------- 策略 ----------------
class PolicyBase(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    enabled: bool = True
    priority: int = 100
    conditions: dict[str, Any] = Field(default_factory=dict)
    threshold_count: int = Field(default=1, ge=1)
    window_minutes: int = Field(default=10, ge=1)
    min_confidence: float = Field(default=0.0, ge=0, le=100)
    risk_levels: list[str] = Field(default_factory=lambda: ["critical", "high", "medium"])
    target_plugins: list[str] = Field(default_factory=list)
    block_duration: int = Field(default=7200, ge=0)
    require_approval: bool = False
    auto_dispatch: bool = True


class PolicyCreateIn(PolicyBase):
    policy_code: str = Field(min_length=1, max_length=64)


class PolicyUpdateIn(BaseModel):
    name: str | None = None
    description: str | None = None
    enabled: bool | None = None
    priority: int | None = None
    conditions: dict[str, Any] | None = None
    threshold_count: int | None = None
    window_minutes: int | None = None
    min_confidence: float | None = None
    risk_levels: list[str] | None = None
    target_plugins: list[str] | None = None
    block_duration: int | None = None
    require_approval: bool | None = None
    auto_dispatch: bool | None = None


class PolicyOut(_Out):
    id: int
    policy_code: str
    name: str
    description: str | None = None
    enabled: int
    priority: int
    conditions: Any = None
    threshold_count: int
    window_minutes: int
    min_confidence: float
    risk_levels: Any = None
    target_plugins: Any = None
    block_duration: int
    require_approval: int
    auto_dispatch: int
    created_at: datetime


# ---------------- 任务 / 审计 / 大盘 ----------------
class TaskOut(_Out):
    id: int
    task_no: str
    ioc_id: int | None = None
    ioc_type: str
    ioc_value: str
    device_id: int
    plugin_code: str
    operation: str
    task_status: str
    retry_count: int
    max_retry: int
    next_retry_at: datetime | None = None
    result_msg: str | None = None
    expire_at: datetime | None = None
    created_at: datetime
    finished_at: datetime | None = None


class TaskLogOut(_Out):
    id: int
    task_id: int
    attempt: int
    request_payload: str | None = None
    response_payload: str | None = None
    http_status: int | None = None
    cost_ms: int | None = None
    success: int
    error_msg: str | None = None
    created_at: datetime


class AuditOut(_Out):
    id: int
    operator: str
    role_code: str | None = None
    op_type: str
    target_type: str | None = None
    target_id: str | None = None
    content: str | None = None
    client_ip: str | None = None
    created_at: datetime


class DashboardOut(BaseModel):
    alerts_today: int
    alerts_total: int
    ioc_active: int
    ioc_expired: int
    whitelist_count: int
    device_online: int
    device_total: int
    task_pending: int
    task_success: int
    task_failed: int
    task_total: int
    kill_switch: bool
    risk_distribution: dict[str, int]
    recent_alerts: list[AlertOut]


class KillSwitchIn(BaseModel):
    enabled: bool
    reason: str | None = None


class SystemStatusOut(BaseModel):
    version: str
    app_env: str
    kill_switch: bool
    task_eager: bool
    database: str
    plugin_count: int
