"""首次启动自举：幂等补齐角色、插件、示例设备、默认策略与初始管理员。

生产（MySQL）由 sql/init.sql + sql/seed.sql 初始化，本模块只补管理员并兜底；
SQLite / 单元测试环境则通过 ORM 全量建表与播种，保证两端行为一致。
管理员口令不在 SQL 中硬编码，由 BOOTSTRAP_ADMIN_PASSWORD 生成 bcrypt 哈希，
并强制首次登录改密。
"""
from __future__ import annotations

import ipaddress
import logging
import time
from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

from app.config import settings
from app.database import SessionLocal, init_db
from app.models import (
    AutomationPolicy,
    DeviceCapability,
    DevicePlugin,
    IpWhitelist,
    PolicyDeviceRel,
    SecurityDevice,
    SystemRole,
    SystemUser,
)
from app.security import hash_password

logger = logging.getLogger("aegis")

ROLES: list[dict[str, Any]] = [
    {
        "role_code": "admin",
        "role_name": "系统管理员",
        "permission_json": ["*"],
        "description": "全部权限，含用户管理与系统设置",
    },
    {
        "role_code": "operator",
        "role_name": "安全运营",
        "permission_json": [
            "alert:*", "ioc:*", "whitelist:*", "device:*", "plugin:*",
            "policy:*", "task:*", "audit:read", "dashboard:read",
            "inspection:read", "inspection:run",
        ],
        "description": "日常告警处置、IOC 与策略管理",
    },
    {
        "role_code": "auditor",
        "role_name": "只读审计员",
        "permission_json": [
            "alert:read", "ioc:read", "whitelist:read", "device:read", "plugin:read",
            "policy:read", "task:read", "audit:read", "dashboard:read",
            "inspection:read",
        ],
        "description": "仅查看，禁止任何写操作",
    },
]

DEMO_WHITELIST = [
    ("192.0.2.0", "192.0.2.0/24", "RFC5737 示例网段：演示 CIDR 白名单包含检查"),
    ("198.51.100.10", None, "RFC5737 示例地址：演示单 IP 白名单豁免"),
]


def _ip_bin(value: str) -> tuple[bytes, int, bool]:
    network = ipaddress.ip_network(value, strict=False)
    return network.network_address.packed.ljust(16, b"\x00"), network.prefixlen, "/" in value


def _wait_for_tables(max_retries: int = 30, interval: float = 2.0) -> None:
    for attempt in range(1, max_retries + 1):
        try:
            with SessionLocal() as db:
                db.execute(text("SELECT 1 FROM system_role LIMIT 1"))
            return
        except Exception as exc:
            logger.warning("等待数据库就绪 (%s/%s): %s", attempt, max_retries, exc.__class__.__name__)
            time.sleep(interval)
    raise RuntimeError("数据库在限定时间内未就绪，请检查 MySQL 容器与 sql/init.sql 挂载")


def _get_or_create(db: Session, model: type, *, lookup: dict[str, Any], defaults: dict[str, Any]) -> Any:
    row = db.query(model).filter_by(**lookup).first()
    if row is not None:
        return row
    row = model(**{**lookup, **defaults})
    db.add(row)
    db.flush()
    return row


def _plugin_manifests() -> list[dict[str, Any]]:
    """从插件注册表读取 Manifest；插件包未就绪时静默跳过（由后续启动补齐）。"""
    try:
        from plugins.registry import list_manifests

        return list_manifests()
    except Exception as exc:  # pragma: no cover
        logger.warning("插件注册表暂不可用: %s", exc)
        return []


def _seed_plugins(db: Session) -> None:
    for item in _plugin_manifests():
        _get_or_create(
            db,
            DevicePlugin,
            lookup={"plugin_code": item["plugin_code"]},
            defaults={
                "plugin_name": item.get("plugin_name", item["plugin_code"]),
                "version": item.get("version", "1.0.0"),
                "manifest": item.get("manifest", {}),
                "enabled": 1,
                "builtin": 1,
                "description": item.get("description"),
            },
        )


def _seed_device_and_policy(db: Session) -> None:
    device = _get_or_create(
        db,
        SecurityDevice,
        lookup={"device_code": "mock-device-01"},
        defaults={
            "name": "演示设备（Mock）",
            "vendor": "AegisSoc",
            "model": "mock",
            "region": "lab",
            "plugin_code": "mock",
            "config_json": {"mode": "log"},
            "credential_ref": None,
            "capabilities": [
                {"ioc_type": "IP", "capability": "BLOCK"},
                {"ioc_type": "IP", "capability": "UNBLOCK"},
                {"ioc_type": "DOMAIN", "capability": "BLOCK"},
            ],
            "status": "online",
            "auto_dispatch": 1,
        },
    )
    for ioc_type, capability in [
        ("IP", "BLOCK"), ("IP", "UNBLOCK"), ("IP", "QUERY"), ("DOMAIN", "BLOCK")
    ]:
        _get_or_create(
            db,
            DeviceCapability,
            lookup={"device_id": device.id, "ioc_type": ioc_type, "capability": capability},
            defaults={"plugin_code": "mock", "enabled": 1},
        )

    policy = _get_or_create(
        db,
        AutomationPolicy,
        lookup={"policy_code": "default-auto-block"},
        defaults={
            "name": "默认自动封禁",
            "description": "Graylog 高危告警命中后自动封禁 2 小时；白名单与内网地址强制豁免",
            "enabled": 1,
            "priority": 100,
            "conditions": {},
            "threshold_count": 1,
            "window_minutes": 10,
            "min_confidence": 60.0,
            "risk_levels": ["critical", "high", "medium"],
            "target_plugins": [],
            "block_duration": 7200,
            "require_approval": 0,
            "auto_dispatch": 1,
        },
    )
    _get_or_create(
        db,
        PolicyDeviceRel,
        lookup={"policy_id": policy.id, "device_id": device.id},
        defaults={},
    )


def _seed_whitelist(db: Session) -> None:
    for ip_value, cidr, remark in DEMO_WHITELIST:
        packed, prefix_len, is_cidr = _ip_bin(cidr or ip_value)
        _get_or_create(
            db,
            IpWhitelist,
            lookup={"ip_value": ip_value, "prefix_len": prefix_len},
            defaults={
                "cidr": cidr,
                "ip_bin": packed,
                "cidr_flag": 1 if is_cidr else 0,
                "remark": remark,
                "status": 1,
                "created_by": "system",
            },
        )


def _seed_admin(db: Session) -> None:
    _get_or_create(
        db,
        SystemUser,
        lookup={"username": "admin"},
        defaults={
            "password_hash": hash_password(settings.bootstrap_admin_password),
            "nickname": "系统管理员",
            "role_code": "admin",
            "status": 1,
            "must_change_password": 1,
        },
    )


def run_bootstrap() -> None:
    if settings.is_sqlite:
        init_db()
    else:
        _wait_for_tables()

    with SessionLocal() as db:
        for role in ROLES:
            _get_or_create(
                db, SystemRole, lookup={"role_code": role["role_code"]},
                defaults={k: v for k, v in role.items() if k != "role_code"},
            )
        _seed_plugins(db)
        _seed_device_and_policy(db)
        _seed_whitelist(db)
        _seed_admin(db)
        db.commit()
    logger.info("bootstrap 完成（环境：%s）", settings.app_env)
