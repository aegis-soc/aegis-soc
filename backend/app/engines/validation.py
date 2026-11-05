"""IOC 校验、白名单优先检查与设备能力匹配（文档硬性安全边界）。"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import dataclass
from typing import Any

from sqlalchemy.orm import Session

from app.models import DeviceCapability, IpWhitelist, SecurityDevice

# 最大允许 /16 网段：避免 /8 等大网段误封整个业务网段
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 64

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:\*\.)?(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$",
    re.IGNORECASE,
)
IP_KEYS = {
    "src_ip", "source_ip", "attack_ip", "attacker_ip", "client_ip", "src", "ip",
    "source.address", "source_ip_addr", "remote_ip", "alert_src_ip", "srcip",
}
EXCLUDE_KEYS = {"dst_ip", "dest_ip", "destination_ip", "target_ip", "dip", "server_ip"}
DOMAIN_KEYS = {"domain", "hostname", "host", "url_domain", "fqdn", "dns_name"}

IPV4_CANDIDATE_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")


@dataclass
class IocValidation:
    ok: bool
    message: str = ""
    normalized: str = ""
    ip_bin: bytes = b""
    prefix_len: int = 0
    address_family: int = 4
    cidr: str | None = None
    match_mode: str = "exact"
    root_domain: str | None = None
    is_wildcard: bool = False


def _reject(addr: ipaddress._BaseAddress) -> str | None:
    if addr.is_unspecified:
        return "未指定地址禁止封禁"
    if addr.is_loopback:
        return "环回地址禁止封禁"
    if addr.is_link_local:
        return "链路本地地址禁止封禁"
    if addr.is_multicast:
        return "组播地址禁止封禁"
    if addr.is_reserved:
        return "保留地址禁止封禁"
    if addr.is_private:
        return "内网/私有地址禁止封禁（含 RFC5737 文档地址）"
    return None


def normalize_domain(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if value.startswith("http://") or value.startswith("https://"):
        value = value.split("://", 1)[1].split("/", 1)[0]
    return value


def validate_ioc(ioc_type: str, value: str) -> IocValidation:
    """返回归一化结果与二进制表示；不合法（内网/保留/大网段等）直接拒绝。"""
    raw = (value or "").strip()
    if not raw:
        return IocValidation(False, "IOC 值不能为空")

    if ioc_type == "IP":
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            return IocValidation(False, f"非法 IP 或 CIDR: {raw}")
        addr = network.network_address
        reason = _reject(addr)
        if reason:
            return IocValidation(False, f"{reason}: {raw}")
        min_prefix = MIN_IPV4_PREFIX if addr.version == 4 else MIN_IPV6_PREFIX
        if network.prefixlen < min_prefix:
            return IocValidation(False, f"网段过大（最大允许 /{min_prefix}）: {raw}")
        normalized = str(addr) if "/" not in raw else str(network)
        return IocValidation(
            ok=True,
            normalized=normalized,
            ip_bin=addr.packed.ljust(16, b"\x00"),
            prefix_len=network.prefixlen,
            address_family=addr.version,
            cidr=str(network) if "/" in raw else None,
        )

    if ioc_type == "DOMAIN":
        normalized = normalize_domain(raw)
        is_wildcard = normalized.startswith("*.")
        check_value = normalized[2:] if is_wildcard else normalized
        if not DOMAIN_RE.match(check_value):
            return IocValidation(False, f"非法域名: {raw}")
        labels = check_value.split(".")
        root = ".".join(labels[-2:]) if len(labels) >= 2 else check_value
        return IocValidation(
            ok=True,
            normalized=normalized,
            match_mode="wildcard" if is_wildcard else "subdomain",
            root_domain=root,
            is_wildcard=is_wildcard,
        )

    return IocValidation(False, f"v1.0 暂不支持 IOC 类型: {ioc_type}")


def check_whitelist(db: Session, ip_value: str) -> tuple[bool, str | None]:
    """白名单优先：命中返回 (True, 匹配条目)；支持单 IP 与 CIDR 段包含。"""
    try:
        candidate = ipaddress.ip_address(ip_value.strip())
    except ValueError:
        return False, None
    rows = db.query(IpWhitelist).filter(IpWhitelist.status == 1).all()
    for row in rows:
        try:
            network = ipaddress.ip_network(f"{row.ip_value}/{row.prefix_len}", strict=False)
        except ValueError:
            continue
        if network.version == candidate.version and candidate in network:
            return True, row.cidr or f"{row.ip_value}/{row.prefix_len}"
    return False, None


def match_devices(
    db: Session,
    ioc_type: str,
    capability: str = "BLOCK",
    target_plugins: list[str] | None = None,
) -> list[SecurityDevice]:
    """只把任务下发给声明了对应 (ioc_type, capability) 且允许自动下发的设备。"""
    query = db.query(SecurityDevice).filter(
        SecurityDevice.auto_dispatch == 1,
        SecurityDevice.status != "disabled",
    )
    if target_plugins:
        query = query.filter(SecurityDevice.plugin_code.in_(target_plugins))
    candidates = query.all()
    if not candidates:
        return []
    device_ids = [d.id for d in candidates]
    caps = (
        db.query(DeviceCapability)
        .filter(
            DeviceCapability.device_id.in_(device_ids),
            DeviceCapability.ioc_type == ioc_type,
            DeviceCapability.capability == capability,
            DeviceCapability.enabled == 1,
        )
        .all()
    )
    allowed = {c.device_id for c in caps}
    return [d for d in candidates if d.id in allowed]


def apply_credential(config: dict[str, Any], ref: str | None = None) -> dict[str, Any]:
    """把 credential_ref 指向的环境变量合并进配置。

    供两处复用：设备执行前解析，以及界面在「保存设备之前」点测试连接。
    变量值为 JSON 对象则逐键合并，否则整体当作 password；变量缺失不抛异常，
    只写入 `_credential_missing`，由插件统一转成「凭据环境变量 XXX 未设置」。
    """
    merged: dict[str, Any] = dict(config or {})
    name = (ref or merged.pop("credential_ref", "") or "").strip()
    if not name:
        return merged
    secret = os.getenv(name)
    if secret:
        try:
            parsed = json.loads(secret)
            if isinstance(parsed, dict):
                merged.update(parsed)
            else:
                merged["password"] = str(parsed)
        except json.JSONDecodeError:
            merged["password"] = secret
    else:
        merged["_credential_missing"] = name
    return merged


def resolve_device_config(device: SecurityDevice) -> dict[str, Any]:
    """合并插件配置与凭据引用；凭据只从环境变量读取，绝不落库、绝不写日志。"""
    return apply_credential(dict(device.config_json or {}), device.credential_ref)
