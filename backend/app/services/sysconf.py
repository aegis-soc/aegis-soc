"""系统级运行配置：落库的 key/value，页面保存即生效。

目前只有「告警接口来源 IP 白名单」一组，但接口按通用 key/value 设计，
后续要加「是否允许匿名健康检查」「登录失败锁定阈值」这类开关不用再建表。

一个刻意的取舍：**空列表 = 关闭限制**。默认就是空的，所以升级后行为不变；
反过来如果只看开关不看列表，误把开关打开而列表为空就会把所有告警挡在门外，
因此在 :func:`save` 里直接拒绝这种组合。
"""
from __future__ import annotations

import ipaddress
from typing import Iterable

from sqlalchemy.orm import Session

from app.models import SystemSetting

# 允许出现在 system_setting 里的 key（白名单，避免前端塞任意键）
KEY_ALERT_IP_ENFORCE = "alert_ip_enforce"
KEY_ALERT_IP_ALLOWLIST = "alert_ip_allowlist"

DEFAULTS: dict[str, str] = {
    KEY_ALERT_IP_ENFORCE: "0",
    KEY_ALERT_IP_ALLOWLIST: "",
}

Network = ipaddress.IPv4Network | ipaddress.IPv6Network

MAX_ENTRIES = 200


def load(db: Session) -> dict[str, str]:
    """读取全部已知配置，缺的用默认值补齐（老库没这行也能跑）。"""
    data = dict(DEFAULTS)
    rows = db.query(SystemSetting).filter(SystemSetting.skey.in_(list(DEFAULTS))).all()
    for row in rows:
        if row.skey in data:
            data[row.skey] = row.svalue or ""
    return data


def parse_allowlist(raw: str | None) -> list[Network]:
    """把「每行一个 IP/网段」的文本解析成网络列表。

    逗号、分号、空白都当分隔符——用户从表格里粘出来的多半是制表符或换行。
    非法条目直接抛 ``ValueError``，让保存失败而不是静默丢一项：
    少一项目标可能就是把真告警挡在门外。
    """
    entries: list[Network] = []
    seen: set[str] = set()
    for token in (raw or "").replace(";", ",").replace("\t", "\n").replace(" ", "\n").splitlines():
        for item in token.split(","):
            text = item.strip()
            if not text or text.startswith("#"):
                continue
            try:
                network = ipaddress.ip_network(text, strict=False)
            except ValueError:
                raise ValueError(f"不是合法的 IP 或网段：{text}") from None
            key = str(network)
            if key in seen:
                continue
            seen.add(key)
            entries.append(network)
    if len(entries) > MAX_ENTRIES:
        raise ValueError(f"条目过多（{len(entries)} 条），上限 {MAX_ENTRIES} 条")
    return entries


def ip_allowed(ip_text: str, networks: Iterable[Network]) -> bool:
    """来源 IP 是否落在名单内；来源不是合法 IP 一律不放行。"""
    try:
        address = ipaddress.ip_address((ip_text or "").strip())
    except ValueError:
        return False
    return any(address in network for network in networks)


def enabled(data: dict[str, str]) -> bool:
    """开关打开且名单非空才真正生效。"""
    if data.get(KEY_ALERT_IP_ENFORCE) != "1":
        return False
    try:
        return bool(parse_allowlist(data.get(KEY_ALERT_IP_ALLOWLIST)))
    except ValueError:
        # 库里存了脏数据（比如手工 UPDATE 改了表）：宁可放行并留日志，
        # 也不能让告警接入整体不可用。
        return False


def public(db: Session) -> dict:
    data = load(db)
    try:
        entries = [str(item) for item in parse_allowlist(data.get(KEY_ALERT_IP_ALLOWLIST))]
    except ValueError:
        entries = []
    return {
        "alert_ip_enforce": data.get(KEY_ALERT_IP_ENFORCE) == "1",
        "alert_ip_allowlist": data.get(KEY_ALERT_IP_ALLOWLIST, ""),
        "alert_ip_entries": entries,
        "alert_ip_count": len(entries),
    }


def save(db: Session, *, enforce: bool, allowlist: str, operator: str) -> dict:
    """保存两项配置，返回 :func:`public` 同结构。非法输入抛 ``ValueError``。"""
    entries = parse_allowlist(allowlist)
    if enforce and not entries:
        raise ValueError("启用来源限制时必须至少填写一个 IP 或网段")
    normalized = "\n".join(str(item) for item in entries)
    values = {
        KEY_ALERT_IP_ENFORCE: "1" if enforce else "0",
        KEY_ALERT_IP_ALLOWLIST: normalized,
    }
    existing = {row.skey: row for row in db.query(SystemSetting).filter(SystemSetting.skey.in_(values)).all()}
    for key, value in values.items():
        row = existing.get(key)
        if row is None:
            db.add(SystemSetting(skey=key, svalue=value, updated_by=operator))
        else:
            row.svalue = value
            row.updated_by = operator
    db.flush()
    return public(db)


def allowlist_networks(db: Session) -> list[Network]:
    """告警接入用：返回生效的网段列表；未启用时返回空列表（= 不限制）。"""
    data = load(db)
    if not enabled(data):
        return []
    return parse_allowlist(data.get(KEY_ALERT_IP_ALLOWLIST))
