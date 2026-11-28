"""LBA 采集器（lba-collector）：零信任流 → 用户×小时预聚合落库。

与页面实时聚合（``lba._aggregate``）的关系：
- 采集器由 Beat 每 5 分钟唤醒，按水位增量拉日志、按小时桶合并进
  ``lba_user_hourly``，之后页面读本地表，秒开且不受单次 5000 条截断；
- 页面在采集器未运行/未覆盖时自动回落实时聚合（见 ``lba._collect_users``），
  两条路径产出同构的用户统计，风险口径共用 ``lba._classify_risk``。

增量语义：水位 ``watermark`` = 已合并记录的最大 ``seen_at``；每轮取
``[watermark - OVERLAP, now]``，重叠 2 分钟兜住 Graylog 迟到记录，重叠窗口
内的重复靠 ``event_keys`` 去重（请求计数不会因重叠而虚增）。
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy.orm import Session

from app.database import utcnow
from app.models import LbaCollectState, LbaUserHourly
from app.services import lba, patrol

logger = logging.getLogger("aegis")

OVERLAP = timedelta(minutes=2)     # 两轮采集窗口重叠，兜住迟到/边界重复
EVENTS_CAP = 200                   # 每小时桶时间线事件封顶（超出丢最旧）
KEYS_CAP = 1000                    # 每小时桶去重键封顶
IPS_CAP = 500                      # 每小时桶 IP 明细封顶（TEXT 列 64KB，防撑爆）
DEVICES_CAP = 100                  # 每小时桶设备明细封顶
DEVICE_IPS_CAP = 50                # 单设备 IP 明细封顶
DOMAINS_CAP = 200                  # 每小时桶域名计数封顶
FETCH_LIMIT = lba.FETCH_LIMIT      # 单次拉取上限（与页面实时聚合同口径）
FIRST_BACKFILL = timedelta(days=7)  # 首轮无水位时回填范围
CATCHUP_ROUNDS = 10                # 单轮采集的回溯补拉轮数（被截断时向更早分页）


def _event_key(rec: dict[str, Any]) -> str:
    """事件去重键：时间+身份+动作+目标，同一事件跨轮重复可识别。"""
    raw = "|".join([
        str(int(rec["seen_at"].timestamp() * 1000)), str(rec["username"] or ""),
        rec["method"], rec["url"], rec["src_ip"], str(rec["status_code"]),
    ])
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:32]


def _load_json(text: str | None, default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default


def _bucket_of(seen_at: datetime) -> datetime:
    return seen_at.replace(minute=0, second=0, microsecond=0)


def _ts_str(value: datetime) -> str:
    """JSON 里存的时间统一成 %Y-%m-%d %H:%M:%S 字符串：格式固定，字典序即时间序，
    第二轮合并从 JSON 读回后可直接 min/max 比较（datetime 与 str 混比会崩）。"""
    return value.strftime("%Y-%m-%d %H:%M:%S")


def _cap_by(mapping: dict[str, Any], cap: int) -> dict[str, Any]:
    """dict 明细按「最后活跃时间」倒序保留前 cap 条（ips/devices 用 last，domains 用计数）。"""
    if len(mapping) <= cap:
        return mapping

    def sort_key(item: tuple[str, Any]) -> Any:
        value = item[1]
        if isinstance(value, dict):
            return value.get("last") or value.get("last_active") or ""
        return value          # domains 的 value 是计数

    kept = sorted(mapping.items(), key=sort_key, reverse=True)[:cap]
    return dict(kept)


def _merge_group(db: Session, username: str, bucket: datetime,
                 group: list[dict[str, Any]]) -> None:
    """把同一 (用户, 小时桶) 的记录增量合并进一行。"""
    group.sort(key=lambda r: r["seen_at"])
    row = db.query(LbaUserHourly).filter_by(username=username, bucket=bucket).first()
    if row is None:
        row = LbaUserHourly(username=username, bucket=bucket, last_active=bucket)
        db.add(row)
        db.flush()

    keys = list(_load_json(row.event_keys, []))
    key_set = set(keys)
    events = list(_load_json(row.events, []))
    ips = _load_json(row.ips, {})
    devices = _load_json(row.devices, {})
    domains = _load_json(row.domains, {})

    requests_delta = 0
    fails_delta = 0
    last_active = row.last_active
    for rec in group:
        key = rec.setdefault("_key", _event_key(rec))
        if key in key_set:
            continue                    # 重叠窗口里的重复事件：不计数不重复入库
        key_set.add(key)
        keys.append(key)
        requests_delta += 1
        if rec["status_code"] in (401, 403):
            fails_delta += 1
        events.append({
            "k": key, "ts": lba._ts_ms(rec["seen_at"]), "url": rec["url"],
            "domain": rec["domain"], "method": rec["method"],
            "status_code": rec["status_code"], "src_ip": rec["src_ip"],
            "app_id": rec["app_id"],
        })
        if rec["seen_at"] > last_active:
            last_active = rec["seen_at"]
        if rec["src_ip"]:
            seen = _ts_str(rec["seen_at"])
            entry = ips.setdefault(rec["src_ip"], {
                "first": seen, "last": seen,
                "internal": rec["internal"], "country": rec["country"],
                "city": rec["city"], "isp": rec["isp"]})
            entry["first"] = min(entry["first"], seen)
            entry["last"] = max(entry["last"], seen)
            if not entry.get("country") and rec["country"]:
                entry["country"] = rec["country"]
        dkey = lba.device_key_of(username, rec["ua_class"], rec["browser"], rec["browser_ver"])
        device = devices.setdefault(dkey, {
            "ua_class": rec["ua_class"], "browser": rec["browser"],
            "browser_ver": rec["browser_ver"], "ua_raw": rec["ua_raw"],
            "managed": "unknown", "ips": {},
            "last_active": _ts_str(rec["seen_at"])})
        device["last_active"] = max(device["last_active"], _ts_str(rec["seen_at"]))
        # 设备级 IP 明细：与实时聚合 device["ips"] 同键名（first_seen/last_seen），
        # 用户详情页设备卡片直接复用 _device_payload 渲染
        if rec["src_ip"]:
            seen = _ts_str(rec["seen_at"])
            dip = device["ips"].setdefault(rec["src_ip"], {
                "first_seen": seen, "last_seen": seen,
                "internal": rec["internal"], "country": rec["country"],
                "city": rec["city"], "isp": rec["isp"]})
            dip["first_seen"] = min(dip["first_seen"], seen)
            dip["last_seen"] = max(dip["last_seen"], seen)
            if len(device["ips"]) > DEVICE_IPS_CAP:
                device["ips"] = dict(sorted(
                    device["ips"].items(),
                    key=lambda kv: kv[1]["last_seen"], reverse=True)[:DEVICE_IPS_CAP])
        if rec["domain"]:
            domains[rec["domain"]] = domains.get(rec["domain"], 0) + 1

    if requests_delta == 0:             # 全是重叠重复，只可能推进 last_active
        row.last_active = max(row.last_active, last_active)
        return

    row.requests += requests_delta
    row.fails += fails_delta
    row.events = json.dumps(
        sorted(events, key=lambda e: e["ts"], reverse=True)[:EVENTS_CAP],
        ensure_ascii=False, default=str)
    row.event_keys = json.dumps(keys[-KEYS_CAP:], ensure_ascii=False)
    # 明细列有封顶：TEXT 上限 64KB，重度用户（NAT 出口等）一小时也可能出几百 IP，
    # 超限写入会让整轮采集失败——按最近活跃保留 N 条，聚合层 union 不受影响
    row.ips = json.dumps(_cap_by(ips, IPS_CAP), ensure_ascii=False, default=str)
    row.devices = json.dumps(_cap_by(devices, DEVICES_CAP), ensure_ascii=False, default=str)
    row.domains = json.dumps(_cap_by(domains, DOMAINS_CAP), ensure_ascii=False)
    row.last_active = max(row.last_active, last_active)
    if not row.display_name:
        for rec in group:
            if rec["display_name"]:
                row.display_name = rec["display_name"]
                break


def merge_records(db: Session, records: list[dict[str, Any]]) -> int:
    """归一记录 → 按 (用户, 小时桶) 分组合并；匿名记录跳过。返回合并的用户数。"""
    groups: dict[tuple[str, datetime], list[dict[str, Any]]] = {}
    for rec in records:
        name = rec["username"]
        if name is None:
            continue
        groups.setdefault((name, _bucket_of(rec["seen_at"])), []).append(rec)
    for (username, bucket), group in groups.items():
        _merge_group(db, username, bucket, group)
    db.flush()
    return len({username for username, _ in groups})


def run_collect(db: Session, trigger: str = "cron",
                cfg: Any = None) -> dict[str, Any]:
    """一轮增量采集：拉日志 → 合并落库 → 推进水位。可安全重复执行。"""
    now = utcnow()
    try:
        cfg = cfg or patrol.load_config(db)
        stream = lba._ztna_stream(cfg)
    except Exception as exc:            # 数据源未配置/停用：记状态即可，不算失败
        _mark(db, now, "skipped", str(exc)[:250])
        return {"skipped": str(exc)[:250]}

    client = patrol.build_client(cfg)
    state = db.query(LbaCollectState).filter_by(source_code="ztna").first()
    if state is None:
        state = LbaCollectState(source_code="ztna")
        db.add(state)
        db.flush()
    start = state.watermark or (now - FIRST_BACKFILL)
    fetch_start = start - OVERLAP      # 回退重叠窗口，兜住迟到/边界重复（靠事件键去重）
    end = now

    records, status = patrol._fetch_stream(client, stream, fetch_start, end, FETCH_LIMIT, cfg=cfg)
    if status.get("error"):
        _mark(db, now, "error", f"fetched=0 {status['error']}"[:250])
        return {"error": status["error"][:250]}

    norm = lba._norm_records(records, end)
    users = merge_records(db, norm)

    # 回溯补拉：单次取数达上限即被截断（Graylog 回的是最新一批），老数据出现
    # 「水位缺口」且增量永远不补——预聚合表只覆盖最近几小时，页面 1h/24h/7d
    # 三个窗口一模一样（2026-11-28 真机确认）。被截断时从本批最旧时间往前
    # 分页补拉，单轮最多 CATCHUP_ROUNDS 次，剩余缺口由后续采集轮继续补。
    total_fetched = len(records)
    batch = norm
    rounds = 0
    while status.get("fetched", 0) >= FETCH_LIMIT and rounds < CATCHUP_ROUNDS:
        oldest = min((r["seen_at"] for r in batch), default=None)
        if oldest is None:
            break
        cursor_end = oldest - timedelta(seconds=1)
        if cursor_end <= fetch_start:
            break
        records, status = patrol._fetch_stream(
            client, stream, fetch_start, cursor_end, FETCH_LIMIT, cfg=cfg)
        if status.get("error"):
            logger.warning("LBA 回溯补拉失败（第 %s 轮）：%s", rounds + 1, status["error"])
            break
        batch = lba._norm_records(records, cursor_end)
        merge_records(db, batch)
        total_fetched += len(records)
        rounds += 1

    truncated = total_fetched >= FETCH_LIMIT
    if norm:
        newest = max(r["seen_at"] for r in norm)
        state.watermark = max(state.watermark, newest) if state.watermark else newest
    else:
        # 空轮也推进水位，避免源长时间无日志时扫描窗口越滚越大；
        # 回退 OVERLAP 保证下轮仍覆盖迟到记录
        state.watermark = max(start, end - OVERLAP)
    state.last_run_at = now
    state.last_status = "ok"
    state.fetched_total += total_fetched
    state.last_message = (
        f"fetched={total_fetched} users={users} window={fetch_start:%m-%d %H:%M}~{end:%H:%M}"
        + (f" 回溯{rounds}轮" if rounds else "")
        + ("（仍有缺口，下轮继续补）" if truncated else ""))[:250]
    db.commit()
    return {"fetched": total_fetched, "users": users,
            "watermark": state.watermark.strftime("%Y-%m-%d %H:%M:%S"),
            "truncated": truncated, "trigger": trigger}


def _mark(db: Session, now: datetime, status: str, message: str) -> None:
    state = db.query(LbaCollectState).filter_by(source_code="ztna").first()
    if state is None:
        state = LbaCollectState(source_code="ztna")
        db.add(state)
    state.last_run_at = now
    state.last_status = status
    state.last_message = message[:250]
    db.commit()


def collect_status(db: Session) -> dict[str, Any]:
    """采集器状态（页面 / 诊断用）：水位、最近一轮、覆盖范围。"""
    state = db.query(LbaCollectState).filter_by(source_code="ztna").first()
    rows = db.query(LbaUserHourly).count()
    if state is None:
        return {"configured": False, "source": "ztna", "rows": rows,
                "watermark": "", "last_run_at": "", "last_status": "",
                "last_message": "", "fetched_total": 0}
    return {
        "configured": True, "source": state.source_code, "rows": rows,
        "watermark": state.watermark.strftime("%Y-%m-%d %H:%M:%S") if state.watermark else "",
        "last_run_at": state.last_run_at.strftime("%Y-%m-%d %H:%M:%S") if state.last_run_at else "",
        "last_status": state.last_status or "",
        "last_message": state.last_message or "",
        "fetched_total": state.fetched_total,
    }
