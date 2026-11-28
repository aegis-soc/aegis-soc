"""LBA 采集器测试：水位增量、重叠去重、小时桶合并、页面读数回退。

MCP 取数层 mock 掉（``patrol._fetch_stream``），只测合并与读数逻辑。
"""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from app.database import SessionLocal
from app.models import LbaCollectState, LbaUserHourly
from app.services import lba, lba_collector


def _norm_rec(username, seen_at, ip="8.8.8.8", url="/api/x", status=200,
              method="GET", domain="oa.xx.com"):
    """构造 _norm_records 出参形状的记录（真实字段由 lba._norm_records 产出）。"""
    return {
        "username": username, "display_name": "张三" if username else "",
        "internal": False, "src_ip": ip, "seen_at": seen_at,
        "url": url, "method": method, "status_code": status,
        "app_id": "", "ua_raw": "Mozilla/5.0 (Windows NT 10.0) Chrome/131.0.0.0",
        "ua_class": "pc", "browser": "chrome", "browser_ver": "131", "os": "windows",
        "domain": domain, "country": "", "city": "", "isp": "",
    }


@pytest.fixture
def db():
    from app.database import Base, engine
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


NOW = datetime(2026, 11, 28, 18, 0, 0)


def test_merge_dedupes_overlapping_batches(db):
    """两轮采集窗口重叠：重复事件不重复计数、不重复入库。"""
    base = NOW - timedelta(minutes=3)
    recs = [_norm_rec("zhang", base + timedelta(seconds=i)) for i in range(5)]
    recs.append(_norm_rec("zhang", base + timedelta(seconds=99), status=401))
    lba_collector.merge_records(db, recs)
    db.flush()
    row = db.query(LbaUserHourly).filter_by(username="zhang").one()
    assert row.requests == 6 and row.fails == 1

    # 第二轮完全重叠 + 1 条新增：重复的不计，新增的计入
    second = recs + [_norm_rec("zhang", base + timedelta(seconds=120), url="/api/new")]
    lba_collector.merge_records(db, second)
    db.flush()
    row = db.query(LbaUserHourly).filter_by(username="zhang").one()
    assert row.requests == 7 and row.fails == 1
    assert len(lba_collector._load_json(row.events, [])) == 7


def test_merge_hour_buckets_and_counters(db):
    """同一用户跨小时分桶；域名/IP/设备明细与失败计数正确合并。"""
    base = NOW.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
    recs = [
        _norm_rec("zhang", base + timedelta(minutes=10), status=401),
        _norm_rec("zhang", base + timedelta(minutes=70), ip="9.9.9.9", domain="mail.xx.com"),
    ]
    lba_collector.merge_records(db, recs)
    db.flush()
    rows = db.query(LbaUserHourly).filter_by(username="zhang").order_by(LbaUserHourly.bucket).all()
    assert len(rows) == 2
    assert rows[0].requests == 1 and rows[0].fails == 1
    assert rows[1].requests == 1 and rows[1].fails == 0
    assert lba_collector._load_json(rows[1].domains, {}).get("mail.xx.com") == 1
    assert "9.9.9.9" in lba_collector._load_json(rows[1].ips, {})
    events = lba_collector._load_json(rows[1].events, [])
    assert events[0]["domain"] == "mail.xx.com"


def test_run_collect_advances_watermark(db, monkeypatch):
    """拉到数据推进水位到最新 seen_at；空轮推进到 now-重叠，窗口不越滚越大。"""
    fetch_calls: list[tuple[datetime, datetime]] = []

    def fake_fetch(client, stream, start, end, limit, cfg=None):
        fetch_calls.append((start, end))
        return ([_norm_rec("zhang", end - timedelta(minutes=1))], {"fetched": 1, "error": ""})

    monkeypatch.setattr(lba_collector.patrol, "_fetch_stream", fake_fetch)
    monkeypatch.setattr(lba_collector.patrol, "load_config", lambda db=None: None)
    monkeypatch.setattr(lba_collector.lba, "_ztna_stream", lambda cfg: {"name": "ztna"})
    monkeypatch.setattr(lba_collector.patrol, "build_client", lambda cfg: None)
    monkeypatch.setattr(lba_collector.lba, "_norm_records", lambda raw, fb: raw)

    r1 = lba_collector.run_collect(db)
    assert r1["fetched"] == 1
    state = db.query(LbaCollectState).filter_by(source_code="ztna").one()
    wm1 = state.watermark

    def fake_empty(client, stream, start, end, limit, cfg=None):
        fetch_calls.append((start, end))
        return ([], {"fetched": 0, "error": ""})

    monkeypatch.setattr(lba_collector.patrol, "_fetch_stream", fake_empty)
    lba_collector.run_collect(db)
    state = db.query(LbaCollectState).filter_by(source_code="ztna").one()
    assert state.watermark >= wm1                # 空轮水位只进不退
    start2, _ = fetch_calls[-1]
    assert start2 < state.watermark              # 起点含重叠窗口


def test_run_collect_marks_error(db, monkeypatch):
    def fake_error(client, stream, start, end, limit, cfg=None):
        return ([], {"fetched": 0, "error": "connection refused"})
    monkeypatch.setattr(lba_collector.patrol, "_fetch_stream", fake_error)
    monkeypatch.setattr(lba_collector.patrol, "load_config", lambda db=None: None)
    monkeypatch.setattr(lba_collector.lba, "_ztna_stream", lambda cfg: {"name": "ztna"})
    monkeypatch.setattr(lba_collector.patrol, "build_client", lambda cfg: None)

    result = lba_collector.run_collect(db)
    assert "connection refused" in result["error"]
    state = db.query(LbaCollectState).filter_by(source_code="ztna").one()
    assert state.last_status == "error"


def test_overview_reads_store_and_falls_back(db, client, auth_headers, monkeypatch):
    """采集器健康 → 读预聚合表；未运行 → 回落实时聚合（不发 MCP 请求）。"""
    from app.database import SessionLocal as _SL
    from app.services import lba_collector as col

    bucket = NOW.replace(minute=0, second=0, microsecond=0)
    row = LbaUserHourly(username="zhang", display_name="张三", bucket=bucket,
                        requests=3, fails=0, last_active=bucket + timedelta(minutes=30))
    row.ips = '{"8.8.8.8": {"first": "%s", "last": "%s", "internal": false, "country": "", "city": "", "isp": ""}}' % (
        (bucket - timedelta(hours=2)).isoformat(sep=" "), (bucket + timedelta(minutes=30)).isoformat(sep=" "))
    row.devices = '{"k1": {"ua_class": "pc", "browser": "chrome", "browser_ver": "131", "ua_raw": "u", "last_active": "%s"}}' % (
        (bucket + timedelta(minutes=30)).isoformat(sep=" "))
    row.domains = '{"oa.xx.com": 3}'
    row.events = '[{"k": "a", "ts": %d, "url": "/x", "domain": "oa.xx.com", "method": "GET", "status_code": 200, "src_ip": "8.8.8.8", "app_id": ""}]' % int(
        (bucket + timedelta(minutes=30)).timestamp() * 1000)
    row.event_keys = '["a"]'
    db.add(row)
    db.add(LbaCollectState(source_code="ztna", last_run_at=NOW, last_status="ok",
                           watermark=NOW, fetched_total=10))
    db.commit()

    # 测试的 NOW 是固定的，页面用真实 utcnow()——把「新鲜度」窗口放宽到覆盖 NOW，
    # 并把页面时钟钉在 NOW，避免真实时间流逝造成窗口错位
    monkeypatch.setattr(lba, "STORE_FRESH_AFTER", timedelta(days=3650))
    monkeypatch.setattr(lba, "utcnow", lambda: NOW)

    resp = client.get("/api/v1/lba/login/overview?range=24h", headers=auth_headers)
    data = resp.json()["data"]
    assert data["window_desc"]["source"] == "store"
    assert data["active_users"] == 1
    assert data["requests_total"] == 3
    assert data["devices_total"] == 1

    # 未运行采集器 → 回落 live（_fetch_window mock 成空，不报错）
    db2 = _SL()
    try:
        state = db2.query(LbaCollectState).filter_by(source_code="ztna").one()
        state.last_status = "error"
        db2.commit()
    finally:
        db2.close()
    monkeypatch.setattr(lba.patrol, "_fetch_stream", lambda *a, **k: ([], {"fetched": 0, "error": ""}))
    resp = client.get("/api/v1/lba/login/overview?range=1h", headers=auth_headers)
    assert resp.json()["data"]["window_desc"]["source"] == "live"


def test_device_payload_tolerates_legacy_store_rows():
    """真机回归：老版本 store 设备 JSON 没有 ips/managed，payload 不再 KeyError。"""
    legacy = {"device_key": "k1", "ua_class": "pc", "browser": "chrome",
              "browser_ver": "131", "ua_raw": "u", "last_active": "2026-11-28 18:00:00"}
    out = lba._device_payload(legacy)
    assert out["ips"] == [] and out["managed"] == "unknown"
    assert out["last_active"] == "2026-11-28 18:00:00"

    # collector 新格式（first_seen/last_seen）与旧 ips 明细（first/last）都兼容
    new = {**legacy, "ips": {"8.8.8.8": {"first_seen": "2026-11-28 17:00:00",
                                         "last_seen": "2026-11-28 18:00:00",
                                         "internal": False, "country": "美国"}}}
    out = lba._device_payload(new)
    assert out["ips"][0]["ip"] == "8.8.8.8" and out["ips"][0]["last_seen"] == "2026-11-28 18:00:00"


def test_merge_stores_device_ips(db):
    """采集器给设备记 IP 明细（用户详情页设备卡片数据源）。"""
    base = NOW - timedelta(minutes=10)
    recs = [_norm_rec("zhang", base, ip="8.8.8.8"),
            _norm_rec("zhang", base + timedelta(minutes=1), ip="9.9.9.9")]
    lba_collector.merge_records(db, recs)
    db.flush()
    row = db.query(LbaUserHourly).filter_by(username="zhang").one()
    devices = lba_collector._load_json(row.devices, {})
    ips = devices["k1"]["ips"] if "k1" in devices else next(iter(devices.values()))["ips"]
    assert set(ips) == {"8.8.8.8", "9.9.9.9"}
    assert ips["8.8.8.8"]["last_seen"] == lba_collector._ts_str(base)


def test_run_collect_backfills_when_truncated(db, monkeypatch):
    """真机回归：单次拉取被截断 → 回溯分页补拉，消除水位缺口（三窗口一样根因）。"""
    from app.services.lba_collector import FETCH_LIMIT

    calls: list[tuple[datetime, datetime]] = []
    newest = NOW - timedelta(minutes=5)
    older = NOW - timedelta(days=3)

    def fake_fetch(client, stream, start, end, limit, cfg=None):
        calls.append((start, end))
        if len(calls) == 1:
            return ([_norm_rec("zhang", newest)], {"fetched": limit, "error": ""})
        return ([_norm_rec("zhang", older)], {"fetched": 1, "error": ""})

    monkeypatch.setattr(lba_collector.patrol, "_fetch_stream", fake_fetch)
    monkeypatch.setattr(lba_collector.patrol, "load_config", lambda db=None: None)
    monkeypatch.setattr(lba_collector.lba, "_ztna_stream", lambda cfg: {"name": "ztna"})
    monkeypatch.setattr(lba_collector.patrol, "build_client", lambda cfg: None)
    monkeypatch.setattr(lba_collector.lba, "_norm_records", lambda raw, fb: raw)

    result = lba_collector.run_collect(db)
    assert len(calls) == 2                       # 第一批截断后回溯了一轮
    assert calls[1][1] == newest - timedelta(seconds=1)   # 第二批从首批最旧时间往前
    assert result["fetched"] == 2
    state = db.query(LbaCollectState).filter_by(source_code="ztna").one()
    assert state.watermark == newest             # 水位仍是最新
    buckets = {r.bucket for r in db.query(LbaUserHourly).all()}
    assert lba_collector._bucket_of(older) in buckets   # 老数据已入库
