"""LBA 行为分析（v1）测试：UA 派生、设备指纹、风险启发、三接口契约形状。

取数层 mock 掉（``lba._fetch_window``），只测聚合与接口逻辑；MCP 链路本身
由巡检测试覆盖，这里不重复。
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta

import pytest

from app.services import lba


def _rec(username, ip="1.2.3.4", ts=None, ua=None, url="/api/x", status=200,
         method="GET", ua_class="", domain=""):
    ts = ts or datetime(2026, 11, 26, 12, 0, 0)
    return {
        "username": username, "src_ip": ip, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url, "method": method, "status_code": status,
        "ua_raw": ua or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
        "ua_class": ua_class, "dst_domain": domain,
    }


# ---------------------------------------------------------------- 单元
def test_parse_ua_matches_pipeline_vocab():
    assert lba.parse_ua("Mozilla/5.0 (Windows NT 10.0) Chrome/131.0.0.0") == \
        {"browser": "chrome", "browser_ver": "131", "os": "windows"}
    assert lba.parse_ua("Mozilla/5.0 (Windows NT 10.0; x64) Edg/119.0.0.0")["browser"] == "edge"
    assert lba.parse_ua("Mozilla/5.0 (iPhone; CPU iPhone OS 17_1) Version/17.1 Safari/605.1") == \
        {"browser": "safari", "browser_ver": "17", "os": "ios"}
    assert lba.parse_ua("LvmiFeishu/7.0.10 Chrome/108")["browser"] == "feishu"
    assert lba.parse_ua("")["browser"] == "other"


def test_ua_class_of_derives_from_raw_when_missing():
    assert lba.ua_class_of({"ua_class": "pc", "ua_raw": "x"}) == "pc"
    assert lba.ua_class_of({"ua_raw": "iPhone Safari"}) == "mobile"
    assert lba.ua_class_of({"ua_raw": "LvmiFeishu/7.0"}) == "feishu"
    assert lba.ua_class_of({"ua_raw": "Mozilla/5.0 Firefox"}) == "pc"
    assert lba.ua_class_of({}) == "unknown"


def test_device_key_stable_and_identity_sensitive():
    a = lba.device_key_of("lisi", "pc", "chrome", "120")
    b = lba.device_key_of("lisi", "pc", "chrome", "120")
    c = lba.device_key_of("lisi", "mobile", "chrome", "120")
    assert a == b and a != c and len(a) == 40


def test_record_username_anonymous_excluded():
    assert lba._record_username({"username": "lisi"}) == "lisi"
    assert lba._record_username({"username": "-"}) is None
    assert lba._record_username({"username": "anonymous"}) is None
    assert lba._record_username({}) is None


def test_norm_records_time_alias_fallback(monkeypatch):
    """时间列不是 timestamp/ts（如 event_time、自定义映射列）时仍能解析，
    不允许全部记录被兜底成「当前时间」——否则三个时间窗口数据一模一样。"""
    now = datetime(2026, 11, 26, 12, 0, 0)
    rec = _rec("zhang", ts=now - timedelta(hours=3))
    rec.pop("timestamp")
    rec["event_time"] = (now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
    monkeypatch.setattr(lba.geoip, "lookup", lambda ip: None)
    out = lba._norm_records([rec], now)
    seen = out[0]["seen_at"]
    assert seen < now - timedelta(hours=2)        # 解析到了 3 小时前，不是 now 兜底


def test_norm_records_domain_extraction(monkeypatch):
    """时间线需要 dst_domain（零信任网关字段，如 oa.xx.com），走别名表兜底。"""
    now = datetime(2026, 11, 26, 12, 0, 0)
    monkeypatch.setattr(lba.geoip, "lookup", lambda ip: None)
    rec = _rec("zhang", domain="oa.xx.com")
    assert lba._norm_records([rec], now)[0]["domain"] == "oa.xx.com"
    alt = _rec("zhang")
    alt.pop("dst_domain")
    alt["domain"] = "mail.xx.com"                 # 别名兜底：domain 命名也认
    assert lba._norm_records([alt], now)[0]["domain"] == "mail.xx.com"
    assert lba._norm_records([_rec("zhang")], now)[0]["domain"] == ""


def test_classify_risk_thresholds():
    def stats(ip=1, country=1, devices=1, fail=0):
        return {"ip_count_7d": ip, "country_count_7d": country,
                "device_count": devices, "fails_window": fail}
    assert lba._classify_risk(stats()) == "low"
    assert lba._classify_risk(stats(ip=3)) == "medium"
    assert lba._classify_risk(stats(devices=3)) == "medium"
    assert lba._classify_risk(stats(ip=5)) == "high"
    assert lba._classify_risk(stats(country=2)) == "high"
    assert lba._classify_risk(stats(fail=10)) == "high"


def test_is_public_ip():
    assert lba._is_public_ip("8.8.8.8") is True
    assert lba._is_public_ip("10.46.1.5") is False
    assert lba._is_public_ip("172.16.0.9") is False
    assert lba._is_public_ip("192.168.1.1") is False
    assert lba._is_public_ip("172.32.1.1") is True      # 172.16/12 之外是公网
    assert lba._is_public_ip("not-an-ip") is False


def test_aggregate_internal_ip_not_counted(monkeypatch):
    """内网 IP 不参与异常判定（2026-11-26 真机反馈），但轨迹明细保留。"""
    now = datetime(2026, 11, 26, 12, 0, 0)
    recs = [
        _rec("zhang", ip="10.46.1.5", ts=now - timedelta(hours=1)),
        _rec("zhang", ip="10.46.1.6", ts=now - timedelta(hours=2)),
        _rec("zhang", ip="192.168.8.8", ts=now - timedelta(hours=3)),
        _rec("zhang", ip="58.1.2.3", ts=now - timedelta(hours=4)),
        _rec("zhang", ip="58.1.2.3", ts=now - timedelta(hours=5)),
        _rec("zhang", ip="58.1.2.4", ts=now - timedelta(hours=6)),
    ]
    for r in recs:
        r["display_name"] = "张三"
    monkeypatch.setattr(lba, "_fetch_window", lambda *a, **k: recs)
    monkeypatch.setattr(lba.geoip, "lookup", lambda ip: None)
    users, meta = lba._aggregate(None, None, now)
    u = users[0]
    assert u["ip_count_7d"] == 2                 # 只算公网，内网 3 个不计
    assert u["country_count_7d"] == 0
    assert u["risk"] == "low"                    # 内网再多也不触发风险
    assert u["display_name"] == "张三"
    assert len(u["ip_7d"]) == 5                  # 轨迹明细仍保留内网
    assert u["ip_7d"]["10.46.1.5"]["internal"] is True
    assert u["ip_7d"]["58.1.2.3"]["internal"] is False


# ---------------------------------------------------------------- 接口
@pytest.fixture
def lba_users(monkeypatch):
    """7d 窗口聚合结果直接注入，绕过 MCP 取数。"""
    now = datetime(2026, 11, 26, 12, 0, 0)
    users = [
        {"username": "wangwu", "display_name": "", "risk": "high", "device_count": 2, "ip_count_7d": 6,
         "country_count_7d": 2, "fails_window": 0, "requests_window": 10,
         "last_active": now - timedelta(hours=1), "ip_7d": {}, "timeline": [],
         "devices": {"k1": {"device_key": "k1", "ua_class": "pc", "browser": "chrome",
                            "browser_ver": "131", "managed": "unknown", "ua_raw": "u1",
                            "last_active": now, "ips": {}}},
         },
        {"username": "lisi", "display_name": "", "risk": "low", "device_count": 1, "ip_count_7d": 1,
         "country_count_7d": 1, "fails_window": 0, "requests_window": 5,
         "last_active": now, "ip_7d": {}, "timeline": [],
         "devices": {"k2": {"device_key": "k2", "ua_class": "feishu", "browser": "feishu",
                            "browser_ver": "7", "managed": "unknown", "ua_raw": "u2",
                            "last_active": now, "ips": {}}},
         },
    ]
    def fake_aggregate(db=None, cfg=None, now=None, username=None, window=None):
        # 模拟真实聚合的 username 过滤语义；last_active 相对传入的 now，
        # 避免硬编码日期随真实时间流逝变成「24h 不活跃」（时间炸弹）。
        base = now or datetime(2026, 11, 26, 12, 0, 0)
        shifted = []
        for u in users:
            u = dict(u)
            u["last_active"] = (base - timedelta(hours=1)
                                if u["username"] == "wangwu" else base)
            u["devices"] = {k: dict(v, last_active=u["last_active"])
                            for k, v in u["devices"].items()}
            shifted.append(u)
        if username is None:
            return shifted, {"fetched": 2, "records": 2, "data_first_seen": base,
                             "data_last_seen": base}
        return [u for u in shifted if u["username"] == username], {
            "fetched": 1, "records": 1, "data_first_seen": base, "data_last_seen": base}

    monkeypatch.setattr(lba, "_aggregate", fake_aggregate)
    monkeypatch.setattr(lba, "_fetch_window", lambda *a, **k: [])
    return users


def test_overview_contract(client, auth_headers, lba_users):
    resp = client.get("/api/v1/lba/login/overview", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["range"] == "24h"                 # 默认 24h 窗口
    assert data["active_users"] == 2
    assert data["devices_total"] == 2
    assert data["pending_anomaly_users"] == 1
    assert data["high_risk_users"] == 1
    assert data["requests_total"] == 15           # 10 + 5
    desc = data["window_desc"]
    assert desc["window"] == "24h"
    assert desc["fetched"] == 2 and desc["records"] == 2
    assert desc["window_start"] and desc["window_end"]
    assert desc["data_first_seen"] and desc["data_last_seen"]

    # range 参数：1h/7d 各自缓存与窗口
    resp = client.get("/api/v1/lba/login/overview?range=7d", headers=auth_headers)
    assert resp.status_code == 200
    assert resp.json()["data"]["range"] == "7d"
    resp = client.get("/api/v1/lba/login/overview?range=bogus", headers=auth_headers)
    assert resp.status_code == 400


def test_anomaly_users_sort_and_filter(client, auth_headers, lba_users):
    resp = client.get("/api/v1/lba/login/anomaly-users", headers=auth_headers)
    items = resp.json()["data"]["items"]
    assert [i["username"] for i in items] == ["wangwu", "lisi"]   # 风险降序
    high = items[0]
    assert high["device_types"] == ["pc"]
    assert high["pending_events"] == 0            # 事件引擎未落地

    resp = client.get("/api/v1/lba/login/anomaly-users?risk_level=low", headers=auth_headers)
    items = resp.json()["data"]["items"]
    assert [i["username"] for i in items] == ["lisi"]

    resp = client.get("/api/v1/lba/login/anomaly-users?risk_level=bogus", headers=auth_headers)
    assert resp.status_code == 400


def test_profile_contract(client, auth_headers, lba_users):
    resp = client.get("/api/v1/lba/profile/user/lisi", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["username"] == "lisi" and data["risk"] == "low"
    assert data["device_count"] == 1 and data["ip_count_7d"] == 1
    assert data["timeline"] == [] and data["risk_history"] == []
    assert data["devices"][0]["device_key"] == "k2"

    resp = client.get("/api/v1/lba/profile/user/nobody", headers=auth_headers)
    assert resp.status_code == 404


def test_endpoints_require_auth(client):
    assert client.get("/api/v1/lba/login/overview").status_code in (401, 403)
    assert client.get("/api/v1/lba/login/anomaly-users").status_code in (401, 403)
    assert client.get("/api/v1/lba/profile/user/x").status_code in (401, 403)


def test_cached_roundtrip(client, auth_headers, lba_users):
    """缓存命中时不重复聚合：预热后直接改缓存值，接口必须原样返回缓存内容。"""
    client.get("/api/v1/lba/login/overview", headers=auth_headers)
    from app.cache import cache
    assert cache.get("lba:overview:24h") is not None
    raw = json.loads(cache.get("lba:overview:24h"))
    raw["active_users"] = 99999
    cache.set("lba:overview:24h", json.dumps(raw), ex=120)
    second = client.get("/api/v1/lba/login/overview", headers=auth_headers).json()["data"]
    assert second["active_users"] == 99999
