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
         method="GET", ua_class=""):
    ts = ts or datetime(2026, 11, 26, 12, 0, 0)
    return {
        "username": username, "src_ip": ip, "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "url": url, "method": method, "status_code": status,
        "ua_raw": ua or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
        "ua_class": ua_class,
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


def test_classify_risk_thresholds():
    def stats(ip=1, country=1, devices=1, fail=0):
        return {"ip_count_7d": ip, "country_count_7d": country,
                "device_count": devices, "fail_24h": fail}
    assert lba._classify_risk(stats()) == "low"
    assert lba._classify_risk(stats(ip=3)) == "medium"
    assert lba._classify_risk(stats(devices=3)) == "medium"
    assert lba._classify_risk(stats(ip=5)) == "high"
    assert lba._classify_risk(stats(country=2)) == "high"
    assert lba._classify_risk(stats(fail=10)) == "high"


# ---------------------------------------------------------------- 接口
@pytest.fixture
def lba_users(monkeypatch):
    """7d 窗口聚合结果直接注入，绕过 MCP 取数。"""
    now = datetime(2026, 11, 26, 12, 0, 0)
    users = [
        {"username": "wangwu", "risk": "high", "device_count": 2, "ip_count_7d": 6,
         "country_count_7d": 2, "fail_24h": 0, "requests_24h": 10,
         "last_active": now - timedelta(hours=1), "ip_7d": {}, "timeline": [],
         "devices": {"k1": {"device_key": "k1", "ua_class": "pc", "browser": "chrome",
                            "browser_ver": "131", "managed": "unknown", "ua_raw": "u1",
                            "last_active": now, "ips": {}}},
         },
        {"username": "lisi", "risk": "low", "device_count": 1, "ip_count_7d": 1,
         "country_count_7d": 1, "fail_24h": 0, "requests_24h": 5,
         "last_active": now, "ip_7d": {}, "timeline": [],
         "devices": {"k2": {"device_key": "k2", "ua_class": "feishu", "browser": "feishu",
                            "browser_ver": "7", "managed": "unknown", "ua_raw": "u2",
                            "last_active": now, "ips": {}}},
         },
    ]
    def fake_aggregate(db=None, cfg=None, now=None, username=None):
        # 模拟真实聚合的 username 过滤语义
        if username is None:
            return list(users)
        return [u for u in users if u["username"] == username]

    monkeypatch.setattr(lba, "_aggregate", fake_aggregate)
    monkeypatch.setattr(lba, "_fetch_window", lambda *a, **k: [])
    return users


def test_overview_contract(client, auth_headers, lba_users):
    resp = client.get("/api/v1/lba/login/overview", headers=auth_headers)
    assert resp.status_code == 200
    data = resp.json()["data"]
    assert data["active_users_24h"] == 2          # 两人最近 24h 都活跃
    assert data["devices_total"] == 2
    assert data["pending_anomaly_users"] == 1
    assert data["high_risk_users"] == 1
    assert data["window_desc"] == {"ip_change_days": 7}


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
    assert cache.get("lba:overview") is not None
    raw = json.loads(cache.get("lba:overview"))
    raw["active_users_24h"] = 99999
    cache.set("lba:overview", json.dumps(raw), ex=120)
    second = client.get("/api/v1/lba/login/overview", headers=auth_headers).json()["data"]
    assert second["active_users_24h"] == 99999
