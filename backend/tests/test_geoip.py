"""IP 归属地：解析、降级、写入快照与按国家筛选。

测试不依赖真实的 11 MB xdb 文件：库解析用 `_parse_region` 直接测，
查询链路用 monkeypatch 替换 `geoip.lookup`，这样 CI 上没有数据文件也能跑。
"""
from __future__ import annotations

from app.config import settings
from app.models import IocIndicator
from app.services import geoip
from app.services.geoip import GeoInfo
from app.schemas import IocOut
from tests.conftest import graylog_payload


def _post(client, alert_id: str, ip: str, **fields):
    payload = graylog_payload(alert_id, ip)
    payload["event"]["fields"].update(fields)
    return client.post(
        f"/api/v1/alerts/graylog?secret={settings.graylog_webhook_secret}", json=payload
    )


def _rows(client, headers, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    url = "/api/v1/ioc/ips" + (f"?{query}" if query else "")
    return client.get(url, headers=headers).json()["data"]["items"]


# ---------------------------------------------------------------- 解析纯函数

def test_parse_domestic_region_keeps_chinese():
    info = geoip._parse_region("中国|广东省|深圳市|电信|CN")
    assert info == GeoInfo(country="中国", province="广东省", city="深圳市", isp="电信", iso_code="CN")
    assert info.region == "广东省·深圳市"


def test_parse_foreign_region_maps_country_to_chinese():
    info = geoip._parse_region("United States|California|Los Angeles|Google LLC|US")
    assert info.country == "美国"  # ISO 码映射成中文，省份/城市保留英文原值
    assert info.region == "California·Los Angeles"
    assert info.isp == "Google LLC"


def test_parse_municipality_region_is_deduped():
    info = geoip._parse_region("中国|北京市|北京市|0|CN")
    assert info.region == "北京市"
    assert info.isp is None  # "0" 视为未知


def test_parse_reserved_and_unknown():
    reserved = geoip._parse_region("Reserved|Reserved|Reserved|0|0")
    assert reserved is not None and reserved.country == "保留地址"
    assert reserved.region is None
    assert geoip._parse_region("0|0|0|0|0") is None
    assert geoip._parse_region("") is None


def test_unmapped_country_falls_back_to_original_name():
    info = geoip._parse_region("Atlantis|North|Capital|0|ZZ")
    assert info.country == "Atlantis"


# ---------------------------------------------------------------- 降级行为

def test_missing_db_degrades_to_none(monkeypatch, tmp_path):
    monkeypatch.setattr(geoip, "db_path", lambda: tmp_path / "not-exist.xdb")
    geoip.reset_cache()
    try:
        assert geoip._get_searcher() is None
        assert geoip.lookup("8.8.8.8") is None
        assert geoip.geo_fields("8.8.8.8") == {
            "geo_country": None, "geo_province": None, "geo_city": None, "geo_isp": None,
        }
    finally:
        geoip.reset_cache()


def test_internal_ip_is_marked_as_intranet():
    """内网地址不查库（也无需库文件），直接标「内网」便于识别横向移动。"""
    assert geoip.lookup("10.20.30.40").country == "内网"
    assert geoip.lookup("192.168.1.1").country == "内网"
    assert geoip.lookup("172.16.9.9").country == "内网"


def test_invalid_ip_and_ipv6_return_none():
    # 非法值在解析阶段就被挡掉，不需要库文件；IPv6 当前没有加载 v6 库
    assert geoip.lookup("1.2.3.999") is None
    assert geoip.lookup("2001:db8::1") is None
    assert geoip.lookup("") is None
    assert geoip.lookup(None) is None


# ---------------------------------------------------------------- 写入与查询

def test_alert_writes_geo_snapshot(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        geoip, "lookup",
        lambda value: GeoInfo(country="中国", province="广东省", city="深圳市", isp="电信", iso_code="CN"),
    )
    _post(client, "evt-geo1", "45.9.9.1")

    rows = [r for r in _rows(client, auth_headers) if r["normalized_value"] == "45.9.9.1"]
    assert len(rows) == 1
    row = rows[0]
    assert row["geo_country"] == "中国"
    assert row["geo_region"] == "广东省·深圳市"
    assert row["geo_isp"] == "电信"


def test_rejected_ip_also_gets_geo(client, auth_headers, monkeypatch):
    monkeypatch.setattr(
        geoip, "lookup",
        lambda value: GeoInfo(country="中国", province="北京市", city="北京市", iso_code="CN"),
    )
    _post(client, "evt-geo2", "10.30.40.50")

    rows = [
        r for r in _rows(client, auth_headers, status="rejected")
        if r["normalized_value"] == "10.30.40.50"
    ]
    assert rows and rows[0]["geo_country"] == "中国" and rows[0]["geo_region"] == "北京市"


def test_geo_snapshot_is_frozen_at_write_time(client, auth_headers, monkeypatch):
    """库更新后不应该改写历史记录：写入后换 lookup 结果，旧行保持原值。"""
    monkeypatch.setattr(geoip, "lookup", lambda value: GeoInfo(country="美国", province="California"))
    _post(client, "evt-geo3", "45.9.9.3")

    monkeypatch.setattr(geoip, "lookup", lambda value: GeoInfo(country="加拿大", province="Ontario"))
    rows = [r for r in _rows(client, auth_headers) if r["normalized_value"] == "45.9.9.3"]
    assert rows[0]["geo_country"] == "美国"


def test_filter_by_country_and_keyword(client, auth_headers, monkeypatch):
    mapping = {
        "45.9.9.11": GeoInfo(country="中国", province="广东省", city="深圳市", iso_code="CN"),
        "45.9.9.12": GeoInfo(country="美国", province="California", city="Los Angeles", iso_code="US"),
    }
    monkeypatch.setattr(geoip, "lookup", lambda value: mapping.get(value))
    _post(client, "evt-geo-cn", "45.9.9.11")
    _post(client, "evt-geo-us", "45.9.9.12")

    cn = _rows(client, auth_headers, country="中国")
    assert [r["normalized_value"] for r in cn] == ["45.9.9.11"]

    # keyword 覆盖归属地，方便直接搜「深圳」「美国」
    assert [r["normalized_value"] for r in _rows(client, auth_headers, keyword="深圳")] == ["45.9.9.11"]
    assert [r["normalized_value"] for r in _rows(client, auth_headers, keyword="美国")] == ["45.9.9.12"]

    countries = client.get("/api/v1/ioc/geo/countries", headers=auth_headers).json()["data"]["items"]
    assert {c["country"] for c in countries} == {"中国", "美国"}


def test_geo_region_in_schema():
    row = IocOut(
        id=1, ioc_type="IP", ioc_value="1.1.1.1", normalized_value="1.1.1.1", status="active",
        source_count=1, created_at="2026-11-05T00:00:00",
        geo_country="中国", geo_province="广东省", geo_city="深圳市",
    )
    assert row.geo_region == "广东省·深圳市"
    assert row.model_dump()["geo_region"] == "广东省·深圳市"


def test_manual_create_backfills_geo_on_existing_row(client, auth_headers, monkeypatch):
    """功能上线前写的记录没有归属地，手工再次添加时应补上。"""
    monkeypatch.setattr(geoip, "lookup", lambda value: None)
    body = {"ioc_value": "45.9.9.21", "confidence": 80, "risk_level": "high", "dispatch": False}
    assert client.post("/api/v1/ioc/ips", json=body, headers=auth_headers).status_code == 200

    monkeypatch.setattr(
        geoip, "lookup",
        lambda value: GeoInfo(country="中国", province="浙江省", city="杭州市", iso_code="CN"),
    )
    assert client.post("/api/v1/ioc/ips", json=body, headers=auth_headers).status_code == 200

    rows = [r for r in _rows(client, auth_headers) if r["normalized_value"] == "45.9.9.21"]
    assert len(rows) == 1
    assert rows[0]["geo_country"] == "中国"
    assert rows[0]["geo_region"] == "浙江省·杭州市"
