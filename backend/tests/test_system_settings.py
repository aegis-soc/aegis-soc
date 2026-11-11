"""系统设置：告警接口来源 IP 白名单。

重点验三件事：默认不改变行为、名单按 nginx 传入的 X-Real-IP 判定、
脏输入在保存阶段就被挡住（而不是写进库让告警接入整体失效）。
"""
from __future__ import annotations

from app.config import settings
from app.services import sysconf
from tests.conftest import graylog_payload


def _post_alert(client, source: str | None = None, ip: str = "8.8.8.8"):
    headers = {"X-Real-IP": source} if source else {}
    return client.post(
        f"/api/v1/alerts/graylog?secret={settings.graylog_webhook_secret}",
        json=graylog_payload("evt-src", ip),
        headers=headers,
    )


def _save_guard(client, auth_headers, enforce: bool, allowlist: str):
    return client.put(
        "/api/v1/system/settings",
        headers=auth_headers,
        json={"alert_ip_enforce": enforce, "alert_ip_allowlist": allowlist},
    )


def test_settings_default_off(client, auth_headers):
    response = client.get("/api/v1/system/settings", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["alert_ip_enforce"] is False
    assert data["alert_ip_count"] == 0
    assert data["alert_ip_allowlist"] == ""


def test_default_allows_any_source(client):
    assert _post_alert(client, source="203.0.113.9").json()["code"] == 0


def test_parse_allowlist_accepts_common_separators():
    networks = sysconf.parse_allowlist("10.0.0.1, 10.0.1.0/24\n\n10.0.0.1\t192.168.1.0/24")
    assert [str(item) for item in networks] == ["10.0.0.1/32", "10.0.1.0/24", "192.168.1.0/24"]


def test_parse_allowlist_rejects_garbage():
    try:
        sysconf.parse_allowlist("10.0.0.1\nnot-an-ip")
    except ValueError as exc:
        assert "not-an-ip" in str(exc)
    else:  # pragma: no cover
        raise AssertionError("非法条目应报错")


def test_save_rejects_invalid_entry(client, auth_headers):
    response = _save_guard(client, auth_headers, True, "10.0.0.1\n10.0.0.999")
    assert response.status_code == 400
    assert "10.0.0.999" in response.json()["msg"]


def test_enforce_requires_entries(client, auth_headers):
    response = _save_guard(client, auth_headers, True, "")
    assert response.status_code == 400
    assert "至少填写一个" in response.json()["msg"]


def test_enforce_blocks_unknown_source(client, auth_headers):
    saved = _save_guard(client, auth_headers, True, "10.32.239.10\n10.46.0.0/16")
    assert saved.status_code == 200
    data = saved.json()["data"]
    assert data["alert_ip_enforce"] is True
    assert data["alert_ip_count"] == 2

    blocked = _post_alert(client, source="203.0.113.9")
    assert blocked.status_code == 403
    assert "白名单" in blocked.json()["msg"]

    allowed = _post_alert(client, source="10.46.7.8")
    assert allowed.status_code == 200
    assert allowed.json()["code"] == 0


def test_enforce_off_keeps_list_but_stops_blocking(client, auth_headers):
    _save_guard(client, auth_headers, True, "10.46.0.0/16")
    assert _post_alert(client, source="203.0.113.9").status_code == 403

    _save_guard(client, auth_headers, False, "10.46.0.0/16")
    assert _post_alert(client, source="203.0.113.9").status_code == 200

    data = client.get("/api/v1/system/settings", headers=auth_headers).json()["data"]
    assert data["alert_ip_count"] == 1


def test_unauthenticated_cannot_change_settings(client, auth_headers):
    response = client.put(
        "/api/v1/system/settings",
        json={"alert_ip_enforce": True, "alert_ip_allowlist": "10.0.0.0/8"},
    )
    assert response.status_code == 401


def test_client_spoofed_forwarded_for_ignored(client, auth_headers):
    """直连对端不是私网地址时，X-Forwarded-For 不能顶替真实来源。"""
    _save_guard(client, auth_headers, True, "10.46.0.0/16")
    response = client.post(
        f"/api/v1/alerts/graylog?secret={settings.graylog_webhook_secret}",
        json=graylog_payload("evt-spoof", "8.8.8.8"),
        headers={"X-Forwarded-For": "10.46.1.1"},
    )
    # TestClient 的对端是 "testclient"（本机链路），此时按设计信任 X-Real-IP；
    # 这里没带 X-Real-IP，取到的就是 testclient，不在名单内 → 拒绝
    assert response.status_code == 403
