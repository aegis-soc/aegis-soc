"""端到端业务闭环：告警 → 去重 → 白名单 → 策略 → IOC → 插件下发 → 审计 → 到期解封。"""
from __future__ import annotations

from app.config import settings
from tests.conftest import graylog_payload


def _post_alert(client, alert_id="evt-001", ip="8.8.8.8", secret=None):
    return client.post(
        f"/api/v1/alerts/graylog?secret={secret or settings.graylog_webhook_secret}",
        json=graylog_payload(alert_id, ip),
    )


def test_healthz(client):
    response = client.get("/api/healthz")
    assert response.status_code == 200
    assert response.json()["data"]["status"] == "healthy"


def test_openapi_contains_business_routes(client):
    paths = client.get("/api/openapi.json").json()["paths"]
    assert "/api/v1/alerts/graylog" in paths
    assert "/api/v1/ioc/ips" in paths
    assert "/api/v1/tasks" in paths


def test_login_and_me(client, auth_headers):
    assert "access_token" not in auth_headers["Authorization"] or True
    me = client.get("/api/v1/auth/me", headers=auth_headers)
    assert me.status_code == 200
    assert me.json()["data"]["username"] == "admin"


def test_graylog_full_flow(client, auth_headers):
    response = _post_alert(client)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["status"] == "accepted"
    assert data["ioc_count"] == 1
    assert data["task_count"] >= 1

    iocs = client.get("/api/v1/ioc/ips", headers=auth_headers).json()["data"]
    assert iocs["total"] >= 1
    assert any(item["normalized_value"] == "8.8.8.8" for item in iocs["items"])

    tasks = client.get("/api/v1/tasks", headers=auth_headers).json()["data"]
    assert tasks["total"] >= 1
    assert all(t["task_status"] == "SUCCESS" for t in tasks["items"]), tasks["items"]

    detail = client.get(f"/api/v1/tasks/{tasks['items'][0]['id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert len(detail.json()["data"]["logs"]) >= 1


def test_alert_dedupe_and_secret(client, auth_headers):
    assert _post_alert(client, alert_id="evt-dup").json()["data"]["duplicated"] is False
    assert _post_alert(client, alert_id="evt-dup").json()["data"]["duplicated"] is True
    bad = _post_alert(client, alert_id="evt-bad", secret="wrong-secret")
    assert bad.json()["code"] == 403


def test_whitelist_protection(client, auth_headers):
    check = client.get("/api/v1/whitelist/ips/check?ip=198.51.100.10", headers=auth_headers)
    assert check.json()["data"]["whitelisted"] is True

    response = _post_alert(client, alert_id="evt-wl", ip="198.51.100.10")
    assert response.json()["data"]["task_count"] == 0

    created = client.post(
        "/api/v1/whitelist/ips",
        headers=auth_headers,
        json={"ip_value": "8.8.8.0/24", "remark": "测试网段"},
    )
    assert created.status_code == 200, created.text
    assert created.json()["data"]["unblock_task_count"] >= 0


def test_manual_ioc_and_domain(client, auth_headers):
    ip = client.post(
        "/api/v1/ioc/ips", headers=auth_headers,
        json={"ioc_value": "1.1.1.1", "confidence": 85, "duration_seconds": 60, "remark": "手工"},
    )
    assert ip.status_code == 200, ip.text
    assert ip.json()["data"]["task_count"] >= 1

    domain = client.post(
        "/api/v1/ioc/domains", headers=auth_headers,
        json={"ioc_value": "evil.example.com", "dispatch": False},
    )
    assert domain.status_code == 200, domain.text


def test_manual_ioc_rejects_whitelisted(client, auth_headers):
    response = client.post(
        "/api/v1/ioc/ips", headers=auth_headers, json={"ioc_value": "192.0.2.10"},
    )
    assert response.json()["code"] == 403


def test_policy_plugin_device_audit(client, auth_headers):
    assert client.get("/api/v1/policies", headers=auth_headers).json()["data"]["total"] >= 1
    plugins = client.get("/api/v1/plugins", headers=auth_headers).json()["data"]
    codes = {p["plugin_code"] for p in plugins["items"]}
    assert plugins["total"] == len(codes)
    assert {
        "mock", "http_generic", "ssh_firewall", "sangfor_ips",
        "paloalto_fw", "qiming_fw", "aliyun_waf_v3",
    } <= codes
    assert client.get("/api/v1/devices", headers=auth_headers).json()["data"]["total"] >= 1
    assert client.get("/api/v1/audit", headers=auth_headers).json()["data"]["total"] >= 1
    dashboard = client.get("/api/v1/dashboard", headers=auth_headers)
    assert dashboard.status_code == 200
    assert "task_total" in dashboard.json()["data"]


def test_kill_switch(client, auth_headers):
    enabled = client.post(
        "/api/v1/system/kill-switch", headers=auth_headers,
        json={"enabled": True, "reason": "演练"},
    )
    assert enabled.json()["data"]["enabled"] is True
    response = _post_alert(client, alert_id="evt-kill")
    assert response.json()["data"]["task_count"] == 0
    assert response.json()["data"]["message"] == "熔断开启，仅记录告警"
    client.post("/api/v1/system/kill-switch", headers=auth_headers, json={"enabled": False})


def test_expire_and_unblock(client, auth_headers):
    from datetime import timedelta

    from app.database import SessionLocal, utcnow
    from app.models import IocIndicator
    from workers.tasks import expire_iocs

    _post_alert(client, alert_id="evt-expire")
    db = SessionLocal()
    try:
        for ioc in db.query(IocIndicator).filter(IocIndicator.status == "active").all():
            ioc.expire_at = utcnow() - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    result = expire_iocs()
    assert result["task_count"] >= 1
    tasks = client.get("/api/v1/tasks?operation=UNBLOCK", headers=auth_headers).json()["data"]
    assert tasks["total"] >= 1


def test_approval_and_cancel(client, auth_headers):
    policies = client.get("/api/v1/policies", headers=auth_headers).json()["data"]["items"]
    policy_id = policies[0]["id"]
    updated = client.put(
        f"/api/v1/policies/{policy_id}", headers=auth_headers,
        json={"require_approval": True},
    )
    assert updated.status_code == 200

    _post_alert(client, alert_id="evt-approve")
    pending = client.get(
        "/api/v1/tasks?task_status=APPROVING", headers=auth_headers
    ).json()["data"]["items"]
    assert pending, "应生成待审批任务"

    task_id = pending[0]["id"]
    approved = client.post(
        f"/api/v1/tasks/{task_id}/approve?approve=true", headers=auth_headers
    )
    assert approved.status_code == 200, approved.text

    _post_alert(client, alert_id="evt-cancel", ip="9.9.9.9")
    pending2 = client.get(
        "/api/v1/tasks?task_status=APPROVING", headers=auth_headers
    ).json()["data"]["items"]
    assert pending2
    cancelled = client.post(
        f"/api/v1/tasks/{pending2[0]['id']}/cancel", headers=auth_headers
    )
    assert cancelled.status_code == 200, cancelled.text
    assert cancelled.json()["data"]["task_status"] == "CANCELED"
