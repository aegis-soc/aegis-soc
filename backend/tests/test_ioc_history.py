"""黑名单流水表：同值不合并、被拦截留痕、来源识别、解封去重。"""
from __future__ import annotations

from datetime import timedelta

from app.config import settings
from app.database import SessionLocal, utcnow
from app.engines.policy import expire_iocs_and_unblock
from app.models import DeviceTask, IocIndicator
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


def _for_ip(items, ip):
    return [item for item in items if item["normalized_value"] == ip]


def test_same_ip_is_not_merged(client, auth_headers):
    assert _post(client, "evt-h1", "45.9.8.7").json()["data"]["ioc_count"] == 1
    assert _post(client, "evt-h2", "45.9.8.7").json()["data"]["ioc_count"] == 1

    rows = _for_ip(_rows(client, auth_headers), "45.9.8.7")
    assert len(rows) == 2
    assert {row["alert_id"] for row in rows} == {"evt-h1", "evt-h2"}
    assert all(row["status"] == "active" for row in rows)
    assert all(row["created_at"] for row in rows)


def test_private_ip_is_recorded_as_rejected(client, auth_headers):
    data = _post(client, "evt-private", "10.1.2.3").json()["data"]
    assert data["ioc_count"] == 0
    assert data["task_count"] == 0
    assert data["rejected_count"] == 1

    rows = _for_ip(_rows(client, auth_headers, status="rejected"), "10.1.2.3")
    assert len(rows) == 1
    assert rows[0]["status"] == "rejected"
    assert "内网" in rows[0]["reject_reason"]
    assert rows[0]["expire_at"] is None


def test_whitelisted_ip_is_recorded(client, auth_headers):
    data = _post(client, "evt-wl2", "198.51.100.10").json()["data"]
    assert data["task_count"] == 0
    assert data["rejected_count"] == 1

    rows = _for_ip(_rows(client, auth_headers, status="whitelisted"), "198.51.100.10")
    assert rows and "白名单" in rows[0]["reject_reason"]


def test_rejected_rows_have_no_tasks(client, auth_headers):
    _post(client, "evt-private2", "172.16.9.9")
    with SessionLocal() as db:
        assert db.query(DeviceTask).filter(DeviceTask.ioc_value == "172.16.9.9").count() == 0


def test_source_classification(client, auth_headers):
    cases = [
        ("evt-src-waf", "45.9.8.11", {"device_type": "WAF"}, "WAF"),
        ("evt-src-ztna", "45.9.8.12", {"stream": "零信任网关"}, "ZTNA"),
        ("evt-src-ti", "45.9.8.13", {"vendor": "微步在线威胁情报"}, "TI"),
        ("evt-src-ips", "45.9.8.14", {"log_source": "天清IPS"}, "IPS"),
    ]
    for alert_id, ip, fields, expected in cases:
        assert _post(client, alert_id, ip, **fields).json()["data"]["ioc_count"] == 1
        row = _for_ip(_rows(client, auth_headers), ip)[0]
        assert row["source_type"] == expected, row
        assert row["source_detail"]


def test_expire_unblocks_once_per_ip(client, auth_headers):
    _post(client, "evt-exp1", "45.9.8.21")
    _post(client, "evt-exp2", "45.9.8.21")
    with SessionLocal() as db:
        rows = db.query(IocIndicator).filter(IocIndicator.normalized_value == "45.9.8.21").all()
        assert len(rows) == 2
        for row in rows:
            row.expire_at = utcnow() - timedelta(minutes=5)
        db.commit()

    with SessionLocal() as db:
        task_count = expire_iocs_and_unblock(db)

    with SessionLocal() as db:
        unblock_rows = (
            db.query(DeviceTask)
            .filter(DeviceTask.ioc_value == "45.9.8.21", DeviceTask.operation == "UNBLOCK")
            .all()
        )
        assert len(unblock_rows) == task_count
        # 两台记录同一 IP，只按设备数下发一次解封
        assert len({task.device_id for task in unblock_rows}) == task_count
        statuses = {
            row.status
            for row in db.query(IocIndicator).filter(IocIndicator.normalized_value == "45.9.8.21")
        }
        assert statuses == {"expired"}


def test_expire_skips_when_duplicate_still_live(client, auth_headers):
    _post(client, "evt-live1", "45.9.8.31")
    _post(client, "evt-live2", "45.9.8.31")
    with SessionLocal() as db:
        rows = (
            db.query(IocIndicator)
            .filter(IocIndicator.normalized_value == "45.9.8.31")
            .order_by(IocIndicator.id)
            .all()
        )
        rows[0].expire_at = utcnow() - timedelta(minutes=5)
        rows[1].expire_at = utcnow() + timedelta(hours=6)
        db.commit()

    with SessionLocal() as db:
        assert expire_iocs_and_unblock(db) == 0

    with SessionLocal() as db:
        assert (
            db.query(DeviceTask)
            .filter(DeviceTask.ioc_value == "45.9.8.31", DeviceTask.operation == "UNBLOCK")
            .count()
            == 0
        )
        statuses = [
            row.status
            for row in db.query(IocIndicator)
            .filter(IocIndicator.normalized_value == "45.9.8.31")
            .order_by(IocIndicator.id)
        ]
        assert statuses == ["expired", "active"]
