"""AI 巡检：检查项判定、评分、报告落库与接口权限。"""
from __future__ import annotations

import json

from app.config import settings
from app.models import InspectionReport, IpWhitelist
from app.services import inspector
from tests.conftest import graylog_payload


def _post(client, alert_id: str, ip: str, **fields):
    payload = graylog_payload(alert_id, ip)
    payload["event"]["fields"].update(fields)
    return client.post(
        f"/api/v1/alerts/graylog?secret={settings.graylog_webhook_secret}", json=payload
    )


def _checks_by_key(report: dict) -> dict:
    return {c["key"]: c for c in report["checks"]}


# ---------------------------------------------------------------- 单项检查

def test_check_devices_warns_without_devices(client):
    from tests.conftest import engine
    from sqlalchemy.orm import Session
    from app.models import SecurityDevice
    with Session(bind=engine) as db:
        db.query(SecurityDevice).delete()
        db.commit()
        result = inspector.check_devices(db)
    assert result["status"] == "warn"
    assert "尚未接入" in result["summary"]


def test_check_expire_detects_overdue(client, auth_headers, monkeypatch):
    """已过期仍 active 的记录 = 解封链路失灵，必须 fail。"""
    from tests.conftest import engine
    from sqlalchemy.orm import Session
    from datetime import timedelta

    from app.database import utcnow
    from app.models import IocIndicator

    _post(client, "evt-insp-1", "45.11.11.1")
    with Session(bind=engine) as db:
        row = db.query(IocIndicator).filter(
            IocIndicator.normalized_value == "45.11.11.1").first()
        row.expire_at = utcnow() - timedelta(minutes=30)  # 人为造成「已过期未解封」
        db.commit()
        result = inspector.check_expire(db)
    assert result["status"] == "fail"
    assert result["data"]["overdue"] >= 1


def test_check_whitelist_flags_wide_cidr(client):
    from tests.conftest import engine
    from sqlalchemy.orm import Session

    with Session(bind=engine) as db:
        db.add(IpWhitelist(ip_value="10.0.0.1", cidr="10.0.0.0/8", ip_bin=b"\n\x00\x00\x00",
                           prefix_len=8, cidr_flag=1, status=1))
        db.commit()
        result = inspector.check_whitelist(db)
    assert result["status"] == "warn"
    assert "10.0.0.0/8" in result["data"]["too_wide"]


def test_check_policies_fails_without_enabled_policy(client):
    from tests.conftest import engine
    from sqlalchemy.orm import Session
    from app.models import AutomationPolicy

    with Session(bind=engine) as db:
        db.query(AutomationPolicy).update({"enabled": 0})
        db.commit()
        result = inspector.check_policies(db)
    assert result["status"] == "fail"
    assert "没有启用" in result["summary"] or "没有任何启用" in result["summary"]


def test_check_attacks_reports_repeat_offender(client, auth_headers):
    _post(client, "evt-insp-r1", "45.12.12.9")
    _post(client, "evt-insp-r2", "45.12.12.9")
    _post(client, "evt-insp-r3", "45.12.12.9")
    from tests.conftest import engine
    from sqlalchemy.orm import Session
    with Session(bind=engine) as db:
        result = inspector.check_attacks(db)
    repeats = {r["ip"]: r["count"] for r in result["data"]["repeat_offenders"]}
    assert repeats.get("45.12.12.9", 0) >= 3


def test_check_blacklist_warns_when_empty(client):
    from tests.conftest import engine
    from sqlalchemy.orm import Session
    with Session(bind=engine) as db:
        result = inspector.check_blacklist(db)
    assert result["status"] == "warn"


# ---------------------------------------------------------------- 整场巡检

def test_run_inspection_persists_report(client, auth_headers):
    body = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]
    assert 0 <= body["score"] <= 100
    assert body["overall"] in ("ok", "warn", "fail")
    assert len(body["checks"]) == len(inspector.CHECKS)
    assert body["summary"], "总结不能为空"
    assert body["trigger"] == "manual"

    keys = {c["key"] for c in body["checks"]}
    assert {"devices", "blacklist", "tasks", "expire", "whitelist",
            "policies", "attacks", "system"} <= keys
    for c in body["checks"]:
        assert c["score"] in (100, 55, 0)
        assert c["status"] in ("ok", "warn", "fail")


def test_run_inspection_degrades_on_check_error(client, auth_headers, monkeypatch):
    """单项检查抛异常时整场巡检不中断，该项降级为 fail。"""
    def boom(db):
        raise RuntimeError("数据库炸了")
    monkeypatch.setattr(
        inspector, "CHECKS",
        [boom if f is inspector.check_blacklist else f for f in inspector.CHECKS],
    )
    body = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]
    broken = [c for c in body["checks"] if c["status"] == "fail" and "数据库炸了" in c["summary"]]
    assert broken


def test_rule_summary_lists_failures_and_advice(client, auth_headers, monkeypatch):
    monkeypatch.setattr(inspector, "_llm_summary", lambda checks, score, metrics=None: None)
    from tests.conftest import engine
    from sqlalchemy.orm import Session
    from app.models import AutomationPolicy
    with Session(bind=engine) as db:
        db.query(AutomationPolicy).update({"enabled": 0})
        db.commit()
    report = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]
    assert "策略覆盖" in report["summary"]


def test_llm_summary_disabled_without_config(client, auth_headers, monkeypatch):
    """没配置 LLM 时不应发起任何网络请求，直接用规则总结。"""
    called = {"n": 0}

    def fake_urlopen(*args, **kwargs):
        called["n"] += 1
        raise AssertionError("未配置 LLM 时不应发起网络请求")

    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    report = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]
    assert called["n"] == 0
    assert report["ai_enhanced"] == 0


# ---------------------------------------------------------------- 接口

def test_latest_and_history_and_detail(client, auth_headers):
    assert client.get("/api/v1/inspections/latest", headers=auth_headers).json()["data"] is None
    client.post("/api/v1/inspections/run", headers=auth_headers)
    latest = client.get("/api/v1/inspections/latest", headers=auth_headers).json()["data"]
    assert latest and latest["id"] > 0

    listing = client.get("/api/v1/inspections/reports", headers=auth_headers).json()["data"]
    assert listing["total"] >= 1

    detail = client.get(f"/api/v1/inspections/reports/{latest['id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert detail.json()["data"]["checks"]

    missing = client.get("/api/v1/inspections/reports/999999", headers=auth_headers)
    assert missing.status_code == 404
