"""安全运营指标：缺口归因、豁免口径、处置率趋势、持续攻击、来源覆盖、封禁节奏。"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy.orm import Session

from app.config import settings
from app.database import utcnow
from app.models import AutomationPolicy, IocIndicator, IpWhitelist
from app.services import inspector
from app.services import security_metrics as metrics
from tests.conftest import engine, graylog_payload


def _post(client, alert_id: str, ip: str, **fields):
    payload = graylog_payload(alert_id, ip)
    payload["event"]["fields"].update(fields)
    return client.post(
        f"/api/v1/alerts/graylog?secret={settings.graylog_webhook_secret}", json=payload
    )


def _disable_policies() -> None:
    with Session(bind=engine) as db:
        db.query(AutomationPolicy).update({"enabled": 0})
        db.commit()


def _enable_policies() -> None:
    with Session(bind=engine) as db:
        db.query(AutomationPolicy).update({"enabled": 1})
        db.commit()


def _add_ioc(db: Session, value: str, days_ago: int, status: str = "active") -> None:
    created = utcnow() - timedelta(days=days_ago)
    db.add(IocIndicator(
        ioc_type="IP", ioc_value=value, normalized_value=value, status=status,
        source_type="IPS", source_count=1, created_at=created, updated_at=created,
    ))


# ---------------------------------------------------------------- 缺口归因

def test_gap_reports_no_policy(client):
    """策略全关时：检出了但一个都没封，原因归类到「未命中策略」。"""
    _disable_policies()
    _post(client, "evt-gap-1", "45.77.1.1")
    _post(client, "evt-gap-2", "45.77.1.2")

    with Session(bind=engine) as db:
        gap = metrics.gap_breakdown(db)

    assert gap["detected_ips"] == 2
    assert gap["blocked_ips"] == 0
    assert gap["gap_ips"] == 2
    assert gap["block_rate"] == 0.0
    top = gap["reasons"][0]
    assert top["key"] == "no_policy"
    assert top["label"] == "未命中策略"
    assert top["exempt"] is False
    assert gap["top_gaps"][0]["label"] == "未命中策略"


def test_gap_treats_whitelist_and_private_as_exempt(client):
    """白名单与内网地址是设计内豁免，不能算成「该封未封」。"""
    with Session(bind=engine) as db:
        db.add(IpWhitelist(ip_value="1.2.3.4", cidr=None,
                           ip_bin=b"\x01\x02\x03\x04", prefix_len=32,
                           cidr_flag=0, status=1))
        db.commit()

    _post(client, "evt-ex-1", "1.2.3.4")
    _post(client, "evt-ex-2", "10.20.30.40")

    with Session(bind=engine) as db:
        gap = metrics.gap_breakdown(db)

    assert gap["exempt_ips"] == 2
    assert gap["gap_ips"] == 0
    assert gap["block_rate"] is None
    assert all(r["exempt"] for r in gap["reasons"])
    assert {r["key"] for r in gap["reasons"]} <= {"whitelist", "invalid_ioc"}


def test_check_gap_fails_when_block_rate_low(client):
    """1 封 4 漏 → 处置率 20%，必须 fail 而不是 warn。"""
    _disable_policies()
    for idx in range(4):
        _post(client, f"evt-low-{idx}", f"45.88.1.{idx + 1}")
    _enable_policies()
    _post(client, "evt-low-hit", "45.88.1.99")

    with Session(bind=engine) as db:
        result = inspector.check_gap(db)

    assert result["status"] == "fail"
    assert result["data"]["block_rate"] == 0.2
    assert "处置率 20%" in result["summary"]


# ---------------------------------------------------------------- 处置率与节奏

def test_detection_trend_and_block_rhythm(client):
    for idx in range(3):
        _post(client, f"evt-trend-{idx}", "45.66.6.6")

    with Session(bind=engine) as db:
        trend = metrics.detection_trend(db, days=7)
        rhythm = metrics.block_rhythm(db)
        result = inspector.check_detection(db)

    assert len(trend["series"]) == 7
    assert trend["latest_rate"] == 1.0
    assert rhythm["blocked"] >= 3
    assert rhythm["peak_count"] >= 3
    assert rhythm["repeat"][0]["ip"] == "45.66.6.6"
    assert result["status"] == "ok"
    assert "处置率" in result["summary"]


# ---------------------------------------------------------------- 持续攻击

def test_persistent_attackers_spans_days(client):
    with Session(bind=engine) as db:
        for days_ago in (1, 2, 3):
            _add_ioc(db, "45.55.55.55", days_ago)
        for days_ago in range(1, 6):
            _add_ioc(db, "45.55.55.66", days_ago)
        _add_ioc(db, "45.55.55.77", 1)  # 只出现一天，不应计入
        db.commit()

    with Session(bind=engine) as db:
        per = metrics.persistent_attackers(db)
        result = inspector.check_persistent(db)

    assert per["total"] == 2
    items = {item["ip"]: item for item in per["items"]}
    assert items["45.55.55.55"]["days"] == 3
    assert items["45.55.55.55"]["suggest_hours"] == 24
    assert items["45.55.55.66"]["days"] == 5
    assert items["45.55.55.66"]["suggest_hours"] == 168  # 长期打点 → 建议 7 天
    assert result["status"] == "warn"
    assert "反复出现" in result["summary"]


# ---------------------------------------------------------------- 来源覆盖

def test_source_coverage_flags_missing_streams(client):
    _post(client, "evt-src-only-ips", "45.44.4.4", device_type="IPS")

    with Session(bind=engine) as db:
        coverage = metrics.source_coverage(db)
        result = inspector.check_sources(db)

    assert coverage["active_sources"] == 1
    assert coverage["missing_core"] == ["WAF", "ZTNA"]
    assert result["status"] == "warn"
    assert "仅 IPS 一路" in result["summary"]


def test_source_coverage_ok_with_three_streams(client):
    _post(client, "evt-3s-ips", "45.43.4.1", device_type="IPS")
    _post(client, "evt-3s-waf", "45.43.4.2", device_type="WAF")
    _post(client, "evt-3s-zt", "45.43.4.3", stream="零信任网关")

    with Session(bind=engine) as db:
        result = inspector.check_sources(db)

    assert result["status"] == "ok"
    assert "三流齐全" in result["summary"]


# ---------------------------------------------------------------- 评分与落库

def test_weighted_score_penalises_safety_gap(client, auth_headers, monkeypatch):
    """加权评分：安全效果项（gap 权重 2.0）失败时，分数应明显低于简单均分。"""
    def fake_ok(db, ctx=None):
        return inspector.CheckResult("gap", "封禁缺口", "ok", "无缺口")

    def fake_fail(db, ctx=None):
        return inspector.CheckResult("whitelist", "白名单风险", "fail", "白名单过宽")

    monkeypatch.setattr(inspector, "CHECKS", [fake_ok, fake_fail])
    body = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]

    # (100 * 2.0 + 0 * 0.5) / 2.5 = 80，简单均分则为 50
    assert body["score"] == 80


def test_metrics_persisted_and_compared_with_previous(client, auth_headers):
    _post(client, "evt-metrics-1", "45.33.3.3")  # 有一条真实处置记录，指标才有值
    first = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]
    assert first["metrics"]["detection_rate_7d"] is not None
    assert len(first["metrics"]["trend"]) == 7
    assert "score_delta" not in first["metrics"]  # 首次巡检没有对比基准

    second = client.post("/api/v1/inspections/run", headers=auth_headers).json()["data"]
    assert second["metrics"]["score_delta"] == second["score"] - first["score"]
    assert second["metrics"]["previous_score"] == first["score"]

    listing = client.get("/api/v1/inspections/reports", headers=auth_headers).json()["data"]
    assert listing["items"][0]["metrics"]["detection_rate_7d"] is not None
