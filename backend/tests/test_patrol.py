"""日志巡检 P0 测试：字段归一、L1 规则、闸门预判、窗口游标与降级。

重点验证两件事：
1. **dry-run 真的什么都不写**——不产生 IOC、不产生设备任务；
2. **MCP 故障不会中断**——降级成 failed 的批次，而不是抛异常或误封。
"""
from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from app.database import SessionLocal, utcnow
from app.models import DeviceTask, IocIndicator, IpWhitelist, PatrolCandidate, PatrolRun
from app.services import patrol
from app.services.mcp_client import McpError


class FakeClient:
    """伪 MCP 客户端：按 stream_id 返回预置日志，或模拟连接失败。"""

    def __init__(self, payloads: dict[str, list[dict]] | None = None, error: str | None = None):
        self.payloads = payloads or {}
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    def call_tool(self, name: str, arguments: dict | None = None) -> dict:
        self.calls.append((name, arguments or {}))
        if self.error:
            raise McpError(self.error)
        stream = str((arguments or {}).get("stream_id") or "")
        return {"messages": self.payloads.get(stream, [])}


def patch_settings(monkeypatch, **overrides):
    base = {
        "patrol_mcp_url": "http://mcp.test/mcp",
        "patrol_mcp_token": "test-token",
        "patrol_enabled": True,
        "patrol_mode": "dry-run",
        "patrol_interval_seconds": 300,
        "patrol_overlap_seconds": 60,
        "patrol_max_records": 500,
        "patrol_repeat_hours": 24,
        "patrol_mcp_tool": "search_messages",
    }
    base.update(overrides)
    monkeypatch.setattr(patrol, "settings", replace(patrol.settings, **base))


def graylog_message(msg_id: str, ip: str, *, action: str = "alert", severity: int = 4,
                    rule: str = "sql-injection", timestamp: str | None = None,
                    extra: dict | None = None) -> dict:
    fields = {"src_ip": ip, "action": action, "severity": severity, "rule_name": rule}
    fields.update(extra or {})
    return {
        "message": {
            "_id": msg_id,
            "timestamp": timestamp or utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            "source": ip,
            "message": f"{rule} from {ip}",
            "fields": fields,
        }
    }


THREE_STREAMS = (
    '[{"name": "IPS", "label": "IPS", "stream_id": "ips-1", "query": ""},'
    ' {"name": "WAF", "label": "WAF", "stream_id": "waf-1", "query": ""},'
    ' {"name": "ZTNA", "label": "ZTNA", "stream_id": "ztna-1", "query": ""}]'
)


def test_extract_records_handles_common_shapes():
    plain = [{"_id": "1", "message": "x"}]
    assert len(patrol.extract_records(plain)) == 1
    nested = {"messages": {"messages": [{"_id": "2"}]}}
    assert patrol.extract_records(nested)[0]["_id"] == "2"
    wrapped = {"data": {"records": [{"_id": "3"}]}}
    assert patrol.extract_records(wrapped)[0]["_id"] == "3"


@pytest.mark.parametrize("value,expected", [
    ("block", "block"), ("阻断", "block"), ("Drop", "block"),
    ("alert", "observe"), ("pass", "observe"), ("仅记录", "observe"),
    ("", "unknown"), ("weird", "unknown"),
])
def test_classify_action(value, expected):
    assert patrol.classify_action(value) == expected


@pytest.mark.parametrize("value,expected", [
    ("4", 4), ("9", 5), ("high", 4), ("critical", 5), ("中", 3), ("", 0),
])
def test_parse_severity(value, expected):
    assert patrol.parse_severity(value) == expected


def test_l1_rules_and_internal_ips_ignored():
    now = utcnow()
    items = [
        patrol._flatten(graylog_message("m1", "45.33.20.10", action="pass")),
        patrol._flatten(graylog_message("m2", "45.33.20.10", action="log",
                                        extra={"tags": ["threat_intel"]})),
        # 内网地址不允许封禁，只计数不进候选
        patrol._flatten(graylog_message("m3", "10.1.1.5", action="pass")),
    ]
    for item in items:
        item.setdefault("_stream", "WAF")
    candidates, ignored = patrol.build_candidates(items, now)

    assert ignored == 1
    assert len(candidates) == 1
    top = candidates[0]
    assert top.ip == "45.33.20.10"
    assert top.hits == 2
    assert top.rule_counts["waf_observed"] == 2
    assert top.rule_counts["intel_hit"] == 1


def test_ztna_burst_needs_threshold():
    now = utcnow()
    few = [patrol._flatten(graylog_message(f"z{i}", "45.33.20.20", action="fail"))
           for i in range(3)]
    for item in few:
        item.setdefault("_stream", "ZTNA")
    candidates, _ = patrol.build_candidates(few, now)
    assert candidates == []  # 单次失败不构成理由

    many = [patrol._flatten(graylog_message(f"z{i}", "45.33.20.20", action="fail"))
            for i in range(12)]
    for item in many:
        item.setdefault("_stream", "ZTNA")
    candidates, _ = patrol.build_candidates(many, now)
    assert candidates[0].rule_counts["ztna_burst"] == 12


def test_gates_skip_whitelist_and_existing(client, monkeypatch):
    patch_settings(monkeypatch, patrol_streams=THREE_STREAMS)
    now = utcnow()
    with SessionLocal() as db:
        db.add(IpWhitelist(ip_value="45.33.20.31", ip_bin=b"\x00" * 16, prefix_len=32,
                           cidr_flag=0, status=1, remark="办公出口"))
        db.add(IocIndicator(ioc_type="IP", ioc_value="45.33.20.32",
                            normalized_value="45.33.20.32", status="active"))
        db.commit()

        payloads = {"waf-1": [
            graylog_message("w1", "45.33.20.31", action="pass"),
            graylog_message("w2", "45.33.20.32", action="pass"),
            graylog_message("w3", "45.33.20.33", action="pass"),
        ]}
        run = patrol.run_patrol(db, trigger="manual", now=now, client=FakeClient(payloads))

        decisions = {
            c.ip_value: c.decision
            for c in db.query(PatrolCandidate).filter(PatrolCandidate.run_id == run.id)
        }
        assert decisions["45.33.20.31"] == "skipped_whitelist"
        assert decisions["45.33.20.32"] == "skipped_existing"
        assert decisions["45.33.20.33"] == "would_block"
        assert run.would_block == 1


def test_dry_run_writes_no_ioc_or_task(client, monkeypatch):
    patch_settings(monkeypatch, patrol_streams=THREE_STREAMS)
    payloads = {"ips-1": [graylog_message("i1", "45.33.20.41", action="alert", severity=5)]}
    with SessionLocal() as db:
        run = patrol.run_patrol(db, trigger="manual", client=FakeClient(payloads))
        assert run.blocked == 0
        assert run.status == "ok"
        assert run.fetched == 1
        assert db.query(IocIndicator).count() == 0
        assert db.query(DeviceTask).count() == 0
        assert "P0" in (run.summary or {}).get("note", "")


def test_window_overlaps_previous_run(client, monkeypatch):
    patch_settings(monkeypatch, patrol_streams=THREE_STREAMS)
    t0 = utcnow()
    with SessionLocal() as db:
        first = patrol.run_patrol(db, trigger="cron", now=t0, client=FakeClient({}))
        second = patrol.run_patrol(db, trigger="cron", now=t0 + timedelta(minutes=5),
                                   client=FakeClient({}))
        assert second.window_start == first.window_end - timedelta(seconds=60)
        assert second.window_end == t0 + timedelta(minutes=5)


def test_mcp_failure_degrades_without_raising(client, monkeypatch):
    patch_settings(monkeypatch, patrol_streams=THREE_STREAMS)
    with SessionLocal() as db:
        run = patrol.run_patrol(db, trigger="cron", client=FakeClient(error="连接被拒绝"))
        assert run.status == "failed"
        assert run.candidate_count == 0
        assert "连接被拒绝" in (run.error or "")


def test_unconfigured_mcp_is_skipped(client, monkeypatch):
    patch_settings(monkeypatch, patrol_mcp_url="")
    with SessionLocal() as db:
        run = patrol.run_patrol(db, trigger="cron")
        assert run.status == "skipped"
        assert run.fetched == 0


def test_repeat_ip_marked_on_second_run(client, monkeypatch):
    patch_settings(monkeypatch, patrol_streams=THREE_STREAMS)
    payloads = {"waf-1": [graylog_message("r1", "45.33.20.51", action="pass")]}
    t0 = utcnow()
    with SessionLocal() as db:
        patrol.run_patrol(db, trigger="cron", now=t0, client=FakeClient(payloads))
        second = patrol.run_patrol(db, trigger="cron", now=t0 + timedelta(minutes=5),
                                   client=FakeClient(payloads))
        row = db.query(PatrolCandidate).filter(PatrolCandidate.run_id == second.id).one()
        assert row.decision == "skipped_repeat"
        assert second.would_block == 0


def test_api_run_latest_and_list(client, auth_headers, monkeypatch):
    patch_settings(monkeypatch, patrol_streams=THREE_STREAMS)
    payloads = {"waf-1": [graylog_message("a1", "45.33.20.61", action="pass")]}
    monkeypatch.setattr(patrol, "build_client", lambda: FakeClient(payloads))

    run = client.post("/api/v1/patrols/run", headers=auth_headers)
    assert run.status_code == 200, run.text
    data = run.json()["data"]
    assert data["blocked"] == 0
    assert len(data["candidates"]) == 1
    assert data["candidates"][0]["ip_value"] == "45.33.20.61"

    latest = client.get("/api/v1/patrols/latest", headers=auth_headers).json()["data"]
    assert latest["id"] == data["id"]

    listing = client.get("/api/v1/patrols", headers=auth_headers).json()["data"]
    assert listing["total"] == 1
    assert listing["mode"] == "dry-run"
