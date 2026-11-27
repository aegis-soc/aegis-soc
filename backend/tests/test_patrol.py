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
    ("banned", "ban"), ("blacklist", "ban"),
    ("reject", "reject"), ("REJECT", "reject"),
    ("permit", "pass"), ("allow", "pass"), ("放行", "pass"),
    ("audit", "audit"),
    ("alert", "observe"), ("pass", "pass"), ("仅记录", "observe"),
    ("", "unknown"), ("weird", "unknown"),
])
def test_classify_action(value, expected):
    assert patrol.classify_action(value) == expected


def test_normalize_action_value_mapping_priority():
    """厂商数字枚举必须走 value_mapping；映射优先于关键词启发。"""
    nsfocus = {"1": "observe", "3": "block", "6": "audit", "8": "ban"}
    assert patrol.normalize_action("1", nsfocus) == "observe"
    assert patrol.normalize_action("3", nsfocus) == "block"
    assert patrol.normalize_action("8", nsfocus) == "ban"
    assert patrol.normalize_action("permit", {"permit": "observe"}) == "observe"
    # 未命中映射走启发兜底
    assert patrol.normalize_action("blocked", nsfocus) == "block"
    # 映射值不在标准词表也原样返回（规则判定自然落空，不悄悄改语义）
    assert patrol.normalize_action("9", nsfocus) == "unknown"


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
    """ztna_burst 按 redirect_auth（认证重定向）计数——网关失败也回 200，
    status_code 不可靠（2026-11-26 真机确认）；普通请求不计数。"""
    now = utcnow()
    few = [patrol._flatten(graylog_message(f"z{i}", "45.33.20.20", action="pass",
            extra={"l7_app_request_type": "redirect_auth"})) for i in range(3)]
    for item in few:
        item.setdefault("_stream", "ZTNA")
    candidates, _ = patrol.build_candidates(few, now)
    assert candidates == []  # 少于阈值不构成理由

    many = [patrol._flatten(graylog_message(f"z{i}", "45.33.20.20", action="pass",
             extra={"l7_app_request_type": "redirect_auth"})) for i in range(12)]
    for item in many:
        item.setdefault("_stream", "ZTNA")
    candidates, _ = patrol.build_candidates(many, now)
    assert candidates[0].rule_counts["ztna_burst"] == 12

    # 只有 anonymous_access（无 redirect_auth）不触发认证爆破
    anon = [patrol._flatten(graylog_message(f"a{i}", "45.33.20.21", action="pass",
             extra={"l7_app_request_type": "anonymous_access"})) for i in range(15)]
    for item in anon:
        item.setdefault("_stream", "ZTNA")
    candidates, _ = patrol.build_candidates(anon, now)
    assert all("ztna_burst" not in c.rule_counts for c in candidates)



def _waf(ip, action="reject", url="/api/x", extra=None, i=0):
    item = patrol._flatten(graylog_message(f"w{i}", ip, action=action,
                                           extra={"r_url": url, **(extra or {})}))
    item.setdefault("_stream", "WAF")
    return item


def _zt(ip, rtype="anonymous_access", domain="h1.example.com", url="/a/b", i=0):
    item = patrol._flatten(graylog_message(f"t{i}", ip, action="pass",
                    extra={"l7_app_request_type": rtype, "dst_domain": domain,
                           "request_uri": url}))
    item.setdefault("_stream", "ZTNA")
    return item


def test_waf_reject_and_bruteforce_login():
    now = utcnow()
    # 5 次 REJECT 触发 waf_reject
    items = [_waf("45.33.20.30", i=i) for i in range(5)]
    candidates, _ = patrol.build_candidates(items, now)
    assert candidates[0].rule_counts["waf_reject"] == 5
    # 10 次登录页 REJECT 同时触发登录爆破
    items = [_waf("45.33.20.31", url="/portal/login.jsp", i=i) for i in range(10)]
    candidates, _ = patrol.build_candidates(items, now)
    assert candidates[0].rule_counts["waf_reject"] == 10
    assert candidates[0].rule_counts["bruteforce_login"] == 10
    # 4 次 REJECT 不触发
    candidates, _ = patrol.build_candidates([_waf("45.33.20.32", i=i) for i in range(4)], now)
    assert all("waf_reject" not in c.rule_counts for c in candidates)


def test_waf_spoofed_xff():
    now = utcnow()
    items = [_waf("45.33.20.40", action="permit",
                  extra={"r_url": "/x", "XForwardedFor": "1.2.3.4, 5.6.7.8"}, i=i)
             for i in range(2)]
    candidates, _ = patrol.build_candidates(items, now)
    assert candidates[0].rule_counts.get("waf_spoofed") == 1
    # XFF 最后一个与直连一致 → 不算伪造
    ok = [_waf("45.33.20.41", action="permit",
               extra={"r_url": "/x", "XForwardedFor": "45.33.20.41"}, i=i) for i in range(2)]
    candidates, _ = patrol.build_candidates(ok, now)
    assert all("waf_spoofed" not in c.rule_counts for c in candidates)


def test_zt_multi_domain_scan():
    now = utcnow()
    domains = [f"h{n}.example.com" for n in range(4)]
    items = [_zt("45.33.20.50", domain=d, url=f"/h{n}/x", i=n) for n, d in enumerate(domains)]
    candidates, _ = patrol.build_candidates(items, now)
    assert candidates[0].rule_counts["zt_multi_domain"] == 4
    # 3 个域名不触发
    items = [_zt("45.33.20.51", domain=f"h{n}.e.com", url=f"/h{n}/x", i=n) for n in range(3)]
    candidates, _ = patrol.build_candidates(items, now)
    assert all("zt_multi_domain" not in c.rule_counts for c in candidates)


def test_zt_dir_scan_needs_uri_and_prefix():
    now = utcnow()
    # 20 个不同 URI 且前缀分散 → 触发
    uris = [f"/app{a}/mod{b}/file" for a in range(5) for b in range(4)]
    items = [_zt("45.33.20.60", url=u, domain="h.e.com", i=n) for n, u in enumerate(uris)]
    candidates, _ = patrol.build_candidates(items, now)
    assert candidates[0].rule_counts["zt_dir_scan"] == 20
    # URI 多但前缀集中（同一 /app/mod 下翻页参数不同）→ 不触发
    uris = [f"/app/mod/file?x={n}" for n in range(25)]
    items = [_zt("45.33.20.61", url=u, domain="h.e.com", i=n) for n, u in enumerate(uris)]
    candidates, _ = patrol.build_candidates(items, now)
    assert all("zt_dir_scan" not in c.rule_counts for c in candidates)


def test_ip_whitelist_skips_candidates():
    now = utcnow()
    items = [_zt("180.184.86.192", domain=f"h{n}.e.com", url=f"/h{n}/x", i=n)
             for n in range(6)]
    candidates, ignored = patrol.build_candidates(items, now)
    assert candidates and candidates[0].rule_counts.get("zt_multi_domain")  # 无白名单时照常触发
    candidates, ignored = patrol.build_candidates(
        items, now, ip_whitelist={"180.184.86.192"})
    assert candidates == []          # 白名单命中：不进候选
    assert ignored == 0              # 也不计入非公网（语义不同）


def test_value_mapping_drives_ips_rule():
    """绿盟 IPS：action=1 仅告警 → observe 触发未拦截规则；action=3 阻断 → 不触发。"""
    now = utcnow()
    maps = {"IPS": {"action": {"1": "observe", "3": "block", "8": "ban"}}}
    items = [patrol._flatten(graylog_message(f"n{i}", "45.33.20.70", action="1",
             extra={"threat_type": "exploit"})) for i in range(2)]
    for item in items:
        item.setdefault("_stream", "IPS")
    candidates, _ = patrol.build_candidates(items, now, action_maps=maps)
    assert candidates[0].rule_counts["ips_observed"] == 2
    blocked = [patrol._flatten(graylog_message(f"n{i}", "45.33.20.71", action="3"))
               for i in range(2)]
    for item in blocked:
        item.setdefault("_stream", "IPS")
    candidates, _ = patrol.build_candidates(blocked, now, action_maps=maps)
    assert candidates == []          # 已阻断不进候选


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
    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: FakeClient(payloads))

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
