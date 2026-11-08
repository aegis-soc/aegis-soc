"""日志巡检配置测试：库优先、token 掩码、留空不改、权限与草稿试连。

重点验证四条「安全边界」：
1. token 永远不会通过接口回到前端（只回 ``token_set`` + 尾号）；
2. 保存时 token 留空不改、只有 ``clear_token`` 才清空；
3. 改配置需要管理员（``system:*``），普通运营账号被拒；
4. 试连用草稿配置，不落库。
"""
from __future__ import annotations

import pytest

from app.common import BizError
from app.config import settings
from app.database import SessionLocal
from app.models import SystemRole, SystemUser
from app.security import hash_password
from app.services import patrol, patrol_settings


# ---------------------------------------------------------------- 服务层
def test_defaults_come_from_env(client):
    with SessionLocal() as db:
        cfg = patrol_settings.load(db, base=settings)
    assert cfg.source == "env"
    assert cfg.auth == "token"
    assert [s["name"] for s in cfg.streams] == ["IPS", "WAF", "ZTNA"]


def test_save_then_load_roundtrip(client):
    with SessionLocal() as db:
        saved = patrol_settings.save(db, {
            "enabled": True,
            "mcp_url": "https://graylog.lab/api/mcp",
            "mcp_token": "secret-token-123456",
            "mcp_auth": "token",
            "streams": [
                {"name": "IPS", "label": "IPS", "stream_id": "aaa", "query": "action:alert"},
                {"name": "WAF", "label": "WAF", "stream_id": "bbb", "query": ""},
            ],
            "interval_seconds": 120,
            "overlap_seconds": 30,
            "repeat_hours": 48,
        }, operator="admin")
        assert saved.source == "db"
        assert saved.token == "secret-token-123456"
        assert saved.interval == 120

        reloaded = patrol_settings.load(db)
        assert reloaded.url == "https://graylog.lab/api/mcp"
        assert reloaded.enabled is True
        # 只给了两条流也保留，不再强行补第三条
        assert [s["stream_id"] for s in reloaded.streams] == ["aaa", "bbb"]
        assert reloaded.streams[0]["query"] == "action:alert"
        assert reloaded.updated_by == "admin"


def test_public_never_exposes_token(client):
    with SessionLocal() as db:
        cfg = patrol_settings.save(db, {
            "mcp_url": "https://graylog.lab/api/mcp",
            "mcp_token": "abcdef1234567890",
        }, operator="admin")
        payload = patrol_settings.public(cfg)
    assert "mcp_token" not in payload
    assert payload["token_set"] is True
    assert payload["token_hint"] == "abcd***7890"


def test_blank_token_keeps_previous_and_clear_works(client):
    with SessionLocal() as db:
        patrol_settings.save(db, {"mcp_url": "https://a/api/mcp", "mcp_token": "keep-me"}, operator="admin")
        # 改地址、token 留空 → 保留原 token（避免"改个 URL 把凭证冲掉"）
        kept = patrol_settings.save(db, {"mcp_url": "https://b/api/mcp"}, operator="admin")
        assert kept.token == "keep-me"
        # 显式清除
        cleared = patrol_settings.save(db, {"clear_token": True}, operator="admin")
        assert cleared.token == ""
        assert patrol_settings.public(cleared)["token_set"] is False


def test_validation_rejects_bad_values(client):
    with SessionLocal() as db:
        with pytest.raises(BizError):
            patrol_settings.save(db, {"mcp_url": "graylog.lab/api/mcp"}, operator="admin")
        with pytest.raises(BizError):
            patrol_settings.save(db, {"mcp_auth": "magic"}, operator="admin")
        with pytest.raises(BizError):
            patrol_settings.save(db, {"interval_seconds": 5}, operator="admin")


# ---------------------------------------------------------------- 接口层
def test_api_get_and_save_config(client, auth_headers):
    response = client.get("/api/v1/patrols/config", headers=auth_headers)
    assert response.status_code == 200
    assert response.json()["data"]["source"] == "env"

    response = client.put("/api/v1/patrols/config", headers=auth_headers, json={
        "enabled": True,
        "mcp_url": "https://graylog.lab/api/mcp",
        "mcp_token": "tok-abcdefghijkl",
        "mcp_auth": "token",
        "streams": [{"name": "IPS", "label": "IPS", "stream_id": "s1", "query": ""}],
    })
    assert response.status_code == 200
    data = response.json()["data"]
    assert data["source"] == "db"
    assert data["token_set"] is True
    assert "mcp_token" not in data          # 明文不得回前端
    assert data["streams"][0]["stream_id"] == "s1"

    again = client.get("/api/v1/patrols/config", headers=auth_headers).json()["data"]
    assert again["mcp_url"] == "https://graylog.lab/api/mcp"
    assert again["enabled"] is True


def test_api_save_requires_admin(client):
    with SessionLocal() as db:
        # bootstrap 已内置 admin/operator/auditor 三个角色，这里只确保有运营账号
        if db.query(SystemRole).filter(SystemRole.role_code == "operator").first() is None:
            db.add(SystemRole(
                role_code="operator", role_name="安全运营",
                permission_json=["alert:*", "ioc:*", "inspection:read", "inspection:run"],
            ))
            db.flush()
        if db.query(SystemUser).filter(SystemUser.username == "op1").first() is None:
            db.add(SystemUser(
                username="op1", password_hash=hash_password("Op@123456"),
                role_code="operator", status=1,
            ))
        db.commit()

    login = client.post("/api/v1/auth/login", json={"username": "op1", "password": "Op@123456"})
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}

    # 读可以，写不行
    assert client.get("/api/v1/patrols/config", headers=headers).status_code == 200
    denied = client.put("/api/v1/patrols/config", headers=headers, json={"mcp_url": "https://evil/api/mcp"})
    assert denied.status_code == 403
    assert client.post("/api/v1/patrols/mcp/test", headers=headers, json={}).status_code == 403


def test_probe_uses_draft_without_persisting(client, auth_headers, monkeypatch):
    captured: dict = {}

    class _Stub:
        transport = "streamable-http"

        def describe(self):
            return {"server": {"name": "stub"}, "tools": [], "protocol_version": "x"}

    def _build(cfg=None, db=None):
        captured["url"] = cfg.url
        captured["token"] = cfg.token
        return _Stub()

    monkeypatch.setattr(patrol, "build_client", _build)
    monkeypatch.setattr(patrol, "discover_streams", lambda *a, **k: [])

    response = client.post("/api/v1/patrols/mcp/test", headers=auth_headers, json={
        "mcp_url": "https://draft.lab/api/mcp", "mcp_token": "draft-token",
    })
    assert response.status_code == 200
    assert response.json()["data"]["error"] == ""
    assert captured == {"url": "https://draft.lab/api/mcp", "token": "draft-token"}

    # 试连不落库：GET 仍是环境变量状态
    assert client.get("/api/v1/patrols/config", headers=auth_headers).json()["data"]["source"] == "env"


def test_run_patrol_uses_saved_config(client, auth_headers, monkeypatch):
    body = client.put("/api/v1/patrols/config", headers=auth_headers, json={
        "mcp_url": "https://saved.lab/api/mcp",
        "mcp_token": "saved-token",
        "streams": [{"name": "IPS", "label": "IPS", "stream_id": "s-ips", "query": ""}],
        "repeat_hours": 12,
    })
    assert body.status_code == 200

    class FakeClient:
        def tool_schema(self, name):
            return {"properties": {"stream_id": {"type": "string"}, "query": {"type": "string"}}}

        def call_tool(self, name, arguments=None):
            return {"messages": [{"message": {
                "_id": "m1", "timestamp": "2026-11-08T09:00:00.000Z",
                "fields": {"src_ip": "45.33.20.10", "action": "alert", "severity": 5,
                           "rule_name": "sql-injection"},
            }}]}

    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: FakeClient())

    run = client.post("/api/v1/patrols/run", headers=auth_headers).json()["data"]
    assert run["status"] == "ok"
    assert run["fetched"] == 1
    assert run["candidate_count"] == 1
    summary = run["summary"]
    assert summary["mcp"]["url"] == "https://saved.lab/api/mcp"
    assert summary["mcp"]["config_source"] == "db"
    assert summary["streams"][0]["stream_id"] == "s-ips"
