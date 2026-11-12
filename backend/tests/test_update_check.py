"""版本信息与「检查更新」。

重点验三件事：版本号能落到接口上、检查更新只读且网络异常不炸页面、
缓存既不重复打 GitHub 也不把失败结果缓存成「已是最新」。
"""
from __future__ import annotations

import urllib.error
from dataclasses import replace

import pytest

from app import __version__
from app.config import settings
from app.database import SessionLocal
from app.models import SystemRole, SystemUser
from app.security import hash_password
from app.services import update_check


def _release(tag: str = "v99.0.0", body: str = "修复若干问题") -> dict:
    return {
        "tag_name": tag,
        "name": tag,
        "published_at": "2026-12-01T00:00:00Z",
        "html_url": f"https://github.com/aegis-soc/aegis-soc/releases/tag/{tag}",
        "body": body,
    }


@pytest.fixture(autouse=True)
def _clear_cache():
    update_check.reset_cache()
    yield
    update_check.reset_cache()


@pytest.fixture
def online(monkeypatch):
    """把配置换成「开启检查 + 假 API 地址」，避免测试读真实 .env。"""
    patched = replace(
        settings,
        update_check_enabled=True,
        github_api_base="https://api.example.test",
        update_cache_ttl=600,
        update_check_timeout=3,
    )
    monkeypatch.setattr(update_check, "settings", patched)
    return patched


@pytest.mark.parametrize(
    "text,expected",
    [
        ("v1.2.3", (1, 2, 3)),
        ("1.0.0", (1, 0, 0)),
        ("v2.1", (2, 1, 0)),
        ("1", (1, 0, 0)),
        ("v1.2.3-beta.1", (1, 2, 3)),
        ("", None),
        ("abc", None),
        ("v1.x.3", None),
        ("1.2.3.4", None),
    ],
)
def test_parse_version(text, expected):
    assert update_check.parse_version(text) == expected


def test_detects_newer_release(online, monkeypatch):
    monkeypatch.setattr(update_check, "_fetch_latest", lambda timeout: _release("v99.0.0"))

    data = update_check.check(force=True)

    assert data["has_update"] is True
    assert data["latest_version"] == "v99.0.0"
    assert data["current_version"] == __version__
    assert data["error"] == ""
    assert data["cached"] is False
    assert data["checked_at"]


def test_same_or_older_release_is_not_an_update(online, monkeypatch):
    monkeypatch.setattr(update_check, "_fetch_latest", lambda timeout: _release("v0.9.0"))
    assert update_check.check(force=True)["has_update"] is False


def test_cache_avoids_repeated_github_calls(online, monkeypatch):
    calls = []

    def fake(timeout):
        calls.append(timeout)
        return _release("v99.0.0")

    monkeypatch.setattr(update_check, "_fetch_latest", fake)

    first = update_check.check()
    second = update_check.check()
    forced = update_check.check(force=True)

    assert len(calls) == 2            # 第二次命中缓存，force 才重打
    assert first["cached"] is False
    assert second["cached"] is True
    assert forced["cached"] is False


def test_network_error_degrades_and_is_not_cached(online, monkeypatch):
    calls = []

    def boom(timeout):
        calls.append(1)
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr(update_check, "_fetch_latest", boom)

    first = update_check.check()
    second = update_check.check()

    assert first["has_update"] is False
    assert "无法连接 GitHub" in first["error"]
    assert len(calls) == 2            # 失败不缓存，下次还能重试


def test_http_404_means_no_release_yet(online, monkeypatch):
    def not_found(timeout):
        raise urllib.error.HTTPError("https://api.example.test", 404, "Not Found", {}, None)

    monkeypatch.setattr(update_check, "_fetch_latest", not_found)
    assert "还没有发布" in update_check.check()["error"]


def test_http_403_explains_rate_limit(online, monkeypatch):
    def forbidden(timeout):
        raise urllib.error.HTTPError("https://api.example.test", 403, "Forbidden", {}, None)

    monkeypatch.setattr(update_check, "_fetch_latest", forbidden)
    assert "上限" in update_check.check()["error"]


def test_unparsable_tag_is_reported(online, monkeypatch):
    monkeypatch.setattr(update_check, "_fetch_latest", lambda timeout: _release("nightly-20260101"))
    data = update_check.check(force=True)
    assert data["has_update"] is False
    assert "无法解析版本号" in data["error"]


def test_long_notes_are_truncated(online, monkeypatch):
    monkeypatch.setattr(update_check, "_fetch_latest", lambda timeout: _release("v99.0.0", "x" * 5000))
    data = update_check.check(force=True)
    assert data["notes_truncated"] is True
    assert len(data["notes"]) <= update_check.NOTES_LIMIT


def test_disabled_check_does_not_touch_network(online, monkeypatch):
    monkeypatch.setattr(update_check, "settings", replace(online, update_check_enabled=False))

    def should_not_run(timeout):  # pragma: no cover - 被调用即失败
        raise AssertionError("关闭后不应发起网络请求")

    monkeypatch.setattr(update_check, "_fetch_latest", should_not_run)
    data = update_check.check(force=True)
    assert "已关闭" in data["error"]
    assert data["has_update"] is False


def test_status_exposes_version_meta(client):
    data = client.get("/api/v1/system/status").json()["data"]
    assert data["version"] == __version__
    assert data["commit"]
    assert data["build_time"]


def test_update_endpoint_returns_payload(client, auth_headers, online, monkeypatch):
    monkeypatch.setattr(update_check, "_fetch_latest", lambda timeout: _release("v99.0.0"))

    response = client.get("/api/v1/system/update/check?force=1", headers=auth_headers)

    assert response.status_code == 200
    data = response.json()["data"]
    assert data["has_update"] is True
    assert data["latest_version"] == "v99.0.0"
    assert data["current_commit"]


def test_update_endpoint_requires_system_permission(client, online):
    """运营账号没有 system:*，不能触发对外请求（也就不能拿它当探测跳板）。"""
    with SessionLocal() as db:
        if db.query(SystemRole).filter(SystemRole.role_code == "operator").first() is None:
            db.add(SystemRole(
                role_code="operator",
                role_name="安全运营",
                permission_json=["alert:*", "ioc:*", "chat:ask"],
            ))
            db.flush()
        if db.query(SystemUser).filter(SystemUser.username == "op-upd").first() is None:
            db.add(SystemUser(
                username="op-upd",
                password_hash=hash_password("Op@123456"),
                role_code="operator",
                status=1,
            ))
        db.commit()

    login = client.post("/api/v1/auth/login", json={"username": "op-upd", "password": "Op@123456"})
    assert login.status_code == 200, login.text
    headers = {"Authorization": f"Bearer {login.json()['data']['access_token']}"}

    assert client.get("/api/v1/system/update/check", headers=headers).status_code == 403
