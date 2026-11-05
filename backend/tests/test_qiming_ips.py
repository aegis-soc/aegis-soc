"""启明星辰 天清IPS 插件测试（按厂商 API v3 文档）。

重点验证：口令 SHA256、JWT 复用与 401 重登、type=4/IP 报文、end_time 分钟语义、
业务码判定、连通性测试不写数据、不伪造解封。
"""
from __future__ import annotations

import hashlib

import pytest

import plugins.builtin.qiming_ips as qiming_mod
from plugins.builtin.qiming_ips import QimingIpsPlugin

CONFIG = {
    "base_url": "https://10.10.10.10:8443",
    "username": "api_user",
    "password": "Passw0rd!",
    "end_time_minutes": 60,
}


class FakeDevice:
    """内存假 IPS：记录请求，可按需返回业务错误或 401。"""

    def __init__(self) -> None:
        self.calls: list[dict] = []
        self.logins = 0
        self.blocks = 0
        self.login_code = 0
        self.block_code = 0
        self.block_msg = "success"
        self.expire_token_once = False
        self._token_seq = 0

    def post(self, url, json=None, headers=None, timeout=None, verify=None):
        body = json or {}
        self.calls.append({"url": url, "body": body, "headers": headers or {}})
        if url.endswith("/api/v3/login"):
            self.logins += 1
            self.last_password = body.get("password")
            if self.login_code != 0:
                return Resp(200, {"code": self.login_code, "msg": "用户名或密码错误"})
            self._token_seq += 1
            return Resp(200, {
                "code": 0, "msg": "success",
                "data": {"authorization": f"jwt-{self._token_seq}"},
            })
        if url.endswith("/api/v3/block_policy"):
            if self.expire_token_once:
                self.expire_token_once = False
                return Resp(401, {"code": 401, "msg": "token expired"})
            self.blocks += 1
            return Resp(200, {"code": self.block_code, "msg": self.block_msg, "data": {"id": "1"}})
        raise AssertionError(f"未预期 URL: {url}")


class Resp:
    def __init__(self, status_code: int, payload: dict) -> None:
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        return self._payload


@pytest.fixture(autouse=True)
def _clear_token_cache():
    qiming_mod._TOKEN_CACHE.clear()
    yield
    qiming_mod._TOKEN_CACHE.clear()


def _plugin(device: FakeDevice, monkeypatch) -> QimingIpsPlugin:
    monkeypatch.setattr(qiming_mod.requests, "post", device.post)
    return QimingIpsPlugin()


def test_login_sends_sha256_not_plaintext(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", CONFIG)
    assert result.success is True
    assert device.last_password == hashlib.sha256("Passw0rd!".encode()).hexdigest()
    assert device.last_password != "Passw0rd!"
    assert len(device.last_password) == 64


def test_block_payload_for_ip(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", CONFIG)
    assert result.success is True
    call = [c for c in device.calls if c["url"].endswith("/block_policy")][0]
    assert call["body"] == {
        "type": 4, "block_content": "1.2.3.4", "end_time": 60, "enable": 1,
    }
    assert call["headers"]["Authorization"] == "jwt-1"
    assert "60 分钟" in result.message


def test_block_permanent_when_end_time_zero(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", dict(CONFIG, end_time_minutes=0))
    assert result.success is True
    call = [c for c in device.calls if c["url"].endswith("/block_policy")][0]
    assert call["body"]["end_time"] == 0
    assert "永久" in result.message


def test_domain_maps_to_type_2(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).block("evil.example.com", "DOMAIN", CONFIG)
    assert result.success is True
    call = [c for c in device.calls if c["url"].endswith("/block_policy")][0]
    assert call["body"]["type"] == 2
    assert call["body"]["block_content"] == "evil.example.com"


def test_explicit_block_type_wins(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", dict(CONFIG, block_type=5))
    assert result.success is True
    call = [c for c in device.calls if c["url"].endswith("/block_policy")][0]
    assert call["body"]["type"] == 5


def test_business_code_failure_is_reported(monkeypatch):
    device = FakeDevice()
    device.block_code = 10021
    device.block_msg = "策略数量已达上限"
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", CONFIG)
    assert result.success is False
    assert "10021" in result.message
    assert "策略数量已达上限" in result.message


def test_login_failure_surfaces_device_message(monkeypatch):
    device = FakeDevice()
    device.login_code = 10001
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", CONFIG)
    assert result.success is False
    assert "登录失败" in result.message


def test_token_is_reused_across_blocks(monkeypatch):
    device = FakeDevice()
    plugin = _plugin(device, monkeypatch)
    plugin.block("1.1.1.1", "IP", CONFIG)
    plugin.block("2.2.2.2", "IP", CONFIG)
    assert device.logins == 1
    assert device.blocks == 2


def test_expired_token_relogin_once(monkeypatch):
    device = FakeDevice()
    device.expire_token_once = True
    result = _plugin(device, monkeypatch).block("1.2.3.4", "IP", CONFIG)
    assert result.success is True
    assert device.logins == 2
    assert device.blocks == 1


def test_test_connection_never_writes(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).test_connection(CONFIG)
    assert result.success is True
    assert "登录成功" in result.message
    assert device.blocks == 0
    assert all(c["url"].endswith("/login") for c in device.calls)


def test_missing_credential_fails_fast(monkeypatch):
    device = FakeDevice()
    result = _plugin(device, monkeypatch).execute(
        "BLOCK", "1.2.3.4", "IP", dict(CONFIG, _credential_missing="QIMING_IPS_PASSWORD")
    )
    assert result.success is False
    assert "QIMING_IPS_PASSWORD" in result.message


def test_unblock_is_not_faked(monkeypatch):
    """未声明 UNBLOCK，平台不会派发解封任务；直接调用也必须失败。"""
    device = FakeDevice()
    result = _plugin(device, monkeypatch).execute("UNBLOCK", "1.2.3.4", "IP", CONFIG)
    assert result.success is False
    assert "不支持能力 UNBLOCK" in result.message
    assert device.calls == []


def test_plugin_registered():
    from plugins import registry

    manifest = registry.get_manifest("qiming_ips")
    assert manifest is not None
    assert manifest["capabilities"] == ["BLOCK"]
    assert "IP" in manifest["ioc_types"]
    assert "end_time_minutes" in manifest["config_schema"]
