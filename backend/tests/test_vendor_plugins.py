"""厂商插件测试：PA（PAN-OS XML API）与启明（Web API）。

全部用假响应/假会话，不依赖真实设备，也不需要网络。
"""
from __future__ import annotations

import pytest

import plugins.builtin.paloalto_fw as pa_mod
import plugins.builtin.qiming_fw as qm_mod
from plugins.base import PluginResult
from plugins.builtin.paloalto_fw import PaloAltoFwPlugin
from plugins.builtin.qiming_fw import QimingFwPlugin

PA_CONFIG = {
    "base_url": "https://10.0.0.1",
    "api_key": "secret-key",
    "vsys": "vsys1",
    "tag_name": "aegis-block",
    "verify_ssl": "false",
}

QM_CONFIG = {
    "base_url": "https://10.0.0.3",
    "username": "aegis",
    "password": "p@ss",
    "block_path": "/api/v1/firewall/blacklist",
    "unblock_path": "/api/v1/firewall/blacklist",
    "save_path": "/api/v1/firewall/save",
}


class _XmlResponse:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code


def _patch_pa(monkeypatch, text: str, captured: dict):
    def fake_post(url, params=None, data=None, timeout=None, verify=None):
        captured.update(url=url, params=params, body=(data or b"").decode("utf-8"),
                        verify=verify, timeout=timeout)
        return _XmlResponse(text)

    monkeypatch.setattr(pa_mod.requests, "post", fake_post)


def test_pa_block_registers_ip_with_tag(monkeypatch):
    captured: dict = {}
    _patch_pa(monkeypatch, '<response status="success" code="19"><result/></response>', captured)
    result = PaloAltoFwPlugin().execute("BLOCK", "1.2.3.4", "IP", PA_CONFIG)
    assert result.success is True
    assert captured["params"]["type"] == "user-id"
    assert captured["params"]["key"] == "secret-key"
    assert "<register>" in captured["body"]
    assert 'ip="1.2.3.4"' in captured["body"]
    assert "<member>aegis-block</member>" in captured["body"]
    assert captured["verify"] is False


def test_pa_unblock_uses_unregister(monkeypatch):
    captured: dict = {}
    _patch_pa(monkeypatch, '<response status="success" code="19"/>', captured)
    result = PaloAltoFwPlugin().execute("UNBLOCK", "1.2.3.4", "IP", PA_CONFIG)
    assert result.success is True
    assert "<unregister>" in captured["body"]
    assert "<register>" not in captured["body"]


def test_pa_error_status_is_failure_even_on_http_200(monkeypatch):
    """PAN-OS 业务失败仍返回 HTTP 200，必须按 XML status 判失败。"""
    captured: dict = {}
    _patch_pa(
        monkeypatch,
        '<response status="error" code="13"><msg><line>Invalid credentials</line></msg></response>',
        captured,
    )
    result = PaloAltoFwPlugin().execute("BLOCK", "1.2.3.4", "IP", PA_CONFIG)
    assert result.success is False
    assert "code=13" in result.message
    assert "Invalid credentials" in result.message


def test_pa_non_xml_response_is_failure(monkeypatch):
    captured: dict = {}
    _patch_pa(monkeypatch, "<html>502 Bad Gateway</html", captured)
    result = PaloAltoFwPlugin().execute("BLOCK", "1.2.3.4", "IP", PA_CONFIG)
    assert result.success is False
    assert "非 XML" in result.message


def test_pa_test_connection_is_read_only(monkeypatch):
    captured: dict = {}
    _patch_pa(monkeypatch, '<response status="success"><result/></response>', captured)
    result = PaloAltoFwPlugin().test_connection(PA_CONFIG)
    assert result.success is True
    assert captured["params"]["type"] == "op"
    assert "show" in captured["params"]["cmd"]


def test_pa_missing_api_key_blocked_by_validation():
    result = PaloAltoFwPlugin().execute("BLOCK", "1.2.3.4", "IP", {"base_url": "https://10.0.0.1"})
    assert result.success is False
    assert "api_key" in result.message


class _JsonResponse:
    def __init__(self, payload, status_code: int = 200):
        self._payload = payload
        self.status_code = status_code
        self.text = str(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _Cookies:
    def __init__(self, data: dict | None = None):
        self._data = data or {}

    def get_dict(self) -> dict:
        return dict(self._data)


def _patch_qm(monkeypatch, login, block=None, save=None, cookies=None):
    """构造一个假会话：login / 业务接口 / save 各自返回预设 JSON。"""
    instances: list = []

    class FakeSession:
        def __init__(self):
            self.calls: list[dict] = []
            self.cookies = _Cookies(cookies)
            instances.append(self)

        def post(self, url, data=None, headers=None, timeout=None, verify=None):
            body = (data or b"").decode("utf-8")
            self.calls.append({"url": url, "body": body, "headers": headers or {}})
            if "login" in url:
                return _JsonResponse(login[0], login[1])
            if "save" in url:
                return _JsonResponse(save if save is not None else {"code": 0})
            return _JsonResponse(block if block is not None else {"code": 0})

        def close(self):
            pass

    monkeypatch.setattr(qm_mod.requests, "Session", FakeSession)
    return instances


def test_qiming_block_with_token_and_save(monkeypatch):
    instances = _patch_qm(monkeypatch, ({"code": 0, "data": {"token": "tk-1"}}, 200))
    result = QimingFwPlugin().execute("BLOCK", "5.6.7.8", "IP", QM_CONFIG)
    assert result.success is True
    session = instances[0]
    urls = [c["url"] for c in session.calls]
    assert urls[0].endswith("/api/v1/login")
    assert "blacklist" in urls[1]
    assert urls[-1].endswith("/api/v1/firewall/save")
    block_call = session.calls[1]
    assert '"5.6.7.8"' in block_call["body"]
    assert block_call["headers"]["Authorization"] == "Bearer tk-1"


def test_qiming_business_code_failure(monkeypatch):
    _patch_qm(
        monkeypatch,
        ({"code": 0, "data": {"token": "tk-1"}}, 200),
        block={"code": 1001, "msg": "blacklist is full"},
    )
    result = QimingFwPlugin().execute("BLOCK", "5.6.7.8", "IP", QM_CONFIG)
    assert result.success is False
    assert "封禁失败" in result.message
    assert "1001" in result.message


def test_qiming_save_failure_marks_task_failed(monkeypatch):
    """下发成功但配置未保存 -> 策略未生效，必须判失败。"""
    _patch_qm(
        monkeypatch,
        ({"code": 0, "data": {"token": "tk-1"}}, 200),
        save={"code": 500, "msg": "save failed"},
    )
    result = QimingFwPlugin().execute("BLOCK", "5.6.7.8", "IP", QM_CONFIG)
    assert result.success is False
    assert "未保存生效" in result.message


def test_qiming_login_http_error(monkeypatch):
    _patch_qm(monkeypatch, ({"code": 401, "msg": "bad password"}, 401))
    result = QimingFwPlugin().execute("BLOCK", "5.6.7.8", "IP", QM_CONFIG)
    assert result.success is False
    assert "登录失败" in result.message


def test_qiming_cookie_only_login(monkeypatch):
    """只发 Cookie 不返回 token 的设备也要能跑通。"""
    config = dict(QM_CONFIG, token_path="")
    instances = _patch_qm(monkeypatch, ({"code": 0}, 200), cookies={"SESSION": "abc"})
    result = QimingFwPlugin().execute("BLOCK", "5.6.7.8", "IP", config)
    assert result.success is True
    assert "Authorization" not in instances[0].calls[1]["headers"]


def test_qiming_login_without_token_or_cookie(monkeypatch):
    config = dict(QM_CONFIG, token_path="")
    _patch_qm(monkeypatch, ({"code": 0}, 200))
    result = QimingFwPlugin().execute("BLOCK", "5.6.7.8", "IP", config)
    assert result.success is False
    assert "token_path" in result.message


def test_qiming_test_connection_does_not_send_policy(monkeypatch):
    instances = _patch_qm(monkeypatch, ({"code": 0, "data": {"token": "tk-1"}}, 200))
    result = QimingFwPlugin().test_connection(dict(QM_CONFIG, save_path=""))
    assert result.success is True
    assert len(instances[0].calls) == 1


def test_new_plugins_are_registered():
    from plugins import registry

    assert registry.get("paloalto_fw") is not None
    assert registry.get("qiming_fw") is not None
    manifest = registry.get_manifest("paloalto_fw")
    assert manifest["capabilities"] == ["BLOCK", "UNBLOCK"]
    assert manifest["ioc_types"] == ["IP"]
