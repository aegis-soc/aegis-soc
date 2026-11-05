"""插件层回归测试：必填校验、连通性测试不炸 500、设备拒绝执行不得判成功。"""
from __future__ import annotations

import pytest

from plugins import registry
from plugins.base import BasePlugin, PluginResult
from plugins.builtin.http_generic import HttpGenericPlugin
from plugins.builtin.sangfor_ips import SangforIpsPlugin
from plugins.builtin.ssh_firewall import SshFirewallPlugin


class _NoQueryPlugin(BasePlugin):
    plugin_code = "no_query"
    plugin_name = "只封禁不解封"
    capabilities = ["BLOCK"]

    def test_connection(self, config):
        return PluginResult(True, "ok")

    def block(self, ioc_value, ioc_type, config):
        return PluginResult(True, "ok")

    def unblock(self, ioc_value, ioc_type, config):
        return PluginResult(True, "ok")


def test_default_query_status_is_failure():
    """未实现 QUERY 的插件不能默认返回成功（避免伪造查询结果）。"""
    result = _NoQueryPlugin().query_status("1.1.1.1", "IP", {})
    assert result.success is False
    assert "未实现" in result.message


def test_execute_blocks_undeclared_capability():
    result = _NoQueryPlugin().execute("QUERY", "1.1.1.1", "IP", {})
    assert result.success is False
    assert "不支持能力" in result.message


def test_execute_validates_required_config():
    result = SshFirewallPlugin().execute("BLOCK", "1.1.1.1", "IP", {"host": "", "username": "u"})
    assert result.success is False
    assert "缺少必填配置" in result.message


def test_execute_reports_missing_credential_env():
    config = {"host": "10.0.0.1", "username": "u", "_credential_missing": "AEGIS_FW_PWD"}
    result = SshFirewallPlugin().execute("BLOCK", "1.1.1.1", "IP", config)
    assert result.success is False
    assert "AEGIS_FW_PWD" in result.message


def test_plugin_test_never_raises_config_error():
    """缺 base_url 时连通性测试必须返回结构化失败，而不是抛异常导致接口 500。"""
    result = registry.test_plugin("http_generic", {})
    assert result["success"] is False
    assert "插件配置错误" in result["message"]


def test_register_rejects_illegal_capability():
    class Bad(BasePlugin):
        plugin_code = "bad_cap"
        capabilities = ["DROP"]

        def test_connection(self, config):
            return PluginResult(True)

        def block(self, ioc_value, ioc_type, config):
            return PluginResult(True)

        def unblock(self, ioc_value, ioc_type, config):
            return PluginResult(True)

    with pytest.raises(ValueError, match="非法能力"):
        registry.register(Bad)


def test_ssh_block_detects_device_error(monkeypatch):
    plugin = SshFirewallPlugin()
    monkeypatch.setattr(
        plugin, "_send",
        lambda config, commands: ("<H3C>system\n[H3C]blacklist ip 1.1.1.1\n% Invalid input\n[H3C]", True),
    )
    result = plugin.block("1.1.1.1", "IP", {"host": "10.0.0.1", "username": "u", "password": "p"})
    assert result.success is False
    assert "拒绝执行" in result.message


def test_ssh_block_detects_prompt_timeout(monkeypatch):
    plugin = SshFirewallPlugin()
    monkeypatch.setattr(plugin, "_send", lambda config, commands: ("login as: ", False))
    result = plugin.block("1.1.1.1", "IP", {"host": "10.0.0.1", "username": "u", "password": "p"})
    assert result.success is False
    assert "结果未知" in result.message


def test_ssh_block_success(monkeypatch):
    plugin = SshFirewallPlugin()
    monkeypatch.setattr(plugin, "_send", lambda config, commands: ("[H3C]blacklist ip 1.1.1.1 timeout 7200\n[H3C]", True))
    result = plugin.block("1.1.1.1", "IP", {"host": "10.0.0.1", "username": "u", "password": "p"})
    assert result.success is True


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict | None = None):
        self.status_code = status_code
        self._payload = payload
        self.text = str(payload)

    def json(self):
        if self._payload is None:
            raise ValueError("not json")
        return self._payload


class _FakeSession:
    """黑名单接口 200，配置生效 500 —— 这种情况必须判失败。"""

    def __init__(self):
        self.calls: list[str] = []

    def post(self, url, data=None, verify=None, timeout=None):
        if "applyconfig" in url:
            self.calls.append("apply")
            return _FakeResponse(500, {"message": "apply failed"})
        self.calls.append("blacklist")
        return _FakeResponse(200, {"message": "success"})

    def get(self, url, verify=None, timeout=None):
        return _FakeResponse(200, {})

    def close(self):
        pass


def test_sangfor_fails_when_apply_not_effective(monkeypatch):
    plugin = SangforIpsPlugin()
    session = _FakeSession()
    monkeypatch.setattr(plugin, "_session", lambda config: (session, "sk", "ak"))
    result = plugin.block(
        "1.1.1.1", "IP",
        {"base_url": "https://10.0.0.2:8081", "username": "u", "password": "p"},
    )
    assert "apply" in session.calls
    assert result.success is False
    assert "未生效" in result.message or "未落地" in result.message


def test_http_generic_string_false_verify_ssl():
    """字符串 "false" 必须按 False 处理，否则自签证书设备会报 SSL 错误。"""
    from plugins.base import as_bool

    assert as_bool("false", True) is False
    assert as_bool("true", False) is True
    assert as_bool(None, True) is True
    assert HttpGenericPlugin.required_config == ["base_url"]


def test_plugin_test_endpoint_returns_structured_failure(client, auth_headers):
    """接口层：缺配置时应返回 code=0 + success=false，而不是 500。"""
    response = client.post(
        "/api/v1/plugins/test",
        json={"plugin_code": "http_generic", "config_json": {}},
        headers=auth_headers,
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["code"] == 0
    assert body["data"]["success"] is False
    assert "插件配置错误" in body["data"]["message"]
