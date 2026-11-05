"""P1 插件上下文测试：设备作为显式参数、配置三层拆分、旧调用兼容。"""
from __future__ import annotations

import json

from plugins import registry
from plugins.context import ActionRequest, DeviceLimits, DeviceTarget


def test_flat_config_splits_into_three_layers():
    target = DeviceTarget.from_flat(
        {
            "base_url": "https://10.1.1.1:8443",
            "verify_ssl": False,
            "tag_name": "aegis-block",
            "end_time_minutes": 120,
            "password": "s3cret",
            "username": "api",
        },
        id=3,
        code="pa-hq-01",
        plugin_code="paloalto_fw",
    )
    assert target.connection == {"base_url": "https://10.1.1.1:8443", "verify_ssl": False}
    assert target.params == {"tag_name": "aegis-block", "end_time_minutes": 120, "username": "api"}
    assert target.secrets == {"password": "s3cret"}
    assert target.address == "https://10.1.1.1:8443"


def test_nested_layered_config():
    """设备配置也可显式分层，顶层字段优先级更高，便于单设备覆盖模板。"""
    target = DeviceTarget.from_flat(
        {
            "connection": {"base_url": "https://10.1.1.1", "timeout": 5},
            "params": {"tag_name": "aegis-block", "vsys": "vsys1"},
            "tag_name": "override-tag",
        },
        plugin_code="paloalto_fw",
    )
    assert target.connection["base_url"] == "https://10.1.1.1"
    assert target.params["vsys"] == "vsys1"
    assert target.params["tag_name"] == "override-tag"
    assert target.limits.timeout == 5


def test_secrets_win_over_params():
    """同一 key 出现在多层时，凭据层优先，避免数据库参数顶掉真实口令。"""
    target = DeviceTarget.from_flat({"base_url": "https://h", "password": "from-env"})
    assert target.config["password"] == "from-env"
    assert target.get("password") == "from-env"


def test_credential_missing_is_preserved():
    target = DeviceTarget.from_flat({"_credential_missing": "FW_HQ_PASSWORD"})
    assert target.credential_missing == "FW_HQ_PASSWORD"
    assert target.config["_credential_missing"] == "FW_HQ_PASSWORD"


def test_limits_are_parsed_and_not_leaked_into_params():
    target = DeviceTarget.from_flat(
        {"host": "10.0.0.1", "timeout": 30, "max_qps": 5, "max_concurrency": 2}
    )
    assert target.limits == DeviceLimits(timeout=30, max_qps=5.0, max_concurrency=2)
    assert "max_qps" not in target.params
    assert "max_concurrency" not in target.params


def test_execute_target_and_request_are_explicit():
    """设备、IOC、动作三者显式传入；设备编码会进入插件回执。"""
    target = DeviceTarget.from_flat({}, id=1, code="fw-hq-01", plugin_code="mock")
    result = registry.execute(target, ActionRequest("BLOCK", "1.2.3.4", "IP"))
    assert result.success is True
    assert json.loads(result.raw)["device"] == "fw-hq-01"


def test_two_devices_share_one_plugin_type():
    """同一插件下多台设备，各自独立的地址，互不影响。"""
    a = DeviceTarget.from_flat({"host": "10.0.0.1"}, code="fw-a", plugin_code="mock")
    b = DeviceTarget.from_flat({"host": "10.0.0.2"}, code="fw-b", plugin_code="mock")
    ra = registry.execute(a, ActionRequest("BLOCK", "1.1.1.1"))
    rb = registry.execute(b, ActionRequest("BLOCK", "1.1.1.1"))
    assert json.loads(ra.raw)["device"] == "fw-a"
    assert json.loads(rb.raw)["device"] == "fw-b"


def test_legacy_registry_signature_still_works():
    result = registry.execute("mock", "BLOCK", "5.6.7.8", "IP", {"mode": "silent"})
    assert result.success is True


def test_execute_rejects_wrong_ioc_type_and_capability():
    target = DeviceTarget.from_flat({}, plugin_code="mock")
    assert registry.execute(target, ActionRequest("BLOCK", "8.8.8.8", "URL")).success is False
    ips = DeviceTarget.from_flat({}, plugin_code="ssh_firewall")
    denied = registry.execute(ips, ActionRequest("QUERY", "8.8.8.8", "IP"))
    assert denied.success is False
    assert "不支持能力" in denied.message


def test_unknown_plugin_is_reported():
    target = DeviceTarget.from_flat({}, plugin_code="not_registered")
    result = registry.execute(target, ActionRequest("BLOCK", "1.1.1.1"))
    assert result.success is False
    assert "插件未注册" in result.message
