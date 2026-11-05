"""配置字段描述（界面向导）测试：插件声明什么，界面就渲染什么。"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from plugins import registry  # noqa: E402
from plugins.base import build_config_fields  # noqa: E402


def _fields(code: str) -> list[dict]:
    manifest = [m for m in registry.list_manifests() if m["plugin_code"] == code][0]["manifest"]
    return manifest["config_fields"]


def test_type_inference():
    fields = {f["key"]: f for f in _fields("qiming_ips")}
    assert fields["base_url"]["type"] == "string"
    assert fields["verify_ssl"]["type"] == "bool"
    assert fields["end_time_minutes"]["type"] == "int"
    assert fields["base_url"]["address"] is True


def test_labels_are_chinese_not_keys():
    fields = {f["key"]: f for f in _fields("aliyun_waf_v3")}
    assert fields["template_id"]["label"] == "模板 ID"
    assert fields["max_entries"]["default"] == 200
    assert fields["auto_create_rule"]["default"] is True
    assert fields["endpoint"]["group"] == "connection"


def test_secret_fields_hidden_from_form():
    """凭据字段不能出现在表单里，只能填环境变量名。"""
    for code in ("aliyun_waf_v3", "paloalto_fw", "sangfor_ips"):
        keys = {f["key"] for f in _fields(code)}
        assert "credential_ref" not in keys
        assert "password" not in keys
        assert "access_key_secret" not in keys


def test_required_flag_follows_required_config():
    fields = {f["key"]: f for f in _fields("ssh_firewall")}
    assert fields["host"]["required"] is True
    assert fields["vendor"]["required"] is False


def test_address_field_first():
    fields = _fields("paloalto_fw")
    assert fields[0]["address"] is True
    groups = [f["group"] for f in fields]
    assert groups == sorted(groups, key=lambda g: 0 if g == "connection" else 1)


def test_enum_options_parsed():
    fields = {f["key"]: f for f in _fields("ssh_firewall")}
    assert fields["vendor"]["type"] == "enum"
    assert fields["vendor"]["options"] == ["h3c", "huawei"]


def test_unknown_plugin_schema_does_not_crash():
    assert build_config_fields({}, []) == []
    fields = build_config_fields({"weird_key": "某厂商自定义参数"}, ["weird_key"])
    assert fields[0]["key"] == "weird_key"
    assert fields[0]["type"] == "string"
    assert fields[0]["required"] is True
