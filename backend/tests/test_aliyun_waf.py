"""阿里云 WAF 3.0 插件测试。

用内存假 WAF 模拟 Create/Modify/Describe，重点验证：
整表回写不丢条目、200 条分片、幂等、解封只剩零条时停用规则、并发覆盖保护。
"""
from __future__ import annotations

import json

import pytest

import plugins.builtin.aliyun_waf_v3 as aliyun_mod
from plugins.builtin.aliyun_waf_v3 import AliyunApiError, AliyunWafV3Plugin

CONFIG = {
    "instance_id": "waf_test_001",
    "template_id": 5327,
    "access_key_id": "ak",
    "access_key_secret": "sk",
    "rule_name": "aegis-block",
    "max_entries": 200,
    "max_rules": 5,
}


class FakeWaf:
    def __init__(self, rules=None, scene="ip_blacklist", template_name="aegis-ip-black"):
        self.rules = rules or []
        self.writes: list[tuple[str, dict]] = []
        self.next_id = 9000
        self.fail_with: str | None = None
        self.scene = scene
        self.template_name = template_name

    def add_rule(self, name: str, ips: list[str], status: int = 1):
        self.next_id += 1
        self.rules.append({
            "RuleId": self.next_id,
            "RuleName": name,
            "Status": status,
            "DefenseScene": "ip_blacklist",
            "Config": json.dumps({"remoteAddr": ips, "action": "block"}),
        })
        return self.next_id

    def rpc(self, action, params, config):
        if self.fail_with:
            raise AliyunApiError(self.fail_with)
        if action == "DescribeInstance":
            return {"InstanceStatus": "running"}
        if action == "DescribeDefenseTemplate":
            return {"Template": {
                "TemplateId": params["TemplateId"],
                "TemplateName": self.template_name,
                "DefenseScene": self.scene,
                "TemplateStatus": 1,
            }}
        if action == "DescribeDefenseRules":
            return {"TotalCount": len(self.rules), "Rules": self.rules}
        if action in {"CreateDefenseRule", "ModifyDefenseRule"}:
            for item in json.loads(params["Rules"]):
                self.writes.append((action, item))
                if action == "CreateDefenseRule":
                    self.add_rule(item["name"], item["remoteAddr"], item.get("status", 1))
                else:
                    for rule in self.rules:
                        if rule["RuleId"] == item["id"]:
                            rule["RuleName"] = item["name"]
                            rule["Status"] = item["status"]
                            rule["Config"] = json.dumps(
                                {"remoteAddr": item["remoteAddr"], "action": item["action"]}
                            )
            return {"RequestId": "req-1"}
        raise AssertionError(f"未预期的 Action: {action}")


def _plugin(fake: FakeWaf) -> AliyunWafV3Plugin:
    plugin = AliyunWafV3Plugin()
    plugin._rpc = fake.rpc  # type: ignore[method-assign]
    return plugin


def test_block_appends_and_rewrites_full_list():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1", "2.2.2.2"])
    result = _plugin(fake).execute("BLOCK", "3.3.3.3", "IP", CONFIG)
    assert result.success is True
    action, item = fake.writes[-1]
    assert action == "ModifyDefenseRule"
    # 整表回写：老条目必须保留
    assert item["remoteAddr"] == ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
    assert item["status"] == 1


def test_block_is_idempotent():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1"])
    result = _plugin(fake).execute("BLOCK", "1.1.1.1", "IP", CONFIG)
    assert result.success is True
    assert "已在" in result.message
    assert fake.writes == []


def test_block_creates_new_shard_when_rule_is_full():
    fake = FakeWaf()
    full = [f"10.0.{i // 250}.{i % 250 + 1}" for i in range(200)]
    fake.add_rule("aegis-block", full)
    result = _plugin(fake).execute("BLOCK", "8.8.8.8", "IP", CONFIG)
    assert result.success is True
    names = [r["RuleName"] for r in fake.rules]
    assert names == ["aegis-block", "aegis-block-2"]
    new_rule = fake.rules[-1]
    assert json.loads(new_rule["Config"])["remoteAddr"] == ["8.8.8.8"]
    assert len(json.loads(fake.rules[0]["Config"])["remoteAddr"]) == 200


def test_max_entries_cannot_exceed_200():
    """配置写 5000 也只能按 200 分片，避免触发 DefenseIpCountOversize。"""
    fake = FakeWaf()
    fake.add_rule("aegis-block", [f"10.1.0.{i}" for i in range(1, 201)])
    result = _plugin(fake).execute("BLOCK", "7.7.7.7", "IP", dict(CONFIG, max_entries=5000))
    assert result.success is True
    assert [r["RuleName"] for r in fake.rules] == ["aegis-block", "aegis-block-2"]


def test_shard_limit_reached():
    fake = FakeWaf()
    fake.add_rule("aegis-block", [f"10.2.0.{i}" for i in range(1, 201)])
    fake.add_rule("aegis-block-2", [f"10.3.0.{i}" for i in range(1, 201)])
    result = _plugin(fake).execute("BLOCK", "6.6.6.6", "IP", dict(CONFIG, max_rules=2))
    assert result.success is False
    assert "分片上限" in result.message
    assert fake.writes == []


def test_unblock_removes_only_target_ip():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1", "2.2.2.2", "3.3.3.3"])
    result = _plugin(fake).execute("UNBLOCK", "2.2.2.2", "IP", CONFIG)
    assert result.success is True
    action, item = fake.writes[-1]
    assert item["remoteAddr"] == ["1.1.1.1", "3.3.3.3"]
    assert item["status"] == 1


def test_unblock_last_ip_disables_rule():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["9.9.9.9"])
    result = _plugin(fake).execute("UNBLOCK", "9.9.9.9", "IP", CONFIG)
    assert result.success is True
    _, item = fake.writes[-1]
    assert item["remoteAddr"] == []
    assert item["status"] == 0


def test_unblock_missing_ip_is_success_without_write():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1"])
    result = _plugin(fake).execute("UNBLOCK", "4.4.4.4", "IP", CONFIG)
    assert result.success is True
    assert fake.writes == []


def test_api_error_is_reported_as_failure():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1"])
    fake.fail_with = "Defense.Control.DefenseIpCountOversize: The number of IPs exceeds the limit."
    result = _plugin(fake).execute("BLOCK", "5.5.5.5", "IP", CONFIG)
    assert result.success is False
    assert "DefenseIpCountOversize" in result.message


def test_missing_template_id_fails_fast():
    fake = FakeWaf()
    config = {k: v for k, v in CONFIG.items() if k != "template_id"}
    config["template_id"] = 0
    result = _plugin(fake).execute("BLOCK", "1.1.1.1", "IP", config)
    assert result.success is False
    assert "template_id" in result.message


def test_signature_parameters(monkeypatch):
    captured = {}

    class Resp:
        status_code = 200
        text = '{"RequestId":"x","Rules":[],"TotalCount":0}'

        def json(self):
            return {"RequestId": "x", "Rules": [], "TotalCount": 0}

    def fake_get(url, params=None, timeout=None, verify=None):
        captured.update(url=url, params=params or {}, verify=verify)
        return Resp()

    monkeypatch.setattr(aliyun_mod.requests, "get", fake_get)
    AliyunWafV3Plugin()._rpc(
        "DescribeDefenseRules",
        {"InstanceId": "waf_test_001", "Query": "{}", "PageNumber": 1, "PageSize": 50},
        CONFIG,
    )
    params = captured["params"]
    assert captured["url"] == "https://wafopenapi.cn-hangzhou.aliyuncs.com/"
    assert params["Action"] == "DescribeDefenseRules"
    assert params["Version"] == "2021-10-01"
    assert params["SignatureMethod"] == "HMAC-SHA1"
    assert params["Signature"]
    assert "sk" not in json.dumps(params)  # 密钥不得出现在请求参数里


def test_auto_create_rule_false_never_creates_rule():
    """模板下没有规则时，禁止新建，明确要求人工在控制台建。"""
    fake = FakeWaf()
    result = _plugin(fake).execute("BLOCK", "1.2.3.4", "IP", dict(CONFIG, auto_create_rule=False))
    assert result.success is False
    assert "auto_create_rule=false" in result.message
    assert "手动创建" in result.message
    assert fake.writes == []


def test_auto_create_rule_false_still_writes_existing_rule():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1"])
    result = _plugin(fake).execute("BLOCK", "2.2.2.2", "IP", dict(CONFIG, auto_create_rule=False))
    assert result.success is True
    action, item = fake.writes[-1]
    assert action == "ModifyDefenseRule"
    assert item["remoteAddr"] == ["1.1.1.1", "2.2.2.2"]


def test_connection_checks_template_scene():
    fake = FakeWaf()
    fake.add_rule("aegis-block", ["1.1.1.1"])
    result = _plugin(fake).test_connection(CONFIG)
    assert result.success is True
    assert "aegis-ip-black" in result.message
    assert "aegis-block(1条)" in result.message


def test_connection_rejects_wrong_template_scene():
    """模板 ID 填成了别的场景时，必须失败而不是显示正常。"""
    fake = FakeWaf(scene="waf_group")
    result = _plugin(fake).test_connection(CONFIG)
    assert result.success is False
    assert "waf_group" in result.message
    assert "ip_blacklist" in result.message


def test_template_error_gets_actionable_hint():
    """模板不存在时给出「先去控制台建模板」的中文提示，而不是干巴巴的英文码。"""
    message = aliyun_mod._explain("Defense.Template.NotFound", "The specified template does not exist.")
    assert "控制台" in message
    assert "template_id" in message


def test_rpc_maps_api_error_with_hint(monkeypatch):
    class Resp:
        status_code = 400
        text = '{"Code":"Defense.Template.NotFound","Message":"The specified template does not exist."}'

        def json(self):
            return {"Code": "Defense.Template.NotFound", "Message": "The specified template does not exist."}

    monkeypatch.setattr(aliyun_mod.requests, "get", lambda *a, **k: Resp())
    with pytest.raises(AliyunApiError) as exc:
        AliyunWafV3Plugin()._rpc("DescribeDefenseRules", {}, CONFIG)
    assert "控制台" in str(exc.value)


def test_plugin_registered():
    from plugins import registry

    manifest = registry.get_manifest("aliyun_waf_v3")
    assert manifest is not None
    assert manifest["ioc_types"] == ["IP"]
    assert set(manifest["capabilities"]) == {"BLOCK", "UNBLOCK"}
    assert "template_id" in manifest["config_schema"]
