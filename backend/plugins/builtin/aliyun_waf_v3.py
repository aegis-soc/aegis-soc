"""阿里云 WAF 3.0 插件（IP 黑名单 / DefenseScene=ip_blacklist）。

为什么必须"读-改-写"：
WAF 3.0 的 IP 黑名单没有"追加单条"的接口，ModifyDefenseRule 的 remoteAddr 是**整表覆盖**。
所以每次封禁都要先 DescribeDefenseRules 取当前列表，合并新 IP 后再整体回写，否则会把别人的条目冲掉。

容量限制（官方文档）：
- 单条规则最多 200 个 IP / CIDR，超出返回 Defense.Control.DefenseIpCountOversize；
- 需要更多时只能新建规则，因此本插件按 `rule_name` + 序号自动分片（aegis-block、aegis-block-2 ...），
  每个分片独立维护自己的全量列表。

并发：读-改-写存在覆盖风险，本插件用进程内锁串行化，并在写入后回读确认 IP 已落地，
未确认则重试一次，仍失败即判失败（不谎报成功）。

凭据：AccessKey 只从 credential_ref 注入，支持 RAM 子账号最小权限；
签名使用阿里云 RPC 风格 HMAC-SHA1，不引入官方 SDK 依赖。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests
import urllib3

from plugins.base import BasePlugin, PluginConfigError, PluginResult, as_bool, as_int
from plugins.context import ActionRequest, DeviceTarget

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_VERSION = "2021-10-01"
DEFAULT_ENDPOINT = "wafopenapi.cn-hangzhou.aliyuncs.com"
SCENE = "ip_blacklist"
MAX_ENTRIES_HARD_LIMIT = 200
_LOCK = threading.Lock()


class AliyunApiError(Exception):
    """阿里云返回的错误（Code + Message），用于收敛为任务失败原因。"""


# 常见错误码 → 可执行的处置建议。模板由用户在控制台预先创建，插件只往里推 IP。
_ERROR_HINTS = {
    "InvalidAccessKeyId.NotFound": "AccessKey 不存在，检查 credential_ref 里的 access_key_id",
    "SignatureDoesNotMatch": "AccessKeySecret 不匹配或系统时间偏差超过 15 分钟",
    "Forbidden.RAM": "RAM 子账号缺少权限：需要 DescribeInstance / DescribeDefenseTemplate / "
                     "DescribeDefenseRules / CreateDefenseRule / ModifyDefenseRule",
    "Forbidden": "RAM 子账号无权限访问该实例，检查授权策略",
    "InvalidInstanceId": "instance_id 不是有效的 WAF 实例 ID（形如 waf_xxx）",
    "Defense.Control.DefenseIpCountOversize": "单条 IP 黑名单规则最多 200 条，请调低 max_entries 或增加分片",
}


def _explain(code: str, message: str) -> str:
    """把阿里云的英文错误码翻译成能直接照做的中文提示。"""
    hint = _ERROR_HINTS.get(code)
    if hint is None and "template" in code.lower():
        hint = "template_id 不存在或不属于该实例，请先在 WAF 控制台「防护配置 → 防护规则 → IP 黑名单」创建模板并取 ID"
    if hint is None and "Signature" in code:
        hint = "签名校验失败，检查 access_key_secret 是否完整复制（含特殊字符时注意转义）"
    base = f"{code}: {message}" if message else code
    return f"{base}（{hint}）" if hint else base


def _percent_encode(value: Any) -> str:
    return quote(str(value), safe="~")


class AliyunWafV3Plugin(BasePlugin):
    plugin_code = "aliyun_waf_v3"
    plugin_name = "阿里云 WAF 3.0"
    version = "1.0.0"
    ioc_types = ["IP"]
    capabilities = ["BLOCK", "UNBLOCK"]
    description = "WAF 3.0 IP 黑名单：取全量 → 合并 → 整表回写，单规则 200 条自动分片"
    config_schema = {
        "instance_id": "string（必填，WAF 实例 ID，waf_xxx）",
        "template_id": "int（必填，IP 黑名单模板 ID）",
        "credential_ref": 'string（环境变量名，JSON：{"access_key_id":"...","access_key_secret":"..."}）',
        "rule_name": "string（默认 aegis-block，多分片自动加 -2/-3）",
        "action": "string（默认 block，可选 monitor）",
        "max_entries": "int（每规则最多 IP，默认 200，上限 200）",
        "max_rules": "int（最多分片数，默认 5）",
        "auto_create_rule": "bool（默认 true；false 时只写已有规则，绝不新建规则）",
        "endpoint": "string（默认 wafopenapi.cn-hangzhou.aliyuncs.com）",
        "region_id": "string（默认 cn-hangzhou）",
        "timeout": "int（秒，默认 10）",
    }
    required_config = [
        "instance_id", "template_id", "access_key_id", "access_key_secret",
    ]
    default_timeout = 10

    # ---------- 阿里云 RPC 签名 ----------
    def _rpc(self, action: str, params: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
        common = {
            "Action": action,
            "Version": API_VERSION,
            "Format": "JSON",
            "AccessKeyId": str(config["access_key_id"]),
            "SignatureMethod": "HMAC-SHA1",
            "SignatureVersion": "1.0",
            "SignatureNonce": uuid.uuid4().hex,
            "Timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "RegionId": str(config.get("region_id") or "cn-hangzhou"),
        }
        query = {**common, **{k: v for k, v in params.items() if v is not None}}
        canonical = "&".join(
            f"{_percent_encode(k)}={_percent_encode(v)}" for k, v in sorted(query.items())
        )
        string_to_sign = f"GET&%2F&{_percent_encode(canonical)}"
        secret = str(config["access_key_secret"])
        digest = hmac.new(
            f"{secret}&".encode("utf-8"), string_to_sign.encode("utf-8"), hashlib.sha1
        ).digest()
        query["Signature"] = base64.b64encode(digest).decode("utf-8")

        endpoint = str(config.get("endpoint") or DEFAULT_ENDPOINT).replace("https://", "").strip("/")
        try:
            response = requests.get(
                f"https://{endpoint}/",
                params=query,
                timeout=as_int(config.get("timeout"), self.default_timeout),
                verify=as_bool(config.get("verify_ssl"), True),
            )
        except requests.RequestException as exc:
            raise AliyunApiError(f"请求失败: {exc.__class__.__name__}: {exc}") from exc

        try:
            payload = response.json()
        except ValueError:
            payload = {"Message": response.text[:200]}
        if response.status_code >= 300:
            code = payload.get("Code") or f"HTTP {response.status_code}"
            message = payload.get("Message") or payload.get("Message_") or ""
            raise AliyunApiError(_explain(str(code), str(message)))
        return payload

    # ---------- 规则读写 ----------
    def _list_rules(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        rules: list[dict[str, Any]] = []
        page = 1
        while True:
            payload = self._rpc(
                "DescribeDefenseRules",
                {
                    "InstanceId": config["instance_id"],
                    "Query": json.dumps(
                        {"scene": SCENE, "templateId": as_int(config.get("template_id"), 0)}
                    ),
                    "PageNumber": page,
                    "PageSize": 50,
                },
                config,
            )
            batch = payload.get("Rules") or []
            rules.extend(batch)
            total = as_int(payload.get("TotalCount"), 0)
            if len(batch) < 50 or len(rules) >= total:
                break
            page += 1
            if page > 20:  # 保险丝，避免分页异常时死循环
                break
        return rules

    @staticmethod
    def _parse_config(rule: dict[str, Any]) -> dict[str, Any]:
        raw = rule.get("Config")
        if isinstance(raw, dict):
            return raw
        try:
            parsed = json.loads(raw or "{}")
        except (TypeError, ValueError):
            return {}
        return parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _addr_list(config_json: dict[str, Any]) -> list[str]:
        value = config_json.get("remoteAddr")
        if isinstance(value, str):
            value = [v.strip() for v in value.split(",")]
        if not isinstance(value, list):
            return []
        return [str(v).strip() for v in value if str(v).strip()]

    def _shards(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        """收集本插件管理的规则分片（rule_name、rule_name-2 ...），按序号排序。"""
        prefix = str(config.get("rule_name") or "aegis-block")
        shards = []
        for rule in self._list_rules(config):
            if str(rule.get("DefenseScene") or SCENE) != SCENE:
                continue
            name = str(rule.get("RuleName") or "")
            if name != prefix and not name.startswith(f"{prefix}-"):
                continue
            tail = name[len(prefix):].lstrip("-")
            index = as_int(tail, 1) if tail else 1
            shards.append(
                {
                    "id": rule.get("RuleId"),
                    "name": name,
                    "index": index,
                    "ips": self._addr_list(self._parse_config(rule)),
                    "status": as_int(rule.get("Status"), 1),
                }
            )
        return sorted(shards, key=lambda item: item["index"])

    def _write(
        self,
        config: dict[str, Any],
        name: str,
        ips: list[str],
        rule_id: Any = None,
        status: int = 1,
    ) -> None:
        """整表回写：remoteAddr 始终传完整列表。"""
        item = {
            "name": name,
            "status": 0 if not ips else status,
            "action": str(config.get("action") or "block"),
            "remoteAddr": ips,
        }
        params: dict[str, Any] = {
            "InstanceId": config["instance_id"],
            "DefenseScene": SCENE,
            "Rules": json.dumps([item], ensure_ascii=False),
        }
        template_id = as_int(config.get("template_id"), 0)
        if template_id:
            params["TemplateId"] = template_id
        if rule_id is None:
            self._rpc("CreateDefenseRule", params, config)
        else:
            params["Rules"] = json.dumps([{"id": rule_id, **item}], ensure_ascii=False)
            self._rpc("ModifyDefenseRule", params, config)

    def _contains(self, config: dict[str, Any], ioc_value: str) -> bool:
        return any(ioc_value in shard["ips"] for shard in self._shards(config))

    # ---------- 业务 ----------
    def _block(self, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        shards = self._shards(config)
        for shard in shards:
            if ioc_value in shard["ips"]:
                return PluginResult(True, f"IP 已在规则 {shard['name']} 中，无需重复下发",
                                    raw=json.dumps({"rule": shard["name"], "count": len(shard["ips"])}))

        max_entries = min(
            max(1, as_int(config.get("max_entries"), MAX_ENTRIES_HARD_LIMIT)),
            MAX_ENTRIES_HARD_LIMIT,
        )
        max_rules = max(1, as_int(config.get("max_rules"), 5))
        prefix = str(config.get("rule_name") or "aegis-block")

        target = next((s for s in shards if len(s["ips"]) < max_entries), None)
        if target is not None:
            new_ips = [*target["ips"], ioc_value]
            self._write(config, target["name"], new_ips, target["id"], target["status"] or 1)
            expected = new_ips
            name = target["name"]
        else:
            if not as_bool(config.get("auto_create_rule"), True):
                return PluginResult(
                    False,
                    f"模板 {config.get('template_id')} 下没有可容纳新 IP 的规则，且 auto_create_rule=false；"
                    f"请在控制台该模板内手动创建 IP 黑名单规则并命名为 {prefix}（可续 {prefix}-2/-3）",
                )
            if len(shards) >= max_rules:
                return PluginResult(
                    False,
                    f"已达分片上限 {max_rules} × {max_entries} 条，无法继续下发；"
                    f"请清理黑名单或调大 max_rules",
                )
            index = max((s["index"] for s in shards), default=0) + 1
            name = prefix if index == 1 else f"{prefix}-{index}"
            self._write(config, name, [ioc_value])
            expected = [ioc_value]

        if not self._contains(config, ioc_value):
            # 并发覆盖保护：重读未命中则按最新列表再写一次
            shards = self._shards(config)
            again = next((s for s in shards if s["name"] == name), None)
            if again is None:
                self._write(config, name, expected)
            else:
                merged = [*again["ips"], ioc_value] if ioc_value not in again["ips"] else again["ips"]
                self._write(config, name, merged, again["id"], again["status"] or 1)
            if not self._contains(config, ioc_value):
                return PluginResult(False, f"写入后回读未发现 {ioc_value}，可能被并发覆盖，请重试")

        return PluginResult(
            True,
            f"已写入规则 {name}（该规则当前 {len(expected)} 条，上限 {max_entries}）",
            raw=json.dumps({"rule": name, "count": len(expected)}, ensure_ascii=False),
        )

    def _unblock(self, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        shards = self._shards(config)
        for shard in shards:
            if ioc_value not in shard["ips"]:
                continue
            remaining = [ip for ip in shard["ips"] if ip != ioc_value]
            self._write(config, shard["name"], remaining, shard["id"], shard["status"] or 1)
            if self._contains(config, ioc_value):
                return PluginResult(False, f"已从 {shard['name']} 移除，但回读仍存在，请重试")
            note = "，规则已置为停用" if not remaining else ""
            return PluginResult(
                True,
                f"已从规则 {shard['name']} 解封（剩余 {len(remaining)} 条{note}）",
                raw=json.dumps({"rule": shard["name"], "count": len(remaining)}, ensure_ascii=False),
            )
        return PluginResult(True, "该 IP 不在 WAF 黑名单中（可能已解封或已过期）")

    def _act(self, operation: str, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        self.validate_config(config)
        if as_int(config.get("template_id"), 0) <= 0:
            raise PluginConfigError("template_id 必须是正整数（IP 黑名单模板 ID）")
        with _LOCK:
            try:
                if operation == "BLOCK":
                    return self._block(ioc_value, config)
                return self._unblock(ioc_value, config)
            except AliyunApiError as exc:
                return PluginResult(False, f"阿里云 API 返回错误: {exc}")
            except requests.RequestException as exc:
                return PluginResult(False, f"请求阿里云失败: {exc.__class__.__name__}: {exc}")

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        """只读：校验 AK、实例、模板三者匹配，并列出本插件管理的规则；不写任何数据。"""
        self.validate_config(config)
        template_id = as_int(config.get("template_id"), 0)
        try:
            instance = self._rpc("DescribeInstance", {"InstanceId": config["instance_id"]}, config)
            template = self._rpc(
                "DescribeDefenseTemplate",
                {"InstanceId": config["instance_id"], "TemplateId": template_id},
                config,
            ).get("Template") or {}
            shards = self._shards(config)
        except AliyunApiError as exc:
            return PluginResult(False, f"连通性测试失败: {exc}")
        except requests.RequestException as exc:
            return PluginResult(False, f"连通性测试失败: 请求异常 {exc.__class__.__name__}")

        scene = str(template.get("DefenseScene") or "")
        if scene and scene != SCENE:
            return PluginResult(
                False,
                f"模板 {template_id}（{template.get('TemplateName', '未命名')}）的场景是 {scene}，"
                f"不是 {SCENE}；请填 IP 黑名单模板的 ID",
            )
        status = instance.get("InstanceStatus") or instance.get("Status") or "unknown"
        detail = "、".join(f"{s['name']}({len(s['ips'])}条)" for s in shards) or "暂无（首次封禁将创建）"
        return PluginResult(
            True,
            f"AK 与实例可用（状态 {status}），模板 {template.get('TemplateName') or template_id} 场景 {scene or SCENE}，"
            f"当前规则：{detail}",
            raw=json.dumps(
                {"template": template.get("TemplateName"), "scene": scene, "shards": [s["name"] for s in shards]},
                ensure_ascii=False,
            ),
        )

    def block(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act("BLOCK", req.ioc_value, target.config)

    def unblock(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act("UNBLOCK", req.ioc_value, target.config)
