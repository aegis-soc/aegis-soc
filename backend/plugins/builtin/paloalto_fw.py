"""Palo Alto PAN-OS 防火墙插件（user-id + Dynamic Address Group）。

原理：把 IP 以 user-id 消息注册到指定 Tag，PA 上由 Dynamic Address Group 引用该 Tag，
拒绝策略再引用 DAG。user-id 更新即时生效，不需要 commit，适合秒级自动封禁。

前置条件（PA 侧一次性配置）：
1. 创建 Tag（默认 aegis-block）；
2. 创建 Dynamic Address Group，Match 条件为 `'aegis-block'`；
3. 在拒绝策略的目的地址中引用该 DAG；
4. 生成 API Key（https://<fw>/api/?type=keygen&user=<admin>&password=<pwd>），
   写入环境变量（JSON：{"api_key": "..."}），设备侧只填 credential_ref。

⚠️ unregister 需要 PAN-OS 9.1+；低版本请改用地址组静态成员方案（需 commit，延迟更大）。
"""
from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any
from xml.sax.saxutils import escape

import requests
import urllib3

from plugins.base import BasePlugin, PluginResult, as_bool, as_int
from plugins.context import ActionRequest, DeviceTarget

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

API_PATH = "/api/"


class PaloAltoFwPlugin(BasePlugin):
    plugin_code = "paloalto_fw"
    plugin_name = "Palo Alto PAN-OS"
    credential_hint = "PA_API_KEY"   # 值为 {"api_key":"..."}
    version = "1.0.0"
    ioc_types = ["IP"]
    capabilities = ["BLOCK", "UNBLOCK"]
    description = "PAN-OS XML API：user-id 注册 IP 到 DAG tag，即时生效、无需 commit"
    config_schema = {
        "base_url": "string（必填，如 https://10.0.0.1）",
        "credential_ref": 'string（环境变量名，JSON：{"api_key":"..."}）',
        "vsys": "string（默认 vsys1）",
        "tag_name": "string（默认 aegis-block，需在 PA 上预先创建）",
        "verify_ssl": "bool（默认 false，设备多为自签证书）",
        "timeout": "int（秒，默认 10）",
    }
    required_config = ["base_url", "api_key"]
    default_timeout = 10

    def _request(self, config: dict[str, Any], params: dict[str, str], body: str = "") -> PluginResult:
        url = str(config["base_url"]).rstrip("/") + API_PATH
        query = {"key": str(config["api_key"]), **params}
        try:
            response = requests.post(
                url,
                params=query,
                data=body.encode("utf-8"),
                timeout=as_int(config.get("timeout"), self.default_timeout),
                verify=as_bool(config.get("verify_ssl"), False),
            )
        except requests.RequestException as exc:
            return PluginResult(False, f"请求 PAN-OS 失败: {exc.__class__.__name__}: {exc}")

        raw = response.text[:4000]
        try:
            root = ET.fromstring(response.text)
        except ET.ParseError:
            return PluginResult(
                False,
                f"PAN-OS 响应非 XML（HTTP {response.status_code}）",
                raw=raw,
                http_status=response.status_code,
            )
        # PAN-OS 业务失败也返回 HTTP 200，必须解析 status 属性，不能只看状态码
        if root.attrib.get("status") != "success":
            detail = " ".join(t.strip() for t in root.itertext() if t.strip())[:200]
            code = root.attrib.get("code", "?")
            return PluginResult(
                False,
                f"PAN-OS 返回失败（code={code}）: {detail}",
                raw=raw,
                http_status=response.status_code,
            )
        return PluginResult(True, "PAN-OS 执行成功", raw=raw, http_status=response.status_code)

    def _uid_message(self, operation: str, ioc_value: str, config: dict[str, Any]) -> str:
        vsys = escape(str(config.get("vsys") or "vsys1"))
        tag = escape(str(config.get("tag_name") or "aegis-block"))
        ip = escape(ioc_value)
        if operation == "BLOCK":
            payload = (
                f'<register><entry ip="{ip}" vsys="{vsys}">'
                f"<tag><member>{tag}</member></tag></entry></register>"
            )
        else:
            payload = f'<unregister><entry ip="{ip}" vsys="{vsys}"/></unregister>'
        return (
            "<uid-message><version>1.0</version><type>update</type>"
            f"<payload>{payload}</payload></uid-message>"
        )

    def _act(self, operation: str, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        self.validate_config(config)
        return self._request(
            config,
            {"type": "user-id", "action": "set"},
            self._uid_message(operation, ioc_value, config),
        )

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        """只读命令，不产生任何封禁副作用。"""
        self.validate_config(config)
        return self._request(
            config,
            {"type": "op", "cmd": "<show><system><info></info></system></show>"},
        )

    def block(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act("BLOCK", req.ioc_value, target.config)

    def unblock(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act("UNBLOCK", req.ioc_value, target.config)
