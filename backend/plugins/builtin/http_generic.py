"""通用 HTTP 设备插件（低代码）。

通过配置 URL / HTTP 方法 / 请求头 / 请求体模板适配任意 REST 型安全设备，
无需为每款设备编写 Python 代码。模板占位符：
{ioc_value} {ioc_type} {operation} {timestamp}
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import requests

from plugins.base import BasePlugin, PluginConfigError, PluginResult


class HttpGenericPlugin(BasePlugin):
    plugin_code = "http_generic"
    plugin_name = "通用 HTTP 设备"
    version = "1.0.0"
    ioc_types = ["IP", "DOMAIN"]
    capabilities = ["BLOCK", "UNBLOCK", "QUERY"]
    description = "通过 URL / 方法 / 请求体模板适配任意 REST 型设备 API"
    config_schema = {
        "base_url": "string（必填）",
        "method": "string（默认 POST）",
        "headers": "object（请求头，敏感值请勿写入数据库）",
        "body_template": "string（支持 {ioc_value} 等占位符）",
        "timeout": "int（秒，默认 10）",
        "verify_ssl": "bool（默认 true）",
    }

    def _render(self, template: str, ioc_value: str, ioc_type: str, operation: str) -> str:
        values = {
            "{ioc_value}": ioc_value,
            "{ioc_type}": ioc_type,
            "{operation}": operation,
            "{timestamp}": datetime.now(timezone.utc).isoformat(),
        }
        for placeholder, value in values.items():
            template = template.replace(placeholder, str(value))
        return template

    def _request(self, operation: str, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        base_url = str(config.get("base_url") or "").rstrip("/")
        if not base_url:
            raise PluginConfigError("缺少 base_url")
        method = str(config.get(f"{operation.lower()}_method") or config.get("method") or "POST").upper()
        template = str(
            config.get(f"{operation.lower()}_body_template")
            or config.get("body_template")
            or '{"ip":"{ioc_value}","action":"{operation}"}'
        )
        payload = self._render(template, ioc_value, ioc_type, operation)
        path = str(config.get(f"{operation.lower()}_path") or config.get("path") or "")
        url = f"{base_url}/{path.lstrip('/')}" if path else base_url
        headers = dict(config.get("headers") or {})
        timeout = int(config.get("timeout") or self.default_timeout)
        verify = bool(config.get("verify_ssl", True))

        response = requests.request(
            method, url, data=payload.encode("utf-8"), headers=headers,
            timeout=timeout, verify=verify,
        )
        success = 200 <= response.status_code < 300
        return PluginResult(
            success,
            f"HTTP {response.status_code}",
            raw=response.text[:4000],
            http_status=response.status_code,
        )

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        base_url = str(config.get("base_url") or "").rstrip("/")
        if not base_url:
            raise PluginConfigError("缺少 base_url")
        try:
            response = requests.get(
                base_url,
                timeout=int(config.get("timeout") or self.default_timeout),
                verify=bool(config.get("verify_ssl", True)),
            )
            return PluginResult(
                True, f"连通性正常 HTTP {response.status_code}",
                raw=response.text[:1000], http_status=response.status_code,
            )
        except requests.RequestException as exc:
            return PluginResult(False, f"连通性测试失败: {exc}", raw=str(exc))

    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._request("BLOCK", ioc_value, ioc_type, config)

    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._request("UNBLOCK", ioc_value, ioc_type, config)

    def query_status(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._request("QUERY", ioc_value, ioc_type, config)
