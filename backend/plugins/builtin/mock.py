"""Mock 设备插件：只记录任务与日志，不调用任何真实设备。

用于开箱即用的闭环演示、CI 与单元测试；默认示例设备即使用本插件。
"""
from __future__ import annotations

import json
import logging
from typing import Any

from plugins.base import BasePlugin, PluginResult

logger = logging.getLogger("aegis")


class MockPlugin(BasePlugin):
    plugin_code = "mock"
    plugin_name = "Mock 测试设备"
    version = "1.0.0"
    ioc_types = ["IP", "DOMAIN"]
    capabilities = ["BLOCK", "UNBLOCK", "QUERY"]
    description = "只记录任务不真实下发，用于闭环演示与单元测试"
    config_schema = {"mode": "string（可选，log / silent）"}

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        return PluginResult(True, "mock 插件连通性正常（无需真实设备）", raw="")

    def _act(self, operation: str, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        record = {"plugin": "mock", "operation": operation, "ioc_type": ioc_type, "ioc_value": ioc_value}
        if config.get("mode") != "silent":
            logger.info("[mock] %s %s %s", operation, ioc_type, ioc_value)
        return PluginResult(True, "mock 已记录任务（未真实下发）", raw=json.dumps(record, ensure_ascii=False))

    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._act("BLOCK", ioc_value, ioc_type, config)

    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._act("UNBLOCK", ioc_value, ioc_type, config)

    def query_status(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._act("QUERY", ioc_value, ioc_type, config)
