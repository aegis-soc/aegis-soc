"""Mock 设备插件：只记录任务与日志，不调用任何真实设备。

用于开箱即用的闭环演示、CI 与单元测试；默认示例设备即使用本插件。
"""
from __future__ import annotations

import json
import logging
from typing import Any

from plugins.base import BasePlugin, PluginResult
from plugins.context import ActionRequest, DeviceTarget

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

    def _act(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        record = {
            "plugin": "mock",
            "device": target.code or target.address,
            "operation": req.operation,
            "ioc_type": req.ioc_type,
            "ioc_value": req.ioc_value,
        }
        if target.get("mode") != "silent":
            logger.info("[mock] %s %s %s on %s", req.operation, req.ioc_type,
                        req.ioc_value, target.code or "-")
        return PluginResult(True, "mock 已记录任务（未真实下发）", raw=json.dumps(record, ensure_ascii=False))

    def block(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act(target, req)

    def unblock(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act(target, req)

    def query_status(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act(target, req)
