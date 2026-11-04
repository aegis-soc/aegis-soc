"""插件注册表：注册式发现，规避 Go/Python 动态插件的跨平台坑。

新增插件：实现 BasePlugin → 在 plugins/builtin/__init__.py 的 register_builtins 中注册。
"""
from __future__ import annotations

import logging
from typing import Any

from plugins.base import BasePlugin, PluginResult

logger = logging.getLogger("aegis")
_plugins: dict[str, BasePlugin] = {}
_initialized = False


def register(plugin: BasePlugin | type[BasePlugin]) -> None:
    instance = plugin() if isinstance(plugin, type) else plugin
    if not instance.plugin_code:
        raise ValueError("插件必须声明 plugin_code")
    if instance.plugin_code in _plugins:
        raise ValueError(f"插件重复注册: {instance.plugin_code}")
    _plugins[instance.plugin_code] = instance
    logger.debug("插件已注册: %s", instance.plugin_code)


def register_all() -> None:
    global _initialized
    if _initialized:
        return
    from plugins.builtin import register_builtins

    register_builtins(register)
    _initialized = True


def get(code: str) -> BasePlugin | None:
    register_all()
    return _plugins.get(code)


def get_manifest(code: str) -> dict[str, Any] | None:
    plugin = get(code)
    if plugin is None:
        return None
    manifest = plugin.manifest()
    return {
        "plugin_code": manifest.plugin_code,
        "plugin_name": manifest.plugin_name,
        "version": manifest.version,
        "ioc_types": manifest.ioc_types,
        "capabilities": manifest.capabilities,
        "config_schema": manifest.config_schema,
        "description": manifest.description,
    }


def list_manifests() -> list[dict[str, Any]]:
    register_all()
    result: list[dict[str, Any]] = []
    for code in sorted(_plugins):
        plugin = _plugins[code]
        manifest = plugin.manifest()
        result.append(
            {
                "plugin_code": code,
                "plugin_name": manifest.plugin_name,
                "version": manifest.version,
                "manifest": manifest.to_dict(),
                "description": manifest.description,
            }
        )
    return result


def test_plugin(code: str, config: dict[str, Any]) -> dict[str, Any]:
    plugin = get(code)
    if plugin is None:
        return {"success": False, "message": f"插件未注册: {code}", "raw": ""}
    return plugin.test_connection(config or {}).to_dict()


def execute(
    code: str,
    operation: str,
    ioc_value: str,
    ioc_type: str,
    config: dict[str, Any],
) -> PluginResult:
    plugin = get(code)
    if plugin is None:
        return PluginResult(False, f"插件未注册: {code}")
    return plugin.execute(operation, ioc_value, ioc_type, config or {})


register_all()
