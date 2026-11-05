"""插件 SDK：统一接口、能力声明（Manifest）与执行结果。

新增设备插件只需继承 BasePlugin 并在 plugins/builtin/__init__.py 注册，
平台主体（策略引擎、任务调度、前端配置向导）无需改动。
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

VALID_OPERATIONS = {"BLOCK", "UNBLOCK", "QUERY"}


@dataclass
class PluginResult:
    success: bool
    message: str = ""
    raw: str = ""
    http_status: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "raw": self.raw[:4000],
            "http_status": self.http_status,
        }


@dataclass
class Manifest:
    plugin_code: str
    plugin_name: str
    version: str = "1.0.0"
    ioc_types: list[str] = field(default_factory=lambda: ["IP"])
    capabilities: list[str] = field(default_factory=lambda: ["BLOCK", "UNBLOCK"])
    config_schema: dict[str, str] = field(default_factory=dict)
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_types": self.ioc_types,
            "capabilities": self.capabilities,
            "config_schema": self.config_schema,
            "description": self.description,
        }


class PluginConfigError(Exception):
    """插件配置缺失或非法（不构成任务失败重试的硬件故障，直接判定失败并留痕）。"""


def as_bool(value: Any, default: bool = False) -> bool:
    """把 JSON / 表单里的各种写法统一成 bool，避免字符串 "false" 被当成 True。"""
    if value is None or value == "":
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def as_int(value: Any, default: int) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


class BasePlugin(ABC):
    plugin_code: str = ""
    plugin_name: str = ""
    version: str = "1.0.0"
    ioc_types: list[str] = ["IP"]
    capabilities: list[str] = ["BLOCK", "UNBLOCK"]
    config_schema: dict[str, str] = {}
    # 必填配置键：为空则跳过校验；口令类字段由 credential_ref 注入，也需在此声明
    required_config: list[str] = []
    description: str = ""
    default_timeout: int = 10

    def validate_config(self, config: dict[str, Any]) -> None:
        """检查必填项与凭据注入结果，缺失即抛 PluginConfigError（不重试、直接留痕）。"""
        missing_credential = str(config.get("_credential_missing") or "").strip()
        if missing_credential:
            raise PluginConfigError(
                f"凭据环境变量 {missing_credential} 未设置或为空，无法取得口令"
            )
        missing = [
            key for key in self.required_config
            if not str(config.get(key) or "").strip()
        ]
        if missing:
            raise PluginConfigError(f"缺少必填配置: {', '.join(missing)}")

    def safe_test_connection(self, config: dict[str, Any]) -> PluginResult:
        """连通性测试的安全封装：任何异常都收敛为失败结果，绝不向上冒泡成 HTTP 500。"""
        try:
            self.validate_config(config or {})
            return self.test_connection(config or {})
        except PluginConfigError as exc:
            return PluginResult(False, f"插件配置错误: {exc}")
        except Exception as exc:  # noqa: BLE001
            return PluginResult(False, f"连通性测试异常: {exc.__class__.__name__}: {exc}")

    def manifest(self) -> Manifest:
        return Manifest(
            plugin_code=self.plugin_code,
            plugin_name=self.plugin_name,
            version=self.version,
            ioc_types=list(self.ioc_types),
            capabilities=list(self.capabilities),
            config_schema=dict(self.config_schema),
            description=self.description,
        )

    @abstractmethod
    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        """连通性测试，不产生任何封禁副作用。"""

    @abstractmethod
    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        """下发封禁。"""

    @abstractmethod
    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        """下发解封。"""

    def query_status(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        """默认不实现状态查询：必须显式返回失败，避免伪造“查询成功”。"""
        return PluginResult(
            False,
            f"插件 {self.plugin_code} 未实现状态查询（QUERY）",
            raw="",
        )

    def execute(
        self,
        operation: str,
        ioc_value: str,
        ioc_type: str,
        config: dict[str, Any],
    ) -> PluginResult:
        operation = operation.upper()
        if operation not in VALID_OPERATIONS:
            return PluginResult(False, f"不支持的操作: {operation}")
        if ioc_type not in self.ioc_types:
            return PluginResult(False, f"插件 {self.plugin_code} 不支持 IOC 类型 {ioc_type}")
        if operation not in self.capabilities:
            return PluginResult(False, f"插件 {self.plugin_code} 不支持能力 {operation}")
        handler = {
            "BLOCK": self.block,
            "UNBLOCK": self.unblock,
            "QUERY": self.query_status,
        }[operation]
        try:
            self.validate_config(config)
            return handler(ioc_value, ioc_type, config)
        except PluginConfigError as exc:
            return PluginResult(False, f"插件配置错误: {exc}")
        except Exception as exc:  # noqa: BLE001 - 插件异常必须收敛为失败结果，避免 worker 崩溃
            return PluginResult(False, f"插件执行异常: {exc.__class__.__name__}: {exc}")
