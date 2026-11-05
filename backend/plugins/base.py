"""插件 SDK：统一接口、能力声明（Manifest）与执行结果。

新增设备插件只需继承 BasePlugin 并在 plugins/builtin/__init__.py 注册，
平台主体（策略引擎、任务调度、前端配置向导）无需改动。
"""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from plugins.context import ActionRequest, DeviceTarget

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


# 配置字段的中文名：界面向导据此渲染表单，只有 credential_ref 不出现在表单里
FIELD_LABELS: dict[str, str] = {
    "base_url": "设备地址",
    "host": "设备地址",
    "endpoint": "服务地址",
    "region_id": "地域",
    "port": "端口",
    "timeout": "超时（秒）",
    "verify_ssl": "校验 TLS 证书",
    "username": "账号",
    "instance_id": "WAF 实例 ID",
    "template_id": "模板 ID",
    "rule_name": "规则名",
    "action": "动作",
    "max_entries": "单规则上限",
    "max_rules": "分片上限",
    "auto_create_rule": "自动建规则",
    "method": "请求方法",
    "headers": "请求头",
    "body_template": "请求体模板",
    "mode": "运行模式",
    "vsys": "虚拟系统",
    "tag_name": "标签名",
    "login_path": "登录路径",
    "login_body": "登录报文",
    "token_path": "Token 路径",
    "token_header": "Token 头",
    "token_prefix": "Token 前缀",
    "block_path": "封禁路径",
    "unblock_path": "解封路径",
    "block_body": "封禁报文",
    "unblock_body": "解封报文",
    "save_path": "保存生效路径",
    "block_type": "封禁类型",
    "end_time_minutes": "封禁时长（分钟）",
    "enable": "启用策略",
    "protocol": "协议",
    "src_port": "源端口",
    "dst_ip": "目的 IP",
    "dst_port": "目的端口",
    "password_hash": "口令摘要方式",
    "sha256_uppercase": "摘要大写",
    "token_ttl": "Token 缓存（秒）",
    "vendor": "厂商型号",
    "timeout_minutes": "封禁时长（分钟）",
}

# 只能由 credential_ref 注入的字段，界面不渲染，也禁止写进数据库
SECRET_FIELD_KEYS = {"credential_ref", "password", "secret", "api_key", "access_key_id", "access_key_secret"}

# 归入「设备连接」分组的字段，其余归「业务参数」
CONNECTION_FIELD_KEYS = {
    "host", "base_url", "endpoint", "region_id", "port", "verify_ssl", "timeout", "username",
}

_DEFAULT_RE = re.compile(r"默认\s*([^，,；;）)\s]+)")


def _field_type(text: str) -> tuple[str, list[str]]:
    """从 `int（默认 10）` 这类说明里解析出控件类型与枚举选项。"""
    head = str(text or "").split("（")[0].split("(")[0].strip().strip("`")
    if head in {"string", "int", "bool", "float", "object", "list"}:
        return head, []
    if "|" in head:
        return "enum", [part.strip().strip("`") for part in head.split("|") if part.strip()]
    return "string", []


def _field_default(text: str, ftype: str, options: list[str]) -> Any:
    match = _DEFAULT_RE.search(str(text or ""))
    if not match:
        return None
    raw = match.group(1).strip().strip("\"'`")
    if ftype == "bool":
        return as_bool(raw, False)
    if ftype in {"int", "float"}:
        try:
            return int(raw) if ftype == "int" else float(raw)
        except ValueError:
            return None
    if ftype == "enum":
        return raw if raw in options else None
    return raw


def build_config_fields(schema: dict[str, str], required: list[str]) -> list[dict[str, Any]]:
    """把插件的 config_schema 变成前端可直接渲染的字段描述。

    每个字段带：key / label / group / type / required / options / default / description。
    界面不需要认识任何插件细节，新增插件自动获得可视化表单。
    """
    fields: list[dict[str, Any]] = []
    for key, text in schema.items():
        if key in SECRET_FIELD_KEYS:
            continue
        ftype, options = _field_type(text)
        fields.append(
            {
                "key": key,
                "label": FIELD_LABELS.get(key, key),
                "group": "connection" if key in CONNECTION_FIELD_KEYS else "params",
                "type": ftype,
                "required": key in required or "必填" in str(text),
                "options": options,
                "default": _field_default(text, ftype, options),
                "description": str(text),
                "address": key in {"host", "base_url", "endpoint"},
            }
        )
    # 设备地址排最前，其次连接类，最后业务参数
    fields.sort(key=lambda f: (0 if f["address"] else 1 if f["group"] == "connection" else 2))
    return fields


@dataclass
class Manifest:
    plugin_code: str
    plugin_name: str
    version: str = "1.0.0"
    ioc_types: list[str] = field(default_factory=lambda: ["IP"])
    capabilities: list[str] = field(default_factory=lambda: ["BLOCK", "UNBLOCK"])
    config_schema: dict[str, str] = field(default_factory=dict)
    description: str = ""
    required_config: list[str] = field(default_factory=list)
    credential_hint: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ioc_types": self.ioc_types,
            "capabilities": self.capabilities,
            "config_schema": self.config_schema,
            "required_config": self.required_config,
            "credential_hint": self.credential_hint,
            "config_fields": build_config_fields(self.config_schema, self.required_config),
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
    # 界面「凭据环境变量」的建议名字，仅为填空提示，不参与鉴权
    credential_hint: str = ""
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
            required_config=list(self.required_config),
            credential_hint=self.credential_hint,
        )

    @abstractmethod
    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        """连通性测试，不产生任何封禁副作用。

        只验证「能不能连上、凭据对不对」，与具体设备实例无关，
        因此保持扁平 config 入参，便于界面在保存设备前先测一次。
        """

    @abstractmethod
    def block(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        """对某台设备下发封禁。"""

    @abstractmethod
    def unblock(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        """对某台设备下发解封。"""

    def query_status(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        """默认不实现状态查询：必须显式返回失败，避免伪造“查询成功”。"""
        return PluginResult(
            False,
            f"插件 {self.plugin_code} 未实现状态查询（QUERY）",
            raw="",
        )

    def execute(
        self,
        target: DeviceTarget | str,
        req: ActionRequest | str | None = None,
        ioc_type: str | None = None,
        config: dict[str, Any] | None = None,
    ) -> PluginResult:
        """统一执行入口。

        推荐写法：``execute(DeviceTarget, ActionRequest)`` —— 设备、IOC、动作三者显式。
        兼容写法：``execute("BLOCK", "1.2.3.4", "IP", config)`` —— 由扁平配置临时构造 target。
        """
        if isinstance(target, DeviceTarget):
            if not isinstance(req, ActionRequest):
                return PluginResult(False, "execute 需要 ActionRequest 作为第二个参数")
            device, action = target, req
        else:
            device = DeviceTarget.from_flat(config or {}, plugin_code=self.plugin_code)
            action = ActionRequest(str(target), str(req or ""), str(ioc_type or "IP"))

        operation = action.operation
        if operation not in VALID_OPERATIONS:
            return PluginResult(False, f"不支持的操作: {operation}")
        if action.ioc_type not in self.ioc_types:
            return PluginResult(
                False, f"插件 {self.plugin_code} 不支持 IOC 类型 {action.ioc_type}"
            )
        if operation not in self.capabilities:
            return PluginResult(False, f"插件 {self.plugin_code} 不支持能力 {operation}")
        handler = {
            "BLOCK": self.block,
            "UNBLOCK": self.unblock,
            "QUERY": self.query_status,
        }[operation]
        try:
            self.validate_config(device.config)
            return handler(device, action)
        except PluginConfigError as exc:
            return PluginResult(False, f"插件配置错误: {exc}")
        except Exception as exc:  # noqa: BLE001 - 插件异常必须收敛为失败结果，避免 worker 崩溃
            return PluginResult(False, f"插件执行异常: {exc.__class__.__name__}: {exc}")
