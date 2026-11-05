"""插件执行上下文：把「哪台设备」「封什么」「做什么」拆成显式参数。

设计目标（v1.1 P1）：

- **插件是类型，设备是实例**。``DeviceTarget`` 代表一台具体设备，一个插件可服务多台；
  设备地址、业务参数、凭据分三层存放，不再混在一个扁平 dict 里。
- **调用形状与业务语义一致**：``execute(target, req)`` 即「对哪台设备 + 封/解哪个 IOC」。
- **旧格式零迁移**：``DeviceTarget.from_flat()`` 把历史上的扁平 ``config_json``
  按字段名自动拆层；插件内部仍可用 ``target.config`` 拿到合并后的扁平视图。

三层配置的优先级（后者覆盖前者）：``params`` < ``connection`` < ``secrets``。
凭据永远最后覆盖，避免数据库里的参数把真实口令顶掉。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# 归属「怎么连到设备」的字段：地址、端口、TLS、超时
CONNECTION_KEYS = {
    "host",
    "base_url",
    "endpoint",
    "region_id",
    "port",
    "verify_ssl",
    "timeout",
}

# 归属「凭据」的字段：只应来自 credential_ref 指向的环境变量
SECRET_KEYS = {
    "password",
    "secret",
    "api_key",
    "token",
    "authorization",
    "access_key_id",
    "access_key_secret",
}


@dataclass(frozen=True)
class DeviceLimits:
    """单台设备的执行约束。P1 先承载字段，限流/熔断在 P3 接入调度层。"""

    timeout: int = 10
    max_qps: float = 0.0          # 0 = 不限
    max_concurrency: int = 0      # 0 = 不限


@dataclass(frozen=True)
class DeviceTarget:
    """一台具体设备：插件类型的实例。"""

    code: str
    plugin_code: str
    connection: dict[str, Any] = field(default_factory=dict)
    params: dict[str, Any] = field(default_factory=dict)
    secrets: dict[str, Any] = field(default_factory=dict)
    id: int | None = None
    limits: DeviceLimits = field(default_factory=DeviceLimits)
    credential_missing: str = ""

    @property
    def address(self) -> str:
        """人类可读的设备地址：SSH 取 host，HTTP 类取 base_url/endpoint。"""
        for key in ("host", "base_url", "endpoint"):
            value = str(self.connection.get(key) or "").strip()
            if value:
                return value
        return ""

    @property
    def config(self) -> dict[str, Any]:
        """合并后的扁平视图，兼容既有插件的 ``config.get(...)`` 写法。"""
        merged: dict[str, Any] = {**self.params, **self.connection, **self.secrets}
        if self.credential_missing:
            merged["_credential_missing"] = self.credential_missing
        return merged

    def get(self, key: str, default: Any = None) -> Any:
        """按层查找单个配置，顺序：secrets → connection → params。"""
        for layer in (self.secrets, self.connection, self.params):
            if key in layer and layer[key] not in (None, ""):
                return layer[key]
        return default

    @classmethod
    def from_flat(
        cls,
        config: dict[str, Any] | None,
        *,
        id: int | None = None,
        code: str = "",
        plugin_code: str = "",
        limits: DeviceLimits | None = None,
    ) -> "DeviceTarget":
        """从设备配置构造 target。

        支持两种写法，可混用（顶层字段优先）：
        - 分层：``{"connection": {...}, "params": {...}}``
        - 扁平：``{"base_url": "...", "tag_name": "..."}``，按字段名自动拆层
        """
        flat = dict(config or {})
        credential_missing = str(flat.pop("_credential_missing", "") or "")
        connection: dict[str, Any] = {}
        secrets: dict[str, Any] = {}
        params: dict[str, Any] = {}
        for layer, bucket in (
            ("connection", connection),
            ("params", params),
            ("secrets", secrets),
        ):
            nested = flat.pop(layer, None)
            if isinstance(nested, dict):
                bucket.update(nested)
        for key, value in flat.items():
            if key in CONNECTION_KEYS:
                connection[key] = value
            elif key in SECRET_KEYS:
                secrets[key] = value
            else:
                params[key] = value
        if limits is None:
            limits = DeviceLimits(
                timeout=int(connection.get("timeout") or 10),
                max_qps=float(params.pop("max_qps", 0) or 0),
                max_concurrency=int(params.pop("max_concurrency", 0) or 0),
            )
        return cls(
            id=id,
            code=code,
            plugin_code=plugin_code,
            connection=connection,
            params=params,
            secrets=secrets,
            limits=limits,
            credential_missing=credential_missing,
        )


@dataclass(frozen=True)
class ActionRequest:
    """一次动作请求：封禁 / 解封 / 查询哪个 IOC。"""

    operation: str
    ioc_value: str
    ioc_type: str = "IP"
    duration_minutes: int = 0     # 0 = 用插件默认值（各插件自行解释）
    reason: str = ""              # 触发来源说明，便于审计与 raw 留痕
    policy_code: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "operation", str(self.operation).upper())
