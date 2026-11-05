"""启明星辰 天清 IPS 插件（REST API v3）。

接口依据（厂商《API 接口说明》，IPS *080 及以上版本）：

- 登录：``POST /api/v3/login``，请求体 ``{"username": "...", "password": "<SHA256>"}``，
  响应 ``{"code": 0, "msg": "success", "data": {"authorization": "<JWT>"}}``；
- 封堵：``POST /api/v3/block_policy``，请求头 ``Authorization: <JWT>``，
  ``type`` 1=五元组 2=域名 3=URL 4=IP 5=XFF，``block_content`` 为封禁对象，
  ``end_time`` 单位**分钟**，``0`` 表示永久生效，``enable`` 0/1（*080SP3 起支持）。

两个刻意的设计：

1. **口令先做 SHA256 再发送**。设备要的是摘要值，不是明文；``password_hash`` 可切 ``plain``
   以兼容改过认证方式的版本，``sha256_uppercase`` 应对个别要求大写十六进制的固件。
2. **只声明 BLOCK 能力**。这份文档没有删除/查询封堵策略的接口，无法保证解封真的生效，
   因此不声明 UNBLOCK——到期解封由设备自身的 ``end_time`` 完成。
   等拿到删除接口文档，补 ``unblock()`` 并把 ``capabilities`` 加上 UNBLOCK 即可。

token 按 (base_url, username) 缓存，遇到 401 自动重新登录一次再重试，避免每条封禁都登录。
"""
from __future__ import annotations

import hashlib
import threading
import time
from typing import Any

import requests
import urllib3

from plugins.base import BasePlugin, PluginConfigError, PluginResult, as_bool, as_int

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/api/v3/login"
BLOCK_PATH = "/api/v3/block_policy"

# IOC 类型 → 设备封禁类型（type）
IOC_TYPE_MAP = {"IP": 4, "DOMAIN": 2, "URL": 3}

# token 缓存：(base_url, username) -> (token, 过期时间 monotonic)
_TOKEN_CACHE: dict[tuple[str, str], tuple[str, float]] = {}
_CACHE_LOCK = threading.Lock()


class QimingIpsError(Exception):
    """设备返回的业务错误（code != 0）或协议错误。"""


class QimingIpsPlugin(BasePlugin):
    plugin_code = "qiming_ips"
    plugin_name = "启明星辰 天清IPS"
    version = "1.0.0"
    ioc_types = ["IP", "DOMAIN"]
    # 未提供删除/查询封堵策略的接口文档，不声明 UNBLOCK，避免"解封成功"其实没生效
    capabilities = ["BLOCK"]
    description = "天清IPS REST API v3：登录取 JWT → block_policy 封堵，到期由设备自动失效"
    config_schema = {
        "base_url": "string（必填，https://<设备IP>:<端口>）",
        "username": "string（必填，API 账号）",
        "credential_ref": "string（必填，环境变量名，值为登录口令明文，插件内部做 SHA256）",
        "block_type": "int（默认按 IOC 类型: IP=4 / 域名=2 / URL=3；1=五元组 5=XFF）",
        "end_time_minutes": "int（封禁时长，默认 120 分钟；0=永久）",
        "enable": "int（0/1，默认 1；*080SP3 起支持）",
        "protocol": "string（type=1 时有效：ANY/TCP/UDP/OTHER，默认 ANY）",
        "src_port": "int（type=1 时有效，默认 0 不限）",
        "dst_ip": "string（type=1 时有效，默认 0.0.0.0 不限）",
        "dst_port": "int（type=1 时有效，默认 0 不限）",
        "password_hash": "string（sha256/plain，默认 sha256）",
        "sha256_uppercase": "bool（默认 false，个别固件要大写摘要）",
        "token_ttl": "int（token 缓存秒数，默认 1500）",
        "login_path": "string（默认 /api/v3/login）",
        "block_path": "string（默认 /api/v3/block_policy）",
        "verify_ssl": "bool（默认 false，设备多为自签证书）",
        "timeout": "int（秒，默认 10）",
    }
    required_config = ["base_url", "username", "password"]
    default_timeout = 10

    # ---------- 基础请求 ----------
    def _url(self, config: dict[str, Any], key: str, default: str) -> str:
        base = str(config["base_url"]).rstrip("/")
        return base + str(config.get(key) or default)

    def _post(
        self,
        config: dict[str, Any],
        url: str,
        body: dict[str, Any],
        token: str | None = None,
    ) -> requests.Response:
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = token
        try:
            return requests.post(
                url,
                json=body,
                headers=headers,
                timeout=as_int(config.get("timeout"), self.default_timeout),
                verify=as_bool(config.get("verify_ssl"), False),
            )
        except requests.RequestException as exc:
            raise QimingIpsError(f"请求设备失败: {exc.__class__.__name__}: {exc}") from exc

    @staticmethod
    def _payload(response: requests.Response) -> dict[str, Any]:
        try:
            payload = response.json()
        except ValueError as exc:
            raise QimingIpsError(
                f"设备响应非 JSON（HTTP {response.status_code}）: {response.text[:200]}"
            ) from exc
        if not isinstance(payload, dict):
            raise QimingIpsError(f"设备响应结构异常: {str(payload)[:200]}")
        return payload

    @classmethod
    def _check_code(cls, payload: dict[str, Any], action: str) -> None:
        code = as_int(payload.get("code"), -1)
        if code != 0:
            message = str(payload.get("msg") or payload.get("message") or "无错误描述")
            raise QimingIpsError(f"{action}失败 code={code}: {message}")

    # ---------- 登录与 token ----------
    def _digest(self, config: dict[str, Any]) -> str:
        password = str(config.get("password") or "")
        if str(config.get("password_hash") or "sha256").strip().lower() == "plain":
            return password
        digest = hashlib.sha256(password.encode("utf-8")).hexdigest()
        if as_bool(config.get("sha256_uppercase"), False):
            return digest.upper()
        return digest

    def _login(self, config: dict[str, Any]) -> str:
        payload = self._payload(
            self._post(
                config,
                self._url(config, "login_path", LOGIN_PATH),
                {"username": str(config["username"]), "password": self._digest(config)},
            )
        )
        self._check_code(payload, "登录")
        data = payload.get("data") or {}
        token = str(data.get("authorization") or "").strip()
        if not token:
            raise QimingIpsError("登录响应缺少 data.authorization，无法取得 token")
        ttl = max(60, as_int(config.get("token_ttl"), 1500))
        with _CACHE_LOCK:
            _TOKEN_CACHE[(str(config["base_url"]).rstrip("/"), str(config["username"]))] = (
                token,
                time.monotonic() + ttl,
            )
        return token

    def _token(self, config: dict[str, Any], force: bool = False) -> str:
        key = (str(config["base_url"]).rstrip("/"), str(config["username"]))
        with _CACHE_LOCK:
            cached = _TOKEN_CACHE.get(key)
        if cached and not force and cached[1] > time.monotonic():
            return cached[0]
        return self._login(config)

    def _drop_token(self, config: dict[str, Any]) -> None:
        key = (str(config["base_url"]).rstrip("/"), str(config["username"]))
        with _CACHE_LOCK:
            _TOKEN_CACHE.pop(key, None)

    # ---------- 业务 ----------
    def _block_body(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> dict[str, Any]:
        explicit = as_int(config.get("block_type"), 0)
        block_type = explicit or IOC_TYPE_MAP.get(ioc_type.upper(), 0)
        if block_type <= 0:
            raise PluginConfigError(f"无法映射 IOC 类型 {ioc_type}，请显式配置 block_type")
        body: dict[str, Any] = {
            "type": block_type,
            "end_time": max(0, as_int(config.get("end_time_minutes"), 120)),
            "enable": 1 if as_bool(config.get("enable"), True) else 0,
        }
        if block_type == 1:
            body.update(
                {
                    "src_ip": ioc_value,
                    "src_port": max(0, as_int(config.get("src_port"), 0)),
                    "dst_ip": str(config.get("dst_ip") or "0.0.0.0"),
                    "dst_port": max(0, as_int(config.get("dst_port"), 0)),
                    "protocol": str(config.get("protocol") or "ANY").upper(),
                }
            )
            if body["protocol"] == "OTHER":
                body["protocol_num"] = as_int(config.get("protocol_num"), 0)
        else:
            body["block_content"] = ioc_value
        return body

    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        self.validate_config(config)
        body = self._block_body(ioc_value, ioc_type, config)
        url = self._url(config, "block_path", BLOCK_PATH)
        try:
            token = self._token(config)
            response = self._post(config, url, body, token)
            if response.status_code == 401:
                self._drop_token(config)
                response = self._post(config, url, body, self._token(config, force=True))
            payload = self._payload(response)
            self._check_code(payload, "封堵")
        except QimingIpsError as exc:
            return PluginResult(False, f"封堵失败: {exc}")
        minutes = body["end_time"]
        duration = "永久" if minutes == 0 else f"{minutes} 分钟"
        return PluginResult(
            True,
            f"封堵成功（type={body['type']}，{ioc_value}，生效 {duration}）",
            raw=str(payload)[:4000],
            http_status=response.status_code,
        )

    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        """设备原生按 end_time 到期失效；未提供删除接口，绝不伪造解封成功。"""
        return PluginResult(
            False,
            f"插件 {self.plugin_code} 未实现解封：厂商文档未提供删除封堵策略接口，"
            f"当前依赖 end_time 到期自动失效；如需即时解封，请补充删除接口后启用 UNBLOCK 能力",
        )

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        """只读：仅登录取 token，不写任何封堵策略。"""
        self.validate_config(config)
        try:
            token = self._login(config)
        except QimingIpsError as exc:
            return PluginResult(False, f"连通性测试失败: {exc}")
        minutes = max(0, as_int(config.get("end_time_minutes"), 120))
        return PluginResult(
            True,
            "登录成功，已取得 API token"
            f"（默认封禁时长 {'永久' if minutes == 0 else f'{minutes} 分钟'}，"
            f"token 长度 {len(token)}）",
            raw="",
        )
