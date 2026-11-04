"""深信服 IPS 全局黑名单插件（由现有生产脚本抽象）。

流程：登录取 security_key / api_key / cookie → SHA256 签名 → 黑名单插入/删除
→ applyconfig 配置生效 → 登出。

⚠️ 安全说明：本文件不含任何真实设备地址、账号、口令或口令哈希。
所有连接参数通过设备 config_json / credential_ref（环境变量）注入。
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Any
from urllib.parse import urlparse

import requests
import urllib3

from plugins.base import BasePlugin, PluginConfigError, PluginResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOGIN_PATH = "/api/system/account/login/login"
LOGOUT_PATH = "/api/system/account/login/logout"
BLACKLIST_PATH = "/api/policy/globalList/black/manual"
APPLY_PATH = "/api/index/applyconfig"


class SangforIpsPlugin(BasePlugin):
    plugin_code = "sangfor_ips"
    plugin_name = "深信服 IPS 全局黑名单"
    version = "1.0.0"
    ioc_types = ["IP"]
    capabilities = ["BLOCK", "UNBLOCK"]
    description = "登录 → SHA256 签名 → 全局黑名单插入/删除 → 配置生效"
    config_schema = {
        "base_url": "string（必填，如 https://<device>:8081）",
        "username": "string（必填）",
        "credential_ref": "string（环境变量名，值为口令或含 password 的 JSON）",
        "password": "string（仅由 credential_ref 注入，禁止写入数据库）",
        "verify_ssl": "bool（默认 false，设备多为自签证书）",
        "timeout": "int（秒，默认 10）",
    }
    default_timeout = 10

    @staticmethod
    def _sign(security_key: str, api_key: str, timestamp_ms: int, rest_uri: str) -> str:
        raw = f"security-key:{security_key};api-key:{api_key};time:{timestamp_ms};rest-uri:{rest_uri}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _session(self, config: dict[str, Any]) -> tuple[requests.Session, str, str]:
        base_url = str(config.get("base_url") or "").rstrip("/")
        username = str(config.get("username") or "")
        password = str(config.get("password") or config.get("secret") or "")
        if not base_url or not username or not password:
            raise PluginConfigError("缺少 base_url / username / password（请通过 credential_ref 注入）")
        verify = bool(config.get("verify_ssl", False))
        timeout = int(config.get("timeout") or self.default_timeout)
        session = requests.Session()
        login_body = json.dumps({"username": username, "password": password, "lang": "zh_CN"})
        response = session.post(
            base_url + LOGIN_PATH, data=login_body.encode("utf-8"),
            verify=verify, timeout=timeout,
        )
        payload = response.json()
        data = payload.get("data") or {}
        security_key, api_key = data.get("security_key"), data.get("api_key")
        if not security_key or not api_key:
            raise PluginConfigError(f"登录失败，未取得密钥: {str(payload)[:200]}")
        return session, security_key, api_key

    def _signed_url(self, config: dict[str, Any], security_key: str, api_key: str, path: str) -> str:
        timestamp_ms = int(round(time.time() * 1000))
        sign = self._sign(security_key, api_key, timestamp_ms, path)
        base_url = str(config["base_url"]).rstrip("/")
        return f"{base_url}{path}?sign={sign}&apikey={api_key}&time={timestamp_ms}"

    def _apply(self, session: requests.Session, config: dict[str, Any], sk: str, ak: str) -> None:
        verify = bool(config.get("verify_ssl", False))
        timeout = int(config.get("timeout") or self.default_timeout)
        url = self._signed_url(config, sk, ak, APPLY_PATH)
        session.post(url, data=b"", verify=verify, timeout=timeout)

    def _logout(self, session: requests.Session, config: dict[str, Any], sk: str, ak: str) -> None:
        try:
            verify = bool(config.get("verify_ssl", False))
            session.get(
                self._signed_url(config, sk, ak, LOGOUT_PATH),
                verify=verify, timeout=5,
            )
        except requests.RequestException:
            pass

    def _act(self, operation: str, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        session, sk, ak = self._session(config)
        verify = bool(config.get("verify_ssl", False))
        timeout = int(config.get("timeout") or self.default_timeout)
        try:
            action = "insert" if operation == "BLOCK" else "delete"
            body = json.dumps(
                {
                    "action": action,
                    "data": {
                        "name": ioc_value,
                        "direction": "1",
                        "start_time": "",
                        "end_time": "",
                        "threat_type": "",
                        "abstract": "added by AegisSoc",
                    },
                },
                ensure_ascii=False,
            )
            url = self._signed_url(config, sk, ak, BLACKLIST_PATH)
            response = session.post(url, data=body.encode("utf-8"), verify=verify, timeout=timeout)
            self._apply(session, config, sk, ak)
            try:
                payload = response.json()
                message = str(payload.get("message", ""))
                success = response.status_code < 300 and "fail" not in message.lower()
            except ValueError:
                success = response.status_code < 300
                message = response.text[:200]
            return PluginResult(
                success,
                message or f"HTTP {response.status_code}",
                raw=response.text[:4000],
                http_status=response.status_code,
            )
        finally:
            self._logout(session, config, sk, ak)
            session.close()

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        try:
            session, sk, ak = self._session(config)
            self._logout(session, config, sk, ak)
            session.close()
            return PluginResult(True, "深信服 IPS 登录成功", raw="")
        except Exception as exc:
            return PluginResult(False, f"连通性测试失败: {exc.__class__.__name__}: {exc}")

    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._act("BLOCK", ioc_value, config)

    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        return self._act("UNBLOCK", ioc_value, config)
