"""启明星辰 天清汉马 USG 防火墙插件（Web API）。

不同型号/固件的 Web API 路径与返回字段差异较大，因此本插件把
「登录 → 鉴权 → 下发 → 保存生效」四步全部参数化，路径与请求体在设备 config_json 中维护，
换型号只改配置、不改代码。默认值对应常见的 /api/v1 形态。

成功判定（避免"接口 200 但实际失败"的假成功）：
- HTTP >= 300 判失败；
- 响应为 JSON 时依次识别 code / success / status 字段；
- 配了 save_path（保存/生效接口）时，保存失败整单判失败，因为策略尚未真正生效。

安全：账号口令只从 credential_ref 注入；raw 只存响应报文，不含凭据。
"""
from __future__ import annotations

import json
from typing import Any

import requests
import urllib3

from plugins.base import BasePlugin, PluginConfigError, PluginResult, as_bool, as_int
from plugins.context import ActionRequest, DeviceTarget

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SUCCESS_CODES = {"0", "200", "true", "success", "ok"}
SUCCESS_WORDS = {"success", "ok", "0", "true"}


class QimingFwPlugin(BasePlugin):
    plugin_code = "qiming_fw"
    plugin_name = "启明星辰 天清汉马 USG"
    credential_hint = "QIMING_FW_PASSWORD"   # 设备登录口令
    version = "1.0.0"
    ioc_types = ["IP"]
    capabilities = ["BLOCK", "UNBLOCK"]
    description = "天清汉马 Web API：登录鉴权 → 黑名单下发 → 可选保存生效，路径与报文可配"
    config_schema = {
        "base_url": "string（必填，如 https://10.0.0.3）",
        "username": "string（必填）",
        "credential_ref": "string（环境变量名，值为口令或 JSON）",
        "login_path": "string（默认 /api/v1/login）",
        "login_body": 'string（默认 {"username":"{username}","password":"{password}"}）',
        "token_path": "string（JSON 路径，默认 data.token；留空表示仅用 Cookie 会话）",
        "token_header": "string（默认 Authorization）",
        "token_prefix": "string（默认 'Bearer '，无前缀留空）",
        "block_path": "string（必填，如 /api/v1/firewall/blacklist）",
        "unblock_path": "string（必填，同接口则填相同值）",
        "block_body": 'string（默认 {"ip":"{ioc_value}","action":"add"}）',
        "unblock_body": 'string（默认 {"ip":"{ioc_value}","action":"del"}）',
        "save_path": "string（可选，封禁后调用的保存/生效接口，空则跳过）",
        "verify_ssl": "bool（默认 false，设备多为自签证书）",
        "timeout": "int（秒，默认 10）",
    }
    required_config = ["base_url", "username", "block_path", "unblock_path"]
    default_timeout = 10

    @staticmethod
    def _render(template: str, ioc_value: str, config: dict[str, Any]) -> str:
        return (
            template.replace("{ioc_value}", ioc_value)
            .replace("{ioc_type}", "IP")
            .replace("{username}", str(config.get("username") or ""))
            .replace("{password}", str(config.get("password") or ""))
        )

    @staticmethod
    def _pick(payload: Any, path: str) -> str:
        current = payload
        for part in [p for p in path.split(".") if p]:
            if not isinstance(current, dict) or part not in current:
                return ""
            current = current[part]
        return "" if current is None else str(current)

    def _is_success(self, status_code: int, payload: Any) -> bool:
        if status_code >= 300:
            return False
        if isinstance(payload, dict):
            if "code" in payload:
                return str(payload.get("code")).strip().lower() in SUCCESS_CODES
            if "success" in payload:
                return as_bool(payload.get("success"), False)
            if "status" in payload:
                return str(payload.get("status")).strip().lower() in SUCCESS_WORDS
        return True

    def _login(self, config: dict[str, Any]) -> tuple[requests.Session | None, str, str]:
        """返回 (session, token, 错误信息)。token 为空但 Cookie 有效时也视为成功。"""
        password = str(config.get("password") or config.get("secret") or "")
        if not password:
            raise PluginConfigError("缺少 password（请通过 credential_ref 注入）")
        base_url = str(config["base_url"]).rstrip("/")
        login_path = str(config.get("login_path") or "/api/v1/login")
        body = self._render(
            str(config.get("login_body") or '{"username":"{username}","password":"{password}"}'),
            "", config,
        )
        timeout = as_int(config.get("timeout"), self.default_timeout)
        verify = as_bool(config.get("verify_ssl"), False)

        session = requests.Session()
        try:
            response = session.post(
                base_url + login_path,
                data=body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
                timeout=timeout,
                verify=verify,
            )
        except requests.RequestException as exc:
            session.close()
            return None, "", f"登录请求失败: {exc.__class__.__name__}: {exc}"

        try:
            payload = response.json()
        except ValueError:
            payload = None
        if not self._is_success(response.status_code, payload):
            session.close()
            detail = json.dumps(payload, ensure_ascii=False)[:200] if payload is not None else response.text[:200]
            return None, "", f"登录失败（HTTP {response.status_code}）: {detail}"

        token_path = str(config.get("token_path") or "data.token")
        token = self._pick(payload, token_path) if (payload is not None and token_path) else ""
        if not token and not session.cookies.get_dict():
            session.close()
            return None, "", "登录返回成功但既无 token 也无 Cookie，请核对 token_path 配置"
        return session, token, ""

    def _call(
        self,
        session: requests.Session,
        token: str,
        config: dict[str, Any],
        path: str,
        body: str,
        action: str,
    ) -> PluginResult:
        headers = {"Content-Type": "application/json"}
        if token:
            header = str(config.get("token_header") or "Authorization")
            prefix = config.get("token_prefix")
            prefix = "Bearer " if prefix is None else str(prefix)
            headers[header] = f"{prefix}{token}"
        url = str(config["base_url"]).rstrip("/") + "/" + path.lstrip("/")
        try:
            response = session.post(
                url,
                data=body.encode("utf-8"),
                headers=headers,
                timeout=as_int(config.get("timeout"), self.default_timeout),
                verify=as_bool(config.get("verify_ssl"), False),
            )
        except requests.RequestException as exc:
            return PluginResult(False, f"{action}请求失败: {exc.__class__.__name__}: {exc}")

        raw = response.text[:4000]
        try:
            payload = response.json()
        except ValueError:
            payload = None
        if not self._is_success(response.status_code, payload):
            detail = (
                json.dumps(payload, ensure_ascii=False)[:200]
                if payload is not None
                else response.text[:200]
            )
            return PluginResult(
                False,
                f"{action}失败（HTTP {response.status_code}）: {detail}",
                raw=raw,
                http_status=response.status_code,
            )
        return PluginResult(True, f"{action}成功（HTTP {response.status_code}）", raw=raw,
                            http_status=response.status_code)

    def _act(self, operation: str, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        self.validate_config(config)
        key = operation.lower()
        path = str(config.get(f"{key}_path") or "").strip()
        template = str(
            config.get(f"{key}_body")
            or (
                '{"ip":"{ioc_value}","action":"add"}'
                if operation == "BLOCK"
                else '{"ip":"{ioc_value}","action":"del"}'
            )
        )
        body = self._render(template, ioc_value, config)
        verb = "封禁" if operation == "BLOCK" else "解封"

        session, token, error = self._login(config)
        if session is None:
            return PluginResult(False, error)
        try:
            result = self._call(session, token, config, path, body, verb)
            if not result.success:
                return result
            save_path = str(config.get("save_path") or "").strip()
            if save_path:
                saved = self._call(session, token, config, save_path, "", "配置保存")
                if not saved.success:
                    return PluginResult(
                        False,
                        f"{verb}已提交但配置未保存生效，策略可能尚未落地: {saved.message}",
                        raw=saved.raw,
                        http_status=saved.http_status,
                    )
                return PluginResult(True, f"{verb}成功且配置已保存生效", raw=result.raw)
            return PluginResult(True, f"{verb}成功", raw=result.raw, http_status=result.http_status)
        finally:
            session.close()

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        """仅登录验证，不下发任何策略。"""
        self.validate_config(config)
        try:
            session, token, error = self._login(config)
        except PluginConfigError as exc:
            return PluginResult(False, f"插件配置错误: {exc}")
        if session is None:
            return PluginResult(False, error)
        session.close()
        mode = "Token" if token else "Cookie"
        return PluginResult(True, f"登录成功，鉴权方式：{mode}")

    def block(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act("BLOCK", req.ioc_value, target.config)

    def unblock(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._act("UNBLOCK", req.ioc_value, target.config)
