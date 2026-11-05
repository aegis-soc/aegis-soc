"""SSH 防火墙插件（H3C / 华为），由现有生产 paramiko 脚本抽象而来。

⚠️ 安全说明：本文件不含任何真实设备地址、账号或口令。
所有连接参数通过设备 config_json / credential_ref（环境变量）注入，
交互命令模板化，超时受控，避免原脚本中的无界等待。
"""
from __future__ import annotations

import socket
import time
from typing import Any

import paramiko

from plugins.base import BasePlugin, PluginConfigError, PluginResult, as_int
from plugins.context import ActionRequest, DeviceTarget

# 设备 CLI 拒绝执行时常见的回显特征（小写匹配）
ERROR_MARKERS = (
    "error:",
    "% invalid",
    "% incomplete",
    "% wrong",
    "% unrecognized",
    "% permission denied",
    "unrecognized command",
    "incomplete command",
    "wrong parameter",
    "invalid input",
    "permission denied",
    "authentication failed",
    "too many",
)


class SshFirewallPlugin(BasePlugin):
    plugin_code = "ssh_firewall"
    plugin_name = "SSH 防火墙（H3C / 华为）"
    credential_hint = "FW_PASSWORD"   # SSH 口令，写入 .env 后在此填变量名
    version = "1.0.0"
    ioc_types = ["IP"]
    capabilities = ["BLOCK", "UNBLOCK"]
    description = "SSH CLI 下发 H3C / 华为防火墙黑名单，凭据通过环境变量引用"
    config_schema = {
        "host": "string（必填，设备地址）",
        "port": "int（默认 22）",
        "username": "string（必填）",
        "credential_ref": "string（环境变量名，值为口令或含 password 的 JSON）",
        "password": "string（仅由 credential_ref 注入，禁止写入数据库）",
        "vendor": "h3c | huawei（默认 h3c）",
        "timeout_minutes": "int（封禁时长，默认 120）",
    }
    required_config = ["host", "username"]
    default_timeout = 15

    def _connect(self, config: dict[str, Any]) -> paramiko.SSHClient:
        host = str(config.get("host") or "")
        username = str(config.get("username") or "")
        password = str(config.get("password") or config.get("secret") or "")
        if not host or not username or not password:
            raise PluginConfigError("缺少 host / username / password（请通过 credential_ref 注入）")
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            host,
            port=as_int(config.get("port"), 22),
            username=username,
            password=password,
            timeout=as_int(config.get("timeout"), self.default_timeout),
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    @staticmethod
    def _wait_prompt(
        shell: paramiko.Channel, suffixes: tuple[str, ...], timeout: float = 12.0
    ) -> tuple[str, bool]:
        """读取回显直到出现预期提示符；返回 (文本, 是否等到提示符)。"""
        buffer = b""
        matched = False
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                chunk = shell.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                break
            buffer += chunk
            text = buffer.decode("utf-8", errors="ignore").rstrip()
            if any(text.endswith(suffix) for suffix in suffixes):
                matched = True
                break
        return buffer.decode("utf-8", errors="ignore"), matched

    def _send(self, config: dict[str, Any], commands: list[str]) -> tuple[str, bool]:
        """下发命令并回读；返回 (完整回显, 是否正常进入系统视图并完成下发)。"""
        client = self._connect(config)
        output = ""
        ok = True
        try:
            shell = client.invoke_shell()
            shell.settimeout(1.0)
            text, matched = self._wait_prompt(shell, (">",))
            output += text
            ok = ok and matched
            shell.send("system\n")
            text, matched = self._wait_prompt(shell, ("]",))
            output += text
            ok = ok and matched
            for command in commands:
                shell.send(command + "\n")
                text, matched = self._wait_prompt(shell, ("]",))
                output += text
                ok = ok and matched
            shell.send("exit\n")
            shell.send("exit\n")
        finally:
            client.close()
        return output, ok

    def _command(self, operation: str, ioc_value: str, config: dict[str, Any]) -> str:
        vendor = str(config.get("vendor") or "h3c").lower()
        duration = as_int(config.get("timeout_minutes"), 120) * 60
        if operation == "BLOCK":
            if vendor == "huawei":
                return f"firewall blacklist item source-ip {ioc_value} timeout {duration}"
            return f"blacklist ip {ioc_value} timeout {duration}"
        if vendor == "huawei":
            return f"undo firewall blacklist item source-ip {ioc_value}"
        return f"undo blacklist ip {ioc_value}"

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        self.validate_config(config)
        try:
            output, ok = self._send(config, [])
        except Exception as exc:
            return PluginResult(False, f"SSH 连通性测试失败: {exc.__class__.__name__}: {exc}")
        if not ok:
            return PluginResult(
                False, "SSH 已连接，但未出现预期提示符（可能被 ACL / 二次认证拦截）",
                raw=output[:4000],
            )
        return PluginResult(True, "SSH 登录并进入系统视图成功", raw=output[:4000])

    def _run(self, operation: str, ioc_value: str, config: dict[str, Any]) -> PluginResult:
        command = self._command(operation, ioc_value, config)
        output, prompt_ok = self._send(config, [command])
        if not prompt_ok:
            return PluginResult(
                False,
                "设备回显超时或未进入系统视图，命令下发结果未知",
                raw=output[:4000],
            )
        lowered = output.lower()
        hit = next((marker for marker in ERROR_MARKERS if marker in lowered), "")
        if hit:
            return PluginResult(
                False,
                f"设备拒绝执行（回显包含“{hit.strip()}”），请检查命令模板与账号权限",
                raw=output[:4000],
            )
        verb = "封禁" if operation == "BLOCK" else "解封"
        return PluginResult(True, f"{verb}命令已下发且设备回显正常", raw=output[:4000])

    def block(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._run("BLOCK", req.ioc_value, target.config)

    def unblock(self, target: DeviceTarget, req: ActionRequest) -> PluginResult:
        return self._run("UNBLOCK", req.ioc_value, target.config)
