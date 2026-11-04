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

from plugins.base import BasePlugin, PluginConfigError, PluginResult


class SshFirewallPlugin(BasePlugin):
    plugin_code = "ssh_firewall"
    plugin_name = "SSH 防火墙（H3C / 华为）"
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
            port=int(config.get("port") or 22),
            username=username,
            password=password,
            timeout=int(config.get("timeout") or self.default_timeout),
            allow_agent=False,
            look_for_keys=False,
        )
        return client

    @staticmethod
    def _wait_prompt(shell: paramiko.Channel, suffixes: tuple[str, ...], timeout: float = 12.0) -> str:
        buffer = b""
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
                break
        return buffer.decode("utf-8", errors="ignore")

    def _send(self, config: dict[str, Any], commands: list[str]) -> str:
        client = self._connect(config)
        output = ""
        try:
            shell = client.invoke_shell()
            shell.settimeout(1.0)
            output += self._wait_prompt(shell, (">",))
            shell.send("system\n")
            output += self._wait_prompt(shell, ("]",))
            for command in commands:
                shell.send(command + "\n")
                output += self._wait_prompt(shell, ("]",))
            shell.send("exit\n")
            shell.send("exit\n")
        finally:
            client.close()
        return output

    def _command(self, operation: str, ioc_value: str, config: dict[str, Any]) -> str:
        vendor = str(config.get("vendor") or "h3c").lower()
        duration = int(config.get("timeout_minutes") or 120) * 60
        if operation == "BLOCK":
            if vendor == "huawei":
                return f"firewall blacklist item source-ip {ioc_value} timeout {duration}"
            return f"blacklist ip {ioc_value} timeout {duration}"
        if vendor == "huawei":
            return f"undo firewall blacklist item source-ip {ioc_value}"
        return f"undo blacklist ip {ioc_value}"

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        try:
            output = self._send(config, [])
            return PluginResult(True, "SSH 登录并进入系统视图成功", raw=output[:4000])
        except Exception as exc:
            return PluginResult(False, f"SSH 连通性测试失败: {exc.__class__.__name__}: {exc}")

    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        output = self._send(config, [self._command("BLOCK", ioc_value, config)])
        return PluginResult(True, "封禁命令已下发", raw=output[:4000])

    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        output = self._send(config, [self._command("UNBLOCK", ioc_value, config)])
        return PluginResult(True, "解封命令已下发", raw=output[:4000])
