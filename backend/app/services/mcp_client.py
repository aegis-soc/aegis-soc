"""最小 MCP 客户端：Streamable HTTP 传输上的 JSON-RPC 2.0。

为什么自己写而不用 SDK：这里只需要「列出工具」和「调用一个检索工具」两件事，
标准库即可覆盖，避免为一条只读链路引入额外运行时依赖（也便于离线部署）。

支持的能力：
- ``initialize`` 握手，按服务端返回维持 ``Mcp-Session-Id``；
- ``notifications/initialized`` 通知（服务端返回 202 空体）；
- ``tools/list`` 与 ``tools/call``；
- 响应既可能是 ``application/json``，也可能是 ``text/event-stream``（SSE），两种都解析。

不做的：stdio 传输、OAuth 授权流（内网场景用 Bearer Token 足够）。
所有失败统一抛 :class:`McpError`，由调用方决定降级策略——巡检链路绝不允许
因为 MCP 抖动而中断或误封。
"""
from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any

logger = logging.getLogger("aegis")

# 先试较新的协议版本，服务端不认再退回上一个
PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05")


class McpError(Exception):
    """MCP 调用失败（网络、HTTP 状态、JSON-RPC error 三种都归到这里）。"""


def mask_url(url: str) -> str:
    """日志/接口里展示地址时隐去 query 中的 token。"""
    if not url:
        return ""
    if "?" not in url:
        return url
    base, _, query = url.partition("?")
    return f"{base}?<hidden>"


class McpHttpClient:
    """Streamable HTTP MCP 客户端；实例可复用，会话在首次调用时建立。"""

    def __init__(self, url: str, token: str = "", timeout: float = 30.0):
        self.url = (url or "").strip()
        self.token = (token or "").strip()
        self.timeout = timeout
        self.session_id: str | None = None
        self.server_info: dict[str, Any] = {}
        self.protocol_version: str | None = None
        self._next_id = 0

    # ---------------------------------------------------------------- 传输
    def _headers(self, *, notify: bool = False) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        if self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        if self.protocol_version and not notify:
            headers["MCP-Protocol-Version"] = self.protocol_version
        return headers

    def _post(self, payload: dict[str, Any]) -> tuple[str, dict[str, str]]:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            self.url, data=body, headers=self._headers(notify="id" not in payload), method="POST"
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in response.headers.items()}
                return raw, headers
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:  # noqa: BLE001 - 读错误体失败不影响主流程
                pass
            raise McpError(f"MCP HTTP {exc.code} {exc.reason}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise McpError(f"MCP 连接失败：{exc.reason}") from exc
        except TimeoutError as exc:
            raise McpError(f"MCP 请求超时（{self.timeout}s）") from exc

    @staticmethod
    def _parse_body(raw: str) -> dict[str, Any] | None:
        """解析 JSON 或 SSE 响应，返回第一条带 result/error 的 JSON-RPC 消息。"""
        text = (raw or "").strip()
        if not text:
            return None
        if text.startswith("{") or text.startswith("["):
            try:
                data = json.loads(text)
            except json.JSONDecodeError:
                return None
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and ("result" in item or "error" in item):
                        return item
                return None
            return data if isinstance(data, dict) else None

        # SSE：每行 data: {...}，可能多事件，取第一个能解析出 result/error 的
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith("data:"):
                continue
            chunk = line[5:].strip()
            if not chunk or chunk == "[DONE]":
                continue
            try:
                data = json.loads(chunk)
            except json.JSONDecodeError:
                continue
            if isinstance(data, dict) and ("result" in data or "error" in data):
                return data
        return None

    def _request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            payload["params"] = params
        raw, headers = self._post(payload)
        if headers.get("mcp-session-id"):
            self.session_id = headers["mcp-session-id"]
        message = self._parse_body(raw)
        if message is None:
            # 某些实现握手阶段返回 202 + 空体
            return None
        if "error" in message and message["error"]:
            err = message["error"]
            raise McpError(f"MCP {method} 失败：{err.get('message') or err}")
        return message.get("result")

    def _notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        try:
            self._post(payload)
        except McpError as exc:
            # 通知失败不致命：部分服务端直接 204/202，甚至忽略 unknown notification
            logger.debug("MCP 通知 %s 未确认：%s", method, exc)

    # ---------------------------------------------------------------- 握手
    def initialize(self, force: bool = False) -> dict[str, Any]:
        """建立会话；重复调用直接返回缓存的 server info。"""
        if self.server_info and not force:
            return self.server_info
        last_error: Exception | None = None
        for version in PROTOCOL_VERSIONS:
            try:
                result = self._request(
                    "initialize",
                    {
                        "protocolVersion": version,
                        "capabilities": {},
                        "clientInfo": {"name": "aegis-soc", "version": "1.0"},
                    },
                )
                self.protocol_version = version
                self.server_info = result or {}
                self._notify("notifications/initialized")
                return self.server_info
            except McpError as exc:
                last_error = exc
                logger.debug("MCP 握手失败（协议 %s）：%s", version, exc)
        raise McpError(f"MCP 握手失败：{last_error}")

    def list_tools(self) -> list[dict[str, Any]]:
        self.initialize()
        result = self._request("tools/list") or {}
        tools = result.get("tools") if isinstance(result, dict) else None
        return tools or []

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """调用工具并返回 result；工具的业务数据可用 :func:`parse_tool_result` 取出。"""
        self.initialize()
        return self._request("tools/call", {"name": name, "arguments": arguments or {}})

    # ---------------------------------------------------------------- 诊断
    def describe(self) -> dict[str, Any]:
        """连通性自检：返回服务端信息与工具列表，供页面「测试连接」使用。"""
        info = self.initialize(force=True)
        tools = []
        for tool in self.list_tools():
            if not isinstance(tool, dict):
                continue
            schema = tool.get("inputSchema") or {}
            properties = schema.get("properties") if isinstance(schema, dict) else {}
            tools.append({
                "name": tool.get("name"),
                "description": (tool.get("description") or "")[:200],
                "arguments": sorted(properties) if isinstance(properties, dict) else [],
            })
        return {
            "url": mask_url(self.url),
            "session": bool(self.session_id),
            "protocol_version": self.protocol_version,
            "server": {
                "name": (info or {}).get("serverInfo", {}).get("name"),
                "version": (info or {}).get("serverInfo", {}).get("version"),
            },
            "tools": tools,
        }


def parse_tool_result(result: Any) -> Any:
    """把 tools/call 的 result 还原成业务数据。

    优先级：``structuredContent`` → ``content[].text``（尝试 JSON 解析）→ 原样返回。
    这样无论服务端返回结构化还是纯文本，上层都不需要写分支。
    """
    if result is None:
        return None
    if isinstance(result, dict):
        if isinstance(result.get("structuredContent"), (dict, list)):
            return result["structuredContent"]
        blocks = result.get("content")
        if isinstance(blocks, list):
            texts: list[str] = []
            for block in blocks:
                if isinstance(block, dict) and block.get("type") == "text":
                    texts.append(str(block.get("text") or ""))
            joined = "\n".join(t for t in texts if t).strip()
            if joined:
                try:
                    return json.loads(joined)
                except json.JSONDecodeError:
                    return joined
        for key in ("messages", "data", "records", "items", "result"):
            if key in result:
                return result[key]
    return result
