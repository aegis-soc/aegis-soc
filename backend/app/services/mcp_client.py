"""最小 MCP 客户端：同时支持 Streamable HTTP 与旧版 HTTP+SSE 两种传输。

为什么要自己写：这里只需要「列工具 / 读 schema / 调一个检索工具」三件事，
标准库即可覆盖，避免为一条只读链路引入额外运行时依赖（也便于离线内网部署）。

真实 Graylog 的接入形态（按官方文档）：
- 地址 ``https://<graylog-host>/api/mcp``；
- 鉴权 ``Authorization: Token <API_TOKEN>``（**不是** Bearer）；
- 默认开 ``System → Configurations → MCP`` 才有这个端点；
- 权限完全继承该用户 RBAC，调用会写进 Graylog 审计日志。

传输策略：
1. 先按 Streamable HTTP 发 POST（``Accept: application/json, text/event-stream``），
   响应既可能是 JSON，也可能是 SSE 分片——两种都解析；
2. 若 POST 被拒（404/405/406 等，说明该服务端只实现了旧版 SSE），
   自动降级为 HTTP+SSE：GET 取事件流 → 等服务端下发 ``endpoint`` →
   后续请求 POST 到该 endpoint → 响应仍从 GET 流上按 ``id`` 收回。

所有失败统一抛 :class:`McpError`（传输层问题为其子类
:class:`McpTransportError`），由调用方决定降级策略——巡检链路绝不允许因为
MCP 抖动而中断或误封。
"""
from __future__ import annotations

import json
import logging
import threading
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

logger = logging.getLogger("aegis")

# 先试较新的协议版本，服务端不认再退回上一个
PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05")

# 认证方式：token = Graylog 的 `Authorization: Token xxx`
AUTH_SCHEMES = ("token", "bearer", "basic", "none", "raw")


class McpError(Exception):
    """MCP 调用失败（网络、HTTP 状态、JSON-RPC error 三种都归到这里）。"""


class McpTransportError(McpError):
    """传输层失败：连不上、HTTP 4xx/5xx、超时。可据此尝试换传输方式。"""


def mask_url(url: str) -> str:
    """日志/接口里展示地址时隐去 query 中的 token。"""
    if not url:
        return ""
    if "?" not in url:
        return url
    base, _, _ = url.partition("?")
    return f"{base}?<hidden>"


def mask_token(token: str) -> str:
    """只暴露尾部 4 位，便于核对「用的是哪个 token」又不泄露。"""
    token = (token or "").strip()
    if not token:
        return ""
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}***{token[-4:]}"


# ---------------------------------------------------------------- SSE 通道
class _SseChannel:
    """旧版 HTTP+SSE 传输的通道：一条长连接 GET 收事件，POST 到 endpoint 发请求。

    线程模型：一个后台线程独占 GET 连接逐行读事件；主线程发 POST 后用
    ``Condition`` 等对应 ``id`` 的 JSON-RPC 响应。任何异常都记录在 ``error``
    上并唤醒等待者，绝不把异常抛到后台线程外面。
    """

    def __init__(self, url: str, headers: dict[str, str], timeout: float):
        self.url = url
        self.headers = headers
        self.timeout = timeout
        self.endpoint: str | None = None
        self.error: str = ""
        self._ready = threading.Event()
        self._cv = threading.Condition()
        self._messages: dict[Any, dict[str, Any]] = {}
        self._thread: threading.Thread | None = None
        self._response: Any = None

    # -------------------------------------------------- 生命周期
    def open(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="mcp-sse", daemon=True)
        self._thread.start()
        if not self._ready.wait(self.timeout):
            raise McpTransportError(f"SSE 连接超时：{self.timeout}s 内未收到 endpoint 事件")
        if not self.endpoint:
            raise McpTransportError(self.error or "SSE 未返回 endpoint 事件")

    def close(self) -> None:
        try:
            if self._response is not None:
                self._response.close()
        except Exception:  # noqa: BLE001 - 关闭失败无关紧要
            pass

    # -------------------------------------------------- 后台读流
    def _run(self) -> None:
        headers = dict(self.headers)
        headers["Accept"] = "text/event-stream"
        request = urllib.request.Request(self.url, headers=headers, method="GET")
        event: str | None = None
        data_lines: list[str] = []
        try:
            self._response = urllib.request.urlopen(request, timeout=self.timeout)
            while True:
                raw = self._response.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if line.startswith(":"):        # 心跳 / 注释
                    continue
                if line == "":                  # 事件结束
                    self._dispatch(event, data_lines)
                    event, data_lines = None, []
                    continue
                if line.startswith("event:"):
                    event = line[6:].strip()
                elif line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
        except Exception as exc:  # noqa: BLE001 - 后台线程不能抛
            self.error = f"SSE 连接中断：{exc}"
        finally:
            self._ready.set()
            with self._cv:
                self._cv.notify_all()

    def _dispatch(self, event: str | None, data_lines: list[str]) -> None:
        data = "\n".join(data_lines).strip()
        if not data:
            return
        # endpoint 事件给出后续 POST 的地址（相对或绝对）
        if event == "endpoint" or (event is None and data[0] in "/h"):
            self.endpoint = urllib.parse.urljoin(self.url, data)
            self._ready.set()
            return
        try:
            message = json.loads(data)
        except json.JSONDecodeError:
            return
        if not isinstance(message, dict):
            return
        with self._cv:
            self._messages[message.get("id")] = message
            self._cv.notify_all()

    # -------------------------------------------------- 收发
    def post(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        if not self.endpoint:
            self.open()
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = dict(self.headers)
        headers.update({"Content-Type": "application/json",
                        "Accept": "application/json, text/event-stream"})
        request = urllib.request.Request(self.endpoint, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:300]
            except Exception:  # noqa: BLE001
                pass
            raise McpTransportError(f"MCP SSE 端点 HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise McpTransportError(f"MCP SSE 端点连接失败：{exc.reason}") from exc
        except TimeoutError as exc:
            raise McpTransportError(f"MCP SSE 端点请求超时（{self.timeout}s）") from exc

        # 少数实现直接在 POST 响应里回 JSON
        text = (raw or "").strip()
        if text.startswith("{"):
            try:
                direct = json.loads(text)
            except json.JSONDecodeError:
                direct = None
            if isinstance(direct, dict) and direct.get("id") == payload.get("id"):
                return direct

        if "id" not in payload:
            return None
        return self._wait(payload["id"])

    def _wait(self, request_id: Any) -> dict[str, Any] | None:
        with self._cv:
            ok = self._cv.wait_for(
                lambda: request_id in self._messages or bool(self.error),
                timeout=self.timeout,
            )
            if request_id in self._messages:
                return self._messages.pop(request_id)
            if not ok:
                raise McpTransportError(f"MCP SSE 等待响应超时（{self.timeout}s）")
            raise McpTransportError(self.error or "MCP SSE 连接已关闭")


# ---------------------------------------------------------------- 主客户端
class McpHttpClient:
    """MCP 客户端；实例可复用，会话在首次调用时建立。"""

    def __init__(self, url: str, token: str = "", timeout: float = 30.0,
                 auth: str = "token", extra_headers: dict[str, str] | None = None):
        self.url = (url or "").strip()
        self.token = (token or "").strip()
        self.timeout = timeout
        self.auth = (auth or "token").strip().lower()
        self.extra_headers = extra_headers or {}
        self.session_id: str | None = None
        self.server_info: dict[str, Any] = {}
        self.protocol_version: str | None = None
        self.transport = "streamable-http"   # 可能降级为 "sse"
        self._sse: _SseChannel | None = None
        self._next_id = 0
        self._transport_locked = False
        self._schemas: dict[str, dict[str, Any]] = {}

    # ---------------------------------------------------------------- 传输
    def auth_headers(self) -> dict[str, str]:
        """按配置生成鉴权头；Graylog 用 ``Token`` 前缀，其它平台可切 bearer。"""
        if not self.token:
            return {}
        if self.auth in ("none", "off", "no", "false"):
            return {}
        if self.auth in ("bearer", "oauth", "jwt"):
            return {"Authorization": f"Bearer {self.token}"}
        if self.auth == "basic":
            return {"Authorization": f"Basic {self.token}"}
        if self.auth == "raw":
            return {"Authorization": self.token}
        return {"Authorization": f"Token {self.token}"}

    def _headers(self, *, notify: bool = False) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        headers.update(self.auth_headers())
        headers.update(self.extra_headers)
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
            raise McpTransportError(f"MCP HTTP {exc.code} {exc.reason}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise McpTransportError(f"MCP 连接失败：{exc.reason}") from exc
        except TimeoutError as exc:
            raise McpTransportError(f"MCP 请求超时（{self.timeout}s）") from exc

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

    def _open_sse(self) -> bool:
        """尝试建立旧版 SSE 通道；失败返回 False（保留 streamable 的原始错误）。"""
        try:
            channel = _SseChannel(self.url, self._headers(), self.timeout)
            channel.open()
        except McpError as exc:
            logger.warning("MCP SSE 降级失败：%s", exc)
            return False
        self._sse = channel
        self.transport = "sse"
        return True

    def _request(self, method: str, params: dict[str, Any] | None = None) -> Any:
        self._next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            payload["params"] = params

        message: dict[str, Any] | None = None
        if self.transport == "sse" and self._sse is not None:
            message = self._sse.post(payload)
        else:
            try:
                raw, headers = self._post(payload)
            except McpTransportError as exc:
                # 只在第一次请求、且还没锁定传输方式时降级，避免每轮都白试一次
                if not self._transport_locked and self._open_sse():
                    logger.info("MCP 已降级为 HTTP+SSE 传输（原错误：%s）", exc)
                    message = self._sse.post(payload) if self._sse else None
                else:
                    raise
            else:
                self._transport_locked = True
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
            if self.transport == "sse" and self._sse is not None:
                self._sse.post(payload)
            else:
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

    def tool_schema(self, name: str) -> dict[str, Any]:
        """取某个工具的 inputSchema（缓存）。拿不到时返回空 dict，调用方走兜底参数。"""
        if name in self._schemas:
            return self._schemas[name]
        schema: dict[str, Any] = {}
        try:
            for tool in self.list_tools():
                if isinstance(tool, dict):
                    self._schemas[str(tool.get("name"))] = tool.get("inputSchema") or {}
            schema = self._schemas.get(name, {})
        except McpError as exc:
            logger.debug("读取工具 schema 失败：%s", exc)
        return schema

    def call_tool(self, name: str, arguments: dict[str, Any] | None = None) -> Any:
        """调用工具并返回 result；业务数据用 :func:`parse_tool_result` 取出。"""
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
            self._schemas[str(tool.get("name"))] = schema if isinstance(schema, dict) else {}
            tools.append({
                "name": tool.get("name"),
                "description": (tool.get("description") or "")[:200],
                "arguments": sorted(properties) if isinstance(properties, dict) else [],
            })
        return {
            "url": mask_url(self.url),
            "transport": self.transport,
            "auth": self.auth,
            "token_hint": mask_token(self.token),
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
