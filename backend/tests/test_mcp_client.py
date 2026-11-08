"""MCP 客户端测试：真实 Graylog 接入形态（Token 鉴权 + SSE 传输）。

覆盖四件事：
1. ``Authorization: Token <token>`` 确实发出去了（Graylog 只认这个前缀）；
2. Streamable HTTP 下 JSON 响应能正确解析；
3. 服务端只支持旧版 HTTP+SSE 时能自动降级（POST 被 405 拒绝 → GET 取 endpoint → 收回响应）；
4. 参数按工具 inputSchema 自动映射，只传服务端声明过的字段。
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue

import pytest

from app.services import patrol
from app.services.mcp_client import McpHttpClient, mask_token, parse_tool_result

SEARCH_SCHEMA = {
    "type": "object",
    "properties": {
        "query": {"type": "string"},
        "stream_id": {"type": "string"},
        "from": {"type": "string"},
        "to": {"type": "string"},
        "limit": {"type": "integer"},
    },
}

ALT_SCHEMA = {
    "type": "object",
    "properties": {
        "query_string": {"type": "string"},
        "streams": {"type": "array"},
        "start": {"type": "string"},
        "end": {"type": "string"},
        "size": {"type": "string"},
    },
}


def _rpc_response(payload: dict) -> dict | None:
    """模拟 Graylog MCP 的 JSON-RPC 行为（通知无 id 时返回 None）。"""
    if "id" not in payload:
        return None
    method = payload.get("method")
    if method == "initialize":
        result = {
            "protocolVersion": payload.get("params", {}).get("protocolVersion"),
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-graylog-mcp", "version": "7.0"},
        }
    elif method == "tools/list":
        result = {"tools": [
            {"name": "search_messages", "description": "日志检索", "inputSchema": SEARCH_SCHEMA},
            {"name": "list_streams", "description": "流清单",
             "inputSchema": {"type": "object", "properties": {}}},
        ]}
    elif method == "tools/call":
        result = {
            "structuredContent": {"messages": [
                {"_id": "m1", "message": "sql-injection", "fields": {"src_ip": "45.33.20.10"}},
            ]},
            "content": [{"type": "text", "text": "ok"}],
        }
    else:
        return {"jsonrpc": "2.0", "id": payload["id"],
                "error": {"code": -32601, "message": "method not found"}}
    return {"jsonrpc": "2.0", "id": payload["id"], "result": result}


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):  # 保持测试输出干净
        pass

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def _empty(self, code: int) -> None:
        self.send_response(code)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        payload = self._read_json()
        self.server.seen.append(("POST", self.path, dict(self.headers), payload))
        if self.server.mode == "sse":
            if self.path.rstrip("/") == "/api/mcp":
                self._empty(405)      # 强制客户端降级
                return
            self._empty(202)          # SSE 模式：响应从 GET 流上回去
            message = _rpc_response(payload)
            if message:
                self.server.queue.put(message)
            return
        body = json.dumps(_rpc_response(payload) or {}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.server.seen.append(("GET", self.path, dict(self.headers), None))
        if self.server.mode != "sse":
            self._empty(405)
            return
        self.protocol_version = "HTTP/1.0"
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(b"event: endpoint\ndata: /api/mcp/message?sessionId=t1\n\n")
        self.wfile.flush()
        while not self.server.stopping:
            try:
                message = self.server.queue.get(timeout=0.2)
            except Empty:
                continue
            chunk = "event: message\ndata: " + json.dumps(message) + "\n\n"
            try:
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
            except OSError:
                break


class _FakeServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, mode: str):
        super().__init__(("127.0.0.1", 0), _Handler)
        self.mode = mode
        self.seen: list[tuple] = []
        self.queue: Queue = Queue()
        self.stopping = False

    @property
    def base(self) -> str:
        return f"http://127.0.0.1:{self.server_address[1]}"


@pytest.fixture
def start_server():
    servers: list[_FakeServer] = []

    def _start(mode: str = "json") -> _FakeServer:
        server = _FakeServer(mode)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return server

    yield _start

    for server in servers:
        server.stopping = True
        server.shutdown()
        server.server_close()


def _header(entry: tuple, name: str) -> str:
    for key, value in entry[2].items():
        if key.lower() == name.lower():
            return value
    return ""


# ---------------------------------------------------------------- 鉴权
def test_graylog_token_auth_header(start_server):
    server = start_server("json")
    client = McpHttpClient(f"{server.base}/api/mcp", token="abc123def456789", timeout=5)

    info = client.initialize()

    assert info["serverInfo"]["name"] == "fake-graylog-mcp"
    assert client.transport == "streamable-http"
    first_post = next(s for s in server.seen if s[0] == "POST")
    assert _header(first_post, "Authorization") == "Token abc123def456789"


def test_bearer_scheme_is_configurable(start_server):
    server = start_server("json")
    client = McpHttpClient(f"{server.base}/api/mcp", token="jwt-abc", timeout=5, auth="bearer")
    client.initialize()
    first_post = next(s for s in server.seen if s[0] == "POST")
    assert _header(first_post, "Authorization") == "Bearer jwt-abc"


def test_mask_token_keeps_only_edges():
    assert mask_token("abcdefghijkl") == "abcd***ijkl"
    assert mask_token("short") == "*****"
    assert mask_token("") == ""


# ---------------------------------------------------------------- 传输
def test_call_tool_over_streamable_http(start_server):
    server = start_server("json")
    client = McpHttpClient(f"{server.base}/api/mcp", token="t", timeout=5)

    result = client.call_tool("search_messages", {"query": "attack", "limit": 10})
    data = parse_tool_result(result)

    assert data["messages"][0]["fields"]["src_ip"] == "45.33.20.10"
    assert client.session_id is None or isinstance(client.session_id, str)


def test_falls_back_to_sse_when_post_rejected(start_server):
    server = start_server("sse")
    client = McpHttpClient(f"{server.base}/api/mcp", token="t", timeout=5)

    info = client.initialize()

    assert client.transport == "sse"
    assert info["serverInfo"]["name"] == "fake-graylog-mcp"
    data = parse_tool_result(client.call_tool("search_messages", {"query": "attack"}))
    assert data["messages"][0]["_id"] == "m1"
    # 降级后 GET 必须带着同一个 token
    first_get = next(s for s in server.seen if s[0] == "GET")
    assert _header(first_get, "Authorization") == "Token t"


# ---------------------------------------------------------------- 参数映射
def test_map_arguments_uses_declared_names(monkeypatch):
    from datetime import datetime, timezone

    start = datetime(2026, 11, 8, 9, 0, 0, tzinfo=timezone.utc)
    end = datetime(2026, 11, 8, 9, 5, 0, tzinfo=timezone.utc)

    args = patrol.map_arguments(
        SEARCH_SCHEMA, stream_id="ips-1", query="attack", start=start, end=end, limit=200,
    )
    assert args == {
        "query": "attack", "stream_id": "ips-1",
        "from": "2026-11-08T09:00:00Z", "to": "2026-11-08T09:05:00Z", "limit": 200,
    }

    alt = patrol.map_arguments(
        ALT_SCHEMA, stream_id="waf-1", query="pass", start=start, end=end, limit=50,
    )
    # 换名字也能命中；数组字段自动包成 list；字符串型 limit 转成字符串
    assert alt["streams"] == ["waf-1"]
    assert alt["query_string"] == "pass"
    assert alt["size"] == "50"
    assert "stream_id" not in alt


def test_map_arguments_skips_empty_values_and_unknown_schema():
    from datetime import datetime, timezone

    now = datetime(2026, 11, 8, 9, 0, 0, tzinfo=timezone.utc)
    args = patrol.map_arguments(SEARCH_SCHEMA, stream_id="", query="", start=now, end=now, limit=0)
    assert args == {"from": "2026-11-08T09:00:00Z", "to": "2026-11-08T09:00:00Z", "limit": 0}
    assert patrol.map_arguments({}, stream_id="x", query="y", start=now, end=now, limit=1) is None
    assert patrol.map_arguments(None, stream_id="x", query="y", start=now, end=now, limit=1) is None


# ---------------------------------------------------------------- 流发现
class _StreamStub:
    def __init__(self, payload):
        self.payload = payload
        self.calls: list[str] = []

    def call_tool(self, name, arguments=None):
        self.calls.append(name)
        return {"structuredContent": self.payload}


def test_discover_streams_normalizes_and_suggests(monkeypatch):
    stub = _StreamStub({"streams": [
        {"id": "aaa111", "title": "IPS 入侵防御", "description": "边界 IPS"},
        {"id": "bbb222", "title": "WAF access log"},
        {"id": "ccc333", "title": "零信任接入日志"},
    ]})
    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: stub)

    streams = patrol.discover_streams()

    assert stub.calls == ["list_streams"]
    assert [s["id"] for s in streams] == ["aaa111", "bbb222", "ccc333"]
    assert [s["suggested"] for s in streams] == ["IPS", "WAF", "ZTNA"]


def test_discover_streams_degrades_on_mcp_error(monkeypatch):
    class _Boom:
        def call_tool(self, name, arguments=None):
            from app.services.mcp_client import McpError
            raise McpError("connect refused")

    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: _Boom())
    assert patrol.discover_streams() == []
