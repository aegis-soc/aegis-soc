"""MCP 客户端测试：真实 Graylog 接入形态（官方 Token 认证 + SSE 传输）。

覆盖四件事：
1. Graylog 官方 Token 认证确实发对了：``Authorization: Basic base64("<token>:token")``
   （username=API Token，password=固定字面 ``token``，不是 ``user:<token>``）；
2. Streamable HTTP 下 JSON 响应能正确解析；
3. 服务端只支持旧版 HTTP+SSE 时能自动降级（POST 被 405 拒绝 → GET 取 endpoint → 收回响应）；
4. 参数按工具 inputSchema 自动映射，只传服务端声明过的字段。
"""
from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from queue import Empty, Queue

import pytest

from app.services import patrol
from app.services.mcp_client import McpHttpClient, mask_token, parse_tool_result
from app.services.patrol_settings import PatrolConfig

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
def _basic(user: str, password: str = "token") -> str:
    """Graylog 官方约定：Basic 的 username=API Token，password=固定字面 token。"""
    return "Basic " + base64.b64encode(f"{user}:{password}".encode("utf-8")).decode("ascii")


def test_graylog_token_auth_header(start_server):
    server = start_server("json")
    client = McpHttpClient(f"{server.base}/api/mcp", token="abc123def456789", timeout=5)

    info = client.initialize()

    assert info["serverInfo"]["name"] == "fake-graylog-mcp"
    assert client.transport == "streamable-http"
    first_post = next(s for s in server.seen if s[0] == "POST")
    assert _header(first_post, "Authorization") == _basic("abc123def456789")
    # 密码位必须是固定字面量 token，不是真实密码、不是空串
    assert _header(first_post, "Authorization") != _basic("abc123def456789", "other")
    assert _header(first_post, "Authorization") != _basic("user", "abc123def456789")


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
    assert _header(first_get, "Authorization") == _basic("t")


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


# 真机 Graylog 7.1 的 search_messages 参数形状（逐字照抄自 inputSchema）
GRAYLOG_SCHEMA = {"type": "object", "properties": {
    "fields": {"type": "array"}, "limit": {"type": "integer"},
    "offset": {"type": "integer"}, "query": {"type": "string"},
    "range_seconds": {"type": "integer"},
    "stream_categories": {"type": "array"}, "streams": {"type": "array"},
}}


def test_map_arguments_uses_range_seconds_and_fields():
    """真机用 range_seconds 而不是 from/to；不请求 fields 只会回两列。"""
    from datetime import datetime, timedelta, timezone

    end = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)
    start = end - timedelta(minutes=30)
    args = patrol.map_arguments(GRAYLOG_SCHEMA, stream_id="6a30a6ab", query="",
                                start=start, end=end, limit=20,
                                fields=patrol._request_fields(
                                    {"required_fields": ["ts", "src_ip", "action"]}))
    assert args["range_seconds"] == 1800
    assert args["streams"] == ["6a30a6ab"]
    assert args["limit"] == 20
    # ts 必须换成真机字段名 timestamp，否则请求的是一个不存在的列
    assert args["fields"] == ["timestamp", "src_ip", "action", "source"]
    assert "from" not in args and "to" not in args        # schema 没声明就不该发
    assert "query" not in args                            # 空查询不发


def test_map_arguments_omits_empty_fields():
    from datetime import datetime, timezone

    now = datetime(2026, 11, 25, 15, 0, 0, tzinfo=timezone.utc)
    args = patrol.map_arguments(GRAYLOG_SCHEMA, stream_id="s1", query="", start=now,
                                end=now, limit=5, fields=[])
    assert "fields" not in args       # 空数组会让服务端可能一列都不回


# ---------------------------------------------------------------- 字段映射
ZTNA_MAPPING = {"username": "employee_id", "display_name": "employee_name"}


def test_request_fields_applies_mapping_and_forces_time_source():
    """映射优先生效；timestamp/source 强制附带——漏时间列时巡检窗口静默失效。"""
    stream = {"required_fields": ["ts", "username", "display_name"],
              "field_mapping": dict(ZTNA_MAPPING)}
    assert patrol._request_fields(stream) == ["timestamp", "employee_id", "employee_name", "source"]


def test_request_fields_respects_custom_ts_mapping():
    """ts 被映射到设备自己的时间列时，以映射为准，不再追加 timestamp。"""
    stream = {"required_fields": ["ts", "src_ip"],
              "field_mapping": {"ts": "occurred_at"}}
    fields = patrol._request_fields(stream)
    assert fields == ["occurred_at", "src_ip", "source"]
    assert "timestamp" not in fields


def test_request_fields_no_mapping_falls_back_to_builtin():
    assert patrol._request_fields({"required_fields": ["ts", "src_ip"]}) == \
        ["timestamp", "src_ip", "source"]


def test_apply_field_mapping_rewrites_platform_names():
    records = [{"employee_id": "emp_1", "employee_name": "张三", "src_ip": "1.1.1.1"},
               {"employee_id": "emp_2", "src_ip": "2.2.2.2"}]   # 第二条没有 employee_name
    stream = {"field_mapping": dict(ZTNA_MAPPING)}
    out = patrol._apply_field_mapping(records, stream)
    assert out[0] == {"username": "emp_1", "display_name": "张三", "src_ip": "1.1.1.1"}
    assert "username" in out[1] and "display_name" not in out[1]   # 缺列不动，如实统计缺失


def test_apply_field_mapping_never_overwrites_native_fields():
    """服务端本就回了 username（标准字段）时，不做映射覆盖。"""
    records = [{"username": "native", "employee_id": "emp_9"}]
    out = patrol._apply_field_mapping(records, {"field_mapping": dict(ZTNA_MAPPING)})
    assert out[0]["username"] == "native"
    assert out[0]["employee_id"] == "emp_9"     # 原字段保留


def test_apply_field_mapping_noop_without_mapping():
    records = [{"employee_id": "x"}]
    assert patrol._apply_field_mapping(records, {}) is records


def test_apply_field_mapping_skips_dash_placeholder():
    """设备用 '-' 占位表示缺失：不写入平台字段，否则会凭空多出叫 '-' 的用户。"""
    records = [{"employee_id": "-", "employee_name": "-"},
               {"employee_id": "emp_1", "employee_name": "10096661"}]
    out = patrol._apply_field_mapping(records, {"field_mapping": dict(ZTNA_MAPPING)})
    assert "username" not in out[0] and "display_name" not in out[0]
    assert out[0]["employee_id"] == "-"          # 原始字段保留，缺不缺由统计如实呈现
    assert out[1]["username"] == "emp_1"
    assert out[1]["display_name"] == "10096661"


def test_apply_field_mapping_converts_bool_ua_class():
    """真机 ua_is_pc 是布尔：映射到 ua_class 时 true→pc；false 不写值——
    只声明「不是 PC」可能是手机/平板，写 other 会把设备类型全部压平，
    留空交给 ua_class_of 从 UA 文本派生 mobile/feishu。"""
    records = [{"ua_is_pc": True}, {"ua_is_pc": False},
               {"ua_is_pc": "true"},
               {"ua_is_pc": "0", "ua_raw": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_1) Safari/605"}]
    out = patrol._apply_field_mapping(
        records, {"field_mapping": {"ua_class": "ua_is_pc"}})
    assert out[0]["ua_class"] == "pc"
    assert "ua_class" not in out[1]                # false 不写，待派生
    assert out[2]["ua_class"] == "pc"
    assert "ua_class" not in out[3]


def test_request_fields_real_ztna_stream_shape():
    """真机零信任流（2026-11-26 Fields 面板实测）：契约字段 + 默认映射后的取数列。"""
    from app.services.patrol_settings import ZTNA_DEFAULT_MAPPING
    stream = {"required_fields": ["ts", "src_ip", "url", "status_code", "ua_raw",
                                  "ua_class", "username", "display_name"],
              "field_mapping": dict(ZTNA_DEFAULT_MAPPING)}
    assert patrol._request_fields(stream) == [
        "timestamp", "src_ip", "request_uri", "response_status",
        "request_user_agent", "ua_is_pc", "employee_id", "employee_name", "source"]


# ---------------------------------------------------------------- 列式返回
def test_extract_records_parses_columnar_with_schema_prefix():
    """真机返回：schema 列定义 + datarows 行数组，列名带 "field: " 前缀。"""
    payload = {
        "schema": [
            {"column_type": "field", "type": "string", "field": "source", "name": "field: source"},
            {"column_type": "field", "type": "date", "field": "timestamp", "name": "field: timestamp"},
        ],
        "datarows": [["10.46.255.138", "2026-11-25T15:25:00.683Z"],
                     ["10.46.255.139", "2026-11-25T15:24:58.476Z"]],
        "metadata": {"keys": ["effective_timerange"]},
    }
    records = patrol.extract_records(payload)
    assert len(records) == 2
    assert records[0] == {"source": "10.46.255.138", "timestamp": "2026-11-25T15:25:00.683Z"}


def test_extract_records_parses_columnar_nested_and_dict_rows():
    payload = {"data": {"columns": [{"field": "src_ip"}, {"field": "action"}],
                        "rows": [{"src_ip": "1.1.1.1", "action": "block"},
                                 ["2.2.2.2", "observe"]]}}
    records = patrol.extract_records(payload)
    assert records == [{"src_ip": "1.1.1.1", "action": "block"},
                       {"src_ip": "2.2.2.2", "action": "observe"}]


def test_extract_records_still_reads_message_lists():
    payload = {"messages": [{"message": {"src_ip": "1.1.1.1"}, "_id": "m1"}], "total": 1}
    assert patrol.extract_records(payload) == [{"src_ip": "1.1.1.1", "_id": "m1"}]


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

    # 显式传 cfg，避免 discover_streams 内部去读 patrol_setting 表（测试库未建）
    streams = patrol.discover_streams(cfg=PatrolConfig(url="http://graylog.local"))

    assert stub.calls == ["list_streams"]
    assert [s["id"] for s in streams] == ["aaa111", "bbb222", "ccc333"]
    assert [s["suggested"] for s in streams] == ["IPS", "WAF", "ZTNA"]


def test_discover_streams_degrades_on_mcp_error(monkeypatch):
    class _Boom:
        def call_tool(self, name, arguments=None):
            from app.services.mcp_client import McpError
            raise McpError("connect refused")

    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: _Boom())
    # 端口 9 必然拒绝：REST 兜底会立刻失败，不拖慢测试
    cfg = PatrolConfig(url="http://127.0.0.1:9/api/mcp", timeout=0.5)
    assert patrol.discover_streams(cfg=cfg) == []


def test_discover_streams_parses_grn_list(monkeypatch):
    """真实 Graylog 的一种包法：list_streams 只回 GRN 字符串列表（无标题）。

    应逐条 describe_resource 补全 title；describe 不可用时退回「id 从 GRN 解析、
    title 用 id 占位」，且不应触发 list_resource（清单本身已拿到）。
    """
    stub = _StreamStub({"resources": [
        "grn:graylog:stream:aaa111",
        "grn:graylog:stream:bbb222",
        "grn:graylog:user:should-not-match",   # 非流 GRN 必须被忽略
    ]})
    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: stub)

    streams = patrol.discover_streams(cfg=PatrolConfig(url="http://graylog.local"))

    assert stub.calls == ["list_streams", "describe_resource", "describe_resource"]
    assert [s["id"] for s in streams] == ["aaa111", "bbb222"]
    assert streams[0]["title"] == "aaa111"   # describe 拿不到 title，用 id 占位


def test_discover_streams_falls_back_to_list_resource(monkeypatch):
    """list_streams 拿不到东西时：list_resource(type=stream) → describe_resource 补全。"""
    class _SeqStub:
        def __init__(self, results):
            self.results = list(results)
            self.calls = []

        def call_tool(self, name, arguments=None):
            self.calls.append(name)
            result = self.results.pop(0)
            if isinstance(result, Exception):
                raise result
            return {"structuredContent": result}

    stub = _SeqStub([
        [],                                                  # list_streams：空
        {"resources": ["grn:graylog:stream:aaa111",
                       "grn:graylog:stream:bbb222"]},        # list_resource：GRN 列表
        {"id": "aaa111", "title": "IPS 入侵防御", "description": "边界 IPS"},   # describe
        {"id": "bbb222", "title": "norm-ztna"},              # describe（无描述）
    ])
    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: stub)

    streams = patrol.discover_streams(cfg=PatrolConfig(url="http://graylog.local"))

    assert stub.calls == ["list_streams", "list_resource",
                          "describe_resource", "describe_resource"]
    assert [s["id"] for s in streams] == ["aaa111", "bbb222"]
    assert [s["title"] for s in streams] == ["IPS 入侵防御", "norm-ztna"]
    assert [s["suggested"] for s in streams] == ["IPS", "ZTNA"]


def test_discover_streams_survives_list_resource_missing(monkeypatch):
    """两级都不可用（老版本服务端没有资源接口）时：返回空且不抛异常。"""
    class _Missing:
        def __init__(self):
            self.calls = []

        def call_tool(self, name, arguments=None):
            from app.services.mcp_client import McpError
            self.calls.append(name)
            raise McpError("tool not found: -32601")

    stub = _Missing()
    monkeypatch.setattr(patrol, "build_client", lambda *a, **k: stub)
    cfg = PatrolConfig(url="http://127.0.0.1:9/api/mcp", timeout=0.5)
    assert patrol.discover_streams(cfg=cfg) == []
    assert stub.calls == ["list_streams", "list_resource"]


def test_rest_streams_url_derives_from_mcp_url():
    """MCP 地址 → REST 流清单地址（兜底用），三种写法都要对。"""
    assert patrol._rest_streams_url("https://graylog:9000/api/mcp") == "https://graylog:9000/api/streams"
    assert patrol._rest_streams_url("https://graylog:9000/api/mcp/") == "https://graylog:9000/api/streams"
    assert patrol._rest_streams_url("http://10.0.0.5:9000") == "http://10.0.0.5:9000/api/streams"


def test_discover_streams_falls_back_to_rest(monkeypatch):
    """MCP 工具全部不可用时，最后一级 REST /api/streams 必须能拿到流。"""
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import threading

    seen_auth: list[str] = []

    class _Rest(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            seen_auth.append(self.headers.get("Authorization") or "")
            body = json.dumps({"streams": [
                {"id": "rest111", "title": "IPS 入侵防御", "description": "边界 IPS"},
                {"id": "rest222", "title": "WAF access log", "description": ""},
            ]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Rest)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()

    class _NoTools:
        def call_tool(self, name, arguments=None):
            from app.services.mcp_client import McpError
            raise McpError("tool not found")

    try:
        cfg = PatrolConfig(url=f"http://127.0.0.1:{port}/api/mcp", token="abc123")
        detail = patrol.discover_streams_detailed(_NoTools(), cfg=cfg)
        streams = detail["streams"]
        assert [s["id"] for s in streams] == ["rest111", "rest222"]
        assert streams[0]["title"] == "IPS 入侵防御"
        assert streams[0]["suggested"] == "IPS"
        # 兜底也走同一套鉴权：Basic base64("<token>:token")
        assert seen_auth and seen_auth[0].startswith("Basic ")
        assert detail["attempts"][-1]["step"].startswith("REST")
        assert detail["attempts"][-1]["ok"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_discover_streams_reports_why_empty(monkeypatch):
    """全链路拿不到时，attempts 必须说清每一步为什么失败（页面直接展示）。"""
    class _Boom:
        def call_tool(self, name, arguments=None):
            from app.services.mcp_client import McpError
            raise McpError("HTTP 403 Forbidden")

    cfg = PatrolConfig(url="http://127.0.0.1:9/api/mcp", token="wrong", timeout=0.5)
    detail = patrol.discover_streams_detailed(_Boom(), cfg=cfg)

    assert detail["streams"] == []
    steps = [a["step"] for a in detail["attempts"]]
    assert steps[:2] == ["MCP list_streams", "MCP list_resource(type=stream)"]
    assert all(a["ok"] is False for a in detail["attempts"])
    assert "403" in detail["attempts"][0]["detail"]
