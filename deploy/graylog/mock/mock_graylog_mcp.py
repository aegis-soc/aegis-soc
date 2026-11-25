#!/usr/bin/env python3
"""本地 mock：模拟 Graylog 7.x 的 MCP Server，用于在没装 Graylog 时打通平台侧链路。

用途
----
平台「数据源」页依赖 MCP 读 Graylog 的 stream 清单、字段清单和消息，
用来做流选择、拉取量统计与健康度判定。手边还没有可用 Graylog 时，用这个
进程顶上，验证的是**平台侧的 MCP 客户端**：握手、tools/list、tools/call、
以及各种返回包法的解析（`{"streams": [...]}`、`structuredContent`、text 内嵌 JSON）。

不能做什么
----------
- **不执行 pipeline**：`ztna.rules` 的分流结果只能在真 Graylog 的 Simulator 里看。
  这里的消息是合成的，`_schema_ok` 全部人为置位，验证不了规则对错。
- **不校验 token**：任何 token 都放行，不能用它验证鉴权逻辑。
- **数据全在内存**：进程退出即丢；stream id 硬编码，重启后不变。

用法
----
    python mock_graylog_mcp.py                  # 127.0.0.1:18080，search 返回空
    python mock_graylog_mcp.py --port 9001
    python mock_graylog_mcp.py --messages 30    # search_messages 返回 30 条合成消息

接平台：数据源页 → 「Graylog 接入」→ MCP 地址 `http://127.0.0.1:18080/mcp`，
Token 随便填（如 `mock-token`），鉴权选 token，保存后点「测试连接」。
"""
from __future__ import annotations

import argparse
import json
import random
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# 9 条流：四类日志源 × (raw|norm) + ztna 的 reject 流 + Graylog 自身的系统事件。
# id 是固定的假值，方便配置后反复重启仍然对得上。
STREAMS = [
    {"id": "65f3a2b1c0d4e5f6a7b8c9d0", "title": "raw-ztna", "description": "零信任网关原始日志（保真，平台不读）"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d1", "title": "norm-ztna", "description": "零信任网关归一化（平台唯一读入口）"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d2", "title": "norm-ztna-reject", "description": "缺必填字段的零信任日志"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d3", "title": "raw-ips", "description": "IPS 原始日志"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d4", "title": "norm-ips", "description": "IPS 归一化"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d5", "title": "raw-waf", "description": "WAF 原始日志"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d6", "title": "norm-waf", "description": "WAF 归一化"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d7", "title": "norm-nta", "description": "流量分析归一化"},
    {"id": "65f3a2b1c0d4e5f6a7b8c9d8", "title": "系统事件", "description": "Graylog 自身运行事件"},
]

FIELDS = [
    "ts", "ingest_ts", "src_ip", "username", "url", "method", "status_code",
    "ua_raw", "ua_class", "ua_browser", "ua_browser_ver", "ua_os",
    "app_id", "gateway_node", "_schema_ok", "_schema_missing",
]

USERS = ["zhangsan", "lisi", "wangwu", "zhaoliu", None]
UA_CLASSES = ["pc", "mobile", "feishu", "tablet"]
APPS = ["oa-portal", "gitlab", "jumpserver", "wiki", "erp"]
NODES = ["zt-gw-sh-01", "zt-gw-sh-02", "zt-gw-bj-01"]
PATHS = ["/login", "/api/v1/user/profile", "/dashboard", "/api/v1/doc/list"]


def build_messages(count: int, stream_id: str) -> list[dict]:
    """合成符合 log-source-spec 的 norm-ztna 消息。

    匿名访问按规范「移除 username 字段」，不写空串也不写 null——用于验证
    平台侧遇到缺字段时不会把它算成解析失败。
    """
    rnd = random.Random(20261122)  # 固定种子：每次启动消息一致，便于对比
    now_ms = int(time.time() * 1000)
    out: list[dict] = []
    for i in range(count):
        ts = now_ms - rnd.randint(0, 900) * 1000
        user = rnd.choice(USERS)
        ok = rnd.random() > 0.03  # 约 3% 不合规，用来看健康度降级
        msg = {
            "_id": f"mock-{stream_id[:6]}-{i:06d}",
            "timestamp": ts // 1000,
            "source": rnd.choice(NODES),
            "ts": ts,
            "ingest_ts": ts + rnd.randint(200, 1500),
            "src_ip": f"10.32.{rnd.randint(1, 40)}.{rnd.randint(2, 250)}",
            "url": rnd.choice(PATHS),
            "method": rnd.choice(["GET", "GET", "POST"]),
            "status_code": rnd.choice([200, 200, 200, 302, 401, 403]),
            "ua_raw": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0.0.0",
            "ua_class": rnd.choice(UA_CLASSES),
            "ua_browser": "Chrome",
            "ua_browser_ver": "131",
            "ua_os": "Windows",
            "app_id": rnd.choice(APPS),
            "gateway_node": rnd.choice(NODES),
            "source_code": "ztna",
            "schema_version": "1.0",
            "_schema_ok": "true" if ok else "false",
            "_schema_missing": "" if ok else "src_ip,",
            "_ts_from_ingest": "false",
            "_anonymous": "false",
        }
        if user:
            msg["username"] = user
        else:
            msg["_anonymous"] = "true"
        out.append(msg)
    return out


def build_columnar(messages: list[dict], args: dict) -> dict:
    """按真机 Graylog 的列式包法返回：``schema`` 列定义 + ``datarows`` 行数组。

    真机不传 ``fields`` 时只回 ``source`` / ``timestamp`` 两列；传了 ``fields``
    就按请求的列顺序返回。``--columns`` 模式复现这个形态，用来回归平台的解析层：
    不认 ``datarows`` 就会「回了 20 行、平台判成 0 条」。
    """
    wanted = args.get("fields")
    names = ([str(x) for x in wanted if str(x).strip()]
             if isinstance(wanted, list) and wanted else ["source", "timestamp"])
    schema = [{"column_type": "field",
               "type": "date" if n in ("timestamp", "ts") else "string",
               "field": n, "name": f"field: {n}"} for n in names]
    rows: list[list] = []
    for msg in messages:
        row = []
        for n in names:
            value = msg.get(n)
            if n == "timestamp" and isinstance(value, (int, float)):
                value = time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime(value))
            row.append(value)
        rows.append(row)
    return {
        "schema": schema,
        "datarows": rows,
        "metadata": {"keys": ["effective_timerange"],
                     "effective_timerange": {"range_seconds": args.get("range_seconds")}},
    }


class MockHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    message_count = 0
    grn_mode = False
    empty_mcp = False
    columns_mode = False

    def log_message(self, *args):  # 静音，避免刷屏
        pass

    def _json(self, obj, code: int = 200, extra_headers: dict | None = None) -> None:
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Mcp-Session-Id", "mock-session-1")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        """REST 流清单 + 状态页。

        ``/api/streams`` 模拟 Graylog REST API（平台在 MCP 取不到流时会退到这里）；
        其它路径给一行运行状态，方便确认进程活着。
        """
        if self.path.rstrip("/").endswith("/api/streams"):
            payload = {"streams": STREAMS, "total": len(STREAMS)}
            self._json(payload)
            return
        body = (
            "mock-graylog-mcp 正在运行。\n"
            f"POST 到此端点进行 MCP 调用（当前端点 {self.path}）。\n"
            f"GET /api/streams 模拟 Graylog REST 流清单。\n"
            f"流 {len(STREAMS)} 条，合成消息 {self.message_count} 条/次查询。\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw or b"{}")
        except json.JSONDecodeError:
            self._json({"jsonrpc": "2.0", "id": None,
                        "error": {"code": -32700, "message": "parse error"}})
            return

        req_id = req.get("id")
        method = req.get("method")

        # 通知（无 id）：按 JSON-RPC 规范回 202 空体
        if req_id is None:
            self.send_response(202)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if method == "initialize":
            result = {
                "protocolVersion": "2025-06-18",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-graylog-mcp", "version": "7.1.0"},
            }
        elif method == "tools/list":
            tools = [
                {"name": "list_streams", "description": "List Graylog streams",
                 "inputSchema": {"type": "object", "properties": {}}},
                {"name": "list_fields", "description": "List message fields",
                 "inputSchema": {"type": "object", "properties": {}}},
                {"name": "search_messages", "description": "Search messages",
                 "inputSchema": {"type": "object", "properties": {
                     "query": {"type": "string"}, "limit": {"type": "integer"},
                     "stream_id": {"type": "string"}}}},
                {"name": "aggregate_messages", "description": "Aggregate count",
                 "inputSchema": {"type": "object", "properties": {
                     "query": {"type": "string"}, "stream_id": {"type": "string"}}}},
            ]
            if MockHandler.columns_mode:
                # 真机 Graylog 7.1 的 search_messages 参数形状（字段名逐个照抄）
                tools[2] = {
                    "name": "search_messages", "description": "Search messages, columnar result",
                    "inputSchema": {"type": "object", "properties": {
                        "fields": {"type": "array"}, "limit": {"type": "integer"},
                        "offset": {"type": "integer"}, "query": {"type": "string"},
                        "range_seconds": {"type": "integer"},
                        "stream_categories": {"type": "array"},
                        "streams": {"type": "array"}}},
                }
            if MockHandler.grn_mode:
                tools += [
                    {"name": "list_resource", "description": "List resources by type",
                     "inputSchema": {"type": "object", "properties": {
                         "type": {"type": "string"}}}},
                    {"name": "describe_resource", "description": "Describe a resource by GRN",
                     "inputSchema": {"type": "object", "properties": {
                         "grn": {"type": "string"}}}},
                ]
            result = {"tools": tools}
        elif method == "tools/call":
            params = req.get("params") or {}
            name = params.get("name")
            args = params.get("arguments") or {}
            result = self._call_tool(name, args)
        else:
            self._json({"jsonrpc": "2.0", "id": req_id,
                        "error": {"code": -32601, "message": f"method not found: {method}"}})
            return

        self._json({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _call_tool(self, name: str, args: dict) -> dict:
        if name == "list_streams":
            if MockHandler.empty_mcp:
                payload = {"streams": []}
            elif MockHandler.grn_mode:
                # 模拟真实 Graylog 的 GRN 包法：只有 GRN 字符串，没有流对象
                payload = {"resources": [f"grn:graylog:stream:{s['id']}" for s in STREAMS]}
            else:
                payload = {"streams": STREAMS}
            return {
                "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
                "structuredContent": payload,
            }
        if name == "list_resource":
            rtype = str((args or {}).get("type") or "")
            if rtype != "stream" or MockHandler.empty_mcp:
                return {"structuredContent": {"resources": []}}
            payload = {"resources": [f"grn:graylog:stream:{s['id']}" for s in STREAMS]}
            return {"structuredContent": payload}
        if name == "describe_resource":
            grn = str((args or {}).get("grn") or "")
            sid = grn.rsplit(":", 1)[-1] if grn.startswith("grn:graylog:stream:") else ""
            stream = next((s for s in STREAMS if s["id"] == sid), None)
            if not stream:
                return {"content": [{"type": "text", "text": f"unknown grn: {grn}"}],
                        "isError": True}
            payload = {"id": stream["id"], "grn": grn, "title": stream["title"],
                       "description": stream["description"], "disabled": False,
                       "index_set_id": "default-index-set"}
            return {
                "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
                "structuredContent": payload,
            }
        if name == "list_fields":
            return {"structuredContent": {"fields": [{"name": f} for f in FIELDS]}}
        if name in ("search_messages", "aggregate_messages"):
            streams = args.get("streams")
            first = str(streams[0]) if isinstance(streams, list) and streams else ""
            stream_id = (first or str(args.get("stream_id") or args.get("query")
                                     or "65f3a2b1c0d4e5f6a7b8c9d1"))
            limit = self.message_count
            try:
                limit = min(int(args.get("limit") or limit), limit) if self.message_count else 0
            except (TypeError, ValueError):
                limit = self.message_count
            messages = build_messages(limit, stream_id) if limit else []
            if name == "aggregate_messages":
                return {"structuredContent": {"count": len(messages), "total": len(messages)}}
            if MockHandler.columns_mode:
                payload = build_columnar(messages, args)
                return {
                    "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False)}],
                    "structuredContent": payload,
                }
            return {"structuredContent": {"messages": messages, "total": len(messages)}}
        return {"content": [{"type": "text", "text": f"unknown tool: {name}"}],
                "isError": True}


def main() -> None:
    parser = argparse.ArgumentParser(description="Mock Graylog MCP server for local testing")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址（默认仅本机）")
    parser.add_argument("--port", type=int, default=18080, help="监听端口，默认 18080")
    parser.add_argument("--messages", type=int, default=0,
                        help="search_messages 每次返回的合成消息条数，0 表示返回空")
    parser.add_argument("--grn", action="store_true",
                        help="模拟真实 Graylog 的 GRN 包法：list_streams 只回 "
                             "grn:graylog:stream:<id> 列表，需靠 list_resource / "
                             "describe_resource 兜底（用于验证平台的降级链路）")
    parser.add_argument("--empty-mcp", action="store_true",
                        help="让 MCP 的 list_streams / list_resource 都回空，用于验证平台"
                             "退到 REST GET /api/streams 的兜底是否生效")
    parser.add_argument("--columns", action="store_true",
                        help="复现真机 Graylog 的列式返回：search_messages 的参数是 "
                             "fields/limit/offset/query/range_seconds/stream_categories/streams，"
                             "返回 schema + datarows（行数组），用于回归平台的解析层")
    args = parser.parse_args()

    MockHandler.grn_mode = args.grn
    MockHandler.empty_mcp = args.empty_mcp
    MockHandler.columns_mode = args.columns
    MockHandler.message_count = max(args.messages, 0)
    server = ThreadingHTTPServer((args.host, args.port), MockHandler)
    modes = " / ".join(m for m, on in (("GRN 包法", args.grn), ("MCP 空返回", args.empty_mcp),
                                       ("列式返回", args.columns)) if on)
    print(f"mock-graylog-mcp 已启动: http://{args.host}:{args.port}/mcp", flush=True)
    print(f"  流 {len(STREAMS)} 条 / 字段 {len(FIELDS)} 个 / 合成消息 {MockHandler.message_count} 条每次"
          + (f" / {modes}" if modes else ""), flush=True)
    print("  REST 兜底端点: GET /api/streams", flush=True)
    print("  接平台：数据源页 → Graylog 接入 → 上述地址 + 任意 token", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n已停止", flush=True)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
