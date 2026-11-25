# mock-graylog：没有真 Graylog 时，先把平台侧链路打通

平台「数据源」页要经 MCP 读 Graylog 的 **流清单 / 字段清单 / 消息**，才能选流、算拉取量、判健康度。这个进程用标准库实现 MCP 传输的最小集合，顶上真 Graylog 的位置。

纯标准库，无依赖，Windows / Linux / macOS 都能直接跑。

## 它能验证什么，不能验证什么

| | 说明 |
|---|---|
| ✅ 能验 | MCP 握手（`initialize`）、工具发现（`tools/list`）、工具调用与**返回包解析**（`structuredContent`、text 内嵌 JSON、`{"streams": [...]}` 三种包法）、数据源页的流下拉与「校验流 ID」、巡检拉取量与缺失率统计 |
| ❌ 不能验 | **pipeline 分流**——`ztna.rules` 的 `_schema_ok` / `route_to_stream` 只能在真 Graylog 的 `Simulator` 里看，这里的消息是合成的 |
| ❌ 不能验 | **鉴权**——任何 token 都放行，别用它判断「token 配错了会不会报错」 |

## 启动

```bash
python deploy/graylog/mock/mock_graylog_mcp.py                 # 127.0.0.1:18080
python deploy/graylog/mock/mock_graylog_mcp.py --port 9001
python deploy/graylog/mock/mock_graylog_mcp.py --messages 30   # search 返回 30 条合成消息
```

`--messages` 打开后，`search_messages` / `aggregate_messages` 会按固定种子生成消息：字段符合 [`docs/log-source-spec.md`](../../../docs/log-source-spec.md)，约 3% 故意不合规（`_schema_ok=false`），匿名访问按规范**移除 `username`** 而不是填空串——正好用来检查平台有没有把这些情况算错。

## 返回内容

| 工具 | 返回 |
|---|---|
| `list_streams` | 9 条流：`raw/norm × ztna/ips/waf` + `norm-ztna-reject` + `系统事件`，id 硬编码（重启不变） |
| `list_fields` | 17 个规范字段（`ts` / `src_ip` / `ua_class` / `_schema_ok` …） |
| `search_messages` | `--messages N` 时返回 N 条合成消息，否则空 |
| `aggregate_messages` | 消息条数（跟随 `--messages`） |

## 接到平台上

数据源页 → 右上「Graylog 接入」：

| 字段 | 值 |
|---|---|
| MCP 地址 | `http://127.0.0.1:18080/mcp` |
| Token | 任意，如 `mock-token` |
| 鉴权方式 | `token`（发 `Authorization: Basic base64("<token>:token")`，Graylog 官方约定；mock 本身不校验，随便填） |

保存后点「测试连接」，应回 `server=mock-graylog-mcp 7.1.0` 与 9 条流；再打开「Graylog 流清单」核对下拉是否可搜索。

浏览器直接访问 `http://127.0.0.1:18080/mcp` 会看到一行运行状态，用来确认进程还活着。

## 用完切回真 Graylog

把「Graylog 接入」里的地址换成真实 `http(s)://<graylog>/api/mcp`、Token 换成真实 API Token（生产建议只读 Token），保存后重测。mock 进程可以直接关掉，配置不需要清理——地址一换就指回去了。

> 不要把这个地址留在任何共享环境或生产配置里：它不校验 token，也没有任何访问控制。默认只监听 `127.0.0.1`，请不要用 `--host 0.0.0.0` 暴露到网络上。
