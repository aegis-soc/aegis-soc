# 设备插件开发指南

平台采用**注册式插件 + Manifest 能力声明**：新增一款安全设备只需写一个 Python 类并注册一行，策略引擎、任务调度、前端配置向导都无需改动。

## 1. 核心概念

| 概念 | 说明 |
|---|---|
| `BasePlugin` | 插件抽象基类，位于 `backend/plugins/base.py` |
| `Manifest` | 能力声明：`ioc_types`（支持的 IOC 类型）、`capabilities`（BLOCK/UNBLOCK/QUERY）、`config_schema` |
| `PluginResult` | 统一执行结果：`success` / `message` / `raw` / `http_status` |
| `credential_ref` | 设备表中的环境变量名；凭据只从环境变量注入，**不落库、不写日志** |
| 能力矩阵 | `device_capability` 表；策略引擎只向声明了对应 `(ioc_type, capability)` 的设备派发任务 |

> v1.0 采用注册式（进程内）以规避动态插件的跨平台坑；v1.1 将支持独立进程/容器插件与签名校验。

## 2. 五步开发一个新插件

### 步骤 1：新建文件 `backend/plugins/builtin/my_device.py`

```python
from typing import Any
import requests
from plugins.base import BasePlugin, PluginConfigError, PluginResult


class MyDevicePlugin(BasePlugin):
    plugin_code = "my_device"
    plugin_name = "示例设备"
    version = "1.0.0"
    ioc_types = ["IP"]                       # 仅支持 IP，不会收到 DOMAIN 任务
    capabilities = ["BLOCK", "UNBLOCK"]      # 声明支持的能力
    description = "示例：通过 REST API 下发 IP 黑名单"
    config_schema = {
        "base_url": "string（必填）",
        "credential_ref": "string（环境变量名，值为含 api_key 的 JSON）",
        "timeout": "int（秒，默认 10）",
    }
    required_config = ["base_url"]           # 平台在执行前统一校验，缺失直接判配置错误
    default_timeout = 10

    def _headers(self, config: dict[str, Any]) -> dict[str, str]:
        api_key = config.get("api_key")
        if not api_key:
            raise PluginConfigError("缺少 api_key，请通过 credential_ref 注入")
        return {"Authorization": f"Bearer {api_key}"}

    def test_connection(self, config: dict[str, Any]) -> PluginResult:
        # 只做连通性检查，不产生任何封禁副作用
        try:
            r = requests.get(
                config["base_url"].rstrip("/") + "/health",
                headers=self._headers(config), timeout=self.default_timeout,
            )
            return PluginResult(True, f"HTTP {r.status_code}", raw=r.text[:1000], http_status=r.status_code)
        except Exception as exc:
            return PluginResult(False, str(exc))

    def block(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        r = requests.post(
            config["base_url"].rstrip("/") + "/blacklist",
            json={"ip": ioc_value}, headers=self._headers(config), timeout=self.default_timeout,
        )
        return PluginResult(r.ok, f"HTTP {r.status_code}", raw=r.text[:1000], http_status=r.status_code)

    def unblock(self, ioc_value: str, ioc_type: str, config: dict[str, Any]) -> PluginResult:
        r = requests.delete(
            config["base_url"].rstrip("/") + "/blacklist/" + ioc_value,
            headers=self._headers(config), timeout=self.default_timeout,
        )
        return PluginResult(r.ok, f"HTTP {r.status_code}", raw=r.text[:1000], http_status=r.status_code)
```

### 步骤 2：注册

在 `backend/plugins/builtin/__init__.py` 的 `register_builtins` 中加一行：

```python
register(MyDevicePlugin)
```

重启 `api` / `worker` 后，插件自动出现在「插件管理」页面，并在 bootstrap 时写入 `device_plugin` 表。

### 步骤 3：声明能力

- `ioc_types`：目前支持 `IP` / `DOMAIN`；策略引擎会据此过滤。
- `capabilities`：`BLOCK`（封禁）、`UNBLOCK`（解封）、`QUERY`（状态查询）。注册时校验，出现未知能力直接拒绝启动。
- `required_config`：必填配置键列表。`BasePlugin.execute()` 与连通性测试都会先调用 `validate_config()`，
  缺项返回「插件配置错误: 缺少必填配置: base_url」并直接判失败（不重试、不进熔断），
  同时会识别 `_credential_missing`，提示「凭据环境变量 XXX 未设置」。
- 若插件不支持 `UNBLOCK`，到期解封与白名单解封任务不会派发给它（会在任务中心体现为无匹配设备）。
- 未实现 `query_status()` 时保持默认实现即可：它**返回失败**，不会伪造「查询成功」。

### 步骤 4：配置设备

在「设备管理」新增设备，选择 `my_device`：

- **插件配置(JSON)**：`{"base_url": "https://device.example.internal", "timeout": 10}`
- **凭据环境变量**：`MY_DEVICE_CRED`

宿主机环境变量（写入 `.env`，**不要提交仓库**）：

```bash
MY_DEVICE_CRED='{"api_key":"your-real-key"}'
```

`resolve_device_config()` 会把该 JSON 合并进插件配置，插件里通过 `config["api_key"]` 读取。

### 步骤 5：测试与验收

- 「设备管理 → 连通性测试」验证 `test_connection`；
- 用 `mock` 之外的真实设备前，先在测试环境发一条告警，检查任务中心的 `device_task_log` 请求/响应报文；
- 补充单元测试（见 `backend/tests/`），禁止依赖真实设备。

## 3. 硬性规范

1. **不得硬编码**任何设备地址、账号、口令、API Key、Token；
2. `test_connection()` 不得产生封禁副作用；
3. 所有网络调用必须设置超时；
4. 异常必须收敛为 `PluginResult(False, ...)`，不要抛到 Worker 之外（`BasePlugin.execute` 已统一兜底）；
5. `raw` 中不得包含凭据；平台写 `device_task_log` 时只存动作与 IOC，不存插件配置；
6. **不得假成功**：只有设备明确确认成功才返回 `success=True`。HTTP 型插件要看状态码与返回体 `message`，
   CLI 型插件要检查回显中的 `% Invalid input` / `Unrecognized command` / `Permission denied` 等错误特征，
   带"配置生效"步骤的设备（如深信服 `applyconfig`）必须校验生效结果，否则黑名单没有真正落地；
7. 读超时 / 提示符未出现属于"结果未知"，应返回失败让任务重试，不要当成功；
8. 插件需自带 README、参数说明、连通性测试与超时控制；
9. 提交 PR 前执行 `pytest -q` 与 `python -m compileall -q app plugins workers`。

## 4. 内置插件参考

| 插件 | 文件 | 可参考的实现要点 |
|---|---|---|
| `mock` | `builtin/mock.py` | 最小实现、闭环演示、单元测试 |
| `http_generic` | `builtin/http_generic.py` | 低代码模板渲染、方法/请求体可配 |
| `ssh_firewall` | `builtin/ssh_firewall.py` | paramiko 交互式 CLI、提示符等待与超时、H3C/华为命令模板 |
| `sangfor_ips` | `builtin/sangfor_ips.py` | 登录取密钥、SHA256 签名、插入/删除、applyconfig 生效、登出 |
| `paloalto_fw` | `builtin/paloalto_fw.py` | PAN-OS XML API、user-id + DAG Tag、解析 `status` 属性避免 200 假成功 |
| `qiming_fw` | `builtin/qiming_fw.py` | Web API 登录（Token 或 Cookie）、路径/报文全参数化、保存生效校验 |
| `qiming_ips` | `builtin/qiming_ips.py` | 口令 SHA256 登录、JWT 缓存与 401 重登、`block_policy` 按 type 封堵、end_time 分钟语义 |
| `aliyun_waf_v3` | `builtin/aliyun_waf_v3.py` | RPC 签名、Describe→合并→整表回写、200 条自动分片、写入后回读校验 |

## 5. 任务执行链路（插件作者需了解）

```
策略引擎 create_task() → device_task(PENDING)
        ↓ dispatch_tasks()
Celery Worker execute_task(task_id)
        ↓ registry.execute(plugin_code, operation, ioc_value, ioc_type, config)
BasePlugin.execute() → 能力校验 → block/unblock/query_status
        ↓ PluginResult
device_task_log 留痕 + 状态回写（SUCCESS / RETRY / FAILED）
        ↓ 失败且未超 max_retry
指数退避：backoff × 2^(retry-1) 秒后重新投递
```

- 幂等：`device_task.uk_task_idempotent (ioc_id, device_id, operation, request_id)`；同一次告警不会重复下发。
- 补偿：Beat 每 2 分钟扫描长期 PENDING 的任务重新投递，防止 broker 抖动丢任务。
- `TASK_EAGER=true`（本地调试）时任务同步执行，方便单步排查插件问题。
