# PA 与启明防火墙接入指南

对应插件：`paloalto_fw`（PAN-OS ≥ 9.1）、`qiming_fw`（天清汉马 USG Web API）。

两个插件都不含任何设备地址与凭据：地址写在设备 `config_json`，口令 / API Key 写在宿主机
环境变量并由 `credential_ref` 引用。

---

## 一、Palo Alto PAN-OS（user-id + DAG）

### 1. 设备侧一次性配置

| 步骤 | 位置 | 说明 |
|---|---|---|
| 建 Tag | Objects → Tags | 名称 `aegis-block`（可用 `tag_name` 改） |
| 建动态地址组 | Objects → Address Groups → Type 选 Dynamic | Match 条件填 `'aegis-block'`（含单引号） |
| 拒绝策略引用 | Policies → Security | 目的地址选该 DAG，动作 Deny，放在放行策略之前 |
| 生成 API Key | 浏览器访问 `/api/?type=keygen&user=<admin>&password=<pwd>` | 返回 `<key>...</key>`，只保存到环境变量 |

> user-id 注册是**即时生效**的，不触发 commit；但设备重启或执行 `clear user-id` 后条目会丢失，
> 需要在平台侧重新下发（后续可加定时对账任务）。

### 2. 平台侧配置

设备「插件配置(JSON)」：

```json
{
  "base_url": "https://10.0.0.1",
  "vsys": "vsys1",
  "tag_name": "aegis-block",
  "verify_ssl": false,
  "timeout": 10
}
```

「凭据环境变量」填 `PA_FW_CRED`，宿主机 `.env`：

```bash
PA_FW_CRED='{"api_key":"LUFRPT0...="}'
```

### 3. 验证

1. 「设备管理 → 连通性测试」应显示 `PAN-OS 执行成功`（内部执行只读 `show system info`）；
2. 发一条测试告警，任务日志的 raw 里应看到 `<response status="success" ...>`；
3. PA 上 Objects → Address Groups 展开 DAG → 成员列表应出现该 IP；
4. 从该 IP 发起访问，Traffic 日志应命中 deny。

### 4. 常见失败

| 现象 | 原因 |
|---|---|
| `code=13` / `Invalid credentials` | API Key 错误或无该 vsys 权限 |
| `code=12` 之类 | Tag 未创建，或 `tag_name` 拼写不一致 |
| 注册成功但流量没被拦 | DAG 未加入拒绝策略，或策略顺序在放行之后 |
| 解封报错 | PAN-OS < 9.1 不支持 `unregister`，需升级或改用地址组方案 |

---

## 二、启明星辰 天清汉马 USG（Web API）

固件版本之间接口差异大，插件不预设业务路径，必须先拿到该型号的接口文档（或抓包）再配置。

### 1. 先用 curl 打通三步

```bash
# 1) 登录
curl -k -X POST https://10.0.0.3/api/v1/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"aegis","password":"***"}'

# 2) 用返回的 token（或 Cookie）下发黑名单
curl -k -X POST https://10.0.0.3/api/v1/firewall/blacklist \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"ip":"5.6.7.8","action":"add"}'

# 3) 如设备需要保存/生效，再调一次
curl -k -X POST https://10.0.0.3/api/v1/firewall/save \
  -H 'Authorization: Bearer <token>'
```

确认每步返回结构，再填平台；不同型号可能用 `token` 头、`X-Token`、纯 Cookie，都可配。

### 2. 平台侧配置

```json
{
  "base_url": "https://10.0.0.3",
  "username": "aegis",
  "login_path": "/api/v1/login",
  "token_path": "data.token",
  "token_header": "Authorization",
  "token_prefix": "Bearer ",
  "block_path": "/api/v1/firewall/blacklist",
  "unblock_path": "/api/v1/firewall/blacklist",
  "block_body": "{\"ip\":\"{ioc_value}\",\"action\":\"add\"}",
  "unblock_body": "{\"ip\":\"{ioc_value}\",\"action\":\"del\"}",
  "save_path": "/api/v1/firewall/save",
  "verify_ssl": false,
  "timeout": 10
}
```

「凭据环境变量」填 `QM_FW_CRED`，值就是口令本身：

```bash
QM_FW_CRED='your-password'
```

### 3. 成功判定规则

- HTTP ≥ 300 → 失败；
- 响应 JSON 含 `code` → 仅 `0 / 200 / true / success / ok` 算成功；
- 含 `success` → 按布尔值；
- 含 `status` → 仅 `success / ok / 0 / true` 算成功；
- 配了 `save_path` 时，保存失败一律整单失败（避免"加了但没生效"的假成功）。

若该型号用 `errCode`、`retCode` 等字段，当前判定会回落为「HTTP 200 即成功」，需要扩展
`_is_success()`——把响应样本发我，加一个字段映射即可。

### 4. 验证

1. 连通性测试只做登录，返回 `登录成功，鉴权方式：Token/Cookie`；
2. 测试告警下发后看任务日志 raw 是否为文档里的成功报文；
3. 设备 Web 界面黑名单列表确认条目存在，再验证策略实际拦截。
