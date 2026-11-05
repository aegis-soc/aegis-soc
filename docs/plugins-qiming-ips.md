# 启明星辰 天清IPS 接入指南（REST API v3）

对应插件：`qiming_ips`，适用于 **IPS \*080 及以上版本**（`enable` 字段需 \*080SP3）。

## 1. 接口对应关系

| 平台动作 | 设备接口 | 关键参数 |
|---|---|---|
| 连通性测试 | `POST /api/v3/login` | 只登录取 token，**不写任何策略** |
| 封禁 IP | `POST /api/v3/block_policy` | `type=4`、`block_content=<IP>`、`end_time`（分钟，0=永久） |
| 到期解封 | 无 | 由设备按 `end_time` 自动失效 |

设备 URL 规范：`{protocol}://{host}:{port}/api/v3/{resource}`，插件默认 `https`，可配 `base_url`。

## 2. 两个关键实现细节

**口令先做 SHA256 再发送。** 设备要的不是明文，插件对 `credential_ref` 里的明文口令做
`SHA256(utf8)` 后取 64 位小写十六进制发送。个别固件要大写，把 `sha256_uppercase` 设为 `true`；
改过认证方式的版本可用 `password_hash: "plain"` 直传。

**只声明 BLOCK，不声明 UNBLOCK。** 厂商这份文档只有「添加封堵策略」，没有删除/查询接口，
因此插件不做解封——到期由设备自身 `end_time` 完成，不会伪造「解封成功」。
拿到删除接口文档后，补 `unblock()` 并把 `capabilities` 加上 `UNBLOCK` 即可，其余代码不用动。

## 3. 设备侧准备

1. 确认版本：登录设备「系统信息」查看是否为 \*080 及以上；\*080SP3 前没有 `enable` 字段；
2. 建 API 账号：建议单独建只具备封堵权限的账号，不要复用 admin；
3. 开放管理口 HTTPS 端口，并在平台所在网段可达。

## 4. 平台侧配置

设备「插件配置(JSON)」：

```json
{
  "base_url": "https://10.10.10.10:8443",
  "username": "api_user",
  "end_time_minutes": 120,
  "enable": 1,
  "verify_ssl": false,
  "timeout": 10
}
```

「凭据环境变量」填 `QIMING_IPS_PASSWORD`，宿主机 `.env`：

```bash
QIMING_IPS_PASSWORD='明文口令'
```

> 环境变量里放**明文**，摘要由插件计算。这样换固件版本时只改配置，不用重新算哈希。

常用可选项：

| 配置 | 默认 | 说明 |
|---|---|---|
| `end_time_minutes` | 120 | 封禁时长，单位分钟；`0` = 永久 |
| `block_type` | 按 IOC 推断 | `IP→4`、`DOMAIN→2`、`URL→3`；也可显式指定 `1`（五元组）或 `5`（XFF） |
| `enable` | 1 | 策略是否启用 |
| `token_ttl` | 1500 | token 缓存秒数；过期或遇到 401 自动重新登录一次 |
| `login_path` / `block_path` | `/api/v3/login`、`/api/v3/block_policy` | 固件路径不同时改这里 |

封禁 IP 时实际发出的报文：

```json
{
  "type": 4,
  "block_content": "1.2.3.4",
  "end_time": 120,
  "enable": 1
}
```

请求头：`Authorization: <登录返回的 data.authorization>`。

## 5. 验证顺序

1. 「设备管理 → 连通性测试」应返回「登录成功，已取得 API token（默认封禁时长 120 分钟…）」，
   这一步只有一次 `/api/v3/login`，不会产生策略；
2. 发一条测试告警，任务日志 raw 里应出现设备返回的 `{"code":0,"msg":"success","data":{"id":…}}`；
3. 设备「封堵策略」列表里应看到 `1.2.3.4`，剩余时间与 `end_time` 一致；
4. 策略到期后设备自动移除该条目（插件不会、也不需要下发解封）。

## 6. 排错

| 现象 | 原因 | 处理 |
|---|---|---|
| `登录失败 code=…` | 账号口令错、或固件要求别种摘要 | 先确认明文能登录 Web；再试 `sha256_uppercase: true` 或 `password_hash: "plain"` |
| `封堵失败 code=…: 策略数量已达上限` | 设备侧封堵条目满 | 清理设备上过期的封堵策略，或缩短 `end_time_minutes` |
| `设备响应非 JSON（HTTP 404）` | `base_url` 少了端口或路径前缀不同 | 用 `curl -k https://ip:port/api/v3/login` 先确认路径 |
| `token` 反复失效 | 设备 token 有效期短 | 调小 `token_ttl`（如 300） |
| 到期后策略还在 | `end_time` 被配成 `0` | `0` 是永久生效，按需改成分钟数 |
