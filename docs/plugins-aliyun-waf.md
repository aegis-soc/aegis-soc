# 阿里云 WAF 3.0 接入指南（IP 黑名单）

对应插件：`aliyun_waf_v3`，走 `DefenseScene=ip_blacklist` 的防护规则，不是 WAF 2.0 的旧接口。

## 1. 为什么是"读-改-写"

WAF 3.0 没有"追加一条 IP"的接口：`ModifyDefenseRule` 的 `remoteAddr` 是**整表覆盖**。
插件因此固定执行三步：

1. `DescribeDefenseRules` 取当前规则与 IP 列表（分页取全）；
2. 在内存里合并新 IP（已存在则直接返回成功，不写）；
3. `ModifyDefenseRule` 回写**完整列表**。

> 如果自己写脚本时跳过第 1 步直接覆盖，会把规则里原有的 IP 全部冲掉——这是最容易踩的坑。

## 2. 容量与分片

| 项 | 值 |
|---|---|
| 单条规则 IP 上限 | **200**（官方限制，超出报 `Defense.Control.DefenseIpCountOversize`） |
| 插件默认分片 | `aegis-block`、`aegis-block-2`、`aegis-block-3` … 每片独立维护 200 条 |
| 默认最大分片数 | `max_rules=5`，即 1000 条；满了会**明确失败**并提示清理，不会静默丢弃 |

分片规则：先填满低序号分片，再创建下一片；解封时自动定位到 IP 所在分片，只改那一片。
某片被清空后规则保留但置为停用（`status=0`），不会残留空规则继续匹配。

## 3. 前置准备

1. **WAF 3.0 实例**，记下 `InstanceId`（形如 `waf_xxx`）；
2. 控制台「防护配置 → 防护规则 → IP 黑名单」**先建好模板**，记下模板 ID 填到 `template_id`；
   模板的"生效对象"决定这些规则作用于哪些域名/实例。

> 插件**不会创建模板**，也不修改模板：模板属于变更审批范围，由人工在控制台建好。
> 插件只做一件事——把 IP 推进这个模板下的 `ip_blacklist` 规则。
> 若模板 ID 不存在、或场景不是 `ip_blacklist`（例如误填了 `waf_group` 的模板），
> 连通性测试会直接失败并指出原因，不会带着错误配置跑下去。

3. **RAM 子账号**，只授予以下权限（最小权限）：

```json
{
  "Version": "1",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "yundun-waf:DescribeInstance",
        "yundun-waf:DescribeDefenseTemplate",
        "yundun-waf:DescribeDefenseRules",
        "yundun-waf:CreateDefenseRule",
        "yundun-waf:ModifyDefenseRule"
      ],
      "Resource": "*"
    }
  ]
}
```

> 不需要任何 `CreateDefenseTemplate` / `ModifyDefenseTemplate` 权限——插件不碰模板。
> `DescribeInstance` / `DescribeDefenseTemplate` 只在「连通性测试」时调用，用于校验实例与模板是否匹配。

## 4. 平台侧配置

设备「插件配置(JSON)」：

```json
{
  "instance_id": "waf_xxxxxxxx",
  "template_id": 5327,
  "rule_name": "aegis-block",
  "action": "block",
  "max_entries": 200,
  "max_rules": 5,
  "auto_create_rule": true,
  "endpoint": "wafopenapi.cn-hangzhou.aliyuncs.com",
  "region_id": "cn-hangzhou",
  "timeout": 10
}
```

「凭据环境变量」填 `ALIYUN_WAF_AK`，宿主机 `.env`：

```bash
ALIYUN_WAF_AK='{"access_key_id":"LTAI...","access_key_secret":"..."}'
```

> 中国内地用 `cn-hangzhou`；非中国内地用 `ap-southeast-1`，endpoint 同步改为
> `wafopenapi.ap-southeast-1.aliyuncs.com`。

## 5. 验证顺序

1. 「设备管理 → 连通性测试」：只读调用 `DescribeInstance` + `DescribeDefenseTemplate` + `DescribeDefenseRules`，
   返回形如「AK 与实例可用（状态 running），模板 aegis-ip-black 场景 ip_blacklist，当前规则：aegis-block(3条)」；
   模板不存在或场景不对会直接返回失败原因；
2. 发一条测试告警，任务日志 raw 里应出现 `{"rule":"aegis-block","count":4}`；
3. WAF 控制台 IP 黑名单规则里应看到新 IP，且**原有 IP 仍在**（验证整表回写没丢数据）；
4. 用该 IP 访问受保护域名，应被拦截；「安全报表」能看到命中记录；
5. 等任务到期或手动解封，确认该 IP 从列表消失、其余 IP 保留。

## 6. 注意事项

- **白名单优先**：同一 IP 同时命中 IP 白名单时不会被拦，先查白名单；
- **并发**：插件用进程内锁串行化，并在写入后回读确认；多 worker 极端并发下仍可能互相覆盖，
  建议单实例只让一个 worker 承担该设备的任务（或在设备上关闭 `auto_dispatch`，由策略定向单设备）；
- **不要在插件运行期间手工编辑同一规则**，会与整表回写互相覆盖；
- **费用**：命中黑名单的请求仍会经过 WAF 并计入 QPS/流量，黑名单只减少回源，不减少 WAF 计费；
- 若 AK 被禁用、模板 ID 写错、或分片满，任务会失败并写明原因，不会虚报成功；
- 若所在组织要求"规则也只能人工建"，把 `auto_create_rule` 设为 `false`：插件只往已有规则里加 IP，
  某次需要新分片时会明确失败并提示去控制台手动创建 `aegis-block-N`，不会擅自新建规则。
