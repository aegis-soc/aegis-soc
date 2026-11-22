# ztna 日志归一化：建流与 pipeline 落地步骤

> 目标：让 Graylog 产出 `norm-ztna` 流，字段严格符合 [`docs/log-source-spec.md`](../../docs/log-source-spec.md) §3.4。
> 平台（LBA / 巡检）只读这个流，不读原始流、不猜字段名。
> 规则文件：[`ztna.rules`](./ztna.rules)

## 0. 前置检查

> 手头还没有可用的 Graylog？先看 [§9 测试环境选型](#9-测试环境选型装在哪最低什么配置)——这东西对 CPU / 内存 / 磁盘的要求比一般中间件高，装错地方等于白折腾。

| 项 | 要求 |
|---|---|
| Graylog | 7.1（`System → Nodes` 可看版本） |
| 权限 | 管理员（建流、建 pipeline、改 input） |
| 输入 | 零信任网关日志已经能进 Graylog，且能查到（原始字段完整） |
| 字段现状 | 先在搜索页随便点开一条日志，展开「All fields」，对照本文 §4 记录真实字段名 |

**先做字段实测，别照着规则猜。** 本文的候选字段名（`user_name` / `account` / `client_ip` / `request_uri`）是常见写法，你们网关的实际名字可能不同——以 `All fields` 为准，改规则里的 `rename` 部分。

## 1. 建三个流

`Streams → Create Stream`，建三条，记下每条流的 **Stream ID**（形如 `65f3a2...`，在流的详情页 URL 里也能看到）：

| 流标题 | 用途 | 保留期建议 | Stream Rule |
|---|---|---|---|
| `raw-ztna` | 原始日志保真，平台不读 | 7–30 天 | 按 **Input** 匹配零信任那个 input（最稳）；若一个 input 收多设备，改用字段 `gl2_source_input` 或 `source` 精确匹配 |
| `norm-ztna` | 归一化后，平台唯一读取入口 | 与业务一致（30 天+） | **不建规则**——由 pipeline 的 `route_to_stream` 投递 |
| `norm-ztna-reject` | 缺必填字段，可见但不读 | 7 天 | **不建规则**——同上 |

> 为什么 `norm-*` 不建 stream rule：Graylog 的 stream rule 在 pipeline **之前**评估，此时 `_schema_ok` 还不存在。用 pipeline 的 `route_to_stream(id: ...)` 才能按归一化结果分流。

## 2. 建 pipeline 并挂规则

`Pipelines → Create Pipeline`，命名 `ztna-normalize`，然后按 **4 个 stage** 依次添加规则（顺序不能乱）：

| Stage | 内容 | 说明 |
|---|---|---|
| 0 | 常量 + rename + 拆 `url_query` | 只做字段映射，不做加工 |
| 1 | 类型转换（`ingest_ts` / `ts` / `status_code` / bytes / method） | `timestamp` 保持不动 |
| 2 | `ua_class` / `ua_browser` / `ua_os` / `ua_browser_ver` + **初始化校验标记** | 顺序即优先级 |
| 3 | 必填校验 + `_schema_ok` / `_schema_missing` + `route_to_stream` | 缺字段不补齐 |

操作方式：打开 pipeline → `Edit` → 在对应 stage 点 `Add new rule` → 粘贴 `ztna.rules` 里该分组的单条 `rule "..." when ... then ... end`（**一条规则一次粘贴**，不要整段粘进一个规则框）。

Stage 2 的最后一条 `ztna :: init schema flags` 很关键：它初始化 `_schema_ok=true`、`_schema_missing=""`，stage 3 的所有检查只做「追加 + 置 false」。如果漏了这条，`_schema_missing` 会变成字符串 `"null"`。

## 3. 替换两处 Stream ID

把 `ztna.rules` 末尾两条 `route_to_stream` 里的占位符换成第 1 步记下的真实 ID：

```
route_to_stream(id: "NORM_ZTNA_STREAM_ID");          → norm-ztna 的 ID
route_to_stream(id: "NORM_ZTNA_REJECT_STREAM_ID");   → norm-ztna-reject 的 ID
```

> 若你的 Graylog 版本 `route_to_stream` 只认流名称，改成 `route_to_stream(stream: "norm-ztna")`。

## 4. 把 pipeline 连到 raw 流

`Streams → raw-ztna → Manage Rules → Pipeline connections` → 连接 `ztna-normalize`。

**只连 raw 流。** 连到 `norm-ztna` 会导致消息被重复处理（pipeline 幂等，但浪费性能）；连到 `All messages` 会让全平台日志都过一遍 ztna 规则，既是性能问题也会污染别的源。

## 5. 验证

### 5.1 Pipeline 模拟器（先用假消息，不动生产）

`Pipelines → ztna-normalize → Simulate`，粘贴一条真实原始日志的 JSON（从搜索页 `Show raw message` 复制），点 `Start simulation`，检查输出：

- `source_code` = `ztna`、`schema_version` = `1.0`
- `ts`、`ingest_ts` 都是整数毫秒
- `ua_class` ∈ {pc, mobile, tablet, feishu, other}
- `_schema_ok` = `"true"`（字符串），`_schema_missing` = `""`

### 5.2 真实数据核对

等 1–2 分钟（stream 路由有缓冲），在 `norm-ztna` 流里搜：

```
streams:norm-ztna
```

逐项核对：

| 检查 | 期望 | 不达标说明 |
|---|---|---|
| 有数据 | 条数 > 0 | raw 流有数据但 norm 为空 → pipeline 没连上，或全部被判 reject |
| `_schema_ok` | 全部 `true` | 有 `false` → 看 `_schema_missing` 缺哪个字段，补 rename 规则 |
| `ua_class` | 无 `null` | 网关没给 `ua_*` 布尔字段且 UA 也没有 → 需网关侧补字段 |
| `ts` | 与设备时间一致 | 全部等于 `ingest_ts` → 设备没给 `event_time`，看 `_ts_from_ingest` |
| `url` | 不含 `?` | 说明 `url_query` 拆分规则没生效 |

再搜 `streams:norm-ztna-reject`，**正常情况下应该很少**。如果 reject 占比超过 1%，按 `_schema_missing` 分组看 Top 缺失字段：

```
streams:norm-ztna-reject
```

## 6. 排错清单

| 现象 | 原因 | 处理 |
|---|---|---|
| `norm-ztna` 一条都没有，raw 流有数据 | pipeline 没连到 raw 流；或 `route_to_stream` 的 ID 写错 | 查 `System → Pipelines` 的 connection；核对流 ID |
| 全部进 reject | `_schema_missing` 显示同一个字段 | 该字段实际叫别的名字，补一条 rename |
| 消息字段突然消失 | 规则里写了 `remove_field` | 检查是否误改；`remove_field` 只应出现在「匿名归一」 |
| pipeline 报 `InvalidValueException` | `to_int` / `to_long` 遇到非数字 | 在搜索页找 `status_code` 非数字的样本，加 `when` 约束或让设备侧修正 |
| `_schema_missing` 是 `"nullsrc_ip,"` | stage 2 的 `init schema flags` 没加 | 补上那条规则 |
| `ts` 与日志时间轴对不上 | 覆盖了 Graylog 的 `timestamp` | 规则里只能写 `ts`，绝不能 `set_field("timestamp", ...)` |

## 7. 与平台侧的对接点

| 平台侧 | 读什么 |
|---|---|
| 日志源注册表 | 把 `norm-ztna` 的 stream ID 填进「系统设置 → 数据源」的 `ztna.stream_id` |
| LBA 采集器 | 只读 `norm-ztna`，按 `ts` 窗口 + `_id` 去重 |
| 巡检 | 读 `norm-ztna` 的 `src_ip / status_code / ts` 做认证爆破计数 |
| 质量看板 | 读 `_schema_ok` / `_schema_missing` / `_ts_from_ingest` 统计缺失率与时间回退率 |

## 8. 后续（ips / waf / nta）

结构与 ztna 完全一致，只换三处：

1. **字段表**：改用 `log-source-spec.md` §3.3（攻击字段），不需要 `ua_*` 那一段；
2. **必填项**：`src_ip` / `action` / `severity` 必填，`url` 仅 waf 必填；
3. **`action` 词表**：设备原值（`阻断`/`拦截`/`deny`/`drop`）必须折算成 `block/deny/drop/reset/alert/allow/log/monitor`，平台只按「已阻断 / 未阻断」二分。

`ips` / `waf` 的规则文件建议在 ztna 稳定运行一周后再建——那时 §5 的映射表已经有了真实字段，不必二次返工。

## 9. 测试环境选型：装在哪、最低什么配置

> 一句话结论：**别在办公笔记本上装**。Graylog 7.x 单机是「JVM 应用 + 搜索引擎 + 配置库」三件套，空载就吃 4–5 GB 内存，落在机械盘上启动要十几分钟、查询频繁超时——装完也只是「能启动，不能用」，验证不出规则对错。

### 9.1 最低配置（单机测试口径）

| 资源 | 最低 | 说明 |
|---|---|---|
| CPU | 4 vCPU | 2 核能起来，但建索引和搜索时会卡到没法点 |
| 内存 | 8 GB **可自由使用** | 空载栈实测 4.6–5.4 GB：Data Node（OpenSearch）≈ 3 GB heap + Graylog ≈ 0.7 GB + MongoDB ≈ 0.15 GB |
| 磁盘空间 | 40 GB，**剩余 ≥ 20 GB** | 镜像 + 卷约 6 GB；索引另按「每日日志量 × 保留天数 × 1.2」算 |
| 磁盘类型 | SSD | HDD 上段合并会把 IO 打满，搜索超时、pipeline 模拟器几十秒才出结果 |
| 运行时 | Docker Engine 20.10+ / Compose v2 | Windows 侧需 WSL2 或 Hyper-V，且 BIOS 已开虚拟化 |

判断口径很简单：**4 vCPU + 8 GB 可用内存 + 20 GB 空闲 SSD，三条同时满足才值得动手**。缺一条就别硬上，验证结论不可信。

### 9.2 为什么笔记本经常不够（实测一例）

一台典型办公笔记本：i5-5250U（2 核 4 线程）、8 GB 内存但系统已占 6.2 GB（可用 1.7 GB）、C 盘剩 9.9 GB、5400rpm 机械盘、Windows 跑在 BootCamp 分区。三条硬指标全不达标：

- **内存**：栈要 4–5 GB，可用只有 1.7 GB → 启动即 OOM，或全程换页
- **磁盘**：只剩 9.9 GB，镜像占 6 GB，索引滚几天就满
- **虚拟化**：BootCamp 下 Hyper-V 不可用，WSL 又多被组策略禁用 → Docker Desktop 根本装不起来

把 heap 压到极限（OpenSearch 768 MB + Graylog 512 MB）能骗过启动，但查询会超时、模拟器要等几十秒，等于用一堆假阴性/假阳性换一个「装好了」的心理安慰。

### 9.3 三条可行路径

| 路径 | 成本 | 能验证什么 | 适用 |
|---|---|---|---|
| **A. 内网 Linux 虚机 + docker compose**（推荐） | 一台 4C/8G/40G SSD | 全链路：pipeline 分流、`ua_*` 派生、reject 流、MCP 读流清单、LBA 采集 | 有虚机资源就走这条 |
| **B. 本地规则模拟（不装 Graylog）** | 零资源 | 规则分支结果：`_schema_ok` 打标、`_schema_missing` 内容、`route_to_stream` 落到哪个流 | 规则先回归干净，等虚机就绪 |
| **C. Windows 原生硬装**（MongoDB zip + OpenSearch zip + Graylog tarball + JDK 17） | 清出 25 GB、腾出 5 GB 内存，官方不支持 Windows | 能跑，但路径与脚本问题要自己趟 | 不建议 |

A 与 B 不冲突，且是推荐组合：B 把 `ztna.rules` 用样例日志跑一遍，A 上机后一次过，省掉「改一版、等一轮、再看日志」的来回。

### 9.4 上机自检（30 秒）

在目标主机上依次确认，任何一条不过就先别装：

```bash
nproc                        # ≥ 4
free -g                      # available ≥ 8
df -h /                      # 剩余 ≥ 20G
lsblk -d -o name,rota        # rota=0 是 SSD
docker version && docker compose version
```

Linux 还要放开 OpenSearch 需要的内核参数，并持久化：

```bash
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-graylog.conf
sudo sysctl --system
```

> 本仓库暂未内置 compose 文件：Graylog 7.x 的 Data Node 首次启动要走 preflight（生成 CA、输入一次性密码、provisioning），heap 也要按主机内存现场定（一般取内存一半，上限 31 GB）。确认目标虚机的 CPU / 内存后，再按该规格生成 compose，避免给了模板却跑不起来。

