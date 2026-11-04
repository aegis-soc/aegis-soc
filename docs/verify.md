# 验证与验收指南

> 目标：用最短路径确认「平台真的跑通了」，而不是「看起来装好了」。
> 本文分三层：**CI 自动验证** → **一键冒烟脚本** → **界面人工验收**。

---

## 0. 先明确一件事：GitHub 上看不到运行界面

GitHub 是**代码托管 + CI 执行**平台，不会替你跑起服务。在仓库页面上你能看到的是：

| 能看到 ✅ | 看不到 ❌ |
|---|---|
| 源码、README、文档、Issue/PR | 登录页、大盘、黑名单管理等真实界面 |
| Actions 运行结果（测试是否通过、镜像是否构建成功） | 容器运行状态、数据库数据 |
| Releases 版本页、ghcr 镜像包 | 实时告警流、任务执行日志 |

**要看到界面，必须让容器真正跑起来**，三种方式：

| 方式 | 成本 | 适用 |
|---|---|---|
| **免 Docker 本机直跑** | ~190 MB 内存，无需装 Docker | 只想看界面 / 改样式（最低门槛，见 §0.1） |
| 本地 Docker Desktop | 装一次，空闲即占 1~2 GB 内存 + 5~10 GB 磁盘 | 开发调试 |
| 云服务器 `docker compose up -d` | 2C4G 起 | 生产 / 长期演示（推荐） |
| GitHub Codespaces | 每月免费额度，用完按量 | 临时演示，能拿到一个公网预览链接 |

> Codespaces 路线：仓库页 → `Code` → `Codespaces` → 新建 → 终端里执行
> `cp .env.example .env && docker compose up -d`，待 `docker compose ps` 全绿后，
> 在 **PORTS** 面板把 `8080` 设为 Public，即可用浏览器打开界面。

### 0.1 免 Docker 本机直跑（最轻，仅用于看界面）

机器装不了 Docker（磁盘不足、虚拟化未开、系统版本过低）时，可直接用原生进程跑：

```powershell
# Windows
powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1          # 启动
powershell -ExecutionPolicy Bypass -File scripts\dev-local.ps1 -Stop    # 停止
```

```bash
# macOS / Linux
cd backend && python -m venv .venv && .venv/bin/pip install -r requirements.txt
DATABASE_URL="sqlite:///./_local.db" TASK_EAGER=true GRAYLOG_WEBHOOK_SECRET="local-dev-secret" \
  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 &
cd ../frontend && npm install && npx vite --host 127.0.0.1 --port 5173
```

打开 `http://127.0.0.1:5173`（前端 Vite，`/api` 反代到 8000）。

| 项 | 本模式 | 生产（Docker） |
|---|---|---|
| 数据库 | SQLite 单文件 | MySQL 8 |
| 任务执行 | 同步、进程内（`TASK_EAGER`） | Celery Worker + Redis |
| 到期解封 | 无 Beat，需手动触发 | Beat 每分钟自动扫描 |
| 内存占用 | ≈ 190 MB | ≈ 2 GB |

> ⚠️ 本模式**只用于界面与流程演示**，不能替代 MySQL/Redis/Celery 的真实链路验收。

---

## 1. 第一层：CI（推送即验证，无需你操作）

每次 push / PR，`.github/workflows/ci.yml` 自动执行：

| Job | 内容 | 通过标准 |
|---|---|---|
| backend | `compileall` + `pytest` | 18 项测试全绿（含告警→策略→任务→插件→审计→解封闭环） |
| frontend | `npm ci` + `npm run build` | 12 个视图产物生成成功 |
| compose | `docker compose config -q` | 两份编排语法与变量插值合法 |

查看位置：仓库 → **Actions** → `CI`。绿色对勾即通过。

> 局限：CI 用的是 SQLite + 同步执行，**不覆盖 MySQL / Redis / Celery / nginx 的真实链路**，所以还需要第 2、3 层。

---

## 2. 第二层：一键冒烟脚本（推荐，30 秒出结论）

部署完成后执行：

```bash
python scripts/smoke_test.py \
  --base http://127.0.0.1:8080 \
  --secret  <你的 GRAYLOG_WEBHOOK_SECRET> \
  --password <你的管理员口令>
```

脚本只依赖 Python 标准库，Windows / Linux / macOS 通用。也可以用环境变量传参，避免口令进入命令历史：

```bash
export SMOKE_ADMIN_PASSWORD=xxx
export SMOKE_WEBHOOK_SECRET=yyy
python scripts/smoke_test.py
```

### 覆盖的 9 组检查（共 18 项）

| # | 检查 | 验证了什么 |
|---|---|---|
| 1 | 首页返回前端页面 | nginx → frontend 静态资源链路 |
| 2 | `/api/healthz` | API 存活、数据库与缓存状态 |
| 3 | 管理员登录 | JWT 签发、账号可用 |
| 4 | 白名单命中检查 | 白名单优先这条硬性边界 |
| 5 | 告警受理 / IOC / 任务 | Graylog Webhook → 策略匹配 → 任务生成 |
| 6 | 重复投递去重 | `alert_id` 幂等，防重复封禁 |
| 7 | 黑名单查询 + 任务状态 + 日志 | 插件实际执行成功、请求响应有留痕 |
| 8 | 熔断开 / 关 | 应急刹车有效，且脚本会自动还原 |
| 9 | 插件数 / 审计 / 大盘 | 4 个内置插件、审计落库、大盘接口 |

### 成功输出样例

```
[5/9] Graylog 告警接入 → 策略 → 下发
  ✅ 告警被受理（快速返回 accepted）  —— HTTP 200 status=accepted msg=命中策略 default-auto-block，生成 1 个任务
  ✅ 生成 IOC  —— ioc_count=1
  ✅ 生成下发任务  —— task_count=1
...
结果：18/18 项通过
🎉 全链路闭环验证通过：界面 → 告警 → 策略 → 下发 → 审计 均正常
```

退出码 `0` = 全通过，`1` = 有失败项（会列出失败原因与排查命令）。

---

## 3. 第三层：界面人工验收（5 分钟）

| # | 操作 | 预期 |
|---|---|---|
| 1 | 打开 `http://<地址>:8080`，用 `admin` 登录 | 强制跳转改密页（首次登录） |
| 2 | 改密后进入大盘 | 卡片数字正常，无接口报错 |
| 3 | 侧边栏 → **任务** | 看到 mock 设备的下发任务，状态 `SUCCESS`，点开有请求/响应日志 |
| 4 | 侧边栏 → **IP 黑名单** | 存在脚本写入的 `93.184.216.34`，来源/过期时间正确 |
| 5 | 侧边栏 → **白名单** | 含种子地址 `198.51.100.10`；"命中检查"输入它返回已命中 |
| 6 | 侧边栏 → **告警** | 有多条冒烟告警记录 |
| 7 | 侧边栏 → **审计** | 能看到登录、封禁、熔断等操作流水 |
| 8 | 侧边栏 → **系统设置** → 熔断开关 | 打开后新告警只记录不封禁，**验完记得关掉** |

---

## 4. 常见失败对照

| 现象 | 原因 | 处理 |
|---|---|---|
| 脚本第 1 步 404 | 用的是后端直连端口（8000） | 改用 nginx 入口 8080 |
| 登录 401 | `--password` 与 `.env` 的 `BOOTSTRAP_ADMIN_PASSWORD` 不一致 | 查 `.env`，或重置管理员口令 |
| 告警 403 | `--secret` 与 `GRAYLOG_WEBHOOK_SECRET` 不一致 | 两处对齐 |
| `task_count=0` | 策略阈值未命中 / 熔断开启 / IP 在白名单 | 看告警返回的 `message` 字段 |
| 任务一直 `PENDING` / `RETRYING` | worker 未起或 Redis 不通 | `docker compose ps`、`docker compose logs worker` |
| 任务 `FAILED` | 插件配置错误（真实设备才可能） | 看任务详情里的响应报文 |
| 首页 502 | frontend 容器未就绪 | `docker compose ps frontend`，等健康检查 |

---

## 5. 上线前的最小验收结论

以下四条都满足，才算「功能跑通」：

1. CI 绿色（代码层面可信）
2. `scripts/smoke_test.py` 输出 **18/18**
3. 界面 8 步人工验收无异常
4. 至少用**一台真实设备插件**（而非 mock）成功下发并解封一次
