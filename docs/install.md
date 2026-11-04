# 安装与部署指南

## 1. 前置条件

| 项 | 要求 |
|---|---|
| Docker | 24.0+ |
| Docker Compose | v2（`docker compose version`） |
| 可用端口 | `8080`（前端入口，可通过 `FRONTEND_PORT` 修改） |
| 内存 | 建议 ≥ 4 GB（MySQL 8 + Redis + 3 个 Python 进程） |
| 磁盘 | 建议 ≥ 20 GB（Graylog 日志仍在外部，平台自身数据很小） |

> 生产模式**不拉起 Graylog**：平台通过 Webhook 对接你已有的 Graylog 集群。
> Demo 模式（一键全套 Graylog）规划于 v1.1，见 `docker-compose-demo.yml`。

## 2. 快速部署

```bash
git clone https://github.com/aegis-soc/aegis-soc.git
cd aegis-soc
cp .env.example .env
```

**编辑 `.env`，至少修改以下 4 项**（全部为占位值，切勿原样上生产）：

| 变量 | 说明 |
|---|---|
| `JWT_SECRET` | JWT 签名密钥，≥ 32 位随机串 |
| `GRAYLOG_WEBHOOK_SECRET` | Graylog Webhook 校验密钥 |
| `MYSQL_ROOT_PASSWORD` / `MYSQL_PASSWORD` | 数据库口令，两者都要改 |
| `BOOTSTRAP_ADMIN_PASSWORD` | 初始管理员口令 |

```bash
docker compose up -d
docker compose ps          # 7 个容器应全部 running / healthy
docker compose logs -f api # 首次启动会执行 bootstrap 并打印完成日志
```

| 访问项 | 地址 |
|---|---|
| 管理界面 | `http://127.0.0.1:8080` |
| API 文档（Swagger） | `http://127.0.0.1:8080/api/docs` |
| 健康检查 | `http://127.0.0.1:8080/api/healthz` |
| Graylog Webhook | `http://127.0.0.1:8080/api/v1/alerts/graylog?secret=<你的SECRET>` |

默认账号 `admin / <BOOTSTRAP_ADMIN_PASSWORD>`（默认 `Admin@123456`），**首次登录会强制要求改密**。

> ✅ **部署完成先别急着用**：执行 `python scripts/smoke_test.py --secret <你的SECRET> --password <你的口令>`
> 一条命令跑完 16 项闭环检查（界面 / 告警 / 策略 / 下发 / 审计 / 熔断），
> 详见 [verify.md](verify.md)。

### 2.1 可选：使用预构建镜像（不本地构建）

仓库打了 `v*` tag 后，GitHub Actions 会自动构建多架构镜像（`linux/amd64` + `linux/arm64`）并推送到 ghcr.io，
适合**不想在云主机上跑 Vite 构建**的场景：

```bash
docker pull ghcr.io/aegis-soc/aegis-soc-backend:1.0.0
docker pull ghcr.io/aegis-soc/aegis-soc-frontend:1.0.0

# Compose 默认镜像名是 <项目名>-<服务名>，本地打标签后即可直接 up
docker tag ghcr.io/aegis-soc/aegis-soc-backend:1.0.0  aegis-soc-api
docker tag ghcr.io/aegis-soc/aegis-soc-backend:1.0.0  aegis-soc-worker
docker tag ghcr.io/aegis-soc/aegis-soc-backend:1.0.0  aegis-soc-beat
docker tag ghcr.io/aegis-soc/aegis-soc-frontend:1.0.0 aegis-soc-frontend
```

> 拉取私有包前需先 `echo $GITHUB_TOKEN | docker login ghcr.io -u <用户名> --password-stdin`；
> 若把包设为 Public，则可直接匿名拉取。国内拉取慢时可参考 `docs/deploy-cloud.md` 配置镜像加速或同步到阿里云 ACR。

## 3. 启动顺序与健康检查

Compose 通过 `depends_on + healthcheck` 保证顺序：

```
mysql(healthy) + redis(healthy)
        ↓
api(healthy) → bootstrap 幂等补齐角色/插件/设备/策略/管理员
        ↓
worker / beat / frontend / nginx
```

- `api` 首次启动会等待数据库就绪（最多约 60 秒），无需手动执行 SQL。
- `sql/init.sql`、`sql/seed.sql` 只在**数据卷首次创建**时执行；已有数据卷不会重复初始化。
- 若 `redis` 短暂不可用，平台自动降级为进程内缓存并在日志中告警；生产环境请保证 Redis 常驻。

## 4. 无 Graylog 也能跑通闭环

内置 `mock` 插件（默认示例设备）不调用任何真实设备。用下面的请求即可验证「告警 → 策略 → 任务 → 下发 → 审计」：

```bash
curl -X POST "http://127.0.0.1:8080/api/v1/alerts/graylog?secret=你的SECRET" \
  -H "Content-Type: application/json" \
  -d '{
    "event_definition_title": "WAF 暴力破解告警",
    "event_definition_id": "ed-demo",
    "event": {
      "id": "demo-001",
      "priority": 3,
      "message": "攻击源 8.8.8.8 触发规则",
      "fields": {"src_ip": "8.8.8.8", "confidence": 90}
    }
  }'
```

在「任务中心」可看到 `BLOCK` 任务及设备回执；「IP 黑名单」中可看到 `8.8.8.8`。
到期解封由 Celery Beat 每分钟扫描 `expire_at` 自动触发。

## 5. 对接真实设备

1. 进入「设备管理」→ 新增设备，选择插件（`http_generic` / `ssh_firewall` / `sangfor_ips`）；
2. 在「插件配置(JSON)」中填写**非敏感**连接参数；
3. 凭据（口令、API Key）放入宿主机环境变量，例如：

```bash
# .env（不要提交到仓库）
FW_HQ_PASSWORD='{"password":"你的设备口令"}'
```

在设备的「凭据环境变量」填 `FW_HQ_PASSWORD`，平台启动时读取，不落库、不写日志；
4. 点击「连通性测试」确认 `online`；
5. 在「策略配置」确认目标设备与能力匹配，之后告警即会自动下发。

## 6. 常用运维命令

```bash
make up / down / build / logs / ps     # 封装了 docker compose
docker compose exec api sh             # 进入 API 容器
docker compose exec mysql mysql -uroot -p aegis_soc
docker compose logs -f worker beat     # 查看任务执行与定时解封日志
```

数据备份：

```bash
docker compose exec mysql sh -c 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" aegis_soc' > backup.sql
```

> ☁️ 云上部署的定时备份脚本、恢复演练、Docker 日志轮转与审计表归档清理，见 [deploy-cloud.md](deploy-cloud.md)。

升级：拉取新版本后 `docker compose up -d --build`，表结构变更通过版本化迁移脚本执行（v1.0 起随 CHANGELOG 说明）。

## 7. 本地开发（无 Docker）

```bash
# 后端
cd backend
python -m venv .venv && . .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r requirements.txt
export DATABASE_URL="sqlite:///./aegis_dev.db"
export TASK_EAGER=true
uvicorn app.main:app --reload --port 8000

# 前端（另开终端）
cd frontend
npm install
npm run dev            # http://127.0.0.1:5173，已配置 /api 代理到 8000

# 测试
cd backend && pytest -q
```

> SQLite 仅用于本地快速体验；生产请使用 MySQL 8（部分 `VARBINARY(16)` 网段检索与 JSON 函数在 SQLite 下行为不同）。

## 8. 常见问题

| 现象 | 排查 |
|---|---|
| `api` 反复重启，日志出现「等待数据库就绪」 | 检查 `mysql` 是否 healthy、`DATABASE_URL` 中的口令与 `MYSQL_PASSWORD` 是否一致 |
| 健康检查 500 | `docker compose logs api` 查看 bootstrap 异常；确认 `sql/init.sql` 已挂载 |
| 告警返回 403 | `secret` 与 `GRAYLOG_WEBHOOK_SECRET` 不一致，或配置了 `GRAYLOG_BEARER_TOKEN` 但请求未带 |
| 告警 accepted 但没有任务 | 依次检查：熔断开关、白名单命中、IP 是否为内网/保留地址、策略置信度与阈值、设备能力矩阵 |
| 任务一直 PENDING | 检查 `worker` 是否运行、Redis 是否连通；Beat 每 2 分钟会补偿投递 |
| 前端 502 | `nginx` 依赖 `frontend` 与 `api`，确认两者已启动 |

## 9. 生产加固建议

- 用反向代理（或 Ingress）为 `8080` 增加 HTTPS，并限制管理界面来源 IP；
- 修改所有默认口令与密钥，禁止使用 `.env.example` 中的占位值；
- 数据库与 Redis 不暴露到公网，仅容器内网可达；
- 定期备份 MySQL 数据卷并演练恢复；
- 上线前按 [security.md](security.md) 完成脱敏自查。
