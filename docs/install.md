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

### 2.1 一键安装（推荐）

```bash
git clone https://github.com/aegis-soc/aegis-soc.git
cd aegis-soc
sudo bash scripts/install.sh          # 默认对外 8080
```

脚本按顺序做五件事：检查 Docker / Compose → 用随机值生成 `.env`（JWT 密钥、数据库口令、Webhook 密钥、管理员口令，文件权限 600）→ `docker compose up -d --build` → 轮询 `/api/healthz` 直到就绪 → 打印访问地址、初始口令和 Graylog 回调地址。

| 参数 | 作用 |
|---|---|
| `--port 80` | 改对外端口（同时写入 `FRONTEND_PORT`） |
| `--admin-password 'Xx@123456'` | 指定初始管理员口令，不使用随机值 |
| `--install-docker` | 主机没装 Docker 时用官方脚本自动安装 |
| `--no-build` | 用已有镜像启动，不重新构建 |
| `--low-mem` | 强制启用 2G 裁剪档（内存 ≤2.5 GB 时会自动启用，无需手工指定） |
| `--normal` | 强制用默认 4G 档，不用裁剪 |

> **2 GB 机型**：脚本检测到内存 ≤ 2.5 GB 会自动做四件事——加 2 GB swap、开启 Docker 日志轮转、挂上 `docker-compose.2g.yml`（MySQL 缓冲池 128M / api 单 worker / celery 并发 1 / Redis 限 96M）、把巡检节奏放到 900 秒、单次批量降到 800 条。仍建议尽快升配到 4 GB，细节见 [deploy-cloud.md](deploy-cloud.md) 第 7 节。

> 可重复执行：已存在的 `.env` 不会被覆盖，脚本只会把其中的 CRLF 转成 LF（`.env` 里的值带 `\r` 会导致 `DATABASE_URL` 解析失败、api 起不来）。
> 忘记初始口令时：`grep BOOTSTRAP_ADMIN_PASSWORD .env`。

### 2.2 手动安装（分步）

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
> 一条命令跑完 18 项闭环检查（界面 / 告警 / 策略 / 下发 / 审计 / 熔断），
> 详见 [verify.md](verify.md)。

### 2.3 可选：使用预构建镜像（不本地构建）

仓库打了 `v*` tag 后，GitHub Actions 会自动构建多架构镜像（`linux/amd64` + `linux/arm64`）并推送到 ghcr.io，
适合**不想在云主机上跑 Vite 构建**的场景：

```bash
docker pull ghcr.io/aegis-soc/aegis-soc-backend:1.0.0
docker pull ghcr.io/aegis-soc/aegis-soc-frontend:1.0.0

# compose 里三个后端服务的镜像名固定为 aegis-soc-backend:local，前端为 aegis-soc-frontend:local
docker tag ghcr.io/aegis-soc/aegis-soc-backend:1.0.0  aegis-soc-backend:local
docker tag ghcr.io/aegis-soc/aegis-soc-frontend:1.0.0 aegis-soc-frontend:local
docker compose up -d --no-build
```

> 拉取私有包前需先 `echo $GITHUB_TOKEN | docker login ghcr.io -u <用户名> --password-stdin`；
> 若把包设为 Public，则可直接匿名拉取。国内拉取慢时可参考 `docs/deploy-cloud.md` 配置镜像加速或同步到阿里云 ACR。

### 2.4 可选：构建走国内源

pip / npm 默认走官方源。境内主机常见两类失败：`pip` 拉大索引页超时（报 `Could not find a version that satisfies…`
或 `from versions: none`）、npm 卡在 `registry.npmjs.org`。**不用改 Dockerfile**，两种方式任选：

```bash
# 方式一：重跑安装脚本时加参数（会写进 .env，之后每次 build 都生效）
sudo bash scripts/install.sh --cn-mirror

# 方式二：手工在 .env 里加两行，再重建
echo 'AEGIS_PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple' >> .env
echo 'AEGIS_NPM_REGISTRY=https://registry.npmmirror.com'          >> .env
docker compose build api frontend
```

只换其中一个源就用 `--pip-index <URL>` / `--npm-registry <URL>`。内网 HTTP 私服还要加一行
`AEGIS_PIP_TRUSTED_HOST=<主机名>`（HTTPS 源不需要）。构建日志会打印实际使用的源：
`pip index: …` / `npm registry: …`。留空 = 官方源，境外或直连正常的机器不受影响。

> 为什么不再手改 Dockerfile：以前只能在服务器上直接改 `backend/Dockerfile`，导致 `git pull` 报
> `local changes would be overwritten`，每次升级都得 `git stash`。改成构建参数后，这些配置都在 `.env` 里，
> 与代码彻底分离，升级可以干净快进。

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

在「任务日志」可看到 `BLOCK` 任务及设备回执；「IP 黑名单」中可看到 `8.8.8.8`。
到期解封由 Celery Beat 每分钟扫描 `expire_at` 自动触发。

### 4.1 限制告警来源 IP（可选，默认关闭）

告警接入接口 `/api/v1/alerts/graylog` 被调用就会封 IP，URL 一旦外泄等于把封禁开关交出去。
确定 Graylog 的出口地址后，建议在「系统设置 → API 调用来源限制」里只放行它：

1. 打开开关，按行填 Graylog 服务器出口 IP 或网段（如 `10.32.239.10`、`10.46.0.0/16`），保存；
2. 保存即生效，不需要重启容器；名单外的来源直接 `403 来源 IP x.x.x.x 不在 API 调用白名单内`；
3. 判断依据是 nginx 写入的 `X-Real-IP`（`$remote_addr`），客户端自带的 `X-Forwarded-For` **不参与**判断，伪造该头绕不过去。

留空或关闭开关 = 不限制。老库升级需先建表：

```bash
docker compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" aegis_soc < sql/migrate_20261111_system_setting.sql
```

误配把自己挡在外面时，用管理员在页面上关掉开关即可（该接口本身不走白名单）。

## 5. 对接真实设备

1. 进入「设备管理」→ 新增设备，选择插件（`http_generic` / `ssh_firewall` / `sangfor_ips` / `paloalto_fw` / `qiming_fw`）；
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
| 构建时 pip 报 `Could not find a version that satisfies…` / `from versions: none` | 拉 PyPI 索引页超时（不是包不存在）。按 2.4 节给 `.env` 设 `AEGIS_PIP_INDEX`（或重跑 `install.sh --cn-mirror`），再 `docker compose build api` |
| 构建卡在 `npm ci`、日志里是 `registry.npmjs.org` | 同上，设 `AEGIS_NPM_REGISTRY=https://registry.npmmirror.com` 后 `docker compose build frontend` |
| 想确认实际使用的镜像名 | `docker compose config --images`，应为 `aegis-soc-backend:local` 与 `aegis-soc-frontend:local` |
| 中文备注显示成 `RFC5737 ç¤ºä¾‹…` 这类乱码 | 初始化 SQL 被 MySQL 客户端按 latin1 读入（双重编码）。仓库已修（`SET NAMES utf8mb4` + `--character-set-client-handshake=OFF`），但初始化脚本只在数据目录为空时执行：`docker compose down -v && docker compose up -d` 重建即可，注意会清空已有数据 |

## 9. 生产加固建议

- 用反向代理（或 Ingress）为 `8080` 增加 HTTPS，并限制管理界面来源 IP；
- 修改所有默认口令与密钥，禁止使用 `.env.example` 中的占位值；
- 数据库与 Redis 不暴露到公网，仅容器内网可达；
- 定期备份 MySQL 数据卷并演练恢复；
- 上线前按 [security.md](security.md) 完成脱敏自查。

## 10. 版本升级（已有部署）

原则：**代码可以覆盖，`.env` 与 `mysql-data` 卷永远不动**。一次升级只有四步——备份、取新代码、跑迁移、重建镜像。
`docker compose restart` 不算升级：镜像里才是代码，`restart` 只是重启旧镜像。

### 10.1 升级前备份（别省这一步）

```bash
cd ~/aegis-soc
STAMP=$(date +%F-%H%M)
cp -a .env .env.bak.$STAMP
docker compose exec -T mysql \
  sh -c 'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction aegis_soc' > backup-$STAMP.sql
ls -lh backup-$STAMP.sql
```

`backup-*.sql` 是全部告警 / IOC / 任务 / 审计数据；`.env` 里是数据库口令与 `GRAYLOG_WEBHOOK_SECRET`。两个都留着。

### 10.2 取新代码

```bash
git pull --ff-only
```

**如果报 `Your local changes would be overwritten`**：说明服务器上直接改过被 Git 跟踪的文件（多为通网时给 `backend/Dockerfile` 加镜像源、给 `docker-compose.yml` 加 `image:`）。先存档再拉：

```bash
git stash push -m "server-local-$STAMP"
git pull --ff-only
git stash pop          # 自动合并成功就不用管；冲突时手工取舍
git stash list         # 确认没有残留的 stash
```

> 从本版本起，镜像源与镜像名都改成了构建参数（`.env` 里的 `AEGIS_PIP_INDEX` / `AEGIS_NPM_REGISTRY`）+ compose 里的固定 tag，
> **服务器上不再需要改 Dockerfile 和 compose**。所以这次 `stash pop` 冲突可以整段丢弃（`git checkout -- .` 后重拉），
> 只需把原来的镜像源值按 2.4 节写进 `.env`：
>
> ```bash
> echo 'AEGIS_PIP_INDEX=https://pypi.tuna.tsinghua.edu.cn/simple' >> .env
> echo 'AEGIS_NPM_REGISTRY=https://registry.npmmirror.com'          >> .env
> ```
>
> 以后再升级就不会再有本地改动，`git pull --ff-only` 直接快进即可。

**如果 GitHub 连不上**（首次安装用过 `ghfast.top` 的情况很常见），改成下载发行包覆盖，只覆盖代码、不动数据：

```bash
curl -fL "https://ghfast.top/https://github.com/aegis-soc/aegis-soc/archive/refs/heads/main.tar.gz" -o /tmp/aegis.tgz
tar -xzf /tmp/aegis.tgz -C ~/aegis-soc --strip-components=1 --exclude='.env'
git -C ~/aegis-soc diff --stat        # 覆盖后应只剩代码变动
```

### 10.3 跑数据库迁移

新版本可能在 `sql/` 下新增 `migrate_YYYYMMDD_*.sql`，**按日期顺序各执行一次**。脚本都是幂等的，重复执行不会重复建表：

```bash
for f in sql/migrate_*.sql; do
  echo "== $f"
  docker compose exec -T mysql sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" aegis_soc' < "$f"
done
```

只跑本版本新增的也可以——例如「告警来源 IP 白名单」只需 `sql/migrate_20261111_system_setting.sql`。
迁移不会改老数据：本次只新增 `system_setting` 表。

### 10.4 重建镜像并重启

```bash
docker compose build api frontend      # 2 GB 机型约 3–8 分钟
docker compose up -d                   # 只重建有变化的容器
docker compose restart nginx           # 仅当本次改过 deploy/nginx/*.conf
```

- `api` / `worker` / `beat` 三个服务共用同一后端镜像（`image: aegis-soc-backend:local`），`build api` 一次即可，`up -d` 会把三者一起换成新镜像；
- `frontend` 用 `aegis-soc-frontend:local`，改过前端（`.vue` / 菜单 / 文案）必须 `build frontend`，仅 `restart` 看不到变化；
- 构建慢看进度：`docker compose build --progress=plain api`。
- **第一次升到本版本会重建全部容器**：镜像名从 compose 自动生成的 `aegis-soc-api` 等改成固定 tag，
  `up -d` 会按新名重建（数据在卷里，不受影响）。旧镜像可用 `docker image prune` 清理。

### 10.5 验证

```bash
docker compose ps                       # api 为 healthy，其余 Up，且 CREATED 是刚才
curl -s localhost:8080/api/healthz      # {"data":{"status":"healthy",...}}
docker compose logs --tail=50 api       # 无 traceback、无「等待数据库就绪」
```

页面确认三处（本次 a5dbef2 的可见变化）：

1. 左侧是 **7 个一级菜单**（首页大盘 / AI 运营 / 告警中心 / 黑白名单 / 策略配置 / 日志审计 / 系统设置）；
2. 「系统设置」出现 **API 调用来源限制**，默认关闭；
3. 「日志审计 → 任务日志」历史任务与回执仍在。

### 10.6 回滚

```bash
git log --oneline -5                    # 找到升级前的提交
# 镜像打标，方便秒回滚（可选但强烈建议）
docker tag aegis-soc-backend:local  aegis-soc-backend:backup-$STAMP 2>/dev/null || true
docker tag aegis-soc-frontend:local aegis-soc-frontend:backup-$STAMP 2>/dev/null || true
git checkout <升级前的提交> -- .
docker compose build api frontend && docker compose up -d
```

只有迁移改了表结构且必须回退时才动数据（会在备份点之后丢新数据）：

```bash
docker compose exec -T mysql sh -c 'mysql -uroot -p"$MYSQL_ROOT_PASSWORD" aegis_soc' < backup-$STAMP.sql
```

> 升级不会碰 `mysql-data` 卷，也不会覆盖 `.env`；**只有 `docker compose down -v` 才清数据**，升级时不要加 `-v`。
