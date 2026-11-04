# 云上部署与运维指南

> 面向**云服务器（Linux，2 vCPU / 4 GB 及以上）**的生产部署与日常运维补充。
> 基础安装步骤见 [install.md](install.md)，Graylog 对接见 [graylog-config-guide.md](graylog-config-guide.md)。
> 适用版本：v1.0.0（宙斯盾 AegisSoc）

---

## 1. 资源基线

| 项 | 建议 | 说明 |
|---|---|---|
| CPU | 2 vCPU | 下发任务是 IO 密集（HTTP / SSH 调设备），CPU 极少成为瓶颈 |
| 内存 | **4 GB（最低建议）** | 7 容器常驻约 1.6~2.0 GB，需留余量抗告警高峰 |
| 磁盘 | 40 GB+ | 审计表与任务日志持续增长，治理见 §6 |
| 系统 | Debian 12 / Ubuntu 22.04 / AlmaLinux 9（minimal） | 避免预装大量服务的镜像 |
| Docker | 24+ / Compose v2 | 安装见 [install.md](install.md) |

> ⚠️ **2 GB 机型不建议按默认配置部署**：常驻内存已逼近上限，告警高峰会触发 OOM（通常先杀 MySQL 或 worker）。
> 若只能在 2G 上跑，请按 §7 手动裁剪参数并加 swap，属于**非受支持配置**。

---

## 2. 主机初始化

```bash
# 1) 系统与时区
timedatectl set-timezone Asia/Shanghai
apt update && apt upgrade -y          # AlmaLinux: dnf update -y

# 2) 创建运维账号（不要直接用 root）
adduser ops && usermod -aG sudo ops   # AlmaLinux: usermod -aG wheel ops

# 3) SSH 加固：禁用 root 登录与口令登录（确认密钥可用后再执行）
sudo sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sudo sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sudo systemctl restart sshd

# 4) swap 兜底（4G 机型建议 2G，防突发）
sudo fallocate -l 2G /swapfile && sudo chmod 600 /swapfile
sudo mkswap /swapfile && sudo swapon /swapfile
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
sudo sysctl -w vm.swappiness=10 && echo 'vm.swappiness=10' | sudo tee -a /etc/sysctl.conf

# 5) 安装 Docker（官方脚本）
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker ops && newgrp docker
docker version && docker compose version
```

---

## 3. 安全组与端口

| 端口 | 用途 | 建议暴露范围 |
|---|---|---|
| 8080 | 平台 HTTP | 仅办公网 / VPN；启用 HTTPS 后可关闭 |
| 443 | 平台 HTTPS | 对外（按需） |
| 22 | SSH | **仅固定来源 IP** |
| 3306 | MySQL | ❌ **绝不暴露公网**（compose 未做端口映射，仅容器网络内可达） |
| 6379 | Redis | ❌ **绝不暴露公网**（同上） |

> ✅ 当前 `docker-compose.yml` **只映射了 nginx 的 8080**，MySQL / Redis 无宿主端口映射，默认即是安全的，请勿自行添加。
>
> Graylog → 平台的 Webhook 需能访问 8080（或 443）。**优先同 VPC 内网互通**；走公网时务必配置强 `GRAYLOG_WEBHOOK_SECRET` 并开启时间戳防重放。

---

## 4. 启用 HTTPS（可选但推荐）

采用 **nginx 终止 TLS**，后端容器仍走 HTTP。

**① 准备证书**（云厂商免费证书 / Let's Encrypt 二选一）：

```bash
sudo mkdir -p /opt/aegis-soc/deploy/nginx/certs
# 云厂商证书：把 fullchain.pem / privkey.pem 放到该目录
# Let's Encrypt（需先临时放行 80 端口）：
#   sudo certbot certonly --standalone -d soc.example.com
#   sudo cp /etc/letsencrypt/live/soc.example.com/{fullchain,privkey}.pem .../certs/
sudo chmod 600 /opt/aegis-soc/deploy/nginx/certs/privkey.pem
```

**② 切换 nginx 配置**（仓库已提供 [`deploy/nginx/nginx-https.conf`](../deploy/nginx/nginx-https.conf)）：

编辑 `docker-compose.yml` 的 `nginx` 服务，把挂载文件改为 HTTPS 版本并加 443 端口：

```yaml
  nginx:
    image: nginx:1.27-alpine
    ports:
      - "${FRONTEND_PORT:-8080}:80"
      - "443:443"
    volumes:
      - ./deploy/nginx/nginx-https.conf:/etc/nginx/conf.d/default.conf:ro
      - ./deploy/nginx/certs:/etc/nginx/certs:ro
    depends_on:
      - frontend
      - api
    restart: unless-stopped
```

并把配置里的 `server_name` 改成你的域名，然后 `docker compose up -d nginx`。

> 证书目录已在 `.gitignore` 中排除，**不要把私钥提交进仓库**。

---

## 5. 备份与恢复

```bash
# /opt/aegis/backup.sh
#!/usr/bin/env bash
set -euo pipefail
cd /opt/aegis-soc
mkdir -p /opt/aegis/backup
docker compose exec -T mysql sh -c \
  'mysqldump -uroot -p"$MYSQL_ROOT_PASSWORD" --single-transaction --routines aegis_soc' \
  | gzip > "/opt/aegis/backup/aegis-$(date +%F).sql.gz"
find /opt/aegis/backup -name 'aegis-*.sql.gz' -mtime +7 -delete
```

```bash
chmod +x /opt/aegis/backup.sh
# 每天 03:00 备份
echo '0 3 * * * /opt/aegis/backup.sh >> /var/log/aegis-backup.log 2>&1' | sudo tee -a /etc/crontab
```

**恢复**：

```bash
gunzip < /opt/aegis/backup/aegis-2026-11-03.sql.gz \
  | docker compose exec -T mysql mysql -uroot -p"$MYSQL_ROOT_PASSWORD" aegis_soc
```

> ⚠️ `docker compose down` **不会**删除数据卷；`docker compose down -v` **会连数据卷一起删除**，生产环境慎用。
> Redis 仅存去重窗口、幂等锁与熔断状态，**无需备份**，重启后自动重建。
> 建议再把备份同步到对象存储实现异地留存。

---

## 6. 磁盘与日志治理

**① Docker 容器日志轮转**（默认 `json-file` 无上限，最容易吃满磁盘）：

```bash
sudo tee /etc/docker/daemon.json > /dev/null <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
EOF
sudo systemctl restart docker     # 会重启所有容器，请在维护窗口执行
```

**② 定期清理悬空镜像与构建缓存**：

```bash
docker system prune -f --volumes=false     # 不要用 --volumes，会删数据卷
docker image prune -a -f
```

**③ 业务表增长治理**：`operation_audit`、`device_task_log`、`alert_event` 会持续写入。

> 🔴 **合规优先**：等保 2.0 等要求安全审计日志留存通常**不少于 6 个月**。
> 清理前请先确认本单位留存要求，宁可扩容磁盘或归档，也不要直接删除。

```sql
-- 1) 先评估数据量（以 180 天为例）
SELECT COUNT(*) FROM operation_audit   WHERE created_at < NOW() - INTERVAL 180 DAY;
SELECT COUNT(*) FROM device_task_log   WHERE created_at < NOW() - INTERVAL 180 DAY;

-- 2) 归档（推荐，保留可追溯性）
CREATE TABLE operation_audit_archive LIKE operation_audit;
INSERT INTO operation_audit_archive SELECT * FROM operation_audit
  WHERE created_at < NOW() - INTERVAL 180 DAY;

-- 3) 分批删除，避免长事务锁表（循环执行直到影响行数为 0）
DELETE FROM device_task_log WHERE created_at < NOW() - INTERVAL 180 DAY LIMIT 5000;
DELETE FROM operation_audit WHERE created_at < NOW() - INTERVAL 180 DAY LIMIT 5000;
```

执行入口：`docker compose exec mysql mysql -uroot -p aegis_soc`

**④ 磁盘监控**：建议对 `/` 使用率 ≥ 80% 配置告警，或在主机加一个简单的每日检查。

---

## 7. 2G 机型裁剪参数（应急参考，非受支持）

仅当你坚持在 2 GB 内存上部署时，**手动**调整以下参数（默认配置已按 4G 调优，请勿在 4G 上照改）：

| 位置 | 默认 | 2G 建议值 |
|---|---|---|
| `docker-compose.yml` → `mysql.command` | `--innodb-buffer-pool-size=256M` | `128M`，并追加 `--performance-schema=OFF`、`--max-connections=100` |
| `docker-compose.yml` → `worker.command` | `-c "4"` | `-c "2"`，追加 `--max-tasks-per-child=100` |
| `docker-compose.yml` → `api.command` | `--workers 2` | `--workers 1` |
| `docker-compose.yml` → `redis.command` | 无内存上限 | 追加 `--maxmemory 128mb --maxmemory-policy noeviction`，去掉 `--appendonly yes` |

同时建议给各容器加 `mem_limit`，并保留 §2 的 2G swap 兜底。

---

## 8. 上线自检清单

| # | 检查项 | 预期 |
|---|---|---|
| 1 | `docker compose ps` | 7 个容器均 `Up` 且 mysql / redis / api 为 `healthy` |
| 2 | 安全组 | 仅放行必要端口，3306 / 6379 未暴露公网 |
| 3 | `.env` | 4 类占位值已全部替换（`JWT_SECRET` / `GRAYLOG_WEBHOOK_SECRET` / 数据库口令 / `BOOTSTRAP_ADMIN_PASSWORD`） |
| 4 | 首次登录 | 已强制修改默认口令，且已创建运维自有账号 |
| 5 | 熔断开关 | 已在「系统设置」确认 `GLOBAL_KILL_SWITCH` 初始为关闭，演练过开启效果 |
| 6 | 白名单 | 业务网段、监控源、办公出口 IP 已导入白名单（**务必先做**） |
| 7 | 插件连通性 | 真实设备「连通性测试」为 `online` |
| 8 | 闭环验证 | 用 mock 告警走通「告警 → 策略 → 任务 → 下发 → 到期解封」 |
| 9 | 备份 | 备份脚本已部署，且**成功恢复演练过一次** |
| 10 | 磁盘 | 已配置 Docker 日志轮转与磁盘告警 |

---

## 9. 常见故障速查

| 现象 | 排查 | 处理 |
|---|---|---|
| 容器反复重启 | `docker compose logs --tail=100 <服务>` | 多为 MySQL 未就绪或 `.env` 占位值未替换 |
| API 502 | `docker compose exec nginx nginx -t` | 检查 `api` / `frontend` 是否 healthy |
| worker 不执行任务 | `docker compose logs -f worker beat` | 确认队列名 `aegis` 一致、`TASK_EAGER` 未误设为 true |
| Graylog 回调 401/403 | 比对 `GRAYLOG_WEBHOOK_SECRET` | 同时检查时间戳防重放窗口（服务器时间需同步 NTP） |
| 内存吃满、容器被杀 | `dmesg \| grep -i oom` | 按 §7 裁剪参数、加 swap，或升配到 4G |
| 磁盘告警 | `du -sh /var/lib/docker/*` | 按 §6 清理日志与归档业务表 |
