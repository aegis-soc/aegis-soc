#!/usr/bin/env bash
# AegisSoc 一键安装脚本（Linux + Docker）
#
# 做的事：
#   1. 检查 Docker / Compose 是否可用
#   2. 首次安装时用随机值生成 .env（JWT 密钥、数据库口令、Webhook 密钥、管理员口令）
#   3. 构建并启动 7 个容器，等待 /api/healthz 就绪
#   4. 打印访问地址、账号口令、Graylog Webhook 地址
#
# 用法：
#   sudo bash scripts/install.sh                        # 默认 8080 端口
#   sudo bash scripts/install.sh --port 80              # 换端口
#   sudo bash scripts/install.sh --admin-password 'Xx@123456'   # 指定初始管理员口令
#   sudo bash scripts/install.sh --install-docker       # 未装 Docker 时自动安装（get.docker.com）
#   sudo bash scripts/install.sh --no-build             # 用已构建镜像启动，不重新构建
#   sudo bash scripts/install.sh --low-mem              # 2G 内存机型裁剪档（<=2.5G 会自动启用）
#   sudo bash scripts/install.sh --normal               # 强制用默认配置（4G 及以上）
#
# 重复执行是安全的：已存在 .env 不会覆盖（要重置就先把 .env 改名）。

set -Eeuo pipefail

PORT=8080
ADMIN_PASS=""
INSTALL_DOCKER=0
NO_BUILD=0
LOW_MEM=""        # 空 = 按内存自动判断；1 = 强制裁剪；0 = 强制默认

usage() {
  # 打印文件头注释块（第 2 行到第一个空行）
  sed -n '2,/^$/p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)            PORT="${2:?--port 需要一个端口号}"; shift 2 ;;
    --admin-password)  ADMIN_PASS="${2:?--admin-password 需要一个口令}"; shift 2 ;;
    --install-docker)  INSTALL_DOCKER=1; shift ;;
    --no-build)        NO_BUILD=1; shift ;;
    --low-mem)         LOW_MEM=1; shift ;;
    --normal)          LOW_MEM=0; shift ;;
    -h|--help)         usage; exit 0 ;;
    *) echo "未知参数: $1（--help 查看用法）" >&2; exit 1 ;;
  esac
done

die()  { echo -e "\n[✗] $*" >&2; exit 1; }
step() { echo -e "\n[>] $*"; }
ok()   { echo "[✓] $*"; }

[[ -f docker-compose.yml ]] || die "请在仓库根目录执行：bash scripts/install.sh"
[[ "$PORT" =~ ^[0-9]+$ ]] || die "--port 必须是数字"

# ---------- 1. Docker 环境 ----------
step "检查 Docker 环境"
if ! command -v docker >/dev/null 2>&1; then
  if [[ $INSTALL_DOCKER -eq 1 ]]; then
    step "未检测到 Docker，使用官方脚本安装"
    curl -fsSL https://get.docker.com | sh
    systemctl enable --now docker
  else
    die "未安装 Docker。用 --install-docker 自动装，或手动执行：
    curl -fsSL https://get.docker.com | sh"
  fi
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose v2 不可用（需要 docker compose，而不是 docker-compose）"
docker info >/dev/null 2>&1 || die "无法连接 Docker 守护进程。当前用户没权限时：sudo usermod -aG docker \$USER 后重新登录，或用 sudo 执行本脚本"
ok "Docker $(docker version --format '{{.Server.Version}}') / Compose $(docker compose version --format '{{.Version}}')"

# ---------- 2. 低内存机型适配（swap / 日志轮转 / 裁剪档） ----------
MEM_MB="$(awk '/^MemTotal:/ {print int($2/1024)}' /proc/meminfo 2>/dev/null || echo 0)"
if [[ -z "$LOW_MEM" ]]; then
  if [[ "${MEM_MB:-0}" -gt 0 && "${MEM_MB:-0}" -lt 2500 ]]; then LOW_MEM=1; else LOW_MEM=0; fi
fi

ensure_swap() {
  if swapon --show 2>/dev/null | grep -q .; then
    ok "已有 swap，跳过（$(swapon --show=NAME,SIZE --noheadings 2>/dev/null | tr '\n' ' ')）"
    return
  fi
  local free_mb
  free_mb="$(df -Pm / | awk 'NR==2 {print $4}')"
  if [[ "${free_mb:-0}" -lt 3072 ]]; then
    echo "[!] 根分区仅剩 ${free_mb}MB，不足以建 2G swap，跳过（请自行扩容或加云盘）"
    return
  fi
  { fallocate -l 2G /swapfile 2>/dev/null || dd if=/dev/zero of=/swapfile bs=1M count=2048 status=none 2>/dev/null; } || true
  if [[ ! -f /swapfile ]]; then
    echo "[!] swap 文件创建失败（文件系统可能不支持 fallocate），跳过；请手工建 swap 后再跑"
    return 0
  fi
  chmod 600 /swapfile 2>/dev/null || true
  if ! mkswap /swapfile >/dev/null 2>&1; then
    echo "[!] mkswap 失败，跳过 swap（可手工执行 mkswap /swapfile && swapon /swapfile）"
    rm -f /swapfile
    return 0
  fi
  if ! swapon /swapfile 2>/dev/null; then
    echo "[!] swapon 失败（可能是容器内无特权或已被占用），请手工启用 /swapfile"
    return 0
  fi
  grep -q '^/swapfile' /etc/fstab 2>/dev/null || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  sysctl -q -w vm.swappiness=10 2>/dev/null || true
  ok "已创建 2G swap（swappiness=10）"
}

ensure_docker_logrotate() {
  local f=/etc/docker/daemon.json
  mkdir -p /etc/docker 2>/dev/null || { echo "[!] 无法创建 /etc/docker，跳过日志轮转"; return 0; }
  if [[ -f "$f" ]]; then
    if grep -q 'max-size' "$f"; then
      ok "Docker 日志轮转已存在，跳过"
    else
      echo "[!] $f 已存在但未配日志上限，未改动。可手动补：\"log-opts\": {\"max-size\": \"10m\", \"max-file\": \"3\"}"
    fi
    return 0
  fi

  # 只加 log-opts，不强制 log-driver：有的机器默认 driver 已被改成 local/journald
  # 而 journald 不支持 max-size，写进去 dockerd 会直接起不来，所以先探测。
  local drv
  drv="$(docker info --format '{{.LoggingDriver}}' 2>/dev/null || echo '')"
  if [[ -n "$drv" && "$drv" != "json-file" && "$drv" != "local" ]]; then
    echo "[!] 当前 Docker 日志驱动是 $drv，不支持 max-size 轮转，跳过（不影响安装）"
    return 0
  fi

  cat > "$f" <<'JSON' || { echo "[!] 写入 $f 失败，跳过日志轮转"; rm -f "$f"; return 0; }
{
  "log-opts": { "max-size": "10m", "max-file": "3" }
}
JSON

  # 日志轮转是可选项：重启失败必须回滚，不能把整个安装卡死在这里
  if systemctl restart docker 2>/dev/null; then
    ok "已开启 Docker 日志轮转（10m × 3）"
    return 0
  fi

  echo "[!] 写入日志轮转配置后 Docker 重启失败，正在回滚该配置"
  rm -f "$f"
  systemctl start docker 2>/dev/null || true
  if docker info >/dev/null 2>&1; then
    echo "[!] Docker 已恢复运行；日志轮转未启用（不影响安装与使用）"
    echo "    想排查原因：systemctl status docker --no-pager -l | tail -30"
    return 0
  fi
  die "Docker 未能恢复运行，请先修好再重跑本脚本。排查顺序：
    journalctl -u docker -n 50 --no-pager
    systemctl cat docker | head -20        # 看是否有 drop-in 覆盖或 snap 版冲突
    ls -l /etc/docker/daemon.json          # 确认没有残留配置
  临时恢复：rm -f /etc/docker/daemon.json && systemctl start docker
  若 docker 是 snap 装的：snap start docker"
}

if [[ "$LOW_MEM" -eq 1 ]]; then
  step "检测到 ${MEM_MB}MB 内存，启用 2G 裁剪档"
  ensure_swap
  ensure_docker_logrotate
else
  step "内存 ${MEM_MB}MB，使用默认配置（4G 档）"
fi

# ---------- 3. 生成 .env ----------
rand_hex() {
  local bytes="$1"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "$bytes"
  else
    head -c "$bytes" /dev/urandom | od -An -tx1 | tr -d ' \n'
  fi
}

step "准备配置文件 .env"
if [[ -f .env ]]; then
  if grep -q $'\r' .env; then
    sed -i 's/\r$//' .env
    ok ".env 已存在，已把 CRLF 换成 LF（否则口令与 DATABASE_URL 会带 \\r 导致连不上库）"
  else
    ok ".env 已存在，保留现有配置（重置：mv .env .env.bak 后重跑）"
  fi
else
  [[ -f .env.example ]] || die "缺少 .env.example，仓库不完整"
  DB_PASS="$(rand_hex 16)"
  ROOT_PASS="$(rand_hex 16)"
  JWT="$(rand_hex 32)"
  WEBHOOK="$(rand_hex 24)"
  if [[ -z "$ADMIN_PASS" ]]; then
    ADMIN_PASS="Aegis@$(rand_hex 6)"
  fi
  TZ_VALUE="Asia/Shanghai"
  command -v timedatectl >/dev/null 2>&1 && TZ_VALUE="$(timedatectl show -p Timezone --value 2>/dev/null || echo Asia/Shanghai)"

  umask 077
  sed \
    -e "s|^MYSQL_ROOT_PASSWORD=.*|MYSQL_ROOT_PASSWORD=${ROOT_PASS}|" \
    -e "s|^MYSQL_PASSWORD=.*|MYSQL_PASSWORD=${DB_PASS}|" \
    -e "s|^DATABASE_URL=.*|DATABASE_URL=mysql+pymysql://aegis:${DB_PASS}@mysql:3306/aegis_soc?charset=utf8mb4|" \
    -e "s|^JWT_SECRET=.*|JWT_SECRET=${JWT}|" \
    -e "s|^GRAYLOG_WEBHOOK_SECRET=.*|GRAYLOG_WEBHOOK_SECRET=${WEBHOOK}|" \
    -e "s|^BOOTSTRAP_ADMIN_PASSWORD=.*|BOOTSTRAP_ADMIN_PASSWORD=${ADMIN_PASS}|" \
    -e "s|^FRONTEND_PORT=.*|FRONTEND_PORT=${PORT}|" \
    -e "s|^TZ=.*|TZ=${TZ_VALUE}|" \
    .env.example > .env
  sed -i 's/\r$//' .env          # 仓库里 .env.example 可能来自 Windows，必须去 CR
  chmod 600 .env
  ok ".env 已生成（权限 600，密钥全部随机）"
fi

# 已有 .env 时以文件里的端口/口令为准，保证后面提示与实际一致
read_env() { grep -E "^$1=" .env | tail -1 | cut -d= -f2- | tr -d '\r' ; }
PORT="$(read_env FRONTEND_PORT || true)"; PORT="${PORT:-8080}"
WEBHOOK="$(read_env GRAYLOG_WEBHOOK_SECRET || true)"
ADMIN_PASS="$(read_env BOOTSTRAP_ADMIN_PASSWORD || true)"

if [[ "$LOW_MEM" -eq 1 ]]; then
  # 巡检每次要拉一批日志进内存，2G 上把节奏和批量都收紧
  sed -i \
    -e 's|^PATROL_INTERVAL_SECONDS=.*|PATROL_INTERVAL_SECONDS=900|' \
    -e 's|^PATROL_MAX_RECORDS=.*|PATROL_MAX_RECORDS=800|' .env
  if [[ -f docker-compose.2g.yml ]]; then
    cp docker-compose.2g.yml docker-compose.override.yml
    ok "已挂上裁剪档 docker-compose.override.yml（巡检 900s / 单次 800 条）"
  else
    echo "[!] 缺少 docker-compose.2g.yml，未启用裁剪档"
  fi
fi

# ---------- 4. 启动 ----------
step "构建并启动容器（首次需拉基础镜像 + 编译前端，通常 3~8 分钟）"
if [[ $NO_BUILD -eq 1 ]]; then
  docker compose up -d || die "启动失败。常见原因：镜像拉不下来（国内主机请给 Docker 配加速器，见文末提示）"
else
  docker compose up -d --build || die "构建/启动失败。可先执行 docker compose build 看完整报错"
fi

step "等待服务就绪（最多 4 分钟）"

# 有 curl 就看 HTTP 200；没有 curl 的极简系统退化为读容器健康状态
probe_ready() {
  if command -v curl >/dev/null 2>&1; then
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:${PORT}/api/healthz" 2>/dev/null || true)"
    [[ "$code" == "200" ]]
  else
    local cid
    cid="$(docker compose ps -q api 2>/dev/null | head -1)"
    [[ -n "$cid" ]] && [[ "$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" == "healthy" ]]
  fi
}

READY=0
for _ in $(seq 1 80); do
  if probe_ready; then READY=1; break; fi
  sleep 3
done
if [[ $READY -eq 0 ]]; then
  echo
  docker compose ps || true
  echo
  echo "最近 40 行 api 日志：" >&2
  docker compose logs --tail=40 api >&2 || true
  die "服务未在预期时间内就绪，请按上面的日志排查（常见：数据库口令不一致、内存不足、镜像拉取失败）"
fi
ok "健康检查通过"

# ---------- 5. 输出 ----------
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
LAN_IP="${LAN_IP:-<服务器IP>}"
if [[ "$LOW_MEM" -eq 1 ]]; then
  MODE_NOTE="2G 裁剪档（2G swap + 容器内存上限 + 巡检 900s / 单次 800 条）
               docker stats --no-stream   看实时占用
               dmesg | grep -i oom        查是否被杀过
               升配到 4G 后：rm docker-compose.override.yml && docker compose up -d --build"
else
  MODE_NOTE="默认（4G 档）"
fi
cat <<EOF

============================================================
 AegisSoc 已启动
============================================================
 管理界面      http://${LAN_IP}:${PORT}
 本机验证      http://127.0.0.1:${PORT}/api/healthz
 API 文档      http://${LAN_IP}:${PORT}/api/docs
 Graylog 回调  http://${LAN_IP}:${PORT}/api/v1/alerts/graylog?secret=${WEBHOOK}

 初始账号      admin
 初始口令      ${ADMIN_PASS}
              （首次登录会强制改密）

 运行模式      ${MODE_NOTE}

 配置与口令都写在 $(pwd)/.env（权限 600），请自行备份，勿提交仓库。
============================================================

下一步：
 1) 安全组 / 防火墙放行 ${PORT}（建议只对办公网或 VPN 开放）
      ufw allow ${PORT}/tcp            # Ubuntu / Debian
      firewall-cmd --add-port=${PORT}/tcp --permanent && firewall-cmd --reload   # AlmaLinux / CentOS
 2) 部署自检（18 项闭环检查）：
      python3 scripts/smoke_test.py --base http://127.0.0.1:${PORT} \\
        --password "${ADMIN_PASS}" --secret "${WEBHOOK}"
 3) 接 Graylog：把上面的「Graylog 回调」地址填到 Graylog 的 Alert Webhook
 4) 日志巡检 / 人机对话：登录后进「日志巡检 → MCP 配置」填 MCP 地址与 Token
 5) 换 HTTPS：见 docs/deploy-cloud.md 第 4 节

常用命令：docker compose ps | logs -f api worker | down | up -d --build

提示：国内云主机拉 docker.io 镜像慢时，给 Docker 配镜像加速后再重跑本脚本：
  sudo mkdir -p /etc/docker
  sudo tee /etc/docker/daemon.json <<'JSON'
  { "registry-mirrors": ["https://<你的加速器地址>"] }
  JSON
  sudo systemctl restart docker
EOF
