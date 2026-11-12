# AegisSoc

English | [简体中文](README.zh-CN.md)

> **Universal AI-driven Security Operations & Automation platform** — integrates with Graylog and other log platforms to receive alerts, manage IOC blacklists/whitelists in one place, and dispatch blocks/unblocks to WAFs, firewalls and IPS via pluggable device gateways.

[![CI](https://github.com/aegis-soc/aegis-soc/actions/workflows/ci.yml/badge.svg)](https://github.com/aegis-soc/aegis-soc/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/release-v1.0.0-blue)](https://github.com/aegis-soc/aegis-soc/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)
[![Backend](https://img.shields.io/badge/backend-FastAPI%20%2F%20Python%203.12-orange)]()
[![Frontend](https://img.shields.io/badge/frontend-Vue3%20%2F%20Element%20Plus-brightgreen)]()
[![Queue](https://img.shields.io/badge/queue-Celery%20%2B%20Redis-red)]()

**In one sentence: without touching your log platform, AegisSoc receives alerts from Graylog and other sources, manages IOC centrally, and executes block/unblock actions against security devices through plugins — with async task scheduling, full-chain auditing, AI inspection, MCP log patrol and a natural-language console built in.**

> 🌏 Note: the detailed guides under `docs/` are currently written in Chinese; English translations are on the roadmap.

> Unlike heavyweight commercial SOAR products, AegisSoc is generic, works out of the box, and deploys with a single Docker Compose command. AI-driven analysis is added progressively as plugins.
> Clear division of responsibilities: **Graylog handles log collection, analysis and alert decisions; AegisSoc handles IOC management, policy orchestration, device API integration, tasks and auditing.** Graylog stays a loosely-coupled component — API integration only.

---

## ✨ Highlights

- ✅ **Non-invasive Graylog integration**: uses only the native Alert Webhook — no Graylog source changes; any existing cluster can onboard
- ✅ **Generic alert ingestion**: besides Graylog, a `generic` alert endpoint accepts ElastAlert, Suricata and more
- ✅ **Pluggable device gateway**: unified interface + Manifest capability declaration — adding a device means writing a plugin, not touching the platform
- ✅ **IOC lifecycle**: IP/domain blacklists, IP whitelist (single IP / CIDR / bulk import), auto-expiry unblock, source tagging, labels and remarks
- ✅ **Blacklist as append-only history**: every hit creates its own record (no merging); each keeps its added/expiry time and source alert; sources auto-classified as IPS / WAF / ZTNA / threat intel; blocked attempts are kept as `rejected` records so you can always answer "why wasn't this blocked?"
- ✅ **AI inspection (two layers)**: first checks protection effectiveness — tri-stream coverage (IPS/WAF/ZTNA), **block-gap attribution** (why alerts didn't get blocked), 7-day remediation-rate trend, cross-day persistent attackers; then platform health — devices, blacklist, task queue, expiry risks, whitelist, policies, system. Outputs a weighted health score, KPI snapshot and actionable advice; auto-inspection daily at 08:30, reports are kept for review; optional LLM-generated summaries
- ✅ **Graylog MCP config UI**: set the MCP endpoint, API token, auth scheme and IPS/WAF/ZTNA stream mapping from the page — no `.env` edit, no restart. Token is write-only (masked on read), every save is audited, and a "Test connection" button validates the draft before saving
- ✅ **Log patrol (P0, read-only)**: every 5 minutes it queries Graylog IPS/WAF/ZTNA streams over **MCP** and applies deterministic rules — unblocked IPS alerts, WAF pass-through, ZTNA brute force, high-frequency sources, cross-stream hits, threat-intel tags — to surface attack sources that Graylog rules missed. Dry-run only: no blacklist writes, no blocking
- ✅ **Natural-language console**: ask in Chinese — "blacklist top countries", "any unblocked IP logs across devices in the last 3 days" — and it routes to MySQL aggregates or Graylog MCP by itself. No text2SQL: the router only emits a whitelisted DSL that code compiles into parameterised `SELECT`s or MCP searches; read-only, rate-limited, fully audited, and works without any LLM
- ✅ **Alert-ingest IP allowlist**: decide which source IPs may call the alert webhook, right from the settings page — off by default, applied on save (no `.env` edit, no restart). The source IP is nginx `$remote_addr`; a client-supplied `X-Forwarded-For` is ignored
- ✅ **Version & update check (read-only)**: the sidebar and settings page show `vX.Y.Z` plus the build commit; "Check for updates" asks the GitHub Releases API once (10-minute cache, mirror-friendly via `AEGIS_GITHUB_API_BASE`) and, if a newer tag exists, prints the upgrade commands. It never downloads or restarts anything — upgrading stays a deliberate, human-run step
- ✅ **IP geolocation**: blacklist shows country / province·city (snapshot on write, offline ip2region database — 11 MB, no network, no licensing), filterable by country
- ✅ **Hard safety boundaries**: whitelist first, RFC1918/loopback/reserved addresses never blocked, IOC-type vs device-capability matching, global kill switch
- ✅ **Reliable async tasks**: Celery + Beat with idempotency, exponential-backoff retries, timeout control and scheduled unblock
- ✅ **Full-chain audit**: manual actions, automatic blocks, raw device request/response payloads all recorded
- ✅ **RBAC**: `admin` / `operator` / `auditor` roles with API-level authorization
- ✅ **AI+SOC ready**: plugin interfaces and Manifest capability bits reserved for AI analysis; LLM-assisted triage lands from v1.1
- ✅ **Open-source friendly**: Apache 2.0 — commercial use and fork welcome; community device plugins encouraged

## 🖼 Screenshots

> Captured from a running local instance with demo data, while auto-blocking was active.

### Dashboard

Live overview of alerts / IOCs / devices and tasks, with risk distribution and recent alerts:

![Dashboard](docs/screenshots/dashboard.png)

### IP Blacklist (append-only records · source · geolocation)

Each hit of the same IP is an independent record (never merged); source is auto-detected (WAF / IPS / ZTNA / threat intel…); internal/reserved addresses rejected by policy are also recorded (status "rejected" with the reason in the remark column):

![IP Blacklist](docs/screenshots/blacklist-ip.png)

### Device Management (visual configuration forms)

After picking a plugin, a device-specific configuration form appears — endpoint, business parameters and credential environment variables grouped automatically; no hand-written JSON required (advanced JSON editing still available):

![Device Management](docs/screenshots/device-form.png)

### Plugin Management

8 built-in plugins, each declaring supported IOC types and capabilities (BLOCK / UNBLOCK / QUERY):

![Plugins](docs/screenshots/plugins.png)

---

## 🧱 Architecture

```
Log sources: WAF / IPS / Firewall / NDR / EDR / Nginx / app logs
                          │
                          ▼
        Graylog: Pipeline normalization · Event Definitions · Alerts
                          │ Webhook (secret + timestamp anti-replay)
                          ▼
┌─────────────────────────────────────────────────────────┐
│                    AegisSoc · AI+SOC                    │
│  ┌───────────┐  ┌────────────┐  ┌───────────────────┐  │
│  │  FastAPI  │  │  Vue3 UI   │  │ Celery Worker/Beat│  │
│  │  API      │  │  console   │  │  async / auto-unblock │
│  └─────┬─────┘  └────────────┘  └─────────┬─────────┘  │
│        │     Policy engine · IOC · whitelist · audit    │
│        └──────────────┬───────────────────┘              │
│          Plugin gateway (Manifest capability match)      │
└───────────────────────┬─────────────────────────────────┘
                        ▼
     mock / generic HTTP / SSH firewall / Sangfor IPS / WAF / PA
                        │
                        ▼
              MySQL 8 (data) + Redis 7 (dedupe/limiter/queue/kill-switch)
```

> 🔒 Alert decision logic stays in Graylog; the platform adds thresholds, suppression, approval and a kill switch to prevent over-blocking.
> See [docs/architecture-baseline.md](docs/architecture-baseline.md) for the full architecture baseline.

## 🗣 Natural-language Console

Type a question in Chinese — the platform decides by itself whether it needs platform data or Graylog logs, then answers with a conclusion, a detail table, a bar chart, and the exact query it ran.

| You ask | Route | What runs |
|---|---|---|
| `分析黑名单中来源top10或者top国家，top时间` | MySQL | three aggregates at once: by source, by country, by day |
| `最近3天各个安全设备有未拦截的ip日志告警` | Graylog MCP | queries the IPS / WAF / ZTNA streams, groups by source IP, marks each one as already blocked / suspected gap / internal address |

**No text2SQL.** The router only emits a whitelisted DSL (`source` / `metric` / `group_by` / `filters` / `time` / `limit`); code compiles that into parameterised `SELECT`s or MCP searches. Nothing in the language layer ever holds a table object or a SQL string — unknown fields are rejected instead of guessed.

Guardrails: read-only (`SELECT` only, asserted in tests), every filter value bound as a parameter, `LIMIT ≤ 200`, log window ≤ 7 days, 20 questions/minute per user, `system_user` / `patrol_setting` excluded, every question audited as `CHAT_ASK`. When a question can't be mapped it returns *didn't understand* plus suggested phrasings — it never invents numbers. Works with **no LLM at all**; the rule engine is the only path.

Details, DSL examples and how to add a new question type: [docs/chat-nlq.md](docs/chat-nlq.md).

---

## 📦 Quick Start (Docker Compose)

**Prerequisites**: Docker 24+ / Docker Compose v2

```bash
git clone https://github.com/aegis-soc/aegis-soc.git
cd aegis-soc
cp .env.example .env
# Make sure to change: JWT_SECRET / GRAYLOG_WEBHOOK_SECRET / database passwords / BOOTSTRAP_ADMIN_PASSWORD
docker compose up -d
```

> 🚀 **Or one command** (Linux): `sudo bash scripts/install.sh` — generates `.env` with random secrets, builds, waits for health, then prints the URL and initial password. Options: `--port`, `--admin-password`, `--install-docker`, `--no-build`. On hosts with ≤2.5 GB RAM it automatically switches to a 2 GB profile (adds swap, caps container memory, slows the log patrol to 15 min).

| Item | Value |
|---|---|
| Web console | `http://127.0.0.1:8080` |
| API docs (Swagger) | `http://127.0.0.1:8080/api/docs` |
| Health check | `http://127.0.0.1:8080/api/healthz` |
| Default account | `admin / Admin@123456` (**password change forced on first login**) |

This starts 7 containers: `mysql` · `redis` · `api` · `worker` · `beat` · `frontend` · `nginx`.

**Graylog alert webhook URL**:

```
http://<platform-host>/api/v1/alerts/graylog?secret=YOUR_GRAYLOG_WEBHOOK_SECRET
```

👉 See [docs/graylog-config-guide.md](docs/graylog-config-guide.md)

> You can try the full loop without Graylog: the built-in `mock` plugin plus the `curl` samples in `docs/graylog-config-guide.md` run the entire chain "alert → policy → task → dispatch → expiry unblock".
> Demo mode (one-click Graylog + ES + MongoDB) is planned for v1.1, see `docker-compose-demo.yml`.
> 🗂️ Why the blacklist is append-only and where rejected attempts show up: [docs/blacklist-history.md](docs/blacklist-history.md).
> ☁️ Deploying to a cloud server? See [docs/deploy-cloud.md](docs/deploy-cloud.md): resource baseline, security groups & ports, HTTPS, scheduled backups, disk/log hygiene, go-live checklist.
> ⬆️ Upgrading an existing deployment? See [docs/install.md §10](docs/install.md): backup → pull → migrate → rebuild. Data volume and `.env` are untouched — never add `-v` during an upgrade.
> 🐌 Slow builds (pip / npm timeouts)? Run `bash scripts/install.sh --cn-mirror`, or set `AEGIS_PIP_INDEX` / `AEGIS_NPM_REGISTRY` in `.env` — see [docs/install.md §2.4](docs/install.md). No Dockerfile edits needed, so `git pull` stays clean.
> ✅ **How to verify a deployment?** One command runs 18 closed-loop checks: `python scripts/smoke_test.py --secret <SECRET> --password <PASSWORD>`, see [docs/verify.md](docs/verify.md).

---

## 📁 Repository Layout

```
aegis-soc/
├── sql/                  # init.sql (20 tables), seed.sql (roles/policies/sample devices)
├── backend/
│   ├── app/              # FastAPI: config / models / schemas / api / engines / services
│   ├── plugins/          # plugin abstraction + Manifest + built-in plugins
│   ├── workers/          # Celery Worker / Beat
│   └── tests/            # unit tests + end-to-end mock chain
├── frontend/             # Vue3 + Element Plus + Vite
├── deploy/               # nginx.conf / my.cnf
├── scripts/              # install.sh (one-command deploy) / smoke_test.py (post-deploy smoke checks)
├── docs/                 # install / deploy-cloud / verify / graylog / plugin-dev / api / security / architecture / blacklist-history / geoip / ai-inspection / graylog-patrol / chat-nlq
├── .github/workflows/    # ci.yml (compile+test+build+compose lint), release.yml (tag-triggered multi-arch images)
├── docker-compose.yml
├── .env.example
└── LICENSE               # Apache 2.0
```

---

## ⚙️ Key Configuration (`.env.example`)

| Variable | Description | Default |
|---|---|---|
| `DATABASE_URL` | MySQL connection string | `mysql+pymysql://aegis:...@mysql:3306/aegis_soc?charset=utf8mb4` |
| `REDIS_URL` | Dedupe / kill switch / idempotency locks | `redis://redis:6379/0` |
| `CELERY_BROKER_URL` | Task queue | `redis://redis:6379/1` |
| `JWT_SECRET` | JWT signing key — **must change** | `change-me-...` |
| `GRAYLOG_WEBHOOK_SECRET` | Webhook verification secret | `change-me-...` |
| `BOOTSTRAP_ADMIN_PASSWORD` | Initial admin password | `Admin@123456` |
| `GLOBAL_KILL_SWITCH` | Global auto-blocking kill switch | `false` |
| `TASK_EAGER` | Execute tasks synchronously (local dev/tests) | `false` |
| `ALERT_DEDUPE_TTL` | Alert dedupe window (seconds) | `3600` |

Full list: [`.env.example`](.env.example) and [docs/install.md](docs/install.md).

---

## 🔌 Built-in Plugins (v1.0)

| Code | Description | Live dispatch |
|---|---|---|
| `mock` | Records tasks and logs only; never calls a device | No (default, for closed-loop demos) |
| `http_generic` | Low-code generic REST plugin; URL/method/body templates configurable | Yes |
| `ssh_firewall` | SSH CLI blacklist dispatch for H3C / Huawei firewalls (abstracted from a production script, fully parameterized) | Yes |
| `sangfor_ips` | Sangfor IPS global blacklist API (login → sign → insert → apply) | Yes |
| `paloalto_fw` | Palo Alto PAN-OS: registers IPs as user-id DAG tags, effective immediately without commit (9.1+) | Yes |
| `qiming_fw` | Qiming Tianding Hanma USG Web API: login → blacklist → optional save & apply | Yes |
| `qiming_ips` | Qiming Tianding IPS REST v3: SHA256 password login → JWT → `block_policy`; expiry handled by the device itself | Yes |
| `aliyun_waf_v3` | Aliyun WAF 3.0 IP blacklist: fetch all → merge → write back; auto-shards rules over 200 entries (template must pre-exist; the plugin only pushes IPs) | Yes |

> ⚠️ All device addresses, accounts, passwords and API keys **are injected via plugin config or environment variables — no real credentials in code**.
> Writing a new plugin: [docs/plugin-dev.md](docs/plugin-dev.md); PA & Qiming firewall: [docs/plugins-paloalto-qiming.md](docs/plugins-paloalto-qiming.md);
> Qiming IPS: [docs/plugins-qiming-ips.md](docs/plugins-qiming-ips.md); Aliyun WAF 3.0: [docs/plugins-aliyun-waf.md](docs/plugins-aliyun-waf.md).

---

## 🛠 Local Development

```bash
# Backend
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python ../scripts/fetch_geoip.py                   # optional: download the IP geolocation db (~11 MB); without it country/city stay empty
export DATABASE_URL="sqlite:///./aegis_dev.db"    # SQLite works for a quick start
export TASK_EAGER=true
uvicorn app.main:app --reload --port 8000

# Frontend
cd frontend
npm install
npm run dev

# Tests
cd backend && pytest -q
```

> Use MySQL 8 in production; SQLite is for local quick starts only (some MySQL-specific behaviors degrade).

---

## 🔄 CI / CD

| Workflow | Trigger | What it does |
|---|---|---|
| `ci.yml` | push to main/master, PRs, manual | backend `compileall` + `pytest`; frontend `npm ci` + `npm run build`; Compose config validation |
| `release.yml` | pushing a `v*` tag, manual | builds `linux/amd64` + `linux/arm64` images, pushes to ghcr and creates a GitHub Release |

Image names (tags look like `v1.0.0`):

```
ghcr.io/aegis-soc/aegis-soc-backend:1.0.0
ghcr.io/aegis-soc/aegis-soc-frontend:1.0.0
```

```bash
git tag v1.0.0 && git push origin v1.0.0   # tagging triggers a release
```

---

## 📌 Roadmap

| Version | Scope |
|---|---|
| ✅ v1.0.0 | RBAC/JWT, IP/domain blacklists, IP whitelist + import, Graylog/generic alert ingestion, policy engine, plugin gateway, async tasks & expiry unblock, auditing, kill switch, Swagger, Docker Compose |
| 📅 v1.1.0 | AI security inspection plugin, NLQ follow-up context + log×blacklist cross-check + optional LLM fallback, enhanced approval flows, visual DAG orchestration, DMZ relay agent, full demo-mode compose |
| 📅 v1.2.0 | Real dispatch for domain/URL/hash, alert suppression & IP groups, out-of-process plugins with signature checks, plugin marketplace |
| 📅 v2.0 | Report export, threat-intel integration, more vendor plugins |

---

## 🤝 Contributing

Device plugins, bug fixes and documentation improvements are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) and [docs/plugin-dev.md](docs/plugin-dev.md); make sure `pytest` and `npm run build` pass before opening a PR.

---

## ⚠️ Risks & Disclaimer

1. Auto-blocking is a high-risk operation. Validate rules thoroughly in test environments and tune Graylog alert conditions carefully to avoid blocking legitimate business IPs.
2. The platform provides orchestration only and **does not guarantee zero false negatives or false positives**; it does not replace human security operations.
3. The authors are not liable for business interruptions or mis-blocks caused by using this platform.
4. Do not use it for unauthorized attacks, malicious blocking or any unlawful purpose.
5. Before open-sourcing your fork, complete the credential-scrubbing checklist in [docs/security.md](docs/security.md).

---

## 👤 Author & Contact

- **Maintainer**: AegisSoc team
- **Email**: [30002811@qq.com](mailto:30002811@qq.com)
- **Bug reports & feature requests**: [GitHub Issues](https://github.com/aegis-soc/aegis-soc/issues)
- Device-plugin contributions and cooperation inquiries are welcome via email.

---

## 📄 License

[Apache License 2.0](LICENSE) · Copyright 2026 AegisSoc contributors
