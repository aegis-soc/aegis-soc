#!/usr/bin/env python3
"""宙斯盾 AegisSoc 一键冒烟验收脚本（仅用标准库，无需 pip 安装任何依赖）。

用途：在 `docker compose up -d` 之后，用一条命令验证整条业务闭环是否真的跑通：
    界面静态资源 → 健康检查 → 登录 → 白名单豁免 → 告警接入 → 去重
    → IOC 落库 → 插件下发（mock）→ 任务成功 → 熔断 → 审计

用法：
    python scripts/smoke_test.py --base http://127.0.0.1:8080 \
        --secret <你的 GRAYLOG_WEBHOOK_SECRET> --password <管理员口令>

    # 也可用环境变量，避免口令出现在命令历史里
    export SMOKE_ADMIN_PASSWORD=xxx
    export SMOKE_WEBHOOK_SECRET=yyy
    python scripts/smoke_test.py

退出码：0 全部通过 / 1 存在失败项。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# 冒烟专用测试 IP：公网地址，不会命中内置白名单
PROBE_IP = "93.184.216.34"
# 内置种子白名单里的示例地址（bootstrap / seed.sql 写入）
WHITELISTED_IP = "198.51.100.10"
# v1.0 内置插件清单：冒烟时校验是否全部注册成功（新增插件请同步这里）
EXPECTED_PLUGINS = {
    "mock", "http_generic", "ssh_firewall", "sangfor_ips",
    "paloalto_fw", "qiming_fw", "qiming_ips", "aliyun_waf_v3",
}

RESULTS: list[tuple[str, bool, str]] = []


def http(method: str, url: str, token: str | None = None, body: dict | None = None,
         timeout: int = 20) -> tuple[int, dict | str | None]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", "replace")
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw


def step(name: str, ok: bool, detail: str = "") -> bool:
    RESULTS.append((name, ok, detail))
    print(f"  {'✅' if ok else '❌'} {name}" + (f"  —— {detail}" if detail else ""), flush=True)
    return ok


def skip(name: str, detail: str = "") -> None:
    """不计入结果的中性提示（例如后端直连模式没有前端页面）。"""
    print(f"  ⏭  {name}" + (f"  —— {detail}" if detail else ""), flush=True)


def payload_of(data: object) -> dict:
    return data.get("data") or {} if isinstance(data, dict) else {}


def items_of(data: object) -> list:
    return payload_of(data).get("items") or []


def main() -> int:
    parser = argparse.ArgumentParser(description="AegisSoc 冒烟验收")
    parser.add_argument("--base", default=os.getenv("SMOKE_BASE", "http://127.0.0.1:8080"),
                        help="平台访问地址，默认 http://127.0.0.1:8080")
    parser.add_argument("--user", default=os.getenv("SMOKE_ADMIN_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("SMOKE_ADMIN_PASSWORD", "Admin@123456"))
    parser.add_argument("--secret", default=os.getenv("SMOKE_WEBHOOK_SECRET",
                                                      "change-me-graylog-webhook-secret"),
                        help="GRAYLOG_WEBHOOK_SECRET，必须与 .env 中一致")
    parser.add_argument("--timeout", type=int, default=20)
    args = parser.parse_args()

    base = args.base.rstrip("/")
    print(f"\n🛡  宙斯盾 AegisSoc 冒烟验收  →  {base}\n", flush=True)

    # ---------- 1. 界面静态资源 ----------
    print("[1/9] 管理界面", flush=True)
    try:
        req = urllib.request.Request(f"{base}/", headers={"Accept": "text/html"})
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            html = resp.read().decode("utf-8", "replace")
        step("首页 HTTP 200", resp.status == 200, f"status={resp.status}")
        mounted = '<div id="app">' in html
        has_assets = "/assets/" in html
        step("返回前端页面（含 app 挂载点或 assets 资源）", mounted or has_assets,
             "已挂载 #app" if mounted else
             ("已引用构建产物 /assets/" if has_assets else
              "HTML 中未找到前端挂载点，nginx 可能未指向 frontend 容器"))
    except urllib.error.HTTPError as e:
        if e.code == 404:
            skip("首页检查（当前为后端直连模式，未挂前端）",
                 "界面请通过 nginx 的 8080 端口访问，如 docker compose 的默认入口")
        else:
            step("首页可访问", False, f"HTTP {e.code}")
    except Exception as e:  # noqa: BLE001
        step("首页可访问", False, f"{type(e).__name__}: {e}")

    # ---------- 2. 健康检查 ----------
    print("[2/9] 健康检查", flush=True)
    code, data = http("GET", f"{base}/api/healthz", timeout=args.timeout)
    health = payload_of(data)
    step("GET /api/healthz", code == 200 and health.get("status") == "healthy",
         f"HTTP {code} db={health.get('database')} cache={health.get('cache')}")

    # ---------- 3. 登录 ----------
    print("[3/9] 管理员登录", flush=True)
    code, data = http("POST", f"{base}/api/v1/auth/login",
                      body={"username": args.user, "password": args.password},
                      timeout=args.timeout)
    token = payload_of(data).get("access_token")
    if not token:
        step("POST /api/v1/auth/login", False, f"HTTP {code} {data}")
        print("\n登录失败，后续步骤无法继续。请检查 --user/--password 是否与 .env 一致。\n", flush=True)
        return summarize()
    step("POST /api/v1/auth/login", True, f"role={payload_of(data).get('role_code')}")
    if payload_of(data).get("must_change_password"):
        print("      ⚠️ 该账号仍是初始口令，建议先在界面改密（本次冒烟不受影响）", flush=True)

    # ---------- 4. 白名单豁免 ----------
    print("[4/9] 白名单优先（硬性安全边界）", flush=True)
    code, data = http("GET", f"{base}/api/v1/whitelist/ips/check?ip={WHITELISTED_IP}",
                      token=token, timeout=args.timeout)
    step(f"{WHITELISTED_IP} 命中白名单", code == 200 and payload_of(data).get("whitelisted") is True,
         f"HTTP {code} whitelisted={payload_of(data).get('whitelisted')}")

    # ---------- 5. 告警接入 ----------
    print("[5/9] Graylog 告警接入 → 策略 → 下发", flush=True)
    alert_id = f"smoke-{int(time.time())}"
    payload = {
        "event_definition_title": "冒烟测试：可疑横向扫描",
        "event_definition_id": "smoke-ed",
        "event": {
            "id": alert_id,
            "priority": 3,
            "message": f"攻击源 {PROBE_IP} 触发冒烟规则",
            "fields": {"src_ip": PROBE_IP, "confidence": 90},
        },
    }
    url = f"{base}/api/v1/alerts/graylog?secret={urllib.parse.quote(args.secret)}"
    code, data = http("POST", url, body=payload, timeout=args.timeout)
    d = payload_of(data)
    if code == 403:
        step("告警接入", False, "secret 校验失败：--secret 与 .env 里的 GRAYLOG_WEBHOOK_SECRET 不一致")
        return summarize()
    step("告警被受理（快速返回 accepted）", code == 200 and d.get("status") == "accepted",
         f"HTTP {code} status={d.get('status')} msg={d.get('message')}")
    step("生成 IOC", int(d.get("ioc_count") or 0) >= 1, f"ioc_count={d.get('ioc_count')}")
    step("生成下发任务", int(d.get("task_count") or 0) >= 1,
         f"task_count={d.get('task_count')}（0 表示策略未命中或熔断开启）")

    # ---------- 6. 去重 ----------
    print("[6/9] 告警幂等去重", flush=True)
    code, data = http("POST", url, body=payload, timeout=args.timeout)
    step("同一 alert_id 重复投递被去重", payload_of(data).get("duplicated") is True,
         f"duplicated={payload_of(data).get('duplicated')}")

    # ---------- 7. IOC 与任务回执 ----------
    print("[7/9] IOC 落库与插件执行结果", flush=True)
    code, data = http("GET", f"{base}/api/v1/ioc/ips?keyword={PROBE_IP}", token=token,
                      timeout=args.timeout)
    ioc_items = items_of(data)
    step("黑名单中查到该 IP",
         any(i.get("normalized_value") == PROBE_IP for i in ioc_items),
         f"命中 {len(ioc_items)} 条")

    code, data = http("GET", f"{base}/api/v1/tasks?keyword={PROBE_IP}", token=token,
                      timeout=args.timeout)
    tasks = items_of(data)
    step("生成了设备任务", len(tasks) >= 1, f"{len(tasks)} 条")
    if tasks:
        mock_tasks = [t for t in tasks if t.get("plugin_code") == "mock"]
        statuses = [t.get("task_status") for t in mock_tasks]
        others = [
            f"{t.get('plugin_code')}={t.get('task_status')}"
            for t in tasks if t.get("plugin_code") != "mock"
        ]
        note = f"mock={statuses}"
        if others:
            note += f"，其他设备={others}（未配真实设备时失败属预期）"
        step("任务执行成功（mock 插件）",
             bool(mock_tasks) and all(s == "SUCCESS" for s in statuses), note)
        tid = tasks[0]["id"]
        code, detail = http("GET", f"{base}/api/v1/tasks/{tid}", token=token, timeout=args.timeout)
        logs = payload_of(detail).get("logs") or []
        step("任务留有请求/响应日志", len(logs) >= 1, f"{len(logs)} 条日志")

    # ---------- 8. 熔断开关 ----------
    print("[8/9] 全局熔断", flush=True)
    try:
        code, data = http("POST", f"{base}/api/v1/system/kill-switch", token=token,
                          body={"enabled": True, "reason": "冒烟演练"}, timeout=args.timeout)
        step("开启熔断", code == 200 and payload_of(data).get("enabled") is True, f"HTTP {code}")
        probe = dict(payload)
        probe["event"] = dict(payload["event"], id=alert_id + "-k")
        code, data = http("POST", url, body=probe, timeout=args.timeout)
        d = payload_of(data)
        step("熔断期间只记录不封禁", int(d.get("task_count") or 0) == 0,
             f"task_count={d.get('task_count')} msg={d.get('message')}")
    finally:
        http("POST", f"{base}/api/v1/system/kill-switch", token=token,
             body={"enabled": False}, timeout=args.timeout)
        print("      已自动关闭熔断", flush=True)

    # ---------- 9. 插件 / 审计 / 大盘 ----------
    print("[9/9] 插件、审计与大盘", flush=True)
    code, data = http("GET", f"{base}/api/v1/plugins", token=token, timeout=args.timeout)
    plugins = items_of(data)
    codes = {p.get("plugin_code") for p in plugins}
    missing = EXPECTED_PLUGINS - codes
    step(f"内置插件齐备（{len(EXPECTED_PLUGINS)} 个）",
         not missing,
         f"共 {len(plugins)} 个" + (f"，缺少 {sorted(missing)}" if missing else ""))

    code, data = http("GET", f"{base}/api/v1/audit", token=token, timeout=args.timeout)
    total = payload_of(data).get("total")
    step("审计日志有记录", isinstance(total, int) and total > 0, f"total={total}")

    code, data = http("GET", f"{base}/api/v1/dashboard", token=token, timeout=args.timeout)
    step("大盘接口可用", code == 200 and isinstance(payload_of(data), dict) and payload_of(data) != {},
         f"task_total={payload_of(data).get('task_total')}")

    return summarize()


def summarize() -> int:
    passed = sum(1 for _, ok, _ in RESULTS if ok)
    failed = [r for r in RESULTS if not r[1]]
    print("\n" + "─" * 62, flush=True)
    print(f"结果：{passed}/{len(RESULTS)} 项通过" + ("" if not failed else f"，{len(failed)} 项失败"),
          flush=True)
    if failed:
        print("\n失败项：", flush=True)
        for name, _, detail in failed:
            print(f"  ❌ {name}  —— {detail}", flush=True)
        print("\n排查建议：docker compose ps / docker compose logs -f api worker", flush=True)
        print("─" * 62 + "\n", flush=True)
        return 1
    print("🎉 全链路闭环验证通过：界面 → 告警 → 策略 → 下发 → 审计 均正常", flush=True)
    print("─" * 62 + "\n", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
