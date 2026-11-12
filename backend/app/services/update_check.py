"""检查更新（只读）。

只回答一个问题：GitHub 上有没有比当前更新的版本。

刻意不做的事：不下载、不执行命令、不碰容器、不写数据库。真要做「一键升级」得另起
一个持有 docker.sock 的 updater 角色，风险面完全不同；这里只把「有没有新版」摆到
页面上，升不升、什么时候升，仍由人决定。

网络侧的三条硬约束：
1. 超时 5 秒（可配），失败一律降级为 error 字段，绝不把异常抛给页面；
2. 结果缓存 10 分钟（可配）——GitHub 未认证接口只有 60 次/小时；
3. API 地址可换镜像（AEGIS_GITHUB_API_BASE），国内直连不通时可以指向 ghfast 之类。
"""
from __future__ import annotations

import json
import logging
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from app import __version__
from app.config import settings
from app.services.version_info import get_version_info

logger = logging.getLogger("aegis")

NOTES_LIMIT = 1200

_cache_lock = threading.Lock()
_cache: dict[str, object] = {"at": 0.0, "data": None}


def parse_version(text: str) -> tuple[int, int, int] | None:
    """把 v1.2.3 / 1.2 / 1.2.3-beta.1 解析成三元组；解析不了返回 None。

    预发布后缀（-beta.1）直接丢掉：本项目的 tag 只用 vX.Y.Z，出现后缀说明是
    手工测试构建，按正式版比较更安全（宁可多提示一次，不要漏掉）。
    """
    raw = (text or "").strip().lstrip("vV")
    if not raw:
        return None
    core = raw.split("-")[0].split("+")[0]
    parts = core.split(".")
    if not 1 <= len(parts) <= 3:
        return None
    nums: list[int] = []
    for part in parts:
        if not part.isdigit():
            return None
        nums.append(int(part))
    while len(nums) < 3:
        nums.append(0)
    return nums[0], nums[1], nums[2]


def _fetch_latest(timeout: float) -> dict:
    """拉 GitHub 最新 release。任何网络/解析异常由调用方兜底。"""
    url = f"{settings.github_api_base}/repos/{settings.github_repo}/releases/latest"
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": f"aegis-soc/{__version__}",
            "Accept": "application/vnd.github+json",
        },
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8", "replace"))


def _empty_payload() -> dict:
    info = get_version_info()
    return {
        "current_version": info["version"],
        "current_commit": info["commit"],
        "build_time": info["build_time"],
        "enabled": settings.update_check_enabled,
        "latest_version": "",
        "published_at": "",
        "html_url": "",
        "notes": "",
        "notes_truncated": False,
        "has_update": False,
        "cached": False,
        "checked_at": "",
        "error": "",
    }


def _store(payload: dict) -> dict:
    with _cache_lock:
        _cache["at"] = time.time()
        _cache["data"] = dict(payload)
    return payload


def check(force: bool = False) -> dict:
    """返回检查结果。force=True 跳缓存（页面上的「检查更新」按钮）。"""
    payload = _empty_payload()
    if not settings.update_check_enabled:
        payload["error"] = "更新检查已关闭（AEGIS_UPDATE_CHECK=false）"
        return payload

    now = time.time()
    with _cache_lock:
        cached = _cache["data"]
        cached_at = float(_cache["at"])
    if not force and isinstance(cached, dict) and now - cached_at < settings.update_cache_ttl:
        hit = dict(cached)
        hit["cached"] = True
        return hit

    try:
        release = _fetch_latest(settings.update_check_timeout)
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            payload["error"] = "仓库还没有发布任何 Release"
        elif exc.code == 403:
            payload["error"] = "GitHub 接口调用次数已达上限（未认证 60 次/小时），请稍后再试"
        else:
            payload["error"] = f"GitHub 返回 HTTP {exc.code}"
        logger.warning("检查更新失败：%s", payload["error"])
        return payload
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        payload["error"] = f"无法连接 GitHub（{exc.__class__.__name__}），可稍后重试或配置镜像"
        logger.warning("检查更新失败：%s", payload["error"])
        return payload
    except (ValueError, json.JSONDecodeError):
        payload["error"] = "GitHub 返回内容不是合法 JSON"
        return payload

    tag = str(release.get("tag_name") or "").strip()
    latest = parse_version(tag)
    current = parse_version(__version__)
    notes = str(release.get("body") or "").strip()
    truncated = len(notes) > NOTES_LIMIT

    payload.update(
        {
            "latest_version": tag,
            "published_at": str(release.get("published_at") or ""),
            "html_url": str(release.get("html_url") or ""),
            "notes": notes[:NOTES_LIMIT],
            "notes_truncated": truncated,
            "has_update": bool(latest and current and latest > current),
            "checked_at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
            "error": "" if latest else f"无法解析版本号：{tag or '空'}",
        }
    )
    return _store(payload)


def reset_cache() -> None:
    """测试用：清缓存。"""
    with _cache_lock:
        _cache["at"] = 0.0
        _cache["data"] = None
