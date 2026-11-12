"""版本信息：版本号只有一个来源，其余信息按「构建注入 → 本地 git → 文件时间」回退。

为什么不在前端或 compose 里再写一份版本号：两处写死必然有一天不一致，
排查问题时报出来的版本就是错的。前端一律从 ``/system/status`` 读。
"""
from __future__ import annotations

import os
import subprocess
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from app import __version__

# backend/app/services/version_info.py -> backend/（本地开发）或 /app（容器内）
APP_DIR = Path(__file__).resolve().parents[2]
# 仓库根：本地开发时才有 .git，容器里没有，git 探测会直接失败回退
REPO_DIR = Path(__file__).resolve().parents[3]


def _git(*args: str) -> str:
    """读取 git 信息；没有 git 命令、不是仓库、超时都返回空串，绝不抛异常。"""
    try:
        done = subprocess.run(
            ["git", "-C", str(REPO_DIR), *args],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return done.stdout.strip() if done.returncode == 0 else ""


def _build_time_file() -> str:
    """Dockerfile 在构建时写入 .build_time，容器里据此显示真实构建时间。"""
    path = APP_DIR / ".build_time"
    try:
        return path.read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def _fallback_build_time() -> str:
    """没有注入也没有构建标记时，退回本文件的修改时间（本地开发够用）。"""
    try:
        ts = Path(__file__).stat().st_mtime
    except OSError:
        return ""
    return datetime.fromtimestamp(ts).astimezone().isoformat(timespec="seconds")


@lru_cache(maxsize=1)
def get_version_info() -> dict[str, str]:
    """返回 version / commit / tag / build_time / source，进程内只计算一次。"""
    env_commit = os.getenv("AEGIS_GIT_COMMIT", "").strip()
    env_tag = os.getenv("AEGIS_GIT_TAG", "").strip()

    commit = env_commit or _git("rev-parse", "--short", "HEAD")
    source = "build" if env_commit else ("git" if commit else "unknown")
    tag = env_tag or (_git("describe", "--tags", "--abbrev=0") if commit else "")

    build_time = _build_time_file() or _fallback_build_time()

    return {
        "version": __version__,
        "commit": commit or "unknown",
        "tag": tag or "",
        "build_time": build_time,
        "source": source,
    }
