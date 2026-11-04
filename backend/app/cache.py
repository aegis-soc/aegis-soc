"""缓存抽象：Redis 用于告警去重、限流、幂等锁与全局熔断开关。

Redis 不可用（本地开发 / 单元测试 / 容器启动竞态）时自动降级为进程内内存后端，
保证平台链路仍可运行；生产环境应始终配置 Redis。
"""
from __future__ import annotations

import logging
import threading
import time

from app.config import settings

logger = logging.getLogger("aegis")
KILL_SWITCH_KEY = "aegis:system:kill_switch"


class _MemoryBackend:
    def __init__(self) -> None:
        self._data: dict[str, tuple[str, float | None]] = {}
        self._lock = threading.Lock()

    def _purge(self, key: str) -> None:
        item = self._data.get(key)
        if item and item[1] is not None and item[1] < time.time():
            self._data.pop(key, None)

    def set_nx(self, key: str, value: str, ex: int | None = None) -> bool:
        with self._lock:
            self._purge(key)
            if key in self._data:
                return False
            self._data[key] = (value, time.time() + ex if ex else None)
            return True

    def get(self, key: str) -> str | None:
        with self._lock:
            self._purge(key)
            item = self._data.get(key)
            return item[0] if item else None

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        with self._lock:
            self._data[key] = (value, time.time() + ex if ex else None)

    def delete(self, key: str) -> None:
        with self._lock:
            self._data.pop(key, None)


class _RedisBackend:
    def __init__(self, client) -> None:
        self._client = client

    def set_nx(self, key: str, value: str, ex: int | None = None) -> bool:
        return bool(self._client.set(key, value, nx=True, ex=ex))

    def get(self, key: str) -> str | None:
        return self._client.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._client.set(key, value, ex=ex)

    def delete(self, key: str) -> None:
        self._client.delete(key)


class Cache:
    def __init__(self) -> None:
        self._backend: _RedisBackend | _MemoryBackend = _MemoryBackend()
        self.mode = "memory"
        try:
            import redis

            client = redis.Redis.from_url(settings.redis_url, socket_connect_timeout=1, decode_responses=True)
            client.ping()
            self._backend = _RedisBackend(client)
            self.mode = "redis"
        except Exception as exc:
            logger.warning("Redis 不可用，降级为内存缓存: %s", exc.__class__.__name__)

    def set_nx(self, key: str, value: str = "1", ex: int | None = None) -> bool:
        return self._backend.set_nx(key, value, ex)

    def get(self, key: str) -> str | None:
        return self._backend.get(key)

    def set(self, key: str, value: str, ex: int | None = None) -> None:
        self._backend.set(key, value, ex)

    def delete(self, key: str) -> None:
        self._backend.delete(key)

    @property
    def kill_switch(self) -> bool:
        value = self.get(KILL_SWITCH_KEY)
        if value is None:
            value = "1" if settings.global_kill_switch else "0"
            self.set(KILL_SWITCH_KEY, value)
        return value == "1"

    def set_kill_switch(self, enabled: bool) -> None:
        self.set(KILL_SWITCH_KEY, "1" if enabled else "0")


cache = Cache()
