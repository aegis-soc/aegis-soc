"""全局配置：仅从环境变量读取，任何真实凭据都不得写入代码或配置文件。"""
from __future__ import annotations

import os
from dataclasses import dataclass


def _get(key: str, default: str = "") -> str:
    value = os.getenv(key)
    return value if value not in (None, "") else default


def _bool(key: str, default: bool = False) -> bool:
    return _get(key, "true" if default else "false").strip().lower() in {"1", "true", "yes", "on"}


def _int(key: str, default: int) -> int:
    try:
        return int(_get(key, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Settings:
    app_env: str
    debug: bool
    log_level: str
    database_url: str
    redis_url: str
    celery_broker_url: str
    celery_result_backend: str
    jwt_secret: str
    jwt_algorithm: str
    jwt_expire_minutes: int
    graylog_webhook_secret: str
    graylog_bearer_token: str
    bootstrap_admin_password: str
    global_kill_switch: bool
    alert_dedupe_ttl: int
    alert_replay_tolerance: int
    default_block_duration: int
    task_max_retry: int
    task_retry_backoff: int
    task_eager: bool
    max_block_per_alert: int
    # IP 归属地（ip2region 离线库）：关闭或库文件缺失时归属地留空，不影响封禁
    geoip_enabled: bool
    geoip_db_path: str
    # 可选：OpenAI 兼容 LLM 接口，用于生成巡检总结；不配置则用内置规则总结
    ai_llm_base_url: str
    ai_llm_api_key: str
    ai_llm_model: str

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            app_env=_get("APP_ENV", "production"),
            debug=_bool("DEBUG", False),
            log_level=_get("LOG_LEVEL", "INFO"),
            database_url=_get(
                "DATABASE_URL",
                "mysql+pymysql://aegis:change-me@127.0.0.1:3306/aegis_soc?charset=utf8mb4",
            ),
            redis_url=_get("REDIS_URL", "redis://127.0.0.1:6379/0"),
            celery_broker_url=_get("CELERY_BROKER_URL", "redis://127.0.0.1:6379/1"),
            celery_result_backend=_get("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6379/2"),
            jwt_secret=_get("JWT_SECRET", "change-me-jwt-secret-at-least-32-characters-long"),
            jwt_algorithm=_get("JWT_ALGORITHM", "HS256"),
            jwt_expire_minutes=_int("JWT_EXPIRE_MINUTES", 480),
            graylog_webhook_secret=_get("GRAYLOG_WEBHOOK_SECRET", "change-me-graylog-webhook-secret"),
            graylog_bearer_token=_get("GRAYLOG_BEARER_TOKEN", ""),
            bootstrap_admin_password=_get("BOOTSTRAP_ADMIN_PASSWORD", "Admin@123456"),
            global_kill_switch=_bool("GLOBAL_KILL_SWITCH", False),
            alert_dedupe_ttl=_int("ALERT_DEDUPE_TTL", 3600),
            alert_replay_tolerance=_int("ALERT_REPLAY_TOLERANCE", 300),
            default_block_duration=_int("DEFAULT_BLOCK_DURATION", 7200),
            task_max_retry=_int("TASK_MAX_RETRY", 3),
            task_retry_backoff=_int("TASK_RETRY_BACKOFF", 60),
            task_eager=_bool("TASK_EAGER", False),
            max_block_per_alert=_int("MAX_BLOCK_PER_ALERT", 20),
            geoip_enabled=_bool("GEOIP_ENABLED", True),
            geoip_db_path=_get("GEOIP_DB_PATH", ""),
            ai_llm_base_url=_get("AI_LLM_BASE_URL", ""),      # 如 https://api.openai.com/v1
            ai_llm_api_key=_get("AI_LLM_API_KEY", ""),
            ai_llm_model=_get("AI_LLM_MODEL", "gpt-4o-mini"),
        )

    @property
    def is_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")


settings = Settings.from_env()
