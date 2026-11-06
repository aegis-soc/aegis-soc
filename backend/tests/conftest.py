"""测试环境：SQLite 内存库 + 同步任务执行，无需 MySQL / Redis / 真实设备。"""
from __future__ import annotations

import os

os.environ.setdefault("DATABASE_URL", "sqlite:///:memory:")
os.environ.setdefault("TASK_EAGER", "true")
os.environ.setdefault("REDIS_URL", "redis://127.0.0.1:6399/0")
os.environ.setdefault("CELERY_BROKER_URL", "redis://127.0.0.1:6399/1")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://127.0.0.1:6399/2")
os.environ.setdefault("GRAYLOG_WEBHOOK_SECRET", "test-webhook-secret")

import pytest
from fastapi.testclient import TestClient

from app.cache import cache
from app.config import settings
from app.database import Base, engine
from app.main import app


@pytest.fixture
def client(monkeypatch):
    if hasattr(cache._backend, "_data"):
        cache._backend._data.clear()
    cache.set_kill_switch(False)
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)

    # 内存 SQLite 走 StaticPool 单连接：后台线程并发使用同一连接会互相踩，
    # 因此测试环境把归属地回填改为同步执行（生产 MySQL / 文件库仍是真异步）。
    if ":memory:" in settings.database_url:
        from app.database import SessionLocal
        from app.services import geoip

        def _sync_fill(ioc_ids):
            ids = [i for i in (ioc_ids or []) if i]
            if not ids:
                return
            with SessionLocal() as db:
                if geoip.fill_geo_sync(db, ids):
                    db.commit()

        monkeypatch.setattr(geoip, "schedule_fill", _sync_fill)

    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def auth_headers(client):
    response = client.post(
        "/api/v1/auth/login",
        json={"username": "admin", "password": settings.bootstrap_admin_password},
    )
    assert response.status_code == 200, response.text
    token = response.json()["data"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


def graylog_payload(alert_id: str = "evt-001", ip: str = "8.8.8.8") -> dict:
    return {
        "event_definition_title": "WAF 暴力破解告警",
        "event_definition_id": "ed-1",
        "event": {
            "id": alert_id,
            "priority": 3,
            "message": f"攻击源 {ip} 触发规则",
            "fields": {"src_ip": ip, "confidence": 90},
        },
    }
