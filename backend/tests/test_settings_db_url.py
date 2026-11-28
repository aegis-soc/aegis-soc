"""数据库连接串组装测试：分量化密码自动 URL 编码，显式 DATABASE_URL 优先。

背景（2026-11-26 真机踩坑）：密码 admin@123 拼进 DATABASE_URL 会被 @ 截断
解析（host 变成 123@mysql），api 起不来报 OperationalError。分量化（DB_*）
让 .env 写原始密码，编码由平台负责。
"""
from __future__ import annotations

from app.config import Settings, _database_url


def _with_env(monkeypatch, **env):
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    return Settings.from_env()


def test_db_password_components_url_encode_special_chars(monkeypatch):
    """密码含 @ 时自动编码成 %40，不再截断 URL。"""
    _with_env(monkeypatch,
              DATABASE_URL="", DB_PASSWORD="admin@123",
              DB_USER="aegis", DB_HOST="mysql", DB_PORT="3306", DB_NAME="aegis_soc")
    url = _database_url()
    assert url == "mysql+pymysql://aegis:admin%40123@mysql:3306/aegis_soc?charset=utf8mb4"


def test_db_password_more_special_chars_encoded(monkeypatch):
    """# : / 等字符同样编码。"""
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DB_PASSWORD", "p#1:2/3")
    url = _database_url()
    assert "p%231%3A2%2F3@" in url


def test_explicit_database_url_takes_precedence(monkeypatch):
    """显式 DATABASE_URL 优先，DB_* 分量不参与。"""
    monkeypatch.setenv("DATABASE_URL", "mysql+pymysql://u:p@db:3307/x?charset=utf8mb4")
    monkeypatch.setenv("DB_PASSWORD", "admin@123")
    assert _database_url() == "mysql+pymysql://u:p@db:3307/x?charset=utf8mb4"


def test_no_config_falls_back_to_default(monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DB_PASSWORD", raising=False)
    assert _database_url() == \
        "mysql+pymysql://aegis:change-me@127.0.0.1:3306/aegis_soc?charset=utf8mb4"


# ---------------------------------------------------------------- 必填字段校验
def test_validate_required_fields_blocking():
    from app.services.patrol_settings import validate_required_fields
    errors, _ = validate_required_fields("ips", ["src_ip", "action"], {})
    assert any("ts" in e for e in errors)          # 缺 ts 阻断
    errors, _ = validate_required_fields("ips", [], {})
    assert len(errors) == 2                        # ts + src_ip 都缺
    errors, warnings = validate_required_fields("ips", ["ts", "src_ip"], {})
    assert errors == []
    assert any("action" in w for w in warnings)    # 建议项缺失仅提示
    errors, warnings = validate_required_fields(
        "ztna", ["ts", "src_ip", "username", "ua_class", "dst_domain"], {})
    assert errors == []
    assert any("l7_app_request_type" in w for w in warnings)


def test_field_status_resolution():
    from app.services.patrol_settings import field_status
    stream = {"source_code": "ztna",
              "required_fields": ["ts", "src_ip", "url", "username"],
              "field_mapping": {"url": "request_uri"}}
    status = {s["field"]: s for s in field_status(stream)}
    assert status["ts"]["graylog"] == "timestamp" and status["ts"]["how"] == "alias"
    assert status["ts"]["level"] == "blocking"
    assert status["src_ip"]["how"] == "same" and status["src_ip"]["level"] == "blocking"
    assert status["url"]["graylog"] == "request_uri" and status["url"]["how"] == "mapping"
    assert status["username"]["how"] == "same" and status["username"]["level"] == "suggested"


def test_save_rejects_missing_blocking_fields(client, auth_headers):
    from app.database import SessionLocal
    from app.services import patrol_settings
    db = SessionLocal()
    try:
        cfg = patrol_settings.load(db)
        streams = [dict(s) for s in cfg.streams]
        for s in streams:
            if s.get("source_code") == "ips":
                s["required_fields"] = ["src_ip"]       # 故意去掉 ts
        import pytest
        from app.common import BizError
        with pytest.raises(BizError) as exc:
            patrol_settings.save(db, {"streams": streams}, operator="test")
        assert "ts" in str(exc.value)
    finally:
        db.close()


# ---------------------------------------------------------------- 老库升级补表
def test_create_missing_tables_recreates_dropped(client, auth_headers):
    """模拟老库缺新表（lba_collect_state 被删）→ bootstrap 补建，500 根因回归。"""
    from sqlalchemy import text

    from app.bootstrap import _create_missing_tables
    from app.database import engine

    with engine.begin() as conn:
        conn.execute(text("DROP TABLE IF EXISTS lba_collect_state"))
        conn.execute(text("DROP TABLE IF EXISTS lba_user_hourly"))

    _create_missing_tables()

    with engine.connect() as conn:
        names = {r[0] for r in conn.execute(text("SELECT name FROM sqlite_master WHERE type='table'"))}
    assert "lba_collect_state" in names and "lba_user_hourly" in names
