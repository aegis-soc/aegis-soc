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
