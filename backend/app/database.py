"""数据库引擎与会话管理。

生产环境使用 MySQL 8（表结构由 sql/init.sql 初始化）；
本地开发与单元测试可切换为 SQLite（DATABASE_URL=sqlite:///./dev.db），
由 init_db() 通过 ORM 元数据建表，保证两端模型一致。
"""
from __future__ import annotations

from collections.abc import Generator
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings


def utcnow() -> datetime:
    """naive UTC 时间，避免 Python 3.12+ 对 datetime.utcnow 的弃用告警。"""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Base(DeclarativeBase):
    pass


def _build_engine():
    if settings.is_sqlite:
        kwargs = {"connect_args": {"check_same_thread": False}, "future": True}
        if ":memory:" in settings.database_url:
            kwargs["poolclass"] = StaticPool
        return create_engine(settings.database_url, **kwargs)
    return create_engine(
        settings.database_url,
        pool_pre_ping=True,
        pool_recycle=3600,
        pool_size=10,
        max_overflow=20,
        future=True,
    )


engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False, class_=Session)


def get_db() -> Generator[Session, None, None]:
    """FastAPI 依赖：每请求一个会话，异常自动回滚。"""
    db = SessionLocal()
    try:
        yield db
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


def init_db() -> None:
    """仅用于 SQLite / 测试环境；MySQL 由 sql/init.sql + sql/seed.sql 初始化。"""
    from app import models  # noqa: F401  确保全部模型注册到 Base.metadata

    Base.metadata.create_all(bind=engine)
