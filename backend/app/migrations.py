"""轻量结构升级（无 Alembic）。

生产 MySQL 用 `sql/migrate_20261105_ioc_history.sql` 手工执行；
本地 SQLite 由 `init_db()` 自动调用本模块完成等价升级，
保证 `_local.db` 这类开发库不用删库就能平滑演进。

注意：pysqlite 对 DDL 会隐式提交，`engine.begin()` 并不能把整个重建包成一个
原子事务，所以这里按「先重命名 → 建新表 → 搬数据 → 删旧表」分步执行，
每一步都可重入：中途失败时旧表（*_legacy）仍在，下次启动会接着补齐。
"""
from __future__ import annotations

import logging

from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("aegis")

LEGACY = "ioc_indicator_legacy"
CARRY_COLUMNS = [
    "id", "ioc_type", "ioc_value", "normalized_value", "status", "confidence",
    "risk_level", "expire_at", "tags", "remark", "source_count", "created_by",
    "created_at", "updated_at",
]

# 归属地快照字段（v2 新增）。放这里而不是只在 models 里，是为了老库能补列。
GEO_COLUMNS = {
    "geo_country": "VARCHAR(64)",
    "geo_province": "VARCHAR(64)",
    "geo_city": "VARCHAR(64)",
    "geo_isp": "VARCHAR(64)",
}


def _columns(engine: Engine, table: str) -> list[str]:
    return [col["name"] for col in inspect(engine).get_columns(table)]


def _has_unique_ioc_key(engine: Engine, table: str) -> bool:
    """旧版 uk_ioc(ioc_type, normalized_value) 是否还存在。"""
    for index in inspect(engine).get_indexes(table):
        if index.get("unique") and index.get("column_names") == ["ioc_type", "normalized_value"]:
            return True
    return False


def _copy_sql(legacy_columns: list[str]) -> str:
    carry = [col for col in CARRY_COLUMNS if col in legacy_columns]
    source_type = (
        "CASE WHEN remark LIKE '由告警%' THEN 'GRAYLOG' ELSE 'MANUAL' END"
        if "remark" in legacy_columns
        else "'UNKNOWN'"
    )
    return (
        f"INSERT INTO ioc_indicator ({', '.join(carry)}, source_type) "
        f"SELECT {', '.join(carry)}, {source_type} FROM {LEGACY}"
    )


def _finish_interrupted_upgrade(engine: Engine) -> None:
    """上次升级中断后的兜底：能恢复就先恢复，新表已建则补数据后清理旧表。"""
    inspector = inspect(engine)
    tables = set(inspector.get_table_names())
    if LEGACY not in tables:
        return

    if "ioc_indicator" not in tables:
        with engine.begin() as conn:
            conn.execute(text(f"ALTER TABLE {LEGACY} RENAME TO ioc_indicator"))
        logger.warning("恢复中断的升级：%s 已改名回 ioc_indicator", LEGACY)
        return

    legacy_columns = _columns(engine, LEGACY)
    with engine.begin() as conn:
        empty = conn.execute(text("SELECT COUNT(*) FROM ioc_indicator")).scalar() == 0
        if empty:
            conn.execute(text(_copy_sql(legacy_columns)))
        conn.execute(text(f"DROP TABLE {LEGACY}"))
    logger.warning("补齐中断的升级：旧表数据已搬入 ioc_indicator 并清理临时表")


def upgrade_sqlite_schema(engine: Engine) -> None:
    """SQLite 启动升级：旧版同值唯一 → 流水表，再补齐后续新增列。

    两步都必须在每次启动时检查：重建用 `_has_unique_ioc_key` 判定，
    加列用列名判定。这样既能升级很老的库，也能让只差几列的中途版本补齐。
    """
    _finish_interrupted_upgrade(engine)

    inspector = inspect(engine)
    if "ioc_indicator" not in inspector.get_table_names():
        return

    columns = _columns(engine, "ioc_indicator")
    if "source_type" not in columns or _has_unique_ioc_key(engine, "ioc_indicator"):
        _rebuild_as_history_table(engine, columns)

    _ensure_columns(engine, "ioc_indicator", GEO_COLUMNS)
    _ensure_geo_index(engine)


def _rebuild_as_history_table(engine: Engine, columns: list[str]) -> None:
    logger.warning("检测到旧版 ioc_indicator，开始重建为流水表（保留历史数据）")
    from app.database import Base
    from app import models  # noqa: F401  确保模型已注册

    # 重命名后旧索引会跟着走，名字要先释放，否则新表建同名索引会冲突
    inspector = inspect(engine)
    legacy_indexes = [
        idx["name"] for idx in inspector.get_indexes("ioc_indicator") if idx.get("name")
    ]

    with engine.begin() as conn:
        conn.execute(text(f"DROP TABLE IF EXISTS {LEGACY}"))
        conn.execute(text(f"ALTER TABLE ioc_indicator RENAME TO {LEGACY}"))
        for name in legacy_indexes:
            conn.execute(text(f'DROP INDEX IF EXISTS "{name}"'))
        Base.metadata.tables["ioc_indicator"].create(bind=conn)
        conn.execute(text(_copy_sql(columns)))
        conn.execute(text(f"DROP TABLE {LEGACY}"))
    logger.warning("ioc_indicator 重建完成：同值不再合并，历史记录来源标记为 GRAYLOG/MANUAL")


def _ensure_columns(engine: Engine, table: str, columns: dict[str, str]) -> None:
    """按需 ALTER TABLE ADD COLUMN（SQLite 加列不改数据，成本极低、可重入）。"""
    existing = set(_columns(engine, table))
    missing = {name: ddl for name, ddl in columns.items() if name not in existing}
    if not missing:
        return
    with engine.begin() as conn:
        for name, ddl in missing.items():
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
    logger.warning("%s 补充字段：%s", table, ", ".join(missing))


def _ensure_geo_index(engine: Engine) -> None:
    with engine.begin() as conn:
        conn.execute(
            text('CREATE INDEX IF NOT EXISTS "idx_ioc_geo" ON ioc_indicator (geo_country)')
        )

