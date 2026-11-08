"""数据库查询编译器：``dsl.DbItem`` → SQLAlchemy 查询 → 结构化结果。

**这里是全链路唯一生成 SQL 的地方**，也是「不让模型碰数据库」的落点：

- 表、列全部来自 ``catalog.SOURCES`` 的白名单，DSL 里拿不到任何模型对象；
- 过滤值一律走绑定参数（``in_`` / ``==`` / ``like`` 的参数位），没有字符串拼接；
- 结果集强制 ``LIMIT ≤ 200``，时间为必选条件（默认近 7 天），避免全表扫描；
- 分桶表达式按方言分支（SQLite ``strftime`` / MySQL ``DATE_FORMAT``），
  两套库都能跑，测试环境和生产口径一致。

``run()`` 返回的 ``columns/rows`` 是给前端直接渲染的（label 已翻中文），
``sql`` 只用于「查看查询详情」展示——它由 SQLAlchemy 编译而来，不是用户输入。
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import Select, distinct, func, select, text
from sqlalchemy.orm import Session

from app.database import utcnow
from app.models import SecurityDevice
from app.services.chat import catalog
from app.services.chat.dsl import DbItem

logger = logging.getLogger("aegis")

# 去重统计取哪一列：ioc 用指标值，告警用去重键，其余退回主键
DISTINCT_ATTR: dict[str, str] = {"ioc": "normalized_value", "alert": "dedupe_key"}


def _dialect(db: Session) -> str:
    try:
        return db.get_bind().dialect.name
    except Exception:                       # noqa: BLE001 - 取不到就当 sqlite 处理
        return "sqlite"


def _bucket_expr(db: Session, column: Any, unit: str) -> Any:
    """时间分桶：SQLite 与 MySQL 各有一套函数，产出同格式字符串。"""
    fmt = "%Y-%m-%d %H:00" if unit == "hour" else "%Y-%m-%d"
    if _dialect(db) == "sqlite":
        return func.strftime(fmt, column)
    return func.date_format(column, fmt)


def _metric_expr(db: Session, item: DbItem, src: catalog.Source) -> Any:
    if item.metric == "avg_confidence":
        return func.avg(getattr(src.model, "confidence"))
    if item.metric == "distinct_value":
        attr = DISTINCT_ATTR.get(src.key, "id")
        return func.count(distinct(getattr(src.model, attr)))
    return func.count()


def _apply_filters(stmt: Select, item: DbItem, src: catalog.Source) -> Select:
    for key, value in (item.filters or {}).items():
        attr = src.filters.get(key)
        if attr is None:                    # DSL 已校验，这里只是二道保险
            continue
        column = getattr(src.model, attr)
        if key == "keyword":
            safe = str(value).replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
            stmt = stmt.where(column.like(f"%{safe}%", escape="\\"))
        elif isinstance(value, (list, tuple, set)):
            values = [str(v) for v in value if str(v).strip()]
            if values:
                stmt = stmt.where(column.in_(values))
        elif value not in (None, ""):
            stmt = stmt.where(column == str(value))
    return stmt


def _apply_window(stmt: Select, item: DbItem, src: catalog.Source) -> Select:
    start = utcnow() - timedelta(days=item.time.last_days)
    column = getattr(src.model, src.time_attr)
    return stmt.where(column >= start)


def _compile_text(db: Session, stmt: Select) -> str:
    try:
        return str(stmt.compile(bind=db.get_bind(), compile_kwargs={"literal_binds": True}))
    except Exception:                       # noqa: BLE001 - 展示用，失败不影响查询
        return ""


def _device_names(db: Session, ids: list[int]) -> dict[int, str]:
    if not ids:
        return {}
    rows = (
        db.query(SecurityDevice.id, SecurityDevice.name)
        .filter(SecurityDevice.id.in_(ids))
        .all()
    )
    return {int(row[0]): row[1] for row in rows}


def _scalar_total(db: Session, item: DbItem, src: catalog.Source) -> int | None:
    """分组被 LIMIT 截断时，另外算一次总量，结论里才不会把「Top10 之和」当总数。"""
    if not item.group_by:
        return None
    stmt = select(func.count()).select_from(src.model)
    stmt = _apply_filters(stmt, item, src)
    stmt = _apply_window(stmt, item, src)
    try:
        return int(db.execute(stmt).scalar() or 0)
    except Exception as exc:                # noqa: BLE001
        logger.debug("统计总量失败：%s", exc)
        return None


def run(db: Session, item: DbItem) -> dict[str, Any]:
    """执行一个子查询，返回可直接渲染的结果块数据。异常向上抛，由 pipeline 兜。"""
    src = catalog.source(item.source)
    if src is None:                         # pragma: no cover - DSL 已保证
        raise ValueError(f"未知数据源 {item.source}")

    if _dialect(db) == "mysql":
        # 尽力设置语句级超时；只读账号可能没权限，失败就靠 LIMIT + 时间窗兜底
        try:
            db.execute(text(f"SET SESSION MAX_EXECUTION_TIME={catalog.QUERY_TIMEOUT_MS}"))
        except Exception:                   # noqa: BLE001
            pass

    metric_expr = _metric_expr(db, item, src).label("metric_value")
    group_col: Any = None
    if item.group_by == "time_bucket":
        group_col = _bucket_expr(db, getattr(src.model, src.time_attr), item.time.bucket)
    elif item.group_by:
        group_col = getattr(src.model, src.dims[item.group_by])

    if group_col is None:
        stmt = select(metric_expr).select_from(src.model)
        stmt = _apply_filters(stmt, item, src)
        stmt = _apply_window(stmt, item, src)
        sql_text = _compile_text(db, stmt)
        value = db.execute(stmt).scalar() or 0
        return {
            "source": src.key,
            "source_label": src.label,
            "group_by": None,
            "group_label": catalog.metric_label(item.metric),
            "metric": item.metric,
            "metric_label": catalog.metric_label(item.metric),
            "columns": [
                {"key": "label", "label": "口径"},
                {"key": "value", "label": catalog.metric_label(item.metric)},
            ],
            "rows": [{"label": f"{src.label}{catalog.metric_label(item.metric)}",
                      "value": float(value), "raw": None}],
            "total": float(value),
            "truncated": False,
            "sql": sql_text,
            "days": item.time.last_days,
            "filters": item.filters,
        }

    stmt = select(group_col.label("group_value"), metric_expr).select_from(src.model)
    stmt = _apply_filters(stmt, item, src)
    stmt = _apply_window(stmt, item, src)
    stmt = stmt.group_by(group_col)
    if item.group_by == "time_bucket":
        stmt = stmt.order_by(group_col.asc())
    else:
        order = metric_expr.desc() if item.order == "desc" else metric_expr.asc()
        stmt = stmt.order_by(order)
    stmt = stmt.limit(min(item.limit, catalog.MAX_LIMIT))
    sql_text = _compile_text(db, stmt)

    raw_rows = db.execute(stmt).all()
    names: dict[int, str] = {}
    if item.group_by == "device_id":
        ids = [int(row[0]) for row in raw_rows if str(row[0]).isdigit()]
        names = _device_names(db, ids)

    rows: list[dict[str, Any]] = []
    for raw, value in raw_rows:
        if item.group_by == "time_bucket":
            label = str(raw or "(未知时间)")
        elif item.group_by == "device_id":
            label = names.get(int(raw), f"设备#{raw}") if str(raw).isdigit() else str(raw)
        else:
            label = catalog.value_label(item.group_by, raw)
        rows.append({"label": label, "value": float(value or 0), "raw": raw})

    return {
        "source": src.key,
        "source_label": src.label,
        "group_by": item.group_by,
        "group_label": catalog.dim_label(item.group_by),
        "metric": item.metric,
        "metric_label": catalog.metric_label(item.metric),
        "columns": [
            {"key": "label", "label": catalog.dim_label(item.group_by)},
            {"key": "value", "label": catalog.metric_label(item.metric)},
        ],
        "rows": rows,
        "total": _scalar_total(db, item, src),
        "truncated": len(raw_rows) >= min(item.limit, catalog.MAX_LIMIT),
        "sql": sql_text,
        "days": item.time.last_days,
        "filters": item.filters,
    }
