"""查询编排：一次提问从解析到出块的完整流程。

顺序刻意固定，每一步都能单独失败而不拖垮整条链路：

1. 限流（成本护栏，非安全边界）；
2. 规则解析 → ``Intent``（失败即澄清，不抛异常）；
3. 按路由走编译器（库 / 日志），单个子查询失败只丢这一块；
4. 生成结论与渲染块；
5. 返回 ``answer + blocks + trace``，前端按 block 类型渲染，不需要知道问法。

``trace`` 里带着编译后的 SQL / MCP 查询说明，回答底部折叠展示——这是
「让运营自己判断结论可不可信」的关键，也是出了问题能复盘的全部依据。
"""
from __future__ import annotations

import logging
import time
from typing import Any

from sqlalchemy.orm import Session

from app.cache import cache
from app.services.chat import catalog, narrative
from app.services.chat import compiler_db, compiler_log
from app.services.chat.compiler_log import LogQueryError
from app.services.chat.dsl import Intent
from app.services.chat.router_intent import safe_parse

logger = logging.getLogger("aegis")

RATE_LIMIT_PER_MINUTE = 20


def _rate_limited(username: str) -> bool:
    """按分钟桶计数。Redis 下非原子（并发可能多放几条），够用作成本护栏。"""
    if not username:
        return False
    bucket = int(time.time() // 60)
    key = f"aegis:chat:rl:{username}:{bucket}"
    try:
        used = int(cache.get(key) or 0)
        if used >= RATE_LIMIT_PER_MINUTE:
            return True
        cache.set(key, str(used + 1), ex=90)
    except Exception as exc:                # noqa: BLE001 - 限流故障不阻断提问
        logger.debug("限流计数失败：%s", exc)
    return False


def _kpi_block(results: list[dict[str, Any]]) -> dict[str, Any] | None:
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in results:
        if result.get("group_by"):
            total = result.get("total")
            if total is None:
                continue
            label = f"{result['source_label']}总数"
            value = total
        else:
            row = (result.get("rows") or [{}])[0]
            label = f"{result['source_label']}{result['metric_label']}"
            value = row.get("value", 0)
        # 一句话问三件事时三个 KPI 往往同值，重复堆着反而干扰判断
        if label in seen:
            continue
        seen.add(label)
        items.append({"label": label, "value": value})
    if not items:
        return None
    return {"type": "kpi", "title": "关键数字", "items": items}


def _result_blocks(result: dict[str, Any]) -> list[dict[str, Any]]:
    blocks: list[dict[str, Any]] = []
    rows = result.get("rows") or []
    if not rows:
        return blocks
    title = f"{result['source_label']} · 按{result['group_label']}" if result.get("group_by") \
        else f"{result['source_label']} · {result['metric_label']}"
    blocks.append({
        "type": "table",
        "title": title,
        "columns": result.get("columns", []),
        "rows": rows,
        "total": result.get("total"),
        "truncated": result.get("truncated", False),
    })
    # 柱图只在分组且条目不多时给：时间桶太多会糊成一团，交给表格
    if result.get("group_by") and result["group_by"] != "time_bucket" and len(rows) >= 2:
        blocks.append({
            "type": "bar",
            "title": title,
            "categories": [row["label"] for row in rows[:12]],
            "values": [row["value"] for row in rows[:12]],
            "metric_label": result.get("metric_label", "数量"),
        })
    return blocks


def _note_block(notes: list[str]) -> dict[str, Any] | None:
    if not notes:
        return None
    return {"type": "note", "title": "口径说明", "lines": notes}


def _trace(intent: Intent, results: list[dict[str, Any]], elapsed_ms: int) -> dict[str, Any]:
    return {
        "route": intent.route,
        "confidence": intent.confidence,
        "matched": intent.matched,
        "reason": intent.reason,
        "elapsed_ms": elapsed_ms,
        "queries": [
            {
                "source": result.get("source"),
                "group_by": result.get("group_by"),
                "limit": len(result.get("rows") or []),
                "sql": result.get("sql", ""),
                "query_desc": result.get("query_desc", ""),
                "fetched": result.get("fetched"),
                "matched": result.get("matched"),
                "window": result.get("window"),
                "stream_stats": result.get("stream_stats"),
            }
            for result in results
        ],
    }


def ask(db: Session, question: str, *, username: str = "") -> dict[str, Any]:
    """主入口。任何分支都返回同样结构的 dict，前端只需一套渲染逻辑。"""
    started = time.perf_counter()
    if _rate_limited(username):
        return {
            "answer": f"提问太频繁了（每分钟上限 {RATE_LIMIT_PER_MINUTE} 次），歇一下再问。",
            "blocks": [],
            "trace": {"route": "clarify", "elapsed_ms": 0},
            "suggestions": narrative.suggestions_for("clarify"),
            "assumptions": [],
            "route": "clarify",
            "dsl": None,
        }

    intent = safe_parse(question)
    if intent.route == "clarify":
        payload = {
            "answer": narrative.clarify_sentence(intent.reason),
            "blocks": [{"type": "note", "title": "可以这样问", "lines": list(catalog.SUGGESTIONS)}],
            "trace": {"route": "clarify", "reason": intent.reason, "elapsed_ms": 0},
            "suggestions": narrative.suggestions_for("clarify"),
            "assumptions": [],
            "route": "clarify",
            "dsl": {"route": "clarify", "reason": intent.reason},
        }
        payload["trace"]["elapsed_ms"] = int((time.perf_counter() - started) * 1000)
        return payload

    results: list[dict[str, Any]] = []
    errors: list[str] = []
    if intent.route == "db":
        for item in intent.items:
            try:
                results.append(compiler_db.run(db, item))
            except Exception as exc:        # noqa: BLE001 - 单块失败不拖垮整问
                logger.warning("自然语言查询失败（%s/%s）：%s", item.source, item.group_by, exc)
                label = catalog.source(item.source)
                errors.append(f"{label.label if label else item.source} 这一项查询失败：{str(exc)[:120]}")
    else:
        try:
            assert intent.log is not None
            results.append(compiler_log.run(db, intent.log))
        except LogQueryError as exc:
            errors.append(str(exc))
        except Exception as exc:            # noqa: BLE001
            logger.warning("日志查询异常：%s", exc)
            errors.append(f"日志查询异常：{str(exc)[:120]}")

    sentences: list[str] = []
    for index, result in enumerate(results):
        if result.get("source") == "log":
            assert intent.log is not None
            sentences.append(narrative.log_sentence(result, intent.log))
        else:
            item = intent.items[index] if index < len(intent.items) else intent.items[0]
            sentences.append(narrative.db_sentence(result, item))

    if sentences:
        answer = " ".join(sentences)
    elif errors:
        answer = "没查成：" + "；".join(errors)
    else:
        answer = "没有拿到结果，换个问法或稍后再试。"

    blocks: list[dict[str, Any]] = []
    kpi = _kpi_block(results)
    if kpi:
        blocks.append(kpi)
    for result in results:
        blocks.extend(_result_blocks(result))

    notes = list(intent.assumptions)
    for result in results:
        if result.get("source") == "log" and result.get("errors"):
            notes.append("部分流读取失败：" + "；".join(result["errors"][:2]))
        if result.get("truncated"):
            notes.append(f"{result['source_label']}结果按前 {len(result.get('rows') or [])} 条展示，不是全量")
    notes.extend(errors)
    note = _note_block(list(dict.fromkeys(notes)))
    if note:
        blocks.append(note)

    elapsed = int((time.perf_counter() - started) * 1000)
    return {
        "answer": answer,
        "blocks": blocks,
        "trace": _trace(intent, results, elapsed),
        "suggestions": narrative.suggestions_for(intent.route),
        "assumptions": intent.assumptions,
        "route": intent.route,
        "confidence": intent.confidence,
        "dsl": intent.model_dump(mode="json"),
    }
