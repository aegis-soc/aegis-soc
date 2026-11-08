"""结论生成：把查询结果说成人话。

没有大模型可用，所以这里用「事实句 + 阈值判断句」的模板拼装。写法上有两条纪律：

1. **只说数据里有的**。每句都能回溯到某个 ``rows`` 里的数字，不生成任何
   模型式的推测；拿不准就只陈述事实、不评价。
2. **判断句带阈值**。集中度、升降、漏封都用固定阈值（≥50% 算集中、
   ±10% 算明显变化），阈值写进常量，谁都改得动、也谁都看得出依据。

将来接入 LLM 时只需要把 ``summarize`` 的返回值当"草稿"丢给模型润色，
这些模板仍然是有意义的兜底与事实校对基准。
"""
from __future__ import annotations

from typing import Any

from app.database import utcnow
from app.services.chat import catalog
from app.services.chat.dsl import DbItem, LogSpec

# 判断阈值：集中度、趋势变化、漏封提醒
CONCENTRATION_HIGH = 0.5          # 头部一项占比 ≥50% 视为高度集中
TREND_DELTA = 0.1                 # 前后半段变化 ≥10% 才说"上升/下降"
TOP_N_FOR_SHARE = 3


def _num(value: float | int) -> str:
    number = float(value or 0)
    if abs(number - round(number)) < 1e-9:
        return f"{int(round(number)):,}"
    return f"{number:,.1f}"


def _pct(part: float, whole: float) -> str:
    if not whole:
        return "0%"
    return f"{part / whole * 100:.0f}%"


def _range_text(days: int) -> str:
    return f"近 {days} 天"


def db_sentence(result: dict[str, Any], item: DbItem) -> str:
    rows = result.get("rows") or []
    head = f"{_range_text(item.time.last_days)}{result['source_label']}"
    if item.filters.get("status") == ["active"] and item.source == "ioc":
        head += "（已下发）"
    total = result.get("total")
    if not rows or (rows and rows[0]["value"] == 0 and len(rows) == 1 and not item.group_by):
        return f"{head}没有匹配的数据，换个条件或放宽时间范围再试。"

    if not item.group_by:
        return f"{head}共 {_num(rows[0]['value'])} {result['metric_label']}。"

    if item.group_by == "time_bucket":
        unit = "小时" if item.time.is_hourly else "天"
        now = utcnow()
        current = now.strftime("%Y-%m-%d %H:00") if item.time.is_hourly else now.strftime("%Y-%m-%d")
        # 当天/当时段的数据还没走完，算环比会得出"断崖下跌"的假结论，先剔掉
        partial = [row for row in rows if row["label"] == current]
        series = [row for row in rows if row["label"] != current] or rows
        values = [row["value"] for row in series]
        overall = sum(row["value"] for row in rows)
        half = max(1, len(values) // 2)
        first, second = sum(values[:half]), sum(values[half:])
        peak = max(rows, key=lambda row: row["value"])
        text = (f"{head}按{unit}分布，合计 {_num(overall)}，"
                f"峰值出现在 {peak['label']}（{_num(peak['value'])}）")
        if first and second:
            delta = (second - first) / first
            if delta >= TREND_DELTA:
                text += f"；后半段比前半段上升 {delta * 100:.0f}%，攻击/封禁节奏在加快"
            elif delta <= -TREND_DELTA:
                text += f"；后半段比前半段下降 {abs(delta) * 100:.0f}%，节奏在放缓"
            else:
                text += "；前后半段基本持平，没有明显突增"
        if partial:
            text += f"（{current} 这一{unit}尚未结束，未计入环比）"
        return text + "。"

    base = total if total else sum(row["value"] for row in rows)
    top = rows[0]
    parts = [f"{head}按{result['group_label']}统计，共 {_num(base)} 条"]
    if base:
        parts.append(f"最高的是 {top['label']}（{_num(top['value'])} 条，占 {_pct(top['value'], base)}）")
    if len(rows) > 1:
        parts.append(f"其次是 {rows[1]['label']}（{_num(rows[1]['value'])} 条）")
    text = "，".join(parts)
    if base and top["value"] / base >= CONCENTRATION_HIGH:
        text += f"。集中度很高，前 1 项就占了 {_pct(top['value'], base)}，优先从 {top['label']} 这条线查"
    elif len(rows) >= TOP_N_FOR_SHARE and base:
        top3 = sum(row["value"] for row in rows[:TOP_N_FOR_SHARE])
        text += f"。前 {TOP_N_FOR_SHARE} 项合计占 {_pct(top3, base)}，分布相对分散"
    return text + "。"


def log_sentence(result: dict[str, Any], spec: LogSpec) -> str:
    window = result.get("window") or {}
    fetched = result.get("fetched", 0)
    matched = result.get("matched", 0)
    rows = result.get("rows") or []
    action_text = {"pass": "未拦截/放行", "block": "已拦截", "any": "全部动作"}[spec.action]
    head = (f"{window.get('start', '')} 至 {window.get('end', '')} 扫描 "
            f"{fetched} 条三流日志（{result.get('query_desc', '')}），"
            f"其中「{action_text}」{matched} 条")
    if not matched:
        return head + "。这批日志里没有命中条件的记录——要么确实没有，要么是字段口径不匹配，可以先按「全部动作」再问一次对照。"

    if spec.group_by != "src_ip":
        top = rows[0] if rows else None
        text = head + f"，分布在 {len(rows)} 个{result['group_label']}"
        if top:
            text += f"，最多的是 {top['label']}（{int(top['value'])} 条）"
        return text + "。"

    ips = len(rows)
    blocked = [row for row in rows if row.get("blocked")]
    internal = [row for row in rows if row.get("internal")]
    unblocked = [row for row in rows if not row.get("blocked") and not row.get("internal")]
    parts = [head, f"涉及 {ips} 个源 IP"]
    if rows:
        parts.append(f"Top1 是 {rows[0]['label']}（{int(rows[0]['value'])} 条）")
    text = "，".join(parts)
    if unblocked:
        text += (f"。其中 {len(unblocked)} 个 IP 不在当前黑名单里（如 {unblocked[0]['label']}），"
                 "按「未拦截就该处置」的口径属于疑似漏封，建议核对策略阈值后补封")
    if blocked:
        text += f"；另有 {len(blocked)} 个已在黑名单，属处置生效但日志仍在流出"
    if internal:
        text += f"；{len(internal)} 个是内网/保留地址（如 {internal[0]['label']}），按设计不进黑名单，不计入漏封"
    return text + "。"


def clarify_sentence(reason: str) -> str:
    return reason or "没听懂这个问题，换个说法试试。"


def suggestions_for(intent_kind: str) -> list[str]:
    """按路由给不同的推荐问法：澄清时给宽口径，答完给「下一步」。"""
    pool = list(catalog.SUGGESTIONS)
    if intent_kind == "log":
        return ["改成看全部动作", "按规则统计一下", "只看 WAF", "换成按设备看"][:3]
    if intent_kind == "db":
        return ["近 30 天呢", "只看高危", "按省份看", "换成按天趋势"][:3]
    return pool[:4]
