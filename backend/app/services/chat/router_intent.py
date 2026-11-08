"""规则意图路由：中文问句 → ``dsl.Intent``，不依赖任何外部模型。

为什么规则优先而不是直接上大模型：

1. 现网还没有可用的模型接口，功能不能等；
2. 规则可穷举、可测试、可解释——出了错能定位到是哪条词表；
3. 自然语言查询里真正高频的就那十几种句式，规则覆盖率足够。

解析分五步，每步都很笨但都可验证：

1. 归一化（全角转半角、去空白、英文小写）；
2. 判数据源（日志类词优先，但要让「黑名单里的 WAF 来源」这类问法回到库）；
3. 抽槽位（时间窗、topN、维度、动作、流、过滤值）；
4. 补缺省（没给时间就 7 天，并写进 ``assumptions`` 如实告知）；
5. 打分（命中槽位越少越不敢下结论，低于阈值转 ``clarify``）。

规则永远只产出 ``catalog`` 里存在的维度/指标名，编译器的白名单再兜一道。
"""
from __future__ import annotations

import re
from typing import Any

from pydantic import ValidationError

from app.services.chat import catalog
from app.services.chat.dsl import DbItem, Intent, LogSpec, TimeRange, clarify

# ---------------------------------------------------------------- 词表

# 日志类词：出现就说明用户在问 Graylog，而不是问平台自己的统计表
LOG_WORDS = (
    "日志", "流量", "原始日志", "日志告警", "放行记录", "未拦截", "没拦截",
    "没有被拦截", "未阻断", "只告警", "仅告警", "放通",
)
# 黑名单类词：用来把「黑名单里的 WAF 来源」从日志路由里拉回来
IOC_WORDS = ("黑名单", "封禁名单", "封禁记录", "拦截记录", "ioc", "指标库", "封了多少")
STREAM_WORDS: dict[str, tuple[str, ...]] = {
    "IPS": ("ips", "入侵防御"),
    "WAF": ("waf", "web防护", "应用防火墙"),
    "ZTNA": ("ztna", "零信任"),
}
SOURCE_WORDS: dict[str, tuple[str, ...]] = {
    "ioc": IOC_WORDS,
    "task": ("下发", "封禁任务", "任务", "执行结果", "封禁量", "封了多少"),
    "alert": ("告警", "事件", "alert", "报警"),
    "device": ("设备", "探针", "资产"),
}
# 维度词：顺序即优先级，长词排前面（"国家" 要先于 "地区"）
DIM_WORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("geo_country", ("国家", "国籍", "哪国", "归属国", "country")),
    ("geo_province", ("省份", "各省", "哪省", "province")),
    ("geo_city", ("城市", "哪个城市", "city")),
    ("source_type", ("来源", "哪一路", "哪路", "上游系统", "source")),
    ("risk_level", ("风险等级", "风险", "危险等级", "risk")),
    ("ioc_type", ("指标类型", "ioc类型", "类型", "种类")),
    ("status", ("状态", "进展")),
    ("device_id", ("哪个设备", "哪台设备", "各设备", "设备维度")),
    ("plugin_code", ("插件", "哪个插件", "厂商适配")),
    ("vendor", ("厂商", "品牌")),
    ("region", ("区域", "地域")),
    ("severity", ("严重级别", "级别", "等级分布")),
    ("source_system", ("来源系统", "哪个系统")),
    ("task_status", ("任务状态",)),
    ("operation", ("操作类型",)),
    ("time_bucket", ("时间分布", "按时间", "top时间", "时间趋势", "按天", "按小时",
                     "每天", "每小时", "趋势", "走势", "变化")),
)
TREND_WORDS = ("趋势", "走势", "变化", "按天", "按小时", "每天", "每小时", "时间分布", "top时间")
DISTINCT_WORDS = ("去重", "多少个不同", "几个不同", "不同的")
COUNT_WORDS = ("多少", "几条", "数量", "统计", "计数", "总共", "一共", "合计")
# 「分布类」标记：只有出现这些词，维度词才当分组维度用；
# 否则「高风险的 IP 有多少」里的「风险」只是过滤条件，分组会让答案变成列表。
DISTRIBUTION_WORDS = ("分布", "排名", "top", "各", "每", "按", "榜", "占比", "最多", "最大", "最高")
PASS_WORDS = ("未拦截", "没拦截", "没有被拦截", "未阻断", "放行", "放通", "允许",
              "只告警", "仅告警", "pass", "allow")
BLOCK_WORDS = ("拦截", "阻断", "封堵", "拒绝", "deny", "block", "drop")
SEVERITY_WORDS: dict[int, tuple[str, ...]] = {
    5: ("严重", "critical", "致命"),
    4: ("高危", "高风险", "high"),
    3: ("中危", "medium"),
    2: ("低危", "low"),
}
# 状态词只在黑名单语境下当过滤条件用
STATUS_WORDS: dict[str, tuple[str, ...]] = {
    "active": ("已下发", "生效中", "正在封", "封禁中"),
    "expired": ("已到期", "过期", "已失效"),
    "disabled": ("已解封", "已移除"),
    "rejected": ("被拒绝", "校验拦截", "未下发成功"),
    "whitelisted": ("白名单",),
}

TIME_RE = re.compile(r"(?:最近|近|过去|前)\s*(\d+)\s*(?:个)?\s*(小时|天|日|周|星期|月)")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
TOP_RE = re.compile(r"top\s*(\d+)", re.I)
TOP_CN_RE = re.compile(r"(?:前|头|排名前)\s*(\d+)")
NUM_GENERIC_RE = re.compile(r"(\d+)\s*个")

FIXED_TIME: dict[str, tuple[int, str]] = {
    "今天": (1, "今天"), "今日": (1, "今天"),
    "昨天": (1, "昨天"), "昨日": (1, "昨天"),
    "本周": (7, "本周"), "这周": (7, "本周"), "本星期": (7, "本周"),
    "上周": (14, "上周"), "上星期": (14, "上周"),
    "本月": (30, "本月"), "这个月": (30, "本月"),
    "上个月": (60, "上个月"), "上月": (60, "上个月"),
}


def normalize(question: str) -> str:
    """全角转半角、压空白。中文不动，英文统一小写便于匹配 waf / top。"""
    chars: list[str] = []
    for ch in question or "":
        code = ord(ch)
        if code == 0x3000:
            chars.append(" ")
        elif 0xFF01 <= code <= 0xFF5E:      # 全角 ASCII 区
            chars.append(chr(code - 0xFEE0))
        else:
            chars.append(ch)
    text = "".join(chars)
    return re.sub(r"[ \t\u00a0]+", " ", text).strip()


def _hits(text: str, words: tuple[str, ...]) -> list[str]:
    return [word for word in words if word in text]


def _parse_time(text: str) -> tuple[TimeRange, list[str], bool]:
    """返回 (时间窗, 命中的时间词, 是否用户明确指定)。"""
    explicit = False
    days = catalog.DEFAULT_DAYS
    label = ""
    hit = TIME_RE.search(text)
    if hit:
        amount, unit = int(hit.group(1)), hit.group(2)
        days = {"小时": max(1, amount // 24), "天": amount, "日": amount,
                "周": amount * 7, "星期": amount * 7, "月": amount * 30}[unit]
        explicit = True
        label = hit.group(0)
    else:
        for word, (value, name) in FIXED_TIME.items():
            if word in text:
                days, explicit, label = value, True, name
                break
    days = max(1, min(days, 365))
    # 跨度 ≤ 2 天按小时更可读，其余按天；用户明说按小时/按天则以其为准
    bucket = "hour" if days <= 2 else "day"
    if "按小时" in text or "每小时" in text:
        bucket = "hour"
    elif "按天" in text or "每天" in text:
        bucket = "day"
    return TimeRange(last_days=days, bucket=bucket), ([label] if label else []), explicit


def _parse_limit(text: str) -> int | None:
    for pattern in (TOP_RE, TOP_CN_RE, NUM_GENERIC_RE):
        hit = pattern.search(text)
        if hit:
            return max(1, min(int(hit.group(1)), catalog.MAX_LIMIT))
    return None


def _parse_streams(text: str) -> list[str]:
    found = [name for name, words in STREAM_WORDS.items() if _hits(text, words)]
    return found or ["IPS", "WAF", "ZTNA"]


def _parse_action(text: str) -> str:
    # "未拦截" 里含 "拦截"，必须先判放行类词
    if _hits(text, PASS_WORDS):
        return "pass"
    if _hits(text, BLOCK_WORDS):
        return "block"
    return "any"


def _parse_severity(text: str) -> int:
    for level, words in SEVERITY_WORDS.items():
        if _hits(text, words):
            return level
    return 0


def _parse_dims(text: str) -> list[str]:
    """按词在句中的出现顺序返回维度：中文语序本身就是优先级，「来源 top10 和国家」先来源。"""
    found: list[tuple[int, str]] = []
    for dim, words in DIM_WORDS:
        positions = [text.find(word) for word in words if word in text]
        if positions:
            found.append((min(positions), dim))
    found.sort()
    dims = [dim for _, dim in found]
    # "趋势" 类词统一归到时间分桶，避免 item 里出现重复语义
    if any(word in text for word in TREND_WORDS) and "time_bucket" not in dims:
        dims.append("time_bucket")
    return dims


def _pick_source(text: str) -> str:
    """数据源判定：先按最强信号（封禁量→下发），再按命中词数。"""
    if _hits(text, ("封禁量", "封了多少", "下发量")) or (
        _hits(text, ("设备", "哪台")) and _hits(text, ("封禁", "下发", "任务"))
    ):
        return "task"
    scores = {key: len(_hits(text, words)) for key, words in SOURCE_WORDS.items()}
    best = max(scores, key=lambda k: scores[k])
    if scores[best] == 0:
        return "ioc"                        # 兜底：黑名单是最高频查询对象
    return best


def _parse_filters(text: str, source: str) -> tuple[dict[str, Any], list[str]]:
    src = catalog.source(source)
    filters: dict[str, Any] = {}
    matched: list[str] = []
    if src is None:
        return filters, matched

    for value, words in STATUS_WORDS.items():
        if _hits(text, words) and "status" in src.filters:
            filters["status"] = [value]
            matched.append(words[0])
            break
    # 默认只看生效中的黑名单：把已到期/已解封混进来，Top 榜就没有意义了
    if source == "ioc" and "status" not in filters:
        filters["status"] = ["active"]

    if "ioc_type" in src.filters:
        if _hits(text, ("域名", "domain")):
            filters["ioc_type"] = ["DOMAIN"]
        elif _hits(text, ("url", "网址")):
            filters["ioc_type"] = ["URL"]
        elif _hits(text, ("ip", "地址")):
            filters["ioc_type"] = ["IP"]

    if "risk_level" in src.filters:
        for value, words in (("high", ("高危", "高风险")), ("critical", ("严重",)),
                             ("medium", ("中危",)), ("low", ("低危",))):
            if _hits(text, words):
                filters["risk_level"] = [value]
                break

    ip = IP_RE.search(text)
    if ip and "keyword" in src.filters:
        filters["keyword"] = ip.group(0)
        matched.append(ip.group(0))

    for key in ("task_status", "operation", "severity", "source_system"):
        if key in src.filters:
            if key == "task_status" and _hits(text, ("失败", "失败率")):
                filters[key] = ["FAILED"]
            elif key == "task_status" and _hits(text, ("成功",)):
                filters[key] = ["SUCCESS"]
            elif key == "severity":
                level = _parse_severity(text)
                if level:
                    filters[key] = str(level)

    return filters, matched


def _log_group(text: str) -> str:
    if _hits(text, ("按规则", "哪条规则", "攻击类型", "规则")):
        return "rule"
    if _hits(text, ("按设备", "哪路", "哪个流", "按流")):
        return "stream"
    return "src_ip"


def parse(question: str) -> Intent:
    """主入口：问句 → Intent。任何异常都收敛成 ``clarify``，不让接口 500。"""
    raw = (question or "").strip()
    if not raw:
        return clarify("问题是空的，说说你想看什么？")
    if len(raw) > 300:
        return clarify("问题太长了，请压缩到 300 字以内再问一次。")

    text = normalize(raw)
    lower = text.lower()
    matched: list[str] = []
    assumptions: list[str] = []

    has_log_word = bool(_hits(lower, LOG_WORDS))
    has_ioc_word = bool(_hits(lower, IOC_WORDS))
    stream_hit = [name for name, words in STREAM_WORDS.items() if _hits(lower, words)]
    action = _parse_action(lower)
    bucket, time_words, explicit_time = _parse_time(lower)
    matched.extend(time_words)
    limit = _parse_limit(lower)

    log_like = has_log_word or (bool(stream_hit) and action != "any")
    # 黑名单语境优先回到库：「黑名单里 WAF 来源 top10」问的是平台统计，不是日志
    route = "db" if (has_ioc_word and not has_log_word) else ("log" if log_like else "db")

    if not explicit_time:
        assumptions.append(f"未指定时间范围，按近 {bucket.last_days} 天统计")

    if route == "log":
        requested_days = bucket.last_days        # LogSpec 会就地收紧，先记住用户原话
        spec = LogSpec(
            streams=stream_hit or _parse_streams(lower),
            time=bucket,
            action=action,
            severity_min=_parse_severity(lower),
            group_by=_log_group(lower),
            limit=limit or 50,
        )
        if action == "pass":
            matched.append("未拦截/放行")
        elif action == "block":
            matched.append("拦截")
        if requested_days > catalog.MAX_LOG_DAYS:
            assumptions.append(f"日志检索最多回看 {catalog.MAX_LOG_DAYS} 天，已收紧时间窗")
        confidence = min(0.95, 0.45 + 0.15 * len(matched) + (0.15 if stream_hit else 0))
        if action == "any" and not has_log_word:
            confidence = min(confidence, 0.5)
        return Intent(route="log", log=spec, assumptions=assumptions,
                      confidence=round(confidence, 2), matched=matched,
                      reason="检索三流日志")

    source = _pick_source(lower)
    src = catalog.source(source)
    assert src is not None
    raw_dims = _parse_dims(lower)
    if not _hits(lower, DISTRIBUTION_WORDS):
        # 没有分布/排名/各/按 之类标记时，维度词只做过滤，不应变成分组
        raw_dims = [dim for dim in raw_dims if dim == "time_bucket"]
    dims = [dim for dim in raw_dims if dim == "time_bucket" or dim in src.dims]
    if not dims and not _hits(lower, COUNT_WORDS) and not _hits(lower, IOC_WORDS + ("告警", "设备", "下发")):
        return clarify("没听懂要统计什么。可以换个说法，比如「黑名单 top 国家」。",
                       matched=matched)

    metric = "distinct_value" if _hits(lower, DISTINCT_WORDS) and "distinct_value" in src.metrics else "count"
    if _hits(lower, DISTINCT_WORDS):
        matched.append("去重")
    filters, filter_hits = _parse_filters(lower, source)
    matched.extend(filter_hits)
    matched.append(src.label)
    matched.extend(catalog.dim_label(dim) for dim in dims)

    # 「最大/最多/哪个」但不带具体数字时，只要冠军那一行
    if limit is None and _hits(lower, ("最大", "最多", "最高", "哪个")):
        limit = 1

    items: list[DbItem] = []
    for dim in dims or [None]:
        items.append(
            DbItem(
                source=source,
                metric=metric,
                group_by=dim,
                filters=filters,
                time=bucket,
                limit=(limit or (catalog.DEFAULT_LIMIT if dim else 1)),
                order="asc" if dim == "time_bucket" else "desc",
            )
        )

    confidence = min(0.95, 0.4 + 0.15 * len(matched) + (0.15 if dims else 0))
    return Intent(
        route="db",
        items=items,
        assumptions=assumptions,
        confidence=round(confidence, 2),
        matched=matched,
        reason=f"统计{src.label}",
    )


def safe_parse(question: str) -> Intent:
    """``parse`` 的防爆壳：DSL 校验失败说明规则拼出了非法组合，降级成澄清。"""
    try:
        return parse(question)
    except ValidationError as exc:
        first = exc.errors()[0] if exc.errors() else {}
        return clarify(f"这个问法超出了当前支持范围（{first.get('msg', '校验未通过')}）。")
    except Exception:                       # noqa: BLE001 - 路由不能拖垮接口
        return clarify("解析失败，请换个说法再试。")
