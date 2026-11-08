"""语义目录：把「人能说的话」锚定到有限的数据源 / 维度 / 指标集合。

三个用途，缺一不可：

1. ``router_intent`` 的词表来源——说哪些词能落到哪个维度；
2. ``compiler_db`` 的列映射白名单——模型属性名只在本文件出现，其他地方
   拿到的都是 ``geo_country`` 这类逻辑维度名，写不出 ``IocIndicator.xxx``；
3. ``narrative`` 的展示名——列名翻中文，前端不用自己维护翻译表。

**本文件不含任何 SQL**。新增一种问法通常只加几个词条，不动编译逻辑；
要新增数据源/维度才需要改这里，且改动会立刻受 ``compiler_db`` 的白名单约束。

安全边界也在这里定义：``EXCLUDED_TABLES`` 明确列出永不允许作为数据源的表
（账号口令、MCP Token、审计详情），避免「以后有人顺手加个数据源」把
敏感表接进自然语言查询。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.models import (
    AlertEvent,
    DeviceTask,
    IocIndicator,
    SecurityDevice,
)


@dataclass(frozen=True)
class Source:
    """一个可查询的数据源：表 + 维度 + 指标 + 过滤项，全部是逻辑名。"""

    key: str
    label: str
    model: Any
    time_attr: str
    dims: dict[str, str]                      # 逻辑维度 -> 模型属性名
    metrics: tuple[str, ...]
    filters: dict[str, str] = field(default_factory=dict)   # 逻辑过滤项 -> 模型属性名
    # 维度取值需要额外查名字（如 device_id -> 设备名），单独标记
    lookup: str = ""


SOURCES: dict[str, Source] = {
    "ioc": Source(
        key="ioc",
        label="黑名单",
        model=IocIndicator,
        time_attr="created_at",
        dims={
            "source_type": "source_type",
            "geo_country": "geo_country",
            "geo_province": "geo_province",
            "geo_city": "geo_city",
            "ioc_type": "ioc_type",
            "status": "status",
            "risk_level": "risk_level",
            "ioc_value": "normalized_value",
        },
        metrics=("count", "distinct_value", "avg_confidence"),
        filters={
            "status": "status",
            "source_type": "source_type",
            "ioc_type": "ioc_type",
            "risk_level": "risk_level",
            "geo_country": "geo_country",
            "keyword": "normalized_value",
        },
    ),
    "alert": Source(
        key="alert",
        label="告警",
        model=AlertEvent,
        time_attr="received_at",
        dims={
            "source_system": "source_system",
            "severity": "severity",
            "status": "status",
            "dedupe_key": "dedupe_key",
        },
        metrics=("count", "distinct_value"),
        filters={"status": "status", "severity": "severity", "source_system": "source_system"},
    ),
    "task": Source(
        key="task",
        label="封禁下发",
        model=DeviceTask,
        time_attr="created_at",
        dims={
            "device_id": "device_id",
            "task_status": "task_status",
            "plugin_code": "plugin_code",
            "operation": "operation",
            "ioc_type": "ioc_type",
        },
        metrics=("count", "distinct_value"),
        filters={
            "task_status": "task_status",
            "operation": "operation",
            "plugin_code": "plugin_code",
            "ioc_type": "ioc_type",
        },
        lookup="device",
    ),
    "device": Source(
        key="device",
        label="设备",
        model=SecurityDevice,
        time_attr="created_at",
        dims={
            "vendor": "vendor",
            "status": "status",
            "region": "region",
            "plugin_code": "plugin_code",
        },
        metrics=("count",),
        filters={"status": "status", "vendor": "vendor"},
    ),
}

# 逻辑维度 -> 展示名。跨数据源共用，值相同就共用一套文案。
DIM_LABELS: dict[str, str] = {
    "source_type": "来源",
    "geo_country": "国家",
    "geo_province": "省份",
    "geo_city": "城市",
    "ioc_type": "指标类型",
    "status": "状态",
    "risk_level": "风险等级",
    "ioc_value": "指标值",
    "source_system": "来源系统",
    "severity": "严重级别",
    "dedupe_key": "去重键",
    "device_id": "设备",
    "task_status": "任务状态",
    "plugin_code": "插件",
    "operation": "操作",
    "vendor": "厂商",
    "region": "区域",
    "time_bucket": "时间",
}

METRIC_LABELS: dict[str, str] = {
    "count": "数量",
    "distinct_value": "去重值数",
    "avg_confidence": "平均置信度",
}

# 枚举值中文名：只用于展示，不参与过滤校验（库里可能还有别的值）
VALUE_LABELS: dict[str, dict[str, str]] = {
    "status": {
        "active": "已下发", "rejected": "校验拦截", "whitelisted": "白名单",
        "expired": "已到期", "disabled": "已解封",
        "pending": "待处理", "processing": "处理中", "blocked": "已封禁",
        "ignored": "已忽略", "failed": "失败", "success": "成功",
        "unknown": "未知", "online": "在线", "offline": "离线",
    },
    "task_status": {
        "PENDING": "待执行", "RUNNING": "执行中", "SUCCESS": "成功",
        "FAILED": "失败", "EXPIRED": "已过期", "CANCELED": "已取消",
    },
    "operation": {"BLOCK": "封禁", "UNBLOCK": "解封", "QUERY": "查询"},
    "ioc_type": {"IP": "IP", "DOMAIN": "域名", "URL": "URL", "HASH": "哈希"},
    "risk_level": {"high": "高危", "medium": "中危", "low": "低危", "critical": "严重"},
    "source_type": {
        "IPS": "IPS", "WAF": "WAF", "ZTNA": "零信任", "TI": "情报",
        "AV": "防病毒", "FW": "防火墙", "NTA": "流量分析",
        "GRAYLOG": "Graylog", "MANUAL": "手工", "API": "接口", "UNKNOWN": "未知",
    },
}

# 永不允许作为自然语言查询数据源的表：口令、Token、审计详情
EXCLUDED_TABLES: tuple[str, ...] = (
    "system_user", "system_role", "patrol_setting", "operation_audit",
    "approval_record", "workflow_definition",
)

# 硬上限：任何问法都不能突破
MAX_LIMIT = 200
MAX_ITEMS = 3
MAX_LOG_DAYS = 7
DEFAULT_DAYS = 7
DEFAULT_LIMIT = 10
QUERY_TIMEOUT_MS = 10_000


def source(key: str) -> Source | None:
    return SOURCES.get((key or "").strip().lower())


def dim_label(dim: str) -> str:
    return DIM_LABELS.get(dim, dim)


def metric_label(metric: str) -> str:
    return METRIC_LABELS.get(metric, metric)


def value_label(dim: str, value: Any) -> str:
    """枚举值翻中文；没有映射就原样返回（不猜、不丢数据）。"""
    text = "" if value is None else str(value)
    table = VALUE_LABELS.get(dim)
    if not table:
        return text or "(空)"
    return table.get(text, table.get(text.upper(), text)) or "(空)"


def catalog_payload() -> list[dict[str, Any]]:
    """给前端/文档用的能力清单：能问什么，一目了然。"""
    return [
        {
            "key": item.key,
            "label": item.label,
            "dims": [
                {"key": dim, "label": dim_label(dim)} for dim in item.dims
            ],
            "metrics": [
                {"key": metric, "label": metric_label(metric)} for metric in item.metrics
            ],
        }
        for item in SOURCES.values()
    ]


# 推荐问法：既是空态引导，也是 clarify 时的兜底选项。
# 刻意都用 P0 规则能覆盖的句式——推荐了却答不上来最伤信任。
SUGGESTIONS: tuple[str, ...] = (
    "分析黑名单中来源 top10",
    "黑名单 top 国家分布",
    "近 7 天封禁趋势",
    "最近 3 天各设备有未拦截的 IP 日志",
    "近 7 天 WAF 拦截了多少条",
    "各省份黑名单数量",
    "下发失败的任务有多少",
    "哪个设备封禁量最大",
)
