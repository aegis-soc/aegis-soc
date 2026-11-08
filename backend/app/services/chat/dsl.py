"""DSL 数据模型：意图路由的**唯一**合法输出格式。

为什么要有这一层：路由层（规则，将来也可能加 LLM）输出的东西必须先过
Pydantic + 白名单校验，才允许进编译器。这样即使将来接了大模型、它幻觉出
``source=system_user`` 或 ``group_by=password``，也会在编译前被拒掉，而
不是变成一条真实的 SQL。

约束分三类：
- 枚举白名单：数据源 / 维度 / 指标只能取自 ``catalog``；
- 数值区间：``limit`` ≤ 200、时间窗 ≤ 7 天（日志）/ 365 天（库）；
- 结构：一个问句最多 3 个子查询，避免「一句话扫全库」。
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from app.services.chat import catalog

Route = Literal["db", "log", "clarify"]


class TimeRange(BaseModel):
    """时间窗。``bucket`` 是时间分桶粒度，由编译器按跨度决定，不由用户说。"""

    last_days: int = Field(default=catalog.DEFAULT_DAYS, ge=1, le=365)
    bucket: Literal["hour", "day"] = "day"

    @property
    def is_hourly(self) -> bool:
        return self.bucket == "hour"


class DbItem(BaseModel):
    """一个数据库聚合子查询：对 ``source`` 按 ``group_by`` 分组统计 ``metric``。"""

    source: str
    metric: str = "count"
    group_by: str | None = None
    filters: dict[str, Any] = Field(default_factory=dict)
    time: TimeRange = Field(default_factory=TimeRange)
    limit: int = Field(default=catalog.DEFAULT_LIMIT, ge=1, le=catalog.MAX_LIMIT)
    order: Literal["desc", "asc"] = "desc"

    @field_validator("source")
    @classmethod
    def _check_source(cls, value: str) -> str:
        key = (value or "").strip().lower()
        if catalog.source(key) is None:
            raise ValueError(f"不支持的数据源：{value}")
        return key

    @model_validator(mode="after")
    def _check_members(self) -> "DbItem":
        src = catalog.source(self.source)
        assert src is not None                     # 上面的 validator 已保证
        if self.group_by not in (None, "time_bucket") and self.group_by not in src.dims:
            raise ValueError(f"{src.label} 不支持按 {self.group_by} 分组")
        if self.metric not in src.metrics:
            raise ValueError(f"{src.label} 不支持指标 {self.metric}")
        unknown = [key for key in self.filters if key not in src.filters]
        if unknown:
            raise ValueError(f"{src.label} 不支持过滤项：{', '.join(unknown)}")
        return self


class LogSpec(BaseModel):
    """一次 Graylog 三流检索。字段条件在抓取后按别名归一，再在内存里过滤。"""

    streams: list[str] = Field(default_factory=list)
    time: TimeRange = Field(default_factory=TimeRange)
    action: Literal["pass", "block", "any"] = "any"
    severity_min: int = Field(default=0, ge=0, le=5)
    group_by: Literal["src_ip", "rule", "stream"] = "src_ip"
    limit: int = Field(default=50, ge=1, le=catalog.MAX_LIMIT)
    keyword: str = Field(default="", max_length=64)

    @model_validator(mode="after")
    def _clamp_window(self) -> "LogSpec":
        # 日志检索比查库贵得多：时间窗硬限制，超了直接收紧并如实告知
        if self.time.last_days > catalog.MAX_LOG_DAYS:
            self.time.last_days = catalog.MAX_LOG_DAYS
        return self


class Intent(BaseModel):
    """路由结果。``clarify`` 时 items/log 为空，``reason`` 说明为什么没懂。"""

    route: Route
    items: list[DbItem] = Field(default_factory=list)
    log: LogSpec | None = None
    assumptions: list[str] = Field(default_factory=list)
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    matched: list[str] = Field(default_factory=list)
    reason: str = ""

    @model_validator(mode="after")
    def _check_shape(self) -> "Intent":
        if len(self.items) > catalog.MAX_ITEMS:
            self.items = self.items[: catalog.MAX_ITEMS]
        if self.route == "db" and not self.items:
            raise ValueError("db 路由至少需要一个子查询")
        if self.route == "log" and self.log is None:
            raise ValueError("log 路由缺少日志检索参数")
        return self


def clarify(reason: str, *, matched: list[str] | None = None) -> Intent:
    """听懂不了就明说，并给出可执行的方向，绝不去猜。"""
    return Intent(route="clarify", reason=reason, matched=matched or [], confidence=0.0)
