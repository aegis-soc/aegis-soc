"""人机对话：规则路由 12 条验收用例 + 编译白名单 + 落库与接口。

两条底线在这里被钉住：

1. **路由只产出白名单内的维度/指标**——非法组合在 DSL 校验就被拒，不会变成 SQL；
2. **编译器只生成 SELECT**——断言 SQL 以 ``SELECT`` 开头，且用户输入的 IP
   走的是绑定参数（出现在编译后的字面量里，但不是拼接进语句结构）。
"""
from __future__ import annotations

from datetime import timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import Session

from app.database import utcnow
from app.models import ChatMessage, ChatSession, IocIndicator
from app.services.chat import catalog
from app.services.chat import compiler_db, compiler_log
from app.services.chat.dsl import DbItem, Intent, LogSpec
from app.services.chat.pipeline import ask as ask_pipeline
from app.services.chat.router_intent import safe_parse
from app.database import Base
from tests.conftest import engine


@pytest.fixture
def db_ready():
    """只建表、不起 TestClient：编译器级测试直接在库上跑。"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield

# ---------------------------------------------------------------- 路由用例

ROUTE_CASES = [
    ("分析黑名单中来源top10或者top国家，top时间",
     "db", ["source_type", "geo_country", "time_bucket"]),
    ("最近3天再各个安全设备有未拦截的ip日志告警", "log", None),
    ("分析黑名单中来源 top10", "db", ["source_type"]),
    ("黑名单 top 国家分布", "db", ["geo_country"]),
    ("近 7 天封禁趋势", "db", ["time_bucket"]),
    ("近 7 天 WAF 拦截了多少条", "log", None),
    ("各省份黑名单数量", "db", ["geo_province"]),
    ("下发失败的任务有多少", "db", [None]),
    ("哪个设备封禁量最大", "db", ["device_id"]),
    ("高风险 IP 有多少", "db", [None]),
    ("帮我看看", "clarify", None),
    ("明天天气", "clarify", None),
]


@pytest.mark.parametrize("question,route,group_bys", ROUTE_CASES)
def test_router_cases(question: str, route: str, group_bys):
    intent = safe_parse(question)
    assert intent.route == route, f"{question} 被路由到 {intent.route}"
    if group_bys is not None:
        assert [item.group_by for item in intent.items] == group_bys


def test_router_time_and_limit():
    intent = safe_parse("最近3天各个安全设备有未拦截的ip日志告警")
    assert intent.log is not None
    assert intent.log.time.last_days == 3
    assert intent.log.action == "pass"
    assert intent.log.streams == ["IPS", "WAF", "ZTNA"]


def test_router_log_window_is_clamped():
    """日志检索最多回看 7 天：超了要收紧并如实写进 assumptions。"""
    intent = safe_parse("近 30 天 WAF 拦截了多少条")
    assert intent.log is not None
    assert intent.log.time.last_days == catalog.MAX_LOG_DAYS
    assert any("7 天" in item for item in intent.assumptions)


def test_router_defaults_are_declared():
    """没给时间范围就默认 7 天，且必须写在 assumptions 里，不能悄悄假设。"""
    intent = safe_parse("黑名单 top 国家分布")
    assert intent.items[0].time.last_days == catalog.DEFAULT_DAYS
    assert any("未指定时间范围" in item for item in intent.assumptions)


def test_router_high_risk_is_filter_not_group():
    """「高风险 IP 有多少」是计数，不是按风险等级分组。"""
    intent = safe_parse("高风险 IP 有多少")
    assert intent.items[0].group_by is None
    assert intent.items[0].filters.get("risk_level") == ["high"]


def test_router_ip_literal_becomes_filter():
    intent = safe_parse("黑名单里 45.33.7.9 是什么时候进来的")
    assert intent.items[0].filters.get("keyword") == "45.33.7.9"


# ---------------------------------------------------------------- 白名单

def test_dsl_rejects_unknown_source():
    with pytest.raises(ValidationError):
        DbItem(source="system_user")


def test_dsl_rejects_unknown_dimension():
    with pytest.raises(ValidationError):
        DbItem(source="ioc", group_by="password")


def test_dsl_rejects_unknown_filter():
    with pytest.raises(ValidationError):
        DbItem(source="ioc", filters={"mcp_token": "x"})


def test_dsl_clamps_items():
    """一句话最多 3 个子查询，多的直接截断，避免一次扫全库。"""
    items = [DbItem(source="ioc", group_by="source_type") for _ in range(5)]
    intent = Intent(route="db", items=items)
    assert len(intent.items) == catalog.MAX_ITEMS


def test_excluded_tables_are_not_sources():
    for table in catalog.EXCLUDED_TABLES:
        assert table not in catalog.SOURCES


# ---------------------------------------------------------------- 编译器

def _seed(db: Session, value: str, *, country: str = "美国", source: str = "IPS",
          days_ago: int = 1, status: str = "active") -> None:
    created = utcnow() - timedelta(days=days_ago)
    db.add(IocIndicator(
        ioc_type="IP", ioc_value=value, normalized_value=value, status=status,
        source_type=source, geo_country=country, source_count=1,
        created_at=created, updated_at=created,
    ))


def test_db_compiler_counts_by_country(db_ready):
    with Session(bind=engine) as db:
        _seed(db, "45.33.1.1", country="美国")
        _seed(db, "45.33.1.2", country="美国")
        _seed(db, "45.33.1.3", country="巴西")
        _seed(db, "45.33.1.4", country="巴西", status="expired")   # 已到期不计
        db.commit()

        item = DbItem(source="ioc", group_by="geo_country",
                      filters={"status": ["active"]}, limit=10)
        result = compiler_db.run(db, item)

    assert result["rows"][0]["label"] == "美国"
    assert result["rows"][0]["value"] == 2
    assert result["total"] == 3
    assert result["sql"].lstrip().upper().startswith("SELECT")


def test_db_compiler_never_emits_dml(db_ready):
    """任何 DSL 组合都只能生成 SELECT——这是「不让自然语言碰数据库」的硬底线。"""
    combos = [
        DbItem(source="ioc", group_by="source_type"),
        DbItem(source="alert", group_by="severity"),
        DbItem(source="task", group_by="device_id"),
        DbItem(source="device", group_by="vendor"),
        DbItem(source="ioc", metric="distinct_value", group_by="geo_country"),
    ]
    with Session(bind=engine) as db:
        for item in combos:
            sql = compiler_db.run(db, item)["sql"].strip().upper()
            assert sql.startswith("SELECT"), sql
            for word in ("DELETE", "UPDATE", "DROP", "INSERT ", "ALTER"):
                assert word not in sql


def test_db_compiler_keyword_filter_is_bound(db_ready):
    with Session(bind=engine) as db:
        _seed(db, "45.33.9.9")
        _seed(db, "45.33.9.10")
        db.commit()
        item = DbItem(source="ioc", filters={"keyword": "45.33.9.9"})
        result = compiler_db.run(db, item)
    assert result["rows"][0]["value"] == 1
    assert "45.33.9.9" in result["sql"]       # 只是编译后的字面量，不是结构拼接


def test_db_compiler_time_window_excludes_old(db_ready):
    with Session(bind=engine) as db:
        _seed(db, "45.33.2.1", days_ago=1)
        _seed(db, "45.33.2.2", days_ago=30)
        db.commit()
        result = compiler_db.run(db, DbItem(source="ioc", limit=1))
    assert result["rows"][0]["value"] == 1


# ---------------------------------------------------------------- 日志路径

def _fake_stream(records):
    def _inner(client, stream, start, end, limit, cfg=None):
        items = [dict(record, _stream=stream["name"]) for record in records]
        return items, {"name": stream["name"], "fetched": len(items), "error": ""}
    return _inner


def test_log_query_filters_pass_and_marks_blocked(monkeypatch, db_ready):
    records = [
        {"src_ip": "45.33.5.1", "action": "allow", "severity": "high", "timestamp": "2026-11-07T10:00:00Z"},
        {"src_ip": "45.33.5.1", "action": "permit", "severity": "high", "timestamp": "2026-11-07T11:00:00Z"},
        {"src_ip": "45.33.5.2", "action": "block", "severity": "high", "timestamp": "2026-11-07T12:00:00Z"},
    ]
    monkeypatch.setattr(compiler_log, "_fetch_stream", _fake_stream(records))
    with Session(bind=engine) as db:
        _seed(db, "45.33.5.1")          # 已在黑名单
        db.commit()
        result = compiler_log.run(db, LogSpec(action="pass", streams=["WAF"],
                                              time={"last_days": 3}, limit=10))
    assert result["matched"] == 2
    top = result["rows"][0]
    assert top["label"] == "45.33.5.1"
    assert top["blocked"] is True


def test_log_internal_ip_not_counted_as_gap(monkeypatch, db_ready):
    """内网地址出现在放行日志里是正常的（内部扫描/健康检查），不能算漏封。"""
    records = [
        {"src_ip": "10.20.30.40", "action": "allow", "severity": "high"},
        {"src_ip": "45.33.5.9", "action": "allow", "severity": "high"},
    ]
    monkeypatch.setattr(compiler_log, "_fetch_stream", _fake_stream(records))
    with Session(bind=engine) as db:
        spec = LogSpec(action="pass", streams=["IPS"], time={"last_days": 1}, limit=10)
        result = compiler_log.run(db, spec)
        flags = {row["label"]: row["internal"] for row in result["rows"]}
        answer = ask_pipeline(db, "最近 3 天各设备有未拦截的 IP 日志", username="tester")["answer"]
    assert flags["10.20.30.40"] is True
    assert flags["45.33.5.9"] is False
    assert "内网" in answer or "MCP" in answer


def test_log_query_raises_when_mcp_broken(monkeypatch):
    from app.services.patrol import McpError

    def _boom(*args, **kwargs):
        raise McpError("连接被拒绝")

    monkeypatch.setattr(compiler_log, "build_client", _boom)
    with Session(bind=engine) as db:
        with pytest.raises(compiler_log.LogQueryError):
            compiler_log.run(db, LogSpec(action="pass", time={"last_days": 1}))


def test_pipeline_degrades_when_log_fails(monkeypatch):
    """Graylog 挂了也要出人话，而不是 500。"""
    def _boom(*args, **kwargs):
        raise compiler_log.LogQueryError("Graylog MCP 未就绪：未配置地址")

    monkeypatch.setattr(compiler_log, "run", _boom)
    with Session(bind=engine) as db:
        out = ask_pipeline(db, "最近 3 天各设备有未拦截的 IP 日志", username="tester")
    assert "Graylog" in out["answer"]
    assert out["blocks"], "至少要给出口径说明"
    assert out["route"] == "log"


# ---------------------------------------------------------------- 结论

def test_answer_mentions_concentration(db_ready):
    with Session(bind=engine) as db:
        for index in range(3):
            _seed(db, f"45.33.6.{index}", country="美国")
        _seed(db, "45.33.6.9", country="巴西")
        db.commit()
        out = ask_pipeline(db, "黑名单 top 国家分布", username="tester")
    assert "美国" in out["answer"]
    assert "集中度" in out["answer"]
    assert any(block["type"] == "bar" for block in out["blocks"])


def test_clarify_gives_suggestions(db_ready):
    with Session(bind=engine) as db:
        out = ask_pipeline(db, "帮我看看", username="tester")
    assert out["route"] == "clarify"
    assert out["suggestions"]
    assert out["blocks"][0]["type"] == "note"


# ---------------------------------------------------------------- 接口与落库

def _ask(client, headers, question: str, session_id: int | None = None):
    payload = {"question": question}
    if session_id:
        payload["session_id"] = session_id
    return client.post("/api/v1/chat/ask", json=payload, headers=headers)


def test_ask_endpoint_persists_session(client, auth_headers):
    _seed_rows()
    first = _ask(client, auth_headers, "黑名单 top 国家分布")
    assert first.status_code == 200, first.text
    data = first.json()["data"]
    assert data["answer"]
    assert data["session_id"] > 0
    assert data["trace"]["route"] == "db"

    second = _ask(client, auth_headers, "各省份黑名单数量", data["session_id"])
    assert second.status_code == 200, second.text
    assert second.json()["data"]["session_id"] == data["session_id"]

    with Session(bind=engine) as db:
        session = db.get(ChatSession, data["session_id"])
        assert session is not None
        assert session.title == "黑名单 top 国家分布"
        assert session.message_count == 4
        messages = db.query(ChatMessage).filter_by(session_id=session.id).all()
        assert [row.role for row in messages] == ["user", "assistant", "user", "assistant"]
        assert messages[1].dsl and messages[1].dsl["route"] == "db"
        assert messages[1].blocks

    listing = client.get("/api/v1/chat/sessions", headers=auth_headers)
    assert listing.status_code == 200
    assert listing.json()["data"][0]["id"] == data["session_id"]

    detail = client.get(f"/api/v1/chat/sessions/{data['session_id']}", headers=auth_headers)
    assert detail.status_code == 200
    assert len(detail.json()["data"]["messages"]) == 4

    removed = client.delete(f"/api/v1/chat/sessions/{data['session_id']}", headers=auth_headers)
    assert removed.status_code == 200


def _seed_rows() -> None:
    with Session(bind=engine) as db:
        _seed(db, "45.33.8.1", country="美国", source="IPS")
        _seed(db, "45.33.8.2", country="美国", source="WAF")
        _seed(db, "45.33.8.3", country="巴西", source="WAF")
        db.commit()


def test_audit_written(client, auth_headers):
    _seed_rows()
    assert _ask(client, auth_headers, "黑名单 top 国家分布").status_code == 200
    logs = client.get("/api/v1/audit?page=1&page_size=20", headers=auth_headers)
    assert logs.status_code == 200
    items = logs.json()["data"]["items"]
    assert any(row.get("op_type") == "CHAT_ASK" for row in items)


def test_catalog_endpoint(client, auth_headers):
    response = client.get("/api/v1/chat/catalog", headers=auth_headers)
    assert response.status_code == 200
    data = response.json()["data"]
    assert {item["key"] for item in data["sources"]} >= {"ioc", "alert", "task", "device"}
    assert data["suggestions"]


def test_empty_question_rejected(client, auth_headers):
    response = client.post("/api/v1/chat/ask", json={"question": "   "}, headers=auth_headers)
    assert response.status_code == 400
