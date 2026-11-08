"""人机对话 API：自然语言查询的唯一入口。

接口设计围绕「一次提问 = 一问一答两条消息」：

- ``POST /chat/ask``：提问，返回 answer + blocks + trace，并把两条消息落库；
- ``GET  /chat/sessions``：我的会话列表；
- ``GET  /chat/sessions/{id}``：回看某个会话的消息（刷新/换设备都能接上）；
- ``DELETE /chat/sessions/{id}``：删会话；
- ``GET  /chat/catalog``：能问什么（空态引导 + 推荐问法）。

权限用新加的 ``chat:ask``：它读的是跨模块数据（黑名单/告警/任务/日志），
不适合复用某个业务模块的权限点；审计写 ``CHAT_ASK``，把问题原文、路由、
DSL、耗时、返回行数都留痕，便于复盘"当时为什么给出这个结论"。
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok
from app.database import get_db
from app.deps import require_perms
from app.models import ChatMessage, ChatSession, SystemUser
from app.schemas import ChatAskIn, ChatAskOut, ChatMessageOut, ChatSessionOut
from app.services.audit import write_audit
from app.services.chat import catalog
from app.services.chat.pipeline import ask as ask_pipeline

router = APIRouter(tags=["人机对话"])

MAX_SESSIONS = 50
MAX_TITLE = 60


def _session_of(db: Session, user: SystemUser, session_id: int | None) -> ChatSession:
    """取会话；不属于当前用户一律当不存在，不泄露"有没有这个 id"。"""
    if session_id:
        row = (
            db.query(ChatSession)
            .filter(ChatSession.id == session_id, ChatSession.username == user.username)
            .first()
        )
        if row is None:
            raise BizError("会话不存在", code=404, http_status=404)
        return row
    row = ChatSession(username=user.username, title="新对话")
    db.add(row)
    db.flush()
    return row


@router.post("/chat/ask", response_model=None)
def ask(
    payload: ChatAskIn,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("chat:ask")),
):
    question = payload.question.strip()
    if not question:
        raise BizError("问题是空的")

    session = _session_of(db, user, payload.session_id)
    if session.title == "新对话":
        session.title = question[:MAX_TITLE]

    db.add(ChatMessage(session_id=session.id, role="user", content=question))
    db.flush()

    result = ask_pipeline(db, question, username=user.username)

    message = ChatMessage(
        session_id=session.id,
        role="assistant",
        content=result["answer"],
        blocks=result.get("blocks") or [],
        route=result.get("route"),
        dsl=result.get("dsl"),
        trace=result.get("trace"),
        elapsed_ms=int((result.get("trace") or {}).get("elapsed_ms") or 0),
    )
    db.add(message)
    session.message_count = int(session.message_count or 0) + 2
    db.flush()

    write_audit(
        db, "CHAT_ASK", operator=user.username, role_code=user.role_code,
        target_type="chat", target_id=session.id,
        content={
            "question": question[:500],
            "route": result.get("route"),
            "confidence": result.get("confidence"),
            "queries": len((result.get("trace") or {}).get("queries") or []),
            "elapsed_ms": message.elapsed_ms,
        },
        client_ip=client_ip(request),
    )
    db.commit()

    out = ChatAskOut(
        session_id=session.id,
        message_id=message.id,
        answer=result["answer"],
        blocks=result.get("blocks") or [],
        trace=result.get("trace") or {},
        suggestions=result.get("suggestions") or [],
        route=result.get("route") or "db",
    )
    return ok(out.model_dump(mode="json"))


@router.get("/chat/sessions")
def list_sessions(
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("chat:ask")),
):
    rows = (
        db.query(ChatSession)
        .filter(ChatSession.username == user.username)
        .order_by(ChatSession.updated_at.desc(), ChatSession.id.desc())
        .limit(MAX_SESSIONS)
        .all()
    )
    return ok([ChatSessionOut.model_validate(row).model_dump(mode="json") for row in rows])


@router.get("/chat/sessions/{session_id}")
def get_session(
    session_id: int,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("chat:ask")),
):
    session = _session_of(db, user, session_id)
    rows = (
        db.query(ChatMessage)
        .filter(ChatMessage.session_id == session.id)
        .order_by(ChatMessage.id.asc())
        .limit(200)
        .all()
    )
    return ok({
        "session": ChatSessionOut.model_validate(session).model_dump(mode="json"),
        "messages": [ChatMessageOut.model_validate(row).model_dump(mode="json") for row in rows],
    })


@router.delete("/chat/sessions/{session_id}")
def delete_session(
    session_id: int,
    request: Request,
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("chat:ask")),
):
    session = _session_of(db, user, session_id)
    db.query(ChatMessage).filter(ChatMessage.session_id == session.id).delete()
    db.delete(session)
    write_audit(
        db, "CHAT_SESSION_DELETE", operator=user.username, role_code=user.role_code,
        target_type="chat", target_id=session_id,
        content={"title": session.title}, client_ip=client_ip(request),
    )
    db.commit()
    return ok({"deleted": session_id})


@router.get("/chat/catalog")
def get_catalog(
    db: Session = Depends(get_db),
    user: SystemUser = Depends(require_perms("chat:ask")),
):
    """能力清单：数据源 / 维度 / 指标 + 推荐问法。空对话页用它做引导。"""
    return ok({"sources": catalog.catalog_payload(),
               "suggestions": list(catalog.SUGGESTIONS)})
