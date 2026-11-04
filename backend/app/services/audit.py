"""审计日志写入服务（所有写操作必须调用）。"""
from __future__ import annotations

import json
from typing import Any

from sqlalchemy.orm import Session

from app.models import OperationAudit


def write_audit(
    db: Session,
    op_type: str,
    *,
    operator: str = "system",
    role_code: str | None = None,
    target_type: str | None = None,
    target_id: str | int | None = None,
    content: dict[str, Any] | str | None = None,
    client_ip: str | None = None,
    commit: bool = False,
) -> OperationAudit:
    if isinstance(content, (dict, list)):
        content = json.dumps(content, ensure_ascii=False, default=str)
    row = OperationAudit(
        operator=operator,
        role_code=role_code,
        op_type=op_type,
        target_type=target_type,
        target_id=str(target_id) if target_id is not None else None,
        content=content,
        client_ip=client_ip,
    )
    db.add(row)
    db.flush()
    if commit:
        db.commit()
    return row
