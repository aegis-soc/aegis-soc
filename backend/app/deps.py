"""认证与 RBAC 依赖注入。"""
from __future__ import annotations

import json
import logging
from typing import Any

from fastapi import Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.common import BizError
from app.database import get_db
from app.models import SystemRole, SystemUser
from app.security import decode_access_token

logger = logging.getLogger("aegis")
bearer_scheme = HTTPBearer(auto_error=False)


def _permission_list(role: SystemRole | None) -> list[str]:
    if role is None:
        return []
    value: Any = role.permission_json
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except json.JSONDecodeError:
            return []
    return list(value) if isinstance(value, (list, tuple)) else []


def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer_scheme),
    db: Session = Depends(get_db),
) -> SystemUser:
    if credentials is None or not credentials.credentials:
        raise BizError("未提供登录凭证", 401, 401)
    try:
        payload = decode_access_token(credentials.credentials)
    except Exception:
        raise BizError("登录凭证无效或已过期", 401, 401)

    username = str(payload.get("sub") or "")
    user = db.query(SystemUser).filter(SystemUser.username == username).first()
    if user is None or user.status != 1:
        raise BizError("账号不存在或已禁用", 401, 401)
    return user


def require_perms(*required: str):
    """接口级权限校验，支持 "*" 全放行与 "ioc:*" 命名空间通配。"""

    def checker(
        user: SystemUser = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> SystemUser:
        if not required:
            return user
        role = db.query(SystemRole).filter(SystemRole.role_code == user.role_code).first()
        granted = _permission_list(role)
        if "*" in granted:
            return user
        for perm in required:
            if perm in granted:
                continue
            namespace = perm.split(":", 1)[0] + ":*"
            if namespace in granted:
                continue
            raise BizError(f"权限不足，需要 {perm}", 403, 403)
        return user

    return checker
