"""口令哈希、JWT 签发与校验、口令强度策略。

优先使用 bcrypt；若运行环境缺少 bcrypt，则回退到标准库 scrypt，
并以 "{algo}${hash}" 前缀标识，验证时自动识别，保证哈希串向后兼容。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

from app.config import settings

_BCRYPT_PREFIX = "{bcrypt}"
_SCRYPT_PREFIX = "{scrypt}"

try:
    import bcrypt as _bcrypt
except ImportError:  # pragma: no cover - 仅在精简环境触发
    _bcrypt = None


def hash_password(password: str) -> str:
    if _bcrypt is not None:
        return _BCRYPT_PREFIX + _bcrypt.hashpw(password.encode("utf-8"), _bcrypt.gensalt()).decode("ascii")
    salt = os.urandom(16)
    derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return _SCRYPT_PREFIX + base64.b64encode(salt + derived).decode("ascii")


def verify_password(password: str, hashed: str) -> bool:
    try:
        if hashed.startswith(_BCRYPT_PREFIX):
            if _bcrypt is None:
                return False
            return _bcrypt.checkpw(password.encode("utf-8"), hashed[len(_BCRYPT_PREFIX):].encode("ascii"))
        if hashed.startswith(_SCRYPT_PREFIX):
            raw = base64.b64decode(hashed[len(_SCRYPT_PREFIX):].encode("ascii"))
            salt, expected = raw[:16], raw[16:]
            derived = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
            return hmac.compare_digest(derived, expected)
    except (ValueError, TypeError):
        return False
    return False


def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 8 or len(password) > 128:
        return False, "口令长度需为 8-128 位"
    checks = [
        (r"[a-z]", "小写字母"),
        (r"[A-Z]", "大写字母"),
        (r"\d", "数字"),
        (r"[^A-Za-z0-9]", "特殊字符"),
    ]
    missing = [label for pattern, label in checks if not re.search(pattern, password)]
    if len(missing) > 1:
        return False, "口令需包含大写字母、小写字母、数字、特殊字符中的至少三类"
    return True, ""


def create_access_token(subject: str, role_code: str, extra: dict[str, Any] | None = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role_code,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_expire_minutes),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_access_token(token: str) -> dict[str, Any]:
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
