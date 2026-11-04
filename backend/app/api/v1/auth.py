"""认证接口：登录、改密、当前用户。"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.common import BizError, client_ip, ok
from app.config import settings
from app.database import get_db, utcnow
from app.deps import get_current_user
from app.models import SystemUser
from app.schemas import LoginIn, PasswordChangeIn, TokenOut, UserOut
from app.security import create_access_token, hash_password, validate_password_strength, verify_password
from app.services.audit import write_audit

router = APIRouter(prefix="/auth", tags=["认证"])


@router.post("/login")
def login(body: LoginIn, request: Request, db: Session = Depends(get_db)):
    user = db.query(SystemUser).filter(SystemUser.username == body.username).first()
    if user is None or not verify_password(body.password, user.password_hash):
        raise BizError("用户名或密码错误", 401, 401)
    if user.status != 1:
        raise BizError("账号已禁用", 403, 403)

    user.last_login_at = utcnow()
    token = create_access_token(user.username, user.role_code)
    write_audit(
        db, "USER_LOGIN", operator=user.username, role_code=user.role_code,
        target_type="user", target_id=user.id, content={"result": "success"},
        client_ip=client_ip(request),
    )
    db.commit()
    return ok(
        TokenOut(
            access_token=token,
            expires_in=settings.jwt_expire_minutes * 60,
            must_change_password=bool(user.must_change_password),
            role_code=user.role_code,
        ).model_dump()
    )


@router.post("/password/change")
def change_password(
    body: PasswordChangeIn,
    request: Request,
    user: SystemUser = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(body.old_password, user.password_hash):
        raise BizError("原口令不正确", 400, 400)
    valid, message = validate_password_strength(body.new_password)
    if not valid:
        raise BizError(message, 400, 400)
    user.password_hash = hash_password(body.new_password)
    user.must_change_password = 0
    write_audit(
        db, "USER_CHANGE_PASSWORD", operator=user.username, role_code=user.role_code,
        target_type="user", target_id=user.id, client_ip=client_ip(request),
    )
    db.commit()
    return ok({"username": user.username, "must_change_password": False})


@router.get("/me")
def me(user: SystemUser = Depends(get_current_user)):
    return ok(UserOut.model_validate(user).model_dump(mode="json"))
