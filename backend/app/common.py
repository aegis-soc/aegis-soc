"""统一响应格式、业务异常与全局异常处理。

所有接口返回：{"code": 0, "msg": "success", "data": ...}
code: 0 成功 / 400 参数非法 / 401 未认证 / 403 无权限或白名单拦截 / 404 不存在 / 500 内部异常
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session
from starlette.exceptions import HTTPException as StarletteHTTPException

logger = logging.getLogger("aegis")


class BizError(Exception):
    def __init__(self, msg: str, code: int = 400, http_status: int = 400):
        self.msg = msg
        self.code = code
        self.http_status = http_status
        super().__init__(msg)


def ok(data: Any = None, msg: str = "success") -> dict[str, Any]:
    return {"code": 0, "msg": msg, "data": data}


def fail(msg: str, code: int = 400, http_status: int = 400) -> JSONResponse:
    return JSONResponse(status_code=http_status, content={"code": code, "msg": msg, "data": None})


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def paginate(stmt: Select, db: Session, page: int, page_size: int) -> tuple[list[Any], int]:
    """对 Select 语句做分页，返回 (rows, total)。"""
    page = max(1, page)
    page_size = min(max(1, page_size), 200)
    count_stmt = select(func.count()).select_from(stmt.order_by(None).subquery())
    total = db.scalar(count_stmt) or 0
    rows = list(db.scalars(stmt.offset((page - 1) * page_size).limit(page_size)).all())
    return rows, total


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(BizError)
    async def _biz(_: Request, exc: BizError) -> JSONResponse:
        return fail(exc.msg, exc.code, exc.http_status)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = "; ".join(
            f"{'.'.join(str(x) for x in e.get('loc', []))}: {e.get('msg')}" for e in exc.errors()[:5]
        )
        return fail(f"参数校验失败: {details}", 400, 400)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code_map = {401: 401, 403: 403, 404: 404, 405: 405}
        return fail(str(exc.detail), code_map.get(exc.status_code, exc.status_code), exc.status_code)

    @app.exception_handler(Exception)
    async def _unhandled(_: Request, exc: Exception) -> JSONResponse:
        logger.exception("unhandled error: %s", exc)
        return fail("服务内部异常，请查看日志", 500, 500)
