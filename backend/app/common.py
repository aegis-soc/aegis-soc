"""统一响应格式、业务异常与全局异常处理。

所有接口返回：{"code": 0, "msg": "success", "data": ...}
code: 0 成功 / 400 参数非法 / 401 未认证 / 403 无权限或白名单拦截 / 404 不存在 / 500 内部异常
"""
from __future__ import annotations

import ipaddress
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


def source_ip(request: Request) -> str:
    """用于访问控制的来源 IP：只信本机/私网反代传来的 ``X-Real-IP``。

    和 :func:`client_ip` 的区别在这里——审计日志记错一个 IP 只是难看，
    白名单判错一个 IP 就是"谁都能伪造告警"或"真告警全被挡"。所以：
    直连对端是公网地址时用它自己的地址，``X-Real-IP`` 一律不认（那是客户端
    自己写的）；只有对端是 Docker 网段/回环（也就是我们的 nginx）时才取
    ``X-Real-IP``，nginx 里该头由 ``$remote_addr`` 覆盖写入，客户端改不了。
    """
    peer = request.client.host if request.client else ""
    real = (request.headers.get("x-real-ip") or "").strip()
    if real and (not peer or _is_local_peer(peer)):
        return real
    return peer or "unknown"


def _is_local_peer(peer: str) -> bool:
    try:
        return ipaddress.ip_address(peer).is_private
    except ValueError:
        # 非 IP 字面量（容器名、测试客户端的 "testclient"）只可能来自本机链路
        return True


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
