"""宙斯盾 AegisSoc FastAPI 入口。"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.orm import Session

from app import __version__
from app.api.v1.router import api_router
from app.bootstrap import run_bootstrap
from app.cache import cache
from app.common import ok, register_exception_handlers
from app.config import settings
from app.database import get_db

logging.basicConfig(
    level=getattr(logging, settings.log_level.upper(), logging.INFO),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("aegis")


@asynccontextmanager
async def lifespan(_: FastAPI):
    logger.info("宙斯盾 AegisSoc v%s 启动，环境=%s，缓存=%s", __version__, settings.app_env, cache.mode)
    run_bootstrap()
    yield
    logger.info("宙斯盾 AegisSoc 已停止")


app = FastAPI(
    title="宙斯盾 AegisSoc API",
    description="通用安全运营自动化 AI+SOC 平台：告警接入 · IOC 管理 · 插件化设备联动 · 异步任务 · 全链路审计 · AI 巡检扩展",
    version=__version__,
    docs_url="/api/docs",
    redoc_url=None,
    openapi_url="/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)
register_exception_handlers(app)
app.include_router(api_router)


@app.get("/api/healthz", tags=["健康检查"], include_in_schema=False)
def healthz(db: Session = Depends(get_db)):
    db.execute(text("SELECT 1"))
    return ok(
        {
            "status": "healthy",
            "version": __version__,
            "database": "sqlite" if settings.is_sqlite else "mysql",
            "cache": cache.mode,
            "kill_switch": cache.kill_switch,
        }
    )
