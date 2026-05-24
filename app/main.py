"""FastAPI entrypoint.

Lifespan:
  startup → init DB, start scheduler
  shutdown → stop scheduler (clean SIGTERM handling)
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.routes import router
from app.config import PROJECT_ROOT, setup_logging
from app.db.session import init_db
from app.scheduler import start_scheduler, stop_scheduler

setup_logging()
log = logging.getLogger(__name__)

WEB_DIR = PROJECT_ROOT / "app" / "web"
STATIC_DIR = WEB_DIR / "static"
TEMPLATES_DIR = WEB_DIR / "templates"


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Starting CTI Aggregator")
    init_db()
    sched = start_scheduler()
    app.state.scheduler = sched
    try:
        yield
    finally:
        log.info("Shutting down CTI Aggregator")
        stop_scheduler()


def create_app() -> FastAPI:
    app = FastAPI(title="CTI Aggregator", lifespan=lifespan)
    app.state.templates = Jinja2Templates(directory=str(TEMPLATES_DIR))
    if STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
    app.include_router(router)
    return app


app = create_app()
