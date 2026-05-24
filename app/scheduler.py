"""APScheduler glue. One async job per enabled connector at its configured cadence.

Clean shutdown is critical: SIGTERM must stop the scheduler before the event
loop closes, or APScheduler threads hang. We expose start/stop functions and
let FastAPI's lifespan handler call them.
"""
from __future__ import annotations

import logging

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.connectors import ALL_CONNECTORS
from app.runner import run_connector

log = logging.getLogger(__name__)

_scheduler: AsyncIOScheduler | None = None


def get_scheduler() -> AsyncIOScheduler:
    global _scheduler
    if _scheduler is None:
        _scheduler = AsyncIOScheduler()
    return _scheduler


def start_scheduler() -> AsyncIOScheduler:
    sched = get_scheduler()
    for cls in ALL_CONNECTORS:
        conn = cls()
        if not conn.enabled:
            log.info("[scheduler] %s disabled — skipping", conn.name)
            continue
        sched.add_job(
            _run_one,
            trigger=IntervalTrigger(minutes=conn.interval_minutes),
            args=[conn.name],
            id=f"feed:{conn.name}",
            name=conn.display_name,
            replace_existing=True,
            max_instances=1,
            coalesce=True,
        )
        log.info("[scheduler] scheduled %s every %d min", conn.name, conn.interval_minutes)
    sched.start()
    return sched


def stop_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        _scheduler.shutdown(wait=False)
        _scheduler = None
        log.info("[scheduler] stopped")


async def _run_one(connector_name: str) -> None:
    from app.connectors import get_connector
    conn = get_connector(connector_name)
    if conn is None:
        log.error("[scheduler] unknown connector: %s", connector_name)
        return
    await run_connector(conn)
