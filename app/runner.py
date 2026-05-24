"""Runs a single connector end-to-end: fetch → ingest → record FeedRun."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.connectors.base import BaseConnector
from app.db.ingest import ingest_batch
from app.db.models import FeedRun
from app.db.session import session_scope

log = logging.getLogger(__name__)


async def run_connector(connector: BaseConnector) -> dict:
    """Execute one connector cycle. NEVER raises — returns a stats dict."""
    started_at = datetime.now(timezone.utc)
    feed_run_id: int | None = None

    with session_scope() as session:
        fr = FeedRun(connector_name=connector.name, started_at=started_at, status="running")
        session.add(fr)
        session.flush()
        feed_run_id = fr.id

    pulled = stored = updated = skipped = errs = 0
    error_msg: str | None = None
    try:
        raws = await connector.fetch()
        pulled = len(raws)
        with session_scope() as session:
            stats = ingest_batch(session, raws)
        stored = stats.stored
        updated = stats.updated
        skipped = stats.skipped_low_score
        errs = stats.errors
        status = "success"
    except Exception as e:  # noqa: BLE001 — top-level safety net
        log.exception("[runner] %s crashed: %s", connector.name, e)
        error_msg = str(e)[:1000]
        status = "error"

    with session_scope() as session:
        row = session.get(FeedRun, feed_run_id)
        if row is not None:
            row.finished_at = datetime.now(timezone.utc)
            row.iocs_pulled = pulled
            row.iocs_stored = stored
            row.errors = error_msg
            row.status = status

    log.info(
        "[runner] %s: pulled=%d stored=%d updated=%d skipped=%d errors=%d status=%s",
        connector.name, pulled, stored, updated, skipped, errs, status,
    )
    return {
        "connector": connector.name,
        "pulled": pulled,
        "stored": stored,
        "updated": updated,
        "skipped_low_score": skipped,
        "errors": errs,
        "status": status,
        "error_message": error_msg,
    }
