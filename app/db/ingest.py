"""IOC ingestion pipeline.

Given a list of RawIOC from a connector, this:
  1. Scores each IOC for relevance.
  2. Drops anything below the configured threshold (logged, not stored).
  3. Upserts on (type, value) — same IOC from new feed appends a new source row.
  4. Records the full scoring breakdown in `scoring_reasons` (audit trail).
  5. Returns counts for the FeedRun record.

This module is the single chokepoint for writes — connectors never touch the DB.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import get_settings
from app.connectors.base import RawIOC
from app.db.models import IOC, IOCSource, IOCTag, ScoringReason
from app.scoring.relevance import score_ioc

log = logging.getLogger(__name__)


@dataclass
class IngestStats:
    pulled: int = 0
    stored: int = 0
    updated: int = 0
    skipped_low_score: int = 0
    errors: int = 0


def ingest_batch(session: Session, raws: list[RawIOC]) -> IngestStats:
    stats = IngestStats(pulled=len(raws))
    threshold = get_settings().relevance_score_threshold

    for raw in raws:
        try:
            score, reasons = score_ioc(raw)
            if score < threshold:
                stats.skipped_low_score += 1
                log.debug(
                    "[ingest] skip %s=%s score=%d < %d (source=%s)",
                    raw.type, raw.value, score, threshold, raw.source,
                )
                continue

            existing = session.execute(
                select(IOC).where(IOC.type == raw.type, IOC.value == raw.value)
            ).scalar_one_or_none()

            if existing is None:
                ioc = IOC(
                    type=raw.type,
                    value=raw.value,
                    first_seen=raw.first_seen or datetime.now(timezone.utc),
                    last_seen=raw.last_seen or datetime.now(timezone.utc),
                    relevance_score=score,
                    status="active",
                    threat_actor=raw.threat_actor,
                    malware_family=raw.malware_family,
                    cve=raw.cve,
                )
                session.add(ioc)
                session.flush()  # populate ioc.id
                _add_tags(session, ioc, raw.tags)
                _add_reasons(session, ioc, reasons)
                stats.stored += 1
            else:
                existing.last_seen = raw.last_seen or datetime.now(timezone.utc)
                if score > existing.relevance_score:
                    existing.relevance_score = score
                    # Replace reasons with the higher-score reasons.
                    for r in list(existing.reasons):
                        session.delete(r)
                    _add_reasons(session, existing, reasons)
                if raw.threat_actor and not existing.threat_actor:
                    existing.threat_actor = raw.threat_actor
                if raw.malware_family and not existing.malware_family:
                    existing.malware_family = raw.malware_family
                if raw.cve and not existing.cve:
                    existing.cve = raw.cve
                _add_tags(session, existing, raw.tags)
                stats.updated += 1
                ioc = existing

            session.add(
                IOCSource(
                    ioc_id=ioc.id,
                    source_name=raw.source,
                    source_url=raw.source_url,
                    raw_context=(raw.raw_context or "")[:8192],
                    ingested_at=datetime.now(timezone.utc),
                )
            )
        except Exception as e:  # noqa: BLE001
            stats.errors += 1
            log.exception("[ingest] failed for %s=%s: %s", raw.type, raw.value, e)

    return stats


def _add_tags(session: Session, ioc: IOC, tags: list[str]) -> None:
    # Check BOTH the DB and the session's pending-INSERT buffer for existing
    # rows — within a single ingest_batch we may queue many tag inserts before
    # any flush, so the DB query alone misses uncommitted siblings.
    from sqlalchemy import select as _select
    existing_db: set[str] = set(session.scalars(
        _select(IOCTag.tag).where(IOCTag.ioc_id == ioc.id)
    ).all())
    existing_pending: set[str] = {
        obj.tag for obj in session.new
        if isinstance(obj, IOCTag) and obj.ioc_id == ioc.id
    }
    existing = existing_db | existing_pending

    seen_this_call: set[str] = set()
    for tag in tags:
        tag = (tag or "").strip()[:128]
        if not tag or tag in existing or tag in seen_this_call:
            continue
        session.add(IOCTag(ioc_id=ioc.id, tag=tag))
        seen_this_call.add(tag)
    if seen_this_call:
        session.flush()


def _add_reasons(session: Session, ioc: IOC, reasons: list[tuple[str, int]]) -> None:
    for reason, points in reasons:
        session.add(ScoringReason(ioc_id=ioc.id, reason=reason[:256], points=points))
