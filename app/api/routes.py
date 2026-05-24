"""FastAPI routes for the dashboard + JSON API.

Routes
------
GET  /                    → dashboard HTML
GET  /api/stats           → counts for dashboard cards
GET  /api/iocs            → searchable IOC list (filtered, paginated)
GET  /api/iocs/{id}       → IOC detail (sources, reasons, tags)
GET  /api/feeds           → connector status list
POST /api/feeds/{name}/run → manual "Run now"
GET  /api/keywords        → list keywords by category
POST /api/keywords        → add a keyword
DELETE /api/keywords/{cat}/{kw} → remove a keyword
POST /api/rescore         → re-run scoring on all stored IOCs
POST /api/admin/purge     → destructive: delete IOCs (requires confirm)
GET  /api/admin/db-size   → current DB row counts
GET  /api/export          → CSV / JSON / STIX export of current filter
"""
from __future__ import annotations

import csv
import io
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from sqlalchemy import desc, func, select
from sqlalchemy.orm import Session, selectinload

from app import keywords as kw_store
from app.connectors import ALL_CONNECTORS, all_connector_names, get_connector
from app.db.models import IOC, IOCSource, IOCTag, FeedRun, ScoringReason
from app.db.session import get_db
from app.runner import run_connector

log = logging.getLogger(__name__)

router = APIRouter()


# --- HTML pages -------------------------------------------------------------
@router.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "index.html", {"title": "CTI Aggregator"})


@router.get("/feeds", response_class=HTMLResponse)
async def feeds_page(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "feeds.html", {"title": "Feeds — CTI Aggregator"})


@router.get("/keywords", response_class=HTMLResponse)
async def keywords_page(request: Request) -> HTMLResponse:
    templates = request.app.state.templates
    return templates.TemplateResponse(request, "keywords.html", {"title": "Keywords — CTI Aggregator"})


# --- JSON API ---------------------------------------------------------------
@router.get("/api/stats")
def api_stats(db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count(IOC.id))) or 0

    by_type_rows = db.execute(
        select(IOC.type, func.count(IOC.id)).group_by(IOC.type)
    ).all()
    by_type = {t: c for t, c in by_type_rows}

    high = db.scalar(select(func.count(IOC.id)).where(IOC.relevance_score >= 80)) or 0
    med = db.scalar(
        select(func.count(IOC.id)).where(IOC.relevance_score >= 40, IOC.relevance_score < 80)
    ) or 0

    twenty_four_h_ago = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = db.scalar(
        select(func.count(IOC.id)).where(IOC.first_seen >= twenty_four_h_ago)
    ) or 0

    top_actors_rows = db.execute(
        select(IOC.threat_actor, func.count(IOC.id))
        .where(IOC.threat_actor.is_not(None))
        .group_by(IOC.threat_actor)
        .order_by(desc(func.count(IOC.id)))
        .limit(10)
    ).all()
    top_actors = [{"actor": a, "count": c} for a, c in top_actors_rows]

    return {
        "total": total,
        "by_type": by_type,
        "high_score": high,
        "med_score": med,
        "last_24h": last_24h,
        "top_actors": top_actors,
    }


@router.get("/api/iocs")
def api_iocs(
    q: Optional[str] = None,
    type: Optional[str] = None,
    source: Optional[str] = None,
    min_score: int = 0,
    tag: Optional[str] = None,
    actor: Optional[str] = None,
    days: Optional[int] = None,
    keyword: Optional[str] = None,
    limit: int = Query(default=100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
) -> dict:
    stmt = select(IOC).options(
        selectinload(IOC.sources), selectinload(IOC.tags), selectinload(IOC.reasons)
    )
    if q:
        stmt = stmt.where(IOC.value.ilike(f"%{q}%"))
    if type:
        stmt = stmt.where(IOC.type == type)
    if min_score:
        stmt = stmt.where(IOC.relevance_score >= min_score)
    if actor:
        stmt = stmt.where(IOC.threat_actor.ilike(f"%{actor}%"))
    if days:
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = stmt.where(IOC.last_seen >= cutoff)
    if source:
        stmt = stmt.where(IOC.sources.any(IOCSource.source_name == source))
    if tag:
        stmt = stmt.where(IOC.tags.any(IOCTag.tag == tag))
    if keyword:
        kw_like = f"%{keyword}%"
        stmt = stmt.where(
            IOC.reasons.any(ScoringReason.reason.ilike(kw_like))
            | IOC.sources.any(IOCSource.raw_context.ilike(kw_like))
        )

    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0

    stmt = stmt.order_by(desc(IOC.relevance_score), desc(IOC.last_seen)).limit(limit).offset(offset)
    rows = db.scalars(stmt).all()

    return {
        "total": total,
        "items": [_serialize_ioc(r) for r in rows],
    }


@router.get("/api/iocs/{ioc_id}")
def api_ioc_detail(ioc_id: int, db: Session = Depends(get_db)) -> dict:
    ioc = db.get(IOC, ioc_id)
    if not ioc:
        raise HTTPException(404)
    return _serialize_ioc_detail(ioc, db)


@router.get("/api/feeds")
def api_feeds(db: Session = Depends(get_db)) -> dict:
    feeds = []
    for cls in ALL_CONNECTORS:
        inst = cls()
        last_run = db.execute(
            select(FeedRun)
            .where(FeedRun.connector_name == cls.name)
            .order_by(desc(FeedRun.started_at))
            .limit(1)
        ).scalar_one_or_none()
        feeds.append({
            "name": cls.name,
            "display_name": cls.display_name,
            "enabled": inst.enabled,
            "interval_minutes": inst.interval_minutes,
            "last_run": _serialize_feed_run(last_run) if last_run else None,
        })
    return {"feeds": feeds}


@router.post("/api/feeds/{name}/run")
async def api_feed_run(name: str) -> dict:
    if name not in all_connector_names():
        raise HTTPException(404, detail=f"Unknown connector: {name}")
    conn = get_connector(name)
    if conn is None:
        raise HTTPException(404)
    result = await run_connector(conn)
    return result


# --- Keyword management ------------------------------------------------------
@router.get("/api/keywords")
def api_keywords() -> dict:
    return {
        "categories": kw_store.CATEGORY_META,
        "keywords": kw_store.read_all(),
    }


@router.post("/api/keywords")
def api_keywords_add(payload: dict = Body(...)) -> dict:
    cat = (payload.get("category") or "").strip()
    kw = (payload.get("keyword") or "").strip()
    if not cat or not kw:
        raise HTTPException(400, "category and keyword are required")
    try:
        kw_store.add_keyword(cat, kw)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"keywords": kw_store.read_all()}


@router.delete("/api/keywords/{category}/{keyword:path}")
def api_keywords_delete(category: str, keyword: str) -> dict:
    try:
        kw_store.remove_keyword(category, keyword)
    except ValueError as e:
        raise HTTPException(400, str(e))
    return {"keywords": kw_store.read_all()}


@router.post("/api/rescore")
def api_rescore(db: Session = Depends(get_db)) -> dict:
    """Re-run scoring on every stored IOC using current keywords."""
    from app.scoring.relevance import score_ioc
    from app.connectors.base import RawIOC

    updated = 0
    rows = db.scalars(
        select(IOC).options(selectinload(IOC.sources), selectinload(IOC.reasons), selectinload(IOC.tags))
    ).all()
    for r in rows:
        context = " | ".join((s.raw_context or "") for s in r.sources)
        try:
            raw = RawIOC(
                type=r.type, value=r.value,
                source=(r.sources[0].source_name if r.sources else "unknown"),
                raw_context=context, tags=[t.tag for t in r.tags],
                threat_actor=r.threat_actor, malware_family=r.malware_family,
            )
        except ValueError:
            continue
        score, reasons = score_ioc(raw)
        if score != r.relevance_score or len(reasons) != len(r.reasons):
            r.relevance_score = score
            for old in list(r.reasons):
                db.delete(old)
            for reason, points in reasons:
                db.add(ScoringReason(ioc_id=r.id, reason=reason[:256], points=points))
            updated += 1
    db.commit()
    return {"total_iocs": len(rows), "updated": updated}


# --- Admin: purge ----------------------------------------------------------
@router.post("/api/admin/purge")
def api_purge(payload: dict = Body(...), db: Session = Depends(get_db)) -> dict:
    """Delete IOCs (and their cascading children via FK ON DELETE CASCADE).

    Modes:
      - {"mode": "all"}                            → wipe everything
      - {"mode": "older_than", "days": 30}         → IOCs with last_seen < now-N
      - {"mode": "below_score", "score": 50}       → IOCs with relevance_score < N
      - {"confirm": "DELETE"} is REQUIRED on every call (type-to-confirm guard).
    """
    from sqlalchemy import delete as sql_delete

    if payload.get("confirm") != "DELETE":
        raise HTTPException(400, "Pass confirm='DELETE' to authorize this destructive op.")

    mode = payload.get("mode")
    stmt = None
    label = ""
    cutoff = None
    score = None

    if mode == "all":
        stmt = sql_delete(IOC)
        label = "all IOCs"
    elif mode == "older_than":
        try:
            days = int(payload.get("days", 0))
        except (TypeError, ValueError):
            raise HTTPException(400, "days must be an integer")
        if days <= 0:
            raise HTTPException(400, "days must be > 0")
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        stmt = sql_delete(IOC).where(IOC.last_seen < cutoff)
        label = f"IOCs older than {days} days"
    elif mode == "below_score":
        try:
            score = int(payload.get("score", 0))
        except (TypeError, ValueError):
            raise HTTPException(400, "score must be an integer")
        if score < 0 or score > 100:
            raise HTTPException(400, "score must be 0..100")
        stmt = sql_delete(IOC).where(IOC.relevance_score < score)
        label = f"IOCs with score < {score}"
    else:
        raise HTTPException(400, "mode must be one of: all, older_than, below_score")

    count_stmt = select(func.count(IOC.id))
    if mode == "older_than":
        count_stmt = count_stmt.where(IOC.last_seen < cutoff)
    elif mode == "below_score":
        count_stmt = count_stmt.where(IOC.relevance_score < score)
    to_delete = db.scalar(count_stmt) or 0

    db.execute(stmt)
    if mode == "all":
        db.execute(sql_delete(FeedRun))
    db.commit()
    log.warning("[admin] purged: %s (%d IOCs)", label, to_delete)
    return {"deleted_iocs": to_delete, "mode": mode, "label": label}


@router.get("/api/admin/db-size")
def api_db_size(db: Session = Depends(get_db)) -> dict:
    total = db.scalar(select(func.count(IOC.id))) or 0
    by_score = {
        "high":   db.scalar(select(func.count(IOC.id)).where(IOC.relevance_score >= 80)) or 0,
        "med":    db.scalar(select(func.count(IOC.id)).where(IOC.relevance_score >= 40, IOC.relevance_score < 80)) or 0,
        "low":    db.scalar(select(func.count(IOC.id)).where(IOC.relevance_score < 40)) or 0,
    }
    return {"total": total, "by_score": by_score}


@router.get("/api/export")
def api_export(
    format: str = Query(default="json", pattern="^(json|csv|stix)$"),
    min_score: int = 0,
    type: Optional[str] = None,
    db: Session = Depends(get_db),
) -> StreamingResponse:
    stmt = select(IOC).options(
        selectinload(IOC.sources), selectinload(IOC.tags), selectinload(IOC.reasons)
    )
    if min_score:
        stmt = stmt.where(IOC.relevance_score >= min_score)
    if type:
        stmt = stmt.where(IOC.type == type)
    rows = db.scalars(stmt).all()

    if format == "json":
        body = json.dumps([_serialize_ioc(r) for r in rows], indent=2, default=str)
        return StreamingResponse(
            io.BytesIO(body.encode("utf-8")),
            media_type="application/json",
            headers={"Content-Disposition": 'attachment; filename="iocs.json"'},
        )

    if format == "csv":
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["type", "value", "relevance_score", "first_seen", "last_seen",
                    "threat_actor", "malware_family", "cve", "tags", "sources"])
        for r in rows:
            w.writerow([
                r.type, r.value, r.relevance_score,
                r.first_seen.isoformat() if r.first_seen else "",
                r.last_seen.isoformat() if r.last_seen else "",
                r.threat_actor or "", r.malware_family or "", r.cve or "",
                "|".join(t.tag for t in r.tags),
                "|".join(s.source_name for s in r.sources),
            ])
        return StreamingResponse(
            io.BytesIO(buf.getvalue().encode("utf-8")),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="iocs.csv"'},
        )

    bundle = _to_stix_bundle(rows)
    return StreamingResponse(
        io.BytesIO(bundle.encode("utf-8")),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="iocs.stix.json"'},
    )


# --- Serializers ------------------------------------------------------------
def _serialize_ioc(r: IOC) -> dict:
    src_links: dict[str, str | None] = {}
    for s in r.sources:
        if s.source_name not in src_links or (s.source_url and not src_links[s.source_name]):
            src_links[s.source_name] = s.source_url
    score_chips = [
        {"label": _short_reason(reason.reason), "points": reason.points}
        for reason in r.reasons
    ]
    return {
        "id": r.id,
        "type": r.type,
        "value": r.value,
        "relevance_score": r.relevance_score,
        "first_seen": r.first_seen.isoformat() if r.first_seen else None,
        "last_seen": r.last_seen.isoformat() if r.last_seen else None,
        "threat_actor": r.threat_actor,
        "malware_family": r.malware_family,
        "cve": r.cve,
        "status": r.status,
        "tags": [t.tag for t in r.tags],
        "sources": list(src_links.keys()),
        "source_links": [
            {"name": name, "url": url} for name, url in src_links.items()
        ],
        "score_chips": score_chips,
    }


def _short_reason(reason: str) -> str:
    """Compress a scoring reason into a short chip label for the table view."""
    if reason.startswith("keyword hits:"):
        return reason.split(":", 1)[1].strip()
    if reason.startswith("threat actor mentioned:"):
        return reason.split(":", 1)[1].strip()
    if reason.startswith("sector + region"):
        return "sector+region"
    if " host (" in reason and reason.startswith("."):
        return reason.split(" ")[0]  # ".sa host"
    if reason.startswith("GeoIP country"):
        # "GeoIP country = SA (1.2.3.4)" -> "geo:SA"
        try:
            cc = reason.split("=")[1].split("(")[0].strip()
            return f"geo:{cc}"
        except Exception:
            return "geo"
    if reason.startswith("ASN"):
        return reason.split(" on ")[0]
    return reason[:40]


def _serialize_ioc_detail(r: IOC, db: Session) -> dict:
    reasons = db.scalars(
        select(ScoringReason).where(ScoringReason.ioc_id == r.id)
    ).all()
    sources = db.scalars(
        select(IOCSource).where(IOCSource.ioc_id == r.id).order_by(desc(IOCSource.ingested_at))
    ).all()
    base = _serialize_ioc(r)
    base["scoring_reasons"] = [
        {"reason": x.reason, "points": x.points} for x in reasons
    ]
    base["source_records"] = [
        {
            "source": s.source_name,
            "url": s.source_url,
            "raw_context": s.raw_context,
            "ingested_at": s.ingested_at.isoformat() if s.ingested_at else None,
        }
        for s in sources
    ]
    return base


def _serialize_feed_run(fr: FeedRun) -> dict:
    return {
        "id": fr.id,
        "started_at": fr.started_at.isoformat() if fr.started_at else None,
        "finished_at": fr.finished_at.isoformat() if fr.finished_at else None,
        "iocs_pulled": fr.iocs_pulled,
        "iocs_stored": fr.iocs_stored,
        "status": fr.status,
        "errors": fr.errors,
    }


def _to_stix_bundle(rows: list[IOC]) -> str:
    """Minimal STIX 2.1 bundle. Each IOC becomes an indicator SDO."""
    try:
        from stix2 import Bundle, Indicator
        objs = []
        for r in rows:
            pattern = _stix_pattern(r.type, r.value)
            if not pattern:
                continue
            objs.append(Indicator(
                name=f"{r.type}: {r.value}",
                pattern=pattern,
                pattern_type="stix",
                valid_from=r.first_seen,
                labels=["malicious-activity"],
                description=f"Relevance score: {r.relevance_score}. Tags: " +
                            ", ".join(t.tag for t in r.tags),
            ))
        return Bundle(objects=objs).serialize(pretty=True)
    except Exception as e:  # noqa: BLE001
        log.exception("STIX export failed: %s", e)
        return json.dumps({"type": "bundle", "objects": [], "error": str(e)})


def _stix_pattern(t: str, v: str) -> Optional[str]:
    v_escaped = v.replace("'", "\\'")
    return {
        "ip":     f"[ipv4-addr:value = '{v_escaped}']",
        "domain": f"[domain-name:value = '{v_escaped}']",
        "url":    f"[url:value = '{v_escaped}']",
        "md5":    f"[file:hashes.'MD5' = '{v_escaped}']",
        "sha1":   f"[file:hashes.'SHA-1' = '{v_escaped}']",
        "sha256": f"[file:hashes.'SHA-256' = '{v_escaped}']",
        "email":  f"[email-addr:value = '{v_escaped}']",
        "cve":    f"[vulnerability:external_references[*].external_id = '{v_escaped}']",
    }.get(t)
