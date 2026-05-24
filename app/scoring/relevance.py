"""Relevance scoring engine — defensive filter for OSINT IOCs.

Inputs:  a RawIOC (+ its raw_context).
Output:  (score: int 0..100, reasons: list[(str, int)]).

Rules (additive, capped at 100):
  - Keyword hit in context (case-insensitive) ........... +25 each, max +50
  - Sector term + region context combo .................. +15
  - Domain TLD on the relevance country-code list ....... +30
  - IP geolocates to a relevance country ................ +20
  - IP ASN on the relevance ASN allow-list .............. +25
  - Threat actor name appears in context / actor field .. +30

All keyword/country/ASN lists are user-configured via the /keywords UI and
the data/relevance_*.json files. Empty lists by design — fill in for YOUR
organization.

Enrichment lookups (`_cc`, `_asn`) are module-level functions so tests can
monkey-patch them deterministically — no network calls in CI.
"""
from __future__ import annotations

import json
import logging
from functools import lru_cache
from typing import Optional
from urllib.parse import urlparse

from app.config import DATA_DIR, get_yaml_config
from app.connectors.base import RawIOC
from app.enrichment import asn as _asn_enrich
from app.enrichment import geoip

log = logging.getLogger(__name__)


# --- Keyword tables ---------------------------------------------------------
@lru_cache(maxsize=1)
def _keywords() -> dict[str, list[str]]:
    path = DATA_DIR / "relevance_keywords.json"
    if not path.exists():
        log.warning("relevance_keywords.json missing — keyword scoring disabled")
        return {"high_signal": [], "sector_terms": [], "region_context": [], "threat_actors": []}
    data = json.loads(path.read_text(encoding="utf-8"))
    return {
        "high_signal": data.get("high_signal", []),
        "sector_terms": data.get("sector_terms", []),
        "region_context": data.get("region_context", []),
        "threat_actors": data.get("threat_actors", []),
    }


@lru_cache(maxsize=1)
def _country_codes() -> set[str]:
    """ISO-2 codes whose GeoIP matches grant a bonus. Used for both IP-geo and TLD checks."""
    path = DATA_DIR / "relevance_countries.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {str(c).upper() for c in data.get("countries", [])}
    except Exception as e:  # noqa: BLE001
        log.warning("failed to load relevance_countries.json: %s", e)
        return set()


@lru_cache(maxsize=1)
def _points() -> dict[str, int]:
    cfg = get_yaml_config().get("scoring", {})
    return {
        "keyword_points":       int(cfg.get("keyword_points", 25)),
        "keyword_max":          int(cfg.get("keyword_max", 50)),
        "tld_points":           int(cfg.get("tld_points", 30)),
        "geoip_points":         int(cfg.get("geoip_points", 20)),
        "asn_points":           int(cfg.get("asn_points", 25)),
        "actor_points":         int(cfg.get("actor_points", 30)),
        "sector_combo_points":  int(cfg.get("sector_combo_points", 15)),
    }


# --- Enrichment indirection (so tests can monkey-patch) ---------------------
def _cc(ip: str) -> Optional[str]:
    return geoip.country_code(ip)


def _asn(ip: str) -> Optional[int]:
    return _asn_enrich.lookup_asn(ip)


# --- Helpers ----------------------------------------------------------------
def _host_from_url(value: str) -> str:
    try:
        return urlparse(value).hostname or value
    except Exception:  # noqa: BLE001
        return value


def _tld_matches(host: str, codes: set[str]) -> Optional[str]:
    """Return the matched ISO-2 code if host ends with a relevant ccTLD."""
    if not codes:
        return None
    h = host.lower().rstrip(".")
    for code in codes:
        suffix = "." + code.lower()
        if h == code.lower() or h.endswith(suffix):
            return code
    return None


def _find_keyword_hits(text: str, keywords: list[str]) -> list[str]:
    """Case-insensitive substring search. Returns deduped list of hits."""
    if not text or not keywords:
        return []
    lowered = text.lower()
    hits: list[str] = []
    seen: set[str] = set()
    for kw in keywords:
        if not kw:
            continue
        if kw.lower() in lowered and kw not in seen:
            hits.append(kw)
            seen.add(kw)
    return hits


# --- Main entry point -------------------------------------------------------
def score_ioc(raw: RawIOC) -> tuple[int, list[tuple[str, int]]]:
    kw = _keywords()
    pts = _points()
    countries = _country_codes()
    reasons: list[tuple[str, int]] = []

    context = raw.raw_context or ""
    extra = " ".join([*raw.tags, raw.threat_actor or "", raw.malware_family or ""])
    haystack = f"{context} {extra}"

    # 1) Keyword hits (capped)
    hits = _find_keyword_hits(haystack, kw["high_signal"])
    if hits:
        per = pts["keyword_points"]
        raw_total = per * len(hits)
        capped = min(raw_total, pts["keyword_max"])
        reasons.append((f"keyword hits: {', '.join(hits[: pts['keyword_max'] // per or 1])}", capped))

    # 2) Sector + region combo
    sector_hits = _find_keyword_hits(haystack, kw["sector_terms"])
    region_hits = _find_keyword_hits(haystack, kw["region_context"] + kw["high_signal"])
    if sector_hits and region_hits:
        reasons.append((
            f"sector + region combo ({sector_hits[0]} / {region_hits[0]})",
            pts["sector_combo_points"],
        ))

    # 3) TLD match — domain or URL host whose ccTLD is on the relevance list
    host: Optional[str] = None
    if raw.type == "domain":
        host = raw.value
    elif raw.type == "url":
        host = _host_from_url(raw.value)
    if host:
        matched_tld = _tld_matches(host, countries)
        if matched_tld:
            reasons.append((f".{matched_tld.lower()} host ({host})", pts["tld_points"]))

    # 4) GeoIP — country on the relevance list
    if raw.type == "ip" and countries:
        cc = _cc(raw.value)
        if cc and cc.upper() in countries:
            reasons.append((f"GeoIP country = {cc} ({raw.value})", pts["geoip_points"]))

    # 5) ASN allow-list
    if raw.type == "ip":
        asn_num = _asn(raw.value)
        if _asn_enrich.is_relevant_asn(asn_num):
            reasons.append((f"ASN AS{asn_num} on allow-list", pts["asn_points"]))

    # 6) Threat actor match
    actor_text = f"{raw.threat_actor or ''} {haystack}"
    actor_hits = _find_keyword_hits(actor_text, kw["threat_actors"])
    if actor_hits:
        reasons.append((
            f"threat actor mentioned: {actor_hits[0]}",
            pts["actor_points"],
        ))

    total = sum(p for _, p in reasons)
    capped = min(total, 100)
    return capped, reasons
