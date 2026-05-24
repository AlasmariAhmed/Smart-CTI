"""ASN lookup for IP addresses + relevance ASN allow-list check.

DESIGN NOTE — performance: a live whois ASN lookup is a network roundtrip that
can take 1–10s per IP. Calling it on every IOC in a batch of 3000+ would lock
up ingestion for an hour. Two guards:

  1. `lookup_asn()` is cached per-process (`@lru_cache`) so the same IP isn't
     looked up twice.
  2. By default it is *DISABLED* for batch scoring (returns None instantly).
     Set the env var `ENABLE_LIVE_ASN_LOOKUP=1` to turn it on if you want the
     extra signal at the cost of slow ingestion. The static allow-list still
     works via `is_relevant_asn()` for ASN values you supply explicitly.
"""
from __future__ import annotations

import json
import logging
import os
from functools import lru_cache
from typing import Optional

from app.config import DATA_DIR

log = logging.getLogger(__name__)

LIVE_LOOKUP_ENABLED = os.environ.get("ENABLE_LIVE_ASN_LOOKUP", "0").lower() in ("1", "true", "yes")
LIVE_LOOKUP_TIMEOUT_S = float(os.environ.get("ASN_LOOKUP_TIMEOUT_S", "3"))


@lru_cache(maxsize=1)
def _relevant_asns() -> set[int]:
    path = DATA_DIR / "relevance_asns.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return {int(k) for k in data.get("asns", {}).keys() if str(k).isdigit()}
    except Exception as e:  # noqa: BLE001
        log.warning("Failed to load relevance_asns.json: %s", e)
        return set()


def is_relevant_asn(asn: Optional[int]) -> bool:
    if asn is None:
        return False
    return asn in _relevant_asns()


@lru_cache(maxsize=10000)
def lookup_asn(ip: str) -> Optional[int]:
    """Return ASN integer for an IP via whois. None on failure or when disabled.

    Disabled by default — set ENABLE_LIVE_ASN_LOOKUP=1 to enable. Even when
    enabled, each lookup is bounded by ASN_LOOKUP_TIMEOUT_S (default 3s).
    """
    if not LIVE_LOOKUP_ENABLED:
        return None
    try:
        from ipwhois import IPWhois  # heavy import, kept lazy
        res = IPWhois(ip, timeout=LIVE_LOOKUP_TIMEOUT_S).lookup_rdap(depth=1)
        asn = res.get("asn")
        return int(asn) if asn and str(asn).isdigit() else None
    except Exception as e:  # noqa: BLE001
        log.debug("ASN lookup failed for %s: %s", ip, e)
        return None
