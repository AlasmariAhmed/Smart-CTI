"""GeoIP lookup wrapper. Returns ISO country code or None.

Requires GeoLite2-Country.mmdb (see README for download instructions). Absence
of the DB is non-fatal — lookups silently return None so scoring degrades
gracefully (the IP-geo signal just becomes worthless rather than crashing).
"""
from __future__ import annotations

import logging
from functools import lru_cache
from pathlib import Path
from typing import Optional

from app.config import get_settings

log = logging.getLogger(__name__)

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP_AVAILABLE = True
except ImportError:  # pragma: no cover
    _GEOIP_AVAILABLE = False


@lru_cache(maxsize=1)
def _reader():
    if not _GEOIP_AVAILABLE:
        return None
    path = Path(get_settings().geoip_db_path)
    if not path.exists():
        log.info("GeoIP DB not found at %s — geo enrichment disabled", path)
        return None
    try:
        return geoip2.database.Reader(str(path))
    except Exception as e:  # noqa: BLE001
        log.warning("Failed to open GeoIP DB: %s", e)
        return None


def country_code(ip: str) -> Optional[str]:
    """Return ISO-2 country code for an IP, or None on failure."""
    r = _reader()
    if r is None:
        return None
    try:
        return r.country(ip).country.iso_code
    except Exception:  # noqa: BLE001
        return None
