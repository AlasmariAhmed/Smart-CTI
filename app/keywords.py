"""Keyword store — read/write `data/relevance_keywords.json`, invalidate the scoring cache.

The scoring engine reads keywords via `app.scoring.relevance._keywords()`,
which is `@lru_cache(maxsize=1)`. After any mutation we MUST call
`_keywords.cache_clear()` so new keywords take effect without a process restart.
"""
from __future__ import annotations

import json
import logging
import threading

from app.config import DATA_DIR

log = logging.getLogger(__name__)

KEYWORDS_PATH = DATA_DIR / "relevance_keywords.json"

# Categories that influence scoring. Anything not in here is rejected on write.
CATEGORIES = ("high_signal", "sector_terms", "region_context", "threat_actors")

# CATEGORY → (points-per-hit, friendly description). Used by the UI.
CATEGORY_META = {
    "high_signal":     {"points": 25, "cap": 50, "label": "High-signal keywords",
                        "hint": "Your org / brand / region / asset names. +25 per hit, capped at +50."},
    "sector_terms":    {"points": 15, "cap": None, "label": "Sector terms",
                        "hint": "Industry terms (energy, banking, OT/ICS, ...). Combine with a region term for +15."},
    "region_context":  {"points": 0,  "cap": None, "label": "Region context terms",
                        "hint": "Geographic context. Paired with a sector term to grant +15."},
    "threat_actors":   {"points": 30, "cap": None, "label": "Threat actors",
                        "hint": "APT names known to target your sector. +30 if mentioned in context."},
}

_lock = threading.Lock()


def _read_raw() -> dict:
    if not KEYWORDS_PATH.exists():
        return {c: [] for c in CATEGORIES}
    try:
        return json.loads(KEYWORDS_PATH.read_text(encoding="utf-8"))
    except Exception as e:  # noqa: BLE001
        log.warning("failed to read keywords file: %s", e)
        return {c: [] for c in CATEGORIES}


def read_all() -> dict[str, list[str]]:
    """Return {category: [keyword, ...]}. Missing categories are returned empty."""
    raw = _read_raw()
    return {c: list(raw.get(c, [])) for c in CATEGORIES}


def write_all(data: dict[str, list[str]]) -> None:
    """Persist + invalidate scoring cache."""
    with _lock:
        # Preserve any other top-level keys (like _comment) that we don't manage.
        raw = _read_raw()
        for c in CATEGORIES:
            cleaned: list[str] = []
            seen: set[str] = set()
            for kw in data.get(c, []):
                kw = (kw or "").strip()
                if not kw or kw.lower() in seen:
                    continue
                cleaned.append(kw)
                seen.add(kw.lower())
            raw[c] = cleaned
        KEYWORDS_PATH.write_text(json.dumps(raw, indent=2, ensure_ascii=False), encoding="utf-8")
    _invalidate_scoring_cache()


def add_keyword(category: str, keyword: str) -> dict[str, list[str]]:
    if category not in CATEGORIES:
        raise ValueError(f"unknown category: {category}")
    keyword = (keyword or "").strip()
    if not keyword:
        raise ValueError("keyword cannot be empty")
    current = read_all()
    if any(k.lower() == keyword.lower() for k in current[category]):
        return current  # idempotent
    current[category].append(keyword)
    write_all(current)
    return current


def remove_keyword(category: str, keyword: str) -> dict[str, list[str]]:
    if category not in CATEGORIES:
        raise ValueError(f"unknown category: {category}")
    current = read_all()
    current[category] = [k for k in current[category] if k.lower() != keyword.lower()]
    write_all(current)
    return current


def _invalidate_scoring_cache() -> None:
    """Clear the lru_cache on the scoring engine so changes take effect immediately."""
    try:
        from app.scoring.relevance import _keywords
        _keywords.cache_clear()
    except Exception as e:  # noqa: BLE001
        log.warning("failed to invalidate scoring cache: %s", e)
