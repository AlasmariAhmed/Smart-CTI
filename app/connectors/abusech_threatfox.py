"""abuse.ch ThreatFox connector.

ThreatFox publishes a 24h JSON dump of recently-shared IOCs at:
    https://threatfox.abuse.ch/export/json/recent/

The dump is keyed by IOC id; each value is a 1-element list containing the
record. No API key is required for this public endpoint (separate from the
authenticated POST API).
"""
from __future__ import annotations

import logging
from datetime import datetime

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

DUMP_URL = "https://threatfox.abuse.ch/export/json/recent/"

# Map ThreatFox ioc_type strings → our internal IOC types.
TYPE_MAP = {
    "ip:port": "ip",
    "ip": "ip",
    "domain": "domain",
    "url": "url",
    "md5_hash": "md5",
    "sha1_hash": "sha1",
    "sha256_hash": "sha256",
    "email": "email",
}


class ThreatFoxConnector(BaseConnector):
    name = "abusech_threatfox"
    display_name = "abuse.ch ThreatFox"

    async def fetch(self) -> list[RawIOC]:
        resp = await self._get(DUMP_URL)
        if resp is None:
            return []
        try:
            payload = resp.json()
        except ValueError as e:
            log.warning("[%s] non-JSON response: %s", self.name, e)
            return []

        results: list[RawIOC] = []
        for ioc_id, entries in payload.items():
            if not entries:
                continue
            entry = entries[0]
            # The outer dict key IS the canonical ThreatFox IOC id —
            # the inner record sometimes omits it.
            entry.setdefault("id", ioc_id)
            try:
                results.append(self._parse(entry))
            except Exception as e:  # noqa: BLE001
                log.debug("[%s] skipping malformed entry %s: %s", self.name, ioc_id, e)
        log.info("[%s] pulled %d IOCs", self.name, len(results))
        return results

    def _parse(self, entry: dict) -> RawIOC:
        raw_type = (entry.get("ioc_type") or "").lower()
        mapped = TYPE_MAP.get(raw_type)
        if mapped is None:
            raise ValueError(f"unknown ioc_type {raw_type!r}")

        value = entry.get("ioc_value") or ""
        if mapped == "ip" and ":" in value:
            value = value.split(":", 1)[0]  # strip :port

        first_seen = _parse_dt(entry.get("first_seen_utc"))
        last_seen = _parse_dt(entry.get("last_seen_utc")) or first_seen

        tags = []
        if entry.get("tags"):
            if isinstance(entry["tags"], list):
                tags.extend(t for t in entry["tags"] if isinstance(t, str))
            elif isinstance(entry["tags"], str):
                tags.extend(s.strip() for s in entry["tags"].split(",") if s.strip())

        malware = entry.get("malware_printable") or entry.get("malware")

        context_parts = [
            f"ThreatFox id={entry.get('id')}",
            f"threat_type={entry.get('threat_type')}",
            f"malware={malware}",
            f"confidence={entry.get('confidence_level')}",
            f"reporter={entry.get('reporter')}",
            f"reference={entry.get('reference')}",
        ]
        raw_context = " | ".join(p for p in context_parts if p and "None" not in p)

        return RawIOC(
            type=mapped,
            value=value,
            source=self.name,
            raw_context=raw_context,
            source_url=entry.get("reference") or f"https://threatfox.abuse.ch/ioc/{entry.get('id')}/",
            first_seen=first_seen,
            last_seen=last_seen,
            tags=tags,
            malware_family=malware,
        )


def _parse_dt(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None
