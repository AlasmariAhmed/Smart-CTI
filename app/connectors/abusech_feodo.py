"""abuse.ch Feodo Tracker — IPs hosting Emotet / Dridex / TrickBot etc. C2s.

Public JSON blocklist, no auth.
"""
from __future__ import annotations

import logging
from datetime import datetime

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"


class FeodoTrackerConnector(BaseConnector):
    name = "abusech_feodo"
    display_name = "abuse.ch Feodo Tracker"

    async def fetch(self) -> list[RawIOC]:
        resp = await self._get(URL)
        if resp is None:
            return []
        try:
            payload = resp.json()
        except ValueError as e:
            log.warning("[%s] non-JSON: %s", self.name, e)
            return []

        results: list[RawIOC] = []
        for entry in payload:
            try:
                results.append(self._parse(entry))
            except Exception as e:  # noqa: BLE001
                log.debug("[%s] skipping entry: %s", self.name, e)
        log.info("[%s] pulled %d IPs", self.name, len(results))
        return results

    def _parse(self, e: dict) -> RawIOC:
        ip = e.get("ip_address") or e.get("ip")
        if not ip:
            raise ValueError("no ip")
        family = e.get("malware") or None
        first_seen = _parse_dt(e.get("first_seen"))
        last_seen = _parse_dt(e.get("last_online")) or first_seen
        tags = ["feodo", "c2"]
        if family:
            tags.append(family.lower())
        ctx = f"Feodo Tracker malware={family} port={e.get('port')} as={e.get('as_name')}"
        return RawIOC(
            type="ip",
            value=str(ip),
            source=self.name,
            raw_context=ctx,
            source_url="https://feodotracker.abuse.ch/browse/",
            first_seen=first_seen,
            last_seen=last_seen,
            tags=tags,
            malware_family=family,
        )


def _parse_dt(s):
    if not s:
        return None
    try:
        return datetime.fromisoformat(str(s).replace(" ", "T") + "+00:00")
    except (ValueError, TypeError):
        return None
