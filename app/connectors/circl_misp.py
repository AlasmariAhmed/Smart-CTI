"""CIRCL / MISP public OSINT feed.

CIRCL publishes a free, publicly-readable MISP feed at:
    https://www.circl.lu/doc/misp/feed-osint/

The manifest is `manifest.json`, listing event UUIDs whose JSON is at
`<uuid>.json`. We pull the manifest, then iterate recent events.

Disabled by default in config.yaml — review the feed's terms before enabling.
"""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

FEED_BASE = "https://www.circl.lu/doc/misp/feed-osint"
MANIFEST = f"{FEED_BASE}/manifest.json"

# MISP attribute type → our internal IOC type
MISP_TYPE_MAP = {
    "ip-src": "ip", "ip-dst": "ip", "ip-src|port": "ip", "ip-dst|port": "ip",
    "domain": "domain", "hostname": "domain",
    "url": "url", "uri": "url",
    "md5": "md5", "sha1": "sha1", "sha256": "sha256",
    "filename|md5": "md5", "filename|sha1": "sha1", "filename|sha256": "sha256",
    "email-src": "email", "email-dst": "email",
    "vulnerability": "cve",
}


class CIRCLMISPConnector(BaseConnector):
    name = "circl_misp"
    display_name = "CIRCL OSINT MISP feed"

    async def fetch(self) -> list[RawIOC]:
        resp = await self._get(MANIFEST)
        if resp is None:
            return []
        try:
            manifest = resp.json()
        except ValueError:
            return []

        # Take the 5 most recent events to be polite.
        events = sorted(
            manifest.items(),
            key=lambda kv: kv[1].get("Orgc", {}).get("name", ""),
            reverse=True,
        )[:5]

        results: list[RawIOC] = []
        for uuid, _meta in events:
            event_url = f"{FEED_BASE}/{uuid}.json"
            er = await self._get(event_url)
            if er is None:
                continue
            try:
                event = er.json().get("Event", {})
            except ValueError:
                continue
            info = event.get("info", "")
            for attr in event.get("Attribute", []):
                t = MISP_TYPE_MAP.get(attr.get("type"))
                if not t:
                    continue
                value = attr.get("value", "")
                if "|" in value and t in ("md5", "sha1", "sha256"):
                    value = value.split("|")[-1]
                value = value.split("|")[0] if t == "ip" and "|" in value else value
                try:
                    results.append(RawIOC(
                        type=t,
                        value=value,
                        source=self.name,
                        raw_context=f"CIRCL MISP event: {info}",
                        source_url=event_url,
                        tags=["circl", "misp", attr.get("category", "")],
                    ))
                except ValueError:
                    continue
        log.info("[%s] pulled %d IOCs from %d events", self.name, len(results), len(events))
        return results
