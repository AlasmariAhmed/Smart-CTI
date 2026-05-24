"""AlienVault OTX connector — pulls recent subscribed pulses + their IOCs.

Requires OTX_API_KEY in .env (free key: https://otx.alienvault.com/api).
If no key is set, the connector returns [] without error.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

BASE = "https://otx.alienvault.com/api/v1"

OTX_TYPE_MAP = {
    "IPv4": "ip",
    "IPv6": "ip",
    "domain": "domain",
    "hostname": "domain",
    "URL": "url",
    "URI": "url",
    "FileHash-MD5": "md5",
    "FileHash-SHA1": "sha1",
    "FileHash-SHA256": "sha256",
    "email": "email",
    "CVE": "cve",
}


class OTXConnector(BaseConnector):
    name = "otx"
    display_name = "AlienVault OTX"

    async def fetch(self) -> list[RawIOC]:
        key = self.settings.otx_api_key
        if not key:
            log.info("[%s] OTX_API_KEY not set — skipping", self.name)
            return []

        since = (datetime.now(timezone.utc) - timedelta(days=2)).isoformat()
        url = f"{BASE}/pulses/subscribed?modified_since={since}&limit=20"
        headers = {"X-OTX-API-KEY": key}

        await self.limiter.acquire()
        try:
            import httpx
            async with self._client(headers=headers) as client:
                resp = await client.get(url)
                resp.raise_for_status()
                payload = resp.json()
        except Exception as e:  # noqa: BLE001
            log.warning("[%s] fetch failed: %s", self.name, e)
            return []

        results: list[RawIOC] = []
        for pulse in payload.get("results", []):
            actor = (pulse.get("adversary") or "").strip() or None
            tags = list(pulse.get("tags") or [])
            pulse_name = pulse.get("name", "")
            pulse_id = pulse.get("id", "")
            description = (pulse.get("description") or "")[:512]
            for ind in pulse.get("indicators", []):
                t = OTX_TYPE_MAP.get(ind.get("type"))
                if not t:
                    continue
                try:
                    results.append(RawIOC(
                        type=t,
                        value=ind.get("indicator", "").strip(),
                        source=self.name,
                        raw_context=f"OTX pulse: {pulse_name} | {description}",
                        source_url=f"https://otx.alienvault.com/pulse/{pulse_id}",
                        tags=tags,
                        threat_actor=actor,
                    ))
                except ValueError:
                    continue
        log.info("[%s] pulled %d indicators from %d pulses",
                 self.name, len(results), len(payload.get("results", [])))
        return results
