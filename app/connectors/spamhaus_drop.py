"""Spamhaus DROP + EDROP lists — networks known to be controlled by spammers.

Both lists are plaintext, semicolon-comment-delimited CIDR ranges. We expand
each /24 or smaller into a representative IP (the network address) since our
schema stores discrete IPs. For larger blocks (/8..23) we keep the network
address only and tag it with the CIDR.
"""
from __future__ import annotations

import logging

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

URLS = {
    "DROP": "https://www.spamhaus.org/drop/drop.txt",
    "EDROP": "https://www.spamhaus.org/drop/edrop.txt",
}


class SpamhausDROPConnector(BaseConnector):
    name = "spamhaus_drop"
    display_name = "Spamhaus DROP/EDROP"

    async def fetch(self) -> list[RawIOC]:
        results: list[RawIOC] = []
        for list_name, url in URLS.items():
            resp = await self._get(url)
            if resp is None:
                continue
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith(";") or line.startswith("#"):
                    continue
                # Format: "1.2.3.0/24 ; SBL12345"
                cidr_part = line.split(";")[0].strip()
                if "/" not in cidr_part:
                    continue
                net_ip = cidr_part.split("/")[0]
                try:
                    results.append(RawIOC(
                        type="ip",
                        value=net_ip,
                        source=self.name,
                        raw_context=f"Spamhaus {list_name}: {line}",
                        source_url=url,
                        tags=["spamhaus", list_name.lower(), cidr_part],
                    ))
                except ValueError:
                    continue
        log.info("[%s] pulled %d entries", self.name, len(results))
        return results
