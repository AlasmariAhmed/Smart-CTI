"""Emerging Threats open ruleset — compromised IPs blocklist.

ET publishes a compromised-IPs list at:
    https://rules.emergingthreats.net/blockrules/compromised-ips.txt

This is far simpler to parse than full Suricata rules and gives high-volume,
fresh IOCs. We pull this list rather than the full ruleset.
"""
from __future__ import annotations

import logging
import re

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

URL = "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class EmergingThreatsConnector(BaseConnector):
    name = "emerging_threats"
    display_name = "Emerging Threats compromised IPs"

    async def fetch(self) -> list[RawIOC]:
        resp = await self._get(URL)
        if resp is None:
            return []
        results: list[RawIOC] = []
        for line in resp.text.splitlines():
            ip = line.strip()
            if not ip or ip.startswith("#"):
                continue
            if not IP_RE.match(ip):
                continue
            try:
                results.append(RawIOC(
                    type="ip",
                    value=ip,
                    source=self.name,
                    raw_context="Emerging Threats compromised IP blocklist",
                    source_url=URL,
                    tags=["emerging-threats", "compromised"],
                ))
            except ValueError:
                continue
        log.info("[%s] pulled %d IPs", self.name, len(results))
        return results
