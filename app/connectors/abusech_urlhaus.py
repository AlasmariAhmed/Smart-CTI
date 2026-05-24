"""abuse.ch URLhaus connector — public CSV mirror of recent malicious URLs.

URLhaus publishes a CSV at https://urlhaus.abuse.ch/downloads/csv_recent/
(every ~5 min). No API key required for the public dump.
"""
from __future__ import annotations

import csv
import io
import logging
from datetime import datetime

from app.connectors.base import BaseConnector, RawIOC

log = logging.getLogger(__name__)

URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"


class URLhausConnector(BaseConnector):
    name = "abusech_urlhaus"
    display_name = "abuse.ch URLhaus"

    async def fetch(self) -> list[RawIOC]:
        resp = await self._get(URL)
        if resp is None:
            return []
        # Strip the "# ..." comment lines at the top of the CSV.
        lines = [ln for ln in resp.text.splitlines() if ln and not ln.startswith("#")]
        if not lines:
            return []
        reader = csv.reader(lines)
        # First line is the header (already comment-stripped by abuse.ch).
        try:
            header = next(reader)
        except StopIteration:
            return []
        idx = {name: i for i, name in enumerate(header)}

        results: list[RawIOC] = []
        for row in reader:
            try:
                results.append(self._parse(row, idx))
            except Exception as e:  # noqa: BLE001
                log.debug("[%s] skipping row: %s", self.name, e)
        log.info("[%s] pulled %d URLs", self.name, len(results))
        return results

    def _parse(self, row: list[str], idx: dict) -> RawIOC:
        def col(name: str) -> str:
            i = idx.get(name)
            return row[i].strip() if i is not None and i < len(row) else ""

        url = col("url")
        if not url:
            raise ValueError("empty url")

        first_seen = _parse_dt(col("dateadded"))
        tags_raw = col("tags") or ""
        tags = [t.strip() for t in tags_raw.split(",") if t.strip()]
        threat = col("threat")
        if threat:
            tags.append(threat)

        ctx = (
            f"URLhaus id={col('id')} status={col('url_status')} "
            f"threat={threat} reporter={col('reporter')}"
        )

        return RawIOC(
            type="url",
            value=url,
            source=self.name,
            raw_context=ctx,
            source_url=col("urlhaus_link"),
            first_seen=first_seen,
            last_seen=first_seen,
            tags=tags,
        )


def _parse_dt(s: str) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace(" ", "T") + "+00:00")
    except (ValueError, TypeError):
        try:
            return datetime.strptime(s, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            return None
