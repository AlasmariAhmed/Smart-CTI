"""Base classes and shared dataclasses for feed connectors.

Every concrete connector subclasses `BaseConnector` and implements `fetch()`,
returning a list of `RawIOC`. Normalization, scoring, dedup, and persistence
happen *outside* the connector (in the ingestion pipeline) so connectors stay
small and easy to write.
"""
from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import httpx

from app.config import get_settings, get_yaml_config

log = logging.getLogger(__name__)


# --- Allowed IOC types -------------------------------------------------------
IOC_TYPES = frozenset({"ip", "domain", "url", "md5", "sha1", "sha256", "email", "cve"})


@dataclass
class RawIOC:
    """Normalized IOC handed off by a connector to the pipeline."""

    type: str
    value: str
    source: str
    raw_context: str = ""
    source_url: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    tags: list[str] = field(default_factory=list)
    threat_actor: Optional[str] = None
    malware_family: Optional[str] = None
    cve: Optional[str] = None

    def __post_init__(self) -> None:
        if self.type not in IOC_TYPES:
            raise ValueError(f"Invalid IOC type: {self.type!r}")
        self.value = self.value.strip()
        if not self.value:
            raise ValueError("IOC value cannot be empty")
        now = datetime.now(timezone.utc)
        if self.first_seen is None:
            self.first_seen = now
        if self.last_seen is None:
            self.last_seen = now


class RateLimiter:
    """Trivial per-connector rate limiter. Not exact, but good enough for OSINT."""

    def __init__(self, requests_per_sec: float) -> None:
        self.interval = 1.0 / max(requests_per_sec, 0.01)
        self._last_call = 0.0
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            wait = self._last_call + self.interval - now
            if wait > 0:
                await asyncio.sleep(wait)
            self._last_call = time.monotonic()


class BaseConnector:
    """Abstract connector. Subclass + override `name`, `display_name`, `fetch()`."""

    #: Unique key — must match the entry under `connectors:` in config.yaml.
    name: str = ""
    display_name: str = ""

    def __init__(self) -> None:
        cfg = get_yaml_config().get("connectors", {}).get(self.name, {}) or {}
        self.enabled: bool = bool(cfg.get("enabled", True))
        self.interval_minutes: int = int(cfg.get("interval_minutes", 60))
        rate = float(cfg.get("rate_limit_per_sec", 1))
        self.limiter = RateLimiter(rate)
        http_cfg = get_yaml_config().get("http", {})
        self.user_agent: str = http_cfg.get("user_agent", "CTIAggregator/0.1")
        self.timeout: float = float(http_cfg.get("timeout_seconds", 30))
        self.settings = get_settings()

    # --- Interface to implement ------------------------------------------
    async def fetch(self) -> list[RawIOC]:
        """Pull IOCs from the upstream source. MUST not raise — catch and log."""
        raise NotImplementedError

    # --- Helpers for subclasses ------------------------------------------
    def _client(self, **kwargs) -> httpx.AsyncClient:
        headers = {"User-Agent": self.user_agent}
        headers.update(kwargs.pop("headers", {}))
        # Follow redirects by default — many OSINT feeds and CERT sites
        # 301 to a new home, and we'd rather chase the rename than fail.
        kwargs.setdefault("follow_redirects", True)
        return httpx.AsyncClient(timeout=self.timeout, headers=headers, **kwargs)

    async def _get(self, url: str, **kwargs) -> Optional[httpx.Response]:
        """Rate-limited GET. Returns None on failure (caller decides)."""
        await self.limiter.acquire()
        try:
            async with self._client() as client:
                resp = await client.get(url, **kwargs)
                resp.raise_for_status()
                return resp
        except httpx.HTTPError as e:
            log.warning("[%s] GET %s failed: %s", self.name, url, e)
            return None

    async def _post(self, url: str, **kwargs) -> Optional[httpx.Response]:
        await self.limiter.acquire()
        try:
            async with self._client() as client:
                resp = await client.post(url, **kwargs)
                resp.raise_for_status()
                return resp
        except httpx.HTTPError as e:
            log.warning("[%s] POST %s failed: %s", self.name, url, e)
            return None
