"""Reusable IOC extraction helper for HTML/text-based advisory scrapers.

If you write a connector that scrapes a CERT / vendor / blog page for IOCs,
import `extract_iocs_from_text()` — it handles IP/domain/URL/hash/CVE regex
extraction, refanging (`1[.]2[.]3[.]4` → `1.2.3.4`), hash-overlap dedup,
and a small ignore list for common non-IOC domains.
"""
from __future__ import annotations

import re
from typing import Optional

from app.connectors.base import RawIOC

# --- IOC extraction regexes -------------------------------------------------
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
URL_RE = re.compile(r"https?://[^\s<>\"'\]\)]+", re.IGNORECASE)
MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

# Defanged → fanged: `1[.]2[.]3[.]4` and similar.
DEFANGED_RE = re.compile(r"\[\.\]|\(\.\)|\[dot\]", re.IGNORECASE)

# Common non-IOC domains we shouldn't pull from advisory pages.
DEFAULT_IGNORE_DOMAINS = {
    "cisa.gov", "www.cisa.gov", "kb.cert.org", "nvd.nist.gov",
    "microsoft.com", "support.microsoft.com",
    "twitter.com", "x.com", "linkedin.com", "facebook.com", "youtube.com",
    "github.com",
}


def extract_iocs_from_text(
    *,
    text: str,
    source_name: str,
    source_url: Optional[str],
    advisory_title: str,
    extra_ignore_domains: Optional[set[str]] = None,
    tag: str = "advisory",
) -> list[RawIOC]:
    """Pull IOCs from a chunk of advisory text. Pure — no I/O.

    Args:
        text: the body text to scan.
        source_name: connector name (becomes RawIOC.source).
        source_url: the advisory page URL (becomes RawIOC.source_url).
        advisory_title: short title; goes into raw_context.
        extra_ignore_domains: connector-specific domains to skip (e.g., the
            CERT's own host).
        tag: tag applied to every extracted IOC for filtering downstream.
    """
    refanged = DEFANGED_RE.sub(".", text)
    context = f"{advisory_title}".strip()[:1024]

    ignore = DEFAULT_IGNORE_DOMAINS | (extra_ignore_domains or set())
    found: dict[tuple[str, str], RawIOC] = {}

    def _add(t: str, v: str) -> None:
        v = v.strip().rstrip(".,;:)")
        if not v:
            return
        key = (t, v.lower() if t != "url" else v)
        if key in found:
            return
        try:
            found[key] = RawIOC(
                type=t,
                value=v,
                source=source_name,
                raw_context=context,
                source_url=source_url,
                tags=[tag],
            )
        except ValueError:
            pass

    for m in CVE_RE.finditer(refanged):
        _add("cve", m.group(0).upper())
    for m in SHA256_RE.finditer(refanged):
        _add("sha256", m.group(0).lower())

    # Avoid double-counting hash substrings.
    sha256_strs = [k[1] for k in found if k[0] == "sha256"]
    for m in SHA1_RE.finditer(refanged):
        if not any(m.group(0) in v for v in sha256_strs):
            _add("sha1", m.group(0).lower())
    sha1_or_256 = sha256_strs + [k[1] for k in found if k[0] == "sha1"]
    for m in MD5_RE.finditer(refanged):
        if not any(m.group(0) in v for v in sha1_or_256):
            _add("md5", m.group(0).lower())

    for m in URL_RE.finditer(refanged):
        _add("url", m.group(0))
    for m in IP_RE.finditer(refanged):
        ip = m.group(0)
        if _is_valid_ip(ip):
            _add("ip", ip)
    for m in DOMAIN_RE.finditer(refanged):
        d = m.group(0).lower()
        if d in ignore:
            continue
        tld = d.rsplit(".", 1)[-1]
        if tld in {"pdf", "doc", "docx", "html", "htm", "xls", "xlsx", "png", "jpg", "jpeg", "gif"}:
            continue
        _add("domain", d)

    return list(found.values())


def _is_valid_ip(s: str) -> bool:
    parts = s.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(p) for p in parts]
    except ValueError:
        return False
    return all(0 <= n <= 255 for n in nums) and not (nums[0] == 0)
