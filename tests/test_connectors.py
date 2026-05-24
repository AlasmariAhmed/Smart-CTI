"""Connector unit tests with mocked HTTP responses."""
from __future__ import annotations

import httpx
import pytest
import respx

from app.connectors._html_extract import extract_iocs_from_text
from app.connectors.abusech_threatfox import DUMP_URL, ThreatFoxConnector


# --- ThreatFox -------------------------------------------------------------
@pytest.mark.asyncio
@respx.mock
async def test_threatfox_parses_recent_dump():
    sample = {
        "111": [{
            "id": "111",
            "ioc_value": "evil.example.com",
            "ioc_type": "domain",
            "threat_type": "botnet_cc",
            "malware": "win.cobaltstrike",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 80,
            "first_seen_utc": "2026-01-10 12:00:00",
            "last_seen_utc": "2026-01-12 09:00:00",
            "reporter": "abuse_ch",
            "reference": "https://threatfox.abuse.ch/ioc/111/",
            "tags": ["cobaltstrike", "c2"],
        }],
        "222": [{
            "id": "222",
            "ioc_value": "203.0.113.5:443",
            "ioc_type": "ip:port",
            "threat_type": "botnet_cc",
            "malware_printable": "Emotet",
            "confidence_level": 90,
            "first_seen_utc": "2026-01-11 08:00:00",
            "last_seen_utc": "2026-01-11 08:00:00",
            "reporter": "abuse_ch",
            "reference": "https://threatfox.abuse.ch/ioc/222/",
            "tags": "emotet,botnet",
        }],
        "333": [{
            "id": "333",
            "ioc_value": "abc",
            "ioc_type": "totally_unknown",
        }],
    }
    respx.get(DUMP_URL).mock(return_value=httpx.Response(200, json=sample))

    conn = ThreatFoxConnector()
    results = await conn.fetch()

    assert len(results) == 2
    by_value = {r.value: r for r in results}
    assert "evil.example.com" in by_value
    assert "203.0.113.5" in by_value
    assert by_value["evil.example.com"].malware_family == "Cobalt Strike"
    assert "cobaltstrike" in by_value["evil.example.com"].tags
    assert by_value["203.0.113.5"].type == "ip"
    assert "emotet" in by_value["203.0.113.5"].tags


@pytest.mark.asyncio
@respx.mock
async def test_threatfox_handles_network_error_gracefully():
    respx.get(DUMP_URL).mock(side_effect=httpx.ConnectError("boom"))
    conn = ThreatFoxConnector()
    results = await conn.fetch()
    assert results == []


@pytest.mark.asyncio
@respx.mock
async def test_threatfox_handles_non_json_response():
    respx.get(DUMP_URL).mock(return_value=httpx.Response(200, text="not json"))
    conn = ThreatFoxConnector()
    results = await conn.fetch()
    assert results == []


# --- HTML extraction helper -------------------------------------------------
def test_extract_iocs_from_advisory_text():
    text = """
    A new phishing campaign was observed.
    Indicators of Compromise:
      IP: 203.0.113.45 and 198[.]51[.]100[.]9
      Domain: badactor.example.com, evil-domain.com
      URL: https://phish.example.com/login
      MD5:  d41d8cd98f00b204e9800998ecf8427e
      SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      CVE-2024-12345 is exploited.
    """
    iocs = extract_iocs_from_text(
        text=text,
        source_name="my_scraper",
        source_url="https://example.com/advisory/123",
        advisory_title="Phishing campaign",
    )
    by_type: dict[str, list[str]] = {}
    for i in iocs:
        by_type.setdefault(i.type, []).append(i.value)

    assert "203.0.113.45" in by_type.get("ip", [])
    assert "198.51.100.9" in by_type.get("ip", [])  # refanged
    assert "badactor.example.com" in by_type.get("domain", [])
    assert "https://phish.example.com/login" in by_type.get("url", [])
    assert "d41d8cd98f00b204e9800998ecf8427e" in by_type.get("md5", [])
    assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in by_type.get("sha256", [])
    assert "CVE-2024-12345" in by_type.get("cve", [])


def test_extract_iocs_dedupes():
    text = "IP 1.1.1.1 again 1.1.1.1 and one more time 1.1.1.1"
    iocs = extract_iocs_from_text(
        text=text, source_name="x", source_url=None, advisory_title=""
    )
    ips = [i.value for i in iocs if i.type == "ip"]
    assert ips.count("1.1.1.1") == 1


def test_extract_iocs_invalid_ip_rejected():
    text = "999.999.999.999 is not valid"
    iocs = extract_iocs_from_text(
        text=text, source_name="x", source_url=None, advisory_title=""
    )
    assert all(i.type != "ip" for i in iocs)


def test_extract_iocs_skips_file_extensions_as_domains():
    text = "see report.pdf for details, also visit evil.example.com"
    iocs = extract_iocs_from_text(
        text=text, source_name="x", source_url=None, advisory_title=""
    )
    domains = [i.value for i in iocs if i.type == "domain"]
    assert "report.pdf" not in domains
    assert "evil.example.com" in domains


def test_extract_iocs_respects_extra_ignore_domains():
    text = "visit our.cert.example.org and the bad badactor.example.com"
    iocs = extract_iocs_from_text(
        text=text, source_name="x", source_url=None, advisory_title="",
        extra_ignore_domains={"our.cert.example.org"},
    )
    domains = [i.value for i in iocs if i.type == "domain"]
    assert "our.cert.example.org" not in domains
    assert "badactor.example.com" in domains
