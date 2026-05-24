"""Unit tests for the relevance scoring engine.

These tests define the contract. The engine takes a RawIOC and returns
(int score 0..100, list of (reason, points) tuples).

Tests inject keyword/country/asn data via monkeypatch so they're hermetic —
they don't depend on the contents of data/relevance_*.json.
"""
from __future__ import annotations

import pytest

from app.connectors.base import RawIOC
from app.scoring import relevance
from app.scoring.relevance import score_ioc


# --- Default keywords for tests (monkeypatched in) -------------------------
TEST_KEYWORDS = {
    "high_signal": ["AcmeCorp", "Globex", "Initech", "Vandelay", "Hooli", "Pied Piper"],
    "sector_terms": ["energy", "banking", "OT/ICS"],
    "region_context": ["EMEA", "APAC", "GCC"],
    "threat_actors": ["APT28", "Lazarus", "FIN7"],
}
TEST_COUNTRIES = {"US", "SA", "DE"}


@pytest.fixture(autouse=True)
def _inject_test_lists(monkeypatch):
    """Force the engine to use deterministic keyword/country data for every test."""
    monkeypatch.setattr(relevance, "_keywords", lambda: TEST_KEYWORDS)
    monkeypatch.setattr(relevance, "_country_codes", lambda: TEST_COUNTRIES)


# --- Helpers -----------------------------------------------------------------
def _raw(**kwargs) -> RawIOC:
    defaults = dict(type="ip", value="8.8.8.8", source="otx", raw_context="")
    defaults.update(kwargs)
    return RawIOC(**defaults)


# --- Keyword hits -----------------------------------------------------------
def test_single_keyword_hit_adds_25():
    raw = _raw(raw_context="Phishing campaign against AcmeCorp employees.")
    score, reasons = score_ioc(raw)
    assert score >= 25
    assert any("AcmeCorp" in r[0] for r in reasons)


def test_multiple_keywords_capped_at_50():
    raw = _raw(raw_context="AcmeCorp, Globex, Initech, Vandelay, Hooli — all mentioned.")
    score, reasons = score_ioc(raw)
    keyword_points = sum(p for r, p in reasons if "keyword" in r.lower())
    assert keyword_points == 50, f"Keyword contribution should cap at 50, got {keyword_points}"


def test_case_insensitive_keyword_hit():
    raw = _raw(raw_context="ACMECORP breach reported")
    score, _ = score_ioc(raw)
    assert score >= 25


# --- TLD match --------------------------------------------------------------
def test_cctld_domain_gets_30():
    raw = _raw(type="domain", value="evil.example.sa", raw_context="")
    score, reasons = score_ioc(raw)
    assert score >= 30
    assert any(".sa" in r[0].lower() for r in reasons)


def test_subdomain_cctld_gets_30():
    raw = _raw(type="domain", value="bad.sub.example.de", raw_context="")
    score, _ = score_ioc(raw)
    assert score >= 30


def test_non_relevant_tld_no_bonus():
    raw = _raw(type="domain", value="evil.example.jp", raw_context="")  # JP not in TEST_COUNTRIES
    score, reasons = score_ioc(raw)
    assert not any(" host (" in r[0] for r in reasons)


def test_url_with_relevant_host_gets_30():
    raw = _raw(type="url", value="http://phish.example.sa/login", raw_context="")
    score, _ = score_ioc(raw)
    assert score >= 30


# --- GeoIP ------------------------------------------------------------------
def test_ip_geolocated_to_relevant_country_gets_20(monkeypatch):
    monkeypatch.setattr(relevance, "_cc", lambda _ip: "SA")
    raw = _raw(type="ip", value="212.118.0.1")
    score, reasons = score_ioc(raw)
    assert score >= 20
    assert any("geoip" in r[0].lower() and "SA" in r[0] for r in reasons)


def test_ip_geolocated_irrelevant_country_no_bonus(monkeypatch):
    monkeypatch.setattr(relevance, "_cc", lambda _ip: "JP")  # JP not in TEST_COUNTRIES
    raw = _raw(type="ip", value="8.8.8.8")
    score, reasons = score_ioc(raw)
    assert not any("geoip" in r[0].lower() for r in reasons)


# --- ASN --------------------------------------------------------------------
def test_ip_in_allow_listed_asn_gets_25(monkeypatch):
    monkeypatch.setattr(relevance._asn_enrich, "is_relevant_asn", lambda asn: asn == 25019)
    monkeypatch.setattr(relevance, "_asn", lambda _ip: 25019)
    raw = _raw(type="ip", value="46.151.0.1")
    score, reasons = score_ioc(raw)
    assert score >= 25
    assert any("ASN" in r[0] for r in reasons)


def test_ip_in_foreign_asn_no_bonus(monkeypatch):
    monkeypatch.setattr(relevance._asn_enrich, "is_relevant_asn", lambda asn: False)
    monkeypatch.setattr(relevance, "_asn", lambda _ip: 15169)
    raw = _raw(type="ip", value="8.8.8.8")
    score, reasons = score_ioc(raw)
    assert not any("ASN" in r[0] for r in reasons)


# --- Threat actors ----------------------------------------------------------
def test_known_actor_gets_30():
    raw = _raw(raw_context="Attributed to APT28 campaign", threat_actor="APT28")
    score, reasons = score_ioc(raw)
    assert score >= 30
    assert any("actor" in r[0].lower() for r in reasons)


def test_actor_in_context_only():
    raw = _raw(raw_context="Lazarus operators were observed deploying malware.")
    score, _ = score_ioc(raw)
    assert score >= 30


# --- Sector + region combo --------------------------------------------------
def test_sector_plus_region_gets_15():
    raw = _raw(raw_context="energy sector targeted across the GCC region.")
    score, reasons = score_ioc(raw)
    assert any("sector" in r[0].lower() for r in reasons)
    assert score >= 15


def test_sector_without_region_no_bonus():
    raw = _raw(raw_context="energy company in some place was hit.")
    score, reasons = score_ioc(raw)
    assert not any("sector" in r[0].lower() for r in reasons)


# --- Combination tests ------------------------------------------------------
def test_score_caps_at_100(monkeypatch):
    monkeypatch.setattr(relevance, "_cc", lambda _ip: "SA")
    monkeypatch.setattr(relevance._asn_enrich, "is_relevant_asn", lambda asn: asn == 25019)
    monkeypatch.setattr(relevance, "_asn", lambda _ip: 25019)
    raw = _raw(
        type="ip",
        value="212.118.0.1",
        raw_context="APT28 targeting AcmeCorp Globex Initech energy GCC",
        threat_actor="APT28",
    )
    score, _ = score_ioc(raw)
    assert score == 100


def test_zero_score_for_irrelevant_ioc():
    raw = _raw(type="ip", value="8.8.8.8", source="otx", raw_context="Generic Google DNS")
    score, reasons = score_ioc(raw)
    assert score == 0
    assert reasons == []


def test_reasons_points_sum_equals_score_pre_cap():
    raw = _raw(type="domain", value="phish.example.sa", raw_context="AcmeCorp breach")
    score, reasons = score_ioc(raw)
    total = sum(p for _, p in reasons)
    assert min(total, 100) == score


# --- API contract -----------------------------------------------------------
def test_score_returns_int_and_list_of_tuples():
    score, reasons = score_ioc(_raw())
    assert isinstance(score, int)
    assert 0 <= score <= 100
    assert isinstance(reasons, list)
    for entry in reasons:
        assert isinstance(entry, tuple) and len(entry) == 2
        assert isinstance(entry[0], str) and isinstance(entry[1], int)


# --- Empty-config behavior --------------------------------------------------
def test_empty_keyword_list_means_zero_score(monkeypatch):
    """With no keywords configured, generic IOCs should not score."""
    monkeypatch.setattr(relevance, "_keywords", lambda: {
        "high_signal": [], "sector_terms": [], "region_context": [], "threat_actors": []
    })
    monkeypatch.setattr(relevance, "_country_codes", lambda: set())
    raw = _raw(type="ip", value="1.2.3.4", raw_context="some attacker IP from a feed")
    score, reasons = score_ioc(raw)
    assert score == 0
    assert reasons == []
