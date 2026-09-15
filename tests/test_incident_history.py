"""Tests for the incident-history reducer (src/scanner/incident_history.py).

Incident history = OSV MAL- advisories for the TARGET's own coordinate ("was this package
ever compromised?"). Context-only: never scored, never signed. These lock the parse +
the current-version-affected logic that decides live-warning vs historical-context.
"""
from __future__ import annotations

from src.scanner.incident_history import _is_mal, _version_affected, summarize_incidents

_CHALK = {
    "id": "MAL-2025-46969",
    "summary": "Malicious code in chalk (npm)",
    "published": "2025-09-08T00:00:00Z",
    "affected": [{"versions": ["5.6.1"]}],
}
_GHSA = {"id": "GHSA-xxxx-yyyy", "summary": "an ordinary CVE", "published": "2024-01-01T00:00:00Z"}
_ALIASED = {"id": "OSV-2024-1", "aliases": ["MAL-2024-9"], "summary": "aliased mal",
            "published": "2024-05-01T00:00:00Z"}


def test_is_mal_direct_and_aliased():
    assert _is_mal(_CHALK) is True
    assert _is_mal(_ALIASED) is True
    assert _is_mal(_GHSA) is False


def test_version_affected():
    assert _version_affected(_CHALK, "5.6.1") is True
    assert _version_affected(_CHALK, "5.6.2") is False
    assert _version_affected(_CHALK, None) is False  # unknown version -> historical


def test_summarize_filters_to_mal_only():
    r = summarize_incidents([_CHALK, _GHSA, _ALIASED])
    assert r["has_incident"] is True
    assert r["count"] == 2  # GHSA excluded
    assert [i["id"] for i in r["incidents"]] == ["MAL-2025-46969", "OSV-2024-1"]  # newest first


def test_current_version_affected_flag():
    # scanning the compromised version -> live warning
    assert summarize_incidents([_CHALK], version="5.6.1")["current_version_affected"] is True
    # scanning a later, clean version -> historical context only
    assert summarize_incidents([_CHALK], version="5.6.2")["current_version_affected"] is False


def test_no_incident_when_no_mal():
    r = summarize_incidents([_GHSA])
    assert r["has_incident"] is False
    assert r["count"] == 0
    assert r["checked"] is True


def test_empty():
    r = summarize_incidents([])
    assert r == {"checked": True, "has_incident": False,
                 "current_version_affected": False, "count": 0, "incidents": []}
