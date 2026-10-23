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


def test_summarize_filters_to_incidents_only():
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


# ── malware-class GHSA (CWE-506) counts as an incident ───────────────────────────────
# Trimmed from the real OSV record https://api.osv.dev/v1/vulns/GHSA-mh6f-8j2x-4483
# (the 2018 event-stream / flatmap-stream compromise): no MAL- record or alias exists
# for event-stream, only this GHSA with cwe_ids ["CWE-506"].
_EVENT_STREAM = {
    "id": "GHSA-mh6f-8j2x-4483",
    "summary": "Critical severity vulnerability that affects event-stream and flatmap-stream",
    "published": "2018-11-26T23:58:21Z",
    "database_specific": {"cwe_ids": ["CWE-506"], "severity": "CRITICAL",
                          "github_reviewed": True},
    "affected": [
        {"package": {"name": "event-stream", "ecosystem": "npm"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "3.3.6"},
                                                  {"fixed": "4.0.0"}]}],
         "versions": ["3.3.6"]},
        {"package": {"name": "flatmap-stream", "ecosystem": "npm"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}]}]},
    ],
}
_REDOS_GHSA = {"id": "GHSA-aaaa-bbbb-cccc", "summary": "ReDoS",
               "published": "2022-01-01T00:00:00Z",
               "database_specific": {"cwe_ids": ["CWE-1333", "CWE-400"]}}
# debug's 2025 compromise: the GHSA and the MAL- record alias each other.
_DEBUG_GHSA = {"id": "GHSA-4x49-vf9v-38px", "aliases": ["MAL-2025-46974"],
               "published": "2025-09-08T00:00:00Z",
               "database_specific": {"cwe_ids": ["CWE-506"]},
               "affected": [{"package": {"name": "debug", "ecosystem": "npm"},
                             "versions": ["4.4.2"]}]}
_DEBUG_MAL = {"id": "MAL-2025-46974", "aliases": ["GHSA-4x49-vf9v-38px"],
              "published": "2025-09-09T00:00:00Z",
              "affected": [{"package": {"name": "debug", "ecosystem": "npm"}}]}


def test_malware_ghsa_classification():
    from src.scanner.incident_history import _is_incident, _is_malware_ghsa
    assert _is_malware_ghsa(_EVENT_STREAM) is True
    assert _is_incident(_EVENT_STREAM) is True
    assert _is_malware_ghsa(_REDOS_GHSA) is False
    assert _is_malware_ghsa(_GHSA) is False  # no database_specific
    malformed = {"id": "GHSA-x", "database_specific": {"cwe_ids": "CWE-506"}}
    assert _is_malware_ghsa(malformed) is False  # not a list
    assert _is_malware_ghsa({"id": "GHSA-x", "database_specific": {"cwe_ids": ["cwe-506"]}})
    # Only GitHub records: a PYSEC/OSV record carrying the field is not read this way.
    pysec = {"id": "PYSEC-1", "database_specific": {"cwe_ids": ["CWE-506"]}}
    assert _is_malware_ghsa(pysec) is False


def test_event_stream_ghsa_is_an_incident():
    r = summarize_incidents([_EVENT_STREAM, _REDOS_GHSA], version="4.0.1", eco="npm",
                            name="event-stream")
    assert r["has_incident"] is True
    assert r["count"] == 1
    assert r["incidents"][0]["id"] == "GHSA-mh6f-8j2x-4483"
    assert r["current_version_affected"] is False  # 4.0.1 is clean: history only


def test_event_stream_compromised_version_is_affected():
    r = summarize_incidents([_EVENT_STREAM], version="3.3.6", eco="npm", name="event-stream")
    assert r["current_version_affected"] is True
    assert r["incidents"][0]["current_version_affected"] is True


def test_open_range_without_listed_version_is_not_claimed():
    # flatmap-stream's entry is ``introduced: 0`` with no versions list. Incident history
    # stays conservative (explicit versions only); the advisory path reads the range.
    r = summarize_incidents([_EVENT_STREAM], version="0.1.1", eco="npm",
                            name="flatmap-stream")
    assert r["has_incident"] is True
    assert r["current_version_affected"] is False


def test_aliased_ghsa_and_mal_are_one_incident():
    r = summarize_incidents([_DEBUG_GHSA, _DEBUG_MAL], version="4.4.2", eco="npm",
                            name="debug")
    assert r["count"] == 1
    assert r["incidents"][0]["id"] == "MAL-2025-46974"  # the OpenSSF record is kept
    # Affected via the GHSA's version list even though the MAL record lists none.
    assert r["current_version_affected"] is True
    assert r["incidents"][0]["current_version_affected"] is True


def test_malware_ghsa_stays_in_advisories():
    # Kept as an advisory: it is the scored finding for an affected version (incident
    # history is never scored), and the advisory path also reads ranges.
    from src.scanner.incident_history import summarize_advisories
    adv = summarize_advisories([_EVENT_STREAM], "npm", "3.3.6", "event-stream")
    assert [a["id"] for a in adv] == ["GHSA-mh6f-8j2x-4483"]
    assert adv[0]["affects_scanned_version"] is True
    assert adv[0]["severity"] == "critical"
    flat = summarize_advisories([_EVENT_STREAM], "npm", "0.1.1", "flatmap-stream")
    assert flat[0]["affects_scanned_version"] is True


def test_decision_for_a_version_covered_by_a_malware_ghsa():
    from src.scanner.verdict import decide
    hit = summarize_incidents([_EVENT_STREAM], version="3.3.6", eco="npm",
                              name="event-stream")
    assert decide({"trust_score": 90, "findings": [],
                   "incident_history": hit}).decision == "do_not_connect"
    clean = summarize_incidents([_EVENT_STREAM], version="4.0.1", eco="npm",
                                name="event-stream")
    assert decide({"trust_score": 90, "findings": [],
                   "incident_history": clean}).decision != "do_not_connect"
