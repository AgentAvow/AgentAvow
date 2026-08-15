"""Unit tests for the behavioral (sandbox) scan tier's host-agnostic logic — egress
classification, finding mapping, and fail-open behavior. The sandbox execution itself needs
a gVisor host and is validated there, not here."""
from __future__ import annotations

import asyncio

from src.scanner.behavioral.runner import (
    BehavioralResult,
    _classify_egress,
    _import_name,
    behavioral_findings,
    run_behavioral,
)


def test_registry_egress_is_expected():
    hosts = ["registry.npmjs.org", "objects.githubusercontent.com"]
    assert _classify_egress(hosts, set()) == []


def test_subdomain_of_declared_host_allowed():
    assert _classify_egress(["api.mytool.com"], {"mytool.com"}) == []


def test_unexpected_egress_flagged():
    hosts = ["registry.npmjs.org", "evil.example.net", "pastebin.com"]
    out = _classify_egress(hosts, set())
    assert out == ["evil.example.net", "pastebin.com"]


def test_import_name_normalizes():
    assert _import_name("scikit-learn==1.2") == "scikit_learn"
    assert _import_name("requests[security]") == "requests"


def test_findings_empty_when_not_run():
    r = BehavioralResult(ran=False, surface="npm", coordinate="x")
    assert behavioral_findings(r) == []


def test_unexpected_egress_becomes_a_finding():
    r = BehavioralResult(ran=True, surface="npm", coordinate="sketchy",
                         egress_hosts=["evil.net"], unexpected_egress=["evil.net"])
    fs = behavioral_findings(r)
    assert len(fs) == 1
    assert fs[0].category == "exfiltration"
    assert fs[0].severity == "high"
    assert "evil.net" in fs[0].snippet


def test_many_unexpected_hosts_escalates_to_critical():
    r = BehavioralResult(ran=True, surface="npm", coordinate="malware",
                         egress_hosts=[], unexpected_egress=["a.net", "b.net", "c.net"])
    assert behavioral_findings(r)[0].severity == "critical"


def test_clean_run_no_findings():
    r = BehavioralResult(ran=True, surface="npm", coordinate="left-pad",
                         egress_hosts=["registry.npmjs.org"], unexpected_egress=[])
    assert behavioral_findings(r) == []


def test_run_behavioral_fails_open_on_unsupported_surface():
    # crates isn't wired yet → ran=False, never raises, never blocks a static scan.
    r = asyncio.run(run_behavioral("crates", "serde"))
    assert r.ran is False
    assert r.error is not None


def test_manifest_absent_is_empty():
    from src.scanner.behavioral.manifest import parse_manifest
    assert parse_manifest(None).present is False
    assert parse_manifest("   ").egress_set() == set()


def test_manifest_parses_egress_and_caps():
    from src.scanner.behavioral.manifest import parse_manifest
    m = parse_manifest("version: agentavow-manifest-v0\negress:\n  - api.x.com\n  - .cdn.y.net\ncapabilities:\n  - network:egress\n  - bogus:cap\n")
    assert m.present is True
    assert m.egress_set() == {"api.x.com", "cdn.y.net"}
    assert m.capabilities == ["network:egress"]  # bogus cap dropped


def test_manifest_wrong_version_ignored():
    from src.scanner.behavioral.manifest import parse_manifest
    assert parse_manifest("version: something-else\negress: [evil.net]").present is False


def test_manifest_declared_host_suppresses_egress_finding():
    from src.scanner.behavioral.manifest import parse_manifest
    from src.scanner.behavioral.runner import _classify_egress
    declared = parse_manifest("version: agentavow-manifest-v0\negress: [api.mytool.com]").egress_set()
    assert _classify_egress(["api.mytool.com"], declared) == []
    assert _classify_egress(["evil.net"], declared) == ["evil.net"]
