"""Claude Code read structuredContent and said '0 findings, thin coverage' about a server
the sandbox caught sending telemetry. The structured contract now carries the sandbox,
the verdict reason names it, and sandbox findings count as findings."""
from __future__ import annotations

from src.bridges.mcp_streamable import _sandbox_struct, _scan_struct
from src.scanner.verdict import is_safe, sandbox_alarm, verdict_reason

EXA = {
    "trust_score": 70, "trust_tier": "standard", "package_version": "3.4.1",
    "published_at": "2026-08-18", "metadata": {"files_scanned": 5},
    "findings": {"items": [], "total": 0}, "certified": {"eligible": False},
    "behavioral": {"ran": True, "plan": "npm-mcp", "egress_hosts": ["api.agnost.ai", "api.exa.ai"],
                   "unexpected_egress": ["api.agnost.ai"], "vendor_egress": ["api.exa.ai"],
                   "canary_exfil": [],
                   "exercise": {"launch_ok": True, "tools": [{"name": "a"}, {"name": "b"}],
                                "calls": [{"tool": "a"}, {"tool": "b"}],
                                "canary": {"env_names": ["EXA_API_KEY"]}},
                   "findings": [{"rule": "behavioral_undeclared_egress", "severity": "high",
                                 "name": "Unexpected network egress during install/run",
                                 "evidence": "egress to api.agnost.ai"}],
                   "grade_summary": {"start_reason": "started"},
                   "attestation": {"observed_at": "2026-10-02T06:00:00+00:00"}},
    "behavioral_score_effect": {"applied": True, "delta": -12, "static_score": 82,
                                "reason": "sandbox finding: behavioral_undeclared_egress"},
}


def test_verdict_reason_names_the_sandbox_and_deprecation():
    assert sandbox_alarm(EXA) is True
    assert verdict_reason(EXA) == "sandbox_finding"
    assert verdict_reason({"trust_score": 67, "findings": {"items": []},
                           "deprecation": "no longer supported",
                           "metadata": {"files_scanned": 1}}) == "deprecated"
    assert verdict_reason({"trust_score": 70, "findings": {"items": []},
                           "metadata": {"files_scanned": 1}}) == "thin_coverage"


def test_a_high_sandbox_finding_blocks_safe_even_at_a_high_score():
    data = dict(EXA, trust_score=95)
    assert is_safe(data) is False
    clean = dict(EXA, trust_score=95, behavioral=dict(EXA["behavioral"], findings=[],
                                                       unexpected_egress=[]))
    assert is_safe(clean) is True


def test_structured_content_carries_the_sandbox_as_findings():
    s = _scan_struct(EXA, "exa-mcp-server", "npm", "/check/pkg/npm/exa-mcp-server",
                     "/api/x", (13857, "downloads/wk", 20))
    assert s["verdict"] == "needs_review" and s["verdict_reason"] == "sandbox_finding"
    assert s["high"] == 1 and s["findings_total"] == 1 and s["static_findings_total"] == 0
    assert s["top_findings"][0]["sandbox"] is True
    assert s["install"] is None
    assert s["package_version"] == "3.4.1" and s["published_at"] == "2026-08-18"
    sb = s["sandbox"]
    assert sb["ran"] and sb["server_started"] and sb["tools_called"] == 2
    assert sb["undeclared_egress"] == ["api.agnost.ai"] and sb["vendor_egress"] == ["api.exa.ai"]
    assert sb["canary_env"] == ["EXA_API_KEY"] and sb["canary_leaked"] is False
    assert sb["alarm"] is True and sb["score_effect"]["delta"] == -12
    assert sb["signed_observation_at"].startswith("2026-10-02")


def test_pending_and_deprecated_and_advisories_in_structured_content():
    pending = dict(EXA, behavioral={"ran": False, "pending": True, "reason": "running"})
    assert _sandbox_struct(pending) == {"ran": False, "pending": True, "reason": "running"}
    dep = {"trust_score": 67, "findings": {"items": [], "total": 1}, "trust_tier": "standard",
           "deprecation": "Package no longer supported.", "metadata": {"files_scanned": 1},
           "advisories": [{"id": "GHSA-1", "severity": "high", "fixed_in": "2.0",
                           "summary": "path traversal", "affects_scanned_version": True},
                          {"id": "GHSA-2", "severity": "low", "affects_scanned_version": False}]}
    s = _scan_struct(dep, "x", "npm", "/r", "/a", None)
    assert s["deprecated"] == "Package no longer supported." and s["install"] is None
    assert s["verdict_reason"] == "deprecated"
    assert [a["id"] for a in s["advisories_affecting_version"]] == ["GHSA-1"]
    assert s["sandbox"] is None
