"""Public scan API now returns individual findings (severity-sorted, capped, no snippet)."""
from src.api.public_scan_router import _build_scan_payload, _scan_result_to_dict
from src.scanner.scan import Finding, ScanResult


def _result_with(findings):
    r = ScanResult(repo="o/r", stars=0, description="", framework="")
    r.findings = findings
    r.trust_score = 50
    return r


def test_items_present_and_shaped():
    r = _result_with([
        Finding("prompt_injection", "Instruction override", "high", "skill.md", 3, "x"),
    ])
    d = _scan_result_to_dict(r)
    items = d["findings"]["items"]
    assert len(items) == 1
    it = items[0]
    assert it["category"] == "prompt_injection"
    assert it["severity"] == "high"
    assert it["file_path"] == "skill.md"
    assert it["line_number"] == 3
    assert "snippet" not in it  # never leak raw matched content


def test_items_severity_sorted():
    r = _result_with([
        Finding("fs_access", "b", "medium", "f", 1, ""),
        Finding("secret", "a", "critical", "f", 2, ""),
        Finding("unsafe_exec", "c", "high", "f", 3, ""),
    ])
    sev = [i["severity"] for i in _scan_result_to_dict(r)["findings"]["items"]]
    assert sev == ["critical", "high", "medium"]


def test_items_capped_at_100():
    r = _result_with([Finding("fs_access", "x", "medium", "f", i, "") for i in range(250)])
    assert len(_scan_result_to_dict(r)["findings"]["items"]) == 100


def test_items_signed_into_attestation():
    r = _result_with([Finding("toxic_flow", "trifecta", "high", "tool.py", 5, "")])
    d = _scan_result_to_dict(r)
    payload = _build_scan_payload("o/r", d)
    signed_items = payload["scan"]["findings"]["items"]
    assert signed_items and signed_items[0]["name"] == "trifecta"


def test_items_list_decision_inputs_before_dependency_advisories():
    """vercel/next.js: three critical dependency advisories led the list while the
    reason named a high finding in the tool's own code. Decision inputs come first."""
    r = _result_with(
        [Finding("dependency", f"Vulnerable dependency: lib@1 (GHSA-{n})", "critical",
                 "lockfile", 1, "") for n in range(3)]
        + [Finding("dependency", "Vulnerable dependency: x@1 (GHSA-h)", "high",
                   "lockfile", 1, "")]
        + [Finding("unsafe_exec", "execSync / spawn (Node.js)", "high", "lib/run.js", 9, ""),
           Finding("fs_access", "m", "medium", "lib/a.js", 2, "")]
    )
    items = _scan_result_to_dict(r)["findings"]["items"]
    assert len(items) == 6
    assert [(i["category"], i["severity"]) for i in items] == [
        ("unsafe_exec", "high"),
        ("dependency", "critical"), ("dependency", "critical"), ("dependency", "critical"),
        ("dependency", "high"), ("fs_access", "medium"),
    ]


def test_items_cap_keeps_decision_inputs():
    r = _result_with(
        [Finding("dependency", f"Vulnerable dependency: d@{n}", "critical", "lockfile", 1, "")
         for n in range(150)]
        + [Finding("unsafe_exec", "eval of input", "high", "src/x.js", 1, "")]
    )
    items = _scan_result_to_dict(r)["findings"]["items"]
    assert len(items) == 100 and items[0]["name"] == "eval of input"
