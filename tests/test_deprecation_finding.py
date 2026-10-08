"""'Clean but abandoned': the registry's deprecation signal becomes a medium finding,
a response field, a score-page banner, an MCP line and a plugin verdict clause."""
from __future__ import annotations

from src.scanner.artifact_fetch import _npm_deprecation, _pypi_deprecation
from src.scanner.scan import ScanResult, _calculate_trust_score, _deprecation_finding


def test_npm_deprecation_message_or_flag():
    assert _npm_deprecation({"deprecated": "Package no longer supported."}) == \
        "Package no longer supported."
    assert _npm_deprecation({"deprecated": True}) == "deprecated by its maintainer"
    assert _npm_deprecation({"deprecated": ""}) is None
    assert _npm_deprecation({}) is None


def test_pypi_yanked_or_inactive():
    assert _pypi_deprecation({"info": {"yanked": True, "yanked_reason": "CVE-2025-1"}}) == \
        "release yanked: CVE-2025-1"
    assert _pypi_deprecation({"info": {"yanked": True}}) == "release yanked by its maintainer"
    assert "inactive" in _pypi_deprecation(
        {"info": {"classifiers": ["Development Status :: 7 - Inactive"]}})
    assert _pypi_deprecation({"info": {"classifiers": ["Development Status :: 5 - Stable"]}}) is None
    assert _pypi_deprecation({}) is None


def test_deprecation_is_a_medium_maintenance_finding_that_lowers_a_clean_score():
    f = _deprecation_finding("npm", "x", "1.0.0", "Package no longer supported.")
    assert (f.category, f.severity) == ("maintenance", "medium")
    assert "Package no longer supported." in f.snippet
    clean = ScanResult(repo="x", stars=0, description="", framework="")
    clean.files_scanned = clean.total_scannable_files = 40
    retired = ScanResult(repo="x", stars=0, description="", framework="")
    retired.files_scanned = retired.total_scannable_files = 40
    retired.findings = [f]
    assert _calculate_trust_score(retired) < _calculate_trust_score(clean)
    assert _calculate_trust_score(retired) > 45  # never floored like a shipped critical


def test_mcp_output_names_the_deprecation():
    from src.bridges import mcp_streamable as m
    data = {"trust_score": 70, "findings": {"items": []}, "deprecation": "Package no longer supported."}
    import inspect
    fn = next(v for k, v in vars(m).items() if callable(v) and getattr(v, "__doc__", "")
              and "Shape a /public/scan response" in (v.__doc__ or ""))
    params = inspect.signature(fn).parameters
    args = [data] + [""] * (len([p for p in params.values()
                                 if p.default is inspect.Parameter.empty]) - 1)
    out = fn(*args)
    assert "Deprecated by its maintainer" in out and "Package no longer supported." in out
    first = out.strip().splitlines()[0]
    assert first.startswith("⚠️ Review before you connect — the maintainer has deprecated "
                            "this package."), first
    assert "Clean" not in first, first
    assert "Install" not in out
