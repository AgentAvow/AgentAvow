"""Shared safe / needs-review verdict derivation.

ONE source of truth for the binary verdict and its machine-readable reason, so the
public API JSON (`PublicScanResponse`) and the MCP connector (`mcp_streamable`) can
never disagree about whether a target is "safe to connect" or why.

Pure functions over a scan-result dict — no imports, no I/O, no side effects. The dict
shape is the same whether it comes straight from the scanner (API) or round-trips
through the public JSON (MCP), so both callers get identical answers.

Hard rule: adoption/popularity is NEVER a verdict input (popular != safe). The verdict
is code-analysis only, matching the signed trust_score.
"""
from __future__ import annotations

SAFE_BAR = 81  # A/A+ floor for the binary "safe" call (matches the site verdict)


def is_safe(data: dict) -> bool:
    """True iff trust_score >= SAFE_BAR AND there is no critical/high finding.

    Prefers the authoritative ``certified.checks.no_critical_or_high`` flag; falls back
    to scanning the (severity-sorted) findings items when that flag is absent.
    """
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    checks = (data.get("certified") or {}).get("checks") or {}
    no_blocking = checks.get("no_critical_or_high")
    if not isinstance(no_blocking, bool):
        no_blocking = not any(i.get("severity") in ("critical", "high") for i in items)
    return score >= SAFE_BAR and bool(no_blocking) and not sandbox_alarm(data)


def sandbox_alarm(data: dict) -> bool:
    """True when the behavioral sandbox caught something that must block a 'safe' call:
    a leaked canary credential, or a high/critical behavioral finding. Reads the public
    ``behavioral`` block (absent/pending → False)."""
    b = data.get("behavioral")
    if not isinstance(b, dict) or not b.get("ran"):
        return False
    if b.get("canary_exfil"):
        return True
    return any(str(f.get("severity")) in ("critical", "high")
               for f in (b.get("findings") or []) if isinstance(f, dict))


def verdict_reason(data: dict, safe: bool | None = None) -> str:
    """Machine-readable 'why' behind the verdict:

    - ``clean``             — safe.
    - ``blocking_findings`` — held back by a critical/high finding (real risk).
    - ``sandbox_finding``   — the behavioral sandbox caught it (undeclared egress,
                              a read-only tool that wrote, a leaked canary credential).
    - ``known_vulnerability`` — a published advisory (GHSA/CVE) affects this version.
    - ``deprecated``        — no risk found; the maintainer retired the package.
    - ``thin_coverage``     — no risk found, but too little code to inspect (<8 files).
    - ``low_signals``       — no risk found, held down by non-finding signals
                              (maintainer/provenance/adoption), not detected risk.

    Pass ``safe`` if already computed to avoid recomputing it.
    """
    if safe is None:
        safe = is_safe(data)
    if safe:
        return "clean"
    items = (data.get("findings") or {}).get("items") or []
    if any(i.get("severity") in ("critical", "high") for i in items):
        return "blocking_findings"
    if sandbox_alarm(data):
        return "sandbox_finding"
    if any(i.get("category") == "known_vulnerability" for i in items) or any(
            a.get("affects_scanned_version") for a in (data.get("advisories") or [])
            if isinstance(a, dict)):
        return "known_vulnerability"
    dep = data.get("deprecation")
    if isinstance(dep, str) and dep.strip():
        return "deprecated"
    files = (data.get("metadata") or {}).get("files_scanned")
    return "thin_coverage" if isinstance(files, int) and 0 < files < 8 else "low_signals"


def verdict_label(safe: bool) -> str:
    """The stable public string for the binary state."""
    return "safe" if safe else "needs_review"
