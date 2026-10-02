"""Incident-history lookup — has THIS package ever been caught being malicious?

Context-only threat-intel: queries OSV for the TARGET coordinate's own ``MAL-`` advisories
(the OpenSSF ``malicious-packages`` dataset — "malicious code in X" compromise events),
distinct from ``supply_chain`` which checks the target's DEPENDENCIES.

HARD RULES:
- NEVER scored and NEVER signed into the attestation — it is historical context, not a
  code-analysis finding. A package that was compromised and cleaned keeps its current
  (clean) score; the history is shown, not penalised. Only a currently-affected version
  is a live signal (``current_version_affected``), surfaced for the caller to escalate.
- Fail-open: any error / unsupported ecosystem → ``{"checked": False}``; never breaks a scan.
"""
from __future__ import annotations

import httpx

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
_HTTP_TIMEOUT = 8.0

# Our surface id -> OSV ecosystem id. Docker / Hugging Face are not OSV ecosystems, so
# incident-history is npm / PyPI / crates only.
_OSV_ECOSYSTEM = {"npm": "npm", "pypi": "PyPI", "crates": "crates.io"}


def _is_mal(vuln: dict) -> bool:
    """True if the advisory is an OpenSSF known-malicious (MAL-) record."""
    vid = str(vuln.get("id", "")).upper()
    if vid.startswith("MAL-"):
        return True
    return any(str(a).upper().startswith("MAL-") for a in (vuln.get("aliases") or []))


def _version_affected(vuln: dict, version: str | None) -> bool:
    """Best-effort: is ``version`` explicitly listed among the advisory's affected
    versions? Conservative — unknown ranges resolve to False (treat as historical, not a
    live warning), so we never over-claim that the current version is compromised."""
    if not version:
        return False
    for aff in (vuln.get("affected") or []):
        for v in (aff.get("versions") or []):
            if str(v) == str(version):
                return True
    return False


# --- The package's OWN published vulnerabilities (non-MAL advisories) --------------
# Unlike MAL- incident history, a published advisory that AFFECTS THE SCANNED VERSION is
# a real, current code-security fact about the target itself, so it IS raised as a
# finding by the scanner (scan.py). Advisories fixed before the scanned version are
# context only. Deterministic given the OSV response, so the grade stays recomputable
# from the evidence recorded in the attestation (advisory ids + versions).

_SEVERITY = {"CRITICAL": "critical", "HIGH": "high", "MODERATE": "medium",
             "MEDIUM": "medium", "LOW": "low"}


def _parse_version(eco: str, v: str):
    """A comparable key for ``v`` in ``eco``; None when unparseable (→ not affected)."""
    v = str(v or "").strip()
    if not v:
        return None
    if eco == "PyPI":
        try:
            from packaging.version import Version
            return Version(v)
        except Exception:
            return None
    # npm / crates: semver. Pre-release sorts before the release.
    core, _, pre = v.lstrip("v").partition("-")
    core = core.split("+", 1)[0]
    try:
        nums = tuple(int(x) for x in core.split("."))
    except ValueError:
        return None
    nums = (nums + (0, 0, 0))[:3]
    return (nums, 0 if pre else 1, pre)


def _range_affects(rng: dict, eco: str, version: str) -> bool:
    if (rng.get("type") or "").upper() not in ("SEMVER", "ECOSYSTEM"):
        return False
    cur = _parse_version(eco, version)
    if cur is None:
        return False
    affected = False
    for ev in rng.get("events") or []:
        if "introduced" in ev:
            intro = ev["introduced"]
            iv = _parse_version(eco, intro) if intro != "0" else None
            if intro == "0" or (iv is not None and cur >= iv):
                affected = True
        elif "fixed" in ev:
            fv = _parse_version(eco, ev["fixed"])
            if fv is not None and cur >= fv:
                affected = False
        elif "last_affected" in ev:
            lv = _parse_version(eco, ev["last_affected"])
            if lv is not None and cur > lv:
                affected = False
    return affected


def advisory_affects(vuln: dict, eco: str, version: str | None) -> bool:
    """Does this advisory affect ``version`` (explicit versions list or ranges)?"""
    if not version:
        return False
    for aff in vuln.get("affected") or []:
        if str(version) in [str(v) for v in (aff.get("versions") or [])]:
            return True
        if any(_range_affects(r, eco, version) for r in (aff.get("ranges") or [])):
            return True
    return False


def _fixed_in(vuln: dict) -> str | None:
    for aff in vuln.get("affected") or []:
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    return str(ev["fixed"])
    return None


def summarize_advisories(vulns: list[dict], eco: str, version: str | None) -> list[dict]:
    """Non-MAL advisories for the package itself, with whether the scanned version is
    affected. Deduplicated by alias (GHSA and PYSEC records describe the same flaw)."""
    out: list[dict] = []
    seen: set[str] = set()
    for v in vulns:
        if _is_mal(v):
            continue
        ids = {str(v.get("id", ""))} | {str(a) for a in (v.get("aliases") or [])}
        if ids & seen:
            continue
        seen |= ids
        sev = _SEVERITY.get(str((v.get("database_specific") or {}).get("severity") or "")
                            .upper(), "medium")
        primary = next((i for i in sorted(ids) if i.startswith("GHSA-")), v.get("id"))
        out.append({
            "id": primary,
            "aliases": sorted(i for i in ids if i and i != primary)[:5],
            "summary": (v.get("summary") or "").strip()[:200],
            "severity": sev,
            "fixed_in": _fixed_in(v),
            "affects_scanned_version": advisory_affects(v, eco, version),
        })
    out.sort(key=lambda a: (not a["affects_scanned_version"], a["id"] or ""))
    return out[:20]


def summarize_incidents(vulns: list[dict], version: str | None = None) -> dict:
    """Pure reducer: OSV vulns -> the context-only incident_history dict. Network-free
    and unit-testable in isolation."""
    incidents: list[dict] = []
    current_affected = False
    for v in vulns:
        if not _is_mal(v):
            continue
        aff = _version_affected(v, version)
        current_affected = current_affected or aff
        incidents.append({
            "id": v.get("id"),
            "summary": (v.get("summary") or "").strip()[:200],
            "published": v.get("published"),
            "aliases": [a for a in (v.get("aliases") or []) if isinstance(a, str)][:5],
            "current_version_affected": aff,
        })
    incidents.sort(key=lambda i: i.get("published") or "", reverse=True)
    return {
        "checked": True,
        "has_incident": bool(incidents),
        "current_version_affected": current_affected,
        "count": len(incidents),
        "incidents": incidents[:10],
    }


async def fetch_incident_history(
    surface: str, name: str, version: str | None = None,
) -> dict:
    """Query OSV for the package's own MAL- advisories. Fail-open; returns
    ``{"checked": False}`` on any error or unsupported ecosystem."""
    eco = _OSV_ECOSYSTEM.get((surface or "").lower())
    if not eco or not name:
        return {"checked": False}
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(
                OSV_QUERY_URL, json={"package": {"name": name, "ecosystem": eco}},
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulns") or []
    except (httpx.HTTPError, ValueError, KeyError):
        return {"checked": False}
    summary = summarize_incidents(vulns, version)
    # The package's own (non-MAL) advisories ride along; scan.py turns the ones that
    # affect the scanned version into findings. Not part of the never-scored history.
    summary["advisories"] = summarize_advisories(vulns, eco, version)
    return summary
