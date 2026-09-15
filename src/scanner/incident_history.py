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
    return summarize_incidents(vulns, version)
