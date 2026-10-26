"""Incident-history lookup — has THIS package ever been caught being malicious?

Context-only threat-intel: queries OSV for the TARGET coordinate's own ``MAL-`` advisories
(the OpenSSF ``malicious-packages`` dataset — "malicious code in X" compromise events)
and its malware-class GitHub advisories (a GHSA tagged CWE-506, Embedded Malicious Code:
the 2018 event-stream / flatmap-stream compromise has only that record, no MAL- one),
distinct from ``supply_chain`` which checks the target's DEPENDENCIES.

HARD RULES:
- NEVER scored and NEVER signed into the attestation — it is historical context, not a
  code-analysis finding. A package that was compromised and cleaned keeps its current
  (clean) score; the history is shown, not penalised. Only a currently-affected version
  is a live signal (``current_version_affected``), surfaced for the caller to escalate.
- Fail-open: any error / unsupported ecosystem → ``{"checked": False}``; never breaks a scan.
"""
from __future__ import annotations

import re

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


# GitHub's CWE for a malware advisory. A GHSA carrying it (``database_specific.cwe_ids``)
# records a compromise, not a code flaw: GHSA-mh6f-8j2x-4483 (event-stream 3.3.6 /
# flatmap-stream), GHSA-pjwm-rvh2-c87w (ua-parser-js 0.7.29 / 0.8.0 / 1.0.0).
_MALWARE_CWES = frozenset({"CWE-506"})


def _is_malware_ghsa(vuln: dict) -> bool:
    """True if the advisory is a GitHub (GHSA) record classed as malware (CWE-506)."""
    if not str(vuln.get("id", "")).upper().startswith("GHSA-"):
        return False
    ds = vuln.get("database_specific")
    cwes = ds.get("cwe_ids") if isinstance(ds, dict) else None
    if not isinstance(cwes, list):
        return False
    return any(str(c).strip().upper() in _MALWARE_CWES for c in cwes)


def _is_incident(vuln: dict) -> bool:
    """A compromise record for incident history: an OpenSSF MAL- record (or one aliased
    to it), or a malware-class (CWE-506) GHSA."""
    return _is_mal(vuln) or _is_malware_ghsa(vuln)


def _norm_pkg(eco: str, name: str) -> str:
    n = str(name or "").strip().lower()
    return re.sub(r"[-_.]+", "-", n) if eco == "PyPI" else n


def _affected_entries(vuln: dict, eco: str | None = None, name: str | None = None) -> list:
    """The advisory's ``affected`` entries for THIS package. One advisory can cover several
    packages (GHSA-f29h-pxvx-f335 lists eslint-config-prettier, synckit, got-fetch …), and
    another package's range must never be applied to the scanned one. Entries without a
    package name are kept (single-package records)."""
    entries = [a for a in (vuln.get("affected") or []) if isinstance(a, dict)]
    if not name:
        return entries
    want = _norm_pkg(eco or "", name)
    out = []
    for a in entries:
        pkg = a.get("package") or {}
        pname = pkg.get("name") if isinstance(pkg, dict) else None
        peco = pkg.get("ecosystem") if isinstance(pkg, dict) else None
        if eco and peco and str(peco).split(":", 1)[0].lower() != eco.lower():
            continue  # same name in another ecosystem (NuGet jQuery, Maven webjars …)
        if not pname or _norm_pkg(eco or "", pname) == want:
            out.append(a)
    return out


def _own_entries(vuln: dict, eco: str, name: str) -> list:
    """The ``affected`` entries that name THIS package in THIS ecosystem, exactly. Unlike
    ``_affected_entries`` an entry without a package name or ecosystem does not count:
    a range is only ever applied to the package it was written for (#166)."""
    want = _norm_pkg(eco, name)
    out = []
    for a in (vuln.get("affected") or []):
        pkg = a.get("package") if isinstance(a, dict) else None
        if not isinstance(pkg, dict):
            continue
        pname, peco = pkg.get("name"), pkg.get("ecosystem")
        if not pname or not peco or str(peco).split(":", 1)[0].lower() != eco.lower():
            continue
        if _norm_pkg(eco, pname) == want:
            out.append(a)
    return out


def _version_affected(vuln: dict, version: str | None, eco: str | None = None,
                      name: str | None = None) -> bool:
    """Is ``version`` affected by this malware-class advisory (an incident)?

    * listed among the advisory's affected ``versions``; or
    * (2026-10-26) inside one of its ranges, evaluated for real, for the scanned
      package's OWN entries only (exact name + ecosystem). ``introduced: 0`` with no
      ``fixed`` / ``last_affected`` is every version (flatmap-stream's CWE-506 GHSA, a
      package that was malware from the start). A range closed by a fix leaves a clean
      later release clean (ua-parser-js 0.7.29 / 0.8.0 / 1.0.0 -> latest stays clean).

    A withdrawn advisory affects nothing. An unparseable version or a range type other
    than SEMVER / ECOSYSTEM resolves to False."""
    if not version or vuln.get("withdrawn"):
        return False
    for aff in _affected_entries(vuln, eco, name):
        for v in (aff.get("versions") or []):
            if str(v) == str(version):
                return True
    if not eco or not name:
        return False
    return any(_range_affects(r, eco, version)
               for aff in _own_entries(vuln, eco, name)
               for r in (aff.get("ranges") or []) if isinstance(r, dict))


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


def advisory_affects(vuln: dict, eco: str, version: str | None,
                     name: str | None = None) -> bool:
    """Does this advisory affect ``version`` of package ``name`` (explicit versions list
    or ranges)? Only the entries for ``name`` count when it is given."""
    if not version:
        return False
    for aff in _affected_entries(vuln, eco, name):
        if str(version) in [str(v) for v in (aff.get("versions") or [])]:
            return True
        if any(_range_affects(r, eco, version) for r in (aff.get("ranges") or [])):
            return True
    return False


def _fixed_in(vuln: dict, eco: str | None = None, name: str | None = None,
              version: str | None = None) -> str | None:
    entries = _affected_entries(vuln, eco, name)
    if version and eco:
        # Prefer the range the scanned version sits in (an advisory can list one per
        # release line: 8.10.x, 9.1.x, 10.1.x).
        for aff in entries:
            for r in aff.get("ranges") or []:
                if _range_affects(r, eco, version):
                    for ev in r.get("events") or []:
                        if "fixed" in ev:
                            return str(ev["fixed"])
    for aff in entries:
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "fixed" in ev:
                    return str(ev["fixed"])
    return None


def _last_affected(vuln: dict, eco: str | None = None, name: str | None = None) -> str | None:
    """The highest ``last_affected`` bound in this package's ranges, for an advisory whose
    range is closed by a last affected release rather than a fix (GHSA-53gh-p8jc-7rg8:
    introduced 1.40.3.dev2, last_affected 1.40.12). None when no range has one."""
    best: tuple | None = None
    for aff in _affected_entries(vuln, eco, name):
        for r in aff.get("ranges") or []:
            for ev in r.get("events") or []:
                if "last_affected" not in ev:
                    continue
                raw = str(ev["last_affected"])
                key = _parse_version(eco or "", raw)
                if best is None or (key is not None and (best[0] is None or key > best[0])):
                    best = (key, raw)
    return best[1] if best else None


def summarize_advisories(vulns: list[dict], eco: str, version: str | None,
                         name: str | None = None) -> list[dict]:
    """Non-MAL advisories for the package itself, with whether the scanned version is
    affected. Deduplicated by alias (GHSA and PYSEC records describe the same flaw).

    A malware-class (CWE-506) GHSA stays here even though incident history also lists
    it: incident history is never scored (an affected version decides Do not connect
    instead), while this list scores an affected version as a finding, so dropping it
    would lose that finding.

    ``fixed_in`` is the release that fixes it; when the record has no fix event,
    ``last_affected`` is the newest release it names as affected, so a reader is told
    why the scanned version is clear ("affected up to 1.40.12") instead of "fixed"."""
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
            "fixed_in": _fixed_in(v, eco, name, version),
            "last_affected": _last_affected(v, eco, name),
            "affects_scanned_version": advisory_affects(v, eco, version, name),
        })
    out.sort(key=lambda a: (not a["affects_scanned_version"], a["id"] or ""))
    return out[:20]


def summarize_incidents(vulns: list[dict], version: str | None = None,
                        eco: str | None = None, name: str | None = None) -> dict:
    """Pure reducer: OSV vulns -> the context-only incident_history dict. Network-free
    and unit-testable in isolation.

    An incident is a MAL- record or a malware-class (CWE-506) GHSA. Records that alias
    each other (debug's GHSA-4x49-vf9v-38px and MAL-2025-46974) are one incident: the
    MAL- record is kept, and the scanned version counts as affected if either lists it."""
    incidents: list[dict] = []
    current_affected = False
    seen: list[tuple[set, dict]] = []
    # Records whose own id is MAL- first, so the OpenSSF record is the one kept for an
    # aliased pair (stable sort: OSV's order otherwise).
    for v in sorted((v for v in vulns if isinstance(v, dict) and _is_incident(v)),
                    key=lambda v: not str(v.get("id", "")).upper().startswith("MAL-")):
        aff = _version_affected(v, version, eco, name)
        current_affected = current_affected or aff
        ids = {str(v.get("id", ""))} | {str(a) for a in (v.get("aliases") or [])}
        ids.discard("")
        dup = next((rec for known, rec in seen if known & ids), None)
        if dup is not None:
            dup["current_version_affected"] = dup["current_version_affected"] or aff
            continue
        current_affected = current_affected or aff
        rec = {
            "id": v.get("id"),
            "summary": (v.get("summary") or "").strip()[:200],
            "published": v.get("published"),
            "aliases": [a for a in (v.get("aliases") or []) if isinstance(a, str)][:5],
            "current_version_affected": aff,
        }
        seen.append((ids, rec))
        incidents.append(rec)
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
    """Query OSV for the package's own MAL- and malware-class (CWE-506) GHSA advisories
    (incident history) and its other advisories. Fail-open; returns
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
    summary = summarize_incidents(vulns, version, eco, name)
    # The package's own (non-MAL) advisories ride along; scan.py turns the ones that
    # affect the scanned version into findings. Not part of the never-scored history.
    summary["advisories"] = summarize_advisories(vulns, eco, version, name)
    return summary
