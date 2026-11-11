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


def exact_version_incidents(vulns: list[dict], version: str | None, eco: str | None,
                            name: str | None) -> list[str]:
    """Ids of compromise records (MAL- or CWE-506 GHSA) that list ``version`` itself in
    this package's ``affected[].versions``. A range alone doesn't count: this is what
    lets a version the registry removed read Do not connect without its code, so a
    record for a neighbouring version must never trip it."""
    if not version:
        return []
    out: list[str] = []
    for v in vulns or []:
        if not isinstance(v, dict) or not _is_incident(v):
            continue
        for aff in _affected_entries(v, eco, name):
            vers = aff.get("versions") if isinstance(aff, dict) else None
            if isinstance(vers, list) and version in [str(x) for x in vers]:
                vid = str(v.get("id") or "")
                if vid and vid not in out:
                    out.append(vid)
                break
    return out


def any_record_lists_version(vulns: list[dict], version: str | None, eco: str | None,
                             name: str | None) -> bool:
    """True when any OSV record lists ``version`` itself: proof the version existed."""
    if not version:
        return False
    for v in vulns or []:
        for aff in (_affected_entries(v, eco, name) if isinstance(v, dict) else []):
            vers = aff.get("versions") if isinstance(aff, dict) else None
            if isinstance(vers, list) and version in [str(x) for x in vers]:
                return True
    return False


async def fetch_osv_vulns(surface: str, name: str) -> list[dict] | None:
    """Every OSV record for the package, or None when OSV can't be read (fail-open)."""
    eco = _OSV_ECOSYSTEM.get((surface or "").lower())
    if not eco or not name:
        return None
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            resp = await client.post(
                OSV_QUERY_URL, json={"package": {"name": name, "ecosystem": eco}},
            )
            resp.raise_for_status()
            vulns = resp.json().get("vulns") or []
    except (httpx.HTTPError, ValueError, KeyError, AttributeError):
        return None
    return [v for v in vulns if isinstance(v, dict)]


async def fetch_incident_history(
    surface: str, name: str, version: str | None = None,
) -> dict:
    """Query OSV for the package's own MAL- and malware-class (CWE-506) GHSA advisories
    (incident history) and its other advisories. Fail-open; returns
    ``{"checked": False}`` on any error or unsupported ecosystem."""
    eco = _OSV_ECOSYSTEM.get((surface or "").lower())
    vulns = await fetch_osv_vulns(surface, name)
    if vulns is None or not eco:
        return {"checked": False}
    summary = summarize_incidents(vulns, version, eco, name)
    # The package's own (non-MAL) advisories ride along; scan.py turns the ones that
    # affect the scanned version into findings. Not part of the never-scored history.
    summary["advisories"] = summarize_advisories(vulns, eco, version, name)
    return summary


# --- The source repository's own published security advisories ---------------------
# A maintainer can publish a GitHub security advisory on the repository and never have
# it reviewed into GitHub's global advisory database, so OSV never sees it
# (GHSA-mvf5-2qqv-rg3c, @modelcontextprotocol/server-everything < 2.0.1: no CVE, global
# database 404, OSV empty). ``GET repos/{o}/{r}/security-advisories`` still returns it.
# Only entries naming the scanned package in its own ecosystem count: a monorepo lists
# advisories for sibling packages, and another package's range is never applied here.
# A range we cannot parse is recorded as unparsed, never read as "not affected".

GITHUB_REPO_ADVISORIES_URL = "https://api.github.com/repos/{slug}/security-advisories"
REPO_ADVISORY_SOURCE = "repository security advisory"
# OSV ecosystem id -> GitHub advisory ecosystem id.
_GH_ECOSYSTEM = {"npm": "npm", "PyPI": "pip", "crates.io": "rust"}
_REPO_ADV_TTL_S = 6 * 3600
_REPO_ADV_MAX_PAGES = 3
_repo_adv_cache: dict[str, tuple[float, list]] = {}
_CONSTRAINT_RE = re.compile(r"^\s*(>=|<=|>|<|=)?\s*v?([0-9A-Za-z][0-9A-Za-z.+\-_]*)\s*$")
_SLUG_OK_RE = re.compile(r"^[\w.-]+/[\w.-]+$")


_RANGE_NOTE_RE = re.compile(r"\([^()]*\)")
# A range that names every version, stated plainly by the maintainer.
_ALL_VERSIONS = frozenset({"*", "all", "all versions", "any", "any version"})
_HYPHEN_RE = re.compile(r"^v?([0-9][0-9A-Za-z.+\-_]*?)\s+-\s+v?([0-9][0-9A-Za-z.+\-_]*)$")
_X_RANGE_RE = re.compile(r"^v?(\d+)(?:\.(\d+))?\.[xX*]$")
_BARE_VER_RE = re.compile(r"^\s*v?\d[0-9A-Za-z.+\-_]*\s*$")
# Branch separators of an OR-ed range (`< 1.20.6; >= 2.0.0, < 2.3.0`, body-parser) and
# of its patch list (`6.24.0: 7.24.0`, undici).
_OR_RE = re.compile(r"\s*(?:;|\|\|)\s*")
_PATCH_OR_RE = re.compile(r"\s*(?:;|\|\||:(?!//))\s*")
# Suffixes that name a release, not a pre-release (`1.83.10-stable`, berriai/litellm),
# and build metadata: compared on the release part. `-rc1` / `-beta` stay pre-releases.
_RELEASE_SUFFIX_RE = re.compile(r"(?:[-.](?:stable|release|final|ga)|\+[0-9A-Za-z.\-]+)$",
                                re.IGNORECASE)


def _gh_ver(v: str) -> str:
    v = str(v or "").strip()
    prev = None
    while prev != v:
        prev, v = v, _RELEASE_SUFFIX_RE.sub("", v)
    return v
_SPACE_AND_RE = re.compile(r"\s+(?=(?:>=|<=|>|<|=))")
_WILDCARD_RE = re.compile(r"^(\d+)\.(\d+)\.[?xX*]$|^(\d+)\.[?xX*](?:\.[?xX*])?$")


def _range_parts(rng: str) -> list[str]:
    """The AND-ed constraints of a GitHub range as maintainers write it on a repository
    advisory: comma-separated (``">= 1.0.0, < 2.0.1"``), space-separated (``">= 10.0.0
    <= 15.5.27"``, vercel/next.js), joined by ``and`` (``">15.0.4 and <15.2.0"``),
    Unicode or reversed operators (``"≤ 3.6.2"``, ``"=< 2.16.0"``, withastro/astro), and
    a note in parentheses (``"(all versions)"``) dropped. In ``patched_versions`` an
    ``and`` that means OR reads as AND: fewer releases patched, the conservative side."""
    rng = rng.replace("≤", "<=").replace("≥", ">=").replace("＜", "<").replace("＞", ">")
    rng = rng.replace("=<", "<=").replace("=>", ">=")
    rng = re.sub(r"\s+and\s+|\s*&&\s*", ",", rng, flags=re.IGNORECASE)
    rng = _RANGE_NOTE_RE.sub(" ", rng).strip()
    if rng.lower() in _ALL_VERSIONS:
        return [">= 0"]
    hm = _HYPHEN_RE.match(rng)
    if hm:  # `0.26.0 - 0.28.16`: inclusive at both ends (npm semver hyphen range)
        return [">= " + hm.group(1), "<= " + hm.group(2)]
    xm = _X_RANGE_RE.match(rng)
    if xm:  # `2.x` / `2.3.x`: that line only
        if xm.group(2) is None:
            major = int(xm.group(1))
            return [f">= {major}.0.0", f"< {major + 1}.0.0"]
        major, minor = int(xm.group(1)), int(xm.group(2))
        return [f">= {major}.{minor}.0", f"< {major}.{minor + 1}.0"]
    out = []
    for part in rng.split(","):
        out += [x for x in _SPACE_AND_RE.split(part.strip()) if x.strip()]
    return out


def gh_range_affects(rng, eco: str, version: str | None) -> bool | None:
    """Does a GitHub ``vulnerable_version_range`` (``">= 1.0.0, < 2.0.1"``, ``"= 1.2.3"``,
    ``"< 2.0"``; comma means AND) include ``version``? None when the range or the
    version cannot be parsed, so the caller never treats it as "not affected"."""
    if not isinstance(rng, str) or not rng.strip() or not version:
        return None
    cur = _parse_version(eco, _gh_ver(version))
    if cur is None:
        return None
    bounds = []
    parts = _range_parts(rng)
    if not parts:
        return None
    # `7.0.0 < 7.24.0` (nodejs/undici): a bare version followed by an upper bound is
    # the branch's floor.
    for i in range(len(parts) - 1):
        nxt = _CONSTRAINT_RE.match(parts[i + 1])
        if (_BARE_VER_RE.match(parts[i]) and nxt
                and (nxt.group(1) or "") in ("<", "<=")):
            parts[i] = ">= " + parts[i].strip()
    for part in parts:
        m = _CONSTRAINT_RE.match(part)
        if not m:
            return None
        bound = _parse_version(eco, _gh_ver(m.group(2)))
        if bound is None:
            return None
        bounds.append((m.group(1) or "=", bound))
    for op, bound in bounds:
        ok = {">=": cur >= bound, ">": cur > bound, "<=": cur <= bound,
              "<": cur < bound, "=": cur == bound}[op]
        if not ok:
            return False
    return True


def gh_patched_includes(raw, eco: str, version: str | None) -> bool | None:
    """Is ``version`` inside a GitHub ``patched_versions`` value? The repository
    advisory LIST endpoint can publish an open-ended ``vulnerable_version_range``
    (axios GHSA-898c-q2cr-xwhg: ``">=1.0.0"``) and carry the fix only here
    (``">=1.16.0"``); the global database shows the same advisory as ``>= 1.0.0,
    < 1.16.0``. A bare version (``"2.0.1"``) is the first patched release, read as
    ``>= 2.0.1``. Parts joined by commas are ANDed, which for a list of per-branch
    first fixes (``"1.2.3, 2.0.1"``) reads only the highest as patched: the
    conservative side. None when absent or unparsable."""
    if not isinstance(raw, str) or not raw.strip() or not version:
        return None
    parts = []
    for part in _range_parts(raw):
        part = part.strip()
        if part[0].isdigit() or part[0] in "vV":
            part = ">= " + _wildcard_floor(part.lstrip("vV"))
        parts.append(part)
    if not parts:
        return None
    return gh_range_affects(", ".join(parts), eco, version)


def _wildcard_floor(ver: str) -> str:
    """``"16.3.?"`` (some 16.3.x release): every release from 16.4.0 on is patched for
    certain, so the floor is the NEXT line, never 16.3.0 (the conservative side)."""
    m = _WILDCARD_RE.match(ver.strip())
    if not m:
        return ver
    if m.group(1) is not None:
        return f"{m.group(1)}.{int(m.group(2)) + 1}.0"
    return f"{int(m.group(3)) + 1}.0.0"


def _line(eco: str, ver: str):
    """The release line of a version: its major, or major.minor below 1.0."""
    m = re.match(r"^v?(\d+)(?:\.(\d+))?", ver.strip())
    if not m:
        return None
    major, minor = int(m.group(1)), int(m.group(2) or 0)
    return (major, minor) if major == 0 else (major,)


def gh_patched_on_line(vulns: list, eco: str, version: str | None) -> bool:
    """A repository advisory lists one ``vulnerabilities[]`` entry per release line
    (next-auth GHSA-5jpx-9hw9-2fx4: ``<4.24.12`` fixed in 4.24.12, and
    ``<5.0.0-beta.30``). ``version`` is patched when an entry's first patched release
    is on the same line (same major; same major.minor below 1.0) and ``version`` is at
    or above it, as GitHub's global database reads the same advisory."""
    if not version:
        return False
    version = _gh_ver(version)
    cur = _parse_version(eco, version)
    if cur is None or _line(eco, version) is None:
        return False
    fixes = []
    for v in vulns:
        raw = str((v or {}).get("patched_versions") or "").strip()
        for part in _range_parts(raw) if raw else []:
            part = part.strip().lstrip(">=").strip().lstrip("vV")
            if not part or not part[0].isdigit():
                continue
            part = _gh_ver(part)
            fix = _parse_version(eco, part)
            if fix is not None and _line(eco, part) is not None:
                fixes.append((part, fix))
    # Several fixes on one major are per-minor branches (pydantic v1.8.2, v1.7.4,
    # v1.6.2): match on major.minor, so 1.8.1 is not covered by 1.7.4.
    majors = [_line(eco, p)[0] for p, _ in fixes]
    fine = len(majors) != len(set(majors))

    def line_of(ver: str):
        ln = _line(eco, ver)
        if ln is not None and fine and len(ln) == 1:
            m = re.match(r"^v?(\d+)(?:\.(\d+))?", ver)
            return (ln[0], int(m.group(2) or 0))
        return ln

    mine = line_of(version)
    return any(line_of(p) == mine and cur >= f for p, f in fixes)


def _open_ended(rng) -> bool:
    """A vulnerable range with no upper bound (``">=1.0.0"``): its fix, if any, is only
    in ``patched_versions``."""
    if not isinstance(rng, str):
        return True
    for part in rng.split(","):
        m = _CONSTRAINT_RE.match(part)
        if m and (m.group(1) or "=") in ("<", "<=", "="):
            return False
    return True


def gh_vuln_affects(v: dict, eco: str, version: str | None) -> bool | None:
    """One ``vulnerabilities[]`` entry of a repository advisory against ``version``.

    An OR-ed range (``;`` / ``||``) is read branch by branch, each with its own patch
    when the patch list has one entry per branch (undici ``6.24.0: 7.24.0``): affected
    if any branch affects; None if a branch cannot be read and none affects."""
    rng = v.get("vulnerable_version_range")
    raw_patch = v.get("patched_versions")
    if isinstance(rng, str) and _OR_RE.search(rng):
        branches = [b for b in _OR_RE.split(rng.strip()) if b]
        pats = ([p for p in _PATCH_OR_RE.split(raw_patch.strip()) if p]
                if isinstance(raw_patch, str) and raw_patch.strip() else [])
        if len(pats) != len(branches):
            pats = [raw_patch] * len(branches)
        results = [_gh_branch_affects(b, p, eco, version) for b, p in zip(branches, pats)]
        if any(r is True for r in results):
            return True
        return None if any(r is None for r in results) else False
    return _gh_branch_affects(rng, raw_patch, eco, version)


def _gh_branch_affects(rng, raw_patch, eco: str, version: str | None) -> bool | None:
    """Inside ``rng`` and not inside ``raw_patch``. None when it cannot be told: the
    range is unparsable; the range is open-ended and the patch is present but
    unparsable; or the range names every version (``all``) with fixes listed only for
    older release lines than ``version``'s (pydantic ``all`` / ``v1.8.2,v1.7.4,
    v1.6.2`` says nothing about 2.x)."""
    all_like = isinstance(rng, str) and _RANGE_NOTE_RE.sub(" ", rng).strip().lower() \
        in _ALL_VERSIONS
    if all_like and isinstance(raw_patch, str) and raw_patch.strip():
        if gh_patched_on_line([{"patched_versions": raw_patch}], eco, version):
            return False
        lines = [_line(eco, _gh_ver(x.strip().lstrip(">=").strip().lstrip("vV")))
                 for x in _range_parts(raw_patch)]
        lines = [x for x in lines if x is not None]
        mine = _line(eco, _gh_ver(version or ""))
        if not lines or mine is None or mine > max(lines):
            return None
        return True
    r = gh_range_affects(rng, eco, version)
    if not r:
        return r
    p = gh_patched_includes(raw_patch, eco, version)
    if p is True:
        return False
    if p is None and isinstance(raw_patch, str) and raw_patch.strip() and _open_ended(rng):
        return None
    return True


def _patched(v: dict) -> str | None:
    raw = str(v.get("patched_versions") or "").strip()
    raw = raw.split(",", 1)[0].strip().lstrip(">=").strip()
    return raw or None


def summarize_repo_advisories(advisories: list, eco: str, name: str,
                              version: str | None) -> list[dict]:
    """Pure reducer: a repository's published security advisories -> entries in the same
    shape as ``summarize_advisories``, for the scanned package only (exact name in the
    same ecosystem). ``eco`` is the OSV ecosystem id. Each entry carries
    ``source = "repository security advisory"`` and ``range_unparsed`` when no range for
    this package could be read (then ``affects_scanned_version`` is False and the entry
    is disclosed, not scored)."""
    gh_eco = _GH_ECOSYSTEM.get(eco)
    if not gh_eco or not name:
        return []
    want = _norm_pkg(eco, name)
    out: list[dict] = []
    seen: set[str] = set()
    for a in advisories if isinstance(advisories, list) else []:
        if not isinstance(a, dict) or a.get("withdrawn_at"):
            continue
        if a.get("state") not in (None, "published"):
            continue
        ghsa = str(a.get("ghsa_id") or "").strip()
        if not ghsa or ghsa in seen:
            continue
        mine = []
        for v in a.get("vulnerabilities") or []:
            pkg = v.get("package") if isinstance(v, dict) else None
            if not isinstance(pkg, dict):
                continue
            if str(pkg.get("ecosystem") or "").lower() != gh_eco:
                continue
            if _norm_pkg(eco, str(pkg.get("name") or "")) == want:
                mine.append(v)
        if not mine:
            continue
        seen.add(ghsa)
        affected, unparsed, fixed = False, False, None
        if gh_patched_on_line(mine, eco, version):
            mine_checked = []  # patched on its own release line: not affected
        else:
            mine_checked = mine
        for v in mine_checked:
            r = gh_vuln_affects(v, eco, version)
            if r is None:
                unparsed = True
            elif r:
                affected = True
                fixed = fixed or _patched(v)
        if fixed is None and not affected:
            # Only for context on an unaffected version: never name another range's fix
            # as the upgrade for a version in a range that has none.
            fixed = next((p for p in (_patched(v) for v in mine) if p), None)
        cve = str(a.get("cve_id") or "").strip()
        out.append({
            "id": ghsa,
            "aliases": [cve] if cve else [],
            "summary": str(a.get("summary") or "").strip()[:200],
            "severity": _SEVERITY.get(str(a.get("severity") or "").upper(), "medium"),
            "fixed_in": fixed,
            "last_affected": None,
            "affects_scanned_version": affected,
            "range_unparsed": unparsed and not affected,
            "source": REPO_ADVISORY_SOURCE,
            "url": str(a.get("html_url") or "")[:300] or None,
        })
    out.sort(key=lambda x: (not x["affects_scanned_version"], x["id"]))
    return out[:20]


def merge_advisories(existing: list[dict], extra: list[dict]) -> list[dict]:
    """The ``extra`` entries whose id and aliases are not already in ``existing``."""
    known: set[str] = set()
    for a in existing or []:
        known.add(str(a.get("id") or ""))
        known |= {str(x) for x in (a.get("aliases") or [])}
    known.discard("")
    out = []
    for a in extra or []:
        ids = {str(a.get("id") or "")} | {str(x) for x in (a.get("aliases") or [])}
        ids.discard("")
        if ids & known:
            continue
        known |= ids
        out.append(a)
    return out


_REDIRECT_STATUSES = (301, 302, 307, 308)
_REPO_ID_ADVISORIES_RE = re.compile(r"/repositories/\d+/security-advisories")


def _repo_advisory_redirect(location: str | None) -> str | None:
    """The id-based advisories URL a renamed repo redirects to, or None. Accepted only
    as ``https://api.github.com/repositories/<id>/security-advisories`` (a query string
    is allowed and dropped: the caller sends its own); any other host, scheme, port,
    credentials or path is refused."""
    from urllib.parse import urlsplit
    if not isinstance(location, str) or not location:
        return None
    try:
        u = urlsplit(location)
        port = u.port
    except ValueError:
        return None
    if (u.scheme != "https" or u.hostname != "api.github.com" or port not in (None, 443)
            or u.username or u.password or u.netloc.lower() != "api.github.com"
            or not _REPO_ID_ADVISORIES_RE.fullmatch(u.path)):
        return None
    return f"https://api.github.com{u.path}"


async def fetch_repo_advisories(slug: str, token: str | None = None) -> dict:
    """The repository's published security advisories (raw GitHub records).
    ``{"checked": True, "advisories": [...]}`` on success, cached per repository for
    6 hours; ``{"checked": False, ...}`` on any error, 404 or rate limit, which the
    caller discloses rather than reading as "no advisories". Uses the server token when
    one is configured (the endpoint is public; the token only raises the rate limit)."""
    slug = str(slug or "").strip().lower()
    if not _SLUG_OK_RE.match(slug):
        return {"checked": False, "reason": "bad_slug"}
    import time
    hit = _repo_adv_cache.get(slug)
    now = time.monotonic()
    if hit and now - hit[0] < _REPO_ADV_TTL_S:
        return {"checked": True, "advisories": hit[1], "cached": True}
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    found: list = []
    url = GITHUB_REPO_ADVISORIES_URL.format(slug=slug)
    redirected = False
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT) as client:
            page = 1
            while page <= _REPO_ADV_MAX_PAGES:
                resp = await client.get(
                    url, headers=headers,
                    params={"state": "published", "per_page": 100, "page": page},
                )
                if resp.status_code in _REDIRECT_STATUSES and not redirected:
                    # A renamed or transferred repo: GitHub answers with its id-based
                    # address. Followed once, and only to that exact endpoint.
                    moved = _repo_advisory_redirect(resp.headers.get("location"))
                    if moved is None:
                        return {"checked": False, "reason": f"http_{resp.status_code}"}
                    url, redirected = moved, True
                    continue
                if resp.status_code != 200:
                    return {"checked": False, "reason": f"http_{resp.status_code}"}
                batch = resp.json()
                if not isinstance(batch, list):
                    return {"checked": False, "reason": "bad_body"}
                found.extend(b for b in batch if isinstance(b, dict))
                if len(batch) < 100:
                    break
                page += 1
    except (httpx.HTTPError, ValueError):
        return {"checked": False, "reason": "error"}
    _repo_adv_cache[slug] = (now, found)
    return {"checked": True, "advisories": found}
