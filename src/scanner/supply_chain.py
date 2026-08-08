"""Phase 1 — real supply-chain scoring (OSV + deps.dev + OpenSSF Scorecard).

Replaces/augments the scanner's ~20-package regex ``_VULN_DEPS`` list with a real
vulnerability database. The pipeline (all free / no-auth):

  parsed lockfiles  ── §``lockfiles.parse_all`` ──►  flat {ecosystem,name,version}
        │
        ├─ POST api.osv.dev/v1/querybatch ──► vuln IDs per dep (incl. transitive)
        ├─ GET  api.osv.dev/v1/vulns/{id} ──► hydrate severity (CVSS / GHSA)
        ├─ (opt) api.deps.dev/v3 ──► license / dependents / scorecard enrichment
        └─ (opt) api.scorecard.dev ──► OpenSSF Scorecard aggregate (precomputed)

A ``MAL-`` (OpenSSF known-malicious) match is an **automatic critical** distinct
from CVE severity — active malware, not merely "vulnerable".

Design rules that matter:
  * **Fail-open, always.** Any network/parse error returns ``ok=False`` and the
    caller keeps the legacy regex behaviour. A supply-chain lookup must NEVER
    break a scan (roadmap §5 Phase 1, and CLAUDE.md "never break a scan").
  * **Recomputable.** Every external DB records its snapshot date into
    ``db_snapshots`` so the subscore is offline-recomputable (§1.3 / Phase 0).
  * **Pure reducers** (``summarize_osv``, ``*_ratio``) are network-free and unit
    tested directly; the async ``analyze_supply_chain`` orchestrates I/O.

Findings are emitted as plain dicts (category/name/severity/…) so this module has
no import dependency on ``scan.py`` (which imports us) — ``scan.py`` maps them to
``Finding`` objects.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

import httpx

from src.scanner.lockfiles import Dep

logger = logging.getLogger(__name__)

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{vuln_id}"
DEPSDEV_VERSION_URL = (
    "https://api.deps.dev/v3/systems/{system}/packages/{name}/versions/{version}"
)
SCORECARD_URL = "https://api.scorecard.dev/projects/github.com/{owner}/{repo}"

# deps.dev "system" ids differ from OSV ecosystem ids.
_DEPSDEV_SYSTEM = {
    "npm": "npm",
    "PyPI": "pypi",
    "crates.io": "cargo",
    "Go": "go",
}

_SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}

# Cap the OSV batch so a giant lockfile can't fan out into thousands of hydrate
# calls. Direct+transitive deps beyond this are still counted for coverage.
_MAX_BATCH = 1000
_MAX_HYDRATE = 200
_HTTP_TIMEOUT = 12.0


@dataclass
class SupplyChainResult:
    """Outcome of the supply-chain pipeline for one target."""

    ok: bool = False  # True only when OSV was actually queried successfully
    findings: list[dict] = field(default_factory=list)  # scanner-Finding dicts
    deps_total: int = 0
    ecosystems: list[str] = field(default_factory=list)
    counts: dict[str, int] = field(default_factory=dict)  # severity -> count
    malicious: list[str] = field(default_factory=list)  # MAL- advisory ids
    db_snapshots: dict[str, str] = field(default_factory=dict)
    scorecard: dict | None = None
    depsdev: dict | None = None
    github_depth: dict = field(default_factory=dict)
    error: str | None = None

    @property
    def critical_count(self) -> int:
        return self.counts.get("critical", 0)

    @property
    def high_count(self) -> int:
        return self.counts.get("high", 0)


# ---------------------------------------------------------------------------
# Severity mapping (pure)
# ---------------------------------------------------------------------------

_CVSS_RE = re.compile(r"CVSS:3\.[01]/")


def _cvss_score(vector_or_num: str) -> float | None:
    """Best-effort numeric CVSS base score from an OSV ``severity`` entry.

    OSV severity entries carry either a CVSS vector string or a numeric score.
    We only need the coarse band, so a vector we can't fully parse falls back to
    ``None`` and the ``database_specific.severity`` label is used instead.
    """
    if not vector_or_num:
        return None
    s = vector_or_num.strip()
    try:
        return float(s)
    except ValueError:
        pass
    # Extremely small CVSS base-score estimator from the vector's key metrics —
    # enough to pick a band without a full CVSS library.
    if not _CVSS_RE.search(s):
        return None
    metrics = dict(
        part.split(":", 1) for part in s.split("/")[1:] if ":" in part
    )
    # Impact-weighted heuristic: any High impact + Network/Low-complexity ⇒ crit/high.
    impacts = [metrics.get(k, "N") for k in ("C", "I", "A")]
    high_impacts = sum(1 for v in impacts if v == "H")
    av_network = metrics.get("AV") == "N"
    low_complexity = metrics.get("AC") == "L"
    if high_impacts >= 2 and av_network and low_complexity:
        return 9.0
    if high_impacts >= 1 and av_network:
        return 7.5
    if high_impacts >= 1:
        return 5.5
    return 3.5


def _band_from_score(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def severity_for_vuln(vuln: dict) -> str:
    """Map one hydrated OSV vuln record to a scanner severity band.

    ``MAL-`` advisories are forced to **critical** (known-malicious, not merely
    vulnerable). Otherwise prefer a CVSS band, then a database_specific label.
    """
    vid = str(vuln.get("id", ""))
    if vid.upper().startswith("MAL-"):
        return "critical"
    aliases = vuln.get("aliases") or []
    if any(str(a).upper().startswith("MAL-") for a in aliases):
        return "critical"

    best: float | None = None
    for sev in vuln.get("severity") or []:
        if not isinstance(sev, dict):
            continue
        score = _cvss_score(str(sev.get("score", "")))
        if score is not None and (best is None or score > best):
            best = score
    if best is not None:
        return _band_from_score(best)

    # Fallback: GHSA-style label under database_specific.
    label = ""
    dbs = vuln.get("database_specific")
    if isinstance(dbs, dict):
        label = str(dbs.get("severity", "")).lower()
    if label in ("critical",):
        return "critical"
    if label in ("high",):
        return "high"
    if label in ("moderate", "medium"):
        return "medium"
    if label in ("low",):
        return "low"
    # Unknown severity — treat as medium so it still dents the grade but doesn't
    # masquerade as critical.
    return "medium"


def is_malicious(vuln: dict) -> bool:
    vid = str(vuln.get("id", "")).upper()
    if vid.startswith("MAL-"):
        return True
    return any(str(a).upper().startswith("MAL-") for a in (vuln.get("aliases") or []))


# ---------------------------------------------------------------------------
# Reducer: OSV batch + hydrated details -> findings + counts (pure)
# ---------------------------------------------------------------------------


def summarize_osv(
    deps: list[Dep],
    batch_results: list[dict],
    vuln_details: dict[str, dict],
    *,
    lockfile_path: str = "lockfile",
) -> tuple[list[dict], dict[str, int], list[str]]:
    """Reduce OSV batch + hydrated vuln records into scanner-finding dicts.

    ``batch_results`` is the OSV ``querybatch`` ``results`` array, index-aligned
    with ``deps``. ``vuln_details`` maps ``vuln_id`` -> hydrated ``/v1/vulns/{id}``
    record. Returns ``(findings, counts, malicious_ids)``.

    Pure and deterministic — the unit tests drive this with canned JSON so no
    network is involved, and a verifier can replay it from pinned inputs.
    """
    findings: list[dict] = []
    counts: dict[str, int] = {}
    malicious: list[str] = []
    seen: set[tuple[str, str]] = set()  # (dep-key, vuln-id) de-dupe

    for idx, res in enumerate(batch_results):
        if idx >= len(deps) or not isinstance(res, dict):
            continue
        dep = deps[idx]
        for v in res.get("vulns") or []:
            vid = str(v.get("id", "")) if isinstance(v, dict) else str(v)
            if not vid:
                continue
            dep_key = f"{dep.ecosystem}:{dep.name}@{dep.version}"
            if (dep_key, vid) in seen:
                continue
            seen.add((dep_key, vid))

            detail = vuln_details.get(vid, {"id": vid})
            severity = severity_for_vuln(detail)
            mal = is_malicious(detail)
            if mal:
                malicious.append(vid)
                severity = "critical"
            counts[severity] = counts.get(severity, 0) + 1

            summary = detail.get("summary") or detail.get("details") or ""
            summary = str(summary)[:160]
            kind = "Known-malicious package" if mal else "Vulnerable dependency"
            name = f"{kind}: {dep.name}@{dep.version} ({vid})"
            remediation = (
                "Remove this package immediately — it is flagged as malicious "
                "(OpenSSF MAL advisory)."
                if mal
                else f"Upgrade {dep.name} out of the {vid} affected range."
            )
            findings.append({
                "category": "dependency",
                "name": name,
                "severity": severity,
                "file_path": lockfile_path,
                "line_number": 1,
                "snippet": summary,
                "remediation": remediation,
            })
    return findings, counts, malicious


# ---------------------------------------------------------------------------
# GitHub-depth signals — cheap, from data we already fetch (pure)
# ---------------------------------------------------------------------------

_USES_RE = re.compile(r"^\s*-?\s*uses:\s*['\"]?([^'\"\s]+)", re.MULTILINE)
_SHA40_RE = re.compile(r"^[0-9a-f]{40}$")


def hash_pinned_actions_ratio(workflow_texts: list[str]) -> dict:
    """Ratio of ``uses:`` GitHub Actions pinned to a full 40-hex SHA vs a tag.

    The tj-actions/`v3`-mutable-tag vector: a floating tag can be repointed at
    malicious code post-review. Pinned-to-SHA is the hardened posture. Local
    (``./…``) and docker refs are ignored.
    """
    total = 0
    pinned = 0
    for text in workflow_texts:
        if not text:
            continue
        for ref in _USES_RE.findall(text):
            if ref.startswith(("./", "../", "docker://")):
                continue
            total += 1
            after_at = ref.rsplit("@", 1)
            if len(after_at) == 2 and _SHA40_RE.match(after_at[1]):
                pinned += 1
    ratio = round(pinned / total, 4) if total else None
    return {"pinned": pinned, "total": total, "ratio": ratio}


def signed_commit_ratio(commits: list[dict]) -> dict:
    """Ratio of recent commits with a verified GPG/SSH signature.

    ``commits`` is the GitHub ``/commits`` API array; each element's
    ``commit.verification.verified`` is a hard-to-fake behavioural signal.
    """
    total = 0
    verified = 0
    for c in commits or []:
        if not isinstance(c, dict):
            continue
        commit = c.get("commit") or {}
        ver = commit.get("verification") if isinstance(commit, dict) else None
        if not isinstance(ver, dict):
            continue
        total += 1
        if ver.get("verified") is True:
            verified += 1
    ratio = round(verified / total, 4) if total else None
    return {"verified": verified, "total": total, "ratio": ratio}


def repo_staleness(repo_meta: dict) -> dict:
    """Archived/disabled flags + push staleness in days from repo metadata."""
    out: dict = {
        "archived": bool(repo_meta.get("archived")),
        "disabled": bool(repo_meta.get("disabled")),
        "stale_days": None,
    }
    pushed = repo_meta.get("pushed_at")
    if isinstance(pushed, str):
        try:
            dt = datetime.fromisoformat(pushed.replace("Z", "+00:00"))
            out["stale_days"] = (datetime.now(timezone.utc) - dt).days
        except ValueError:
            pass
    return out


def github_depth_findings(depth: dict) -> list[dict]:
    """Turn the cheap GitHub-depth signals into a few low/medium findings.

    Deliberately conservative severities — these are config/behavioural hygiene,
    not vulnerabilities, and the anti-gaming rule (§2.G) weights them lightly.
    """
    findings: list[dict] = []
    actions = depth.get("hash_pinned_actions") or {}
    if actions.get("total", 0) >= 3 and (actions.get("ratio") or 0) < 0.5:
        findings.append({
            "category": "dependency",
            "name": (
                f"Unpinned GitHub Actions ({actions['pinned']}/{actions['total']} "
                "pinned to SHA)"
            ),
            "severity": "low",
            "file_path": ".github/workflows",
            "line_number": 1,
            "snippet": "",
            "remediation": (
                "Pin third-party Actions to a full commit SHA — a mutable tag can "
                "be repointed at malicious code (tj-actions vector)."
            ),
        })
    stale = depth.get("staleness") or {}
    if stale.get("archived"):
        findings.append({
            "category": "dependency",
            "name": "Repository is archived (unmaintained)",
            "severity": "medium",
            "file_path": "",
            "line_number": 1,
            "snippet": "",
            "remediation": "Archived repos receive no security fixes — prefer a maintained fork.",
        })
    return findings


# ---------------------------------------------------------------------------
# Async I/O layer
# ---------------------------------------------------------------------------


async def _osv_querybatch(
    deps: list[Dep], client: httpx.AsyncClient,
) -> list[dict]:
    payload = {"queries": [d.as_osv_query() for d in deps[:_MAX_BATCH]]}
    resp = await client.post(OSV_BATCH_URL, json=payload, timeout=_HTTP_TIMEOUT)
    resp.raise_for_status()
    return resp.json().get("results", []) or []


async def _osv_hydrate(
    vuln_ids: list[str], client: httpx.AsyncClient,
) -> dict[str, dict]:
    details: dict[str, dict] = {}
    for vid in vuln_ids[:_MAX_HYDRATE]:
        try:
            resp = await client.get(
                OSV_VULN_URL.format(vuln_id=vid), timeout=_HTTP_TIMEOUT,
            )
            if resp.status_code == 200:
                details[vid] = resp.json()
        except (httpx.HTTPError, ValueError):
            continue  # a single hydrate miss just falls back to id-only severity
    return details


async def _fetch_scorecard(
    owner: str, repo: str, client: httpx.AsyncClient,
) -> dict | None:
    """OpenSSF Scorecard aggregate (precomputed). 404 ⇒ omit (fall back gracefully)."""
    try:
        resp = await client.get(
            SCORECARD_URL.format(owner=owner, repo=repo), timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "score": data.get("score"),
                "date": data.get("date"),
                "checks": {
                    c.get("name"): c.get("score")
                    for c in (data.get("checks") or [])
                    if isinstance(c, dict)
                },
            }
    except (httpx.HTTPError, ValueError):
        return None
    return None


async def _fetch_depsdev(
    dep: Dep, client: httpx.AsyncClient,
) -> dict | None:
    system = _DEPSDEV_SYSTEM.get(dep.ecosystem)
    if not system:
        return None
    try:
        resp = await client.get(
            DEPSDEV_VERSION_URL.format(
                system=system, name=dep.name, version=dep.version,
            ),
            timeout=_HTTP_TIMEOUT,
        )
        if resp.status_code == 200:
            data = resp.json()
            return {
                "package": f"{dep.ecosystem}:{dep.name}@{dep.version}",
                "licenses": data.get("licenses"),
                "advisoryKeys": data.get("advisoryKeys"),
            }
    except (httpx.HTTPError, ValueError):
        return None
    return None


async def analyze_supply_chain(
    lockfiles: dict[str, str],
    *,
    owner: str = "",
    repo: str = "",
    workflow_texts: list[str] | None = None,
    repo_meta: dict | None = None,
    commits: list[dict] | None = None,
    use_depsdev: bool = True,
    use_scorecard: bool = True,
    client: httpx.AsyncClient | None = None,
) -> SupplyChainResult:
    """Run the full supply-chain pipeline. **Fail-open** on any error.

    Returns a :class:`SupplyChainResult`; ``ok`` is True only when OSV was
    actually queried. On any exception the caller keeps the legacy regex path.
    ``db_snapshots`` pins every DB date consulted for offline recompute.
    """
    from src.scanner.lockfiles import parse_all

    result = SupplyChainResult()

    # Cheap, network-free GitHub-depth signals first — always safe to compute.
    depth: dict = {}
    try:
        if workflow_texts:
            depth["hash_pinned_actions"] = hash_pinned_actions_ratio(workflow_texts)
        if repo_meta:
            depth["staleness"] = repo_staleness(repo_meta)
        if commits:
            depth["signed_commits"] = signed_commit_ratio(commits)
        if depth:
            result.github_depth = depth
            result.findings.extend(github_depth_findings(depth))
    except Exception:
        logger.debug("github-depth signal computation failed", exc_info=True)

    deps = parse_all(lockfiles)
    result.deps_total = len(deps)
    result.ecosystems = sorted({d.ecosystem for d in deps})
    if not deps:
        # No parseable lockfile — nothing for OSV to do, but depth signals stand.
        result.ok = bool(depth)
        return result

    owns_client = client is None
    if owns_client:
        client = httpx.AsyncClient(headers={"User-Agent": "AgentAvow-Scanner"})
    try:
        batch = await _osv_querybatch(deps, client)
        # Collect unique vuln ids to hydrate.
        vuln_ids: list[str] = []
        seen_ids: set[str] = set()
        for res in batch:
            if not isinstance(res, dict):
                continue
            for v in res.get("vulns") or []:
                vid = str(v.get("id", "")) if isinstance(v, dict) else str(v)
                if vid and vid not in seen_ids:
                    seen_ids.add(vid)
                    vuln_ids.append(vid)

        details = await _osv_hydrate(vuln_ids, client) if vuln_ids else {}
        findings, counts, malicious = summarize_osv(deps, batch, details)
        result.findings.extend(findings)
        result.counts = counts
        result.malicious = malicious
        result.ok = True
        result.db_snapshots["osv"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        # Optional enrichment — never gates ok/failure.
        if use_scorecard and owner and repo:
            sc = await _fetch_scorecard(owner, repo, client)
            if sc:
                result.scorecard = sc
                if sc.get("date"):
                    result.db_snapshots["scorecard"] = str(sc["date"])[:10]
        if use_depsdev and deps:
            enrich: list[dict] = []
            for dep in deps[:25]:  # cap enrichment fan-out
                d = await _fetch_depsdev(dep, client)
                if d:
                    enrich.append(d)
            if enrich:
                result.depsdev = {"versions": enrich}
                result.db_snapshots["deps.dev"] = datetime.now(
                    timezone.utc,
                ).strftime("%Y-%m-%d")
    except Exception as exc:  # noqa: BLE001 — fail-open is the whole point
        result.ok = False
        result.error = str(exc)
        logger.warning(
            "Supply-chain OSV pipeline failed for %s/%s (fail-open to regex): %s",
            owner, repo, exc,
        )
    finally:
        if owns_client and client is not None:
            await client.aclose()

    return result
