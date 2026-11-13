"""Weekly discovery: list each registry, keep what the catalog has no page for.

Sources and what each yields (a candidate = a would-be catalog row):

* MCP Registry (registry.modelcontextprotocol.io, latest version of every server): its
  GitHub repo page, else its first npm / PyPI package, else its remote endpoint (the
  live tool-definition scan). Same row shape as scan_mcp_registry.py.
* npm: the registry search API over the agent / MCP terms scan_npm_agents.py used, plus
  MCP keyword searches, ranked by weekly downloads; plus npm packages from the
  ecosyste.ms keyword lists.
* PyPI: PyPI has no search API. The seed list of scan_pypi_agents.py plus PyPI
  packages from the ecosyste.ms keyword lists (mcp, model-context-protocol, agents...).
* OpenClaw: the GitHub searches the launch corpus came from (scan_openclaw_batch.py:
  topic:openclaw, "openclaw skill", org:openclaw, "openclaw in:name"), newest pushes
  first; plus ClawHub listings that carry a GitHub source link. A skill hosted only on
  ClawHub has no code our scanner can read yet and is counted, not queued.
* Smithery (registry.smithery.ai): a GitHub homepage gives the repo page; otherwise a
  deployed server's endpoint, looked up once per server (capped per run).

Every candidate is keyed with the catalog's own page key (``index.row_key_and_target``).
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Any

from src.catalog_growth.http import Fetcher
from src.catalog_growth.index import CatalogIndex, row_key_and_target

logger = logging.getLogger(__name__)

MCP_REGISTRY_URL = "https://registry.modelcontextprotocol.io/v0.1/servers"
NPM_SEARCH_URL = "https://registry.npmjs.org/-/v1/search"
ECOSYSTEMS_KEYWORD_URL = "https://packages.ecosyste.ms/api/v1/keywords/{kw}"
GITHUB_SEARCH_URL = "https://api.github.com/search/repositories"
CLAWHUB_SKILLS_URL = "https://clawhub.ai/api/v1/skills"
SMITHERY_LIST_URL = "https://registry.smithery.ai/servers"
SMITHERY_DETAIL_URL = "https://registry.smithery.ai/servers/{qn}"

# scan_npm_agents.py SEARCH_TERMS, plus the MCP keyword searches.
NPM_TERMS = (
    "mcp server", "agent framework", "langchain", "crewai", "autogen",
    "@modelcontextprotocol", "ai agent tool", "x402 payment",
    "keywords:mcp", "keywords:mcp-server", "keywords:modelcontextprotocol",
    "keywords:model-context-protocol",
)
NPM_PAGE = 250
NPM_PAGES_PER_TERM = 4
# scan_pypi_agents.py SEED_PACKAGES (the agentgraph-* bridges are our own, left out).
PYPI_SEED = (
    "langchain", "langgraph", "crewai", "pyautogen", "pydantic-ai", "llama-index",
    "haystack-ai", "smolagents", "mcp", "fastmcp", "magentic", "instructor",
    "guidance", "outlines", "dspy-ai", "autogenstudio",
)
ECOSYSTEMS_KEYWORDS = (
    "mcp", "mcp-server", "model-context-protocol", "modelcontextprotocol",
    "ai-agent", "ai-agents", "llm-agent", "agents", "langchain", "crewai",
)
ECOSYSTEMS_PAGES = 10
ECOSYSTEMS_PER_PAGE = 100
# scan_openclaw_batch.py strategies.
OPENCLAW_QUERIES = ("topic:openclaw", "openclaw skill", "org:openclaw", "openclaw in:name")
GITHUB_SEARCH_PAGES = 5
CLAWHUB_PAGES = 50
CLAWHUB_PAGE = 100
SMITHERY_PAGE = 100
SMITHERY_MAX_PAGES = 300
# The registry passed 60,000 entries (11-13 dry run stopped at 600 pages); a full read
# is a few thousand pages at most, and the cursor ends the loop before the cap.
MCP_REGISTRY_MAX_PAGES = 3000
# A package below this many weekly downloads is counted, not queued (the long tail of
# one-off MCP experiments would otherwise crowd out tools people use).
MIN_WEEKLY_DOWNLOADS = 25

_GH_RE = re.compile(r"github\.com[:/]+([A-Za-z0-9_.-]+)/([A-Za-z0-9_.-]+)")


def github_repo(url: Any) -> str | None:
    """owner/repo from any GitHub URL flavour (https, git+, ssh); None otherwise."""
    if not isinstance(url, str):
        return None
    m = _GH_RE.search(url)
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo or owner.lower() in ("orgs", "topics", "sponsors"):
        return None
    return f"{owner}/{repo}"


def endpoint_identity(url: Any) -> str | None:
    """The MCP endpoint identity of an https URL (no credentials, query or fragment);
    None for a non-https URL, a templated one or one whose path looks like a key.
    No DNS here: the full SSRF check runs right before a scan (execute.py)."""
    from src.ssrf import mcp_endpoint_identity

    if not isinstance(url, str) or not url.lower().startswith("https://") or "{" in url:
        return None
    try:
        return mcp_endpoint_identity(url.strip())
    except ValueError:
        return None


@dataclass(slots=True)
class Candidate:
    source: str
    surface: str               # catalog surface the row would list under
    name: str
    full_name: str | None = None
    endpoint_url: str | None = None
    version: str | None = None
    adoption: int = 0
    registry_name: str | None = None
    below_floor: bool = False


def _int(v: Any) -> int:
    return int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else 0


# -- sources ---------------------------------------------------------------------
async def mcp_registry(f: Fetcher, *, max_pages: int = MCP_REGISTRY_MAX_PAGES
                       ) -> tuple[list[Candidate], dict[str, str]]:
    """Every server's latest version. Returns (candidates, registry name -> endpoint)
    (the endpoint map serves the skipped-with-URL pass)."""
    out: list[Candidate] = []
    remotes: dict[str, str] = {}
    seen: set[str] = set()
    cursor: str | None = None
    for _ in range(max_pages):
        params: dict[str, Any] = {"limit": 100, "version": "latest"}
        if cursor:
            params["cursor"] = cursor
        data = await f.get_json(MCP_REGISTRY_URL, policy="mcp_registry", params=params)
        if not isinstance(data, dict):
            break
        servers = data.get("servers") or []
        for entry in servers:
            s = entry.get("server") if isinstance(entry, dict) and "server" in entry else entry
            if not isinstance(s, dict):
                continue
            meta = (entry.get("_meta") or {}) if isinstance(entry, dict) else {}
            official = meta.get("io.modelcontextprotocol.registry/official") or {}
            name = s.get("name")
            if not isinstance(name, str) or not name or name in seen:
                continue
            if official.get("status") == "deleted":
                continue
            seen.add(name)
            repo_obj = s.get("repository")
            repo_url = repo_obj.get("url") if isinstance(repo_obj, dict) else repo_obj
            endpoint = None
            rem = [r for r in (s.get("remotes") or []) if isinstance(r, dict)]
            rem.sort(key=lambda r: r.get("type") != "streamable-http")
            for r in rem:
                endpoint = endpoint_identity(r.get("url"))
                if endpoint:
                    break
            if endpoint:
                remotes[name] = endpoint
            version = s.get("version") if isinstance(s.get("version"), str) else None
            gh = github_repo(repo_url)
            if gh:
                out.append(Candidate("mcp_registry", "mcp", name, full_name=gh,
                                     version=version, registry_name=name))
                continue
            pkg = next((p for p in (s.get("packages") or []) if isinstance(p, dict)
                        and p.get("registryType") in ("npm", "pypi")
                        and isinstance(p.get("identifier"), str)), None)
            if pkg:
                out.append(Candidate("mcp_registry", pkg["registryType"], pkg["identifier"],
                                     version=pkg.get("version") or version,
                                     registry_name=name))
                continue
            out.append(Candidate("mcp_registry", "mcp", endpoint or name,
                                 endpoint_url=endpoint, version=version, registry_name=name))
        md = data.get("metadata") or {}
        cursor = md.get("nextCursor") or md.get("next_cursor")
        if not cursor or not servers:
            break
    else:
        logger.warning("mcp_registry: stopped at the %d-page cap; later servers not read",
                       max_pages)
    return out, remotes


async def ecosystems_keywords(f: Fetcher, *, keywords: tuple[str, ...] = ECOSYSTEMS_KEYWORDS,
                              pages: int = ECOSYSTEMS_PAGES) -> list[dict]:
    """Packages tagged with the agent / MCP keywords on ecosyste.ms (all ecosystems;
    callers filter). Only the few fields used are kept."""
    out: list[dict] = []
    for kw in keywords:
        for page in range(1, pages + 1):
            data = await f.get_json(ECOSYSTEMS_KEYWORD_URL.format(kw=kw), policy="ecosystems",
                                    params={"per_page": ECOSYSTEMS_PER_PAGE, "page": page})
            pkgs = data.get("packages") if isinstance(data, dict) else None
            if not pkgs:
                break
            for p in pkgs:
                if isinstance(p, dict) and isinstance(p.get("name"), str):
                    out.append({"ecosystem": p.get("ecosystem"), "name": p["name"],
                                "version": p.get("latest_release_number"),
                                "downloads": _int(p.get("downloads")),
                                "period": p.get("downloads_period")})
            if len(pkgs) < ECOSYSTEMS_PER_PAGE:
                break
    return out


def _weekly(downloads: int, period: Any) -> int:
    # ecosyste.ms reports PyPI/npm downloads for the "last-month" period.
    return downloads // 4 if period in ("last-month", "month") else downloads


async def npm(f: Fetcher, eco: list[dict], *, pages: int = NPM_PAGES_PER_TERM
              ) -> list[Candidate]:
    seen: dict[str, Candidate] = {}
    for term in NPM_TERMS:
        for page in range(pages):
            data = await f.get_json(NPM_SEARCH_URL, policy="npm", params={
                "text": term, "size": NPM_PAGE, "from": page * NPM_PAGE})
            objs = data.get("objects") if isinstance(data, dict) else None
            if not objs:
                break
            for o in objs:
                pkg = o.get("package") if isinstance(o, dict) else None
                name = pkg.get("name") if isinstance(pkg, dict) else None
                if not isinstance(name, str) or name in seen:
                    continue
                weekly = _int((o.get("downloads") or {}).get("weekly"))
                seen[name] = Candidate("npm", "npm", name, version=pkg.get("version"),
                                       adoption=weekly)
            if len(objs) < NPM_PAGE:
                break
    for p in eco:
        if p["ecosystem"] == "npm" and p["name"] not in seen:
            seen[p["name"]] = Candidate("npm", "npm", p["name"], version=p.get("version"),
                                        adoption=_weekly(p["downloads"], p.get("period")))
    out = list(seen.values())
    for c in out:
        c.below_floor = c.adoption < MIN_WEEKLY_DOWNLOADS
    return out


async def pypi(f: Fetcher, eco: list[dict]) -> list[Candidate]:
    seen: dict[str, Candidate] = {}
    for p in eco:
        if p["ecosystem"] == "pypi" and p["name"] not in seen:
            seen[p["name"]] = Candidate("pypi", "pypi", p["name"], version=p.get("version"),
                                        adoption=_weekly(p["downloads"], p.get("period")))
    out = list(seen.values())
    for c in out:
        c.below_floor = c.adoption < MIN_WEEKLY_DOWNLOADS
    for name in PYPI_SEED:  # curated: always eligible
        if name not in seen:
            out.append(Candidate("pypi", "pypi", name))
    return out


async def openclaw(f: Fetcher, *, token: str | None, clawhub_pages: int = CLAWHUB_PAGES
                   ) -> tuple[list[Candidate], int]:
    """(candidates, ClawHub skills with no GitHub source)."""
    out: dict[str, Candidate] = {}
    if token:
        headers = {"Accept": "application/vnd.github+json",
                   "Authorization": f"Bearer {token}"}
        for q in OPENCLAW_QUERIES:
            for page in range(1, GITHUB_SEARCH_PAGES + 1):
                resp = await f.get(GITHUB_SEARCH_URL, policy="github_search", headers=headers,
                                   params={"q": q, "sort": "updated", "order": "desc",
                                           "per_page": 100, "page": page})
                if resp is None or resp.status_code != 200:
                    break  # 422 past the 1,000-result cap, 403 out of budget
                items = (resp.json() or {}).get("items") or []
                for it in items:
                    fn = it.get("full_name") if isinstance(it, dict) else None
                    if isinstance(fn, str) and "/" in fn and fn.lower() not in out:
                        out[fn.lower()] = Candidate("openclaw", "openclaw", fn, full_name=fn,
                                                    adoption=_int(it.get("stargazers_count")))
                if len(items) < 100:
                    break
    clawhub_only = 0
    cursor: str | None = None
    for _ in range(clawhub_pages):
        params: dict[str, Any] = {"limit": CLAWHUB_PAGE}
        if cursor:
            params["cursor"] = cursor
        data = await f.get_json(CLAWHUB_SKILLS_URL, policy="clawhub", params=params)
        items = data.get("items") if isinstance(data, dict) else None
        if not items:
            break
        for it in items:
            if not isinstance(it, dict):
                continue
            src = ((it.get("links") or {}).get("source") or (it.get("install") or {}).get(
                "sourceUrl") or it.get("sourceUrl"))
            gh = github_repo(src)
            if gh is None:
                clawhub_only += 1
                continue
            stats = it.get("stats") or {}
            if gh.lower() not in out:
                out[gh.lower()] = Candidate("openclaw", "openclaw", gh, full_name=gh,
                                            adoption=_int(stats.get("installs")))
        cursor = data.get("nextCursor")
        if not cursor:
            break
    return list(out.values()), clawhub_only


async def smithery(f: Fetcher, *, seen: dict[str, Any], detail_max: int,
                   max_pages: int = SMITHERY_MAX_PAGES
                   ) -> tuple[list[Candidate], dict[str, Any], int]:
    """(candidates, qualifiedName -> resolved page coordinate for state, entries still
    waiting for a detail lookup). ``seen`` maps a server already looked up to its
    candidate fields (or None: no usable code or endpoint)."""
    listed: list[dict] = []
    for page in range(1, max_pages + 1):
        data = await f.get_json(SMITHERY_LIST_URL, policy="smithery",
                                params={"pageSize": SMITHERY_PAGE, "page": page})
        servers = data.get("servers") if isinstance(data, dict) else None
        if not servers:
            break
        for s in servers:
            if isinstance(s, dict) and isinstance(s.get("qualifiedName"), str):
                listed.append({"qn": s["qualifiedName"], "uses": _int(s.get("useCount")),
                               "remote": bool(s.get("remote")),
                               "homepage": s.get("homepage")})
        pag = data.get("pagination") or {}
        if page >= _int(pag.get("totalPages")):
            break
    listed.sort(key=lambda s: -s["uses"])
    out: list[Candidate] = []
    resolved: dict[str, Any] = {}
    waiting = 0
    lookups = 0
    for s in listed:
        qn = s["qn"]
        if qn in seen:
            hit = seen[qn]
        else:
            gh = github_repo(s.get("homepage"))
            if gh:
                hit = {"full_name": gh}
            elif not s["remote"]:
                hit = None  # local-only server with no repo link: nothing to read
            elif lookups < detail_max:
                lookups += 1
                d = await f.get_json(SMITHERY_DETAIL_URL.format(qn=qn), policy="smithery")
                ep = None
                if isinstance(d, dict):
                    ep = endpoint_identity(d.get("deploymentUrl"))
                    for c in d.get("connections") or []:
                        if ep:
                            break
                        if isinstance(c, dict):
                            ep = endpoint_identity(c.get("deploymentUrl"))
                hit = {"endpoint": ep} if ep else None
            else:
                waiting += 1
                continue
            resolved[qn] = hit
        if not hit:
            out.append(Candidate("smithery", "mcp", qn, adoption=s["uses"]))
        elif hit.get("full_name"):
            out.append(Candidate("smithery", "github", hit["full_name"],
                                 full_name=hit["full_name"], adoption=s["uses"]))
        else:
            out.append(Candidate("smithery", "mcp", hit["endpoint"],
                                 endpoint_url=hit["endpoint"], adoption=s["uses"]))
    return out, resolved, waiting


# -- planning ---------------------------------------------------------------------
PRIORITY_NEW = 2
PRIORITY_SKIPPED_URL = 3


def _count(report: dict, source: str, field: str, n: int = 1) -> None:
    bucket = report["by_source"].setdefault(source, {})
    bucket[field] = bucket.get(field, 0) + n


def classify(candidates: list[Candidate], index: CatalogIndex, failed: dict[str, str],
             *, retry_after_iso: str, report: dict, queued: dict[str, dict]) -> None:
    """Sort candidates into queued (new to the catalog, scannable), already listed,
    no code and no URL, below the adoption floor, or waiting to retry a failed scan.
    Mutates ``report`` counts and ``queued`` (page key -> work item)."""
    for c in candidates:
        _count(report, c.source, "discovered")
        key, target = row_key_and_target(c.surface, c.name, c.full_name, c.endpoint_url)
        if key is None or target is None:
            _count(report, c.source, "no_code_no_url")
            continue
        if index.has(key, surface=target[0], name=target[2]):
            _count(report, c.source, "already")
            continue
        if key in queued:
            _count(report, c.source, "already")
            continue
        _count(report, c.source, "new")
        if c.below_floor:
            _count(report, c.source, "below_floor")
            continue
        last_fail = failed.get(key)
        if last_fail and last_fail > retry_after_iso:
            _count(report, c.source, "retry_wait")
            continue
        queued[key] = {
            "key": key, "surface": target[0], "owner": target[1], "repo": target[2],
            "reason": "new", "source": c.source, "priority": PRIORITY_NEW,
            "adoption": c.adoption, "version": c.version,
            **({"registry_name": c.registry_name} if c.registry_name else {}),
        }
        _count(report, c.source, "queued")


def skipped_with_url(index: CatalogIndex, remotes: dict[str, str],
                     fallback: dict[str, str], report: dict, queued: dict[str, dict],
                     failed: dict[str, str], retry_after_iso: str) -> None:
    """Launch MCP rows skipped for no readable code: queue the live tool-definition
    scan of their remote endpoint; a row with no endpoint stays not checked."""
    src = "skipped_corpus"
    for name in sorted(index.skipped_mcp_names):
        _count(report, src, "discovered")
        ep = remotes.get(name) or endpoint_identity(fallback.get(name))
        if not ep:
            _count(report, src, "no_code_no_url")
            continue
        key, target = row_key_and_target("mcp", ep, None, ep)
        if key is None or target is None:
            _count(report, src, "no_code_no_url")
            continue
        _count(report, src, "skipped_with_url")
        if index.has(key) or key in queued:
            _count(report, src, "already")
            continue
        last_fail = failed.get(key)
        if last_fail and last_fail > retry_after_iso:
            _count(report, src, "retry_wait")
            continue
        queued[key] = {"key": key, "surface": "mcp", "owner": "mcp", "repo": ep,
                       "reason": "skipped_url", "source": src,
                       "priority": PRIORITY_SKIPPED_URL, "adoption": 0,
                       "registry_name": name}
        _count(report, src, "queued")


def launch_mcp_remotes(data_dir: Any = None) -> dict[str, str]:
    """name -> remote_url from the launch discovery file (mcp-registry-targets.json),
    for a skipped row the live registry no longer lists."""
    import json

    from src.api import scan_catalog_router as scr

    path = (data_dir or scr._DATA_DIR) / "mcp-registry-targets.json"
    try:
        doc = json.loads(path.read_text())
    except Exception:
        return {}
    out: dict[str, str] = {}
    for t in (doc.get("targets") or []) if isinstance(doc, dict) else []:
        if isinstance(t, dict) and isinstance(t.get("name"), str) and isinstance(
                t.get("remote_url"), str):
            out[t["name"]] = t["remote_url"]
    return out


async def plan_discovery(f: Fetcher, index: CatalogIndex, state: dict, *,
                         github_token: str | None, smithery_detail_max: int,
                         retry_after_iso: str, launch_dir: Any = None) -> tuple[list[dict],
                                                                              dict, dict]:
    """Run every source; returns (work items, report, Smithery lookups to remember)."""
    report: dict = {"by_source": {}}
    queued: dict[str, dict] = {}
    failed = state.get("failed") or {}

    mcp_c, remotes = await mcp_registry(f)
    # The skipped launch rows first: their endpoint item carries the registry name the
    # catalog overlay needs (execute.write_mcp_endpoint), so it must win over the same
    # endpoint arriving as a plain new registry entry.
    skipped_with_url(index, remotes, launch_mcp_remotes(launch_dir), report, queued,
                     failed, retry_after_iso)
    classify(mcp_c, index, failed, retry_after_iso=retry_after_iso, report=report,
             queued=queued)
    del mcp_c

    eco = await ecosystems_keywords(f)
    classify(await npm(f, eco), index, failed, retry_after_iso=retry_after_iso,
             report=report, queued=queued)
    classify(await pypi(f, eco), index, failed, retry_after_iso=retry_after_iso,
             report=report, queued=queued)
    del eco

    oc, clawhub_only = await openclaw(f, token=github_token)
    classify(oc, index, failed, retry_after_iso=retry_after_iso, report=report,
             queued=queued)
    if clawhub_only:
        _count(report, "openclaw", "discovered", clawhub_only)
        _count(report, "openclaw", "no_code_no_url", clawhub_only)
    if not github_token:
        report["notes"] = ["no GitHub token: OpenClaw GitHub searches skipped"]

    sm, resolved, waiting = await smithery(
        f, seen=state.get("smithery_seen") or {}, detail_max=smithery_detail_max)
    classify(sm, index, failed, retry_after_iso=retry_after_iso, report=report,
             queued=queued)
    if waiting:
        _count(report, "smithery", "deferred", waiting)

    items = sorted(queued.values(), key=lambda i: (i["priority"], -(i.get("adoption") or 0),
                                                    i["key"]))
    return items, report, resolved
