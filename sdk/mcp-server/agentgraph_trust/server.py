"""AgentAvow Trust MCP Server (stdio).

A local/stdio MCP server that mirrors the flagship remote connector at
https://agentavow.com/mcp: the same read-only, anonymous TRUST tools, calling
AgentAvow's own public API and returning the SAME contract (0-100 trust score, a plain
safe / needs-review verdict + machine reason, findings, certified eligibility, signed
attestation links).

Consistency by construction: the verdict/verdict_reason/score are read straight from the
public API response (which derives them from src/scanner/verdict.py) — this server never
computes its own, so it can never disagree with the website or the remote connector.

Distributed on PyPI as `agentavow-trust` and in the MCP registry as
`com.agentavow/agentavow-trust`. Run with `uvx agentavow-trust`.

Env:
- AGENTAVOW_URL  — API/site base (default https://agentavow.com). AGENTGRAPH_URL still
  honored for back-compat.
"""
from __future__ import annotations

import asyncio
import json
import os
import sys
from typing import Any
from urllib.parse import quote

# Base URL for the AgentAvow API/site. Default is the current domain; the old env name
# (AGENTGRAPH_URL) is still honored so existing configs keep working.
_BASE_URL = (
    os.environ.get("AGENTAVOW_URL")
    or os.environ.get("AGENTGRAPH_URL")
    or "https://agentavow.com"
).rstrip("/")
_WEB_BASE = _BASE_URL

_VERSION = "0.5.1"

# Package-surface aliases, mirroring the public API + the remote connector.
_SURFACE_ALIASES = {
    "python": "pypi", "pip": "pypi",
    "crate": "crates", "cargo": "crates", "rust": "crates",
    "hf": "huggingface", "hugging_face": "huggingface", "hugging-face": "huggingface",
    "container": "docker", "oci": "docker", "image": "docker", "dockerhub": "docker",
}
_SURFACES = ("npm", "pypi", "crates", "huggingface", "docker")


def _api_url(path: str) -> str:
    return f"{_BASE_URL}/api/v1{path}"


async def _http_get(path: str, params: dict | None = None) -> dict:
    """GET the public API. Timeout sits above the API's ~90s scan budget so we receive
    its graceful 503 rather than tearing the connection down first."""
    import httpx

    async with httpx.AsyncClient(timeout=110.0) as client:
        resp = await client.get(_api_url(path), params=params)
        resp.raise_for_status()
        return resp.json()


# --------------------------------------------------------------------------- #
# response shaping (reads the API's own verdict — never recomputed here)
# --------------------------------------------------------------------------- #
def _findings_counts(data: dict) -> tuple[int, int, int]:
    f = data.get("findings") or {}
    items = f.get("items") or []
    crit = f.get("critical")
    high = f.get("high")
    if not isinstance(crit, int):
        crit = sum(1 for i in items if i.get("severity") == "critical")
    if not isinstance(high, int):
        high = sum(1 for i in items if i.get("severity") == "high")
    total = f.get("total")
    if not isinstance(total, int):
        total = len(items)
    return crit, high, total


def _top_findings(data: dict, limit: int = 5) -> list[dict]:
    """A small sample of findings, most-severe first (the API returns items already
    severity-sorted). Data only — the human summary lives in `summary`."""
    items = (data.get("findings") or {}).get("items") or []
    out = []
    for it in items[:limit]:
        out.append({
            "severity": it.get("severity"),
            "category": it.get("category"),
            "what": it.get("name"),
            "where": it.get("file") or it.get("location") or "",
        })
    return out


def _incident(ih: dict) -> dict | None:
    """Compact the API's incident_history (OSV MAL-) — context only, never scored. None
    when there is no known compromise."""
    if not ih.get("has_incident"):
        return None
    incs = ih.get("incidents") or []
    latest = incs[0] if incs else {}
    return {
        "known_compromise": True,
        "current_version_affected": bool(ih.get("current_version_affected")),
        "count": ih.get("count") or len(incs),
        "latest_id": latest.get("id"),
        "summary": latest.get("summary"),
        "published": latest.get("published"),
    }


_REASON_BLURB = {
    "clean": "no critical/high findings and above the safe bar",
    "blocking_findings": "held back by a critical/high finding — review before connecting",
    "thin_coverage": "no risks found, but little code to inspect — coverage cap, not risk",
    "low_signals": "no risks found; non-finding signals (maintainer/provenance/adoption) "
                   "held the score down",
}


def _scan_result(data: dict, target: str, target_type: str,
                 report_url: str, api_path: str) -> dict:
    """Build the stable scan contract, matching the remote connector's structuredContent.
    verdict / verdict_reason / trust_score come straight from the API."""
    crit, high, total = _findings_counts(data)
    score = int(data.get("trust_score") or 0)
    incident = _incident(data.get("incident_history") or {})
    verdict = data.get("verdict") or "needs_review"
    reason = data.get("verdict_reason") or "low_signals"
    certified = bool((data.get("certified") or {}).get("eligible"))
    safe = verdict == "safe"
    if safe:
        headline = f"Safe to connect — {score}/100."
    elif reason == "blocking_findings":
        headline = f"Review before connecting — {score}/100, {crit} critical / {high} high."
    elif reason == "thin_coverage":
        headline = f"Clean, limited coverage — {score}/100 (little code to inspect)."
    else:
        headline = f"Review — {score}/100."
    return {
        "target": target,
        "target_type": target_type,
        "trust_score": score,          # 0-100 (no letter grade in the external contract)
        "tier": data.get("trust_tier"),
        "verdict": verdict,            # safe | needs_review
        "verdict_reason": reason,      # clean | blocking_findings | thin_coverage | low_signals
        "summary": f"{headline} ({_REASON_BLURB.get(reason, reason)})",
        "critical": crit,
        "high": high,
        "findings_total": total,
        "top_findings": _top_findings(data),
        # certified.eligible matches the signed attestation; certified_mark carries the
        # display rule (only badge it when also safe), same as the remote connector.
        "certified": certified,
        "certified_mark": certified and safe,
        "incident_history": incident,  # context only — was this package ever compromised?
        "signed": bool(data.get("jws")),
        "cached": bool(data.get("cached")),
        "report_url": report_url,
        "report_json_url": f"{_WEB_BASE}{api_path}",
        "verify_url": f"{_WEB_BASE}/verify",
    }


def _error(msg: str) -> dict:
    return {"error": msg}


# --------------------------------------------------------------------------- #
# tool handlers — all read-only, all first-party (agentavow.com)
# --------------------------------------------------------------------------- #
async def _handle_scan_repo(args: dict) -> dict[str, Any]:
    repo = (args.get("repo") or "").strip().strip("/")
    if "/" not in repo:
        return _error("Pass the repo as 'owner/name' (e.g. 'modelcontextprotocol/servers').")
    owner, name = repo.split("/", 1)
    params = {"force": "true"} if args.get("force") else None
    try:
        data = await _http_get(f"/public/scan/{owner}/{name}", params=params)
    except Exception as e:  # noqa: BLE001
        return _error(f"Could not scan {repo}: {_clean_err(e)}")
    return _scan_result(data, repo, "github",
                        f"{_WEB_BASE}/check?target={quote(repo)}",
                        f"/api/v1/public/scan/{owner}/{name}")


async def _handle_scan_package(args: dict) -> dict[str, Any]:
    name = (args.get("name") or "").strip().strip("/")
    surface = (args.get("registry") or args.get("surface")
               or args.get("ecosystem") or "").strip().lower()
    surface = _SURFACE_ALIASES.get(surface, surface)
    if surface not in _SURFACES:
        return _error(
            f"registry must be one of: {', '.join(_SURFACES)} "
            "(aliases like python/rust/hf accepted).")
    if not name:
        return _error("Pass the package 'name'.")
    params = {"force": "true"} if args.get("force") else None
    try:
        pkg = quote(name, safe="@/")
        data = await _http_get(f"/public/scan/package/{surface}/{pkg}", params=params)
    except Exception as e:  # noqa: BLE001
        return _error(f"Could not scan {surface}:{name}: {_clean_err(e)}")
    return _scan_result(data, f"{surface}:{name}", surface,
                        f"{_WEB_BASE}/check?target={quote(f'{surface}:{name}')}",
                        f"/api/v1/public/scan/package/{surface}/{name}")


async def _handle_scan_mcp_server(args: dict) -> dict[str, Any]:
    url = (args.get("endpoint_url") or args.get("endpoint") or args.get("url") or "").strip()
    if not url.startswith("http"):
        return _error("Pass the MCP server's https URL as 'endpoint_url'.")
    params = {"endpoint": url}
    if args.get("force"):
        params["force"] = "true"
    try:
        data = await _http_get("/public/scan/mcp", params=params)
    except Exception as e:  # noqa: BLE001
        return _error(f"Could not scan MCP server {url}: {_clean_err(e)}")
    return _scan_result(data, url, "mcp",
                        f"{_WEB_BASE}/check?target={quote(url)}",
                        f"/api/v1/public/scan/mcp?endpoint={quote(url, safe='')}")


async def _handle_verify_trust(args: dict) -> dict[str, Any]:
    eid = (args.get("entity_id") or "").strip()
    if not eid:
        return _error("Pass the agent's 'entity_id'.")
    try:
        d = await _http_get(f"/entities/{eid}/trust")
    except Exception as e:  # noqa: BLE001
        return _error(f"Could not resolve entity {eid}: {_clean_err(e)}")
    pct = _score_pct(d)
    return {
        "entity_id": eid,
        "trust_score": pct,
        "tier": d.get("tier") or d.get("trust_tier"),
        "report_url": f"{_WEB_BASE}/entities/{eid}/trust",
    }


async def _handle_check_interaction_safety(args: dict) -> dict[str, Any]:
    eid = (args.get("target_entity_id") or args.get("entity_id") or "").strip()
    interaction = (args.get("interaction_type") or "delegate").strip()
    if not eid:
        return _error("Pass the 'target_entity_id' you want to interact with.")
    try:
        d = await _http_get(f"/entities/{eid}/trust")
    except Exception as e:  # noqa: BLE001
        return _error(f"Could not resolve entity {eid}: {_clean_err(e)}")
    pct = _score_pct(d)
    # A plain recommendation band; the trust score itself is the authoritative signal.
    recommend = "proceed" if (pct is not None and pct >= 61) else "caution"
    return {
        "target_entity_id": eid,
        "interaction_type": interaction,
        "trust_score": pct,
        "recommendation": recommend,
        "report_url": f"{_WEB_BASE}/entities/{eid}/trust",
    }


async def _handle_lookup_identity(args: dict) -> dict[str, Any]:
    q = (args.get("query") or "").strip()
    if not q:
        return _error("Pass a 'query' — a DID (did:web:… / did:key:…) or a name.")
    try:
        if q.startswith("did:"):
            d = await _http_get("/did/resolve", params={"uri": q})
            return {"query": q, "resolved": d}
        d = await _http_get("/search", params={"q": q, "limit": 5})
    except Exception as e:  # noqa: BLE001
        return _error(f"Lookup failed for {q}: {_clean_err(e)}")
    results = []
    for ent in (d.get("results") or d.get("entities") or []):
        eid = ent.get("entity_id") or ent.get("id")
        results.append({
            "entity_id": eid,
            "name": ent.get("name") or ent.get("display_name"),
            "report_url": f"{_WEB_BASE}/entities/{eid}/trust" if eid else None,
        })
    return {"query": q, "results": results}


async def _handle_get_trust_badge(args: dict) -> dict[str, Any]:
    eid = (args.get("entity_id") or "").strip()
    if not eid:
        return _error("Pass the 'entity_id' to badge.")
    try:
        d = await _http_get(f"/entities/{eid}/trust")  # 404s cleanly if unknown
    except Exception as e:  # noqa: BLE001
        return _error(f"Unknown entity {eid}: {_clean_err(e)}")
    pct = _score_pct(d)
    badge = f"{_WEB_BASE}/api/v1/badges/trust/{eid}.svg"
    report = f"{_WEB_BASE}/entities/{eid}/trust"
    return {
        "entity_id": eid,
        "trust_score": pct,
        "badge_url": badge,
        "report_url": report,
        "markdown": f"[![AgentAvow Trust]({badge})]({report})",
    }


async def _handle_about_agentavow(args: dict) -> dict[str, Any]:
    return {"about": _ABOUT}


def _score_pct(d: dict) -> int | None:
    """Trust score as 0-100. Accepts either an already-0-100 field or a 0-1 float."""
    for key in ("trust_score_pct", "score_pct"):
        v = d.get(key)
        if isinstance(v, (int, float)):
            return int(round(v))
    v = d.get("score")
    if isinstance(v, (int, float)):
        return int(round(v * 100)) if v <= 1 else int(round(v))
    v = d.get("trust_score")
    if isinstance(v, (int, float)):
        return int(round(v * 100)) if v <= 1 else int(round(v))
    return None


def _clean_err(e: Exception) -> str:
    """A user-safe error string — never leak internal hosts/tracebacks."""
    import httpx
    if isinstance(e, httpx.HTTPStatusError):
        code = e.response.status_code
        if code == 404:
            return "not found"
        if code == 503:
            return "the scan is taking longer than usual — try again shortly"
        return f"the service returned HTTP {code}"
    if isinstance(e, httpx.TimeoutException):
        return "the scan timed out — try again shortly"
    return "temporary error, please retry"


_ABOUT = (
    "AgentAvow — the \"is this safe to connect?\" layer for AI agents. Point it at a "
    "GitHub repo, an npm/PyPI/crates/Docker/Hugging Face package, a live MCP server, or "
    "an agent identity and get a signed 0-100 trust score, a plain safe / needs-review "
    "verdict, the findings behind it, and certified eligibility. Every result is "
    "Ed25519/JWS-signed and recomputable offline. Read-only, no account. This is the "
    "local/stdio build of the same service as the remote connector at "
    "https://agentavow.com/mcp."
)


# --------------------------------------------------------------------------- #
# tool catalog (mirrors the remote connector; all read-only)
# --------------------------------------------------------------------------- #
_RO = {"readOnlyHint": True}

_TOOLS = [
    {
        "name": "scan_repo",
        "description": "Scan a public GitHub repo ('owner/name') for a signed 0-100 trust "
                       "score and a plain safe / needs-review verdict before connecting.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {
                "repo": {"type": "string", "maxLength": 214,
                         "description": "GitHub repo as 'owner/name'."},
                "force": {"type": "boolean", "description": "Bypass the cache and re-scan."},
            },
            "required": ["repo"],
        },
    },
    {
        "name": "scan_package",
        "description": "Scan a published npm / PyPI / crates / Docker / Hugging Face package "
                       "for a signed 0-100 trust score and a safe / needs-review verdict.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string", "maxLength": 214, "description": "Package name."},
                "registry": {"type": "string", "maxLength": 32,
                             "description": "npm | pypi | crates | docker | huggingface "
                                            "(aliases like python/rust/hf accepted)."},
                "force": {"type": "boolean", "description": "Bypass the cache and re-scan."},
            },
            "required": ["name"],
        },
    },
    {
        "name": "scan_mcp_server",
        "description": "Scan a live MCP server by its https URL — checks the tool "
                       "definitions for poisoning / prompt-injection — signed verdict.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {
                "endpoint_url": {"type": "string", "maxLength": 512,
                                 "description": "The MCP server's https URL."},
                "force": {"type": "boolean", "description": "Bypass the cache and re-scan."},
            },
            "required": ["endpoint_url"],
        },
    },
    {
        "name": "verify_trust",
        "description": "Resolve an agent identity and return its current trust score "
                       "before you delegate to it.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {"entity_id": {"type": "string", "maxLength": 64}},
            "required": ["entity_id"],
        },
    },
    {
        "name": "check_interaction_safety",
        "description": "Check whether it's safe to perform a given interaction "
                       "(delegate/trade/…) with an agent.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {
                "target_entity_id": {"type": "string", "maxLength": 64},
                "interaction_type": {"type": "string", "maxLength": 32,
                                     "description": "e.g. delegate, trade, collaborate, follow."},
            },
            "required": ["target_entity_id"],
        },
    },
    {
        "name": "lookup_identity",
        "description": "Resolve a DID (did:web:… / did:key:…) or search agents by name.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {"query": {"type": "string", "maxLength": 200}},
            "required": ["query"],
        },
    },
    {
        "name": "get_trust_badge",
        "description": "Get a shields-style trust badge (SVG URL + README markdown) "
                       "for an agent identity.",
        "annotations": _RO,
        "inputSchema": {
            "type": "object",
            "properties": {"entity_id": {"type": "string", "maxLength": 64}},
            "required": ["entity_id"],
        },
    },
    {
        "name": "about_agentavow",
        "description": "What AgentAvow checks, which tool to use for what, and how to "
                       "read a verdict.",
        "annotations": _RO,
        "inputSchema": {"type": "object", "properties": {}},
    },
]

_HANDLERS = {
    "scan_repo": _handle_scan_repo,
    "scan_package": _handle_scan_package,
    "scan_mcp_server": _handle_scan_mcp_server,
    "verify_trust": _handle_verify_trust,
    "check_interaction_safety": _handle_check_interaction_safety,
    "lookup_identity": _handle_lookup_identity,
    "get_trust_badge": _handle_get_trust_badge,
    "about_agentavow": _handle_about_agentavow,
}


# --------------------------------------------------------------------------- #
# MCP protocol (stdio JSON-RPC)
# --------------------------------------------------------------------------- #
def _write_response(response: dict) -> None:
    sys.stdout.write(json.dumps(response) + "\n")
    sys.stdout.flush()


def _handle_initialize(msg: dict) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": msg.get("id"),
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "agentavow-trust", "version": _VERSION},
            "instructions": _ABOUT,
        },
    }


def _handle_tools_list(msg: dict) -> dict:
    return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": _TOOLS}}


async def _handle_tools_call(msg: dict) -> dict:
    params = msg.get("params", {})
    handler = _HANDLERS.get(params.get("name", ""))
    if handler is None:
        return {
            "jsonrpc": "2.0", "id": msg.get("id"),
            "error": {"code": -32601, "message": f"Unknown tool: {params.get('name')}"},
        }
    try:
        result = await handler(params.get("arguments", {}))
    except Exception as e:  # noqa: BLE001 — never crash the loop on a tool error
        result = _error(_clean_err(e))
    return {
        "jsonrpc": "2.0", "id": msg.get("id"),
        "result": {"content": [{"type": "text", "text": json.dumps(result, indent=2)}]},
    }


async def _process_message(msg: dict) -> dict | None:
    method = msg.get("method", "")
    if method == "initialize":
        return _handle_initialize(msg)
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return _handle_tools_list(msg)
    if method == "tools/call":
        return await _handle_tools_call(msg)
    if "id" in msg:
        return {
            "jsonrpc": "2.0", "id": msg.get("id"),
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def main() -> None:
    """Run the MCP server on stdio."""
    async def _run() -> None:
        for line in sys.stdin:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                _write_response({"jsonrpc": "2.0", "id": None,
                                 "error": {"code": -32700, "message": "Parse error"}})
                continue
            response = await _process_message(msg)
            if response is not None:
                _write_response(response)

    asyncio.run(_run())


if __name__ == "__main__":
    main()
