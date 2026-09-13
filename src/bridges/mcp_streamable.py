"""Spec-compliant REMOTE MCP server (Streamable HTTP) for the Claude Directory.

Exposes AgentAvow's read-only, anonymous TRUST tools over JSON-RPC/Streamable HTTP
so a Claude custom connector (and any MCP client) can reach them at
https://agentavow.com/mcp. Distinct from the legacy REST bridge at /api/v1/mcp
(src/api/mcp_router.py), which serves the old social-graph tools and is NOT MCP.

Design (see docs/internal/claude-directory-listing-plan.md):
- Tools are read-only (readOnlyHint) and unauthenticated — the easy Directory path.
- Each handler calls AgentAvow's own public API (first-party) and shapes a response
  that leads with a plain-English TLDR, then findings + remediation, an 8-bit
  trust/adoption view for terminal clients, and a signed-report link.
- Mounted as an ASGI sub-app; its session manager is started in the app lifespan.
"""
from __future__ import annotations

import json
import os

import httpx
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

# Where to reach our own public API from inside the container, and the public web
# base for user-facing links. Overridable for staging/local preview.
_API_BASE = os.environ.get("MCP_INTERNAL_API_BASE", "http://localhost:8000/api/v1").rstrip("/")
_WEB_BASE = os.environ.get("MCP_PUBLIC_WEB_BASE", "https://agentavow.com").rstrip("/")

_SAFE_BAR = 81  # A/A+ floor for the binary "safe" call (matches the site verdict)

# Shown to the client/model on connect (MCP InitializeResult.instructions) — the "what
# this is + how to use it" welcome. Purely descriptive: no directive that tries to make
# the agent auto-invoke these tools (that would be prompt-injection and fail Directory review).
_INSTRUCTIONS = (
    "AgentAvow grades the safety of anything an AI agent connects to — a GitHub repo, an MCP "
    "server, an npm/PyPI/crates/Docker/Hugging Face package, or a wallet-linked identity — and "
    "returns a signed 0-100 trust score with a plain safe / needs-review verdict that anyone can "
    "recompute offline.\n\n"
    "When to use which tool:\n"
    "• scan_repo — a GitHub repo, passed as 'owner/name'.\n"
    "• scan_package — a published package (registry + name).\n"
    "• scan_mcp_server — a live MCP server, by its https URL (checks the tool definitions "
    "themselves for poisoning/injection).\n"
    "• verify_trust / check_interaction_safety / lookup_identity / get_trust_badge — agent-to-"
    "agent identity and trust.\n\n"
    "Reading a verdict: score >=81 with no critical/high findings is 'safe to connect'; anything "
    "else is 'review before you connect'. Every result links to a full report and a signed "
    "(Ed25519/JWS) attestation. All tools are read-only and need no account.\n\n"
    "A good habit is to scan a tool before connecting or installing it."
)

server: Server = Server(
    "agentavow-trust",
    version="0.5.0",
    website_url="https://agentavow.com",
    instructions=_INSTRUCTIONS,
)


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
async def _get(path: str, params: dict | None = None) -> dict:
    # Above the API's ~90s scan budget (so we receive its graceful 503 rather than
    # timing out first), below nginx's 120s /mcp read timeout.
    async with httpx.AsyncClient(timeout=110.0) as client:
        resp = await client.get(f"{_API_BASE}{path}", params=params)
        resp.raise_for_status()
        return resp.json()


async def _bump(metric: str) -> None:
    """Increment a Directory-connector usage counter. Best-effort — never raises,
    so instrumentation can never break a tool call."""
    try:
        from src.api.metrics_dashboard_router import bump_metric
        await bump_metric(f"mcp:{metric}")
    except Exception:
        pass


def _trust_bar(score: int) -> str:
    """20-cell 8-bit trust bar, filled proportionally to the 0-100 score."""
    filled = max(0, min(20, round(score / 5)))
    return "▓" * filled + "░" * (20 - filled)


def _trust_band(score: float) -> str:
    """Plain-English descriptor for a 0-1 agent trust score (API returns no tier)."""
    if score >= 0.6:
        return "established history"
    if score >= 0.3:
        return "some history"
    return "little history yet"


def _findings(items: list[dict], limit: int = 5) -> list[dict]:
    out = []
    for it in items[:limit]:
        where = it.get("file_path") or ""
        if it.get("line_number"):
            where = f"{where}:{it['line_number']}"
        out.append({
            "severity": it.get("severity"),
            "category": it.get("category"),
            "what": it.get("name"),
            "where": where,
            "remediation": it.get("remediation"),
        })
    return out


def _scan_block(data: dict, verb: str, report_path: str) -> str:
    """Shape a /public/scan response into a plain-TLDR-first markdown block."""
    score = int(data.get("trust_score") or 0)
    checks = (data.get("certified") or {}).get("checks") or {}
    items = (data.get("findings") or {}).get("items") or []
    crit = sum(1 for i in items if i.get("severity") == "critical")
    high = sum(1 for i in items if i.get("severity") == "high")
    no_blocking = checks.get("no_critical_or_high")
    if not isinstance(no_blocking, bool):
        no_blocking = crit == 0 and high == 0
    safe = score >= _SAFE_BAR and no_blocking

    if safe:
        why = "No blocking issues found."
    elif crit + high:
        why = f"{crit + high} blocking finding{'' if crit + high == 1 else 's'} (critical/high)."
    else:
        why = f"Score below the safe bar ({score}/100)."
    summary = f"{'Safe to ' + verb if safe else 'Review before you ' + verb} — {score}/100. {why}"

    lines = [summary, ""]
    fs = _findings(items)
    if fs:
        lines.append("**Findings:**")
        for f in fs:
            tail = f" → {f['remediation']}" if f.get("remediation") else ""
            lines.append(f"- [{f['severity']}] {f['what']} ({f['where']}){tail}")
        if len(items) > len(fs):
            lines.append(f"- … {len(items) - len(fs)} more")
        lines.append("")
    # 8-bit detail (renders in monospace/terminal clients; harmless elsewhere)
    mark = "◆ NEEDS REVIEW" if not safe else "✓ SAFE"
    lines += [
        "```",
        "╔═══════════ AGENTAVOW ═══════════╗",
        f" TRUST  {_trust_bar(score)}  {score:>3}  {mark}",
        "╚═══════════════════════════════════╝",
        "```",
        "",
    ]
    signed = bool(data.get("jws"))
    lines.append(
        f"Full report: {_WEB_BASE}{report_path} · "
        f"Verify offline: {_WEB_BASE}/how-it-works#verify"
        + ("  · signed ✓ (Ed25519/JWS, recomputable)" if signed else "")
    )
    return "\n".join(lines)


def _safe_verdict(data: dict) -> bool:
    """The binary safe/needs-review call, identical to _scan_block's logic."""
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    checks = (data.get("certified") or {}).get("checks") or {}
    no_blocking = checks.get("no_critical_or_high")
    if not isinstance(no_blocking, bool):
        no_blocking = not any(i.get("severity") in ("critical", "high") for i in items)
    return score >= _SAFE_BAR and no_blocking


def _text(s: str) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=s)]


# --------------------------------------------------------------------------- #
# tool definitions (all read-only, unauthenticated)
# --------------------------------------------------------------------------- #
_RO = types.ToolAnnotations  # shorthand

_TOOLS: list[types.Tool] = [
    types.Tool(
        name="scan_repo",
        title="Scan a GitHub repo",
        description=(
            "Scan a public GitHub repository with AgentAvow and return whether it is safe "
            "for an agent to connect to: a 0-100 trust score, a plain safe / needs-review "
            "verdict, the findings behind it (with where and how to fix), and a signed, "
            "offline-verifiable attestation. Read-only, no account. Calls the AgentAvow "
            "public API at agentavow.com."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "repo": {
                    "type": "string",
                    "description": "Repo as 'owner/name' (e.g. 'vercel/next.js'), or just "
                                   "the name when 'owner' is given separately.",
                },
                "owner": {
                    "type": "string",
                    "description": "Repo owner (optional if 'repo' is already 'owner/name').",
                },
            },
            "required": ["repo"],
        },
        annotations=_RO(title="Scan a GitHub repo", readOnlyHint=True),
    ),
    types.Tool(
        name="scan_package",
        title="Scan a package",
        description=(
            "Scan a published package (npm, PyPI, crates, Docker, or Hugging Face) with "
            "AgentAvow. Returns a 0-100 trust score, a safe / needs-review verdict, findings "
            "with remediation, and a signed attestation. Also reports repo-vs-artifact drift "
            "(files shipped that aren't in the source). Read-only; calls agentavow.com."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "registry": {
                    "type": "string",
                    "description": "Package registry: npm, pypi, crates, docker, or hf. "
                                   "(Aliases also accepted: surface, ecosystem.)",
                },
                "name": {
                    "type": "string",
                    "description": "Package name, e.g. 'chalk' (or 'org/model' for hf).",
                },
            },
            "required": ["registry", "name"],
        },
        annotations=_RO(title="Scan a package", readOnlyHint=True),
    ),
    types.Tool(
        name="scan_mcp_server",
        title="Scan an MCP server",
        description=(
            "Scan a live MCP server's tool definitions for tool-poisoning, prompt-injection, "
            "invisible-unicode, and manifest-execution risks before your agent connects to it. "
            "Returns a 0-100 trust score, a safe / needs-review verdict, findings, and a signed "
            "attestation. Read-only; calls the agentavow.com public API."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "endpoint_url": {"type": "string", "description": "The MCP server's https:// URL."},
            },
            "required": ["endpoint_url"],
        },
        annotations=_RO(title="Scan an MCP server", readOnlyHint=True),
    ),
    types.Tool(
        name="verify_trust",
        title="Verify an entity's trust score",
        description=(
            "Verify an AgentAvow entity's trust score. Returns trust_score (0-1), "
            "trust_score_pct (0-100), trust_tier, and whether it meets a minimum threshold. "
            "Read-only, no auth. Use before interacting with an unknown agent."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "entity_id": {"type": "string", "description": "UUID of the AgentAvow entity."},
                "min_trust": {"type": "number", "description": "Min score, 0-1.", "default": 0.3},
            },
            "required": ["entity_id"],
        },
        annotations=_RO(title="Verify an entity's trust score", readOnlyHint=True),
    ),
    types.Tool(
        name="check_interaction_safety",
        title="Check interaction safety",
        description=(
            "Check whether it is safe to interact with another agent by trust threshold. "
            "Thresholds: delegate 0.6, trade 0.5, collaborate 0.4, follow 0.1. Returns is_safe, "
            "risk_level, the score, and a recommendation. Read-only, no auth."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "target_entity_id": {"type": "string", "description": "UUID of the target entity."},
                "interaction_type": {
                    "type": "string", "enum": ["delegate", "trade", "collaborate", "follow"],
                },
            },
            "required": ["target_entity_id", "interaction_type"],
        },
        annotations=_RO(title="Check interaction safety", readOnlyHint=True),
    ),
    types.Tool(
        name="lookup_identity",
        title="Look up an agent or tool",
        description=(
            "Look up an AgentAvow entity by W3C DID or display name. Returns the entity's id, "
            "name, type, trust score and tier. Read-only, no auth. Use to resolve an identity "
            "before checking its trust."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "query": {"type": "string", "description": "A did:web:... or a display name."},
            },
            "required": ["query"],
        },
        annotations=_RO(title="Look up an agent or tool", readOnlyHint=True),
    ),
    types.Tool(
        name="get_trust_badge",
        title="Get a trust badge",
        description=(
            "Get an embeddable AgentAvow trust badge (SVG) for an entity, with ready-to-paste "
            "Markdown and HTML. The badge auto-updates as the score changes. Read-only, no auth."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "entity_id": {"type": "string", "description": "UUID of the AgentAvow entity."},
            },
            "required": ["entity_id"],
        },
        annotations=_RO(title="Get a trust badge", readOnlyHint=True),
    ),
]


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return _TOOLS


@server.call_tool()
async def _call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    await _bump("calls:total")
    await _bump(f"tool:{name}")
    try:
        if name == "scan_repo":
            repo = (arguments.get("repo") or "").strip().strip("/")
            owner = (arguments.get("owner") or "").strip()
            if not owner and "/" in repo:
                owner, repo = repo.split("/", 1)
            if not owner or not repo:
                return _text("Give the repo as 'owner/name' (e.g. 'vercel/next.js'), "
                             "or pass owner and repo separately.")
            data = await _get(f"/public/scan/{owner}/{repo}")
            await _bump("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            return _text(_scan_block(data, "connect", f"/check/{owner}/{repo}"))
        if name == "scan_package":
            surface = (arguments.get("registry") or arguments.get("surface")
                       or arguments.get("ecosystem") or "").strip().lower()
            pkg = (arguments.get("name") or "").strip()
            aliases = {"python": "pypi", "pip": "pypi", "cargo": "crates", "rust": "crates",
                       "huggingface": "hf", "hugging_face": "hf"}
            surface = aliases.get(surface, surface)
            if not surface or not pkg:
                return _text("Give a registry (npm, pypi, crates, docker, or hf) and a package "
                             "name, e.g. registry='npm', name='chalk'.")
            data = await _get(f"/public/scan/package/{surface}/{pkg}")
            await _bump("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            return _text(_scan_block(data, "use", f"/check/pkg/{surface}/{pkg}"))
        if name == "scan_mcp_server":
            url = arguments["endpoint_url"]
            data = await _get("/public/scan/mcp", params={"endpoint": url})
            await _bump("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            return _text(_scan_block(data, "connect", "/check"))
        if name == "verify_trust":
            eid = arguments["entity_id"]
            min_trust = float(arguments.get("min_trust", 0.3))
            d = await _get(f"/entities/{eid}/trust")
            score = float(d.get("score") or 0.0)
            pct = round(score * 100)
            meets = score >= min_trust
            report = f"{_WEB_BASE}/entities/{eid}/trust"
            msg = (f"Agent trust {pct}/100 ({_trust_band(score)}) — "
                   f"{'meets' if meets else 'below'} your {round(min_trust * 100)}/100 threshold.\n"
                   f"Full trust report: {report}")
            return _text(msg)
        if name == "check_interaction_safety":
            eid = arguments["target_entity_id"]
            itype = arguments["interaction_type"]
            d = await _get(f"/entities/{eid}/trust")
            score = float(d.get("score") or 0.0)
            thresholds = {"delegate": 0.6, "trade": 0.5, "collaborate": 0.4, "follow": 0.1}
            thr = thresholds.get(itype, 0.5)
            safe = score >= thr
            report = f"{_WEB_BASE}/entities/{eid}/trust"
            return _text(
                f"{'Safe' if safe else 'Not recommended'} for '{itype}' — "
                f"trust {round(score * 100)}/100 vs the {round(thr * 100)}/100 bar for this "
                f"interaction.\nFull trust report: {report}"
            )
        if name == "lookup_identity":
            q = arguments["query"]
            if q.startswith("did:"):
                d = await _get("/did/resolve", params={"uri": q})
                return _text(json.dumps(d, indent=2)[:2000])
            d = await _get("/search", params={"q": q, "limit": 5})
            ents = d.get("entities") or []
            if not ents:
                return _text(f"No identities found for '{q}'. "
                             "Try a DID (did:web:...) or a more specific name.")
            lines = [f"Identities matching '{q}':", ""]
            for e in ents[:5]:
                eid = e.get("id")
                nm = e.get("display_name") or e.get("did_web") or eid
                pct = round(float(e.get("trust_score") or 0.0) * 100)
                lines.append(f"- {nm} — trust {pct}/100 — {_WEB_BASE}/entities/{eid}/trust")
            return _text("\n".join(lines))
        if name == "get_trust_badge":
            eid = arguments["entity_id"]
            d = await _get(f"/entities/{eid}/trust")  # 404s cleanly if the entity is unknown
            pct = round(float(d.get("score") or 0.0) * 100)
            badge = f"{_API_BASE}/badges/trust/{eid}.svg"
            report = f"{_WEB_BASE}/entities/{eid}/trust"
            return _text(
                f"Trust badge for this agent (currently {pct}/100):\n\n"
                f"README markdown:\n[![AgentAvow Trust]({badge})]({report})\n\n"
                f"Badge image: {badge}\nFull report: {report}"
            )
        return _text(f"Unknown tool: {name}")
    except httpx.TimeoutException:
        await _bump("result:error")
        return _text("That scan is taking longer than usual (large target). AgentAvow caps and "
                     "caches scans — try again in a moment and it should come back quickly.")
    except httpx.HTTPStatusError as e:
        await _bump("result:error")
        code = e.response.status_code
        if code == 404:
            return _text("Not found — check the target coordinates and try again.")
        if code == 503:
            return _text("The scan is still running (large target). Try again shortly — "
                         "results cache once ready.")
        return _text(f"AgentAvow returned an error ({code}). "
                     "Try again shortly, or check the target.")
    except Exception:  # noqa: BLE001 — actionable message; never a stack trace or internal detail
        await _bump("result:error")
        return _text("Could not complete the check right now. Please try again shortly.")


# --------------------------------------------------------------------------- #
# Streamable HTTP transport — stateless JSON responses (nginx-friendly)
# --------------------------------------------------------------------------- #
session_manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)


async def mcp_asgi_app(scope, receive, send) -> None:
    await session_manager.handle_request(scope, receive, send)
