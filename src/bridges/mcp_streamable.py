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

import asyncio
import json
import os
from urllib.parse import quote

import httpx
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from src.bridges.mcp_app_view import TRUST_CARD_HTML

# MCP Apps (SEP-1865): an interactive trust card the host renders natively (vs. the
# model paraphrasing our text). ui:// resource + _meta.ui.resourceUri on scan tools;
# the card reads the scan result via ui/notifications/tool-result. Additive — hosts
# without MCP Apps fall back to the text/structuredContent we already return.
_CARD_URI = "ui://agentavow/trust-card.html"
_CARD_MIME = "text/html;profile=mcp-app"
_CARD_META = {"ui": {"resourceUri": _CARD_URI}, "ui/resourceUri": _CARD_URI}

# Where to reach our own public API from inside the container, and the public web
# base for user-facing links. Overridable for staging/local preview.
_API_BASE = os.environ.get("MCP_INTERNAL_API_BASE", "http://localhost:8000/api/v1").rstrip("/")
_WEB_BASE = os.environ.get("MCP_PUBLIC_WEB_BASE", "https://agentavow.com").rstrip("/")

_SAFE_BAR = 81  # A/A+ floor for the binary "safe" call (matches the site verdict)

# Where users opt in to scanning new tools automatically (a CLAUDE.md rule or a
# SessionStart hook). The user-facing setup guide.
_SETUP_URL = "https://agentavow.com/docs/auto-scan-claude-code"

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
    "A good habit is to scan a tool before connecting or installing it. To do that "
    f"automatically for every new tool, a user can add a one-line CLAUDE.md rule or a "
    f"SessionStart hook (setup: {_SETUP_URL}) — this is the user's own opt-in config."
)

# Canned overview returned by the about_agentavow tool. A tool (not just a prompt)
# so the answer is exact and relayed verbatim — no web-searching stale repo details.
_ABOUT = (
    "AgentAvow — the \"is this safe to connect?\" layer for AI agents.\n\n"
    "WHAT IT CHECKS: point it at a GitHub repo, an npm/PyPI/crates/Docker/Hugging Face "
    "package, a live MCP server, or an agent identity. You get a signed 0-100 trust "
    "score, a plain safe / needs-review verdict, the findings behind it, and adoption "
    "(downloads or stars). Every result is Ed25519/JWS-signed and recomputable offline. "
    "Read-only, no account.\n\n"
    "TOOLS:\n"
    "• scan_repo — a GitHub repo ('owner/name')\n"
    "• scan_package — a published package (registry + name)\n"
    "• scan_mcp_server — a live MCP server by https URL\n"
    "• verify_trust / check_interaction_safety / lookup_identity / get_trust_badge — "
    "agent identity & trust\n\n"
    "READING A VERDICT: 81+ with no critical/high findings = safe to connect; otherwise "
    "review. A sub-81 score with zero findings means non-finding signals (maintainer, "
    "provenance, adoption) held it down, not detected risk.\n\n"
    "TRY:\n"
    "• \"scan the npm package chalk\"\n"
    "• \"scan the repo modelcontextprotocol/servers\"\n"
    "• \"scan the MCP server at https://mcp.deepwiki.com/mcp\"\n\n"
    f"AUTOMATE (Claude Code): add a one-line CLAUDE.md rule or a SessionStart hook so new "
    f"tools are scanned before you use them — {_SETUP_URL}. (Claude Desktop connectors are "
    "invoked on request; Desktop has no user CLAUDE.md or hooks.)"
)

server: Server = Server(
    "agentavow-trust",
    version="0.11.1",
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


def _compact_int(n: int | None) -> str:
    """355306335 -> '355M'. Empty string for None."""
    if not n:
        return ""
    n = int(n)
    for div, suf in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "k")):
        if n >= div:
            return f"{n / div:.1f}".rstrip("0").rstrip(".") + suf
    return str(n)


async def _adoption(surface: str, owner: str, repo: str) -> tuple[int, str, int] | None:
    """Real adoption signal (downloads/wk, stars) for a target. Best-effort: a short
    timeout and fail-open so a slow registry lookup never delays or breaks a scan."""
    try:
        from src.api.public_scan_router import surface_adoption_summary
        score, count, unit = await asyncio.wait_for(
            surface_adoption_summary(surface, owner, repo), timeout=6.0
        )
        if count:
            return (int(count), unit or "", int(score or 0))
    except Exception:
        pass
    return None


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


def _scan_block(
    data: dict,
    verb: str,
    report_path: str,
    target: str,
    adoption: tuple[int, str, int] | None = None,
    install_hint: str = "",
) -> str:
    """Shape a /public/scan response into a response that leads with a plain verdict
    (which survives the model summarizing the tool output), followed by a compact 8-bit
    trust/adoption card, the findings, and the signed-report links."""
    score = int(data.get("trust_score") or 0)
    checks = (data.get("certified") or {}).get("checks") or {}
    items = (data.get("findings") or {}).get("items") or []
    crit = sum(1 for i in items if i.get("severity") == "critical")
    high = sum(1 for i in items if i.get("severity") == "high")
    no_blocking = checks.get("no_critical_or_high")
    if not isinstance(no_blocking, bool):
        no_blocking = crit == 0 and high == 0
    safe = score >= _SAFE_BAR and no_blocking
    risk = (crit + high) > 0
    # Three presentation treatments over the strict two machine states: a clean result
    # that only missed the bar on coverage/signals must NOT wear the same risk warning
    # as a target with real findings. Adoption is context here, never a verdict input.
    mode = "safe" if safe else ("risk" if risk else "limited")

    # Reason phrase, reused in the headline and the Next step (limited mode only).
    _files = (data.get("metadata") or {}).get("files_scanned")
    if isinstance(_files, int) and 0 < _files < 8:
        reason = (f"capped because there's little code to inspect "
                  f"({_files} file{'' if _files == 1 else 's'})")
    else:
        _subs = data.get("category_scores") or {}
        _low = min(_subs.items(), key=lambda kv: kv[1]) if _subs else None
        reason = "held below the bar by non-finding signals (maintainer, provenance, drift)"
        if _low and _low[1] < 80:
            reason += f"; weakest axis '{_low[0]}' ({_low[1]}/100)"

    if mode == "safe":
        head, why, glyph = f"✅ Safe to {verb}", "No blocking issues found.", "✔ SAFE"
    elif mode == "risk":
        n = crit + high
        head = f"⚠️ Review before you {verb}"
        why = f"{n} blocking finding{'' if n == 1 else 's'} (critical/high)."
        glyph = "⚠ REVIEW"
    else:
        head = "◍ Clean, limited coverage"
        why = f"No risks found; {reason}."
        glyph = "◍ LIMITED"

    # Trust and adoption always travel together (as on the site's dual mark). When
    # there's no established adoption signal (bare endpoint / brand-new package), say
    # "new" rather than dropping the pairing.
    if adoption:
        count, unit, _ = adoption
        adopt_clause = f" Adoption: {_compact_int(count)} {unit}."
    else:
        adopt_clause = " Adoption: new (no established public data yet)."
    # Line 1 carries the whole verdict in words, so it survives even if a client only
    # relays the model's one-line summary of the tool result.
    lines = [f"{head} — {target}, {score}/100. {why}{adopt_clause}", ""]

    # Compact 8-bit card. Left-aligned with a top/bottom rule (no right border, which is
    # what breaks alignment across renderers). Renders in any monospace view.
    card = [
        "```",
        "── AGENTAVOW · trust check ──────────────",
        f"  {target}",
        f"  TRUST     {_trust_bar(score)}  {score:>3}/100  {glyph}",
    ]
    if adoption:
        count, unit, ascore = adoption
        card.append(f"  ADOPTION  {_trust_bar(ascore)}  {_compact_int(count)} {unit}".rstrip())
    else:
        card.append(f"  ADOPTION  {_trust_bar(0)}  new")
    if bool(data.get("jws")):
        card.append("  signed ✔ Ed25519 · recompute offline")
    card += ["─────────────────────────────────────────", "```", ""]
    lines += card

    fs = _findings(items)
    if fs:
        lines.append("**Top findings:**")
        for f in fs:
            tail = f" → {f['remediation']}" if f.get("remediation") else ""
            lines.append(f"- [{f['severity']}] {f['what']} ({f['where']}){tail}")
        if len(items) > len(fs):
            lines.append(f"- … {len(items) - len(fs)} more")
        lines.append("")

    # A concrete next step for the agent/user — describes what to do with THIS result.
    # (Purely about our own verdict; it never tells the agent to auto-run other tools.)
    if mode == "safe":
        tail = f" — {install_hint}" if install_hint else ""
        action = f"clears the bar, so it's safe to {verb}{tail}."
    elif mode == "risk":
        n = crit + high
        action = (
            f"hold off. Ask me to walk through the {n} blocking finding"
            f"{'' if n == 1 else 's'} and whether they matter for your use, "
            f"or check an alternative."
        )
    else:
        # Clean, but below the bar on coverage/signals — not detected risk.
        action = (
            f"no risks found — the score is {reason}, a confidence limit rather than "
            f"detected risk. Adoption and the signed report can help you decide."
        )
    lines.append(f"**Next:** {action}")
    lines.append(
        f"Full report: {_WEB_BASE}{report_path} · "
        f"Verify offline: {_WEB_BASE}/how-it-works#verify"
    )
    # On a genuinely fresh scan (first time this target is checked, not a cache hit),
    # let the user know they can automate the "scan before you use it" habit. Shown
    # once per fresh result so it doesn't nag on repeat checks.
    if not data.get("cached"):
        lines.append(
            f"💡 Tip: scan new tools automatically before you use them — add a one-line "
            f"CLAUDE.md rule or a SessionStart hook: {_SETUP_URL}"
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


def _scan_struct(
    data: dict,
    target: str,
    target_type: str,
    report_path: str,
    api_path: str,
    adoption: tuple[int, str, int] | None,
) -> dict:
    """Stable machine-readable contract returned as structuredContent alongside the
    human text. Keep these keys STABLE — tools/CI consume this; the prose block is free
    to change without breaking them. ``target_type`` classifies the target
    (github|npm|pypi|crates|docker|hf|mcp); it is deliberately named apart from the
    scan_package ``registry`` input so consumers don't conflate the two."""
    items = (data.get("findings") or {}).get("items") or []
    crit = sum(1 for i in items if i.get("severity") == "critical")
    high = sum(1 for i in items if i.get("severity") == "high")
    score = int(data.get("trust_score") or 0)
    safe = _safe_verdict(data)
    # Machine-readable "why": distinguishes a real risk review from a coverage cap.
    if safe:
        verdict_reason = "clean"
    elif crit + high:
        verdict_reason = "blocking_findings"
    else:
        files = (data.get("metadata") or {}).get("files_scanned")
        verdict_reason = "thin_coverage" if isinstance(files, int) and 0 < files < 8 \
            else "low_signals"
    return {
        "target": target,
        "target_type": target_type,
        "trust_score": score,
        "grade": data.get("grade"),
        "tier": data.get("trust_tier"),
        "verdict": "safe" if safe else "needs_review",
        "verdict_reason": verdict_reason,
        "critical": crit,
        "high": high,
        "findings_total": int((data.get("findings") or {}).get("total") or len(items)),
        # per-category 0-100 axes — explains WHY the score is what it is
        "subscores": data.get("category_scores") or {},
        "adoption": (
            {"count": adoption[0], "unit": adoption[1], "score_0_100": adoption[2]}
            if adoption else None
        ),
        "signed": bool(data.get("jws")),
        "cached": bool(data.get("cached")),
        "report_url": f"{_WEB_BASE}{report_path}",
        # direct JSON for agents/CI — the /check report page is a JS SPA that returns
        # an empty shell to a non-browser fetch; this path returns the full verdict.
        "report_json_url": f"{_WEB_BASE}{api_path}",
        "verify_url": f"{_WEB_BASE}/how-it-works#verify",
    }


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
                "force": {
                    "type": "boolean",
                    "description": "Re-scan now instead of returning the cached verdict "
                                   "(results cache ~1h). Use after the target has changed.",
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
                    "description": "Package registry: npm, pypi, crates, docker, or hf.",
                },
                "surface": {"type": "string", "description": "Alias for registry."},
                "ecosystem": {"type": "string", "description": "Alias for registry."},
                "name": {
                    "type": "string",
                    "description": "Package name, e.g. 'chalk' (or 'org/model' for hf).",
                },
                "force": {
                    "type": "boolean",
                    "description": "Re-scan now instead of returning the cached verdict "
                                   "(results cache ~1h). Use after a new version ships.",
                },
            },
            # Only 'name' is hard-required so a call using the 'surface'/'ecosystem' alias
            # for the registry passes schema validation and reaches the handler (which
            # resolves the alias). Missing/invalid registry returns a friendly, value-
            # listing error from the handler rather than an opaque schema rejection.
            "required": ["name"],
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
                "force": {
                    "type": "boolean",
                    "description": "Re-scan now instead of returning the cached verdict "
                                   "(results cache ~1h).",
                },
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
                "query": {
                    "type": "string",
                    "description": "A did:web:... or a display name.",
                    # Bounded + character-constrained: a lookup key, not freeform text.
                    # Blocks control chars / quotes / braces used to smuggle instructions
                    # (the injection vector our own scanner flags on unconstrained params).
                    "maxLength": 200,
                    "pattern": r"^[\w .:/@#+-]{1,200}$",
                },
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
    types.Tool(
        name="about_agentavow",
        title="About AgentAvow",
        description=(
            "What AgentAvow is, which tool to use for what, how to read a verdict, and "
            "example scans. Call this for an overview or when getting started. No input, "
            "read-only."
        ),
        inputSchema={"type": "object", "properties": {}},
        annotations=_RO(title="About AgentAvow", readOnlyHint=True),
    ),
]

# Attach the MCP Apps trust-card view to the scan tools. Set on the field (the
# constructor silently drops an unknown `meta=` kwarg; the field alias is _meta).
for _t in _TOOLS:
    if _t.name in ("scan_repo", "scan_package", "scan_mcp_server"):
        _t.meta = _CARD_META


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return _TOOLS


@server.list_resources()
async def _list_resources() -> list[types.Resource]:
    return [types.Resource(
        uri=_CARD_URI,
        name="AgentAvow trust card",
        description="Interactive trust card rendered from a scan result.",
        mimeType=_CARD_MIME,
    )]


@server.read_resource()
async def _read_resource(uri: object) -> list[ReadResourceContents]:
    if str(uri).rstrip("/") == _CARD_URI.rstrip("/"):
        return [ReadResourceContents(content=TRUST_CARD_HTML, mime_type=_CARD_MIME)]
    return []


# A discoverable "intro" the user can invoke from the client's prompt picker — the
# closest thing to a post-install welcome the MCP spec offers (there is no server-
# controlled install-time UI). Complements the connect-time `instructions`.
_GET_STARTED = (
    "Give me a short tour of AgentAvow. In a few lines cover: what it can check for me "
    "(a GitHub repo, an npm/PyPI/crates/Docker/Hugging Face package, a live MCP server, "
    "or an agent identity); how to read a verdict (a 0-100 trust score — 81+ with no "
    "critical/high findings means safe to connect, otherwise needs review — and that "
    "every result is signed and can be recomputed offline); and give me two or three "
    "concrete example things I could ask you to scan right now."
)


@server.list_prompts()
async def _list_prompts() -> list[types.Prompt]:
    return [
        types.Prompt(
            name="agentavow_get_started",
            title="AgentAvow: get started",
            description="What AgentAvow checks and how to read a verdict, with examples.",
        )
    ]


@server.get_prompt()
async def _get_prompt(name: str, arguments: dict | None) -> types.GetPromptResult:
    return types.GetPromptResult(
        description="AgentAvow quick start",
        messages=[
            types.PromptMessage(
                role="user",
                content=types.TextContent(type="text", text=_GET_STARTED),
            )
        ],
    )


@server.call_tool()
async def _call_tool(
    name: str, arguments: dict
) -> list[types.TextContent] | tuple[list[types.TextContent], dict]:
    await _bump("calls:total")
    await _bump(f"tool:{name}")
    try:
        if name == "about_agentavow":
            return _text(_ABOUT)
        force = bool(arguments.get("force"))
        fp = {"force": "true"} if force else None
        if name == "scan_repo":
            repo = (arguments.get("repo") or "").strip().strip("/")
            owner = (arguments.get("owner") or "").strip()
            if not owner and "/" in repo:
                owner, repo = repo.split("/", 1)
            if not owner or not repo:
                return _text("Give the repo as 'owner/name' (e.g. 'vercel/next.js'), "
                             "or pass owner and repo separately.")
            data = await _get(f"/public/scan/{owner}/{repo}", params=fp)
            await _bump("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            adoption = await _adoption("github", owner, repo)
            rp = f"/check/{owner}/{repo}"
            api = f"/api/v1/public/scan/{owner}/{repo}"
            return (
                _text(_scan_block(data, "connect", rp, f"{owner}/{repo}", adoption)),
                _scan_struct(data, f"{owner}/{repo}", "github", rp, api, adoption),
            )
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
            data = await _get(f"/public/scan/package/{surface}/{pkg}", params=fp)
            await _bump("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            adoption = await _adoption(surface, surface, pkg)
            rp = f"/check/pkg/{surface}/{pkg}"
            api = f"/api/v1/public/scan/package/{surface}/{pkg}"
            hint = {
                "npm": f"install with `npm install {pkg}`",
                "pypi": f"install with `pip install {pkg}`",
                "crates": f"add with `cargo add {pkg}`",
            }.get(surface, "")
            return (
                _text(_scan_block(data, "use", rp, f"{pkg} · {surface}", adoption, hint)),
                _scan_struct(data, pkg, surface, rp, api, adoption),
            )
        if name == "scan_mcp_server":
            url = arguments["endpoint_url"]
            params = {"endpoint": url}
            if force:
                params["force"] = "true"
            data = await _get("/public/scan/mcp", params=params)
            await _bump("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            # A bare MCP endpoint has no registry/stars adoption signal — omit it rather
            # than fabricate one.
            label = url.split("://", 1)[-1].split("/", 1)[0] or "MCP server"
            api = f"/api/v1/public/scan/mcp?endpoint={quote(url, safe='')}"
            return (
                _text(_scan_block(data, "connect", "/check", label)),
                _scan_struct(data, url, "mcp", "/check", api, None),
            )
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
