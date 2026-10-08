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
import contextvars
import json
import logging
import os
import re
from urllib.parse import quote

import httpx
import jsonschema
import mcp.types as types
from mcp.server.lowlevel import Server
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from src.bridges.mcp_app_view import trust_card_html
from src.scanner.verdict import DECISION_VALUES as _DECISION_VALUES
from src.scanner.verdict import SAFE_BAR as _SHARED_SAFE_BAR
from src.scanner.verdict import Decision as _Decision
from src.scanner.verdict import decide as _decide
from src.scanner.verdict import is_safe as _shared_is_safe
from src.scanner.verdict import verdict_reason as _shared_verdict_reason
from src.trust_tiers import headline as _decision_headline
from src.trust_tiers import is_certified as _is_certified

logger = logging.getLogger(__name__)

# The three-phrase headline rule for scan RESULTS (text headline + card lead). The
# structuredContent always carries decision / decision_final / decision_reason.
#   True (current, Kenne 2026-10-08 "make everything the same across the board"):
#     always lead with the decision phrase; the `initialize` instructions describe the
#     same three answers.
#   False: lead with the phrase only where it agrees with the binary verdict (safe <->
#     safe; review / do_not_connect <-> needs_review); where they disagree (a
#     thin-coverage 74 decides "safe" but its verdict is needs_review) keep the older
#     wording. A fallback only, for a surface that must keep the binary ">=81" rule.
HEADLINE_FOLLOWS_DECISION = True

_DECISION_ICONS = {"safe": "✅", "review": "⚠️", "do_not_connect": "⛔"}

# MCP Apps (SEP-1865): an interactive trust card the host renders natively (vs. the
# model paraphrasing our text). ui:// resource + _meta.ui.resourceUri on scan tools;
# the card reads the scan result via ui/notifications/tool-result. Additive — hosts
# without MCP Apps fall back to the text/structuredContent we already return.
# Versioned so a host that caches the UI resource is forced to re-fetch when we ship a
# new card (bump the suffix on each card change during the render-debug phase).
_CARD_URI = "ui://agentavow/trust-card-v13.html"
_CARD_MIME = "text/html;profile=mcp-app"
# Shared MCP-Apps standard (Claude + ChatGPT both use it): ui.resourceUri + the
# ui/notifications/tool-result postMessage (which TRUST_CARD_HTML already reads) +
# the text/html;profile=mcp-app mime. `openai/outputTemplate` is OpenAI's compat
# alias for the same resource. `domain`/`csp` are declared for ChatGPT app review;
# the card is fully self-contained (inline HTML/CSS/SVG, no external fetches), so
# both allow-lists are empty.
# The card's "Open report" button opens agentavow.com; ChatGPT needs it allow-listed.
_WIDGET_ORIGIN = "https://agentavow.com"
_WIDGET_CSP = {"connect_domains": [], "resource_domains": [], "redirect_domains": [_WIDGET_ORIGIN]}
_CARD_META = {
    # Shared MCP-Apps standard — Claude reads this; keep `ui` MINIMAL (just the
    # resourceUri) so a strict SEP-1865 host never chokes on extra fields. (Putting
    # domain/csp inside `ui` broke Claude's card render — "Unable to reach AgentAvow".)
    "ui": {"resourceUri": _CARD_URI},
    "ui/resourceUri": _CARD_URI,
    # ChatGPT/OpenAI-namespaced fields live OUTSIDE `ui` so only ChatGPT reads them.
    "openai/outputTemplate": _CARD_URI,
    "openai/widgetDomain": "https://agentavow.com",
    "openai/widgetCSP": _WIDGET_CSP,
}

# Where to reach our own public API from inside the container, and the public web
# base for user-facing links. Overridable for staging/local preview.
_API_BASE = os.environ.get("MCP_INTERNAL_API_BASE", "http://localhost:8000/api/v1").rstrip("/")
_WEB_BASE = os.environ.get("MCP_PUBLIC_WEB_BASE", "https://agentavow.com").rstrip("/")

_SAFE_BAR = _SHARED_SAFE_BAR  # A/A+ floor for the binary "safe" call (shared w/ the public API)

# Where users opt in to scanning new tools automatically (a CLAUDE.md rule or a
# SessionStart hook). The user-facing setup guide.
_SETUP_URL = "https://agentavow.com/docs/auto-scan-claude-code"

# Shown to the client/model on connect (MCP InitializeResult.instructions) — the "what
# this is + how to use it" welcome. Purely descriptive: no directive that tries to make
# the agent auto-invoke these tools (that would be prompt-injection and fail Directory review).
_INSTRUCTIONS = (
    "AgentAvow grades the safety of anything an AI agent connects to — a GitHub repo, an MCP "
    "server, an npm/PyPI/crates/Docker/Hugging Face package, or a wallet-linked identity — and "
    "returns one of three answers with its reason (Safe to connect, Review before you connect, "
    "or Do not connect), a signed 0-100 trust score that anyone can recompute offline, and an "
    "adoption score.\n\n"
    "When to use which tool:\n"
    "• scan_repo — a GitHub repo, passed as 'owner/name'.\n"
    "• scan_package — a published package (registry + name).\n"
    "• scan_mcp_server — a live MCP server, by its https URL (checks the tool definitions "
    "themselves for poisoning/injection).\n"
    "• verify_trust / check_interaction_safety / lookup_identity / get_trust_badge — agent-to-"
    "agent identity and trust.\n\n"
    "Reading a verdict: each result leads with one of three answers and its reason: 'Safe to "
    "connect', 'Review before you connect', or 'Do not connect', with ' · Certified' where the "
    "tool earned it. A 0-100 trust score and an adoption score sit underneath. Every result "
    "links to a full report and a signed (Ed25519/JWS) attestation. All tools are read-only "
    "and need no account.\n\n"
    "A good habit is to scan a tool before connecting or installing it. To do that "
    f"automatically for every new tool, a user can add a one-line CLAUDE.md rule or a "
    f"SessionStart hook (setup: {_SETUP_URL}) — this is the user's own opt-in config."
)

# Canned overview returned by the about_agentavow tool. A tool (not just a prompt)
# so the answer is exact and relayed verbatim — no web-searching stale repo details.
_ABOUT = (
    "AgentAvow — the \"is this safe to connect?\" layer for AI agents.\n\n"
    "WHAT IT CHECKS: point it at a GitHub repo, an npm/PyPI/crates/Docker/Hugging Face "
    "package, a live MCP server, or an agent identity. You get one of three answers with "
    "its reason, a signed 0-100 trust score, the findings behind it, and an adoption "
    "score (downloads or stars). Every result is Ed25519/JWS-signed and recomputable offline. "
    "Read-only, no account.\n\n"
    "TOOLS:\n"
    "• scan_repo — a GitHub repo ('owner/name')\n"
    "• scan_package — a published package (registry + name)\n"
    "• scan_mcp_server — a live MCP server by https URL\n"
    "• verify_trust / check_interaction_safety / lookup_identity / get_trust_badge — "
    "agent identity & trust\n\n"
    "READING A VERDICT: each scan leads with one of three answers and the reason behind "
    "it — Safe to connect, Review before you connect (a high finding, a published "
    "advisory on this version, deprecation, or a score under 51), or Do not connect (a "
    "critical finding, a known-malicious dependency, or a planted credential leaving the "
    "sandbox). \"· Certified\" marks a tool that also passed every provenance check. Two "
    "scores sit under it: trust (0-100) and adoption. A sub-81 score with zero findings "
    "means non-finding signals (maintainer, provenance, adoption) held it down, not "
    "detected risk.\n\n"
    "TRY:\n"
    "• \"scan the npm package chalk\"\n"
    "• \"scan the repo modelcontextprotocol/servers\"\n"
    "• \"scan the MCP server at https://mcp.deepwiki.com/mcp\"\n\n"
    f"AUTOMATE (Claude Code): add a one-line CLAUDE.md rule or a SessionStart hook so new "
    f"tools are scanned before you use them — {_SETUP_URL}. (Claude Desktop connectors are "
    "invoked on request; Desktop has no user CLAUDE.md or hooks.)"
)

# Served ONLY to Claude clients (claude.ai connector, Claude Code, Cursor, VS Code), on
# top of _INSTRUCTIONS. Nothing here auto-invokes a tool: each line is conditioned on
# what the user asks. Claude never sees a hook or install event for a connector, so
# this is the one place to say what to do when a tool question comes up. ChatGPT and
# unknown clients keep the base text byte-for-byte (its initialize is under review).
_INSTRUCTIONS_CLAUDE_ADDENDUM = (
    "When the user asks whether a tool, package, MCP server, or plugin is safe, or says "
    "they are about to install or connect one, run the matching scan first and lead your "
    "answer with the result's one-line answer (Safe to connect, Review before you connect, "
    "or Do not connect, with its reason and ' · Certified' where earned), then the trust "
    "score, the adoption score, and the top finding. "
    "If the user asks what AgentAvow does or how to get started, and other MCP servers or "
    "connectors are enabled in this conversation, name them and offer to check them; "
    "scan a server by its public https URL or its npm / PyPI package, and say which ones "
    "you would need a URL or package name for. The 'agentavow_check_my_connections' "
    "prompt does the same on request. scan_mcp_server also accepts a connector or server "
    "NAME (for example 'DeepWiki') when you cannot see its URL: it is matched against the "
    "AgentAvow catalog of scanned MCP servers, and you are given the candidates if the "
    "match is not clear. A forced re-scan runs in the background: the cached grade is "
    "returned at once and the fresh one on the next call."
)
_DIRECTIVE_SURFACES = frozenset({"claude", "claude-code", "cursor", "vscode"})


def _instructions_for(surface: str) -> str:
    if surface in _DIRECTIVE_SURFACES:
        return _INSTRUCTIONS + "\n\n" + _INSTRUCTIONS_CLAUDE_ADDENDUM
    return _INSTRUCTIONS


# Appended to the about_agentavow answer on Claude surfaces only: the one moment a
# person asks what this is, Claude should look at the other connectors in the chat and
# offer to grade them. ChatGPT gets _ABOUT unchanged.
_ABOUT_CLAUDE_TRAILER = (
    "\n\nNEXT, FOR THIS CONVERSATION: look at the other MCP servers or connectors enabled "
    "here. Name them, say which you can grade right now (a public https URL → "
    "scan_mcp_server; an npm or PyPI package → scan_package) and offer to do it; for the "
    "rest, ask for the URL or package name. The 'AgentAvow: check my connections' prompt "
    "does the same in one step."
)


def _about_for(surface: str) -> str:
    return _ABOUT + _ABOUT_CLAUDE_TRAILER if surface in _DIRECTIVE_SURFACES else _ABOUT


server: Server = Server(
    "agentavow-trust",
    version="0.16.0",
    website_url="https://agentavow.com",
    instructions=_INSTRUCTIONS,
)

# The stateless transport builds InitializeResult per request from
# create_initialization_options(); pick the instructions for the calling surface there
# (the surface contextvar is set in mcp_asgi_app before the request is handled).
_base_create_initialization_options = server.create_initialization_options


def _create_initialization_options(*args, **kwargs):
    opts = _base_create_initialization_options(*args, **kwargs)
    try:
        opts.instructions = _instructions_for(_SURFACE.get())
    except Exception:
        pass
    return opts


server.create_initialization_options = _create_initialization_options  # type: ignore[method-assign]


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _internal_headers() -> dict[str, str]:
    """Prove to the API that this call is the bridge's own, and say who it is for.
    The API then rate-limits per end user (and per surface) instead of lumping every
    connector call into one loopback bucket. Empty when no token is configured."""
    try:
        from src.config import settings
        token = settings.mcp_internal_token or ""
    except Exception:
        token = ""
    if not token:
        return {}
    return {
        "X-AgentAvow-Internal": token,
        "X-AgentAvow-Client-Ip": _CLIENT_IP.get() or "",
        "X-AgentAvow-Surface": _SURFACE.get() or "other",
    }


async def _get(path: str, params: dict | None = None) -> dict:
    # Above the API's ~90s scan budget (so we receive its graceful 503 rather than
    # timing out first), below nginx's 120s /mcp read timeout.
    async with httpx.AsyncClient(timeout=110.0, headers=_internal_headers()) as client:
        resp = await client.get(f"{_API_BASE}{path}", params=params)
        resp.raise_for_status()
        return resp.json()


# --- forced re-scans run in the background -----------------------------------
# A forced re-scan of a large package runs inline for minutes on the API side and
# outlives the tool call. The tool therefore answers with the cached grade at once,
# starts the fresh scan here (same process as the API, so the task survives the
# request), and says so; the next call returns the new grade. One in flight per target.
_RESCANS_IN_FLIGHT: set[str] = set()
RESCAN_NOTE = ("🔄 Fresh re-scan STARTED in the background (you asked for one). Shown below is "
               "the previous grade; ask again in a minute or two for the new one.")


async def _background_rescan(path: str, params: dict) -> None:
    try:
        await _get(path, params={**params, "force": "true"})
    except Exception:
        pass  # best-effort; the next ordinary call shows whatever the API has
    finally:
        _RESCANS_IN_FLIGHT.discard(_rescan_key(path, params))


def _rescan_key(path: str, params: dict) -> str:
    return path + "?" + "&".join(f"{k}={v}" for k, v in sorted(params.items()))


def _schedule_rescan(path: str, params: dict | None) -> bool:
    """Start a forced re-scan for ``path`` unless one is already running. Returns
    whether a new one was started (False = one is already in flight)."""
    params = {k: v for k, v in (params or {}).items() if k != "force"}
    key = _rescan_key(path, params)
    if key in _RESCANS_IN_FLIGHT:
        return False
    _RESCANS_IN_FLIGHT.add(key)
    try:
        asyncio.get_running_loop().create_task(_background_rescan(path, params))
    except RuntimeError:
        _RESCANS_IN_FLIGHT.discard(key)
        return False
    return True


def _with_rescan_note(card: list, struct: dict) -> tuple[list, dict]:
    card = list(card)
    if card and getattr(card[0], "text", None) is not None:
        when = str(struct.get("scanned_at") or "")[:16].replace("T", " ")
        note = RESCAN_NOTE + (f" (previous grade from {when} UTC)" if when else "")
        card[0] = types.TextContent(type="text", text=note + "\n\n" + card[0].text,
                                    **({"annotations": card[0].annotations}
                                       if getattr(card[0], "annotations", None) else {}))
    struct = dict(struct)
    struct["rescan_pending"] = True
    return card, struct


# --- MCP server names → endpoint URLs (claude.ai cannot see a connector's URL) ----
def _norm_name(s: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", (s or "").lower())


async def _resolve_mcp_name(name: str) -> tuple[str | None, list[dict]]:
    """A connector/server NAME (not a URL) → its endpoint URL from the AgentAvow catalog
    of scanned MCP servers. Returns (url, candidates): url when there is one clear
    match (exact normalized name, or a single hit); otherwise None and up to five
    candidates so the person can pick."""
    try:
        data = await _get("/public/scan-catalog", params={"surface": "mcp", "q": name, "limit": 8})
    except Exception:
        return None, []
    rows = [r for r in (data.get("rows") or []) if isinstance(r, dict) and r.get("endpoint_url")]
    if not rows:
        return None, []
    want = _norm_name(name)
    exact = [r for r in rows if _norm_name(str(r.get("name") or "")) == want
             or _norm_name(str(r.get("full_name") or "")).endswith(want)]
    if len(exact) == 1:
        return str(exact[0]["endpoint_url"]), []
    if len(rows) == 1:
        return str(rows[0]["endpoint_url"]), []
    return None, (exact or rows)[:5]


def _name_not_resolved(name: str, candidates: list[dict]) -> str:
    lines = [f"I could not match '{name}' to one MCP server in the AgentAvow catalog."]
    if candidates:
        lines.append("Closest matches — pass the endpoint_url of the right one to scan_mcp_server:")
        for r in candidates:
            score = r.get("trust_score")
            lines.append(f"• {r.get('name')} — {r.get('endpoint_url')}"
                         + (f" (AgentAvow {score}/100)" if isinstance(score, int) else ""))
    else:
        lines.append("Give me its https endpoint URL (in claude.ai: Settings → Connectors shows "
                     "it; in Claude Code: `claude mcp get <name>`), or its npm / PyPI package "
                     "name for scan_package.")
    return "\n".join(lines)


async def _bump(metric: str) -> None:
    """Increment a Directory-connector usage counter. Best-effort — never raises,
    so instrumentation can never break a tool call."""
    try:
        from src.api.metrics_dashboard_router import bump_metric
        await bump_metric(f"mcp:{metric}")
    except Exception:
        pass


# Per-surface attribution. The server is stateless, so clientInfo (which only
# rides the initialize handshake) can't be tied to later tool calls; the reliable
# per-request signal is the User-Agent header, captured in mcp_asgi_app below and
# stashed in this contextvar for the tool handler to read. Fail-open to "other".
_SURFACE: contextvars.ContextVar[str] = contextvars.ContextVar(
    "agentavow_mcp_surface", default="other"
)
# The caller's IP and User-Agent, for the distinct-callers-per-day HLL (see
# src/api/metrics_dashboard_router.record_unique). Captured in mcp_asgi_app; the IP
# is the one uvicorn already resolved through --proxy-headers. Never logged.
_CLIENT_IP: contextvars.ContextVar[str] = contextvars.ContextVar(
    "agentavow_mcp_client_ip", default=""
)
_CLIENT_UA: contextvars.ContextVar[str] = contextvars.ContextVar(
    "agentavow_mcp_client_ua", default=""
)

# Order matters: "claude-code" must be tested before "claude" (it contains it).
_SURFACE_MATCHERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("chatgpt", ("openai", "chatgpt")),
    ("claude-code", ("claude-code", "claude code", "claudecode")),
    ("cursor", ("cursor",)),
    ("vscode", ("vscode", "visual studio code")),
    ("claude", ("claude", "anthropic")),
)


def _surface_from_ua(ua: str) -> str:
    """Bucket a request's User-Agent into a known distribution surface. Best-effort;
    unknown/dev traffic → 'other'.

    A crawler never lands in a product surface: ClaudeBot carries "anthropic" and
    OAI-SearchBot carries "openai", and both are index crawlers, so anything
    src.traffic_class calls automated goes to 'other' before the needles run."""
    from src.traffic_class import classify_user_agent

    u = (ua or "").lower()
    if classify_user_agent(u) == "automated":
        return "other"
    for surface, needles in _SURFACE_MATCHERS:
        if any(n in u for n in needles):
            return surface
    return "other"


async def _bump_s(metric: str) -> None:
    """Bump the aggregate counter AND its per-surface variant (best-effort). The
    per-surface keys sum back to the aggregate (every request lands in one bucket)."""
    await _bump(metric)
    try:
        surface = _SURFACE.get()
    except Exception:
        surface = "other"
    await _bump(f"{metric}:{surface}")


async def _record_caller() -> None:
    """Add this tool call's machine to today's distinct-callers HLL, overall and per
    surface, so the dashboard can say how many machines invoked the connector rather
    than how many calls arrived. Best-effort — never raises."""
    try:
        from src.api.metrics_dashboard_router import record_unique

        ip, ua = _CLIENT_IP.get(), _CLIENT_UA.get()
        await record_unique("mcp:callers", ip, ua)
        await record_unique(f"mcp:callers:{_SURFACE.get()}", ip, ua)
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


def _no_entity_help(what: str) -> str:
    """Guidance when an entity/identity tool is given an id/name not in the graph.

    The identity graph only holds agents that have registered or been claimed, so an
    arbitrary id legitimately resolves to nothing. Return a clearly-functional,
    next-step answer (not a bare "not found") so this reads as a working tool — and
    point to the scan tools, which are the product's main surface and work on any input.
    """
    return (
        f"No AgentAvow entity is registered for {what}. That's expected for an id or name "
        "that hasn't been registered — the identity graph only tracks agents that have "
        "registered or claimed a listing.\n\n"
        "To see AgentAvow in action right now, scan a public tool (works on any input):\n"
        "• scan_repo — e.g. \"modelcontextprotocol/servers\"\n"
        "• scan_package — e.g. npm \"chalk\"\n"
        "• scan_mcp_server — any MCP endpoint URL\n"
        "Then use lookup_identity to resolve a registered agent, and pass its id here. "
        "Call about_agentavow for a guided overview."
    )


def _identity_matches(query: str, entity: dict) -> bool:
    """True when every word of *query* appears in the entity's name or DID."""
    haystack = f"{entity.get('display_name') or ''} {entity.get('did_web') or ''}".lower()
    words = query.lower().split()
    return bool(words) and all(w in haystack for w in words)


def _loc(it: dict) -> str:
    where = it.get("file_path") or ""
    if it.get("line_number"):
        where = f"{where}:{it['line_number']}"
    return where


def _findings(items: list[dict], limit: int = 5) -> list[dict]:
    out = []
    for it in items[:limit]:
        out.append({
            "severity": it.get("severity"),
            "category": it.get("category"),
            "what": it.get("name"),
            "where": _loc(it),
            "remediation": it.get("remediation"),
        })
    return out


def _grouped_findings(items: list[dict], limit: int = 3) -> list[dict]:
    """Collapse repeats of the same finding into one row with a count, so a single
    pattern hit in 25 files reads as 'X (×25)' rather than 25 separate findings."""
    groups: dict[tuple, dict] = {}
    order: list[tuple] = []
    for it in items:
        key = (it.get("severity"), it.get("name"))
        g = groups.get(key)
        if g is None:
            groups[key] = {
                "severity": it.get("severity"),
                "category": it.get("category"),
                "what": it.get("name"),
                "where": _loc(it),
                "remediation": it.get("remediation"),
                "count": 1,
            }
            order.append(key)
        else:
            g["count"] += 1
    # Surface the most important first: severity (critical > high > medium > low), then
    # the highest-count pattern within a severity — so a big cluster (e.g. vulnerable
    # deps) isn't dropped behind a single lower-priority finding. Stable within ties.
    sev_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    ranked = sorted(
        groups.values(),
        key=lambda g: (sev_rank.get(g["severity"], 4), -g["count"]),
    )
    return ranked[:limit]


def _scan_block(
    data: dict,
    verb: str,
    report_path: str,
    target: str,
    adoption: tuple[int, str, int] | None = None,
    install_hint: str = "",
    hosted: bool = False,
) -> str:
    """Shape a /public/scan response into a response that leads with a plain verdict
    (which survives the model summarizing the tool output), followed by a compact 8-bit
    trust/adoption card, the findings, and the signed-report links."""
    score = int(data.get("trust_score") or 0)
    items = (data.get("findings") or {}).get("items") or []
    crit = sum(1 for i in items if i.get("severity") == "critical")
    high = sum(1 for i in items if i.get("severity") == "high")
    safe = _safe_verdict(data)
    risk = (crit + high) > 0
    # Three presentation treatments over the strict two machine states: a clean result
    # that only missed the bar on coverage/signals must NOT wear the same risk warning
    # as a target with real findings. Adoption is context here, never a verdict input.
    mode = "safe" if safe else ("risk" if risk else "limited")
    # A retired package must not lead with "clean": the headline is what a model relays.
    _deprecated = isinstance(data.get("deprecation"), str) and bool(data["deprecation"].strip())
    if _deprecated and mode != "risk":
        mode = "deprecated"
    # A published advisory against THIS version outranks 'clean' and 'deprecated'.
    _advs = [a for a in (data.get("advisories") or [])
             if isinstance(a, dict) and a.get("affects_scanned_version")]
    if _advs and mode != "risk":
        mode = "vulnerable"
    # What the sandbox caught outranks every other headline: a canary leak or a critical
    # behavioral finding never sits under "safe", "clean", or "deprecated".
    _alarm = _sandbox_alarm(data)
    if _alarm:
        mode = "sandbox"

    # Reason phrase, reused in the headline and the Next step (limited mode only).
    _files = (data.get("metadata") or {}).get("files_scanned")
    if isinstance(_files, int) and 0 < _files < 8:
        reason = (f"capped because there's little code to inspect "
                  f"({_files} file{'' if _files == 1 else 's'})")
    else:
        # Only compare numeric subscores — a null/non-numeric value would make min() raise
        # and turn a successful scan into a generic error.
        _subs = {k: v for k, v in (data.get("category_scores") or {}).items()
                 if isinstance(v, (int, float))}
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
    elif mode == "sandbox":
        head = f"⚠️ Review before you {verb} — caught in the sandbox: {_alarm}"
        n = crit + high
        why = (f"Plus {n} blocking static finding{'' if n == 1 else 's'}." if n else
               "The static scan found no blocking issues; the sandbox observation is "
               "what to weigh.")
        glyph = "⚠ REVIEW"
    elif mode == "vulnerable":
        _fix = _highest_fix(_advs)
        n = len(_advs)
        head = (f"⚠️ {n} known vulnerabilit{'y' if n == 1 else 'ies'} in this version"
                + (f" — upgrade to {_fix} or later" if _fix else ""))
        why = ("Published advisories (" + ", ".join(str(a.get("id")) for a in _advs[:3])
               + (", …" if n > 3 else "") + ") affect the version you'd install.")
        glyph = "⚠ VULNERABLE"
    elif mode == "deprecated":
        head = "⚠️ Deprecated — don't adopt for new work"
        why = ("The maintainer retired this package, so it won't get security fixes. "
               "The code itself showed no blocking issues.")
        glyph = "⚠ DEPRECATED"
    else:
        head = "◍ Clean, limited coverage"
        why = f"No risks found; {reason}."
        glyph = "◍ LIMITED"

    # The three-phrase lead (src.scanner.verdict.decide): "<phrase>[ · Certified] —
    # <reason>". The mode-specific detail that the phrase does not carry (the fix
    # release, what the sandbox caught, the coverage cap) stays after the score.
    _decision = _decision_of(data)
    _lead = _decision_leads(_decision, safe)
    if _lead:
        head, glyph = _decision_head(data, _decision)
        if mode in ("safe", "risk"):
            why = ""
        elif mode == "vulnerable":
            _fix = _highest_fix(_advs)
            why = (f"Upgrade to {_fix} or later. " if _fix else "") + why
        elif mode == "sandbox":
            _static = _severity_counts(crit, high)
            why = f"Caught in the sandbox: {_alarm}." + (
                f" Plus {_static} static finding{'' if crit + high == 1 else 's'}."
                if _static else " The static scan found no critical or high finding.")
        elif mode == "limited":
            why = f"Score {reason}."

    # Trust and adoption always travel together (as on the site's dual mark). When
    # there's no established adoption signal (bare endpoint / brand-new package), say
    # "new" rather than dropping the pairing.
    if adoption:
        count, unit, _ = adoption
        adopt_clause = f" Adoption: {_compact_int(count)} {unit}."
    elif hosted:
        # A hosted MCP endpoint has no registry downloads or stars to count. Say that,
        # not "new": a widely used server would otherwise read as unproven.
        adopt_clause = " Adoption: no public data for a hosted endpoint."
    else:
        adopt_clause = " Adoption: new (no established public data yet)."
    # Line 1 carries the whole verdict in words, so it survives even if a client only
    # relays the model's one-line summary of the tool result.
    if _lead:
        _why = f" {why.strip()}" if why.strip() else ""
        lines = [f"{head}. {target}: trust {score}/100.{_why}{adopt_clause}", ""]
    else:
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
    elif hosted:
        card.append(f"  ADOPTION  {_trust_bar(0)}  n/a (hosted endpoint)")
    else:
        card.append(f"  ADOPTION  {_trust_bar(0)}  new")
    _when = str(data.get("scanned_at") or "")[:16].replace("T", " ")
    if _when:
        card.append(f"  scanned   {_when} UTC")
    if bool(data.get("jws")):
        card.append("  signed ✔ Ed25519 · recompute offline")
    card += ["─────────────────────────────────────────", "```"]
    lines += card
    _ver = _version_line(data)
    if _ver:
        lines.append(_ver)
    lines.append("")

    # Incident history (context, not scored): was this package ever caught being malicious?
    _inc = _incident_summary(data.get("incident_history") or {})
    if _inc:
        _latest = _inc.get("latest") or {}
        _id = _latest.get("id") or "advisory"
        _when = (str(_latest.get("published") or "")[:10]) or "date unknown"
        if _inc.get("current_version_affected"):
            lines.append(
                f"🚨 **Known compromise — this version is flagged malicious** "
                f"({_id}, {_when}). Do not install this version.")
        else:
            lines.append(
                f"⚠️ **Incident history:** this package had a known compromise "
                f"({_id}, {_when}); the current version is not flagged. Context only — "
                f"it does not change the score.")
        lines.append("")

    # The sandbox observation: ahead of the static findings when it caught something,
    # after them when clean (or pending / not started).
    _sb = _sandbox_section(data)
    _sb_first = bool(_sb) and _sandbox_has_findings(data)
    if _sb_first:
        lines += _sb + [""]

    fs = _grouped_findings(items, 5)
    if fs:
        lines.append("**Top findings:**")
        for f in fs:
            times = f" (×{f['count']})" if f.get("count", 1) > 1 else ""
            tail = f" → {f['remediation']}" if f.get("remediation") else ""
            lines.append(f"- [{f['severity']}] {f['what']}{times} ({f['where']}){tail}")
        shown = sum(f.get("count", 1) for f in fs)
        if len(items) > shown:
            lines.append(f"- … {len(items) - shown} more")
        lines.append("")

    if _sb and not _sb_first:
        lines += _sb + [""]

    # Install CTA (own line so the model relays it). Shown for anything without blocking
    # findings — safe gets the confident label, limited gets a "verify first" cue. Never
    # on a review result (real findings to weigh first).
    if (install_hint and mode not in ("risk", "deprecated", "sandbox", "vulnerable")
            and _decision.decision != "do_not_connect"):
        if mode == "safe":
            lines.append(f"**Ready to install:** `{install_hint}`")
        else:  # limited — no risks found, but not fully verified
            lines.append(f"**Install** (no risks found, verify first): `{install_hint}`")

    # A concrete next step for the agent/user — describes what to do with THIS result.
    # (Purely about our own verdict; it never tells the agent to auto-run other tools.)
    if _lead:
        action = _next_step(_decision, mode, verb, reason, _advs, report_path,
                            bool(install_hint))
    elif mode == "safe":
        action = f"clears the bar, so it's safe to {verb}."
    elif mode == "vulnerable":
        _fix = _highest_fix(_advs)
        action = (f"upgrade to {_fix} or later before you {verb}; the advisories list the "
                  "fixed releases." if _fix else
                  "no fixed release is listed — avoid this version or isolate it.")
    elif mode == "deprecated":
        action = ("don't adopt it for new work. Pick a maintained alternative (the "
                  "deprecation message may name one) and scan that before you connect it.")
    elif mode == "sandbox":
        action = ("hold off. Ask me to walk through what the sandbox observed and whether "
                  "it matters for your use, or check an alternative.")
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
    _dep = data.get("deprecation")
    if isinstance(_dep, str) and _dep.strip():
        _rel = ", ".join(p for p in _version_parts(data) if p)
        _rel = f" (latest release {_rel})" if _rel else ""
        lines.append(
            f"**Deprecated by its maintainer**{_rel}: \"{_dep.strip()[:200]}\" — it won't "
            "get security fixes; don't adopt it for new work, use a maintained alternative.")
    lines.append(f"**Next:** {action}")
    lines.append(
        f"Full report: {_WEB_BASE}{report_path} · "
        f"Verify offline: {_WEB_BASE}/how-it-works#verify"
    )
    # (The "automate scanning via a CLAUDE.md rule / SessionStart hook" pitch is NOT
    #  emitted per-scan — a reviewer could read config-changing suggestions in tool output
    #  as friction. It lives in about_agentavow + the docs page instead.)
    return "\n".join(lines)


# ── Behavioral sandbox: what AgentAvow saw when it ran the tool ─────────────────────
# Read from ``data["behavioral"]`` (a dated, signed observation kept apart from the
# recomputable score). Everything here is defensive: a missing or odd field drops its
# clause, never the scan result. Wording is plain and factual — no adjectives.

# Why an MCP server did not start (``grade_summary.start_reason``), in plain words. None
# of these is a finding: the run just could not exercise the tools.
_START_REASONS: dict[str, str] = {
    "needs_credentials": "it needs credentials (an API key or token) to start",
    "needs_arguments": "it needs a startup argument, such as a URL or connection string",
    "missing_binary": "a program it depends on is not available in the sandbox",
    "no_entrypoint": "the package has no runnable entry point to start",
    "resource_limit": "it hit the sandbox memory/process limit before starting",
    "install_failed": "the package failed to install",
    "timeout": "it did not start within the sandbox time limit",
    "crashed": "it exited with an error on start",
}
_START_UNKNOWN = "the run did not record why"
_SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _needed_argument(detail: str) -> str:
    """The specific launch argument a needs_arguments error asks for, when it names one."""
    low = (detail or "").lower()
    if any(k in low for k in ("database url", "connection string", "dsn", "postgres://",
                              "postgresql://")):
        return "a database URL"
    if "url" in low or "<https://" in low:
        return "a URL"
    if "path" in low or "directory" in low or "<dir" in low:
        return "a path"
    return ""


def _start_phrase(b: dict) -> tuple[str, str]:
    """(reason key, plain phrase) for a server that did not start."""
    gs = b.get("grade_summary") if isinstance(b.get("grade_summary"), dict) else {}
    reason = str((gs or {}).get("start_reason") or "").strip().lower()
    phrase = _START_REASONS.get(reason, _START_UNKNOWN)
    if reason == "needs_arguments":
        arg = _needed_argument(str((gs or {}).get("start_reason_detail") or ""))
        if arg:
            phrase = f"it needs {arg} as a startup argument"
    elif reason == "crashed":
        detail = str((gs or {}).get("start_reason_detail") or "").strip()
        if detail:
            phrase += f" (\"{detail[:100]}\")"
    return reason, phrase


def _start_short(b: dict) -> str:
    """A few words for one-line summaries: 'needs a database URL', 'crashed on start'."""
    reason, _ = _start_phrase(b)
    gs = b.get("grade_summary") if isinstance(b.get("grade_summary"), dict) else {}
    if reason == "needs_arguments":
        arg = _needed_argument(str((gs or {}).get("start_reason_detail") or ""))
        return f"needs {arg or 'a startup argument'}"
    return {
        "needs_credentials": "needs credentials", "missing_binary": "missing program",
        "no_entrypoint": "no entry point", "resource_limit": "resource limit",
        "install_failed": "install failed", "timeout": "timed out",
        "crashed": "crashed on start",
    }.get(reason, "did not start")


def _cap(s: str) -> str:
    return s[:1].upper() + s[1:]


def _clip(s: str, n: int) -> str:
    s = " ".join(str(s or "").split())
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def _behavioral_findings(b: dict) -> list[dict]:
    """Behavioral findings, a canary leak first, then by severity. A canary hit that the
    graders did not (yet) turn into a finding still leads."""
    fs = [f for f in (b.get("findings") or []) if isinstance(f, dict)]
    exfil = [h for h in (b.get("canary_exfil") or []) if isinstance(h, dict)]
    if exfil and not any(f.get("rule") == "credential_canary_exfiltrated" for f in fs):
        via = ", ".join(f"{h.get('via') or '?'}:{h.get('host') or '?'}" for h in exfil[:4])
        fs.append({"rule": "credential_canary_exfiltrated", "severity": "critical",
                   "evidence": f"canary left the sandbox via {via}"})
    return sorted(fs, key=lambda f: (f.get("rule") != "credential_canary_exfiltrated",
                                     _SEV_RANK.get(str(f.get("severity")), 4)))


def _finding_phrase(f: dict) -> str:
    """One behavioral finding in concrete terms, naming the tools and paths/hosts."""
    rule = str(f.get("rule") or "")
    ev = str(f.get("evidence") or "").strip()
    if rule == "credential_canary_exfiltrated":
        via = ev.split("via", 1)[1].strip() if "via" in ev else ""
        return "a planted credential left the sandbox" + (f" ({_clip(via, 80)})" if via else "")
    if rule == "annotation_readonly_violated" and " wrote " in ev:
        parts = [p.strip() for p in ev.split(";") if " wrote " in p]
        out = [f"{t.strip()} declares read-only but wrote {w.strip()}"
               for t, w in (p.split(" wrote ", 1) for p in parts[:2])]
        if len(parts) > 2:
            out.append(f"+{len(parts) - 2} more tools")
        return _clip("; ".join(out), 160)
    if rule == "ssrf_internal_fetch":
        return _clip(f"followed a URL it was handed to an internal address — {ev}"
                     if ev else "followed a caller-supplied URL to an internal address", 160)
    if rule == "behavioral_undeclared_egress":
        hosts = ev[len("egress to "):] if ev.startswith("egress to ") else ev
        return _clip(f"contacted undeclared hosts: {hosts}", 140)
    if rule == "annotation_open_world_violated":
        return "every tool declares no network access (openWorldHint=false), yet it reached " \
               "the network"
    if rule == "canary_echoed_in_result":
        names = ev.rsplit(" of ", 1)[-1] if " of " in ev else ""
        return "a tool returned an environment secret's value" + (
            f" ({_clip(names, 60)})" if names else "")
    if rule == "tool_call_crashed_server":
        tools = ev.rsplit(" to ", 1)[-1] if " to " in ev else ""
        return "a tool call crashed the server" + (f" ({_clip(tools, 60)})" if tools else "")
    name = str(f.get("name") or rule or "behavioral finding")
    return _clip(name + (f": {ev}" if ev else ""), 140)


def _sandbox_alarm(data: dict) -> str | None:
    """The short phrase for the headline when the sandbox caught something that must not
    sit under a 'safe' or 'clean' headline: a canary leak, or any critical or HIGH
    behavioral finding (the same findings that pull the score below the safe bar).
    Most serious first. None otherwise."""
    b = data.get("behavioral")
    if not isinstance(b, dict) or not b.get("ran") or _is_live_probe(b):
        return None
    found = _behavioral_findings(b)
    for pick in (lambda f: f.get("rule") == "credential_canary_exfiltrated",
                 lambda f: str(f.get("severity")) == "critical",
                 lambda f: str(f.get("severity")) == "high"):
        for f in found:
            if pick(f):
                return _clip(_finding_phrase(f), 90)
    return None


def _sandbox_has_findings(data: dict) -> bool:
    """Sandbox findings that should LEAD the result. A live probe's findings are advisory
    and stay after the static findings."""
    b = data.get("behavioral")
    return (isinstance(b, dict) and bool(b.get("ran")) and not _is_live_probe(b)
            and bool(_behavioral_findings(b)))


def _is_live_probe(b: dict) -> bool:
    from src.scanner.verdict import is_advisory_block
    return is_advisory_block(b)


def _live_probe_section(b: dict) -> list[str]:
    """The opt-in live probe of a remote MCP server (``plan == "live-probe"``), as a short
    labelled block. Advisory and unsigned: only read-only-annotated tools were called, the
    answers are not reproducible, and nothing here moves the score or the verdict."""
    head = "**Probed live** (read-only tools only, advisory, not scored): "
    ex = b.get("exercise") if isinstance(b.get("exercise"), dict) else {}
    gs = b.get("grade_summary") if isinstance(b.get("grade_summary"), dict) else {}
    lines: list[str] = []
    if not ex.get("launch_ok"):
        reason = str(gs.get("start_reason") or "")
        if reason == "needs_credentials":
            lines.append(head + "the server requires credentials (HTTP 401/403 on the "
                         "handshake), so no tool was called.")
        elif reason == "timeout":
            lines.append(head + "the server did not answer the handshake in time; no tool "
                         "was called.")
        else:
            detail = str(gs.get("start_reason_detail") or "").strip()
            lines.append(head + "the handshake failed"
                         + (f" ({_clip(detail, 80)})" if detail else "") + "; no tool was called.")
        return lines
    calls = [c for c in (ex.get("calls") or []) if isinstance(c, dict)]
    called = {c.get("tool") for c in calls if c.get("tool")}
    eligible = [t for t in (ex.get("eligible") or []) if isinstance(t, str)]
    listed = [t for t in (ex.get("tools") or []) if isinstance(t, dict)]
    n, m = len(called), max(len(eligible), len(called))
    skipped = len(listed) - m
    what = (f"called {n} of {m} read-only tool{'' if m == 1 else 's'} once each with "
            "synthetic inputs")
    if skipped > 0:
        what += (f"; {skipped} tool{'' if skipped == 1 else 's'} without a read-only "
                 f"annotation {'was' if skipped == 1 else 'were'} not called")
    if m == 0:
        what = (f"listed {len(listed)} tool{'' if len(listed) == 1 else 's'}; none "
                "declares itself read-only, so none was called")
    errored = sorted({c["tool"] for c in calls if c.get("ok") and c.get("is_error")})
    slow = sorted({c["tool"] for c in calls
                   if not c.get("ok") and str(c.get("error") or "") == "call_timeout"})
    failed = sorted({c["tool"] for c in calls if not c.get("ok") and c["tool"] not in slow})
    tail = []
    if errored:
        tail.append(f"{len(errored)} returned an error")
    if slow:
        tail.append(f"{len(slow)} ({', '.join(slow[:3])}) took longer than the 8 s per-call "
                    "limit — a slow tool, not a failure")
    if failed:
        tail.append(f"{len(failed)} did not answer")
    if ex.get("timed_out"):
        tail.append("stopped at the time budget")
    lines.append(head + what + (" (" + "; ".join(tail) + ")" if tail else "") + ".")
    fs = [f for f in (b.get("findings") or []) if isinstance(f, dict)]
    fs.sort(key=lambda f: _SEV_RANK.get(str(f.get("severity")), 4))
    for f in fs[:4]:
        sev = str(f.get("severity") or "").lower()
        name = str(f.get("name") or f.get("rule") or "finding")
        ev = str(f.get("evidence") or "").strip()
        lines.append(f"- Advisory ({sev or 'note'}): {_clip(name, 110)}"
                     + (f" — {_clip(ev, 120)}" if ev else ""))
    if len(fs) > 4:
        lines[-1] += f" (+{len(fs) - 4} more in the report)"
    lines.append("- Not scored: a live answer cannot be recomputed by a verifier, so this "
                 "never changes the trust score or the verdict.")
    return lines[:6]


def _host_list(hosts: list[str], limit: int = 4) -> str:
    return ", ".join(hosts[:limit]) + (f" (+{len(hosts) - limit} more)" if len(hosts) > limit
                                       else "")


def _network_clause(b: dict) -> str:
    hosts = sorted({str(h) for h in (b.get("egress_hosts") or []) if h})
    if not hosts:
        return "network: no connections"
    vendor = sorted({str(h) for h in (b.get("vendor_egress") or []) if h} & set(hosts))
    odd = sorted({str(h) for h in (b.get("unexpected_egress") or []) if h})
    if odd:
        rest = [h for h in hosts if h not in odd]
        return (f"network: undeclared {_host_list(odd)}"
                + (f" (plus {_host_list(rest, 3)})" if rest else ""))
    out = f"network: only {_host_list(hosts)}"
    if vendor:
        out += f" (vendor: {_host_list(vendor, 2)})"
    return out


def _file_clause(ex: dict) -> str:
    writes = sorted({str(w) for c in (ex.get("calls") or []) if isinstance(c, dict)
                     for w in (c.get("fs_writes") or []) if w})
    if not writes:
        return "file writes: none"
    try:
        from src.scanner.behavioral.graders import _is_cache_like, _is_scratch
        real = [w for w in writes if not _is_scratch(w) and not _is_cache_like(w)]
    except Exception:  # noqa: BLE001 — wording only; fall back to the raw count
        real = writes
    if not real:
        return "file writes: none outside temp/cache dirs"
    return f"file writes: {len(real)} outside temp/cache dirs (e.g. {_clip(real[0], 60)})"


def _credential_clause(ex: dict, b: dict) -> str:
    canary = ex.get("canary") if isinstance(ex.get("canary"), dict) else {}
    names = [str(n) for n in (canary.get("env_names") or []) if n]
    seen = [str(n) for n in (canary.get("seen_in_result") or []) if n]
    if not names or b.get("canary_exfil") or seen:
        return ""  # a leak or an echo is reported as a finding line instead
    shown = ", ".join(names[:3]) + (f" +{len(names) - 3}" if len(names) > 3 else "")
    return f"credentials: canary values for {shown} stayed put"


def _sandbox_section(data: dict) -> list[str]:
    """The behavioral sandbox observation as a short labelled block (≤6 lines), or [] when
    the scan carries no sandbox result (never invented). Pending runs say so and invite a
    follow-up. A server that did not start says why in plain words and that it is not a
    finding. Findings name the tool and what it did; a canary leak leads."""
    b = data.get("behavioral")
    if not isinstance(b, dict):
        return []
    if b.get("pending"):
        return ["**Sandbox:** running now — ask again in about a minute for the observed "
                "behavior (tools called, network, files)."]
    if not b.get("ran"):
        return []
    if _is_live_probe(b):
        return _live_probe_section(b)
    att = b.get("attestation") if isinstance(b.get("attestation"), dict) else None
    when = str((att or {}).get("observed_at") or "")[:10]
    tag = f"gVisor, signed {when}" if (att and when) else ("gVisor, signed" if att else "gVisor")
    head = f"**Observed in the sandbox** ({tag}): "
    ex = b.get("exercise") if isinstance(b.get("exercise"), dict) else None
    plan = str(b.get("plan") or "")
    net = _network_clause(b)
    lines: list[str] = []
    if ex and ex.get("launch_ok"):
        tools = [t for t in (ex.get("tools") or []) if isinstance(t, dict)]
        called = {c.get("tool") for c in (ex.get("calls") or [])
                  if isinstance(c, dict) and c.get("tool")}
        n, m = len(called), max(len(tools), len(called))
        if plan == "skill":
            what = (f"cloned the skill and ran {n} of {m} hook{'' if m == 1 else 's'}/"
                    "script(s) with canary credentials.")
        elif n:
            what = (f"started the server and called {n} of {m} tool{'' if m == 1 else 's'} "
                    "with synthetic inputs.")
        else:
            what = (f"started the server and listed {m} tool{'' if m == 1 else 's'}; "
                    "none were called.")
        lines.append(head + what)
        clauses = [net, _file_clause(ex), _credential_clause(ex, b)]
        lines.append("- " + _cap("; ".join(c for c in clauses if c)) + ".")
    elif plan == "skill":
        reason, phrase = _start_phrase(b)
        if reason == "no_entrypoint":
            phrase = "it ships no lifecycle hook or runnable script"
        lines.append(head + f"cloned the skill, but nothing ran — {phrase}. "
                     "This is not a finding.")
        lines.append(f"- {_cap(net)} (during clone).")
    elif ex is not None or plan.endswith("-mcp"):
        _, phrase = _start_phrase(b)
        lines.append(head + f"installed it, but the server did not start — {phrase}. "
                     "Its tools were not exercised; this is not a finding.")
        lines.append(f"- {_cap(net)} (during install).")
    else:
        code = b.get("exit_code")
        verb = "ran the container image" if plan == "docker" else "installed and imported it"
        if isinstance(code, int) and code != 0:
            lines.append(head + f"{verb}; the step exited with code {code} "
                         f"(not a finding); {net}.")
        else:
            lines.append(head + f"{verb}; {net}.")
    fs = _behavioral_findings(b)
    room = 6 - len(lines) - 1  # leave a line for the score effect
    for f in fs[: max(room, 1)]:
        sev = str(f.get("severity") or "").lower()
        mark = "🚨 " if (f.get("rule") == "credential_canary_exfiltrated"
                         or sev == "critical") else ""
        lines.append(f"- {mark}Caught ({sev or 'finding'}): {_finding_phrase(f)}")
    if len(fs) > max(room, 1):
        lines[-1] += f" (+{len(fs) - max(room, 1)} more in the report)"
    eff = data.get("behavioral_score_effect")
    if isinstance(eff, dict) and eff.get("applied"):
        delta = eff.get("delta")
        why = str(eff.get("reason") or "").strip().rstrip(".")
        if isinstance(delta, int) and not isinstance(delta, bool) and delta:
            amount = f"{'+' if delta > 0 else '−'}{abs(delta)}"
            lines.append(f"- Included in the trust score: {amount}"
                         + (f", {_clip(why, 100)}." if why else "."))
        else:
            lines.append("- Included in the trust score (no change)"
                         + (f": {_clip(why, 100)}." if why else "."))
    return lines[:6]


def _sandbox_line(data: dict) -> str | None:
    """The sandbox block as one string (None when the scan carries no sandbox result)."""
    lines = _sandbox_section(data)
    return "\n".join(lines) if lines else None


def _version_parts(data: dict) -> tuple[str | None, str | None]:
    """(version, publish date YYYY-MM-DD) of the scanned release, when the scan has them."""
    ver = data.get("package_version")
    if not (isinstance(ver, str) and ver.strip()):
        ver = None
        for k in ("artifact_scan", "surface_detail"):
            d = data.get(k)
            if isinstance(d, dict) and isinstance(d.get("version"), str) and d["version"].strip():
                ver = d["version"]
                break
    pub = data.get("published_at")
    pub = pub.strip()[:10] if isinstance(pub, str) and pub.strip() else None
    return (_clip(ver.strip(), 40) if ver else None), pub


def _version_line(data: dict) -> str | None:
    """'Version 0.6.2 · published 2024-12-03' so a model does not fetch the registry."""
    ver, pub = _version_parts(data)
    if ver and pub:
        return f"Version {ver} · published {pub}"
    if ver:
        return f"Version {ver}"
    if pub:
        return f"Published {pub}"
    return None


def _safe_verdict(data: dict) -> bool:
    """The binary safe/needs-review call. Delegates to the shared helper so the MCP and
    the public API can never disagree."""
    return _shared_is_safe(data)


def _decision_of(data: dict) -> _Decision:
    """The three-phrase decision for a /public/scan response: the API's own unsigned
    ``decision`` / ``decision_final`` / ``decision_reason`` when present (so the MCP and
    the Check page say the same thing), else ``src.scanner.verdict.decide`` over the same
    data (an older cached response without the fields)."""
    dec = data.get("decision")
    if dec in _DECISION_VALUES:
        reason = data.get("decision_reason")
        if isinstance(reason, str) and reason.strip():
            return _Decision(dec, data.get("decision_final") is not False, reason.strip())
    return _decide(data)


def _decision_leads(decision: _Decision, safe: bool) -> bool:
    """Whether the headline leads with the decision phrase (see HEADLINE_FOLLOWS_DECISION)."""
    if HEADLINE_FOLLOWS_DECISION:
        return True
    return (decision.decision == "safe") == bool(safe)


def _severity_counts(crit: int, high: int) -> str:
    """'3 critical and 1 high' / '1 high' / '' — counts named by severity, so a line
    never says '4 blocking' next to a headline that says '3 critical'."""
    parts = [f"{n} {sev}" for n, sev in ((crit, "critical"), (high, "high")) if n]
    return " and ".join(parts)


def _next_step(decision: _Decision, mode: str, verb: str, cap: str, advisories: list,
               report_path: str, installable: bool) -> str:
    """The **Next:** line, one per decision: Safe → connect/install as usual; Review →
    the reason and what to check first; Do not connect → don't, see the report."""
    act = "install" if installable else "connect"
    if decision.decision == "safe":
        # Thin coverage reads Safe now that the verdict follows decide(), so key the
        # capped-score note off the decision's own reason, not the old "limited" mode.
        thin = mode == "limited" or "little code to inspect" in decision.reason
        tail = f" The score is {cap}, a confidence limit, not a finding." if thin else ""
        return f"Safe to connect: {act} it as usual.{tail}"
    if decision.decision == "do_not_connect":
        return (f"Do not connect or install it ({decision.reason}). The full report has the "
                f"evidence: {_WEB_BASE}{report_path}. If you need what it does, pick an "
                "alternative and scan that first.")
    if mode == "vulnerable":
        fix = _highest_fix(advisories)
        check = (f"upgrade to {fix} or later before you {verb} it; the advisories list the "
                 "fixed releases" if fix else
                 "no fixed release is listed, so avoid this version or isolate it")
    elif mode == "deprecated":
        check = ("don't adopt it for new work; pick a maintained alternative (the "
                 "deprecation message may name one) and scan that before you connect it")
    elif mode == "sandbox":
        check = ("read what the sandbox observed above and decide whether it matters for "
                 "your use before you connect, or check an alternative")
    elif mode == "risk":
        check = ("read the findings above (where each one is and how to fix it) and decide "
                 "whether they matter for your use before you connect, or check an "
                 "alternative")
    else:
        check = (f"no critical or high finding; the score is {cap}. Check the full report "
                 "for the weak signals before you connect")
    return f"Review before you connect ({decision.reason}): {check}."


def _decision_head(data: dict, decision: _Decision) -> tuple[str, str]:
    """(headline, card glyph): '✅ Safe to connect · Certified — <reason>' and the
    phrase with its icon for the monospace card."""
    phrase = _decision_headline(decision.decision, _is_certified(data))
    icon = _DECISION_ICONS.get(decision.decision, "⚠️")
    return f"{icon} {phrase} — {decision.reason}", f"{icon} {phrase}"


# Registry words people commonly send to scan_repo by mistake ("npm chalk", "npm/chalk",
# "pypi requests"). Mapped to the scan_package registry so we can nudge to the right tool
# instead of a format error or a wasted GitHub 404. Only registries scan_package supports.
_REG_ALIAS = {
    "npm": "npm", "pypi": "pypi", "pip": "pypi", "python": "pypi",
    "crates": "crates", "cargo": "crates", "rust": "crates",
    "docker": "docker", "oci": "docker", "image": "docker", "container": "docker",
    "hf": "hf", "huggingface": "hf", "hugging_face": "hf",
}


def _package_nudge(owner: str, repo: str, raw: str) -> str | None:
    """If a scan_repo input looks like a package coordinate, return a nudge toward
    scan_package (with the normalized registry + name); else None."""
    if owner.lower() in _REG_ALIAS and repo:
        reg, name = _REG_ALIAS[owner.lower()], repo
    else:
        toks = (raw or "").strip().replace(":", " ").split()
        if len(toks) >= 2 and toks[0].lower() in _REG_ALIAS:
            reg, name = _REG_ALIAS[toks[0].lower()], toks[-1]
        else:
            return None
    return (f"That looks like a package, not a GitHub repo. Use scan_package with "
            f"registry='{reg}', name='{name}' (e.g. the npm package chalk → "
            f"scan_package registry='npm', name='chalk').")


def _text(s: str) -> list[types.TextContent]:
    return [types.TextContent(type="text", text=s)]


def _card_text(s: str) -> list[types.TextContent]:
    """A scan card marked audience=['user'] — a spec hint that this block is meant for
    the human (so a client MAY render it as-is rather than let the model paraphrase it).
    Advisory only; harmless where ignored, and the model still has structuredContent."""
    return [types.TextContent(
        type="text", text=s,
        annotations=types.Annotations(audience=["user"], priority=1.0),
    )]


def _incident_summary(ih: dict) -> dict | None:
    """Compact the scan's incident_history (OSV MAL-) into an MCP-friendly object, or
    None when there is no known incident. Context only — never affects the verdict."""
    if not ih.get("has_incident"):
        return None
    incs = ih.get("incidents") or []
    latest = incs[0] if incs else {}
    return {
        "known_compromise": True,
        "current_version_affected": bool(ih.get("current_version_affected")),
        "count": ih.get("count") or len(incs),
        "latest": {
            "id": latest.get("id"),
            "summary": latest.get("summary"),
            "published": latest.get("published"),
        },
    }


def _version_key(v: str) -> tuple:
    parts = []
    for p in str(v).lstrip("v").split("."):
        num = "".join(ch for ch in p if ch.isdigit())
        parts.append((int(num) if num else 0, p))
    return tuple(parts)


def _highest_fix(advisories: list[dict]) -> str | None:
    """The release that fixes ALL the listed advisories = the highest fixed_in."""
    fixes = [str(a.get("fixed_in")) for a in advisories if a.get("fixed_in")]
    return max(fixes, key=_version_key) if fixes else None


def _split_pinned_version(surface: str, spec: str) -> tuple[str, str | None]:
    """'chalk@5.3.0' / '@scope/name@1.2.3' / 'requests==2.32.5' / 'pkg===1.0' /
    'serde@1.0.200' → (name, version). A bare name → (name, None). Only an exact pin is
    honoured (ranges like ^1 or >=2 are ignored: the registry resolves latest)."""
    spec = (spec or "").strip()
    if surface == "pypi":
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*===?\s*([A-Za-z0-9][A-Za-z0-9.+!-]*)$", spec)
        if m:
            return m.group(1), m.group(2)
        m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)@([0-9][A-Za-z0-9.+!-]*)$", spec)
        return (m.group(1), m.group(2)) if m else (spec, None)
    # npm (incl. scoped) / crates: name@version where version starts with a digit
    m = re.match(r"^(@?[^@\s]+)@([0-9][^@\s]*)$", spec)
    if m and surface in ("npm", "crates"):
        return m.group(1), m.group(2)
    return spec, None


def _sandbox_struct(data: dict) -> dict | None:
    """The behavioral sandbox result as stable machine-readable fields. None when the
    tier does not apply; ``pending`` True while the first run is still going."""
    b = data.get("behavioral")
    if not isinstance(b, dict):
        return None
    if b.get("pending") or not b.get("ran"):
        return {"ran": False, "pending": bool(b.get("pending")),
                "reason": b.get("reason") or None}
    ex = b.get("exercise") if isinstance(b.get("exercise"), dict) else {}
    gs = b.get("grade_summary") or {}
    eff = data.get("behavioral_score_effect") or {}
    att = b.get("attestation") or {}
    findings = [{"rule": f.get("rule"), "severity": f.get("severity"), "name": f.get("name"),
                 "evidence": (f.get("evidence") or "")[:200]}
                for f in (b.get("findings") or []) if isinstance(f, dict)]
    leaked = bool(b.get("canary_exfil"))
    advisory = _is_live_probe(b)
    # A live probe's findings are advisory: reported, never an alarm.
    alarm = (not advisory) and (
        leaked or any(f["severity"] in ("critical", "high") for f in findings))
    return {
        "ran": True, "pending": False, "plan": b.get("plan"), "advisory": advisory,
        "server_started": bool(ex.get("launch_ok")) if ex else None,
        "start_reason": gs.get("start_reason"),
        "start_reason_detail": gs.get("start_reason_detail") or None,
        "tools_listed": len(ex.get("tools") or []) if ex else 0,
        "tools_called": len(ex.get("calls") or []) if ex else 0,
        "egress_hosts": b.get("egress_hosts") or [],
        "undeclared_egress": b.get("unexpected_egress") or [],
        "vendor_egress": b.get("vendor_egress") or [],
        "canary_env": (ex.get("canary") or {}).get("env_names") if ex else [],
        "canary_leaked": leaked,
        "findings": findings,
        "alarm": alarm,
        "score_effect": ({"delta": eff.get("delta"), "static_score": eff.get("static_score"),
                          "reason": eff.get("reason")} if eff.get("applied") else None),
        "signed_observation_at": att.get("observed_at") if isinstance(att, dict) else None,
    }


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
    # Shared with the public API so the two surfaces never disagree.
    verdict_reason = _shared_verdict_reason(data, safe)
    sandbox = _sandbox_struct(data)
    # Behavioral high/critical findings are findings: a consumer that only reads
    # findings_total / top_findings must see them (a model summarising structuredContent
    # said "0 findings" about a server caught sending telemetry).
    beh_items = [
        {"severity": f.get("severity"), "category": f.get("category") or "behavioral",
         "name": f.get("name"), "file_path": "<sandbox>", "sandbox": True}
        for f in (sandbox or {}).get("findings") or []
        if f.get("severity") in ("critical", "high") and not (sandbox or {}).get("advisory")
    ]
    alarm = bool(sandbox and sandbox.get("alarm"))
    dep = data.get("deprecation")
    return {
        "target": target,
        "scanned_at": data.get("scanned_at"),
        "target_type": target_type,
        "trust_score": score,
        # NOTE: no letter grade — external output is 0-100 score + tier + certified only.
        "tier": data.get("trust_tier"),
        "verdict": "safe" if safe else "needs_review",
        "verdict_reason": verdict_reason,
        # The three-phrase decision (unsigned; rides beside the binary verdict above,
        # which keeps its meaning): safe | review | do_not_connect, whether it is final
        # (False while the sandbox is still running) and the one-line reason.
        **_decision_of(data).as_dict(),
        "critical": crit + sum(1 for i in beh_items if i["severity"] == "critical"),
        "high": high + sum(1 for i in beh_items if i["severity"] == "high"),
        # a live probe's findings are advisory: they sit in sandbox.findings only
        "findings_total": int((data.get("findings") or {}).get("total") or len(items))
        + (0 if (sandbox or {}).get("advisory") else len((sandbox or {}).get("findings") or [])),
        "static_findings_total": int((data.get("findings") or {}).get("total") or len(items)),
        # Version actually scanned + when it was published (so a model need not fetch
        # the registry), the maintainer's deprecation notice (None = not retired), and
        # the package's own published advisories that affect this version.
        "package_version": data.get("package_version")
        or (data.get("surface_detail") or data.get("artifact_scan") or {}).get("version"),
        "published_at": data.get("published_at"),
        "deprecated": dep.strip()[:300] if isinstance(dep, str) and dep.strip() else None,
        "advisories_affecting_version": [
            {"id": a.get("id"), "severity": a.get("severity"), "fixed_in": a.get("fixed_in"),
             "summary": (a.get("summary") or "")[:160]}
            for a in (data.get("advisories") or []) if a.get("affects_scanned_version")
        ][:10],
        # What the sandbox observed (None until the first run completes; see `pending`).
        "sandbox": sandbox,
        # MUST match the signed attestation's certified.eligible (the 6 crypto gates) — a
        # trust product cannot have its MCP field disagree with its own signed report.
        # The "only render the Certified MARK when also safe" rule is a DISPLAY gate applied
        # in the card/site, NOT here. `certified_mark` carries that display value for
        # consumers who want the badge rule without re-deriving it.
        "certified": bool((data.get("certified") or {}).get("eligible")),
        "certified_mark": bool((data.get("certified") or {}).get("eligible")) and safe,
        # top findings, repeats collapsed to one row + count — for the card + CI triage
        "top_findings": (beh_items + _grouped_findings(items, 3))[:5],
        # context-only incident history (was this package ever compromised?) — never
        # part of the score/verdict; None when there is no known incident.
        "incident": _incident_summary(data.get("incident_history") or {}),
        # per-category 0-100 axes — explains WHY the score is what it is
        "subscores": data.get("category_scores") or {},
        # copy-paste install command — packages with NO blocking findings only (None for
        # repos/MCP endpoints, and None when there are critical/high findings to weigh
        # first, so a consumer can't read "install present" as "safe to install"; and
        # None when the decision is do_not_connect).
        "install": (
            {"npm": f"npm install {target}", "pypi": f"pip install {target}",
             "crates": f"cargo add {target}"}.get(target_type)
            if crit + high == 0 and not alarm and not dep
            and _decision_of(data).decision != "do_not_connect" else None
        ),
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


def _nullable(json_type: str, description: str) -> dict:
    return {"type": [json_type, "null"], "description": description}


# The outputSchema the three scan tools advertise: the shape of _scan_struct above. Keep
# the two in step (tests/test_mcp_output_schema.py checks every key is described). Loose
# where values come straight from the scan API, and extra keys are allowed, so the
# contract can grow without breaking a client.
_SCAN_OUTPUT_SCHEMA: dict = {
    "type": "object",
    "properties": {
        "target": {"type": "string", "description": "What was scanned, as given."},
        "scanned_at": _nullable("string", "When the scan ran (ISO 8601, UTC)."),
        "target_type": {"type": "string",
                        "description": "github, npm, pypi, crates, docker, hf, or mcp."},
        "decision": {
            "type": "string", "enum": list(_DECISION_VALUES),
            "description": "The answer to lead with: safe = Safe to connect, review = Review "
                           "before you connect, do_not_connect = Do not connect.",
        },
        "decision_final": {"type": "boolean",
                           "description": "False while the behavioral sandbox is still "
                                          "running; the decision can still change."},
        "decision_reason": {"type": "string",
                            "description": "One sentence naming what decided it."},
        "trust_score": {"type": "integer", "minimum": 0, "maximum": 100,
                        "description": "Trust score, 0-100. Evidence under the decision."},
        "tier": _nullable("string", "Trust tier for the score (detail, not the headline)."),
        "verdict": {"type": "string", "enum": ["safe", "needs_review"],
                    "description": "Binary form of the decision, kept for older clients."},
        "verdict_reason": {"type": "string",
                           "description": "Machine reason for the binary verdict, e.g. clean, "
                                          "blocking_findings, thin_coverage."},
        "critical": {"type": "integer", "minimum": 0,
                     "description": "Critical findings, static and sandbox."},
        "high": {"type": "integer", "minimum": 0,
                 "description": "High findings, static and sandbox."},
        "findings_total": {"type": "integer", "minimum": 0,
                           "description": "All findings, every severity."},
        "static_findings_total": {"type": "integer", "minimum": 0,
                                  "description": "Findings from static analysis only."},
        "package_version": _nullable("string", "Package version scanned."),
        "published_at": _nullable("string", "When that version was published."),
        "deprecated": _nullable("string", "The maintainer's deprecation notice, or null."),
        "advisories_affecting_version": {
            "type": "array", "description": "Published advisories that affect this version.",
            "items": {"type": "object"},
        },
        "sandbox": {"type": ["object", "null"],
                    "description": "What the behavioral sandbox observed; null if it does "
                                   "not apply."},
        "certified": {"type": "boolean",
                      "description": "Matches the signed attestation's certified.eligible."},
        "certified_mark": {"type": "boolean",
                           "description": "Certified and safe: show the Certified mark."},
        "top_findings": {
            "type": "array", "description": "Up to five most important findings.",
            "items": {"type": "object", "properties": {
                "severity": _nullable("string", "critical, high, medium, or low."),
                "what": _nullable("string", "What was found."),
                "where": _nullable("string", "File and line, if file-based."),
                "remediation": _nullable("string", "How to fix it."),
                "count": {"type": "integer", "description": "How many times it occurs."},
            }},
        },
        "incident": {"type": ["object", "null"],
                     "description": "Known past compromise (context only, never scored)."},
        "subscores": {"type": "object",
                      "description": "Per-category 0-100 scores behind the trust score.",
                      "additionalProperties": {"type": ["number", "null"]}},
        "install": _nullable("string", "Install command, only when nothing blocks it."),
        "adoption": {
            "type": ["object", "null"],
            "description": "The adoption score: real usage (downloads per week, stars or "
                           "installs). Never changes the decision.",
            "properties": {"count": {"type": "integer"}, "unit": {"type": "string"},
                           "score_0_100": {"type": "integer"}},
        },
        "signed": {"type": "boolean",
                   "description": "True when a signed (Ed25519/JWS) attestation backs this."},
        "cached": {"type": "boolean", "description": "Served from the ~1h cache."},
        "rescan_pending": {"type": "boolean",
                           "description": "A fresh scan was started; this is the previous "
                                          "result."},
        "report_url": {"type": "string", "description": "Full report page."},
        "report_json_url": {"type": "string", "description": "The full verdict as JSON."},
        "verify_url": {"type": "string", "description": "How to verify offline."},
    },
    "required": ["target", "target_type", "decision", "decision_final", "decision_reason",
                 "trust_score", "verdict", "report_url"],
}


# --------------------------------------------------------------------------- #
# tool definitions (all read-only, unauthenticated)
# --------------------------------------------------------------------------- #
def _RO(title: str, readOnlyHint: bool = True, openWorldHint: bool = True) -> types.ToolAnnotations:  # noqa: N802, N803, E501 — mirrors MCP field names + existing call sites
    """Read-only tool annotation with EVERY behavioral hint set explicitly (never
    null) so it matches the tool's actual behavior — the four hints app-review checks:
    readOnlyHint (never mutates), destructiveHint=False (nothing is destroyed),
    idempotentHint=True (read-only → repeating a call has no additional effect),
    openWorldHint (True for the scan/lookup tools that reach arbitrary external
    targets; False for a self-contained tool like about_agentavow that reaches
    nothing external)."""
    return types.ToolAnnotations(
        title=title, readOnlyHint=readOnlyHint,
        destructiveHint=False, idempotentHint=True, openWorldHint=openWorldHint,
    )

_TOOLS: list[types.Tool] = [
    types.Tool(
        name="scan_repo",
        title="Scan a GitHub repo",
        description=(
            "Scan a public GitHub repository with AgentAvow and return whether it is safe "
            "for an agent to connect to: one of three answers with its reason (Safe to "
            "connect, Review before you connect, or Do not connect), a 0-100 trust score, an "
            "adoption score from real usage (stars), the findings behind it (with where and how "
            "to fix), and a signed, offline-verifiable attestation. Read-only, no account. "
            "Calls the AgentAvow public API at agentavow.com."
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
            "AgentAvow. Returns one of three answers with its reason (Safe to connect, Review "
            "before you connect, or Do not connect), a 0-100 trust score, an adoption score from "
            "real usage (downloads per week), findings with remediation, and a signed "
            "attestation. Also reports published advisories that affect the scanned version, "
            "the maintainer's deprecation notice, repo-vs-artifact drift (files shipped that "
            "aren't in the source), and AgentAvow's behavioral sandbox results when available. "
            "Scans the "
            "latest version unless `version` (or a pin in the name) names one. Read-only; "
            "calls agentavow.com."
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
                "version": {
                    "type": "string",
                    "description": "Exact version to scan, e.g. '5.3.0'. Optional: the latest "
                                   "version by default. A pin in the name ('chalk@5.3.0', "
                                   "'requests==2.32.5') works too.",
                    "maxLength": 64,
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
            "Returns one of three answers with its reason (Safe to connect, Review before you "
            "connect, or Do not connect), a 0-100 trust score, findings, and a signed "
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
                "entity_id": {
                    "type": "string",
                    "description": ("UUID of a registered AgentAvow entity (resolve one with "
                                    "lookup_identity; unknown ids return guidance, not an error)."),
                },
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
                "target_entity_id": {
                    "type": "string",
                    "description": ("UUID of a registered target entity "
                                    "(resolve one with lookup_identity)."),
                },
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
                "entity_id": {
                    "type": "string",
                    "description": ("UUID of a registered AgentAvow entity "
                                    "(resolve one with lookup_identity)."),
                },
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
        annotations=_RO(title="About AgentAvow", readOnlyHint=True, openWorldHint=False),
    ),
]

# Attach the MCP Apps trust-card view to the scan tools. Set on the field (the
# constructor silently drops an unknown `meta=` kwarg; the field alias is _meta).
_SCAN_TOOLS = ("scan_repo", "scan_package", "scan_mcp_server")
for _t in _TOOLS:
    if _t.name in _SCAN_TOOLS:
        # ChatGPT shows these short status lines while the tool runs and when it is done
        # (openai/* keys; other hosts ignore them).
        _t.meta = {**_CARD_META, "openai/toolInvocation/invoking": "Scanning with AgentAvow…",
                   "openai/toolInvocation/invoked": "AgentAvow scan complete"}
        # The scan tools return structuredContent; describe it (see _SCAN_OUTPUT_SCHEMA).
        _t.outputSchema = _SCAN_OUTPUT_SCHEMA

# Defensive length bounds on string inputs (hygiene — these are interpolated into API
# paths; also what our own scanner flags on unconstrained params). Generous so no real
# input is rejected; additive only (never changes an existing constraint).
_MAXLEN = {"repo": 214, "owner": 214, "name": 214, "endpoint_url": 512,
           "entity_id": 64, "target_entity_id": 64}
for _t in _TOOLS:
    for _k, _p in ((_t.inputSchema or {}).get("properties") or {}).items():
        if _p.get("type") == "string" and "maxLength" not in _p and _k in _MAXLEN:
            _p["maxLength"] = _MAXLEN[_k]


@server.list_tools()
async def _list_tools() -> list[types.Tool]:
    return _TOOLS


@server.list_resources()
async def _list_resources() -> list[types.Resource]:
    _r = types.Resource(
        uri=_CARD_URI,
        name="AgentAvow trust card",
        description="Interactive trust card rendered from a scan result.",
        mimeType=_CARD_MIME,
    )
    # ChatGPT's app review reads the widget domain + CSP off the TEMPLATE resource
    # (not just the tool). The card is fully self-contained (inline HTML/CSS/SVG, no
    # external fetches), so both allow-lists are empty — but they must be *declared*.
    # Set via .meta after construction (the constructor drops an unknown meta= kwarg).
    # ChatGPT-namespaced widget domain/CSP only — no `ui` object here (Claude reads
    # the resource content, and an unexpected ui.* on the resource can break its render).
    _r.meta = {
        "openai/widgetDomain": "https://agentavow.com",
        "openai/widgetCSP": _WIDGET_CSP,
    }
    return [_r]


# OpenAI reads the widget's domain, CSP and description off the resource CONTENTS.
# openai/* keys only: an unexpected ui.* on the resource has broken Claude's render.
_CARD_CONTENTS_META = {
    "openai/widgetDomain": "https://agentavow.com",
    "openai/widgetCSP": _WIDGET_CSP,
    "openai/widgetPrefersBorder": True,
    # Inline only: the card is a compact summary with a link to the full report.
    "openai/ui": {"availableDisplayModes": ["inline"]},
    "openai/widgetDescription": (
        "An AgentAvow trust card: the answer (Safe to connect, Review before you connect, "
        "or Do not connect) with its reason, the 0-100 trust score, the adoption score, "
        "the top findings, and a link to the signed report."
    ),
}


@server.read_resource()
async def _read_resource(uri: object) -> list[ReadResourceContents]:
    if str(uri).rstrip("/") == _CARD_URI.rstrip("/"):
        return [ReadResourceContents(content=trust_card_html(HEADLINE_FOLLOWS_DECISION),
                                     mime_type=_CARD_MIME, meta=_CARD_CONTENTS_META)]
    return []


# A discoverable "intro" the user can invoke from the client's prompt picker — the
# closest thing to a post-install welcome the MCP spec offers (there is no server-
# controlled install-time UI). Complements the connect-time `instructions`.
_GET_STARTED = (
    "Give me a short tour of AgentAvow. In a few lines cover: what it can check for me "
    "(a GitHub repo, an npm/PyPI/crates/Docker/Hugging Face package, a live MCP server, "
    "or an agent identity); how to read a result (each scan leads with one of three "
    "answers and its reason — Safe to connect, Review before you connect, or Do not "
    "connect, marked Certified where earned — with a 0-100 trust score and an adoption "
    "score underneath, and every result is signed and can be recomputed offline); and "
    "give me two or three "
    "concrete example things I could ask you to scan right now. If I'm using Claude Code, "
    "also mention that I can OPT IN to scanning new tools automatically before I install "
    "them, via a one-line CLAUDE.md rule or a SessionStart hook "
    "(setup: https://agentavow.com/docs/auto-scan-claude-code) — it's my own optional "
    "habit to configure, not something the connector does on its own."
)


# User-invoked (a prompt is picked by the person, never run on its own): grade the
# other servers/connectors in the conversation. The closest thing a connector has to
# "scan after install".
_CHECK_MY_CONNECTIONS = (
    "List every MCP server, connector, or plugin enabled in this conversation other than "
    "AgentAvow. For each one you can identify by a public https URL, run scan_mcp_server; "
    "for each one you can identify by an npm or PyPI package, run scan_package; give each "
    "its one-line answer (Safe to connect, Review before you connect, or Do not connect, "
    "with the reason and ' · Certified' where earned), then the trust score, the adoption "
    "score, the top finding, and the report link. For any you cannot identify that way, "
    "say so and ask for its URL or package name. Finish with one line: how many checked, "
    "how many are Safe to connect, how many need review or should not be connected, and "
    "which to look at first."
)


@server.list_prompts()
async def _list_prompts() -> list[types.Prompt]:
    return [
        types.Prompt(
            name="agentavow_get_started",
            title="AgentAvow: get started",
            description="What AgentAvow checks and how to read a verdict, with examples.",
        ),
        types.Prompt(
            name="agentavow_check_my_connections",
            title="AgentAvow: check my connections",
            description="Grade the other MCP servers and connectors enabled in this "
                        "conversation and say which to review first.",
        ),
    ]


@server.get_prompt()
async def _get_prompt(name: str, arguments: dict | None) -> types.GetPromptResult:
    if name == "agentavow_check_my_connections":
        return types.GetPromptResult(
            description="AgentAvow: check my connections",
            messages=[
                types.PromptMessage(
                    role="user",
                    content=types.TextContent(type="text", text=_CHECK_MY_CONNECTIONS),
                )
            ],
        )
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
) -> list[types.TextContent] | tuple[list[types.TextContent], dict] | types.CallToolResult:
    out = await _run_tool(name, arguments)
    if name not in _SCAN_TOOLS:
        return out
    if not isinstance(out, tuple):
        # A scan tool declares an outputSchema, so a reply without structuredContent
        # (bad input, not found, timeout) cannot go back as a success: the SDK and
        # spec-following clients reject it. Same guidance, sent as a tool error, which
        # also keeps a model from reading "not scanned" as an answer.
        return types.CallToolResult(content=out, isError=True)
    content, struct = out
    try:
        jsonschema.validate(instance=struct, schema=_SCAN_OUTPUT_SCHEMA)
    except jsonschema.ValidationError as e:
        # The schema drifted from _scan_struct. Never fail a good scan over it: send it
        # as-is (a CallToolResult skips the SDK's own check) and log loudly.
        logger.error("scan structuredContent does not match its outputSchema (%s): %s",
                     name, e.message)
        return types.CallToolResult(content=content, structuredContent=struct)
    return out


async def _run_tool(
    name: str, arguments: dict
) -> list[types.TextContent] | tuple[list[types.TextContent], dict]:
    await _bump_s("calls:total")
    await _bump(f"tool:{name}")
    await _record_caller()
    try:
        if name == "about_agentavow":
            return _text(_about_for(_SURFACE.get()))
        force = bool(arguments.get("force"))
        fp = None  # a forced re-scan runs in the background (see _schedule_rescan)
        if name == "scan_repo":
            repo = (arguments.get("repo") or "").strip().strip("/")
            owner = (arguments.get("owner") or "").strip()
            if not owner and "/" in repo:
                owner, repo = repo.split("/", 1)
            # Common confusion: a package ("npm chalk", "npm/chalk") sent to scan_repo.
            nudge = _package_nudge(owner, repo, arguments.get("repo") or "")
            if nudge:
                return _text(nudge)
            if not owner or not repo:
                return _text("Give the repo as 'owner/name' (e.g. 'vercel/next.js'), "
                             "or pass owner and repo separately.")
            data = await _get(f"/public/scan/{owner}/{repo}", params=fp)
            rescan = force and _schedule_rescan(f"/public/scan/{owner}/{repo}", None)
            await _bump_s("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            adoption = await _adoption("github", owner, repo)
            rp = f"/check/{owner}/{repo}"
            api = f"/api/v1/public/scan/{owner}/{repo}"
            card, struct = (
                _card_text(_scan_block(data, "connect", rp, f"{owner}/{repo}", adoption)),
                _scan_struct(data, f"{owner}/{repo}", "github", rp, api, adoption),
            )
            if rescan:
                card, struct = _with_rescan_note(card, struct)
            return card, struct
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
            # A pinned version rides in the name the way the ecosystems write it
            # (chalk@5.3.0, requests==2.32.5, serde@1.0.200) — no tool-schema change.
            pkg, version = _split_pinned_version(surface, pkg)
            # The explicit `version` argument; a pin in the name wins if both are given.
            version = version or (str(arguments.get("version") or "").strip() or None)
            params = dict(fp or {})
            if version:
                params["version"] = version
            data = await _get(f"/public/scan/package/{surface}/{pkg}", params=params)
            rescan = force and _schedule_rescan(f"/public/scan/package/{surface}/{pkg}", params)
            await _bump_s("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            adoption = await _adoption(surface, surface, pkg)
            vq = f"?version={quote(version, safe='')}" if version else ""
            rp = f"/check/pkg/{surface}/{pkg}{vq}"
            api = f"/api/v1/public/scan/package/{surface}/{pkg}{vq}"
            hint = {
                "npm": f"npm install {pkg}",
                "pypi": f"pip install {pkg}",
                "crates": f"cargo add {pkg}",
            }.get(surface, "")
            card, struct = (
                _card_text(_scan_block(data, "use", rp, f"{pkg} · {surface}", adoption, hint)),
                _scan_struct(data, pkg, surface, rp, api, adoption),
            )
            if rescan:
                card, struct = _with_rescan_note(card, struct)
            return card, struct
        if name == "scan_mcp_server":
            url = str(arguments.get("endpoint_url") or "").strip()
            if not url.lower().startswith(("http://", "https://")):
                # A connector / server NAME (claude.ai never shows a connector's URL):
                # resolve it against the catalog of scanned MCP servers.
                resolved, candidates = await _resolve_mcp_name(url)
                if not resolved:
                    return _text(_name_not_resolved(url, candidates))
                url = resolved
            params = {"endpoint": url}
            data = await _get("/public/scan/mcp", params=params)
            rescan = force and _schedule_rescan("/public/scan/mcp", params)
            await _bump_s("verdict:safe" if _safe_verdict(data) else "verdict:needs_review")
            # A bare MCP endpoint has no registry/stars adoption signal — omit it rather
            # than fabricate one.
            label = url.split("://", 1)[-1].split("/", 1)[0] or "MCP server"
            api = f"/api/v1/public/scan/mcp?endpoint={quote(url, safe='')}"
            # Target-specific report page (the web reads ?endpoint=) — not the bare /check.
            rp = f"/check/mcp?endpoint={quote(url, safe='')}"
            card, struct = (
                _card_text(_scan_block(data, "connect", rp, label, hosted=True)),
                _scan_struct(data, url, "mcp", rp, api, None),
            )
            if rescan:
                card, struct = _with_rescan_note(card, struct)
            return card, struct
        if name == "verify_trust":
            eid = arguments["entity_id"]
            min_trust = float(arguments.get("min_trust", 0.3))
            try:
                d = await _get(f"/entities/{eid}/trust")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    return _text(_no_entity_help(f"entity id '{eid}'"))
                raise
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
            try:
                d = await _get(f"/entities/{eid}/trust")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    return _text(_no_entity_help(f"target entity id '{eid}'"))
                raise
            score = float(d.get("score") or 0.0)
            # Shared per-type thresholds (src/interaction_safety.py) so the remote MCP,
            # the stdio MCP, and the A2A layer never disagree about the same interaction.
            from src.interaction_safety import interaction_recommendation
            rec = interaction_recommendation(round(score * 100), itype)
            report = f"{_WEB_BASE}/entities/{eid}/trust"
            return _text(
                f"{'Safe' if rec['safe'] else 'Not recommended'} for '{rec['interaction_type']}' "
                f"— trust {round(score * 100)}/100 vs the {rec['threshold']}/100 bar for this "
                f"interaction.\nFull trust report: {report}"
            )
        if name == "lookup_identity":
            q = arguments["query"]
            if q.startswith("did:"):
                try:
                    d = await _get("/did/resolve", params={"uri": q})
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        return _text(_no_entity_help(f"DID '{q}'"))
                    raise
                if not d:
                    return _text(_no_entity_help(f"DID '{q}'"))
                return _text(json.dumps(d, indent=2)[:2000])
            d = await _get("/search", params={"q": q, "limit": 5})
            # /search also matches bio text, so "requests" would surface an agent whose
            # bio mentions "feature requests". An identity lookup is by name or DID only.
            ents = [e for e in (d.get("entities") or []) if _identity_matches(q, e)]
            if not ents:
                return _text(_no_entity_help(f"'{q}'"))
            lines = [f"Identities matching '{q}':", ""]
            for e in ents[:5]:
                eid = e.get("id")
                nm = e.get("display_name") or e.get("did_web") or eid
                pct = round(float(e.get("trust_score") or 0.0) * 100)
                lines.append(f"- {nm} — trust {pct}/100 — {_WEB_BASE}/entities/{eid}/trust")
            return _text("\n".join(lines))
        if name == "get_trust_badge":
            eid = arguments["entity_id"]
            try:
                d = await _get(f"/entities/{eid}/trust")
            except httpx.HTTPStatusError as e:
                if e.response.status_code == 404:
                    return _text(_no_entity_help(f"entity id '{eid}'"))
                raise
            pct = round(float(d.get("score") or 0.0) * 100)
            # Public host, NOT _API_BASE (which is the internal container URL — that would
            # emit a localhost link into the user's README).
            badge = f"{_WEB_BASE}/api/v1/badges/trust/{eid}.svg"
            report = f"{_WEB_BASE}/entities/{eid}/trust"
            return _text(
                f"Trust badge for this agent (currently {pct}/100):\n\n"
                f"README markdown:\n[![AgentAvow Trust]({badge})]({report})\n\n"
                f"Badge image: {badge}\nFull report: {report}"
            )
        return _text(f"Unknown tool: {name}")
    except httpx.TimeoutException:
        await _bump_s("result:error")
        return _text("That scan is taking longer than usual (large target). AgentAvow caps and "
                     "caches scans — try again in a moment and it should come back quickly.")
    except httpx.HTTPStatusError as e:
        await _bump_s("result:error")
        code = e.response.status_code
        if code == 404:
            return _text("Not found — check the target coordinates and try again.")
        if code == 503:
            return _text("The scan is still running (large target). Try again shortly — "
                         "results cache once ready.")
        return _text(f"AgentAvow returned an error ({code}). "
                     "Try again shortly, or check the target.")
    except Exception:  # noqa: BLE001 — actionable message; never a stack trace or internal detail
        await _bump_s("result:error")
        return _text("Could not complete the check right now. Please try again shortly.")


# --------------------------------------------------------------------------- #
# Streamable HTTP transport — stateless JSON responses (nginx-friendly)
# --------------------------------------------------------------------------- #
session_manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)


async def mcp_asgi_app(scope, receive, send) -> None:
    # Capture the request's User-Agent → distribution surface for per-surface
    # metrics. Fail-open: any hiccup leaves the contextvar at its "other" default.
    try:
        ua = ""
        for k, v in scope.get("headers") or []:
            if k == b"user-agent":
                ua = v.decode("latin-1", "replace")
                break
        _SURFACE.set(_surface_from_ua(ua))
        _CLIENT_UA.set(ua)
        client = scope.get("client")
        _CLIENT_IP.set(str(client[0]) if client else "")
    except Exception:
        pass
    await session_manager.handle_request(scope, receive, send)
