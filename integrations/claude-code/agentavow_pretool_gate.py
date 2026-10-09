#!/usr/bin/env python3
"""AgentAvow PreToolUse gate — checks each MCP tool call against the grade on file.

Runs before Claude Code calls an MCP tool (tool names `mcp__<server>__<tool>`). It
reads the verdict the SessionStart pre-check (agentavow_precheck.py) stored for that
server in ~/.cache/agentavow/scanned.json and decides:
  • deny  — the server's answer is "Do not connect" (a critical finding, a planted
            credential leaving the sandbox, a known-malicious package), or its grade is
            in the "blocked" tier (score 0-10). The reason leads with the answer and
            names the score and the report. The threshold is adjustable (below).
  • ask   — a remote (HTTP) server now serves a definition for this tool that differs
            from the one AgentAvow graded (or a tool the grade never saw). The gate
            re-fetches `tools/list` from the server itself, at most once per server
            per recheck window, and recomputes the signed per-tool digest with the
            same derivation the attestation uses (agentavow.mcp-tool-definition.v1:
            RFC 8785 canonical JSON over name, title, description, inputSchema,
            outputSchema, annotations; SHA-256). No call to AgentAvow is made.
  • allow — everything else: an unknown server, no grade on file, a stdio server
            (verdict-only; it serves no definition to re-fetch), any network error
            or timeout, any definition the gate cannot hash.

Settings (environment, all OPTIONAL, read only, never sent anywhere):
  AGENTAVOW_GATE=off                   turn the gate off entirely (default: on)
  AGENTAVOW_GATE_DENY_BELOW            deny when the server's score is below this:
                                       a number 0-100, or a tier name (restricted,
                                       minimal, standard, trusted, verified) meaning
                                       that tier's floor; "off" never denies (not
                                       even on "Do not connect").
                                       Default: deny on "Do not connect" and on the
                                       "blocked" tier.
  AGENTAVOW_GATE_RECHECK_SECONDS       how often a remote server's tools/list is
                                       re-fetched for drift (default 900).

What leaves your machine: for a remote server with a grade on file, one short
`initialize` + `tools/list` exchange with THAT server, over the URL in your config
(user:password@ and #fragment removed). If the config has an Authorization header
for that server, it is sent to that server only, as Claude Code itself would; it is
never written to the cache or printed. Nothing is sent to AgentAvow.

Design guarantees (deliberate):
  • FAIL-OPEN — any error, timeout, or unexpected shape means allow, silently.
  • NEVER BLOCKS ON DRIFT — drift asks; only "Do not connect" or a blocked-tier grade
    denies. "Review before you connect" never prompts here.
  • ONE SHORT BUDGET — the whole run stays under the hook's 8-second timeout.

Install / test: https://agentavow.com/docs/auto-scan-claude-code
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import pathlib
import sys
import time
import urllib.parse
import urllib.request

__version__ = "0.1.26"

CACHE = pathlib.Path.home() / ".cache" / "agentavow" / "scanned.json"
META_KEY = "_agentavow"  # cache entry holding hook state; never a server name

# The per-tool digest, exactly as the attestation signs it
# (docs/standards/tool-manifest-digest-vectors-v1).
PROFILE = "agentavow.mcp-tool-definition.v1"
DIGEST_FIELDS = ("name", "title", "description", "inputSchema", "outputSchema", "annotations")
_MAX_SAFE_INT = 2**53 - 1
_MAX_KEY_NAME = 128
_MAX_TOOL_DIGESTS = 500  # beyond this the signed map is folded; the gate cannot compare

DEFAULT_RECHECK_SECONDS = 900
REQUEST_TIMEOUT = 2.5  # per request to the server
BUDGET = 6.0  # for the whole tools/list fetch; the hook times out at 8

# Score floor of each tier (src/api/public_scan_router.py TRUST_TIERS).
TIER_FLOORS = {
    "blocked": 0, "restricted": 11, "minimal": 31, "standard": 51, "trusted": 81, "verified": 96,
}


# The three headline phrases (src/trust_tiers.py DECISIONS; pinned by tests).
DECISION_PHRASES = {
    "safe": "Safe to connect",
    "review": "Review before you connect",
    "do_not_connect": "Do not connect",
}


class UnhashableError(Exception):
    """A definition RFC 8785 cannot represent the way this gate implements it (a
    non-integer number, an integer beyond 2^53, a value that is not JSON)."""


# ── RFC 8785 (JCS) for JSON that came from json.loads ────────────────────────


def jcs(value: object) -> str:
    """Canonical JSON per RFC 8785: keys sorted by UTF-16 code units, no whitespace,
    strings escaped as JSON.stringify does, non-ASCII kept literal. Integers print
    as digits; an integral float prints as its integer (as ES6 does). Any other
    number raises UnhashableError rather than risk a digest that differs from the
    issuer's."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, int):
        if abs(value) > _MAX_SAFE_INT:
            raise UnhashableError("integer beyond 2^53")
        return str(value)
    if isinstance(value, float):
        if value.is_integer() and abs(value) <= _MAX_SAFE_INT:
            return str(int(value))  # 1.0 -> "1", -0.0 -> "0"
        raise UnhashableError("non-integer number")
    if isinstance(value, str):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, list):
        return "[" + ",".join(jcs(v) for v in value) + "]"
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise UnhashableError("non-string key")
        keys = sorted(value, key=lambda k: k.encode("utf-16-be", "surrogatepass"))
        return "{" + ",".join(
            json.dumps(k, ensure_ascii=False) + ":" + jcs(value[k]) for k in keys) + "}"
    raise UnhashableError(type(value).__name__)


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def tool_key(name: str) -> str:
    """`tool:<name>`: everything outside printable ASCII, plus % and =, is
    percent-encoded as UTF-8 bytes; an overlong key is cut and suffixed."""
    out = []
    for ch in name:
        if "\x21" <= ch <= "\x7e" and ch not in "%=":
            out.append(ch)
        else:
            out.extend(f"%{b:02X}" for b in ch.encode("utf-8", "surrogatepass"))
    enc = "".join(out)
    if len(enc) > _MAX_KEY_NAME:
        enc = enc[:96] + "~" + hashlib.sha256(
            name.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return "tool:" + enc


def tool_digest(tool: dict) -> str:
    """`sha256:<hex>` over JCS({"profile": PROFILE, "tool": <restricted definition>}).
    A missing or null field is omitted; _meta and unknown fields are never hashed."""
    body = {f: tool[f] for f in DIGEST_FIELDS if tool.get(f) is not None}
    return _sha256(jcs({"profile": PROFILE, "tool": body}))


def compute_digests(tools: list) -> tuple[dict[str, str], list[str]]:
    """({key: digest}, [keys that could not be hashed]) for a served tools/list.
    Tools sharing a name fold into one entry over their sorted digests, as the
    issuer does. Entries that are not objects are skipped."""
    by_key: dict[str, list[str]] = {}
    unhashable: list[str] = []
    for t in tools:
        if not isinstance(t, dict):
            continue
        key = tool_key(str(t.get("name", "") or "unnamed"))
        if key in unhashable:
            continue
        try:
            by_key.setdefault(key, []).append(tool_digest(t))
        except UnhashableError:
            by_key.pop(key, None)
            unhashable.append(key)
    digests = {
        key: ds[0] if len(ds) == 1 else _sha256(PROFILE + ".duplicates\n" + "\n".join(sorted(ds)))
        for key, ds in by_key.items()
    }
    return digests, unhashable


# ── tool name and server lookup ──────────────────────────────────────────────


def parse_tool_name(name: object) -> tuple[str, str] | None:
    """`mcp__<server>__<tool>` -> (server, tool). The server segment is the first
    one; a tool name may itself contain `__`, so the rest is the tool."""
    if not isinstance(name, str):
        return None
    parts = name.split("__")
    if len(parts) < 3 or parts[0] != "mcp" or not parts[1] or not parts[-1]:
        return None
    return parts[1], "__".join(parts[2:])


def server_candidates(server: str) -> list[str]:
    """Cache keys to try for a server segment. A plugin-bundled server arrives as
    `plugin_<plugin>_<server>`; the plugin name's own underscores make the split
    ambiguous, so every cut after `plugin_` is tried, longest first."""
    cands = [server]
    if server.startswith("plugin_"):
        rest = server[len("plugin_"):]
        cands.extend(rest[i + 1:] for i, ch in enumerate(rest) if ch == "_")
    return cands


def find_record(cache: dict, server: str) -> tuple[str, dict] | None:
    for cand in server_candidates(server):
        if cand == META_KEY:
            continue
        entry = cache.get(cand)
        if isinstance(entry, dict) and "approved_at" in entry and isinstance(entry.get("id"), str):
            return cand, entry
    return None


def _server_config(name: str) -> dict | None:
    """The `mcpServers[name]` entry from the same files the pre-check reads. Only
    the URL and an Authorization header are ever used from it."""
    candidates = [
        pathlib.Path.home() / ".claude.json",
        pathlib.Path.cwd() / ".mcp.json",
        pathlib.Path.cwd() / ".claude" / "settings.json",
    ]
    for path in candidates:
        try:
            data = json.loads(path.read_text())
        except Exception:
            continue
        stack = [data]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                servers = node.get("mcpServers")
                if isinstance(servers, dict) and isinstance(servers.get(name), dict):
                    return servers[name]
                stack.extend(v for v in node.values() if isinstance(v, (dict, list)))
            elif isinstance(node, list):
                stack.extend(v for v in node if isinstance(v, (dict, list)))
    return None


def _sanitize_url(url: str) -> str:
    """scheme + host + path only: the id the pre-check keyed the record by."""
    try:
        p = urllib.parse.urlsplit(url)
        host = p.hostname or ""
        if p.port:
            host = f"{host}:{p.port}"
        return urllib.parse.urlunsplit((p.scheme, host, p.path, "", ""))
    except Exception:
        return url.split("?", 1)[0].split("#", 1)[0]


ALLOWED_SCHEMES = ("https",)


def _call_url(url: str) -> str | None:
    """The URL the gate calls the server on: the configured one minus any
    user:password@ and #fragment. The query string stays, since it belongs to the
    server being called. https only."""
    try:
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ALLOWED_SCHEMES or not p.hostname:
            return None
        host = p.hostname
        if p.port:
            host = f"{host}:{p.port}"
        return urllib.parse.urlunsplit((p.scheme, host, p.path, p.query, ""))
    except Exception:
        return None


def _config_url(cfg: dict) -> str | None:
    url = cfg.get("url") or cfg.get("endpoint")
    return url if isinstance(url, str) and url.startswith("http") else None


_PACKAGE_RUNNERS = {"npx", "bunx", "pnpm", "uvx", "pipx"}


def _gradable(cfg: dict | None) -> bool:
    """Whether the pre-check could grade this server at all: a remote URL that is
    not local or private, or a stdio server launched from a published package. A
    localhost server or a hand-written script is never graded, so the gate does not
    tell the user to expect a grade for one."""
    if not isinstance(cfg, dict):
        return False
    url = _config_url(cfg)
    if url:
        try:
            host = (urllib.parse.urlsplit(url).hostname or "").lower().rstrip(".")
        except Exception:
            return False
        if not host or "." not in host:
            return False
        if host.endswith((".localhost", ".local", ".internal", ".lan", ".home.arpa")):
            return False
        try:
            return ipaddress.ip_address(host).is_global
        except ValueError:
            return True
    cmd = cfg.get("command")
    return isinstance(cmd, str) and os.path.basename(cmd) in _PACKAGE_RUNNERS


def _authorization(cfg: dict) -> str | None:
    """The configured Authorization header for this server, if any. A value that
    still carries a `${...}` placeholder is not expanded (that would mean reading
    arbitrary environment variables) and is not sent."""
    headers = cfg.get("headers")
    if not isinstance(headers, dict):
        return None
    for k, v in headers.items():
        if isinstance(k, str) and k.lower() == "authorization" and isinstance(v, str):
            return None if "${" in v or not v.strip() else v
    return None


# ── settings ─────────────────────────────────────────────────────────────────


def _setting(name: str) -> str:
    """One of the gate's own knobs. The value is read and compared, never sent."""
    return (os.environ.get(name) or "").strip().lower()


def denies(record: dict, setting: str) -> bool:
    """Whether to deny: the answer on file is "Do not connect", or the grade is low
    enough (default: the blocked tier). ``off`` never denies."""
    if setting in ("off", "none", "never"):
        return False
    if record.get("decision") == "do_not_connect":
        return True
    try:
        score = int(record.get("score"))
    except (TypeError, ValueError):
        return False
    if setting in ("off", "none", "never"):
        return False
    if setting.isdigit():
        return score < min(int(setting), 101)
    if setting in TIER_FLOORS and setting != "blocked":
        return score < TIER_FLOORS[setting]
    tier = str(record.get("tier") or "")
    return tier == "blocked" or (not tier and score < TIER_FLOORS["restricted"])


def _recheck_seconds() -> float:
    raw = _setting("AGENTAVOW_GATE_RECHECK_SECONDS")
    try:
        return max(0.0, float(raw)) if raw else float(DEFAULT_RECHECK_SECONDS)
    except ValueError:
        return float(DEFAULT_RECHECK_SECONDS)


# ── the server's own tools/list (Streamable HTTP) ────────────────────────────


def _install_source() -> str:
    plugin_root = pathlib.Path(__file__).resolve().parent.parent
    return "plugin" if (plugin_root / ".claude-plugin").is_dir() else "manual"


def _user_agent() -> str:
    return f"agentavow-gate/{__version__} ({_install_source()})"


def _read_rpc(resp, want_id: int) -> dict | None:
    """The JSON-RPC response to request `want_id`, from a JSON body or an SSE stream.
    An SSE stream is read line by line and left as soon as the reply arrives, so a
    server that keeps the stream open cannot hold the gate past its timeout."""
    ctype = (resp.headers.get("Content-Type") or "").lower()
    if "text/event-stream" not in ctype:
        try:
            doc = json.loads(resp.read(4_000_000).decode("utf-8", "replace"))
        except Exception:
            return None
        return doc if isinstance(doc, dict) else None
    for raw in resp:
        line = raw.decode("utf-8", "replace").strip()
        if not line.startswith("data:"):
            continue
        payload = line[5:].strip()
        if not payload.startswith("{"):
            continue
        try:
            doc = json.loads(payload)
        except ValueError:
            continue
        if isinstance(doc, dict) and ("result" in doc or "error" in doc) and (
                doc.get("id") in (want_id, None)):
            return doc
    return None


def fetch_tools(url: str, auth: str | None, deadline: float) -> list | None:
    """initialize -> notifications/initialized -> tools/list against the server.
    None on any failure. Never raises."""
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": _user_agent(),
    }
    if auth:
        headers["Authorization"] = auth

    def post(body: dict, want_id: int | None) -> tuple[dict | None, dict]:
        remaining = deadline - time.monotonic()
        if remaining <= 0.2:
            raise TimeoutError
        req = urllib.request.Request(
            url, data=json.dumps(body).encode(), headers=headers, method="POST")
        with urllib.request.urlopen(  # noqa: S310 (https only, user-configured server)
                req, timeout=min(REQUEST_TIMEOUT, remaining)) as resp:
            if want_id is None:
                return None, dict(resp.headers)
            return _read_rpc(resp, want_id), dict(resp.headers)

    try:
        init, resp_headers = post({
            "jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "agentavow-gate", "version": __version__}},
        }, 1)
        if init is None or "result" not in init:
            return None
        session = next((v for k, v in resp_headers.items()
                        if k.lower() == "mcp-session-id"), None)
        if session:
            headers["Mcp-Session-Id"] = session
        headers["MCP-Protocol-Version"] = "2025-06-18"
        try:
            post({"jsonrpc": "2.0", "method": "notifications/initialized"}, None)
        except Exception:
            pass  # a notification; some servers answer 202, some 4xx. Either is fine.
        listing, _ = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}, 2)
        tools = ((listing or {}).get("result") or {}).get("tools")
        return tools if isinstance(tools, list) else None
    except Exception:
        return None


# ── cache ────────────────────────────────────────────────────────────────────


def _load_cache() -> dict:
    try:
        data = json.loads(CACHE.read_text())
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def _save_cache(cache: dict) -> bool:
    try:
        CACHE.parent.mkdir(parents=True, exist_ok=True)
        tmp = CACHE.with_name(f"{CACHE.name}.{os.getpid()}.tmp")
        tmp.write_text(json.dumps(cache))
        os.replace(tmp, CACHE)
        return True
    except Exception:
        return False


# ── decisions ────────────────────────────────────────────────────────────────


def _emit(decision: str, reason: str) -> None:
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
        }
    }))


def _note_once_per_session(cache: dict, session_id: object, message: str) -> None:
    """A user-visible line, at most once per session, recorded in the cache so a
    parallel call does not repeat it. Nothing enters Claude's context."""
    if not isinstance(session_id, str) or not session_id:
        return
    meta = cache.get(META_KEY)
    if not isinstance(meta, dict):
        meta = {}
    if meta.get("gate_noted_session") == session_id:
        return
    meta["gate_noted_session"] = session_id
    cache[META_KEY] = meta
    if _save_cache(cache):
        print(json.dumps({"systemMessage": message}))


def drift_decision(name: str, record: dict, cfg: dict | None, tool: str,
                   cache: dict) -> tuple[str, str] | None:
    """("ask", reason) when the server now serves this tool with a definition the
    grade did not sign; None to allow. Refreshes `last_seen` on the record (never
    the approved digests) at most once per recheck window."""
    approved = record.get("tool_digests")
    if not isinstance(approved, dict) or not approved or len(approved) > _MAX_TOOL_DIGESTS:
        return None
    now = time.time()
    seen = record.get("last_seen") if isinstance(record.get("last_seen"), dict) else {}
    try:
        last_at = float(seen.get("at") or 0)
    except (TypeError, ValueError):
        last_at = 0.0
    url = _call_url(_config_url(cfg) or "") if cfg else None
    if url and now - last_at >= _recheck_seconds():
        tools = fetch_tools(url, _authorization(cfg), time.monotonic() + BUDGET)
        fresh = {"at": now, "ok": tools is not None}
        if tools is not None:
            fresh["tool_digests"], fresh["unhashable"] = compute_digests(tools)
        else:  # keep the last good observation; back off for the window either way
            fresh["tool_digests"] = seen.get("tool_digests") or {}
            fresh["unhashable"] = seen.get("unhashable") or []
        record["last_seen"] = seen = fresh
        _save_cache(cache)

    key = tool_key(tool)
    if key in (seen.get("unhashable") or []):
        noted = record.setdefault("unhashable_noted", [])
        if key not in noted:  # say so once per tool, user-visible only
            noted.append(key)
            if _save_cache(cache):
                print(json.dumps({"systemMessage": (
                    f"AgentAvow gate: the definition of '{tool}' on MCP '{name}' uses a "
                    "number form the gate cannot canonicalize, so it is not checked for "
                    "drift.")}))
        return None
    live_map = seen.get("tool_digests")
    if not isinstance(live_map, dict) or not live_map:
        return None
    live = live_map.get(key)
    if live is None:
        return None  # the server no longer serves it; nothing to compare
    score = record.get("score")
    report = record.get("report_url") or "https://agentavow.com/check"
    expected = approved.get(key)
    if expected is None:
        return "ask", (f"AgentAvow: '{tool}' on MCP '{name}' was not among the tools AgentAvow "
                       f"graded ({score}/100); the server added it since. Review before "
                       f"running. Report: {report}")
    if expected != live:
        return "ask", (f"AgentAvow: the definition of '{tool}' on MCP '{name}' changed since "
                       f"AgentAvow graded this server ({score}/100). Review before running; "
                       f"it is re-graded at your next session start. Report: {report}")
    return None


def decide(payload: dict, cache: dict) -> tuple[str, str] | None:
    """The gate's decision for one PreToolUse payload, or None to stay silent."""
    parsed = parse_tool_name(payload.get("tool_name"))
    if not parsed:
        return None
    server, tool = parsed
    found = find_record(cache, server)
    if not found:
        if _gradable(_server_config(server)):
            _note_once_per_session(cache, payload.get("session_id"), (
                f"AgentAvow gate: MCP '{server}' has no grade on file, so its tools run "
                "unchecked. It is graded at your next session start."))
        return None
    name, record = found
    cfg = _server_config(name)
    if cfg is not None:
        url = _config_url(cfg)
        if url is not None and _sanitize_url(url) != record.get("id"):
            return None  # the config points somewhere else now; the grade is for the old URL
    if denies(record, _setting("AGENTAVOW_GATE_DENY_BELOW")):
        report = record.get("report_url") or "https://agentavow.com/check"
        tier = record.get("tier") or "blocked"
        why = f" — {record['decision_reason']}" if record.get("decision_reason") else ""
        # Never " · Certified" here: the mark only ever sits beside Safe to connect.
        return "deny", (f"AgentAvow: {DECISION_PHRASES['do_not_connect']}{why}. "
                        f"MCP '{name}' is graded {record.get('score')}/100 (tier {tier}); "
                        f"'{tool}' was not run. Report: {report}")
    if record.get("kind") == "mcp":
        return drift_decision(name, record, cfg, tool, cache)
    return None


def main() -> None:
    try:
        payload = json.load(sys.stdin)
    except Exception:
        return
    if not isinstance(payload, dict) or _setting("AGENTAVOW_GATE") in ("off", "0", "false", "no"):
        return
    try:
        decision = decide(payload, _load_cache())
    except Exception:
        return  # fail-open
    if decision:
        _emit(*decision)


if __name__ == "__main__":
    main()
