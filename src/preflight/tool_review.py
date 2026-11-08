"""Per-tool facts the store review rules ask about, read from a live ``tools/list``.

Pure and fail-open. ``scan_mcp`` stores the result in ``surface_detail["review_facts"]``
(unsigned display data, never a score input), and ``gates.py`` turns it into gates:

* tool name length (Claude: 64 characters or fewer)
* a ``title`` on every tool (Claude)
* a non-empty description (OpenAI)
* explicit ``readOnlyHint`` / ``destructiveHint`` / ``openWorldHint`` booleans
  (Claude needs the applicable read/destructive hint; OpenAI needs all three)
* one tool taking both safe and unsafe HTTP methods (Claude: read and write tools
  must be separate)
* a custom query tool (caller-built endpoint, query string or body) whose description
  names no API and links no docs (Claude: reference API docs in custom query tools)
* duplicate tool names (OpenAI: names unique within the server)
* tools that link a UI resource (OpenAI: a UI needs a declared CSP)
"""
from __future__ import annotations

import re

MAX_TOOLS = 200
HINTS = ("readOnlyHint", "destructiveHint", "openWorldHint")
SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

_METHOD_PARAM = re.compile(r"^(?:http_?)?(?:method|verb)$", re.I)
# Parameters through which the caller builds the request itself. A plain ``query`` or
# ``url`` is left out on purpose: a search tool's query and a fetch tool's URL are not
# custom API queries. ``path`` counts only next to a method parameter (an API path,
# not a file path).
_QUERY_PARAMS = re.compile(
    r"^(?:endpoint|endpoint_path|api_path|route|request_body|query_string|raw_query|"
    r"graphql|graphql_query|sql|sql_query)$", re.I)
_URL = re.compile(r"https?://", re.I)
# Inputs the stores say a tool must not ask for: accumulated conversation context
# (OpenAI, Claude) and precise location (OpenAI). Matched on the parameter name.
_CONTEXT_PARAMS = re.compile(
    r"^(?:conversation|conversation_history|chat_history|chat_log|transcript|"
    r"full_transcript|prior_turns|previous_messages|message_history|full_context|"
    r"conversation_context)$", re.I)
_LOCATION_PARAMS = re.compile(
    r"^(?:lat|latitude|lng|lon|long|longitude|gps|coordinates|geo_coordinates|"
    r"street_address|home_address)$", re.I)
# "the Slack Web API", "GitHub REST API", "Stripe API": a capitalised name before "API".
_NAMED_API = re.compile(r"\b[A-Z][\w.-]*(?:\s+[A-Z][\w.-]*)*\s+(?:Web\s+|REST\s+|GraphQL\s+)?API\b")


def _props(schema) -> dict:
    if not isinstance(schema, dict):
        return {}
    p = schema.get("properties")
    return p if isinstance(p, dict) else {}


def _methods(prop) -> tuple[set[str], bool]:
    """(declared HTTP methods, freeform) for a method parameter's schema."""
    if not isinstance(prop, dict):
        return set(), True
    enum = prop.get("enum")
    if isinstance(enum, list) and enum:
        return {str(v).upper() for v in enum}, False
    const = prop.get("const")
    if isinstance(const, str):
        return {const.upper()}, False
    return set(), True


def _tool_facts(t: dict) -> dict:
    name = str(t.get("name") or "")
    ann_raw = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
    title = t.get("title") or ann_raw.get("title")
    desc = t.get("description")
    desc = desc if isinstance(desc, str) else ""
    props = _props(t.get("inputSchema"))

    methods: set[str] = set()
    freeform_method = False
    has_method = False
    for pname, pschema in props.items():
        if _METHOD_PARAM.match(str(pname)):
            has_method = True
            m, free = _methods(pschema)
            methods |= m
            freeform_method = freeform_method or free
    mixed = bool(methods & SAFE_METHODS) and bool(methods & UNSAFE_METHODS)

    custom_query = any(_QUERY_PARAMS.match(str(p)) for p in props) or (
        has_method and any(str(p).lower() in ("path", "url") for p in props))
    api_ref = bool(_URL.search(desc) or _NAMED_API.search(desc))

    meta = t.get("_meta") if isinstance(t.get("_meta"), dict) else {}
    ui = meta.get("ui") if isinstance(meta.get("ui"), dict) else {}
    links_ui = bool(ui.get("resourceUri") or meta.get("openai/outputTemplate"))

    return {
        "name": name[:128],
        "name_length": len(name),
        "has_title": isinstance(title, str) and bool(title.strip()),
        "has_description": bool(desc.strip()),
        "hints": {k: ann_raw[k] for k in HINTS if isinstance(ann_raw.get(k), bool)},
        "mixed_methods": mixed,
        "freeform_method": has_method and freeform_method and not mixed,
        "custom_query": custom_query,
        "api_reference": api_ref,
        "links_ui": links_ui,
        "context_params": sorted(str(p) for p in props if _CONTEXT_PARAMS.match(str(p)))[:5],
        "location_params": sorted(str(p) for p in props
                                  if _LOCATION_PARAMS.match(str(p)))[:5],
    }


def tool_review_facts(tools) -> dict:
    """``{tool_count, duplicate_names, tools: [...]}`` from MCP ``tools/list`` dicts.
    Never raises; an unreadable list gives ``{"tool_count": 0, ...}``."""
    try:
        rows: list[dict] = []
        seen: set[str] = set()
        dupes: set[str] = set()
        for t in tools or []:
            if not isinstance(t, dict):
                continue
            n = str(t.get("name") or "")
            if n in seen:
                dupes.add(n[:128])
                continue
            seen.add(n)
            if len(rows) < MAX_TOOLS:
                rows.append(_tool_facts(t))
        return {"tool_count": len(seen), "duplicate_names": sorted(dupes), "tools": rows}
    except Exception:  # noqa: BLE001 — display data must never break a scan
        return {"tool_count": 0, "duplicate_names": [], "tools": []}
