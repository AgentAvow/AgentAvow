"""The tools an MCP server serves, as a list a page can show: name, declared safety
annotations, and (where we hold the full definition) its digest.

Three sources, each labelled so the page never overstates what we saw:

* ``live``    — ``tools/list`` from a live MCP endpoint (MCP-by-URL scans). The digest
                is the same per-tool digest signed into the score attestation.
* ``sandbox`` — ``tools/list`` observed when the behavioral tier started the published
                package's server. The digest is over the definition as the sandbox
                recorded it (descriptions capped at 2,000 characters, no ``title`` /
                ``outputSchema``), so it pins drift between sandbox runs but is not
                interchangeable with a live-endpoint digest.
* ``source``  — tool registrations found statically in the package's published code
                (``server.tool("x", …)``, ``registerTool``, ``@mcp.tool``). Names and
                literal annotations only; no digest, because this is not the served
                definition.

Everything here is unsigned display data. Pure functions; never raises.
"""
from __future__ import annotations

import re

from src.scanner.mcp_scan import tool_definition_digest

ANNOTATION_KEYS = ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint")
MAX_TOOLS = 200
_MAX_NAME = 128


def _annotations(raw) -> dict:
    """The four standard hints that are explicitly declared as booleans (others dropped:
    an undeclared hint is not the same as ``false``)."""
    if not isinstance(raw, dict):
        return {}
    return {k: raw[k] for k in ANNOTATION_KEYS if isinstance(raw.get(k), bool)}


def build_tool_list(tools: list | None, *, source: str = "live",
                    with_digest: bool = True) -> list[dict]:
    """``[{name, title?, annotations, digest?, source}]`` from MCP-shaped tool dicts
    (``name``, ``description``, ``inputSchema``, ``annotations`` …), sorted by name."""
    out: list[dict] = []
    seen: set[str] = set()
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        name = str(t.get("name") or "").strip()[:_MAX_NAME]
        if not name or name in seen:
            continue
        seen.add(name)
        row: dict = {"name": name, "annotations": _annotations(t.get("annotations")),
                     "source": source}
        ann = t.get("annotations") if isinstance(t.get("annotations"), dict) else {}
        title = t.get("title") or ann.get("title")
        if isinstance(title, str) and title.strip():
            row["title"] = title.strip()[:120]
        if with_digest:
            row["digest"] = tool_definition_digest(t)
        out.append(row)
        if len(out) >= MAX_TOOLS:
            break
    return sorted(out, key=lambda r: r["name"])


def tool_list_from_transcript(transcript) -> list[dict]:
    """Sandbox-observed tool list from a behavioral ``ExerciseTranscript``."""
    tools = []
    for t in getattr(transcript, "tools", None) or []:
        name = getattr(t, "name", None)
        if not name:
            continue
        tools.append({
            "name": name,
            "description": getattr(t, "description", "") or "",
            "inputSchema": getattr(t, "input_schema", None),
            "annotations": getattr(t, "annotations", None),
        })
    return build_tool_list(tools, source="sandbox")


def mcp_shaped(transcript) -> list[dict]:
    """The transcript's tools in ``tools/list`` shape, for ``analyze_mcp``."""
    return [{"name": t.name, "description": t.description or "",
             "inputSchema": t.input_schema, "annotations": t.annotations}
            for t in (getattr(transcript, "tools", None) or []) if getattr(t, "name", None)]


# ── static extraction from published package code ────────────────────────────

_SRC_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".py")
_SKIP_PARTS = ("/test/", "/tests/", "/__tests__/", "/spec/", "/examples/", "/example/",
               "node_modules/")
_MAX_FILES = 300
_MAX_BYTES = 400_000
_WINDOW = 1500

_NAME = r"([A-Za-z0-9_][A-Za-z0-9_.\-]{0,127})"
# JS/TS: server.tool("name", …) / server.registerTool("name", …) / addTool({ name: "x"
_JS_CALL = re.compile(r"\.(?:registerTool|tool)\(\s*[\"'`]" + _NAME + r"[\"'`]")
_JS_ADD = re.compile(r"\.addTool\(\s*\{\s*name\s*:\s*[\"'`]" + _NAME + r"[\"'`]")
# JS/TS ListTools handler arrays: { name: "x", description: … } (name then description,
# optionally a title between) — specific enough not to match arbitrary objects.
_JS_LIST = re.compile(
    r"\{\s*name\s*:\s*[\"'`]" + _NAME + r"[\"'`]\s*,\s*(?:title\s*:[^,\n]{0,200},\s*)?"
    r"description\s*:")
# Python: @mcp.tool() / @server.tool(name="x") / @app.tool  def x(…)
_PY_DECOR = re.compile(
    r"@\w+(?:\.\w+)*\.tool\b(?:\((?P<args>(?:[^()]|\([^()]{0,200}\)){0,400})\))?\s*\n"
    r"(?:\s*@[^\n]*\n)*"
    r"\s*(?:async\s+)?def\s+(?P<fn>[A-Za-z_]\w{0,127})")
_PY_DECOR_NAME = re.compile(r"name\s*=\s*[\"']" + _NAME + r"[\"']")
_PY_TOOL = re.compile(r"\bTool\(\s*name\s*=\s*[\"']" + _NAME + r"[\"']")
_HINT = re.compile(
    r"[\"']?(readOnlyHint|destructiveHint|idempotentHint|openWorldHint)[\"']?\s*[:=]\s*"
    r"(true|false|True|False)\b")


def _is_source(path: str) -> bool:
    p = "/" + path.replace("\\", "/").lower()
    if not p.endswith(_SRC_EXT) or p.endswith(".d.ts"):
        return False
    if any(s in p for s in _SKIP_PARTS):
        return False
    base = p.rsplit("/", 1)[-1]
    return not (base.startswith("test_") or ".test." in base or ".spec." in base)


def _hints(window: str) -> dict:
    out: dict = {}
    for k, v in _HINT.findall(window):
        out.setdefault(k, v.lower() == "true")
    return out


def static_tool_list(files: dict | None) -> list[dict]:
    """Tool registrations found in a package's published source. ``files`` maps path →
    ``ArtifactFile`` (or plain text). Fail-open → []."""
    try:
        hits: dict[str, dict] = {}
        n = 0
        for path, content in (files or {}).items():
            if n >= _MAX_FILES:
                break
            # ``ArtifactFile`` objects carry decoded text in ``.text``; plain str is
            # accepted too (tests, local scans).
            text = content if isinstance(content, str) else getattr(content, "text", None)
            if not isinstance(text, str) or not _is_source(str(path)):
                continue
            n += 1
            text = text[:_MAX_BYTES]
            spans: list[tuple[int, str]] = []
            for rx in (_JS_CALL, _JS_ADD, _JS_LIST, _PY_TOOL):
                spans += [(m.start(), m.group(1)) for m in rx.finditer(text)]
            for m in _PY_DECOR.finditer(text):
                named = _PY_DECOR_NAME.search(m.group("args") or "")
                spans.append((m.start(), named.group(1) if named else m.group("fn")))
            spans.sort()
            for i, (pos, name) in enumerate(spans):
                end = spans[i + 1][0] if i + 1 < len(spans) else len(text)
                window = text[pos:min(end, pos + _WINDOW)]
                row = hits.setdefault(name, {"name": name, "annotations": {},
                                             "source": "source"})
                for k, v in _hints(window).items():
                    row["annotations"].setdefault(k, v)
                if len(hits) >= MAX_TOOLS:
                    break
        return sorted(hits.values(), key=lambda r: r["name"])
    except Exception:  # noqa: BLE001 — display data must never break a scan
        return []
