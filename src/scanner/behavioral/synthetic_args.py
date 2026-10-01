"""Deterministic synthetic arguments for exercising an MCP tool from its ``inputSchema``.

The in-sandbox exerciser (``scripts/sandbox/mcp_exercise.py``) calls every tool a server
lists; the arguments it sends must be (a) valid enough that the tool runs its real code
path and (b) fully deterministic, so a transcript — and the verdict graded from it — is
reproducible. ``scripts/sandbox/mcp_exercise.js`` ports these rules line for line; the
golden files under ``tests/fixtures/behavioral/schemas`` pin both.

Rules, in order, at every schema node:
  ``const`` → ``examples[0]`` → ``default`` → ``enum[0]``; then by type —
  string: by ``format``, then by property-name hint (path/file/dir, url, email, host, id),
  else ``"agentavow"``; number: ``minimum`` (bumped past an exclusive bound) else 1, clamped
  to ``maximum``; boolean: false; array: ``max(1, minItems)`` copies of one item; object:
  every ``required`` property plus up to 6 optional ones; ``anyOf``/``oneOf``/``allOf``:
  first branch; ``$ref`` into ``#/$defs`` or ``#/definitions``; recursion capped at depth
  6; anything unknown → ``"agentavow"``.

STDLIB ONLY and importable standalone: the exerciser copies this file next to itself inside
the container (``node:20-alpine`` / ``python:3.12-alpine`` have no third-party packages).
"""
from __future__ import annotations

import json
import re

FALLBACK = "agentavow"
SAMPLE_PATH = "/work/agentavow-sample.txt"
SAMPLE_URL = "https://example.com/agentavow"
MAX_DEPTH = 6
MAX_OPTIONAL = 6
MAX_ARRAY_ITEMS = 4

_FORMAT_VALUES = {
    "uri": SAMPLE_URL, "url": SAMPLE_URL, "uri-reference": SAMPLE_URL, "iri": SAMPLE_URL,
    "email": "agentavow@example.com", "idn-email": "agentavow@example.com",
    "date": "2024-01-01", "date-time": "2024-01-01T00:00:00Z", "time": "00:00:00Z",
    "uuid": "00000000-0000-4000-8000-000000000000",
    "hostname": "example.com", "idn-hostname": "example.com",
    "ipv4": "192.0.2.1", "ipv6": "2001:db8::1",
}
_HINT_PATH = {"path", "file", "dir", "directory", "filename", "filepath", "folder"}
_HINT_URL = {"url", "uri", "link", "href", "endpoint", "website"}
_HINT_EMAIL = {"email", "mail"}
_HINT_HOST = {"host", "hostname", "domain"}
_HINT_ID = {"id", "uuid", "guid", "identifier"}
_TYPE_ORDER = ("object", "array", "string", "integer", "number", "boolean", "null")


def _tokens(name: str) -> list[str]:
    """``issueId`` / ``file_path`` / ``repo-name`` → lowercase word tokens."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name or "")
    return [t for t in re.split(r"[^a-z0-9]+", s.lower()) if t]


def _string_for(schema: dict, name: str) -> str:
    fmt = schema.get("format")
    value = _FORMAT_VALUES.get(fmt) if isinstance(fmt, str) else None
    if value is None:
        toks = _tokens(name)
        if any(t in _HINT_PATH or t.endswith("path") or t.endswith("file") for t in toks):
            value = SAMPLE_PATH
        elif any(t in _HINT_URL or t.endswith("url") or t.endswith("uri") for t in toks):
            value = SAMPLE_URL
        elif any(t in _HINT_EMAIL for t in toks):
            value = "agentavow@example.com"
        elif any(t in _HINT_HOST for t in toks):
            value = "example.com"
        elif any(t in _HINT_ID for t in toks):
            value = "1"
        else:
            value = FALLBACK
    min_len = schema.get("minLength")
    if isinstance(min_len, int) and not isinstance(min_len, bool) and len(value) < min_len:
        value = value + "x" * (min(min_len, 256) - len(value))
    max_len = schema.get("maxLength")
    if isinstance(max_len, int) and not isinstance(max_len, bool) and 0 < max_len < len(value):
        value = value[:max_len]
    return value


def _num(v: object) -> int | float | None:
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return None
    return int(v) if isinstance(v, float) and v.is_integer() else v


def _number_for(schema: dict, integer: bool) -> int | float:
    minimum = _num(schema.get("minimum"))
    excl_min = schema.get("exclusiveMinimum")
    if _num(excl_min) is not None:
        value = _num(excl_min) + 1
    elif minimum is not None:
        value = minimum + 1 if excl_min is True else minimum
    else:
        value = 1
    maximum = _num(schema.get("maximum"))
    excl_max = schema.get("exclusiveMaximum")
    if _num(excl_max) is not None:
        maximum = _num(excl_max) - 1
    elif maximum is not None and excl_max is True:
        maximum = maximum - 1
    if maximum is not None and value > maximum:
        value = maximum
    if integer:
        value = int(value)
    return _num(value) if _num(value) is not None else 1


def _resolve_ref(ref: str, root: dict) -> dict | None:
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return None
    node: object = root
    for raw in ref[2:].split("/"):
        key = raw.replace("~1", "/").replace("~0", "~")
        if isinstance(node, dict) and key in node:
            node = node[key]
        elif isinstance(node, list) and key.isdigit() and int(key) < len(node):
            node = node[int(key)]
        else:
            return None
    return node if isinstance(node, dict) else None


def _pick_type(schema: dict) -> str | None:
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if isinstance(x, str) and x != "null"), None)
    if isinstance(t, str) and t in _TYPE_ORDER:
        return t
    if isinstance(schema.get("properties"), dict):
        return "object"
    if "items" in schema or "prefixItems" in schema:
        return "array"
    if any(k in schema for k in ("format", "minLength", "maxLength", "pattern")):
        return "string"
    if any(k in schema for k in ("minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum")):
        return "number"
    return None


def _value(schema: object, root: dict, depth: int, name: str) -> object:
    if depth > MAX_DEPTH:
        return FALLBACK
    if not isinstance(schema, dict):
        return FALLBACK
    if isinstance(schema.get("$ref"), str):
        target = _resolve_ref(schema["$ref"], root)
        return _value(target, root, depth + 1, name) if target else FALLBACK
    if "const" in schema:
        return schema["const"]
    examples = schema.get("examples")
    if isinstance(examples, list) and examples:
        return examples[0]
    if "default" in schema:
        return schema["default"]
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        return enum[0]
    for key in ("anyOf", "oneOf", "allOf"):
        branches = schema.get(key)
        if isinstance(branches, list) and branches:
            return _value(branches[0], root, depth + 1, name)
    t = _pick_type(schema)
    if t == "string":
        return _string_for(schema, name)
    if t == "integer":
        return _number_for(schema, True)
    if t == "number":
        return _number_for(schema, False)
    if t == "boolean":
        return False
    if t == "null":
        return None
    if t == "array":
        items = schema.get("items")
        if items is None:
            prefix = schema.get("prefixItems")
            items = prefix[0] if isinstance(prefix, list) and prefix else None
        if isinstance(items, list):
            items = items[0] if items else None
        min_items = schema.get("minItems")
        count = 1
        if isinstance(min_items, int) and not isinstance(min_items, bool):
            count = max(1, min(min_items, MAX_ARRAY_ITEMS))
        one = _value(items, root, depth + 1, name) if items is not None else FALLBACK
        return [json.loads(json.dumps(one)) for _ in range(count)]
    if t == "object":
        return _object_for(schema, root, depth)
    return FALLBACK


def _object_for(schema: dict, root: dict, depth: int) -> dict:
    props = schema.get("properties")
    props = props if isinstance(props, dict) else {}
    required_raw = schema.get("required")
    required = [r for r in required_raw if isinstance(r, str)] \
        if isinstance(required_raw, list) else []
    out: dict = {}
    optional_used = 0
    for key, sub in props.items():
        if not isinstance(key, str):
            continue
        if key in required:
            out[key] = _value(sub, root, depth + 1, key)
        elif optional_used < MAX_OPTIONAL:
            optional_used += 1
            out[key] = _value(sub, root, depth + 1, key)
    for key in required:
        if key not in out:
            out[key] = _string_for({}, key)
    return out


def generate_args(schema: dict | None) -> dict:
    """Deterministic arguments for a tool's ``inputSchema``. Never raises; a schema that
    is not an object (or is garbage) yields ``{}``."""
    try:
        if not isinstance(schema, dict):
            return {}
        value = _value(schema, schema, 0, "")
        return value if isinstance(value, dict) else {}
    except Exception:  # noqa: BLE001 — a hostile schema must not take the exerciser down
        return {}


# --- README / doc mining ---------------------------------------------------------------

_FENCE_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)
_ARG_KEYS = ("arguments", "args", "params", "input")
MAX_README_CHARS = 400_000
MAX_LOOKAHEAD_LINES = 12


def _json_objects(text: str) -> list[dict]:
    """Every top-level JSON object parseable from ``text`` (whole text first, then each
    balanced ``{…}`` span), capped. Tolerant of prose around the JSON."""
    try:
        whole = json.loads(text)
        if isinstance(whole, dict):
            return [whole]
        if isinstance(whole, list):
            return [x for x in whole if isinstance(x, dict)][:20]
    except Exception:  # noqa: BLE001
        pass
    out: list[dict] = []
    i, attempts = 0, 0
    while i < len(text) and attempts < 50 and len(out) < 20:
        start = text.find("{", i)
        if start < 0:
            break
        end = _balanced_end(text, start)
        attempts += 1
        if end < 0:
            i = start + 1
            continue
        try:
            obj = json.loads(text[start:end + 1])
            if isinstance(obj, dict):
                out.append(obj)
                i = end + 1
                continue
        except Exception:  # noqa: BLE001
            pass
        i = start + 1
    return out


def _balanced_end(text: str, start: int) -> int:
    depth, in_str, esc = 0, False, False
    for pos in range(start, min(len(text), start + 100_000)):
        ch = text[pos]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        elif ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return pos
    return -1


def _named_call_args(obj: object, names: set[str], found: dict, depth: int = 0) -> None:
    """Walk ``obj`` for ``{"name": <tool>, "arguments"|"args"|"params"|"input": {…}}``."""
    if depth > 8:
        return
    if isinstance(obj, dict):
        name = obj.get("name")
        if isinstance(name, str) and name in names and name not in found:
            for key in _ARG_KEYS:
                if isinstance(obj.get(key), dict):
                    found[name] = obj[key]
                    break
        for v in obj.values():
            _named_call_args(v, names, found, depth + 1)
    elif isinstance(obj, list):
        for v in obj[:50]:
            _named_call_args(v, names, found, depth + 1)


def mine_examples(readme_text: str | None, tool_names: list[str] | None) -> dict[str, dict]:
    """Example arguments per tool from a README. Two sources, first match wins:
    a fenced JSON block naming the tool with an arguments object (``tools/call`` shapes),
    or a JSON object in the first fenced block following a heading/line naming the tool.
    Deterministic; never raises."""
    try:
        return _mine(readme_text, tool_names)
    except Exception:  # noqa: BLE001
        return {}


def _mine(readme_text: str | None, tool_names: list[str] | None) -> dict[str, dict]:
    names = {n for n in (tool_names or []) if isinstance(n, str) and n}
    if not readme_text or not isinstance(readme_text, str) or not names:
        return {}
    text = readme_text[:MAX_README_CHARS]
    found: dict[str, dict] = {}
    blocks = [(m.start(), m.group(1)) for m in _FENCE_RE.finditer(text)]
    for _, body in blocks:
        for obj in _json_objects(body):
            _named_call_args(obj, names, found)
    # Source 2: a block "directly following" a line that names a tool.
    lines = text.split("\n")
    offsets, pos = [], 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    block_starts = [s for s, _ in blocks]
    in_fence = False
    for idx, line in enumerate(lines):
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        for name in sorted(names - set(found)):
            if not re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", line):
                continue
            limit = offsets[min(idx + MAX_LOOKAHEAD_LINES, len(lines) - 1)]
            nxt = next((i for i, s in enumerate(block_starts) if offsets[idx] < s <= limit), None)
            if nxt is None:
                continue
            for obj in _json_objects(blocks[nxt][1]):
                if "name" in obj and obj.get("name") in names:
                    continue  # a tools/call shape; source 1 owns it
                found[name] = obj
                break
    return {k: _clean(v) for k, v in found.items()}


def _clean(args: object) -> dict:
    if not isinstance(args, dict):
        return {}
    return {k: v for k, v in args.items() if isinstance(k, str)}


def args_for_tool(name: str, schema: dict | None, mined: dict | None) -> dict:
    """Arguments to call ``name`` with: generated from its schema, then a mined README
    example merged over it (so required keys are always present). Never raises."""
    out = generate_args(schema)
    example = (mined or {}).get(name) if isinstance(mined, dict) else None
    if isinstance(example, dict):
        for k, v in example.items():
            if isinstance(k, str):
                out[k] = v
    return out
