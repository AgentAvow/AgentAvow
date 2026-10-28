"""Tool descriptions written in source code, and hidden Unicode in shipped markdown.

**Tool descriptions in code (G1).** An MCP server's tool description is whatever text
the server sends in ``tools/list``. When the scan holds only the server's SOURCE, that
text sits in the code: a FastMCP ``@mcp.tool()`` docstring, a ``Tool(description=…)``,
a TS ``server.tool("name", "description", …)`` / ``registerTool`` / ``addTool`` /
AI-SDK ``tool({ description })``, or a ``description:`` beside an ``inputSchema`` in a
tools list. The metadata scan reads served descriptions with the wider tool-poisoning
shapes (``METADATA_INJECTION_PATTERNS``: the ``<IMPORTANT>`` block, "do not mention …
to the user"); this module finds the same text in source so the code scanner can read
it with those shapes too. They are applied ONLY to the description text — an ordinary
docstring or comment that says "IMPORTANT:" is never read by them.

**Hidden Unicode in markdown (G2).** A package's README is the text a registry page,
an agent's tool picker and a coding agent read. Tag characters (U+E0000–E007F), bidi
controls and runs of zero-width characters there can carry instructions a human
reviewer never sees.

Pure functions; never raise (a parse failure finds nothing).
"""
from __future__ import annotations

import ast
import re
from bisect import bisect_right
from dataclasses import dataclass
from pathlib import Path

from src.scanner.patterns import (
    INVISIBLE_UNICODE_PATTERNS,
    METADATA_INJECTION_PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    ZERO_WIDTH_RUN_NAME,
    ZERO_WIDTH_RUN_RE,
)

# Cheap gates: a file with none of these declares no tool, so it is never parsed.
_PY_GATE_RE = re.compile(
    r"@\s*[\w.]*\b(?:tool|function_tool)\b|\b(?:Tool|FunctionTool|StructuredTool)\s*\(|"
    r"\badd_tool\s*\(|\bfrom_function\s*\(|[\"'](?:inputSchema|input_schema)[\"']")
_JS_CALL_RE = re.compile(
    r"(?<![\w$])(?:[\w$]+\s*\.\s*)?"
    r"(?P<fn>tool|registerTool|addTool|createTool|defineTool)\s*\(")
_JS_SCHEMA_KEY_RE = re.compile(r"""(?<![\w$])["']?(?:inputSchema|input_schema)["']?\s*:""")
# A string literal is a description when the text before it ends in one of these.
_JS_DESC_KEY_TAIL_RE = re.compile(r"""(?:(?<![\w$])description|["']description["'])\s*:\s*$""")
_JS_DESCRIBE_TAIL_RE = re.compile(r"""\.\s*describe\s*\(\s*$""")

# Python: decorators whose function's docstring IS the tool description (FastMCP
# `@mcp.tool`, `@server.tool`, LangChain / smolagents / CrewAI `@tool`, OpenAI Agents
# `@function_tool`).
_PY_TOOL_DECORATORS = frozenset({"tool", "function_tool"})
# Calls whose `description=` keyword is a tool description.
_PY_TOOL_CALLS = frozenset({"Tool", "FunctionTool", "StructuredTool", "add_tool",
                            "from_function"})

_MAX_PARSE_CHARS = 2_000_000
_MAX_JS_SPAN = 40_000          # bound on one tool call / tools-list object
_MAX_JS_ANCHORS = 400
_MAX_JS_LEXED = 1_000_000      # total characters lexed per file (bounds a huge bundle)
_BACKSCAN = 4_000              # how far back to look for a tools-list object's `{`


def _call_name(func: ast.expr) -> str:
    if isinstance(func, ast.Attribute):
        return func.attr
    if isinstance(func, ast.Name):
        return func.id
    return ""


def _is_tool_decorator(d: ast.expr) -> bool:
    return _call_name(d.func if isinstance(d, ast.Call) else d) in _PY_TOOL_DECORATORS


def _desc_kw_values(node: ast.AST) -> list[ast.expr]:
    """`description=` keyword values of every call under ``node`` (Field(description=…),
    Annotated[str, Field(…)] parameter descriptions)."""
    out: list[ast.expr] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            out += [kw.value for kw in sub.keywords if kw.arg == "description"]
    return out


def _dict_str_keys(d: ast.Dict) -> dict[str, ast.expr]:
    return {k.value: v for k, v in zip(d.keys, d.values, strict=False)
            if isinstance(k, ast.Constant) and isinstance(k.value, str)}


def _schema_descriptions(node: ast.AST) -> list[ast.expr]:
    """Every `"description": …` value inside an input-schema dict (parameter text)."""
    out: list[ast.expr] = []
    for sub in ast.walk(node):
        if isinstance(sub, ast.Dict):
            v = _dict_str_keys(sub).get("description")
            if v is not None:
                out.append(v)
    return out


def _py_nodes(tree: ast.AST) -> list[ast.expr]:
    nodes: list[ast.expr] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decs = [d for d in node.decorator_list if _is_tool_decorator(d)]
            if not decs:
                continue
            body0 = node.body[0] if node.body else None
            if (isinstance(body0, ast.Expr) and isinstance(body0.value, ast.Constant)
                    and isinstance(body0.value.value, str)):
                nodes.append(body0.value)
            for d in decs:
                if isinstance(d, ast.Call):
                    nodes += [kw.value for kw in d.keywords if kw.arg == "description"]
            a = node.args
            for arg in a.posonlyargs + a.args + a.kwonlyargs:
                if arg.annotation is not None:
                    nodes += _desc_kw_values(arg.annotation)
            for default in a.defaults + [x for x in a.kw_defaults if x is not None]:
                nodes += _desc_kw_values(default)
        elif isinstance(node, ast.Call) and _call_name(node.func) in _PY_TOOL_CALLS:
            nodes += [kw.value for kw in node.keywords if kw.arg == "description"]
            nodes += [v for kw in node.keywords if kw.arg in ("inputSchema", "input_schema")
                      for v in _schema_descriptions(kw.value)]
        elif isinstance(node, ast.Dict):
            keys = _dict_str_keys(node)
            schema = keys.get("inputSchema") or keys.get("input_schema")
            if schema is None and "name" in keys and isinstance(keys.get("parameters"),
                                                                 ast.Dict):
                schema = keys["parameters"]  # an OpenAI function-calling definition
            if schema is not None:
                if "description" in keys:
                    nodes.append(keys["description"])
                nodes += _schema_descriptions(schema)
    return nodes


def _py_spans(content: str) -> list[tuple[int, int]]:
    if not _PY_GATE_RE.search(content):
        return []
    try:
        tree = ast.parse(content)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return []
    lines = content.split("\n")
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln) + 1)

    def offset(lineno: int, col: int) -> int:
        # ast columns are UTF-8 byte offsets.
        ln = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
        return starts[lineno - 1] + len(ln.encode("utf-8")[:col].decode("utf-8", "ignore"))

    spans = []
    for n in _py_nodes(tree):
        if getattr(n, "end_lineno", None) is None:
            continue
        spans.append((offset(n.lineno, n.col_offset), offset(n.end_lineno, n.end_col_offset)))
    return spans


# ── JS / TS: a small forward lexer (strings, template literals, comments, brackets) ──

def _skip_string(text: str, i: int, end: int) -> int:
    """``text[i]`` opens a string / template literal: the index just past its close."""
    q = text[i]
    i += 1
    depth = 0
    while i < end:
        c = text[i]
        if c == "\\":
            i += 2
            continue
        if q == "`":
            if c == "$" and i + 1 < end and text[i + 1] == "{":
                depth += 1
                i += 2
                continue
            if c == "}" and depth:
                depth -= 1
            elif c == "`" and not depth:
                return i + 1
        elif c == q:
            return i + 1
        elif c == "\n":
            return i  # an unterminated '…' / "…" literal ends at the line
        i += 1
    return end


def _js_strings_in(text: str, open_idx: int) -> tuple[int, list[tuple[int, int, int, int]]]:
    """Lex forward from the bracket at ``open_idx`` to its match. Returns ``(close_idx,
    [(start, end, depth, arg_index)])`` for every string literal inside (depth 1 =
    directly inside the opening bracket; arg_index counts depth-1 commas)."""
    end = min(len(text), open_idx + _MAX_JS_SPAN)
    depth = 0
    arg = 0
    out: list[tuple[int, int, int, int]] = []
    i = open_idx
    while i < end:
        c = text[i]
        if c in "\"'`":
            j = _skip_string(text, i, end)
            out.append((i, j, depth, arg))
            i = j
            continue
        if c == "/" and i + 1 < end and text[i + 1] in "/*":
            if text[i + 1] == "/":
                nl = text.find("\n", i)
                i = end if nl < 0 else nl
            else:
                close = text.find("*/", i + 2)
                i = end if close < 0 else close + 2
            continue
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0:
                return i, out
        elif c == "," and depth == 1:
            arg += 1
        i += 1
    return end, out


def _is_desc_literal(text: str, start: int) -> bool:
    tail = text[max(0, start - 60):start]
    return bool(_JS_DESC_KEY_TAIL_RE.search(tail) or _JS_DESCRIBE_TAIL_RE.search(tail))


def _enclosing_brace(text: str, pos: int) -> int:
    """Best-effort index of the ``{`` that opens the object around ``pos`` (naive: no
    string awareness going backwards, bounded)."""
    depth = 0
    lo = max(0, pos - _BACKSCAN)
    for i in range(pos - 1, lo - 1, -1):
        c = text[i]
        if c in ")]}":
            depth += 1
        elif c in "([{":
            if depth == 0:
                return i if c == "{" else -1
            depth -= 1
    return -1


def _js_spans(content: str) -> list[tuple[int, int]]:
    spans: set[tuple[int, int]] = set()
    budget = _MAX_JS_LEXED  # characters lexed per file, all anchors together
    n = 0
    for m in _JS_CALL_RE.finditer(content):
        n += 1
        if n > _MAX_JS_ANCHORS or budget <= 0:
            break
        open_idx = m.end() - 1
        close, strings = _js_strings_in(content, open_idx)
        budget -= close - open_idx
        positional_desc = m.group("fn") == "tool" and "." in m.group(0)
        for s, e, depth, arg in strings:
            if _is_desc_literal(content, s):
                spans.add((s, e))
            elif positional_desc and depth == 1 and arg == 1:
                # server.tool("name", "description", schema, handler)
                before = content[open_idx + 1:s]
                if before.count(",") == 1 and re.fullmatch(
                        r"""\s*(["'`])[^"'`]*\1\s*,\s*""", before):
                    spans.add((s, e))
    n = 0
    lexed: set[int] = set()
    for m in _JS_SCHEMA_KEY_RE.finditer(content):
        n += 1
        if n > _MAX_JS_ANCHORS or budget <= 0:
            break
        brace = _enclosing_brace(content, m.start())
        if brace < 0 or brace in lexed:
            continue
        lexed.add(brace)
        close, strings = _js_strings_in(content, brace)
        budget -= close - brace
        for s, e, _depth, _arg in strings:
            if _is_desc_literal(content, s):
                spans.add((s, e))
    return sorted(spans)


def tool_description_spans(content: str, file_lang: str | None) -> list[tuple[int, int]]:
    """``(start, end)`` character offsets of the tool-description literals in a source
    file (Python, JavaScript, TypeScript). Fail-open → []."""
    if not content or len(content) > _MAX_PARSE_CHARS:
        return []
    try:
        if file_lang == "python":
            return _py_spans(content)
        if file_lang in ("javascript", "typescript"):
            return _js_spans(content)
    except Exception:  # noqa: BLE001 — detection aid; must never break a scan
        return []
    return []


_ESCAPE_RE = re.compile(r"\\[nrt]")
# The rules read in a tool description: the line-engine prompt-injection rules plus the
# metadata-only widenings (same rule names, so a finding reads the same either way).
TOOL_DESCRIPTION_RULES = PROMPT_INJECTION_PATTERNS + METADATA_INJECTION_PATTERNS
_SEV_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


@dataclass
class DescriptionHit:
    line_number: int
    name: str
    severity: str
    snippet: str


def tool_description_hits(content: str, file_lang: str | None) -> list[DescriptionHit]:
    """Prompt-injection / tool-poisoning matches inside tool-description literals, one per
    line (the most severe). The literal's escapes (``\\n``) read as whitespace, so a
    phrase split by an escaped newline still matches; offsets are preserved."""
    spans = tool_description_spans(content, file_lang)
    if not spans:
        return []
    line_starts = [0] + [i + 1 for i, c in enumerate(content) if c == "\n"]
    lines = content.split("\n")
    best: dict[int, DescriptionHit] = {}
    for s, e in spans:
        seg = _ESCAPE_RE.sub("  ", content[s:e])
        for name, rx, sev in TOOL_DESCRIPTION_RULES:
            for m in rx.finditer(seg):
                line_num = bisect_right(line_starts, s + m.start())
                cur = best.get(line_num)
                if cur is None or _SEV_RANK[sev] > _SEV_RANK[cur.severity]:
                    best[line_num] = DescriptionHit(
                        line_num, name, sev, lines[line_num - 1].strip()[:120])
    return [best[k] for k in sorted(best)]


# ── G2: hidden Unicode in shipped markdown ──────────────────────────────────────

_MARKDOWN_EXTS = frozenset({".md", ".mdx", ".markdown"})
_MAX_MD_FINDINGS = 10


def is_shipped_markdown(path: str) -> bool:
    """README (any extension) or a markdown file."""
    p = Path(path)
    return p.suffix.lower() in _MARKDOWN_EXTS or p.name.lower().startswith("readme")


def markdown_unicode_hits(text: str) -> list[DescriptionHit]:
    """Hidden-Unicode matches in a markdown / README text, one per line. Tag characters
    (outside a well-formed emoji tag sequence) are critical; a bidi control and a run of
    four or more zero-width characters are medium (prose has no code to reorder, but the
    text a reader sees is not the text an agent reads); ANSI escapes are medium."""
    from src.scanner.scan import _benign_unicode_only

    out: list[DescriptionHit] = []
    for i, line in enumerate(text.split("\n"), 1):
        hit: DescriptionHit | None = None
        for name, rx, sev in INVISIBLE_UNICODE_PATTERNS:
            if name.startswith("Zero-width"):
                if ZERO_WIDTH_RUN_RE.search(line):
                    hit = DescriptionHit(i, ZERO_WIDTH_RUN_NAME, "medium", line.strip()[:120])
                    break
                continue
            if rx.search(line) and not _benign_unicode_only(name, rx, line):
                hit = DescriptionHit(i, name, "critical" if sev == "critical" else "medium",
                                     line.strip()[:120])
                break
        if hit:
            out.append(hit)
            if len(out) >= _MAX_MD_FINDINGS:
                break
    return out
