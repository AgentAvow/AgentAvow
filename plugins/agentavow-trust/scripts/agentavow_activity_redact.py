"""Redaction and tool-input summaries for the AgentAvow local activity log.

The activity log records what an agent did, not what it read or wrote. This module
turns a tool call into a short, secret-free summary: commands and URLs are scrubbed
of credentials and cut to a fixed length, file contents are never kept (only a byte
count), and unknown tools keep their argument names only.

Standard library only. Imported by the plugin's hook scripts.
"""
from __future__ import annotations

import json
import math
import os
import re

CMD_LIMIT = 2000
TEXT_LIMIT = 500
MCP_VALUE_LIMIT = 200

_CUT_MARK = "…[cut]"

_NAME = r"(?:pass(?:word|wd)?|secret|token|api[_-]?key|auth|credential)"
_VALUE = r"(?!\[redacted:)(?:\"[^\"]*\"|'[^']*'|[^\s\"']+)"

_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
    re.DOTALL,
)
_JWT = re.compile(r"eyJ[\w-]+\.[\w-]+\.[\w-]+")
_USERINFO = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]{0,20}://)[^\s/@:]+:[^\s/]*@")
_QUERY = re.compile(r"\?[^\s\"'<>)]*")
_AUTH_HEADER = re.compile(
    r"(?i)(\bAuthorization:\s*)(?:(?:Bearer|Basic|Token)\s+)?[^\s\"']+"
)
_BEARER = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_MYSQL_P = re.compile(r"(?i)(\bmysql\b[^\n|;&]{0,100}?\s-p)\S+")
# curl -u / -U / --user / --proxy-user user:password (also in a short-flag cluster: -sSu)
_CURL_USER = re.compile(
    r"(?i)(\bcurl\b[^\n|;&]{0,200}?\s(?:-[a-z]*u\s*|--(?:proxy-)?user(?:\s+|=)))"
    r"(\"[^\"]*\"|'[^']*'|[^\s\"']+)"
)
# Name lengths are bounded so a long run of dots or dashes cannot make matching
# quadratic.
_SECRET_KV = re.compile(
    r"(?i)(" + _NAME + r"[\w.-]{0,40}[\"']?\s*[=:]\s*)" + _VALUE
)
_SECRET_FLAG = re.compile(
    r"(?i)((?<!-)--(?!-)[\w-]{0,40}?" + _NAME + r"[\w-]{0,40}\s+)(?!-)" + _VALUE
)
_ENTROPY_RUN = re.compile(r"[A-Za-z0-9+/=_-]{32,}")
_HEX_ONLY = re.compile(r"[0-9a-fA-F]+")

# (kind, compiled pattern) for the token formats that replace the whole match.
_TOKEN_RULES = (
    ("aws", re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}")),
    ("github", re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}")),
    ("api_key", re.compile(r"(?<![A-Za-z0-9])sk-(?:ant-)?[A-Za-z0-9_-]{20,}")),
    ("slack", re.compile(r"xox[abprs]-[A-Za-z0-9-]{10,}")),
    ("google", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("gitlab", re.compile(r"glpat-[A-Za-z0-9_-]{20,}")),
    ("npm", re.compile(r"npm_[A-Za-z0-9]{36}")),
)


def _mark(kind: str) -> str:
    return f"[redacted:{kind}]"


def _entropy(run: str) -> float:
    counts: dict[str, int] = {}
    for ch in run:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(run)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _token_start(text: str, pos: int) -> int:
    """Start of the whitespace, quote or ``=`` delimited token containing pos."""
    low = max(pos - 256, 0)
    while pos > low and text[pos - 1] not in " \t\r\n\"'=":
        pos -= 1
    return pos


_PATH_PREFIXES = ("/", "~/", "./", "../")
# Readable names: lower-case or Capitalised words (camelCase allowed, no runs of
# capitals), or a whole ALL-CAPS word like LICENSE, joined by . _ -
_PIECE = r"(?:(?:[A-Z][a-z0-9]*|[a-z0-9]+)(?:[A-Z][a-z0-9]+)*|[A-Z]+)"
_READABLE = re.compile(_PIECE + r"(?:[._-]" + _PIECE + r")*")


def _random_segment(seg: str) -> bool:
    """True when one path segment looks like a random secret on its own."""
    if len(seg) < 6 or _HEX_ONLY.fullmatch(seg):
        return False
    if not _READABLE.fullmatch(seg):
        return True
    return (
        len(seg) >= 16
        and any(c.isupper() for c in seg)
        and any(c.islower() for c in seg)
        and any(c.isdigit() for c in seg)
        and _entropy(seg) >= 3.5
    )


def _entropy_sub(match: re.Match) -> str:
    run = match.group(0)
    if _HEX_ONLY.fullmatch(run):
        return run  # commit hashes and digests
    if "/" in run:
        segments = run.split("/")
        random_flags = [_random_segment(seg) for seg in segments]
        text, start = match.string, match.start()
        if text.startswith(_PATH_PREFIXES, _token_start(text, start)):
            # A path: keep readable segments, redact each random-looking one.
            return "/".join(
                _mark("entropy") if flag else seg
                for seg, flag in zip(segments, random_flags)
            )
        if not any(random_flags):
            return run  # a relative path of readable segments
    return _mark("entropy") if _entropy(run) >= 4.0 else run


def _curl_user_sub(match: re.Match) -> str:
    """Keep the user name of ``user:password``; redact the password."""
    value = match.group(2)
    quote = value[0] if value[0] in "\"'" else ""
    inner = value[1:-1] if quote else value
    user, sep, password = inner.partition(":")
    if not sep or not password or password.startswith("[redacted:"):
        return match.group(0)
    return match.group(1) + quote + user + ":" + _mark("secret") + quote


def _query_sub(match: re.Match) -> str:
    """Redact a ``?...`` tail only when it follows a ``scheme://`` URL."""
    text, pos = match.string, match.start()
    low = max(pos - 2048, 0)
    start = pos
    while start > low and text[start - 1] not in " \t\r\n\"'<>":
        start -= 1
    if "://" not in text[start:pos]:
        return match.group(0)
    return "?" + _mark("query")


def redact(text: str) -> str:
    """Replace secrets in text with ``[redacted:<kind>]`` markers."""
    text = _PRIVATE_KEY.sub(_mark("private_key"), text)
    text = _JWT.sub(_mark("jwt"), text)
    for kind, pattern in _TOKEN_RULES:
        text = pattern.sub(_mark(kind), text)
    text = _USERINFO.sub(lambda m: m.group(1) + _mark("url_userinfo") + "@", text)
    text = _QUERY.sub(_query_sub, text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + _mark("bearer"), text)
    text = _BEARER.sub(lambda m: m.group(1) + _mark("bearer"), text)
    text = _MYSQL_P.sub(lambda m: m.group(1) + _mark("secret"), text)
    text = _CURL_USER.sub(_curl_user_sub, text)
    text = _SECRET_KV.sub(lambda m: m.group(1) + _mark("secret"), text)
    text = _SECRET_FLAG.sub(lambda m: m.group(1) + _mark("secret"), text)
    return _ENTROPY_RUN.sub(_entropy_sub, text)


def cut(text: str, limit: int) -> str:
    """Truncate text to at most ``limit`` characters, ending in a marker if cut."""
    if len(text) <= limit:
        return text
    return text[: max(limit - len(_CUT_MARK), 0)] + _CUT_MARK


def _scrub(text: str, limit: int) -> str:
    """Redact then cut. Only a prefix a little past the limit is scanned."""
    return cut(redact(text[: limit + 256]), limit)


# MCP argument names are judged more widely than names inside commands: a name is all
# there is to go on, and masking a harmless value costs little.
_SECRET_ARG_NAME = re.compile(
    _NAME + r"|pwd|private[_-]?key|cookie|bearer", re.IGNORECASE
)
_CAMEL = re.compile(r"([a-z0-9])([A-Z])")
_SEGMENT_SPLIT = re.compile(r"[^a-z0-9]+")
# A name segment that marks a secret on its own (``key``, ``access_key``, ``signingKey``),
# but not as part of a longer word (``keyword``, ``monkey``).
_SECRET_SEGMENTS = frozenset({"key"})
# A {"name": "X-Api-Key", "value": "..."} pair: the label names the secret, the value holds it.
_PAIR_LABELS = frozenset({"name", "key", "header", "field"})
_PAIR_VALUES = frozenset({"value", "val", "content"})
# Bounds for walking a nested MCP argument: past these the value is cut anyway.
_MASK_DEPTH = 8
_MASK_ITEMS = 200


def _secret_name(name: object) -> bool:
    """True when an argument or key name looks like it holds a secret (``client_secret``)."""
    if not isinstance(name, str):
        return False
    name = name[:256]
    if _SECRET_ARG_NAME.search(name):
        return True
    segments = _SEGMENT_SPLIT.split(_CAMEL.sub(r"\1_\2", name).lower())
    return not _SECRET_SEGMENTS.isdisjoint(segments)


def _names_a_secret(pair: dict) -> bool:
    """True when a dict is a label/value pair whose label is a secret's name."""
    for n, (k, v) in enumerate(pair.items()):
        if n >= _MASK_ITEMS:
            return False
        if isinstance(k, str) and k.lower() in _PAIR_LABELS and _secret_name(v):
            return True
    return False


def _mask(value: object, depth: int = 0) -> object:
    """A copy of a nested value with every secret-named dict key's value replaced.

    Walks at most ``_MASK_DEPTH`` levels and ``_MASK_ITEMS`` items per container,
    which is more than a value cut to ``MCP_VALUE_LIMIT`` characters can show.
    """
    if isinstance(value, dict):
        if depth >= _MASK_DEPTH:
            return "…"
        out = {}
        pair = _names_a_secret(value)
        for n, (k, v) in enumerate(value.items()):
            if n >= _MASK_ITEMS:
                break
            hidden = _secret_name(k) or (
                pair and isinstance(k, str) and k.lower() in _PAIR_VALUES)
            out[k] = _mark("secret") if hidden else _mask(v, depth + 1)
        return out
    if isinstance(value, (list, tuple)):
        if depth >= _MASK_DEPTH:
            return "…"
        return [_mask(v, depth + 1) for v in value[:_MASK_ITEMS]]
    if isinstance(value, str):
        return value[: MCP_VALUE_LIMIT + 256]
    return value


def _mcp_value(name: object, value: object) -> str:
    if _secret_name(name):
        return _mark("secret")
    if isinstance(value, (dict, list, tuple)):
        value = _mask(value)
    return _scrub(str(value), MCP_VALUE_LIMIT)


def _tilde(path: str) -> str:
    home = os.path.expanduser("~")
    if home and home != os.sep:
        if path == home:
            return "~"
        if path.startswith(home + os.sep):
            return "~" + path[len(home):]
    return path


def _path(value: object) -> str | None:
    """A file path: home shown as ``~``, scrubbed like other text, cut to TEXT_LIMIT."""
    if not isinstance(value, str):
        return None
    return _scrub(_tilde(value), TEXT_LIMIT)


def _nbytes(value: object) -> int:
    return len(value.encode("utf-8", "replace")) if isinstance(value, str) else 0


def _command_text(tool_input: dict) -> str:
    cmd = tool_input.get("command", tool_input.get("cmd", ""))
    if isinstance(cmd, (list, tuple)):
        return " ".join(str(part) for part in cmd)
    return cmd if isinstance(cmd, str) else ""


def _write_bytes(tool: str, tool_input: dict) -> int | None:
    if tool == "Write":
        return _nbytes(tool_input.get("content"))
    if tool == "Edit":
        return _nbytes(tool_input.get("new_string"))
    if tool == "MultiEdit":
        edits = tool_input.get("edits")
        if not isinstance(edits, list):
            return 0
        return sum(_nbytes(e.get("new_string")) for e in edits if isinstance(e, dict))
    if tool == "NotebookEdit":
        return _nbytes(tool_input.get("new_source"))
    return None


_PATCH_FILE = re.compile(
    r"^\*\*\* (?:Add File|Update File|Delete File|Move to): (.+?)\s*$", re.MULTILINE
)


def _patch_text(tool_input: dict) -> str:
    for key in ("input", "patch", "command", "cmd"):
        value = tool_input.get(key)
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)):
            strs = [v for v in value if isinstance(v, str)]
            if strs:
                return strs[-1]
    return ""


def summarize_input(tool: str, tool_input: object, cwd: str | None) -> dict:
    """Summarise a tool call's input without keeping content or secrets."""
    args = tool_input if isinstance(tool_input, dict) else {}
    if not isinstance(tool, str):
        tool = ""

    if tool in ("Bash", "exec", "shell"):
        return {"command": _scrub(_command_text(args), CMD_LIMIT)}

    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        raw = args.get("file_path") or args.get("notebook_path") or args.get("path") or ""
        summary: dict = {"path": _path(raw) or ""}
        size = _write_bytes(tool, args)
        if size is not None:
            summary["bytes"] = size
        return summary

    if tool == "apply_patch":
        patch = _patch_text(args)
        return {
            "paths": [_path(p) for p in _PATCH_FILE.findall(patch)],
            "bytes": _nbytes(patch),
        }

    if tool == "WebFetch":
        return {"url": _scrub(str(args.get("url", "")), TEXT_LIMIT)}

    if tool == "WebSearch":
        return {"query": _scrub(str(args.get("query", "")), TEXT_LIMIT)}

    if tool in ("Grep", "Glob"):
        return {
            "pattern": _scrub(str(args.get("pattern", "")), TEXT_LIMIT),
            "path": _path(args.get("path")),
        }

    if tool.startswith("mcp__"):
        pair = _names_a_secret(args)
        return {
            "args": {
                cut(str(name), TEXT_LIMIT): (
                    _mark("secret")
                    if pair and isinstance(name, str) and name.lower() in _PAIR_VALUES
                    else _mcp_value(name, value)
                )
                for name, value in args.items()
            }
        }

    return {"arg_names": sorted(cut(str(k), TEXT_LIMIT) for k in args)}


def summarize_output(tool_response: object) -> dict:
    """Return the output size. ``ok`` is None: the caller sets it from the event type."""
    if isinstance(tool_response, str):
        text = tool_response
    else:
        try:
            text = json.dumps(tool_response, default=str)
        except (TypeError, ValueError):
            text = str(tool_response)
    return {"ok": None, "out_bytes": len(text.encode("utf-8", "replace"))}
