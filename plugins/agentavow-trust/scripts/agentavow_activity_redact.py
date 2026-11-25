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
_USERINFO = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://)[^\s/@:]+:[^\s/@]*@")
_QUERY = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.-]*://[^\s?\"'<>]*)\?[^\s\"'<>)]*")
_AUTH_HEADER = re.compile(
    r"(?i)(\bAuthorization:\s*)(?:(?:Bearer|Basic|Token)\s+)?[^\s\"']+"
)
_BEARER = re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]+", re.IGNORECASE)
_MYSQL_P = re.compile(r"(?i)(\bmysql\b[^\n|;&]*?\s-p)\S+")
_SECRET_KV = re.compile(
    r"(?i)((?<![\w])[\w.-]*?" + _NAME + r"[\w.-]*\s*[=:]\s*)" + _VALUE
)
_SECRET_FLAG = re.compile(r"(?i)(--[\w-]*?" + _NAME + r"[\w-]*\s+)(?!-)" + _VALUE)
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


def _entropy_sub(match: re.Match) -> str:
    run = match.group(0)
    if _HEX_ONLY.fullmatch(run):
        return run  # commit hashes and digests
    return _mark("entropy") if _entropy(run) >= 4.0 else run


def redact(text: str) -> str:
    """Replace secrets in text with ``[redacted:<kind>]`` markers."""
    text = _PRIVATE_KEY.sub(_mark("private_key"), text)
    text = _JWT.sub(_mark("jwt"), text)
    for kind, pattern in _TOKEN_RULES:
        text = pattern.sub(_mark(kind), text)
    text = _USERINFO.sub(lambda m: m.group(1) + _mark("url_userinfo") + "@", text)
    text = _QUERY.sub(lambda m: m.group(1) + "?" + _mark("query"), text)
    text = _AUTH_HEADER.sub(lambda m: m.group(1) + _mark("bearer"), text)
    text = _BEARER.sub(lambda m: m.group(1) + _mark("bearer"), text)
    text = _MYSQL_P.sub(lambda m: m.group(1) + _mark("secret"), text)
    text = _SECRET_KV.sub(lambda m: m.group(1) + _mark("secret"), text)
    text = _SECRET_FLAG.sub(lambda m: m.group(1) + _mark("secret"), text)
    return _ENTROPY_RUN.sub(_entropy_sub, text)


def cut(text: str, limit: int) -> str:
    """Truncate text to at most ``limit`` characters, ending in a marker if cut."""
    if len(text) <= limit:
        return text
    return text[: max(limit - len(_CUT_MARK), 0)] + _CUT_MARK


def _tilde(path: str) -> str:
    home = os.path.expanduser("~")
    if home and home != os.sep:
        if path == home:
            return "~"
        if path.startswith(home + os.sep):
            return "~" + path[len(home):]
    return path


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

    if tool in ("Bash", "exec", "shell"):
        return {"command": cut(redact(_command_text(args)), CMD_LIMIT)}

    if tool in ("Read", "Write", "Edit", "MultiEdit", "NotebookEdit"):
        raw = args.get("file_path") or args.get("notebook_path") or args.get("path") or ""
        summary: dict = {"path": _tilde(raw) if isinstance(raw, str) else ""}
        size = _write_bytes(tool, args)
        if size is not None:
            summary["bytes"] = size
        return summary

    if tool == "apply_patch":
        patch = _patch_text(args)
        return {
            "paths": [_tilde(p) for p in _PATCH_FILE.findall(patch)],
            "bytes": _nbytes(patch),
        }

    if tool == "WebFetch":
        return {"url": redact(str(args.get("url", "")))}

    if tool == "WebSearch":
        return {"query": cut(redact(str(args.get("query", ""))), TEXT_LIMIT)}

    if tool in ("Grep", "Glob"):
        path = args.get("path")
        return {
            "pattern": cut(redact(str(args.get("pattern", ""))), TEXT_LIMIT),
            "path": _tilde(path) if isinstance(path, str) else None,
        }

    if tool.startswith("mcp__"):
        return {
            "args": {
                str(name): cut(redact(str(value)), MCP_VALUE_LIMIT)
                for name, value in args.items()
            }
        }

    return {"arg_names": sorted(str(k) for k in args)}


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
