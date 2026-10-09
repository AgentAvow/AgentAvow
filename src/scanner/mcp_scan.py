"""MCP capability grading — score a live MCP server's SERVED tool surface (roadmap
§2.D). This is what makes AgentAvow more than a package scanner: it grades what a
tool is *permitted to do to an agent*, from the actual `tools/list` the server
advertises at runtime — not just what its repo commits.

``analyze_mcp`` is PURE + offline: it takes the parsed handshake JSON and returns
scanner ``Finding``s. Deterministic, so a submitter can upload their own
``tools/list`` and we recompute + sign the identical verdict with no live server.
The live handshake (``fetch_mcp_tools``) is separate and fail-open.

Detectors (all deterministic from the JSON alone):
  * tool-poisoning / hidden instructions in tool names + descriptions + param
    descriptions + resource/prompt text (reuses prompt_injection + hidden_unicode);
  * input-schema risk — freeform/dangerous params, ``additionalProperties: true``;
  * dangerous-capability taxonomy per tool + lethal-trifecta across the tool SET;
  * annotation truthfulness — ``readOnlyHint`` that lies about a write/exec tool.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

import rfc8785

# Capability taxonomy — classify a tool from its name + description.
#
# exec / fs_write / db_write drive the annotation-lie finding and the "mutate" leg of
# the lethal trifecta, so they need a capability PHRASE (a verb plus the thing it acts
# on), not a bare word: "run a search", "dry run", "list commands", "create a summary",
# "update the view" and "drop-in" are not code execution or writes. A match preceded
# in the same clause by a negation ("never executes code", "does not write files",
# "read-only: no writes") does not count (see ``_affirmed``).
_GAP = r"(?:\s+[\w'./-]+){0,%d}?\s+"  # up to N intervening words between verb and object

_EXEC_OBJ = (
    r"(?:commands?|shell|scripts?|programs?|process(?:es)?|binar(?:y|ies)|executables?"
    r"|python|javascript|js|bash|powershell|snippets?"
    r"|code(?!\s+(?:analysis|review|search|scan|quality|coverage|style|navigation|"
    r"intelligence|completion|graph|map|owners?|examples?|documentation|docs)))"
)
_FS_OBJ = r"(?:files?|director(?:y|ies)|folders?|paths?|disk|filesystem|file\s+system)"
_DB_OBJ = (
    r"(?:rows?|records?|tables?|databases?|db|collections?|entries|entry|documents? in"
    r"|keys? in)"
)

_CAP_PATTERNS: dict[str, re.Pattern] = {
    "exec": re.compile(
        r"(?<!-)\b(?:exec(?:ute|utes|uted|uting)?|run|runs|running|eval(?:uate|uates|uating)?"
        r"|invoke|invokes|launch(?:es)?|spawn(?:s|ed|ing)?)" + (_GAP % 3) + _EXEC_OBJ + r"\b(?!-)"
        r"|\b(?:shell|terminal|system|os|cli)\s+commands?\b"
        r"|\b(?:shell|command|code|process)\s+execution\b"
        r"|\b(?:arbitrary|remote)\s+(?:code|commands?|scripts?)\b"
        r"|\b(?:subprocess(?:es)?|child[\s_]process(?:es)?|bash|powershell|zsh)\b"
        r"|\bsh\s+-c\b"
        r"|\b(?:in|via|through|from|into|on)\s+(?:a|the)?\s*shell\b(?!-)",
        re.I),
    "fs_write": re.compile(
        r"\b(?:write|writes|writing|overwrite|overwrites|append|appends|create|creates"
        r"|creating|delete|deletes|deleting|remove|removes|removing|move|moves|moving"
        r"|rename|renames|renaming|save|saves|saving|edit|edits|editing|modify|modifies"
        r"|copy|copies)" + (_GAP % 4) + _FS_OBJ + r"\b"
        r"|\b(?:mkdir|rmdir|chmod|chown|unlink|rm\s+-rf?)\b"
        r"|\bfiles?\s+(?:writes?|deletion|removal)\b",
        re.I),
    "fs_read": re.compile(
        r"\b(?:read|reads|reading|open|opens|list|lists|listing|load|loads|get|gets|view"
        r"|cat|search|searches|find|finds|stat|glob|browse)" + (_GAP % 5) + _FS_OBJ + r"\b"
        r"|\bglob\b|\bfile\s+(?:contents?|tree|listing|search)\b",
        re.I),
    "net": re.compile(
        r"\b(?:https?|urls?|fetch|fetches|curl|wget|downloads?(?!\s+per\b)|upload|uploads"
        r"|webhooks?|api\s+calls?|web\s+(?:pages?|requests?|search)"
        r"|(?:http|web|api|network|post|get)\s+requests?|requests?\s+to"
        r"|post\s+(?:to|data)|send\s+(?:an?\s+)?(?:emails?|messages?|requests?|data))\b",
        re.I),
    "secrets": re.compile(
        r"\b(?:secrets?|passwords?|credentials?|api[_ ]?keys?|private\s+keys?|ssh\s+keys?"
        r"|(?:access|auth|api|bearer|oauth|session|refresh|github|gh|npm|personal)"
        r"[\s_-]tokens?|env(?:ironment)?\s+var(?:iable)?s?|\.env|env\s+files?"
        r"|process\.env|os\.environ|aws\s+(?:credentials|keys?|secrets?))\b",
        re.I),
    "db_write": re.compile(
        r"\b(?:insert|inserts|inserting|update|updates|updating|upsert|upserts|delete"
        r"|deletes|deleting|truncate|truncates|modify|modifies|write"
        r"|writes|writing|alter|alters)" + (_GAP % 3) + _DB_OBJ + r"\b"
        r"|\b(?:drop|truncate|alter)\s+(?:table|database|index|collection)\b"
        r"|\bdelete\s+from\b|\binsert\s+into\b"
        r"|\bgraphql\s+mutations?\b"
        r"|\b(?:run|runs|execute|executes|perform|performs|send|sends)\s+(?:an?\s+|the\s+)?"
        r"mutations?\b"
        r"|\b(?:execute|executes|run|runs)\s+(?:arbitrary|raw|any)\s+sql\b",
        re.I),
}

# A capability match preceded in the same clause (within ~4 words) by one of these
# is a denial, not a claim: "never executes code", "does not write files".
_NEGATION = re.compile(
    r"^(?:not|never|no|none|nor|without|cannot|can't|cant|doesn't|doesnt|don't|dont"
    r"|won't|wont|isn't|isnt|read-only|readonly|non-destructive)$", re.I)
_CLAUSE_BREAK = re.compile(r"[.;:!?\n(),]|\bbut\b|\bwhile\b|\bthen\b", re.I)


def _affirmed(pat: re.Pattern, text: str) -> bool:
    """True when ``pat`` matches somewhere in ``text`` that is not negated."""
    for m in pat.finditer(text):
        head = _CLAUSE_BREAK.split(text[: m.start()])[-1]
        words = re.findall(r"[\w'-]+", head)[-4:]
        if not any(_NEGATION.match(w) for w in words):
            return True
    return False


def _normalize_tool_name(name: str) -> str:
    """``execute_command`` / ``runShellCommand`` → words, so a name reads as prose."""
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", name)
    return re.sub(r"[_\-.:/]+", " ", s)

# Param names that are dangerous when freeform (no enum / constrained format).
_DANGEROUS_PARAM = re.compile(
    r"^(cmd|command|exec|script|code|eval|shell|path|file|filepath|filename|dir|"
    r"directory|url|uri|endpoint|query|sql|expression|template|payload|body)$", re.I
)
# The subset of those that, as a freeform string, is declared evidence of execution.
_EXEC_PARAM = re.compile(r"^(cmd|command|commands|script|shell|shell_command)$", re.I)
# Ambiguous names (``code`` is as often an OTP, invite or country code): evidence only
# when the param's own description says it is source to run.
_EXEC_PARAM_AMBIGUOUS = re.compile(r"^(code|exec|eval|source|expression)$", re.I)
_EXEC_PARAM_DESC = re.compile(
    r"\b(?:python|javascript|typescript|bash|shell|sql|source\s+code|code\s+to\s+(?:run|exec"
    r"|evaluate)|script|snippet|to\s+(?:run|execute|evaluate)|executed|evaluated)\b", re.I)
# A tool whose name, or the first word of its description, is a destructive verb
# ("delete_record", "Removes the entry ...") mutates state whatever object it names.
_DESTRUCTIVE_NAME_VERBS = frozenset({
    "delete", "remove", "drop", "purge", "destroy", "erase", "truncate", "overwrite",
    "write", "insert", "upsert", "wipe",
})
_DESTRUCTIVE_LEAD = re.compile(
    r"^\W*(?:delete|remove|drop|purge|destroy|erase|truncate|overwrite|wipe)s?\b", re.I)
# A description that explicitly says the "command" is not executed on a real host
# (e.g. a docs server's shell-like query over a virtual, in-memory filesystem). The
# schema and the prose then disagree, so the read-only contradiction is medium.
_EXEC_DENIAL = re.compile(
    r"\b(?:not|never|isn't|is\s+not)\s+(?:a\s+)?(?:real\s+)?shell\b"
    r"|\bnothing\s+(?:is\s+)?(?:runs?|executed|executes)\b"
    r"|\bno\s+process\s+(?:control|execution|spawning)\b"
    r"|\b(?:virtual(?:ized)?|in-memory|simulated|sandboxed)\s+(?:in-memory\s+)?"
    r"(?:filesystem|file\s+system|shell)\b",
    re.I)


@dataclass
class McpScanResult:
    findings: list = field(default_factory=list)   # list[Finding]
    tool_count: int = 0
    resource_count: int = 0
    prompt_count: int = 0
    capabilities: dict[str, int] = field(default_factory=dict)  # cap -> tool count
    server_name: str | None = None
    lethal_trifecta: bool = False
    blast_radius: dict = field(default_factory=dict)  # {level, capabilities, why}


# Human labels for the capability taxonomy, for the blast-radius UI.
_CAP_LABEL = {
    "exec": "run code / shell", "net": "reach the network", "fs_write": "write files",
    "fs_read": "read files", "secrets": "read secrets / env", "db_write": "write to a database",
}


def compute_blast_radius(capabilities: dict, lethal_trifecta: bool) -> dict:
    """How much damage this tool could do to an agent if it's misused or exploited —
    derived from the capability taxonomy, not the code grade. A clean-code tool can
    still have a huge blast radius (the gym-booking agent had exactly this: unconstrained
    network reach + a goal). ``level`` ∈ low | moderate | high | critical."""
    caps = {c for c, n in (capabilities or {}).items() if n}
    can_exec = "exec" in caps
    can_net = "net" in caps
    can_write = bool(caps & {"fs_write", "db_write"})
    can_read_sensitive = bool(caps & {"secrets", "fs_read"})

    if lethal_trifecta or (can_exec and can_net):
        level, why = "critical", (
            "Can run code AND reach the network — a compromise or a misread goal can "
            "execute and exfiltrate. This is the class behind the autonomous-exploit stories."
        )
    elif can_exec or (can_net and (can_read_sensitive or can_write)):
        level, why = "high", (
            "Can execute, or can both read sensitive data and send it out / change state — "
            "enough to act well beyond a read-only lookup."
        )
    elif can_net or can_write:
        level, why = "moderate", (
            "Can reach the network or modify state, but not the full read-sensitive + "
            "exfiltrate combination."
        )
    else:
        level, why = "low", "Read-only / local — no network, code execution, or writes."
    return {
        "level": level,
        "capabilities": [
            {"key": c, "label": _CAP_LABEL.get(c, c), "count": (capabilities or {}).get(c, 0)}
            for c in sorted(caps)
        ],
        "lethal_trifecta": bool(lethal_trifecta),
        "why": why,
    }


def _classify_tool(name: str, desc: str) -> set[str]:
    """Capabilities a tool's name + description affirm (prose evidence only)."""
    blob = f"{_normalize_tool_name(name)}. {desc}"
    return {cap for cap, pat in _CAP_PATTERNS.items() if _affirmed(pat, blob)}


def _schema_exec_params(schema: Any) -> list[str]:
    """Freeform string params named like a command / script / code: declared evidence
    that the tool executes what it is given, independent of how the prose reads."""
    props = schema.get("properties") if isinstance(schema, dict) else None
    if not isinstance(props, dict):
        return []
    out = []
    for pname, pspec in props.items():
        if (
            isinstance(pspec, dict) and pspec.get("type") == "string"
            and not pspec.get("enum") and "const" not in pspec
            and not pspec.get("format") and not pspec.get("pattern")
            and (
                _EXEC_PARAM.match(str(pname))
                or (
                    _EXEC_PARAM_AMBIGUOUS.match(str(pname))
                    and _EXEC_PARAM_DESC.search(str(pspec.get("description") or ""))
                )
            )
        ):
            out.append(str(pname))
    return out


def _declares_destruction(name: str, desc: str) -> bool:
    """The tool's name or its description's first word is a destructive verb."""
    words = _normalize_tool_name(name).lower().split()
    return bool(
        (words and words[0] in _DESTRUCTIVE_NAME_VERBS) or _DESTRUCTIVE_LEAD.search(desc)
    )


def _finding(category: str, name: str, severity: str, where: str, remediation: str = ""):
    from src.scanner.scan import Finding
    return Finding(
        category=category, name=name, severity=severity,
        file_path=where, line_number=0, snippet="", remediation=remediation,
    )


def _scan_text_for_injection(text: str, where: str) -> list:
    """Run the prompt_injection + hidden_unicode detectors over a metadata string
    (tool/param description). Reuses the repo scanner so tool descriptions get the
    same tool-poisoning + invisible-character checks as code."""
    if not text or not text.strip():
        return []
    from src.scanner.scan import _scan_content
    try:
        findings, _pos, _sup = _scan_content(text, where, metadata_text=True)
    except Exception:
        return []
    # Keep only the metadata-relevant detectors; relabel path to the MCP location.
    keep = []
    for f in findings:
        if f.category in ("prompt_injection", "hidden_unicode"):
            f.file_path = where
            keep.append(f)
    return keep


def analyze_mcp(
    tools: list[dict] | None,
    *,
    resources: list[dict] | None = None,
    prompts: list[dict] | None = None,
    server_info: dict | None = None,
) -> McpScanResult:
    """Score an MCP server's advertised surface. Pure + deterministic."""
    tools = tools or []
    resources = resources or []
    prompts = prompts or []
    result = McpScanResult(
        tool_count=len(tools), resource_count=len(resources), prompt_count=len(prompts),
        server_name=(server_info or {}).get("name"),
    )
    caps_union: set[str] = set()
    cap_counts: dict[str, int] = {}
    mutates_any = False  # a destructive-verb tool name / lead, outside the cap taxonomy

    for t in tools:
        if not isinstance(t, dict):
            continue
        tname = str(t.get("name", "") or "unnamed")
        tdesc = str(t.get("description", "") or "")
        where = f"tool:{tname}"

        # 1. tool-poisoning / hidden instructions in name + description
        result.findings.extend(_scan_text_for_injection(f"{tname}\n{tdesc}", where))

        # 2. input-schema risk
        schema = t.get("inputSchema") or t.get("input_schema") or {}
        if isinstance(schema, dict):
            if schema.get("additionalProperties") is True:
                result.findings.append(_finding(
                    "schema_risk",
                    f"Tool '{tname}' accepts arbitrary extra params (additionalProperties:true)",
                    "medium", where,
                    "Constrain the input schema; unbounded params widen the attack surface.",
                ))
            props = schema.get("properties")
            if isinstance(props, dict):
                for pname, pspec in props.items():
                    if not isinstance(pspec, dict):
                        continue
                    result.findings.extend(_scan_text_for_injection(
                        str(pspec.get("description", "") or ""), f"{where}:param:{pname}"))
                    is_free = (
                        pspec.get("type") == "string"
                        and not pspec.get("enum") and not pspec.get("format")
                        and not pspec.get("pattern")
                    )
                    if is_free and _DANGEROUS_PARAM.match(str(pname)):
                        result.findings.append(_finding(
                            "schema_risk",
                            f"Tool '{tname}' takes a freeform '{pname}'",
                            "high", f"{where}:param:{pname}",
                            f"Constrain '{pname}' with an enum/pattern;"
                            " freeform is an injection/RCE vector.",
                        ))

        # 3. capability taxonomy — prose phrases, plus declared schema evidence
        prose_caps = _classify_tool(tname, tdesc)
        exec_params = _schema_exec_params(schema)
        # A "command" the description says never runs on a real host (a docs server's
        # shell-like query over a virtual filesystem) is not counted as execution.
        exec_denied = bool(exec_params) and bool(_EXEC_DENIAL.search(tdesc))
        caps = prose_caps | ({"exec"} if exec_params and not exec_denied else set())
        caps_union |= caps
        destructive = _declares_destruction(tname, tdesc)
        mutates_any = mutates_any or destructive
        for c in caps:
            cap_counts[c] = cap_counts.get(c, 0) + 1

        # 4. annotation truthfulness — readOnlyHint that lies. Declared schema evidence
        # (a freeform command/script/code param) is high; a contradiction read only
        # from description prose is medium, since prose is a weaker signal than a
        # schema. The behavioral sandbox's observed write (annotation_readonly_violated)
        # stays high on its own path.
        ann = t.get("annotations") or {}
        if isinstance(ann, dict) and ann.get("readOnlyHint") is True:
            writes = caps & {"fs_write", "exec", "db_write"}
            if exec_params:
                denied = exec_denied
                result.findings.append(_finding(
                    "annotation_lie",
                    f"Tool '{tname}' claims readOnlyHint but takes a freeform "
                    f"'{exec_params[0]}' to execute"
                    + (" (its description says nothing runs on a real host)" if denied else ""),
                    "medium" if denied else "high", f"{where}:param:{exec_params[0]}",
                    "A read-only annotation on a tool that accepts a command/script/code"
                    " string contradicts its declared schema; fix the annotation or the"
                    " input.",
                ))
            elif writes or destructive:
                said = [_CAP_LABEL[c] for c in sorted(writes)] or ["delete or overwrite data"]
                result.findings.append(_finding(
                    "annotation_lie",
                    f"Tool '{tname}' claims readOnlyHint but its name or description says"
                    f" it can {', '.join(said)}",
                    "medium", where,
                    "Either the read-only annotation or the description is wrong; a"
                    " read-only claim that contradicts what the tool says it does misleads"
                    " clients that auto-approve read-only tools.",
                ))

    # resource + prompt text also gets the injection scan (always-loaded content)
    for r in resources:
        if isinstance(r, dict):
            result.findings.extend(_scan_text_for_injection(
                str(r.get("description", "") or ""), f"resource:{r.get('name', '?')}"))
    for p in prompts:
        if isinstance(p, dict):
            result.findings.extend(_scan_text_for_injection(
                str(p.get("description", "") or ""), f"prompt:{p.get('name', '?')}"))

    # lethal trifecta across the whole tool SET: private-data access + external
    # comms + (implicit) untrusted input → the classic exfiltration chain.
    private = bool(caps_union & {"secrets", "fs_read"})
    external = bool(caps_union & {"net"})
    mutate = bool(caps_union & {"fs_write", "exec", "db_write"}) or mutates_any
    if private and external and (mutate or "exec" in caps_union):
        result.lethal_trifecta = True
        result.findings.append(_finding(
            "lethal_trifecta",
            "Lethal trifecta: private-data access + external comms + action/exec across the tools",
            "critical", "server",
            "Split powerful capabilities across servers, or confirm the exfil-capable path.",
        ))

    result.capabilities = cap_counts
    result.blast_radius = compute_blast_radius(cap_counts, result.lethal_trifecta)
    return result


# ── tool-definition digests (rug-pull detection + gate binding) ──────────────

# Version label folded into every per-tool preimage. Changing which fields are
# hashed, or how, means a new label, so an old digest is never read as a new one.
MCP_TOOL_DIGEST_PROFILE = "agentavow.mcp-tool-definition.v1"

# The parts of an MCP tool definition a client or model acts on. ``_meta`` and
# unknown fields are left out: they are not part of the contract, and hashing them
# would report drift on changes that alter nothing an agent sees.
_TOOL_DIGEST_FIELDS = (
    "name", "title", "description", "inputSchema", "outputSchema", "annotations",
)

_MAX_SAFE_INT = 2**53 - 1
_MAX_TOOL_KEY_NAME = 128
# The per-tool map is signed into the attestation. Beyond this many tools the rest
# fold into one entry, so a server cannot inflate the signed payload without bound.
_MAX_TOOL_DIGESTS = 500
TOOL_DIGEST_OVERFLOW_KEY = "tools:overflow"

_KEY_UNSAFE = re.compile(r"[^\x21-\x7e]|[%=]")


def _sha256(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _as_ijson(obj: Any) -> Any:
    """Read numbers the way an ECMAScript ``JSON.parse`` does: every number is an
    IEEE 754 double. Integers outside the safe range become floats, so the canonical
    bytes match what a JS verifier computes from the same ``tools/list`` response."""
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, int):
        return obj if -_MAX_SAFE_INT <= obj <= _MAX_SAFE_INT else float(obj)
    if isinstance(obj, dict):
        return {str(k): _as_ijson(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_as_ijson(v) for v in obj]
    return obj


def tool_digest_key(name: str) -> str:
    """``tool:<name>`` key for the digest map, in printable ASCII.

    Everything outside printable ASCII, plus ``%`` and ``=``, is percent-encoded as
    UTF-8 bytes. A key therefore cannot forge a line in the manifest fold, and the
    signed payload's keys canonicalize the same under any JSON canonicalizer. An
    overlong key is cut and suffixed with a hash of the full name.
    """
    enc = _KEY_UNSAFE.sub(
        lambda m: "".join(f"%{b:02X}" for b in m.group().encode("utf-8", "surrogatepass")),
        name,
    )
    if len(enc) > _MAX_TOOL_KEY_NAME:
        full = hashlib.sha256(name.encode("utf-8", "surrogatepass")).hexdigest()[:16]
        enc = enc[:96] + "~" + full
    return "tool:" + enc


def tool_definition_digest(tool: dict) -> str:
    """SHA-256 over the RFC 8785 canonical bytes of one tool's definition.

    Preimage: ``{"profile": MCP_TOOL_DIGEST_PROFILE, "tool": {...}}`` with ``tool``
    restricted to ``_TOOL_DIGEST_FIELDS``; a missing or null field is omitted.

    Never raises. A definition JCS cannot represent (NaN/Infinity, which Python's
    JSON parser accepts) gets a digest over sorted-key JSON under a distinct
    profile label: still stable for drift detection, but not reproducible by an
    independent verifier, and never equal to a portable digest.
    """
    body = {f: tool[f] for f in _TOOL_DIGEST_FIELDS if tool.get(f) is not None}
    try:
        canon = rfc8785.dumps(
            {"profile": MCP_TOOL_DIGEST_PROFILE, "tool": _as_ijson(body)})
        return "sha256:" + hashlib.sha256(canon).hexdigest()
    except Exception:
        pass
    try:
        return _sha256(MCP_TOOL_DIGEST_PROFILE + ".noncanonical\n" + json.dumps(
            body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str))
    except Exception:
        return _sha256(MCP_TOOL_DIGEST_PROFILE + ".unhashable")


def compute_tool_digests(tools: list | None) -> dict[str, str]:
    """``{"tool:<name>": "sha256:…"}`` for a live server's ``tools/list``.

    Keyed by tool name, not list position, so reordering is not drift. Tools that
    share a name fold into one entry over their sorted digests. Pure and
    deterministic; entries that are not objects are skipped, as in ``analyze_mcp``.
    """
    by_key: dict[str, list[str]] = {}
    for t in tools or []:
        if not isinstance(t, dict):
            continue
        key = tool_digest_key(str(t.get("name", "") or "unnamed"))
        by_key.setdefault(key, []).append(tool_definition_digest(t))

    digests = {
        key: ds[0] if len(ds) == 1 else _sha256(
            MCP_TOOL_DIGEST_PROFILE + ".duplicates\n" + "\n".join(sorted(ds)))
        for key, ds in by_key.items()
    }
    if len(digests) <= _MAX_TOOL_DIGESTS:
        return digests
    keys = sorted(digests)
    kept = {k: digests[k] for k in keys[:_MAX_TOOL_DIGESTS]}
    kept[TOOL_DIGEST_OVERFLOW_KEY] = _sha256(
        MCP_TOOL_DIGEST_PROFILE + ".overflow\n"
        + "\n".join(f"{k}={digests[k]}" for k in keys[_MAX_TOOL_DIGESTS:]))
    return kept


# ── live handshake (Streamable HTTP MCP) — fail-open ─────────────────────────

_MCP_TIMEOUT = 12.0


def _parse_jsonrpc_body(text: str) -> dict | None:
    """MCP Streamable-HTTP responses are either a JSON object or SSE-framed
    (`event: message\\ndata: {...}`). Return the first JSON-RPC result object."""
    import json
    text = (text or "").strip()
    if not text:
        return None
    if text[0] == "{":
        try:
            return json.loads(text)
        except ValueError:
            return None
    # SSE frames: collect `data:` lines.
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("data:"):
            payload = line[5:].strip()
            if payload.startswith("{"):
                try:
                    return json.loads(payload)
                except ValueError:
                    continue
    return None


_MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "User-Agent": "AgentAvow-MCP-Scanner",
}
_MCP_PROTOCOL_VERSION = "2025-06-18"


def _rpc(method: str, params: dict | None = None, rid: int | None = 1) -> dict:
    body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        body["id"] = rid
    if params is not None:
        body["params"] = params
    return body


class McpSession:
    """One Streamable-HTTP MCP session over a (rebind-safe) httpx client: ``initialize``
    + ``notifications/initialized``, then ``tools/list`` / ``tools/call`` on the same
    ``mcp-session-id``. Sends exactly the headers ``fetch_mcp_tools`` always sent — no
    credentials, nothing else. Every method is fail-open (returns a status / None /
    an error record) and never raises past the transport."""

    def __init__(self, client, url: str) -> None:
        self._client = client
        self._url = url
        self._headers = dict(_MCP_HEADERS)
        self.server_info: dict = {}
        self.session_id: str | None = None
        self.init_status: int | None = None
        self._rid = 1

    def _next_id(self) -> int:
        self._rid += 1
        return self._rid

    async def initialize(self) -> int:
        """Run the handshake; returns the HTTP status of ``initialize`` (0 on a transport
        error). ``server_info`` and ``session_id`` are set on success."""
        try:
            init = await self._client.post(self._url, headers=self._headers, json=_rpc(
                "initialize",
                {
                    "protocolVersion": _MCP_PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "AgentAvow", "version": "1.0"},
                },
            ))
        except Exception:
            self.init_status = 0
            return 0
        self.init_status = init.status_code
        if init.status_code >= 400:
            return init.status_code
        session = init.headers.get("mcp-session-id") or init.headers.get("Mcp-Session-Id")
        init_doc = _parse_jsonrpc_body(init.text)
        self.server_info = ((init_doc or {}).get("result") or {}).get("serverInfo") or {}
        if session:
            self.session_id = session
            self._headers["mcp-session-id"] = session
        # notifications/initialized (no id — a notification)
        try:
            await self._client.post(
                self._url, headers=self._headers,
                json=_rpc("notifications/initialized", {}, rid=None))
        except Exception:
            pass
        return init.status_code

    async def list(self, method: str, key: str) -> list:
        try:
            resp = await self._client.post(
                self._url, headers=self._headers, json=_rpc(method, {}, rid=2))
            if resp.status_code >= 400:
                return []
            doc = _parse_jsonrpc_body(resp.text)
            return ((doc or {}).get("result") or {}).get(key) or []
        except Exception:
            return []

    async def call_tool(self, name: str, arguments: dict, *, timeout: float) -> dict:
        """One ``tools/call``. Returns ``{ok, is_error, result, error, status}`` — ``ok``
        is "a JSON-RPC result arrived"; ``is_error`` is the MCP ``isError`` flag;
        ``error`` is ``call_timeout`` / ``http_<status>`` / ``rpc_error: <msg>`` /
        ``transport_error: <class>``. Never raises."""
        import asyncio
        out: dict = {"ok": False, "is_error": False, "result": None, "error": None,
                     "status": None}
        try:
            resp = await asyncio.wait_for(
                self._client.post(
                    self._url, headers=self._headers, timeout=timeout,
                    json=_rpc("tools/call", {"name": name, "arguments": arguments},
                              rid=self._next_id()),
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            out["error"] = "call_timeout"
            return out
        except Exception as exc:  # noqa: BLE001 — transport errors are observations
            msg = str(exc.__class__.__name__)
            out["error"] = "call_timeout" if "Timeout" in msg else f"transport_error: {msg}"
            return out
        out["status"] = resp.status_code
        if resp.status_code >= 400:
            out["error"] = f"http_{resp.status_code}"
            return out
        doc = _parse_jsonrpc_body(resp.text)
        if not isinstance(doc, dict):
            out["error"] = "rpc_error: unparseable response"
            return out
        if isinstance(doc.get("error"), dict):
            msg = str(doc["error"].get("message") or doc["error"].get("code") or "error")
            out["error"] = f"rpc_error: {msg[:160]}"
            return out
        result = doc.get("result")
        out["ok"] = True
        out["result"] = result if isinstance(result, dict) else {}
        out["is_error"] = bool(isinstance(result, dict) and result.get("isError"))
        return out


def mcp_result_text(result: dict | None, limit: int = 65536) -> str:
    """The text an agent would see from a ``tools/call`` result: every ``content`` item
    of type ``text`` (``resource`` text included) plus ``structuredContent`` as JSON,
    capped at ``limit`` characters."""
    if not isinstance(result, dict):
        return ""
    parts: list[str] = []
    for item in result.get("content") or []:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("text"), str):
            parts.append(item["text"])
        res = item.get("resource")
        if isinstance(res, dict) and isinstance(res.get("text"), str):
            parts.append(res["text"])
    sc = result.get("structuredContent")
    if isinstance(sc, (dict, list)):
        try:
            parts.append(json.dumps(sc, ensure_ascii=False, default=str))
        except Exception:
            pass
    return "\n".join(parts)[:limit]


async def fetch_mcp_tools(endpoint_url: str) -> dict | None:
    """Handshake a Streamable-HTTP MCP server and return
    ``{"tools": [...], "resources": [...], "prompts": [...], "server_info": {...}}``.
    Fail-open: any SSRF-guard/transport/protocol error returns None so the caller
    can surface a clean error instead of a wrong grade. Never raises.
    """

    from src.ssrf import validate_url_https

    try:
        url = validate_url_https(endpoint_url, field_name="endpoint")
    except Exception:
        return None

    try:
        # Rebind-safe client: pre-flight validation (validate_url_https above) and the
        # connect-time DNS lookup are otherwise two separate resolutions — a rebinding
        # host can pass the check then connect to an internal IP. The pinned transport
        # connects to the exact validated IP. (This endpoint is USER-supplied.)
        from src.ssrf import ssrf_safe_async_client
        async with ssrf_safe_async_client(timeout=_MCP_TIMEOUT, follow_redirects=False) as client:
            session = McpSession(client, url)
            if await session.initialize() >= 400 or session.init_status == 0:
                return None
            tools = await session.list("tools/list", "tools")
            resources = await session.list("resources/list", "resources")
            prompts = await session.list("prompts/list", "prompts")
            if not tools and not resources and not prompts:
                return None
            return {
                "tools": tools, "resources": resources, "prompts": prompts,
                "server_info": session.server_info,
            }
    except Exception:
        return None
