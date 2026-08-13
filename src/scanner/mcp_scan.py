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

import re
from dataclasses import dataclass, field
from typing import Any

# Capability keyword taxonomy — classify a tool from its name + description.
_CAP_PATTERNS: dict[str, re.Pattern] = {
    "exec": re.compile(
        r"\b(exec|execute|run|shell|command|spawn|subprocess|eval|bash|sh)\b", re.I),
    "fs_write": re.compile(
        r"\b(write|create|delete|remove|unlink|rename|move|mkdir|chmod|save|edit|patch)\b", re.I),
    "fs_read": re.compile(
        r"\b(read|open|cat|list|glob|stat|load|fetch file|get file)\b", re.I),
    "net": re.compile(
        r"\b(http|https|url|fetch|request|curl|download"
        r"|upload|webhook|post|api call|send)\b", re.I),
    "secrets": re.compile(
        r"\b(secret|token|password|credential|api[_ ]?key|env"
        r"|environment|\.env|ssh|aws|private key)\b", re.I),
    "db_write": re.compile(
        r"\b(insert|update|delete from|drop|truncate|mutation|write to|db write|sql)\b", re.I),
}
# Param names that are dangerous when freeform (no enum / constrained format).
_DANGEROUS_PARAM = re.compile(
    r"^(cmd|command|exec|script|code|eval|shell|path|file|filepath|filename|dir|"
    r"directory|url|uri|endpoint|query|sql|expression|template|payload|body)$", re.I
)


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
    blob = f"{name} {desc}"
    return {cap for cap, pat in _CAP_PATTERNS.items() if pat.search(blob)}


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
        findings, _pos, _sup = _scan_content(text, where)
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

        # 3. capability taxonomy
        caps = _classify_tool(tname, tdesc)
        caps_union |= caps
        for c in caps:
            cap_counts[c] = cap_counts.get(c, 0) + 1

        # 4. annotation truthfulness — readOnlyHint that lies
        ann = t.get("annotations") or {}
        if isinstance(ann, dict) and ann.get("readOnlyHint") is True:
            writes = caps & {"fs_write", "exec", "db_write"}
            if writes:
                result.findings.append(_finding(
                    "annotation_lie",
                    f"Tool '{tname}' claims readOnlyHint but looks like it "
                    f"{', '.join(sorted(writes))}",
                    "high", where,
                    "A read-only annotation contradicting the tool's caps"
                    " is a strong bad-actor signal.",
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
    mutate = bool(caps_union & {"fs_write", "exec", "db_write"})
    if private and external and (mutate or "exec" in caps_union):
        result.lethal_trifecta = True
        result.findings.append(_finding(
            "lethal_trifecta",
            "Lethal trifecta: private-data access + external comms + action/exec across the tools",
            "high", "server",
            "Split powerful capabilities across servers, or confirm the exfil-capable path.",
        ))

    result.capabilities = cap_counts
    result.blast_radius = compute_blast_radius(cap_counts, result.lethal_trifecta)
    return result


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

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": "AgentAvow-MCP-Scanner",
    }

    def _rpc(method: str, params: dict | None = None, rid: int | None = 1) -> dict:
        body: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if rid is not None:
            body["id"] = rid
        if params is not None:
            body["params"] = params
        return body

    try:
        # Rebind-safe client: pre-flight validation (validate_url_https above) and the
        # connect-time DNS lookup are otherwise two separate resolutions — a rebinding
        # host can pass the check then connect to an internal IP. The pinned transport
        # connects to the exact validated IP. (This endpoint is USER-supplied.)
        from src.ssrf import ssrf_safe_async_client
        async with ssrf_safe_async_client(timeout=_MCP_TIMEOUT, follow_redirects=False) as client:
            init = await client.post(url, headers=headers, json=_rpc(
                "initialize",
                {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "AgentAvow", "version": "1.0"},
                },
            ))
            if init.status_code >= 400:
                return None
            session = init.headers.get("mcp-session-id") or init.headers.get("Mcp-Session-Id")
            init_doc = _parse_jsonrpc_body(init.text)
            server_info = ((init_doc or {}).get("result") or {}).get("serverInfo") or {}
            sess_headers = dict(headers)
            if session:
                sess_headers["mcp-session-id"] = session

            # notifications/initialized (no id — a notification)
            try:
                await client.post(
                    url, headers=sess_headers,
                    json=_rpc("notifications/initialized", {}, rid=None))
            except Exception:
                pass

            async def _list(method: str, key: str) -> list:
                try:
                    resp = await client.post(
                        url, headers=sess_headers, json=_rpc(method, {}, rid=2))
                    if resp.status_code >= 400:
                        return []
                    doc = _parse_jsonrpc_body(resp.text)
                    return ((doc or {}).get("result") or {}).get(key) or []
                except Exception:
                    return []

            tools = await _list("tools/list", "tools")
            resources = await _list("resources/list", "resources")
            prompts = await _list("prompts/list", "prompts")
            if not tools and not resources and not prompts:
                return None
            return {
                "tools": tools, "resources": resources, "prompts": prompts,
                "server_info": server_info,
            }
    except Exception:
        return None
