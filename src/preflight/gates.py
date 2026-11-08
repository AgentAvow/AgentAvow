"""Store-submission gate evaluator — pure + deterministic.

Maps AgentAvow's scan signals onto the published review rules of the two first-party
directories. Every gate cites its sources (``src.preflight.rules.SOURCES``) and carries
a ``basis``:

* ``documented`` — the store's own docs say it.
* ``observed``   — the Claude plugin directory does it but hasn't documented it.
* ``agentavow``  — AgentAvow's own safety signal. Shown, never decides readiness.

Status is ``pass`` / ``fail`` / ``warn`` / ``unknown`` / ``na``. Severity follows the
stores' own outcomes: ``blocker`` (the submission bounces), ``hold`` (it goes to a
human reviewer first; Claude plugin directory), ``warning`` (clean it up).
``directory_ready`` is true when no documented or observed blocker fails.

Rules last re-read against the sources: ``rules.RULES_CHECKED``.
"""
from __future__ import annotations

from src.preflight.rules import RULES_CHECKED, cite

MIN_DIRECTORY_SCORE = 70   # AgentAvow's own bar; not a store rule
MAX_TOOL_NAME = 64         # Claude connector checklist

# Gate outcome constants
PASS, FAIL, WARN, UNKNOWN, NA = "pass", "fail", "warn", "unknown", "na"
BLOCKER, HOLD, WARNING = "blocker", "hold", "warning"
BOTH = ["anthropic", "openai"]


def _cat(data: dict, name: str) -> int:
    return int((data.get("findings", {}).get("categories", {}) or {}).get(name, 0))


def _cat_sev(data: dict, name: str, severities: tuple[str, ...]) -> int:
    """Findings of category ``name`` at the given severities, from the listed items."""
    items = (data.get("findings", {}) or {}).get("items") or []
    return sum(1 for i in items if isinstance(i, dict) and i.get("category") == name
               and str(i.get("severity") or "").lower() in severities)


def _gate(gate_id, label, status, severity, detail, stores, *sources,
          basis="documented", group="connector"):
    return {
        "id": gate_id,
        "label": label,
        "status": status,
        "severity": severity,
        "detail": detail,
        "stores": stores,
        "basis": basis,
        "sources": cite(*sources),
        "group": group,
    }


def _names(rows: list[dict], n: int = 3) -> str:
    names = [r.get("name") or "?" for r in rows[:n]]
    more = len(rows) - n
    return ", ".join(names) + (f" and {more} more" if more > 0 else "")


def _tool_gates(facts: dict | None, *, readable: bool, why_unread: str) -> list[dict]:
    """Per-tool rules from ``surface_detail.review_facts`` (see ``tool_review``)."""
    defs = [
        ("tool_titles", "Every tool has a title", ["anthropic"],
         ("claude_connector_checklist", "claude_connector_submit")),
        ("tool_hints_claude", "Every tool declares readOnlyHint or destructiveHint",
         ["anthropic"], ("claude_connector_checklist", "claude_connector_submit")),
        ("tool_hints_openai", "Every tool sets readOnlyHint, destructiveHint and "
         "openWorldHint explicitly", ["openai"],
         ("openai_guidelines", "openai_submission_errors")),
        ("tool_name_length", f"Tool names are {MAX_TOOL_NAME} characters or fewer",
         ["anthropic"], ("claude_connector_checklist",)),
        ("tool_descriptions", "Every tool has a description", ["openai"],
         ("openai_guidelines",)),
        ("tool_names_unique", "Tool names are unique", ["openai"], ("openai_guidelines",)),
        ("read_write_separated", "Read and write operations are separate tools",
         ["anthropic"], ("claude_connector_checklist", "openai_guidelines")),
    ]
    if not readable or not isinstance(facts, dict):
        return [_gate(i, lbl, UNKNOWN, BLOCKER, why_unread, st, *src)
                for i, lbl, st, src in defs]

    tools = [t for t in facts.get("tools") or [] if isinstance(t, dict)]
    out: list[dict] = []
    no_title = [t for t in tools if not t.get("has_title")]
    out.append(_gate(
        "tool_titles", defs[0][1], FAIL if no_title else PASS, BLOCKER,
        f"{len(no_title)} tool(s) have no title: {_names(no_title)}. The portal flags "
        "these; add a title on the server." if no_title
        else f"All {len(tools)} tools have a title.", ["anthropic"], *defs[0][3]))

    no_rd = [t for t in tools if not ({"readOnlyHint", "destructiveHint"}
                                      & set((t.get("hints") or {}).keys()))]
    out.append(_gate(
        "tool_hints_claude", defs[1][1], FAIL if no_rd else PASS, BLOCKER,
        f"{len(no_rd)} tool(s) declare neither: {_names(no_rd)}. Set readOnlyHint: true on "
        "read-only tools and destructiveHint: true on tools that modify or delete data; "
        "Claude uses them for auto-permissions." if no_rd
        else "Every tool declares readOnlyHint or destructiveHint.",
        ["anthropic"], *defs[1][3]))

    partial = [t for t in tools if len(t.get("hints") or {}) < 3]
    out.append(_gate(
        "tool_hints_openai", defs[2][1], FAIL if partial else PASS, BLOCKER,
        f"{len(partial)} tool(s) leave a hint unset: {_names(partial)} "
        "(annotations_required). An unset hint is not the same as false." if partial
        else "Every tool sets all three hints to true or false.", ["openai"], *defs[2][3]))

    long_names = [t for t in tools if int(t.get("name_length") or 0) > MAX_TOOL_NAME]
    out.append(_gate(
        "tool_name_length", defs[3][1], FAIL if long_names else PASS, BLOCKER,
        f"Too long: {_names(long_names)}." if long_names
        else "Every tool name fits.", ["anthropic"], *defs[3][3]))

    no_desc = [t for t in tools if not t.get("has_description")]
    out.append(_gate(
        "tool_descriptions", defs[4][1], FAIL if no_desc else PASS, BLOCKER,
        f"Empty description: {_names(no_desc)}." if no_desc
        else "Every tool has a non-empty description.", ["openai"], *defs[4][3]))

    dupes = list(facts.get("duplicate_names") or [])
    out.append(_gate(
        "tool_names_unique", defs[5][1], FAIL if dupes else PASS, BLOCKER,
        f"Listed more than once: {', '.join(dupes[:3])}." if dupes
        else "No tool name repeats.", ["openai"], *defs[5][3]))

    mixed = [t for t in tools if t.get("mixed_methods")
             or (t.get("freeform_method") and t.get("custom_query"))]
    loose = [t for t in tools if t.get("freeform_method") and t not in mixed]
    if mixed:
        out.append(_gate(
            "read_write_separated", defs[6][1], FAIL, BLOCKER,
            f"{_names(mixed)} take both safe (GET/HEAD/OPTIONS) and unsafe (POST/PUT/PATCH/"
            "DELETE) methods in one tool. Split each into a read-only tool and write tools; "
            "documenting it in the description isn't enough.", ["anthropic"], *defs[6][3]))
    elif loose:
        out.append(_gate(
            "read_write_separated", defs[6][1], WARN, WARNING,
            f"{_names(loose)} take a free-text method parameter. If it is an HTTP method, "
            "split read and write into separate tools.", ["anthropic"], *defs[6][3]))
    else:
        out.append(_gate("read_write_separated", defs[6][1], PASS, BLOCKER,
                         "No tool mixes read and write HTTP methods.", ["anthropic"],
                         *defs[6][3]))

    no_ref = [t for t in tools if t.get("custom_query") and not t.get("api_reference")]
    if any(t.get("custom_query") for t in tools):
        out.append(_gate(
            "custom_query_api_docs", "Custom query tools name their API",
            WARN if no_ref else PASS, WARNING,
            f"{_names(no_ref)} take a caller-built endpoint, query or body, and the "
            "description links no docs and names no API. Name the target API or link its "
            "docs (e.g. \"Queries the Slack Web API, see https://api.slack.com/methods\")."
            if no_ref else "Every custom query tool names its API or links its docs.",
            ["anthropic"], "claude_connector_checklist"))

    ctx = [t for t in tools if t.get("context_params")]
    if ctx:
        out.append(_gate(
            "no_conversation_inputs", "Tools don't ask for the conversation",
            WARN, WARNING,
            f"{_names(ctx)} take {', '.join(ctx[0]['context_params'])}. Both stores bar "
            "requesting chat history or accumulated context; take only the task's inputs.",
            BOTH, "openai_guidelines", "claude_connector_checklist"))
    loc = [t for t in tools if t.get("location_params")]
    if loc:
        out.append(_gate(
            "no_precise_location", "Tools don't ask for precise location", WARN, WARNING,
            f"{_names(loc)} take {', '.join(loc[0]['location_params'])}. OpenAI asks tools "
            "to use the coarse location ChatGPT shares instead of GPS coordinates or "
            "addresses.", ["openai"], "openai_guidelines"))

    ui = [t for t in tools if t.get("links_ui")]
    if ui:
        out.append(_gate(
            "ui_csp", "UI resources declare a content security policy", UNKNOWN, BLOCKER,
            f"{_names(ui)} render UI. Declare connectDomains / resourceDomains (and "
            "frameDomains only if needed) on the UI resource; review checks the policy "
            "against what the UI loads. Not read by this check.", ["openai"],
            "openai_app_review", "openai_ui_csp"))
    return out


def _auth_gates(auth: dict | None) -> list[dict]:
    """Claude's sign-in discovery steps (see ``auth_probe``)."""
    src = ("claude_connector_auth",)
    if auth is None:
        return [_gate("auth_declared", "Authentication fits the data", UNKNOWN, WARNING,
                      "Couldn't probe the endpoint's auth. OAuth 2.0 is needed if tools act on "
                      "a user's account; no auth is fine for public data.",
                      ["anthropic"], "claude_connector_submit", *src)]
    protected = bool(auth.get("challenge") or auth.get("prm_found"))
    if not protected:
        return [_gate("auth_declared", "Authentication fits the data", WARN, WARNING,
                      "The server answered without sign-in and serves no OAuth metadata. "
                      "That's fine for public data; tools that act on a user's account need "
                      "OAuth 2.0.", ["anthropic"], "claude_connector_submit", *src)]

    out = [_gate("auth_declared", "Authentication fits the data", PASS, WARNING,
                 "OAuth sign-in detected.", ["anthropic"], "claude_connector_submit", *src)]
    if auth.get("challenge") and auth.get("challenge_points_to_metadata"):
        st, sev, msg = PASS, BLOCKER, ("401 with WWW-Authenticate: Bearer resource_metadata="
                                       "… — Claude can find your sign-in.")
    elif auth.get("challenge") and auth.get("prm_found"):
        st, sev, msg = WARN, WARNING, (
            "Your 401 has no resource_metadata pointer; Claude falls back to probing "
            "/.well-known/oauth-protected-resource, which only works where your platform "
            "serves /.well-known paths. Add the pointer.")
    elif auth.get("challenge"):
        st, sev, msg = FAIL, BLOCKER, (
            "401 without a resource_metadata pointer, and no protected resource metadata at "
            "the well-known paths. Claude can't find your authorization server (\"Couldn't "
            "reach the MCP server\").")
    else:
        st, sev, msg = PASS, WARNING, (
            "Starts without sign-in and publishes OAuth metadata (lazy auth). Answer each "
            "protected call with a 401 — Claude ignores WWW-Authenticate on a 200.")
    out.append(_gate("auth_discovery", "Sign-in is discoverable (401 + resource_metadata)",
                     st, sev, msg, ["anthropic"], *src))

    if auth.get("prm_found"):
        rm = auth.get("resource_matches")
        out.append(_gate(
            "auth_resource_match", "Protected resource `resource` equals the server URL",
            PASS if rm else FAIL, BLOCKER,
            "resource matches the URL exactly." if rm else
            "The metadata's resource field must equal the server URL as users enter it, "
            "path included.", ["anthropic"], *src))
        if not auth.get("authorization_server"):
            out.append(_gate("auth_server_metadata", "Authorization server metadata "
                             "reachable", FAIL, BLOCKER, "authorization_servers is empty.",
                             ["anthropic"], *src))
        else:
            found = bool(auth.get("as_metadata_found"))
            out.append(_gate(
                "auth_server_metadata", "Authorization server metadata reachable",
                PASS if found else FAIL, BLOCKER,
                f"Found for {auth['authorization_server']} (first entry; Claude uses only "
                "that one)." if found else
                f"No RFC 8414 or OpenID discovery document for {auth['authorization_server']}"
                ". It must also be reachable from Anthropic's egress range.",
                ["anthropic"], *src))
            if found:
                out.append(_gate(
                    "auth_pkce_s256", "Authorization server advertises S256 PKCE",
                    PASS if auth.get("pkce_s256") else WARN, WARNING,
                    "code_challenge_methods_supported includes S256." if auth.get("pkce_s256")
                    else "S256 isn't in code_challenge_methods_supported. Claude always sends "
                    "S256 PKCE, and the MCP spec requires advertising it.",
                    ["anthropic"], *src))
                reg = auth.get("dcr") or auth.get("cimd")
                out.append(_gate(
                    "auth_client_registration", "Claude can register as a client",
                    PASS if reg else WARN, WARNING,
                    ("CIMD supported." if auth.get("cimd") else "DCR registration_endpoint "
                     "found.") if reg else
                    "No registration_endpoint (DCR) and no CIMD support. Then Anthropic has to "
                    "hold an OAuth client you enter in the portal.", ["anthropic"], *src))
    return out


def _safety_gates(data: dict, surface: str) -> list[dict]:
    """AgentAvow's own signals. Never decide readiness."""
    detail = data.get("surface_detail", {}) or {}
    score = int(data.get("trust_score") or 0)
    out = [_gate(
        "trust_score", f"AgentAvow trust score at or above {MIN_DIRECTORY_SCORE}",
        PASS if score >= MIN_DIRECTORY_SCORE else WARN, WARNING,
        f"Signed trust score {score}/100. This is AgentAvow's bar, not a store rule.",
        [], basis="agentavow", group="safety")]
    if surface == "mcp":
        lethal = bool(detail.get("lethal_trifecta"))
        out.append(_gate(
            "no_lethal_trifecta", "No lethal trifecta (private data + external comms + "
            "mutation)", WARN if lethal else PASS, WARNING,
            "Tools combine private-data access, external comms and mutation: the classic "
            "exfiltration surface. Not a named store rule; reviewers do check for undisclosed "
            "data transfer." if lethal else "No single flow combines all three.",
            [], "openai_guidelines", basis="agentavow", group="safety"))
        schema = _cat(data, "schema_risk")
        out.append(_gate(
            "schema_hygiene", "Tool inputs are constrained", PASS if schema == 0 else WARN,
            WARNING,
            "Tool input schemas are typed and bounded." if schema == 0
            else f"{schema} tool(s) accept freeform or unbounded input (additionalProperties, "
                 "free-text commands). Related to OpenAI's minimal-input and no-generic-"
                 "executor rules, not a direct rejection rule.",
            [], "openai_guidelines", basis="agentavow", group="safety"))
    return out


def evaluate_gates(data: dict | None, *, surface: str, auth: dict | None = None,
                   plugin: dict | None = None, scanned: bool = True) -> dict:
    """Evaluate the normalized scan ``data`` (from ``_scan_result_to_dict``).

    ``surface`` is "mcp" (live endpoint) or "repo". ``auth`` is the auth-probe result
    for live endpoints (or None). ``plugin`` is ``plugin_check.check_plugin_repo``'s
    result for repos. ``scanned`` is False when a live server needs sign-in before it
    lists tools: only the auth checks run then.
    """
    data = data or {}
    detail = data.get("surface_detail", {}) or {}
    meta = data.get("metadata", {}) or {}
    gates: list[dict] = []

    # --- Content rules both stores state --------------------------------------
    if scanned:
        secrets = _cat(data, "secret")
        gates.append(_gate(
            "no_secrets", "No leaked secrets or credentials",
            PASS if secrets == 0 else FAIL, BLOCKER,
            "No secret material found." if secrets == 0
            else f"{secrets} secret finding(s). Credentials can't ship in a plugin's files, "
                 "and tool output must not carry tokens, keys or passwords.",
            BOTH, "claude_plugin_checklist", "openai_app_review",
            group="plugin" if surface == "repo" else "connector"))

        injection = _cat(data, "prompt_injection") + _cat(data, "hidden_unicode")
        gates.append(_gate(
            "no_injection", "No hidden or injected instructions",
            PASS if injection == 0 else FAIL, BLOCKER,
            "Names and descriptions carry no instructions to the model." if injection == 0
            else f"{injection} injection / hidden-unicode finding(s). Both stores reject "
                 "metadata that steers the model, including encoded or obfuscated text.",
            BOTH, "claude_connector_checklist", "openai_guidelines"))

    if surface == "mcp":
        gates.append(_gate(
            "remote_https", "Remote server on a public HTTPS URL", PASS, BLOCKER,
            "Reached over https:// on a public host.", BOTH,
            "claude_connector_submit", "openai_app_review"))
        why = ("This server needs sign-in before it lists tools, so we couldn't read them. "
               "Check this one in MCP Inspector after signing in." if not scanned
               else "This scan predates per-tool checks; re-run with a fresh scan.")
        facts = detail.get("review_facts")
        gates += _tool_gates(facts, readable=scanned and isinstance(facts, dict),
                             why_unread=why)

        if scanned:
            lie = _cat(data, "annotation_lie")
            # Kenne 2026-10-08: only a lie backed by evidence (HIGH: a freeform
            # command/script parameter on a read-only tool, or the sandbox watching it
            # write) blocks. A MEDIUM one is inferred from description wording alone.
            lie_high = _cat_sev(data, "annotation_lie", ("critical", "high"))
            lie_soft = max(lie - lie_high, 0)
            src = ("claude_connector_checklist", "openai_app_review")
            if lie_high:
                gates.append(_gate(
                    "truthful_annotations", "Tool safety annotations are truthful", FAIL,
                    BLOCKER, f"{lie_high} tool(s) mark themselves read-only but can write or "
                    "execute (a command/script parameter, or observed in the sandbox). Wrong "
                    "hints are a common rejection on both stores.", BOTH, *src))
            elif lie_soft:
                gates.append(_gate(
                    "truthful_annotations", "Tool safety annotations are truthful", WARN,
                    WARNING, f"{lie_soft} read-only tool(s) have descriptions that read as "
                    "writing or executing something. Check the wording or the annotation; "
                    "this alone is not a predicted rejection.", BOTH, *src))
            else:
                gates.append(_gate(
                    "truthful_annotations", "Tool safety annotations are truthful", PASS,
                    BLOCKER, "No read-only hint contradicts what the tool can do.",
                    BOTH, *src))

            blast = (detail.get("blast_radius") or {}).get("level")
            tools = [t for t in ((facts or {}).get("tools") or []) if isinstance(t, dict)]
            any_destructive = any((t.get("hints") or {}).get("destructiveHint") is True
                                  for t in tools)
            if blast in ("high", "critical") and not any_destructive:
                gates.append(_gate(
                    "destructive_hinted", "Tools that modify or delete data say so",
                    WARN, WARNING,
                    f"High blast radius ({blast}), yet no tool sets destructiveHint: true. "
                    "Set it on every tool that modifies or deletes data, so Claude prompts "
                    "before each call.", BOTH, "claude_connector_checklist",
                    "openai_guidelines"))

        gates += _auth_gates(auth)

    if surface == "repo":
        if plugin and plugin.get("found"):
            gates += list(plugin.get("gates") or [])
        else:
            gates += list((plugin or {}).get("gates") or [])
            if plugin is not None and plugin.get("found") is False:
                gates.append(_gate(
                    "plugin_bundle", "Claude plugin bundle", NA, WARNING,
                    "No .claude-plugin/plugin.json in this repo, so plugin checks don't apply. "
                    "To check an MCP connector, run preflight on its live https:// URL.",
                    ["anthropic"], "claude_plugin_checklist", group="plugin"))
            elif plugin is not None and plugin.get("found") is None:
                gates.append(_gate(
                    "plugin_bundle", "Claude plugin bundle", UNKNOWN, WARNING,
                    "Couldn't read the repo's file list to run the plugin checks. Retry "
                    "shortly.", ["anthropic"], "claude_plugin_checklist", group="plugin"))
            if scanned:
                complete = bool(meta.get("has_readme")) and bool(meta.get("has_license"))
                gates.append(_gate(
                    "listing_complete", "README and license present",
                    PASS if complete else WARN, WARNING,
                    "README and license present." if complete
                    else "Missing a README and/or license. Required for a Claude plugin; "
                         "good practice otherwise.", [], "claude_plugin_checklist",
                    basis="agentavow", group="safety"))

    if scanned:
        gates += _safety_gates(data, surface)

    def _decides(g):
        return g["basis"] in ("documented", "observed")

    blockers_failed = [g for g in gates if g["severity"] == BLOCKER and g["status"] == FAIL
                       and _decides(g)]
    holds = [g for g in gates if g["severity"] == HOLD and g["status"] == FAIL]
    warnings = [g for g in gates if g["severity"] == WARNING and g["status"] in (WARN, UNKNOWN)]
    unknown_blockers = [g for g in gates if g["severity"] == BLOCKER and g["status"] == UNKNOWN]
    ready = not blockers_failed and scanned
    if blockers_failed:
        headline = "Needs changes before you submit"
    elif not scanned:
        headline = "Sign-in needed to check the tools"
    elif unknown_blockers:
        n = len(unknown_blockers)
        headline = f"Directory-Ready, {n} item{'' if n == 1 else 's'} to confirm by hand"
    else:
        headline = "Directory-Ready"

    return {
        "directory_ready": ready,
        "headline": headline,
        "gates": gates,
        "rules_checked": RULES_CHECKED,
        "summary": {
            "blockers_total": sum(1 for g in gates if g["severity"] == BLOCKER),
            "blockers_failed": len(blockers_failed),
            "blockers_unknown": len(unknown_blockers),
            "holds": len(holds),
            "warnings": len(warnings),
        },
    }
