"""Store-submission gate evaluator — pure + deterministic.

Maps AgentAvow's existing scan signals onto the *published* rejection criteria of
the two first-party directories:

* **Anthropic — Claude connectors** (claude.com/docs/connectors/building/submission):
  truthful tool safety annotations, read/write separation, OAuth 2.0, a working
  auth challenge (401 + ``WWW-Authenticate``), a privacy policy, and tool
  descriptions free of injected instructions.
* **OpenAI — apps directory** (chatgpt.com/apps): no data-exfiltration surface,
  constrained tool inputs, listing completeness.

Each gate is ``pass`` / ``fail`` / ``warn`` / ``unknown`` / ``na``. A *blocker*
that ``fail``s means "this will bounce at review"; a *warning* is "clean it up".
``directory_ready`` is true when no blocker fails.
"""
from __future__ import annotations

MIN_DIRECTORY_SCORE = 70

# Gate outcome constants
PASS, FAIL, WARN, UNKNOWN, NA = "pass", "fail", "warn", "unknown", "na"
BLOCKER, WARNING = "blocker", "warning"


def _cat(data: dict, name: str) -> int:
    return int((data.get("findings", {}).get("categories", {}) or {}).get(name, 0))


def _gate(gate_id, label, status, severity, detail, stores):
    return {
        "id": gate_id,
        "label": label,
        "status": status,
        "severity": severity,
        "detail": detail,
        "stores": stores,
    }


def evaluate_gates(data: dict, *, surface: str, auth: dict | None = None) -> dict:
    """Evaluate the normalized scan ``data`` (from ``_scan_result_to_dict``) against
    the store gates. ``surface`` is "mcp" (live endpoint) or "repo". ``auth`` is the
    best-effort auth-probe result for live MCP endpoints (or None)."""
    detail = data.get("surface_detail", {}) or {}
    meta = data.get("metadata", {}) or {}
    score = int(data.get("trust_score") or 0)
    blast = (detail.get("blast_radius") or {}).get("level")
    gates: list[dict] = []

    # --- Blockers -----------------------------------------------------------
    secrets = _cat(data, "secret")
    gates.append(_gate(
        "no_secrets", "No leaked secrets or credentials",
        PASS if secrets == 0 else FAIL, BLOCKER,
        "No secret material in the served surface." if secrets == 0
        else f"{secrets} secret finding(s) — reviewers reject connectors "
             "that ship credentials.",
        ["anthropic", "openai"],
    ))

    injection = _cat(data, "prompt_injection") + _cat(data, "hidden_unicode")
    gates.append(_gate(
        "no_injection", "No hidden instructions in tool metadata",
        PASS if injection == 0 else FAIL, BLOCKER,
        "Tool names/descriptions carry no injected instructions." if injection == 0
        else f"{injection} injection/hidden-unicode finding(s) in tool "
             "metadata — an automatic bounce.",
        ["anthropic", "openai"],
    ))

    lie = _cat(data, "annotation_lie")
    if surface == "mcp":
        gates.append(_gate(
            "truthful_annotations", "Tool safety annotations are truthful",
            PASS if lie == 0 else FAIL, BLOCKER,
            "readOnlyHint/destructiveHint match each tool's real capabilities." if lie == 0
            else f"{lie} tool(s) mark themselves read-only but can "
                 "write/exec — reviewers verify this.",
            ["anthropic"],
        ))

    lethal = bool(detail.get("lethal_trifecta"))
    if surface == "mcp":
        gates.append(_gate(
            "no_lethal_trifecta", "No lethal trifecta (private data + exfil + mutate)",
            FAIL if lethal else PASS, BLOCKER,
            "No single flow combines private-data access, external comms, and mutation."
            if not lethal else
            "Tools combine private-data access + external comms + mutation — "
            "the classic exfiltration surface.",
            ["anthropic", "openai"],
        ))

    gates.append(_gate(
        "trust_score", f"Trust score at or above {MIN_DIRECTORY_SCORE}",
        PASS if score >= MIN_DIRECTORY_SCORE else FAIL, BLOCKER,
        f"Signed trust score {score}/100." if score >= MIN_DIRECTORY_SCORE
        else f"Signed trust score {score}/100 — below the "
             f"{MIN_DIRECTORY_SCORE} bar reviewers expect.",
        ["anthropic", "openai"],
    ))

    # --- Warnings -----------------------------------------------------------
    schema = _cat(data, "schema_risk")
    if surface == "mcp":
        gates.append(_gate(
            "schema_hygiene", "Tool inputs are constrained",
            PASS if schema == 0 else WARN, WARNING,
            "Tool input schemas are typed and bounded." if schema == 0
            else f"{schema} tool(s) accept freeform / unbounded input "
                 "(additionalProperties, freeform command params).",
            ["openai"],
        ))

        # Read/write separation + safety hints on destructive tools.
        if blast in ("high", "critical"):
            gates.append(_gate(
                "destructive_hinted",
                "Destructive tools are separated and hinted",
                WARN if lie == 0 else FAIL, WARNING if lie == 0 else BLOCKER,
                f"High blast radius ({blast}) — keep read and write tools separate and hint every "
                "destructive one so the agent (and reviewer) can see it.",
                ["anthropic"],
            ))
        else:
            gates.append(_gate(
                "destructive_hinted",
                "Destructive tools are separated and hinted",
                PASS, WARNING,
                "No high-blast-radius tool surface detected.",
                ["anthropic"],
            ))

        # Auth challenge — best-effort probe (live endpoints only).
        if auth is None:
            auth_status, auth_detail = UNKNOWN, (
                "Couldn't probe auth metadata — confirm your OAuth 2.0 flow returns "
                "401 + WWW-Authenticate and publishes a .well-known discovery document."
            )
        elif auth.get("oauth_discovered") or auth.get("challenge"):
            auth_status, auth_detail = PASS, (
                "OAuth discovery / auth challenge detected."
                if auth.get("oauth_discovered")
                else "Endpoint issues an auth challenge (401 + WWW-Authenticate)."
            )
        elif auth.get("open"):
            auth_status, auth_detail = WARN, (
                "Endpoint answered tools/list with no auth. Public read-only servers can be fine, "
                "but connectors that touch user data must require OAuth 2.0."
            )
        else:
            auth_status, auth_detail = UNKNOWN, "Auth posture indeterminate — verify manually."
        gates.append(_gate(
            "auth_declared", "Authentication is declared (OAuth 2.0)",
            auth_status, WARNING, auth_detail, ["anthropic"],
        ))

    complete = bool(meta.get("has_readme")) and bool(meta.get("has_license"))
    gates.append(_gate(
        "listing_complete", "Listing basics present (README + license)",
        PASS if complete else WARN, WARNING,
        "README and license present." if complete
        else "Missing a README and/or license — listings need both to pass review.",
        ["anthropic", "openai"],
    ))

    blockers_failed = [g for g in gates if g["severity"] == BLOCKER and g["status"] == FAIL]
    warnings = [g for g in gates if g["severity"] == WARNING and g["status"] in (WARN, UNKNOWN)]
    ready = not blockers_failed

    return {
        "directory_ready": ready,
        "headline": "Directory-Ready" if ready else "Needs changes before you submit",
        "gates": gates,
        "summary": {
            "blockers_total": sum(1 for g in gates if g["severity"] == BLOCKER),
            "blockers_failed": len(blockers_failed),
            "warnings": len(warnings),
        },
    }
