"""Tests for the pure Connector Preflight gate evaluator (rules checked 2026-11-07)."""
from __future__ import annotations

from src.preflight.gates import MIN_DIRECTORY_SCORE, evaluate_gates
from src.preflight.rules import RULES_CHECKED, SOURCES


def _tool(name="get_item", *, title=True, desc=True, hints=None, **extra):
    row = {"name": name, "name_length": len(name), "has_title": title,
           "has_description": desc,
           "hints": {"readOnlyHint": True, "destructiveHint": False, "openWorldHint": False}
           if hints is None else hints,
           "mixed_methods": False, "freeform_method": False, "custom_query": False,
           "api_reference": False, "links_ui": False}
    row.update(extra)
    return row


def _mcp_data(*, score=92, categories=None, lethal=False, blast="low",
              has_readme=True, has_license=True, certified=False, tools=None, dupes=None):
    tools = [_tool()] if tools is None else tools
    return {
        "trust_score": score,
        "trust_tier": "trusted",  # the API value (lowercase), as /public/scan emits it
        "grade": "A",
        "findings": {"categories": categories or {}, "items": []},
        "surface_detail": {"surface": "mcp", "lethal_trifecta": lethal,
                           "blast_radius": {"level": blast},
                           "review_facts": {"tool_count": len(tools),
                                            "duplicate_names": dupes or [],
                                            "tools": tools}},
        "metadata": {"has_readme": has_readme, "has_license": has_license,
                     "is_mcp_server": True},
        "certified": {"eligible": certified},
        "scanned_at": "2026-08-18T00:00:00+00:00",
    }


_OAUTH_OK = {"challenge": True, "challenge_points_to_metadata": True, "prm_found": True,
             "resource_matches": True, "authorization_server": "https://auth.example.com",
             "as_metadata_found": True, "pkce_s256": True, "dcr": True, "cimd": False,
             "oauth_discovered": True, "open": False}


def _gate(report, gate_id):
    return next(g for g in report["gates"] if g["id"] == gate_id)


def _ids(report):
    return {g["id"] for g in report["gates"]}


def test_clean_mcp_is_directory_ready():
    r = evaluate_gates(_mcp_data(), surface="mcp", auth=_OAUTH_OK)
    assert r["directory_ready"] is True
    assert r["headline"] == "Directory-Ready"
    assert _gate(r, "no_secrets")["status"] == "pass"
    assert _gate(r, "auth_declared")["status"] == "pass"
    assert _gate(r, "auth_discovery")["status"] == "pass"
    assert r["summary"]["blockers_failed"] == 0
    assert r["rules_checked"] == RULES_CHECKED


def test_every_gate_cites_a_known_source_or_is_agentavow():
    urls = {s["url"] for s in SOURCES.values()}
    r = evaluate_gates(_mcp_data(lethal=True, blast="critical"), surface="mcp",
                       auth=_OAUTH_OK)
    for g in r["gates"]:
        assert g["basis"] in ("documented", "observed", "agentavow")
        if g["basis"] != "agentavow":
            assert g["sources"], g["id"]
        assert all(s["url"] in urls for s in g["sources"])


def test_secret_finding_blocks():
    r = evaluate_gates(_mcp_data(categories={"secret": 2}), surface="mcp", auth=None)
    assert r["directory_ready"] is False
    g = _gate(r, "no_secrets")
    assert g["status"] == "fail" and g["severity"] == "blocker"


def test_injection_blocks():
    r = evaluate_gates(_mcp_data(categories={"prompt_injection": 1}), surface="mcp", auth=None)
    assert r["directory_ready"] is False
    assert _gate(r, "no_injection")["status"] == "fail"


def _with_items(data, *items):
    data["findings"]["items"] = list(items)
    return data


def test_annotation_lie_with_evidence_blocks_on_both_stores():
    """HIGH = evidence (a command/script param on a read-only tool, or the sandbox
    watched it write): a predicted rejection. OpenAI names wrong hints as a common
    rejection too, so the gate now carries both stores."""
    d = _with_items(_mcp_data(categories={"annotation_lie": 1}),
                    {"category": "annotation_lie", "severity": "high"})
    r = evaluate_gates(d, surface="mcp", auth=None)
    g = _gate(r, "truthful_annotations")
    assert g["status"] == "fail" and g["severity"] == "blocker"
    assert g["stores"] == ["anthropic", "openai"]
    assert r["directory_ready"] is False


def test_annotation_lie_from_wording_only_warns():
    """MEDIUM = inferred from description wording alone: a warning, not a blocker
    (Kenne, 2026-10-08)."""
    d = _with_items(_mcp_data(categories={"annotation_lie": 2}),
                    {"category": "annotation_lie", "severity": "medium"},
                    {"category": "annotation_lie", "severity": "medium"})
    r = evaluate_gates(d, surface="mcp", auth=None)
    g = _gate(r, "truthful_annotations")
    assert g["status"] == "warn" and g["severity"] == "warning"
    assert "2 read-only tool(s)" in g["detail"]
    assert r["directory_ready"] is True
    assert r["summary"]["warnings"] >= 1


def test_soft_annotation_lie_on_high_blast_no_longer_blocks():
    """Old bug: destructive_hinted turned ANY annotation_lie into a blocker on a high
    blast radius, undoing the MEDIUM-only-warns rule."""
    d = _with_items(_mcp_data(categories={"annotation_lie": 1}, blast="critical"),
                    {"category": "annotation_lie", "severity": "medium"})
    r = evaluate_gates(d, surface="mcp", auth=_OAUTH_OK)
    assert r["directory_ready"] is True
    assert all(not (g["status"] == "fail" and g["severity"] == "blocker")
               for g in r["gates"])


def test_annotation_lie_mixed_blocks_on_the_high_one():
    d = _with_items(_mcp_data(categories={"annotation_lie": 2}),
                    {"category": "annotation_lie", "severity": "high"},
                    {"category": "annotation_lie", "severity": "medium"})
    g = _gate(evaluate_gates(d, surface="mcp", auth=None), "truthful_annotations")
    assert g["status"] == "fail" and g["detail"].startswith("1 tool(s)")


def test_lethal_trifecta_is_agentavow_warning_not_store_blocker():
    """No store names the lethal trifecta; it was a blocker before 2026-11-07."""
    r = evaluate_gates(_mcp_data(lethal=True), surface="mcp", auth=None)
    g = _gate(r, "no_lethal_trifecta")
    assert g["status"] == "warn" and g["severity"] == "warning"
    assert g["basis"] == "agentavow" and g["stores"] == []
    assert r["directory_ready"] is True


def test_low_score_is_agentavow_warning_not_store_blocker():
    """No store has a minimum score; the 70 bar is ours."""
    r = evaluate_gates(_mcp_data(score=MIN_DIRECTORY_SCORE - 1), surface="mcp", auth=None)
    g = _gate(r, "trust_score")
    assert g["status"] == "warn" and g["basis"] == "agentavow"
    assert "not a store rule" in g["detail"]
    assert r["directory_ready"] is True


def test_agentavow_fail_never_decides_readiness():
    """Even if an agentavow gate were a failed blocker, readiness ignores it."""
    r = evaluate_gates(_mcp_data(), surface="mcp", auth=_OAUTH_OK)
    assert all(g["severity"] == "warning" for g in r["gates"] if g["basis"] == "agentavow")


def test_missing_title_blocks_claude():
    r = evaluate_gates(_mcp_data(tools=[_tool(title=False)]), surface="mcp", auth=_OAUTH_OK)
    g = _gate(r, "tool_titles")
    assert g["status"] == "fail" and g["stores"] == ["anthropic"]
    assert r["directory_ready"] is False


def test_no_read_or_destructive_hint_blocks_claude():
    r = evaluate_gates(_mcp_data(tools=[_tool(hints={"openWorldHint": True})]),
                       surface="mcp", auth=_OAUTH_OK)
    assert _gate(r, "tool_hints_claude")["status"] == "fail"
    assert _gate(r, "tool_hints_openai")["status"] == "fail"


def test_openai_needs_all_three_hints():
    t = _tool(hints={"readOnlyHint": True, "destructiveHint": False})
    r = evaluate_gates(_mcp_data(tools=[t]), surface="mcp", auth=_OAUTH_OK)
    assert _gate(r, "tool_hints_claude")["status"] == "pass"
    g = _gate(r, "tool_hints_openai")
    assert g["status"] == "fail" and g["stores"] == ["openai"]
    assert "annotations_required" in g["detail"]


def test_tool_name_over_64_blocks():
    long = "x" * 65
    r = evaluate_gates(_mcp_data(tools=[_tool(long)]), surface="mcp", auth=_OAUTH_OK)
    assert _gate(r, "tool_name_length")["status"] == "fail"
    ok = evaluate_gates(_mcp_data(tools=[_tool("x" * 64)]), surface="mcp", auth=_OAUTH_OK)
    assert _gate(ok, "tool_name_length")["status"] == "pass"


def test_empty_description_and_duplicate_names_block_openai():
    r = evaluate_gates(_mcp_data(tools=[_tool(desc=False)], dupes=["get_item"]),
                       surface="mcp", auth=_OAUTH_OK)
    assert _gate(r, "tool_descriptions")["status"] == "fail"
    assert _gate(r, "tool_names_unique")["status"] == "fail"


def test_catch_all_method_tool_blocks():
    r = evaluate_gates(_mcp_data(tools=[_tool("api_request", mixed_methods=True)]),
                       surface="mcp", auth=_OAUTH_OK)
    g = _gate(r, "read_write_separated")
    assert g["status"] == "fail" and g["severity"] == "blocker"
    free = evaluate_gates(_mcp_data(tools=[_tool("api_request", freeform_method=True,
                                                 custom_query=True)]),
                          surface="mcp", auth=_OAUTH_OK)
    assert _gate(free, "read_write_separated")["status"] == "fail"
    loose = evaluate_gates(_mcp_data(tools=[_tool("sort", freeform_method=True)]),
                           surface="mcp", auth=_OAUTH_OK)
    assert _gate(loose, "read_write_separated")["status"] == "warn"


def test_custom_query_without_api_reference_warns():
    r = evaluate_gates(_mcp_data(tools=[_tool("run_query", custom_query=True)]),
                       surface="mcp", auth=_OAUTH_OK)
    assert _gate(r, "custom_query_api_docs")["status"] == "warn"
    ok = evaluate_gates(_mcp_data(tools=[_tool("run_query", custom_query=True,
                                               api_reference=True)]),
                        surface="mcp", auth=_OAUTH_OK)
    assert _gate(ok, "custom_query_api_docs")["status"] == "pass"
    assert "custom_query_api_docs" not in _ids(evaluate_gates(_mcp_data(), surface="mcp",
                                                              auth=None))


def test_conversation_and_location_inputs_warn():
    t = _tool("answer", context_params=["chat_history"], location_params=["latitude"])
    r = evaluate_gates(_mcp_data(tools=[t]), surface="mcp", auth=_OAUTH_OK)
    assert _gate(r, "no_conversation_inputs")["status"] == "warn"
    assert _gate(r, "no_precise_location")["stores"] == ["openai"]
    assert r["directory_ready"] is True
    assert "no_conversation_inputs" not in _ids(evaluate_gates(_mcp_data(), surface="mcp",
                                                               auth=_OAUTH_OK))


def test_ui_tool_asks_to_confirm_csp():
    r = evaluate_gates(_mcp_data(tools=[_tool(links_ui=True)]), surface="mcp", auth=_OAUTH_OK)
    g = _gate(r, "ui_csp")
    assert g["status"] == "unknown" and g["stores"] == ["openai"]
    assert r["directory_ready"] is True
    assert "to confirm by hand" in r["headline"]


def test_old_cache_without_review_facts_reads_unknown():
    d = _mcp_data()
    del d["surface_detail"]["review_facts"]
    r = evaluate_gates(d, surface="mcp", auth=None)
    assert _gate(r, "tool_titles")["status"] == "unknown"


def test_unknown_auth_warns_not_blocks():
    r = evaluate_gates(_mcp_data(), surface="mcp", auth=None)
    assert _gate(r, "auth_declared")["status"] == "unknown"
    assert r["directory_ready"] is True          # warnings never block
    assert r["summary"]["warnings"] >= 1


def test_open_server_is_fine_for_public_data():
    r = evaluate_gates(_mcp_data(), surface="mcp", auth={"open": True})
    g = _gate(r, "auth_declared")
    assert g["status"] == "warn" and "public data" in g["detail"]
    assert "auth_discovery" not in _ids(r)


def test_401_without_any_metadata_blocks():
    auth = {"challenge": True, "challenge_points_to_metadata": False, "prm_found": False}
    r = evaluate_gates(_mcp_data(), surface="mcp", auth=auth)
    assert _gate(r, "auth_discovery")["status"] == "fail"
    assert r["directory_ready"] is False


def test_401_without_pointer_but_wellknown_metadata_warns():
    auth = dict(_OAUTH_OK, challenge_points_to_metadata=False)
    assert _gate(evaluate_gates(_mcp_data(), surface="mcp", auth=auth),
                 "auth_discovery")["status"] == "warn"


def test_resource_mismatch_and_missing_as_metadata_block():
    r = evaluate_gates(_mcp_data(), surface="mcp", auth=dict(_OAUTH_OK, resource_matches=False))
    assert _gate(r, "auth_resource_match")["status"] == "fail"
    r = evaluate_gates(_mcp_data(), surface="mcp",
                       auth=dict(_OAUTH_OK, as_metadata_found=False))
    assert _gate(r, "auth_server_metadata")["status"] == "fail"
    assert "auth_pkce_s256" not in _ids(r)


def test_pkce_and_registration_warn():
    r = evaluate_gates(_mcp_data(), surface="mcp",
                       auth=dict(_OAUTH_OK, pkce_s256=False, dcr=False, cimd=False))
    assert _gate(r, "auth_pkce_s256")["status"] == "warn"
    g = _gate(r, "auth_client_registration")
    assert g["status"] == "warn" and "portal" in g["detail"]
    assert r["directory_ready"] is True


def test_lazy_auth_passes_discovery():
    auth = dict(_OAUTH_OK, challenge=False, challenge_points_to_metadata=False)
    assert _gate(evaluate_gates(_mcp_data(), surface="mcp", auth=auth),
                 "auth_discovery")["status"] == "pass"


def test_high_blast_radius_without_destructive_hint_warns():
    r = evaluate_gates(_mcp_data(blast="critical"), surface="mcp", auth={"open": True})
    assert _gate(r, "destructive_hinted")["status"] == "warn"
    assert r["directory_ready"] is True
    hinted = _tool(hints={"readOnlyHint": False, "destructiveHint": True,
                          "openWorldHint": False})
    r = evaluate_gates(_mcp_data(blast="critical", tools=[hinted]), surface="mcp",
                       auth={"open": True})
    assert "destructive_hinted" not in _ids(r)


def test_mcp_surface_drops_readme_license_gate():
    """A live connector listing needs docs and privacy URLs, not a README/license file."""
    r = evaluate_gates(_mcp_data(has_license=False), surface="mcp", auth=None)
    assert "listing_complete" not in _ids(r)


def test_signin_required_runs_only_auth_checks():
    r = evaluate_gates(None, surface="mcp", auth=_OAUTH_OK, scanned=False)
    assert r["directory_ready"] is False
    assert r["headline"] == "Sign-in needed to check the tools"
    assert _gate(r, "tool_titles")["status"] == "unknown"
    assert _gate(r, "auth_discovery")["status"] == "pass"
    assert {"no_secrets", "trust_score", "no_lethal_trifecta"}.isdisjoint(_ids(r))


def test_repo_surface_without_plugin():
    data = _mcp_data(has_license=False)
    data["surface_detail"] = {}
    r = evaluate_gates(data, surface="repo", auth=None,
                       plugin={"found": False, "gates": []})
    ids = _ids(r)
    assert "no_lethal_trifecta" not in ids and "auth_declared" not in ids
    assert "tool_titles" not in ids
    assert _gate(r, "plugin_bundle")["status"] == "na"
    g = _gate(r, "listing_complete")
    assert g["status"] == "warn" and g["basis"] == "agentavow"
    assert r["directory_ready"] is True


def test_repo_surface_includes_plugin_gates_and_holds_dont_block():
    pg = [{"id": "plugin_file_limits", "label": "x", "status": "fail", "severity": "hold",
           "detail": "", "stores": ["anthropic"], "basis": "documented", "sources": [],
           "group": "plugin"}]
    data = _mcp_data()
    data["surface_detail"] = {}
    r = evaluate_gates(data, surface="repo", plugin={"found": True, "gates": pg})
    assert "plugin_file_limits" in _ids(r) and "listing_complete" not in _ids(r)
    assert r["summary"]["holds"] == 1 and r["directory_ready"] is True


def test_observed_blocker_decides_readiness():
    pg = [{"id": "plugin_verified_command_hooks", "label": "x", "status": "fail",
           "severity": "blocker", "detail": "", "stores": ["anthropic"], "basis": "observed",
           "sources": [], "group": "plugin"}]
    data = _mcp_data()
    data["surface_detail"] = {}
    r = evaluate_gates(data, surface="repo", plugin={"found": True, "gates": pg})
    assert r["directory_ready"] is False
