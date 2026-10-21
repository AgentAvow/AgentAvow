"""The three-phrase decision (``src.scanner.verdict.decide``) — every branch, table-driven,
and the TS twin (``decide()`` in ``web/src/components/trust/gradeSystem.ts``) run on the
same table with byte-identical output."""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from src.scanner.verdict import Decision, decide
from src.trust_tiers import (
    DECISIONS,
    REVIEW_PHRASE,
    decision_color,
    decision_label,
    headline,
    is_certified,
    verdict_phrase,
)

ROOT = Path(__file__).resolve().parent.parent


def _f(severity, name="Finding", **kw):
    return {"category": kw.pop("category", "code_safety"), "name": name,
            "severity": severity, "file_path": kw.pop("file_path", "src/x.py"),
            "line_number": 1, "shipped": kw.pop("shipped", True),
            "kind": kw.pop("kind", "defect"), "installed": kw.pop("installed", True), **kw}


def _dep(severity, pkg="lib@1.0.0 (GHSA-xxxx)"):
    """A vulnerable-dependency finding as the API lists it."""
    return _f(severity, f"Vulnerable dependency: {pkg}", category="dependency",
              file_path="lockfile")


def _scan(score=92, files=120, items=(), crit=None, high=None, **extra):
    findings = {"items": list(items)}
    if crit is not None:
        findings["critical"] = crit
    if high is not None:
        findings["high"] = high
    return {"trust_score": score, "findings": findings,
            "metadata": {"files_scanned": files}, **extra}


def _bev(findings=(), **kw):
    return {"ran": True, "findings": list(findings), "attestation": {"jws": "x"}, **kw}


CERTIFIED = {"eligible": True, "checks": {"no_critical_or_high": True}}

# (id, data, decision, final, reason)
CASES = [
    # ── safe ──────────────────────────────────────────────────────────────────────
    ("clean_large", _scan(92, 1200), "safe", True, "nothing found in 1,200 files"),
    ("clean_one_file_not_thin_when_medium", _scan(70, 1, [_f("medium", "Weak hash")]),
     "safe", True, "no critical or high findings in 1 file"),
    ("certified_safe", _scan(98, 340, certified=CERTIFIED), "safe", True,
     "nothing found in 340 files"),
    ("mediums_only_above_51", _scan(60, 40, [_f("medium")] * 3), "safe", True,
     "no critical or high findings in 40 files"),
    ("no_files_known", {"trust_score": 85}, "safe", True, "nothing found"),
    # thin coverage reads Safe with the reason (Kenne, 2026-10-08, #19)
    ("thin_coverage", _scan(74, 3), "safe", True, "nothing found; little code to inspect"),
    ("thin_coverage_seven_files", _scan(82, 7), "safe", True,
     "nothing found; little code to inspect"),
    ("thin_coverage_low_only", _scan(82, 5, [_f("low", "Minor")]), "safe", True,
     "nothing found; little code to inspect"),
    ("eight_files_not_thin", _scan(88, 8), "safe", True, "nothing found in 8 files"),
    # zero files read (a metapackage like fastmcp 4.x, whose code ships in a dependency)
    # is the thinnest coverage, not a plain "nothing found" (#22 follow-up)
    ("zero_files_is_thin", _scan(74, 0), "safe", True, "nothing found; no code to inspect"),
    ("zero_files_low_only_is_thin", _scan(74, 0, [_f("low", "Minor")]), "safe", True,
     "nothing found; no code to inspect"),
    ("zero_files_medium_not_thin", _scan(70, 0, [_f("medium", "Weak hash")]), "safe", True,
     "no critical or high findings"),
    ("zero_files_high_still_review", _scan(70, 0, [_f("high", "Install hook", category="install_hook",
                                                      file_path="package.json")], high=1),
     "review", True, "one high finding in its install script: install hook"),
    ("zero_tools_remote_mcp_keeps_its_reason", _scan(74, 0, coverage={"surface": "mcp"}),
     "safe", True, "tool definitions clean; server code not inspected"),
    ("files_scanned_null_is_unknown_not_thin",
     {"trust_score": 85, "metadata": {"files_scanned": None}}, "safe", True, "nothing found"),
    ("thin_remote_mcp", _scan(82, 4, coverage={"surface": "mcp"},
                              surface_detail={"surface": "mcp", "tool_count": 4}),
     "safe", True, "tool definitions clean; server code not inspected"),
    ("thin_remote_mcp_surface_detail_only", _scan(82, 4, surface_detail={"surface": "mcp"}),
     "safe", True, "tool definitions clean; server code not inspected"),
    ("thin_stdio_mcp_package_is_code", _scan(82, 4, coverage={"surface": "npm"},
                                            metadata={"files_scanned": 4,
                                                      "is_mcp_server": True}),
     "safe", True, "nothing found; little code to inspect"),
    ("remote_mcp_many_tools", _scan(88, 12, coverage={"surface": "mcp"}), "safe", True,
     "nothing found in 12 files"),
    ("thin_remote_mcp_high_still_review", _scan(70, 3, [_f("high", "Tool poisoning", file_path="tool:fetch")],
                                                high=1, coverage={"surface": "mcp"}),
     "review", True, "one high finding in its tool definitions: tool poisoning"),
    ("server_icon_high_is_in_tool_definitions",
     _scan(80, 3, [_f("high", "Icon carries active content: <script>",
                      file_path="server:serverInfo:icons")],
           high=1, coverage={"surface": "mcp"}),
     "review", True,
     "one high finding in its tool definitions: icon carries active content: <script>"),
    ("thin_under_51_still_review", _scan(50, 3), "review", True,
     "trust score 50/100 is under 51"),
    ("capability_never_counts", _scan(88, 30, [_f("low", "Spawns a process",
                                                  kind="capability")]),
     "safe", True, "nothing found in 30 files"),
    ("critical_in_tests_not_blocking", _scan(80, 30, [_f("critical", shipped=False,
                                                         file_path="tests/t.py")], crit=0),
     "safe", True, "no critical or high findings in 30 files"),
    ("cloud_metadata_probe_low", _scan(90, 50, behavioral=_bev(
        [{"rule": "cloud_metadata_probe", "severity": "low", "name": "IMDS"}])),
     "safe", True, "nothing found in 50 files"),
    ("static_ssrf_medium", _scan(75, 50, [_f("medium", "Possible SSRF", category="ssrf")]),
     "safe", True, "no critical or high findings in 50 files"),
    ("live_probe_is_advisory", _scan(90, 50, behavioral=_bev(
        [{"rule": "behavioral_undeclared_egress", "severity": "high"}], plan="live-probe")),
     "safe", True, "nothing found in 50 files"),
    ("sandbox_not_run", _scan(90, 50, behavioral={"ran": False, "reason": "needs_credentials"}),
     "safe", True, "nothing found in 50 files"),
    ("adoption_never_an_input", _scan(90, 50, adoption={"score": 0}), "safe", True,
     "nothing found in 50 files"),
    ("history_advisory_not_affecting", _scan(90, 50, advisories=[
        {"id": "GHSA-old", "affects_scanned_version": False}]), "safe", True,
     "nothing found in 50 files"),
    # ── review ────────────────────────────────────────────────────────────────────
    ("one_high", _scan(85, 200, [_f("high", "Shell command with user input")], high=1),
     "review", True, "one high finding in its code: shell command with user input"),
    ("three_high", _scan(70, 200, [_f("high", "API key in source")] * 3, high=3),
     "review", True, "3 high findings in its code, including API key in source"),
    ("behavioral_undeclared_egress", _scan(70, 200, behavioral=_bev(
        [{"rule": "behavioral_undeclared_egress", "severity": "high", "name": "Egress"}])),
     "review", True, "one high finding: undeclared network call"),
    ("ssrf_internal_fetch_high_is_review", _scan(70, 200, behavioral=_bev(
        [{"rule": "ssrf_internal_fetch", "severity": "high"}])),
     "review", True, "one high finding: fetched an internal network address"),
    ("readonly_violated", _scan(70, 200, behavioral=_bev(
        [{"rule": "annotation_readonly_violated", "severity": "high"}])),
     "review", True, "one high finding: a read-only tool wrote files"),
    ("advisory_affects_version", _scan(88, 200, advisories=[
        {"id": "GHSA-abcd", "affects_scanned_version": True}]),
     "review", True, "a published advisory affects this version (GHSA-abcd)"),
    ("advisory_names_the_fixed_version", _scan(88, 200, advisories=[
        {"id": "GHSA-abcd", "affects_scanned_version": True, "fixed_in": "2.31.0"}]),
     "review", True, "a published advisory affects this version (GHSA-abcd); fixed in 2.31.0"),
    ("advisory_names_the_highest_fix", _scan(88, 200, advisories=[
        {"id": "GHSA-a", "affects_scanned_version": True, "fixed_in": "1.9.2"},
        {"id": "GHSA-b", "affects_scanned_version": True, "fixed_in": "1.10.0"},
        {"id": "GHSA-c", "affects_scanned_version": True}]),
     "review", True, "a published advisory affects this version (GHSA-a); fixed in 1.10.0"),
    ("advisory_fix_ignores_unaffecting_entries", _scan(88, 200, advisories=[
        {"id": "GHSA-a", "affects_scanned_version": True, "fixed_in": "3.0.1"},
        {"id": "GHSA-old", "affects_scanned_version": False, "fixed_in": "9.9.9"}]),
     "review", True, "a published advisory affects this version (GHSA-a); fixed in 3.0.1"),
    ("advisory_in_incident_history", _scan(88, 200, incident_history={"advisories": [
        {"id": "PYSEC-1", "affects_scanned_version": True}]}),
     "review", True, "a published advisory affects this version (PYSEC-1)"),
    ("critical_own_advisory_is_review", _scan(40, 200, [_f(
        "critical", "Published advisory affects this version: RCE",
        category="known_vulnerability", file_path="registry advisory")], crit=1),
     "review", True, "a published advisory affects this version"),
    ("deprecated", _scan(90, 200, deprecation="use foo2"), "review", True,
     "the maintainer has deprecated this package"),
    ("score_under_51", _scan(50, 200, [_f("medium")] * 8), "review", True,
     "trust score 50/100 is under 51"),
    ("headline_high_without_item", _scan(70, 200, [], high=1), "review", True,
     "one high finding"),
    # scripts/ is author-controlled (an entry point can live there), so the scanner tags
    # it shipped and it blocks; the tag and the headline count agree.
    ("high_in_scripts_still_blocks", _scan(70, 200, [_f(
        "high", "Eval of input", file_path="scripts/run.py")], high=1),
     "review", True, "one high finding in its code: eval of input"),
    # A finding tagged not-shipped (CI script, file absent from the artifact) never
    # decides, even on a shape with no headline counts (stored rows, old caches).
    ("unshipped_critical_items_only", {"trust_score": 70, "findings": {"items": [_f(
        "critical", "curl/wget piped to shell", shipped=False, file_path="ci/build.sh")]},
        "metadata": {"files_scanned": 200}},
     "safe", True, "no critical or high findings in 200 files"),
    ("items_only_shape", {"trust_score": 70, "findings": {"items": [_f("high", "X")]}},
     "review", True, "one high finding in its code: X"),
    # ── do_not_connect ────────────────────────────────────────────────────────────
    ("one_critical", _scan(45, 200, [_f("critical", "Hardcoded private key")], crit=1),
     "do_not_connect", True, "one critical finding in its code: hardcoded private key"),
    ("canary_exfil", _scan(45, 200, behavioral=_bev(
        [{"rule": "credential_canary_exfiltrated", "severity": "critical"}],
        canary_exfil=[{"via": "https", "host": "evil.example"}])),
     "do_not_connect", True, "a planted credential left the sandbox"),
    ("other_critical_behavior", _scan(45, 200, behavioral=_bev(
        [{"rule": "some_new_rule", "severity": "critical", "name": "Wiped the disk"}])),
     "do_not_connect", True, "the sandbox caught a critical behavior: wiped the disk"),
    ("malicious_dependency", _scan(30, 200, [_f(
        "critical", "Known-malicious package: evil@1.0.0 (MAL-2025-1)",
        category="dependency", file_path="package-lock.json")], crit=1),
     "do_not_connect", True,
     "a known-malicious dependency: evil@1.0.0 (MAL-2025-1)"),
    ("supply_chain_malicious_list", _scan(60, 200, supply_chain={"malicious": ["MAL-9"]}),
     "do_not_connect", True, "a known-malicious dependency: MAL-9"),
    ("own_mal_advisory", _scan(90, 200, incident_history={"current_version_affected": True}),
     "do_not_connect", True, "this version is listed as malicious (OpenSSF MAL advisory)"),
    ("critical_beats_high", _scan(40, 200, [_f("critical", "Alpha"), _f("high", "Beta")],
                                  crit=1, high=1),
     "do_not_connect", True, "one critical finding in its code: alpha"),
    ("long_name_truncated", _scan(40, 200, [_f("critical", "Z" * 90)], crit=1),
     "do_not_connect", True, "one critical finding in its code: " + "Z" * 69 + "…"),
    # ── pending sandbox: provisional, never a silent flip ─────────────────────────
    ("pending_safe", _scan(90, 300, behavioral={"ran": False, "pending": True}),
     "safe", False, "nothing found in 300 files; sandbox still running"),
    ("pending_review", _scan(70, 300, [_f("high", "X")], high=1,
                             behavioral={"ran": False, "pending": True}),
     "review", False, "one high finding in its code: X; sandbox still running"),
    ("pending_with_stale_findings_ignored", _scan(90, 300, behavioral={
        "ran": True, "pending": True,
        "findings": [{"rule": "behavioral_undeclared_egress", "severity": "high"}]}),
     "safe", False, "nothing found in 300 files; sandbox still running"),
    # ── dependency advisories: never an input, always named beside a count ────────
    # (vercel/next.js read "5 high findings, …" next to totals of 48 high / 6 critical)
    ("deps_review_nextjs_shape", _scan(
        58, 200,
        [_dep("critical", "handlebars@4.7.9 (GHSA-8r5x)")] * 6
        + [_dep("high", "tar@6.1.0 (GHSA-x)")] * 43
        + [_f("high", "execSync / spawn (Node.js)", category="unsafe_exec")] * 5,
        crit=0, high=5,
        supply_chain={"scored": True, "counts": {"critical": 6, "high": 43, "low": 31}}),
     "review", True,
     "5 high findings in its code, including execSync / spawn (Node.js); "
     "plus 6 critical and 43 high in dependencies"),
    ("deps_review_one_high_items_only", _scan(
        80, 200, [_f("high", "Eval of input"), _dep("high", "a@1 (GHSA-1)")], high=1),
     "review", True, "one high finding in its code: eval of input; plus 1 high in dependencies"),
    ("deps_supply_chain_counts_exceed_capped_items", _scan(
        70, 200, [_f("high", "X"), _dep("critical", "a@1 (GHSA-1)")], high=1,
        supply_chain={"scored": True, "counts": {"critical": 4, "high": "9"}}),
     "review", True, "one high finding in its code: X; plus 4 critical and 9 high in dependencies"),
    ("deps_unscored_supply_chain_counts_ignored", _scan(
        70, 200, [_f("high", "X")], high=1,
        supply_chain={"scored": False, "counts": {"critical": 4, "high": 9}}),
     "review", True, "one high finding in its code: X"),
    ("deps_sandbox_high", _scan(70, 200, [_dep("critical", "a@1 (GHSA-1)")], behavioral=_bev(
        [{"rule": "behavioral_undeclared_egress", "severity": "high"}])),
     "review", True,
     "one high finding in the sandbox: undeclared network call; plus 1 critical in dependencies"),
    ("deps_medium_only_no_clause", _scan(70, 40, [_dep("medium", "a@1 (GHSA-1)")]),
     "safe", True, "no critical or high findings in 40 files"),
    ("deps_advisory_branch_unchanged", _scan(88, 200, [_dep("high", "a@1 (GHSA-1)")],
                                             advisories=[{"id": "GHSA-abcd",
                                                          "affects_scanned_version": True}]),
     "review", True, "a published advisory affects this version (GHSA-abcd)"),
    ("deps_score_branch_unchanged", _scan(45, 200, [_dep("critical", "a@1 (GHSA-1)")] * 3),
     "review", True, "trust score 45/100 is under 51"),
    ("deps_safe", _scan(82, 300, [_dep("high", "a@1 (GHSA-1)"), _dep("high", "b@2 (GHSA-2)")]),
     "safe", True, "no critical or high findings in its code (dependencies: 2 high advisories)"),
    ("deps_safe_one", _scan(82, 300, [_dep("critical", "a@1 (GHSA-1)")]),
     "safe", True, "no critical or high findings in its code (dependencies: 1 critical advisory)"),
    ("deps_safe_thin", _scan(82, 3, [_dep("high", "a@1 (GHSA-1)")]),
     "safe", True, "no critical or high findings in its code (dependencies: 1 high advisory)"),
    ("deps_safe_pending", _scan(82, 300, [_dep("high", "a@1 (GHSA-1)")],
                                behavioral={"ran": False, "pending": True}),
     "safe", False,
     "no critical or high findings in its code (dependencies: 1 high advisory); "
     "sandbox still running"),
    ("deps_do_not_connect", _scan(40, 200, [_f("critical", "Hardcoded private key"),
                                            _dep("critical", "a@1 (GHSA-1)"),
                                            _dep("high", "b@1 (GHSA-2)")], crit=1),
     "do_not_connect", True,
     "one critical finding in its code: hardcoded private key; "
     "plus 1 critical and 1 high in dependencies"),
    ("deps_do_not_connect_many", _scan(30, 200, [_f("critical", "Alpha")] * 2
                                       + [_dep("high", "a@1 (GHSA-1)")] * 3, crit=2),
     "do_not_connect", True,
     "2 critical findings in its code, including alpha; plus 3 high in dependencies"),
    ("deps_sandbox_critical", _scan(45, 200, [_dep("high", "a@1 (GHSA-1)")], behavioral=_bev(
        [{"rule": "some_new_rule", "severity": "critical", "name": "Wiped the disk"}])),
     "do_not_connect", True,
     "the sandbox caught a critical behavior: wiped the disk; plus 1 high in dependencies"),
    ("deps_malicious_branch_unchanged", _scan(30, 200, [
        _f("critical", "Known-malicious package: evil@1.0.0 (MAL-2025-1)",
           category="dependency", file_path="package-lock.json"),
        _dep("high", "a@1 (GHSA-1)")], crit=1),
     "do_not_connect", True, "a known-malicious dependency: evil@1.0.0 (MAL-2025-1)"),
    ("deps_canary_branch_unchanged", _scan(45, 200, [_dep("high", "a@1 (GHSA-1)")],
                                           behavioral=_bev(canary_exfil=[{"host": "x"}])),
     "do_not_connect", True, "a planted credential left the sandbox"),
    ("queued_for_slot", _scan(90, 300, behavioral={
        "ran": False, "pending": True, "state": "queued", "queue_position": 3}),
     "safe", False, "nothing found in 300 files; waiting for a sandbox slot"),
    ("running_state_explicit", _scan(90, 300, behavioral={
        "ran": False, "pending": True, "state": "running"}),
     "safe", False, "nothing found in 300 files; sandbox still running"),
    # past the pending age limit the API says final + static-only: decision is final
    ("sandbox_unavailable_is_final", _scan(90, 300, behavioral={
        "ran": False, "pending": False, "state": "unavailable",
        "reason": "sandbox unavailable, static analysis only"}),
     "safe", True, "nothing found in 300 files"),
    ("deps_safe_queued", _scan(82, 300, [_dep("high", "a@1 (GHSA-1)")],
                               behavioral={"ran": False, "pending": True, "state": "queued"}),
     "safe", False,
     "no critical or high findings in its code (dependencies: 1 high advisory); "
     "waiting for a sandbox slot"),
    # ── where the leading finding sits (wording only) ─────────────────────────────
    ("where_agent_instructions", _scan(40, 200, [_f("critical", "curl/wget piped to shell",
                                                    file_path="pkg/skills/hf/SKILL.md")],
                                       crit=1),
     "do_not_connect", True,
     "one critical finding in instructions it gives agents: curl/wget piped to shell"),
    ("where_readme", _scan(70, 200, [_f("high", "Instruction-override phrase",
                                        file_path="README.md")], high=1),
     "review", True, "one high finding in instructions it gives agents: "
     "instruction-override phrase"),
    ("where_skill_script_is_code", _scan(70, 200, [_f("high", "X",
                                                      file_path="skills/x/run.py")], high=1),
     "review", True, "one high finding in its code: X"),
    ("where_install_script", _scan(40, 200, [_f("critical", "Lifecycle script pipes to shell",
                                                category="install_hook",
                                                file_path="package.json")], crit=1),
     "do_not_connect", True,
     "one critical finding in its install script: lifecycle script pipes to shell"),
    # A pipe-to-shell in a package.json script an install lifecycle script reaches (a
    # maintainer-only one is low and never decides): not "in its code".
    ("where_package_json_script", _scan(40, 200, [_f("critical", "curl/wget piped to shell",
                                                     category="dynamic_remote_load",
                                                     file_path="package.json")], crit=1),
     "do_not_connect", True,
     "one critical finding in its install script: curl/wget piped to shell"),
    ("where_nested_package_json", _scan(40, 200, [_f("critical", "curl/wget piped to shell",
                                                     category="dynamic_remote_load",
                                                     file_path="packages/a/package.json")],
                                        crit=1),
     "do_not_connect", True,
     "one critical finding in its install script: curl/wget piped to shell"),
    ("where_data_file", _scan(55, 200, [_f("high", "Instruction-override phrase",
                                           file_path="pkg/filters/prompt_injection.yaml")],
                              high=1),
     "review", True, "one high finding in a data file it ships: instruction-override phrase"),
    ("where_ci_yaml_is_code", _scan(70, 200, [_f("high", "X",
                                                 file_path=".github/workflows/ci.yml")], high=1),
     "review", True, "one high finding in its code: X"),
    ("where_leading_item_decides", _scan(40, 200, [
        _f("critical", "curl/wget piped to shell", file_path="pkg/cli/_cli_utils.py"),
        _f("critical", "curl/wget piped to shell", file_path="SKILL.md")], crit=2),
     "do_not_connect", True,
     "2 critical findings in its code, including curl/wget piped to shell"),
    # ── coverage gaps: a Safe reason states what was not read (wording only) ─────
    ("gap_oversized_one", _scan(92, 120, coverage_gaps={"oversized_files": 1}), "safe", True,
     "nothing found in 120 files; 1 file over 500 KB was not fully read"),
    ("gap_oversized_many", _scan(92, 120, coverage_gaps={"oversized_files": 3}), "safe", True,
     "nothing found in 120 files; 3 files over 500 KB were not fully read"),
    ("gap_over_cap", _scan(92, 200, coverage_gaps={"over_file_cap": 1800, "file_cap": 200}),
     "safe", True, "nothing found in 200 files; 1,800 files past the 200-file limit were "
     "not read"),
    ("gap_three_kinds_counts_the_rest",
     _scan(92, 150, coverage_gaps={"fetch_failed": 2, "time_limit_unread": 1,
                                   "tree_truncated": True}),
     "safe", True, "nothing found in 150 files; 2 files could not be fetched; 1 file was "
     "not read before the time limit; and 1 more coverage gap"),
    ("gap_thin", _scan(74, 3, coverage_gaps={"package_skipped": 4}), "safe", True,
     "nothing found; little code to inspect; 4 files in the package were skipped for size"),
    ("gap_deps_advisory_lookup", _scan(92, 50, coverage_gaps={
        "dependency_files_unread": 1, "advisory_lookup": "failed"}), "safe", True,
     "nothing found in 50 files; 1 dependency file could not be read; the vulnerability "
     "database lookup failed"),
    ("gap_remote_mcp_tool_list", _scan(80, 0, coverage={"surface": "mcp"},
                                       coverage_gaps={"tool_list_unread": True}),
     "review", True, "the server's tool list could not be read"),
    ("gap_tool_list_unread_files", _scan(92, 12, coverage={"surface": "mcp"},
                                         coverage_gaps={"tool_list_unread": True}),
     "review", True, "the server's tool list could not be read"),
    ("gap_tool_list_unread_high_wins", _scan(70, 12, [_f("high", "X")], high=1,
                                             coverage={"surface": "mcp"},
                                             coverage_gaps={"tool_list_unread": True}),
     "review", True, "one high finding in its code: X"),
    # A tool list read only in part (a later page failed, a cursor loop, the page cap)
    # reads Review like an unread one (V2, Kenne 2026-10-20).
    ("gap_mcp_paged", _scan(88, 12, coverage={"surface": "mcp"},
                            coverage_gaps={"tool_list_paged": True}),
     "review", True, "only part of the server's tool list could be read"),
    ("gap_mcp_paged_pages_read", _scan(92, 400, coverage={"surface": "mcp"},
                                       coverage_gaps={"tool_list_paged": True,
                                                      "pages_read": 20}),
     "review", True, "only part of the server's tool list could be read"),
    ("gap_mcp_paged_thin", _scan(80, 3, coverage={"surface": "mcp"},
                                 coverage_gaps={"tool_list_paged": True, "pages_read": 1}),
     "review", True, "only part of the server's tool list could be read"),
    ("gap_mcp_paged_not_true", _scan(92, 12, coverage={"surface": "mcp"},
                                     coverage_gaps={"tool_list_paged": "yes"}),
     "safe", True, "nothing found in 12 files"),
    ("gap_mcp_paged_high_wins", _scan(70, 12, [_f("high", "X")], high=1,
                                      coverage={"surface": "mcp"},
                                      coverage_gaps={"tool_list_paged": True}),
     "review", True, "one high finding in its code: X"),
    ("gap_mcp_unread_before_paged", _scan(92, 12, coverage={"surface": "mcp"},
                                          coverage_gaps={"tool_list_unread": True,
                                                         "tool_list_paged": True}),
     "review", True, "the server's tool list could not be read"),
    # An advertised resources/ or prompts/list that could not be read, or was too large.
    ("gap_mcp_resources_unread", _scan(92, 12, coverage={"surface": "mcp"},
                                       coverage_gaps={"resource_list_unread": True}),
     "review", True, "the server's resource list could not be read"),
    ("gap_mcp_prompts_unread", _scan(92, 12, coverage={"surface": "mcp"},
                                     coverage_gaps={"prompt_list_unread": True}),
     "review", True, "the server's prompt list could not be read"),
    ("gap_mcp_prompts_too_large", _scan(88, 12, [_f("medium", "Prompts list too large")],
                                        coverage={"surface": "mcp"},
                                        coverage_gaps={"prompt_list_too_large": True}),
     "review", True, "the server's prompt list could not be read"),
    ("gap_mcp_resources_too_large", _scan(88, 12, coverage={"surface": "mcp"},
                                          coverage_gaps={"resource_list_too_large": True}),
     "review", True, "the server's resource list could not be read"),
    ("gap_mcp_both_lists", _scan(92, 12, coverage={"surface": "mcp"},
                                 coverage_gaps={"resource_list_too_large": True,
                                                "prompt_list_unread": True}),
     "review", True, "the server's resource and prompt lists could not be read"),
    ("gap_mcp_paged_before_lists", _scan(92, 12, coverage={"surface": "mcp"},
                                         coverage_gaps={"tool_list_paged": True,
                                                        "prompt_list_unread": True}),
     "review", True, "only part of the server's tool list could be read"),
    ("gap_mcp_list_gap_pending", _scan(92, 12, coverage={"surface": "mcp"},
                                       coverage_gaps={"resource_list_unread": True},
                                       behavioral={"pending": True}),
     "review", False, "the server's resource list could not be read; sandbox still running"),
    ("gap_pending_suffix_last", _scan(92, 120, coverage_gaps={"oversized_files": 2},
                                      behavioral={"pending": True}),
     "safe", False, "nothing found in 120 files; 2 files over 500 KB were not fully read; "
     "sandbox still running"),
    # a gap never changes a Review / Do-not-connect answer or its reason
    ("gap_review_unchanged", _scan(70, 200, [_f("high", "X")], high=1,
                                   coverage_gaps={"oversized_files": 5}),
     "review", True, "one high finding in its code: X"),
    ("gap_zero_values_ignored", _scan(92, 120, coverage_gaps={
        "oversized_files": 0, "tree_truncated": False, "advisory_lookup": "ok"}),
     "safe", True, "nothing found in 120 files"),
    ("gap_garbage_shape", _scan(92, 120, coverage_gaps=["x"]), "safe", True,
     "nothing found in 120 files"),
    # ── a hardcoded credential alone caps at Review (Kenne, 2026-10-19) ──────────
    # It exposes the vendor whose key leaked (yt-dlp 2026.8.19: an AWS key in
    # yt_dlp/extractor/shahid.py), not the person installing the tool.
    ("secret_only_is_review", _scan(45, 900, [_f(
        "critical", "AWS Access Key", category="secret",
        file_path="yt_dlp/extractor/shahid.py")], crit=1),
     "review", True,
     "a hardcoded credential in its code (it exposes the vendor's key, not yours)"),
    ("secret_items_only_is_review", {"trust_score": 45, "findings": {"items": [
        _f("critical", "AWS Access Key", category="secret")]}},
     "review", True,
     "a hardcoded credential in its code (it exposes the vendor's key, not yours)"),
    ("two_secrets_is_review", _scan(40, 200, [_f("critical", "AWS Access Key",
                                                 category="secret")] * 2, crit=2),
     "review", True,
     "2 hardcoded credentials in its code (they expose the vendor's keys, not yours)"),
    ("secret_plus_unsafe_exec_critical_stays_dnc", _scan(30, 200, [
        _f("critical", "AWS Access Key", category="secret"),
        _f("critical", "Shell command with user input", category="unsafe_exec")], crit=2),
     "do_not_connect", True, "one critical finding in its code: shell command with user input"),
    ("secret_plus_headline_only_critical_stays_dnc", _scan(30, 200, [
        _f("critical", "AWS Access Key", category="secret")], crit=2),
     "do_not_connect", True, "one critical finding"),
    ("secret_plus_sandbox_critical_stays_dnc", _scan(30, 200, [
        _f("critical", "AWS Access Key", category="secret")], crit=1, behavioral=_bev(
        [{"rule": "some_new_rule", "severity": "critical", "name": "Wiped the disk"}])),
     "do_not_connect", True, "the sandbox caught a critical behavior: wiped the disk"),
    ("secret_plus_malicious_dep_stays_dnc", _scan(30, 200, [
        _f("critical", "AWS Access Key", category="secret"),
        _f("critical", "Known-malicious package: evil@1.0.0 (MAL-2025-1)",
           category="dependency", file_path="package-lock.json")], crit=2),
     "do_not_connect", True, "a known-malicious dependency: evil@1.0.0 (MAL-2025-1)"),
    ("secret_leads_over_high", _scan(40, 200, [
        _f("critical", "AWS Access Key", category="secret"),
        _f("high", "Eval of input")], crit=1, high=1),
     "review", True,
     "a hardcoded credential in its code (it exposes the vendor's key, not yours)"),
    ("secret_in_data_file", _scan(45, 200, [_f("critical", "API key", category="secret",
                                               file_path="pkg/config/keys.json")], crit=1),
     "review", True,
     "a hardcoded credential in a data file it ships (it exposes the vendor's key, not yours)"),
    ("secret_with_deps", _scan(45, 200, [_f("critical", "AWS Access Key", category="secret"),
                                         _dep("high", "a@1 (GHSA-1)")], crit=1),
     "review", True, "a hardcoded credential in its code (it exposes the vendor's key, "
     "not yours); plus 1 high in dependencies"),
    ("secret_pending", _scan(45, 200, [_f("critical", "AWS Access Key", category="secret")],
                             crit=1, behavioral={"ran": False, "pending": True}),
     "review", False, "a hardcoded credential in its code (it exposes the vendor's key, "
     "not yours); sandbox still running"),
    ("secret_in_tests_not_blocking", _scan(80, 30, [_f(
        "critical", "AWS Access Key", category="secret", shipped=False,
        file_path="tests/t.py")], crit=0),
     "safe", True, "no critical or high findings in 30 files"),
    ("secret_high_keeps_high_reason", _scan(70, 200, [_f("high", "Generic token",
                                                         category="secret")], high=1),
     "review", True, "one high finding in its code: generic token"),
    # ── odd shapes never raise ────────────────────────────────────────────────────
    ("empty", {}, "review", True, "trust score 0/100 is under 51"),
    ("garbage", {"trust_score": "x", "findings": "nope", "metadata": None,
                 "behavioral": 3}, "review", True, "trust score 0/100 is under 51"),
]


@pytest.mark.parametrize("case_id,data,decision,final,reason", CASES,
                         ids=[c[0] for c in CASES])
def test_decide_table(case_id, data, decision, final, reason):
    got = decide(data)
    assert isinstance(got, Decision)
    assert (got.decision, got.final, got.reason) == (decision, final, reason)
    assert got.as_dict() == {"decision": decision, "decision_final": final,
                             "decision_reason": reason}


def test_every_branch_value_is_covered():
    assert {c[2] for c in CASES} == {d.value for d in DECISIONS}
    assert any(not c[3] for c in CASES)


def test_certified_is_a_separate_axis():
    data = _scan(98, 340, certified=CERTIFIED)
    assert decide(data).decision == "safe" and is_certified(data)
    assert headline(decide(data), certified=is_certified(data)) == "Safe to connect · Certified"
    # removing the mark never changes the phrase
    assert decide({**data, "certified": {}}) == decide(data)
    assert not is_certified({**data, "certified": {"eligible": "yes"}})


def test_phrase_table():
    assert [(d.value, d.phrase, d.label) for d in DECISIONS] == [
        ("safe", "Safe to connect", "Safe"),
        ("review", "Review before you connect", "Review"),
        ("do_not_connect", "Do not connect", "Don't connect"),
    ]
    assert REVIEW_PHRASE == "Review before you connect"
    assert verdict_phrase("do_not_connect") == "Do not connect"
    assert verdict_phrase(decide(_scan(92, 10))) == "Safe to connect"
    # an API response that already carries the decision is read, not re-decided
    assert verdict_phrase({"trust_score": 99, "decision": "review"}) == REVIEW_PHRASE
    assert verdict_phrase(40) == REVIEW_PHRASE and verdict_phrase(90) == "Safe to connect"
    assert decision_label("do_not_connect") == "Don't connect"
    assert decision_color("safe") == "#22C55E"


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ts_twin_is_byte_identical():
    """Run the TS decide() (node type stripping) over the same table."""
    payload = json.dumps([c[1] for c in CASES])
    script = (
        "const m = await import(process.argv[1]);"
        "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
        "const out=JSON.parse(s).map(x=>m.decide(x));"
        "process.stdout.write(JSON.stringify(out));});"
    )
    ts = ROOT / "web" / "src" / "components" / "trust" / "gradeSystem.ts"
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", script, str(ts)],
        input=payload, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    got = json.loads(proc.stdout)
    want = [{"decision": c[2], "final": c[3], "reason": c[4]} for c in CASES]
    assert got == want


def test_ts_phrase_table_agrees():
    import re
    ts = (ROOT / "web/src/components/trust/gradeSystem.ts").read_text()
    found = re.findall(r"\{ value: '([a-z_]+)', phrase: '([^']+)', label: (['\"])(.+?)\3, "
                       r"color: '(#[0-9A-F]{6})', colorText: '(#[0-9A-F]{6})' \}", ts)
    # The label is double-quoted when it holds an apostrophe ("Don't connect").
    found = [(v, p, lbl, c, ct) for v, p, _q, lbl, c, ct in found]
    assert found == [(d.value, d.phrase, d.label, d.color, d.color_light) for d in DECISIONS]


# ── The Certified mark (display rule) ──────────────────────────────────────────────
# (id, data, mark, why_not)
MARK_CASES = [
    ("mark", _scan(92, 340, certified=CERTIFIED), True, ""),
    ("not_eligible", _scan(98, 340), False, ""),
    ("eligible_not_true", _scan(98, 340, certified={"eligible": "yes"}), False, ""),
    ("review_deprecated", _scan(90, 340, certified=CERTIFIED, deprecation="use x instead"),
     False, "not_safe"),
    ("review_advisory", _scan(88, 340, certified=CERTIFIED,
                              advisories=[{"id": "GHSA-1", "affects_scanned_version": True}]),
     False, "not_safe"),
    ("do_not_connect_canary", _scan(92, 340, certified=CERTIFIED, behavioral=_bev(
        [{"rule": "credential_canary_exfiltrated", "severity": "critical"}])),
     False, "not_safe"),
    ("sandbox_pending", _scan(92, 340, certified=CERTIFIED,
                              behavioral={"ran": False, "pending": True, "state": "running"}),
     False, "sandbox_pending"),
    ("score_80", _scan(80, 340, certified=CERTIFIED), False, "score_below_81"),
    ("score_81", _scan(81, 340, certified=CERTIFIED), True, ""),
    ("thin_7_files", _scan(82, 7, certified=CERTIFIED), False, "thin_coverage"),
    ("zero_files", _scan(82, 0, certified=CERTIFIED), False, "thin_coverage"),
    ("files_8", _scan(82, 8, certified=CERTIFIED), True, ""),
    ("no_metadata", {"trust_score": 92, "certified": CERTIFIED}, False, "thin_coverage"),
    ("score_only", {"trust_score": 99}, False, ""),
    ("garbage", {"trust_score": "x", "certified": 3, "metadata": None}, False, ""),
    ("dependency_advisory_only", _scan(84, 340, [_dep("critical")], certified=CERTIFIED),
     True, ""),
    # ── coverage gaps: only the attacker-cheap kinds take the mark off ────────────────
    ("gap_plain_oversized_bundle_keeps_mark", _scan(
        92, 340, [_f("low", "Source file too large to scan in full", category="obfuscation")],
        certified=CERTIFIED, coverage_gaps={"oversized_files": 2}), True, ""),
    ("gap_over_file_cap_keeps_mark", _scan(92, 340, certified=CERTIFIED, coverage_gaps={
        "over_file_cap": 40, "file_cap": 200, "tree_truncated": True}), True, ""),
    ("gap_package_skipped_keeps_mark", _scan(92, 340, certified=CERTIFIED,
                                             coverage_gaps={"package_skipped": 5}), True, ""),
    ("gap_advisory_lookup_keeps_mark", _scan(92, 340, certified=CERTIFIED,
                                             coverage_gaps={"advisory_lookup": "failed"}),
     True, ""),
    ("gap_fetch_failed", _scan(92, 340, certified=CERTIFIED,
                               coverage_gaps={"fetch_failed": 1}), False, "coverage_gaps"),
    ("gap_fetch_failed_string", _scan(92, 340, certified=CERTIFIED,
                                      coverage_gaps={"fetch_failed": "3"}),
     False, "coverage_gaps"),
    ("gap_padded_oversized", _scan(
        92, 340, [_f("medium", "Oversized source file padded with filler",
                     category="obfuscation")],
        certified=CERTIFIED, coverage_gaps={"oversized_files": 1}), False, "coverage_gaps"),
    ("gap_padded_without_gap_key", _scan(
        92, 340, [_f("medium", "Oversized source file padded with filler",
                     category="obfuscation")], certified=CERTIFIED), True, ""),
    ("gap_agent_file_oversized", _scan(92, 340, certified=CERTIFIED, coverage_gaps={
        "oversized_files": 1, "oversized_agent_files": 1}), False, "coverage_gaps"),
    # A partly read tool list now reads Review (#216), so the mark is off as not_safe.
    ("gap_tool_list_paged", _scan(92, 340, certified=CERTIFIED,
                                  coverage_gaps={"tool_list_paged": True}),
     False, "not_safe"),
    ("gap_skill_ref_unread", _scan(92, 340, certified=CERTIFIED,
                                   coverage_gaps={"skill_refs_unread": 1}),
     False, "coverage_gaps"),
    ("gap_skills_ungraded", _scan(92, 340, certified=CERTIFIED,
                                  coverage_gaps={"skills_ungraded": 3}),
     False, "coverage_gaps"),
    ("gap_skill_surface_over_cap", _scan(92, 340, certified=CERTIFIED,
                                         coverage={"surface": "openclaw"},
                                         coverage_gaps={"over_file_cap": 2, "file_cap": 40}),
     False, "coverage_gaps"),
    ("gap_skill_detail_oversized", _scan(92, 340, certified=CERTIFIED,
                                         surface_detail={"surface": "openclaw"},
                                         coverage_gaps={"oversized_files": 1}),
     False, "coverage_gaps"),
    ("gap_thin_wins", _scan(92, 3, certified=CERTIFIED, coverage_gaps={"fetch_failed": 1}),
     False, "thin_coverage"),
    ("gap_garbage", _scan(92, 340, certified=CERTIFIED, coverage_gaps=["fetch_failed"]),
     True, ""),
]


@pytest.mark.parametrize("case_id,data,mark,why", MARK_CASES, ids=[c[0] for c in MARK_CASES])
def test_certified_mark_table(case_id, data, mark, why):
    from src.scanner.verdict import certified_mark, certified_mark_status
    assert certified_mark_status(data) == (mark, why)
    assert certified_mark(data) is mark
    # trust_tiers.is_certified reads the mark (computed here when the field is absent)
    assert is_certified(data) is mark
    # an API response's own field wins
    assert is_certified({**data, "certified_mark": not mark}) is (not mark)


def test_mark_uses_the_passed_decision():
    from src.scanner.verdict import certified_mark
    data = _scan(92, 340, certified=CERTIFIED)
    assert certified_mark(data, Decision("review", True, "x")) is False
    assert certified_mark(data, Decision("safe", False, "x")) is False


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_ts_certified_mark_twin_is_byte_identical():
    payload = json.dumps([c[1] for c in MARK_CASES])
    script = (
        "const m = await import(process.argv[1]);"
        "let s='';process.stdin.on('data',d=>s+=d);process.stdin.on('end',()=>{"
        "const out=JSON.parse(s).map(x=>m.certifiedMarkStatus(x));"
        "process.stdout.write(JSON.stringify(out));});"
    )
    ts = ROOT / "web" / "src" / "components" / "trust" / "gradeSystem.ts"
    proc = subprocess.run(
        ["node", "--no-warnings", "--experimental-strip-types", "--input-type=module",
         "-e", script, str(ts)],
        input=payload, capture_output=True, text=True, timeout=60)
    if proc.returncode != 0 and "strip-types" in proc.stderr:
        pytest.skip("node lacks type stripping")
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout) == [[c[2], c[3]] for c in MARK_CASES]
