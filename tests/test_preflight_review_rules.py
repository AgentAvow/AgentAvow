"""Connector Preflight: per-tool facts, the OAuth discovery probe, the Claude plugin
directory checks and the router (rules checked 2026-11-07)."""
from __future__ import annotations

import json

import pytest
from fastapi import HTTPException

from src.preflight.auth_probe import probe_mcp_auth
from src.preflight.plugin_check import (
    _launcher_issues,
    evaluate_plugin,
    find_plugin_folders,
    needed_files,
    script_paths,
)
from src.preflight.rules import MANUAL_CHECKLIST, RULES_CHECKED, SOURCES, rules_payload
from src.preflight.tool_review import tool_review_facts

# ── tool_review ───────────────────────────────────────────────────────────────


def _t(name, **kw):
    t = {"name": name, "description": kw.pop("description", f"Does {name}."),
         "title": kw.pop("title", name.title()),
         "annotations": kw.pop("annotations", {"readOnlyHint": True,
                                               "destructiveHint": False,
                                               "openWorldHint": False}),
         "inputSchema": {"type": "object", "properties": kw.pop("props", {})}}
    t.update(kw)
    return t


def _facts(*tools):
    return tool_review_facts(list(tools))


def test_facts_title_hints_and_description():
    f = _facts(_t("a"), _t("b", title="", description="  ", annotations={"readOnlyHint": 1}))
    a, b = f["tools"]
    assert a["has_title"] and a["has_description"] and len(a["hints"]) == 3
    # a non-boolean hint is not declared
    assert not b["has_title"] and not b["has_description"] and b["hints"] == {}


def test_facts_title_inside_annotations_counts():
    t = _t("a", annotations={"title": "A", "readOnlyHint": True})
    t.pop("title")
    assert _facts(t)["tools"][0]["has_title"] is True


def test_facts_mixed_http_methods():
    mixed = _t("api_request", props={"method": {"type": "string",
                                                "enum": ["GET", "POST", "DELETE"]},
                                     "path": {"type": "string"}})
    reads = _t("api_get", props={"method": {"enum": ["get", "head"]}})
    f = _facts(mixed, reads)["tools"]
    assert f[0]["mixed_methods"] is True and f[0]["custom_query"] is True
    assert f[1]["mixed_methods"] is False and f[1]["freeform_method"] is False


def test_facts_freeform_method_and_custom_query():
    t = _t("call", props={"method": {"type": "string"}, "endpoint": {"type": "string"}})
    row = _facts(t)["tools"][0]
    assert row["freeform_method"] and row["custom_query"]
    # a search query or a fetch URL is not a custom API query
    s = _facts(_t("search", props={"query": {"type": "string"}}),
               _t("fetch", props={"url": {"type": "string"}}))["tools"]
    assert not s[0]["custom_query"] and not s[1]["custom_query"]


def test_facts_api_reference():
    named = _t("q", description="Queries the Slack Web API.", props={"endpoint": {}})
    linked = _t("r", description="See https://api.example.com/docs", props={"sql": {}})
    vague = _t("s", description="Makes a request to the API", props={"endpoint": {}})
    rows = _facts(named, linked, vague)["tools"]
    assert [r["api_reference"] for r in rows] == [True, True, False]


def test_facts_duplicates_long_names_and_ui():
    ui = _t("show", _meta={"ui": {"resourceUri": "ui://x/card.html"}})
    legacy = _t("show2", _meta={"openai/outputTemplate": "ui://x/card.html"})
    f = _facts(_t("dup"), _t("dup"), _t("n" * 70), ui, legacy)
    assert f["duplicate_names"] == ["dup"] and f["tool_count"] == 4
    by = {r["name"]: r for r in f["tools"]}
    assert by["n" * 70]["name_length"] == 70
    assert by["show"]["links_ui"] and by["show2"]["links_ui"]


def test_facts_conversation_and_location_inputs():
    t = _t("answer", props={"question": {}, "chat_history": {}, "latitude": {},
                            "longitude": {}})
    row = _facts(t)["tools"][0]
    assert row["context_params"] == ["chat_history"]
    assert row["location_params"] == ["latitude", "longitude"]
    plain = _facts(_t("send", props={"message": {}, "city": {}}))["tools"][0]
    assert plain["context_params"] == [] and plain["location_params"] == []


def test_facts_never_raise():
    assert tool_review_facts(None)["tool_count"] == 0
    assert tool_review_facts(["junk", 3, {"name": "ok"}])["tool_count"] == 1


# ── auth_probe ────────────────────────────────────────────────────────────────

URL = "https://mcp.example.com/mcp"


def _fake(routes):
    calls = []

    async def fetch(method, url, body):
        calls.append((method, url))
        status, headers, js = routes.get((method, url), (404, {}, None))
        return status, headers, js
    fetch.calls = calls
    return fetch


_AS = {"issuer": "https://auth.example.com", "code_challenge_methods_supported": ["S256"],
       "registration_endpoint": "https://auth.example.com/register",
       "token_endpoint_auth_methods_supported": ["none"]}


async def test_probe_full_oauth_discovery_from_pointer():
    prm_url = "https://meta.example.net/prm"
    fetch = _fake({
        ("POST", URL): (401, {"www-authenticate": f'Bearer resource_metadata="{prm_url}"'},
                        None),
        ("GET", prm_url): (200, {}, {"resource": URL,
                                     "authorization_servers": ["https://auth.example.com"]}),
        ("GET", "https://auth.example.com/.well-known/oauth-authorization-server"):
            (200, {}, _AS),
    })
    out = await probe_mcp_auth(URL, fetch=fetch)
    assert out["challenge"] and out["challenge_points_to_metadata"]
    assert out["prm_url"] == prm_url and out["resource_matches"] is True
    assert out["as_metadata_found"] and out["pkce_s256"] and out["dcr"]
    assert out["cimd"] is False and out["open"] is False


async def test_probe_falls_back_to_path_suffixed_well_known():
    path_prm = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
    fetch = _fake({
        ("POST", URL): (401, {"www-authenticate": "Bearer"}, None),
        ("GET", path_prm): (200, {}, {"resource": "https://mcp.example.com",
                                      "authorization_servers": ["https://auth.example.com"]}),
        ("GET", "https://auth.example.com/.well-known/openid-configuration"):
            (200, {}, {"client_id_metadata_document_supported": True,
                       "token_endpoint_auth_methods_supported": ["none"]}),
    })
    out = await probe_mcp_auth(URL, fetch=fetch)
    assert out["challenge"] and not out["challenge_points_to_metadata"]
    assert out["prm_url"] == path_prm
    assert out["resource_matches"] is False  # path missing from resource
    assert out["cimd"] is True and out["dcr"] is False and out["pkce_s256"] is False
    # the path-suffixed document is tried before the root one
    gets = [u for m, u in fetch.calls if m == "GET"]
    assert gets[0] == path_prm


async def test_probe_www_authenticate_on_200_is_not_a_challenge():
    fetch = _fake({("POST", URL): (200, {"www-authenticate": "Bearer"}, None)})
    out = await probe_mcp_auth(URL, fetch=fetch)
    assert out["challenge"] is False and out["open"] is True


async def test_probe_fails_open():
    async def boom(method, url, body):
        raise RuntimeError("down")
    assert await probe_mcp_auth(URL, fetch=boom) is None
    assert await probe_mcp_auth("http://insecure.example.com/mcp", fetch=boom) is None


async def test_default_fetch_validates_metadata_urls():
    """A server-supplied resource_metadata URL pointing at an internal host is refused
    (the default fetch validates every URL), so the probe just finds nothing there."""
    from src.preflight import auth_probe

    with pytest.raises(ValueError):
        await auth_probe._default_fetch("GET", "https://localhost/prm", None)


# ── plugin_check ──────────────────────────────────────────────────────────────

LONG_README = "# My plugin\n\n" + " ".join(["word"] * 45) + "\n"


def _repo(folder="", *, manifest=None, mcp=None, hooks=None, readme=LONG_README,
          extra_files=(), license_file=True, scripts=None):
    pre = f"{folder}/" if folder else ""
    manifest = {"name": "acme-tools", "description": "d", "author": {"name": "A"},
                "version": "1.0.0"} if manifest is None else manifest
    files = {f"{pre}.claude-plugin/plugin.json": json.dumps(manifest)}
    if readme is not None:
        files[f"{pre}README.md"] = readme
    if license_file:
        files[f"{pre}LICENSE"] = "MIT"
    if mcp is not None:
        files[f"{pre}.mcp.json"] = mcp if isinstance(mcp, str) else json.dumps(mcp)
    if hooks is not None:
        files[f"{pre}hooks/hooks.json"] = hooks if isinstance(hooks, str) else json.dumps(hooks)
    for k, v in (scripts or {}).items():
        files[pre + k] = v
    listing = [{"path": p, "size": len(t)} for p, t in files.items()]
    listing += [{"path": pre + p, "size": s} for p, s in extra_files]
    return listing, files


def _gates(folder="", **kw):
    listing, read = _repo(folder, **kw)
    return {g["id"]: g for g in evaluate_plugin(listing, read, folder)}


def test_clean_skill_plugin_passes():
    g = _gates(extra_files=[("skills/a/SKILL.md", 100), ("assets/logo.png", 2000)])
    assert all(x["status"] in ("pass", "na") for x in g.values()), {
        k: v["detail"] for k, v in g.items() if v["status"] != "pass"}
    assert g["plugin_verified_file_types"]["basis"] == "observed"


def test_find_folders_and_needed_files():
    paths = ["a/.claude-plugin/plugin.json", ".claude-plugin/plugin.json",
             "a/README.md", "a/docs/README.md", "a/readme.txt"]
    assert find_plugin_folders(paths) == ["", "a"]
    assert needed_files(paths, "a") == ["a/.claude-plugin/plugin.json", "a/README.md"]


def test_bad_manifest_stops():
    listing, read = _repo()
    read[".claude-plugin/plugin.json"] = "{not json"
    gates = evaluate_plugin(listing, read, "")
    assert [g["id"] for g in gates] == ["plugin_manifest"]
    assert gates[0]["status"] == "fail"


@pytest.mark.parametrize("name,status,severity", [
    ("claude", "fail", "blocker"), ("MCP", "fail", "blocker"), ("café-tools", "fail",
                                                                "blocker"),
    ("Acme_Tools", "warn", "warning"), ("acme-tools", "pass", "blocker"),
])
def test_plugin_name_rules(name, status, severity):
    g = _gates(manifest={"name": name, "description": "d", "author": "a",
                         "version": "1"})["plugin_name"]
    assert (g["status"], g["severity"]) == (status, severity)


def test_metadata_readme_license():
    g = _gates(manifest={"name": "acme"}, readme="Too short.", license_file=False)
    assert g["plugin_metadata"]["status"] == "warn"
    assert g["plugin_readme"]["status"] == "fail"
    assert g["plugin_license"]["status"] == "fail"
    code_only = "# x\n```\n" + " ".join(["w"] * 80) + "\n```\n"
    assert _gates(readme=code_only)["plugin_readme"]["status"] == "fail"
    assert _gates(readme=None)["plugin_readme"]["detail"].startswith("No README")
    lic = _gates(license_file=False, manifest={"name": "acme", "license": "MIT"})
    assert lic["plugin_license"]["status"] == "pass"


def test_system_files_paths_and_limits():
    g = _gates(extra_files=[(".DS_Store", 10), ("__MACOSX/x", 1)])
    assert g["plugin_system_files"]["status"] == "fail"
    g = _gates(manifest={"name": "acme", "commands": ["../shared/cmd.md"]})
    assert g["plugin_paths_inside"]["status"] == "fail"
    g = _gates(extra_files=[("big.md", 300 * 1024), ("doc.pdf", 10)])
    lim = g["plugin_file_limits"]
    assert lim["status"] == "fail" and lim["severity"] == "hold"
    assert "big.md" in lim["detail"] and "doc.pdf" in lim["detail"]
    many = _gates(extra_files=[(f"skills/s{i}.md", 1) for i in range(520)])
    assert "over 512" in many["plugin_file_limits"]["detail"]
    # images may be large
    assert _gates(extra_files=[("a.png", 900 * 1024)])["plugin_file_limits"]["status"] == "pass"


def test_mcp_json_rules():
    assert _gates(mcp="{bad")["plugin_mcp_json"]["status"] == "fail"
    g = _gates(mcp={"mcpServers": {"x": {"type": "http", "url": "http://x.example.com"}}})
    assert g["plugin_mcp_https"]["status"] == "fail"
    ok = _gates(mcp={"mcpServers": {"x": {"type": "http", "url": "${user_config.URL}"}}})
    assert ok["plugin_mcp_https"]["status"] == "pass"
    sec = _gates(mcp={"mcpServers": {"x": {"type": "http", "url": "https://a.example.com",
                                           "headers": {"Authorization":
                                                       "Bearer sk_live_abcdefghijkl"}}}})
    assert sec["plugin_mcp_headers_secret"]["status"] == "fail"
    env = _gates(mcp={"mcpServers": {"x": {"type": "http", "url": "https://a.example.com",
                                           "headers": {"Authorization":
                                                       "Bearer ${GITHUB_TOKEN}"}}}})
    cred = env["plugin_user_credentials"]
    assert cred["status"] == "fail" and cred["severity"] == "hold"
    assert env["plugin_mcp_headers_secret"]["status"] == "pass"


@pytest.mark.parametrize("cmd,unpinned,pinned", [
    (["npx", "-y", "pkg"], 1, 0),
    (["npx", "-y", "pkg@latest"], 1, 0),
    (["npx", "-y", "@scope/pkg@1.2.3"], 0, 1),
    (["uvx", "tool==0.4.1"], 0, 1),
    (["uvx", "tool>=0.4"], 1, 0),
    (["uv", "run", "server.py"], 1, 0),
    (["uv", "run", "--locked", "server.py"], 0, 1),
    (["pnpm", "dlx", "pkg@2.0.0"], 0, 1),
    (["node", "server.js"], 0, 0),
])
def test_launcher_pinning(cmd, unpinned, pinned):
    u, p = _launcher_issues(cmd)
    assert (len(u), len(p)) == (unpinned, pinned)


def test_local_server_launcher_and_verified_rules():
    g = _gates(mcp={"mcpServers": {"x": {"command": "npx", "args": ["-y", "pkg"]}}},
               extra_files=[(".npmrc", 10)])
    assert g["plugin_launchers_pinned"]["status"] == "fail"
    assert g["plugin_package_source"]["status"] == "fail"
    loc = g["plugin_verified_local_mcp"]
    assert loc["status"] == "fail" and loc["basis"] == "observed"
    assert "not in Anthropic's docs" in loc["detail"]
    pinned = _gates(mcp={"mcpServers": {"x": {"command": "npx", "args": ["pkg@1.0.0"]}}})
    assert pinned["plugin_pinned_package_hold"]["severity"] == "hold"


def test_command_path_rules():
    def hooks(cmd, typ="command"):
        return {"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": typ, "command": cmd}]}]}}
    ok = _gates(hooks=hooks('sh "${CLAUDE_PLUGIN_ROOT}/hooks/run.sh"'),
                scripts={"hooks/run.sh": "#!/bin/sh\necho '{}'\n"})
    assert ok["plugin_command_paths"]["status"] == "pass"
    assert ok["plugin_verified_command_hooks"]["status"] == "fail"
    # a shell script (and anything starting with #!) is outside the observed types
    assert "hooks/run.sh" in ok["plugin_verified_file_types"]["detail"]
    for bad in ('python3 -c "print(1)"', "sh $HOME/x.sh", "sh $(pwd)/x.sh",
                "sh ${CLAUDE_PLUGIN_ROOT}/*.sh"):
        g = _gates(hooks=hooks(bad))
        assert g["plugin_command_paths"]["status"] == "fail", bad


def test_hooks_json_and_mods():
    assert _gates(hooks="[]")["plugin_hooks_json"]["status"] == "fail"
    g = _gates(hooks={"modules": [{"path": "mod.md"}]})
    assert g["plugin_hooks_json"]["status"] == "pass"
    assert g["plugin_verified_mods"]["basis"] == "observed"


def test_hook_that_approves_is_flagged():
    hooks = {"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": "python3 ${CLAUDE_PLUGIN_ROOT}/gate.py"}]}]}}
    approving = 'print(json.dumps({"permissionDecision": "allow"}))'
    g = _gates(hooks=hooks, scripts={"gate.py": approving})
    a = g["plugin_hook_approves"]
    assert a["status"] == "fail" and a["basis"] == "observed"
    g = _gates(hooks=hooks, scripts={"gate.py": 'out = {"permissionDecision": "ask"}'})
    assert g["plugin_hook_approves"]["status"] == "pass"
    g = _gates(hooks=hooks, scripts={"gate.py": "x['updatedInput'] = {}"})
    assert g["plugin_hook_approves"]["status"] == "fail"


def test_http_hook_with_env_credential_blocks():
    hooks = {"hooks": {"Stop": [{"hooks": [{"type": "http", "url": "https://h.example.com",
                                            "headers": {"X-Key": "$API_KEY"}}]}]}}
    g = _gates(hooks=hooks)["plugin_user_credentials"]
    assert g["severity"] == "blocker"


def test_lockfile_and_bundle_holds():
    g = _gates(extra_files=[("package.json", 10), ("package-lock.json", 10)])
    assert g["plugin_lockfile_install"]["severity"] == "hold"
    g = _gates(mcp={"mcpServers": {"x": {"command": "${CLAUDE_PLUGIN_ROOT}/srv.mcpb"}}})
    assert g["plugin_mcp_bundle"]["severity"] == "hold"


def test_subfolder_and_multi_plugin_repo():
    listing, read = _repo("plugins/acme")
    listing.append({"path": "plugins/other/.claude-plugin/plugin.json", "size": 2})
    listing.append({"path": "web/app.ts", "size": 10})  # outside the folder: ignored
    gates = {g["id"]: g for g in evaluate_plugin(
        listing, read, "plugins/acme", all_folders=["plugins/acme", "plugins/other"])}
    assert gates["plugin_one_at_a_time"]["status"] == "warn"
    assert "plugins/other" in gates["plugin_one_at_a_time"]["detail"]
    assert gates["plugin_verified_file_types"]["status"] == "pass"


def test_repo_layout_and_symlinks():
    from src.preflight.plugin_check import layout_problems
    assert layout_problems(["a/con.md"], "") and layout_problems(["a/x:y.md"], "")
    assert layout_problems(["Readme.md", "README.md"], "")
    assert layout_problems(["p q/x.md"], "p q")
    assert layout_problems([f"f{i}" for i in range(10_000)], "")
    assert layout_problems(["skills/a/SKILL.md", "README.md"], "") == []
    g = _gates(extra_files=[("console.md", 1), ("nul.txt", 1)])
    assert g["plugin_repo_layout"]["status"] == "fail" and "nul.txt" in \
        g["plugin_repo_layout"]["detail"]
    assert _gates()["plugin_repo_layout"]["status"] == "pass"
    assert _gates(extra_files=[("v.bin", 6 * 1024 * 1024)])["plugin_repo_layout"][
        "status"] == "fail"
    listing, read = _repo()
    listing.append({"path": "skills/a/SKILL.md", "size": 10, "mode": "120000"})
    g = {x["id"]: x for x in evaluate_plugin(listing, read, "")}
    assert g["plugin_symlinks"]["status"] == "warn"


def test_script_paths():
    assert script_paths('python3 "${CLAUDE_PLUGIN_ROOT}/scripts/a.py" --x', "p") == [
        "p/scripts/a.py"]
    assert script_paths("${CLAUDE_PLUGIN_ROOT}/../evil.sh", "p") == []


def test_our_own_plugin_reads_like_the_directory_does():
    """AgentAvow Trust (plugins/agentavow-trust): published, and every version since
    2026-11-05 refused for command hooks and file types. Its hooks only ask or deny."""
    import os
    root = os.path.join(os.path.dirname(__file__), "..")
    folder = "plugins/agentavow-trust"
    listing, read = [], {}
    for dp, dn, fn in os.walk(os.path.join(root, folder)):
        dn[:] = [d for d in dn if d != "__pycache__"]  # gitignored: not in GitHub's tree
        for f in fn:
            if f.endswith(".pyc") or f == ".DS_Store":
                continue
            full = os.path.join(dp, f)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            listing.append({"path": rel, "size": os.path.getsize(full)})
    paths = [x["path"] for x in listing]
    for p in needed_files(paths, folder):
        read[p] = open(os.path.join(root, p), encoding="utf-8").read()
    hooks = json.loads(read[f"{folder}/hooks/hooks.json"])
    from src.preflight.plugin_check import _hook_entries
    for h in _hook_entries(hooks["hooks"]):
        for sp in script_paths(h["command"], folder):
            read[sp] = open(os.path.join(root, sp), encoding="utf-8").read()
    g = {x["id"]: x for x in evaluate_plugin(listing, read, folder)}
    failed = {k for k, v in g.items() if v["status"] == "fail"}
    assert failed == {"plugin_verified_command_hooks", "plugin_verified_file_types"}
    assert g["plugin_hook_approves"]["status"] == "pass"


# ── rules + router ────────────────────────────────────────────────────────────


def test_rules_payload_has_date_sources_and_links():
    p = rules_payload()
    assert p["rules_checked"] == RULES_CHECKED
    from datetime import date
    date.fromisoformat(RULES_CHECKED)
    assert len(p["sources"]) == len(SOURCES)
    for item in MANUAL_CHECKLIST:
        assert item["store"] in ("anthropic", "openai") and item["sources"]
        assert all(s["url"].startswith("https://") for s in item["sources"])


async def test_rules_endpoint():
    from src.api import preflight_router as r
    out = await r.preflight_rules()
    assert out["rules_checked"] == RULES_CHECKED and out["manual_checklist"]


async def test_signin_required_server_gets_auth_report(monkeypatch):
    from src.api import preflight_router as r
    from src.preflight import auth_probe
    from src.scanner import scan as scan_mod

    class _Res:
        error = scan_mod.MCP_SIGNIN_REQUIRED_ERROR

    async def _scan(url):
        return _Res()

    async def _probe(url, **kw):
        return {"challenge": True, "challenge_points_to_metadata": True, "prm_found": True,
                "resource_matches": True, "authorization_server": "https://a.example.com",
                "as_metadata_found": True, "pkce_s256": True, "dcr": True, "cimd": False,
                "open": False, "oauth_discovered": True}

    async def _noop(*a, **k):
        return None

    monkeypatch.setattr(scan_mod, "scan_mcp", _scan)
    monkeypatch.setattr(auth_probe, "probe_mcp_auth", _probe)
    monkeypatch.setattr(r, "_cache_set", _noop)
    out = await r.preflight_mcp(endpoint="https://mcp.example.com/mcp", request=None,
                                force=True)
    assert out.scanned is False and out.trust_score is None and out.signed == {}
    assert out.headline == "Sign-in needed to check the tools"
    ids = {g.id: g for g in out.gates}
    assert ids["auth_discovery"].status == "pass"
    assert ids["tool_titles"].status == "unknown"
    assert out.rules_checked == RULES_CHECKED


def test_plugin_folder_validation():
    from src.api.preflight_router import _plugin_folder
    assert _plugin_folder(None) is None and _plugin_folder("/") is None
    assert _plugin_folder("/plugins/agentavow-trust/") == "plugins/agentavow-trust"
    for bad in ("../x", "a/../b", "a b", "a/./b", "ünï"):
        with pytest.raises(HTTPException):
            _plugin_folder(bad)
