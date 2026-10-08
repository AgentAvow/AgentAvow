"""The public scan router's behavioral block: plan selection from the static scan
(``artifact_scan.is_mcp_server`` → the MCP exerciser plan), the docker surface, env
names + README passthrough, the grade summary, the cache key, and the MCP connector's
sandbox section. Same style as test_behavioral_declared_scope.py: the sandbox
runner is replaced by a fake, redis by a dict."""
from __future__ import annotations

import asyncio

import pytest

import src.api.public_scan_router as router
from src.bridges.mcp_streamable import _sandbox_line, _scan_block
from src.scanner.behavioral import runner as behavioral_runner
from src.scanner.behavioral.runner import BehavioralResult
from src.scanner.behavioral.transcript import parse_transcript


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value


@pytest.fixture
def fake_redis(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    return r


def _transcript(**over):
    doc = {
        "version": 1,
        "launch": {"command": ["node", "bin.js"], "ok": True, "startup_ms": 100},
        "tools": [{"name": "read", "annotations": {"readOnlyHint": True}},
                  {"name": "write", "annotations": {}}],
        "calls": [{"tool": "read", "ok": True, "fs_writes": ["/work/leak"]},
                  {"tool": "write", "ok": True, "fs_writes": ["/work/out"]}],
        "canary": {"env_names": ["API_TOKEN"], "seen_in_result": []},
    }
    doc.update(over)
    return parse_transcript(doc)


@pytest.fixture
def captured_runs(monkeypatch):
    """A fake run_behavioral that records EVERY kwarg it receives."""
    calls: list[dict] = []

    async def fake_run(surface, coordinate, **kw):
        calls.append({"surface": surface, "coordinate": coordinate, **kw})
        plan = kw.get("plan") or surface
        transcript = _transcript() if plan.endswith("-mcp") else None
        return BehavioralResult(ran=True, surface=surface, coordinate=coordinate, plan=plan,
                                egress_hosts=["registry.npmjs.org"], transcript=transcript)

    monkeypatch.setattr(behavioral_runner, "run_behavioral", fake_run)
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", True, raising=False)
    return calls


def test_plan_selection_from_static_scan():
    assert router._behavioral_plan({"artifact_scan": {"is_mcp_server": True}}, "npm") == "npm-mcp"
    assert router._behavioral_plan({"surface_detail": {"is_mcp_server": True}}, "pypi") == "pypi-mcp"
    assert router._behavioral_plan({"artifact_scan": {"is_mcp_server": False}}, "npm") is None
    assert router._behavioral_plan({}, "npm") is None
    assert router._behavioral_plan({"artifact_scan": "garbage"}, "npm") is None
    assert router._behavioral_plan({}, "docker") == "docker"
    assert router._behavioral_plan({"artifact_scan": {"is_mcp_server": True}}, "docker") == "docker"


def test_mcp_package_gets_the_exerciser_plan_with_env_names(fake_redis, captured_runs):
    data = {"package_coordinate": {"surface": "npm", "name": "demo-mcp"},
            "artifact_scan": {"is_mcp_server": True},
            "env_reads": ["API_TOKEN", "OTHER", 7, ""],
            "readme_text": "# demo\n"}
    block = asyncio.run(router._behavioral_block(data, force=True))
    assert captured_runs == [{"surface": "npm", "coordinate": "demo-mcp", "expected_hosts": None,
                              "plan": "npm-mcp", "env_names": ["API_TOKEN", "OTHER"],
                              "readme_text": "# demo\n"}]
    assert block["ran"] is True and block["plan"] == "npm-mcp"
    assert block["exercise"]["launch_ok"] is True
    # the readOnly tool wrote /work/leak → graded
    assert [f["rule"] for f in block["findings"]] == ["annotation_readonly_violated"]
    assert block["findings"][0]["evidence"].startswith("read wrote /work/leak")
    gs = block["grade_summary"]
    assert gs["tools_listed"] == 2 and gs["tools_called"] == 2
    assert gs["findings"] == {"critical": 0, "high": 1, "medium": 0, "low": 0, "total": 1}
    assert gs["rules"] == ["annotation_readonly_violated"]


def test_plain_package_keeps_the_old_call_shape(fake_redis, captured_runs):
    data = {"package_coordinate": {"surface": "pypi", "name": "requests"},
            "artifact_scan": {"is_mcp_server": False}}
    block = asyncio.run(router._behavioral_block(data, force=True))
    # no plan / env_names / readme_text kwargs when there is nothing to pass
    assert captured_runs == [{"surface": "pypi", "coordinate": "requests",
                              "expected_hosts": None}]
    assert block["plan"] == "pypi" and block["exercise"] is None
    assert block["findings"] == [] and block["grade_summary"]["findings"]["total"] == 0


def test_docker_surface_runs_image_mode(fake_redis, captured_runs):
    data = {"package_coordinate": {"surface": "docker", "name": "ghcr.io/acme/tool:1.0"}}
    block = asyncio.run(router._behavioral_block(data, force=True))
    assert captured_runs[0]["plan"] == "docker"
    assert captured_runs[0]["coordinate"] == "ghcr.io/acme/tool:1.0"
    assert block["plan"] == "docker" and block["ran"] is True


def test_unsupported_surface_is_still_skipped(fake_redis, captured_runs):
    data = {"package_coordinate": {"surface": "crates", "name": "serde"}}
    assert asyncio.run(router._behavioral_block(data, force=False)) is None
    assert asyncio.run(router._behavioral_block(data, force=True))["ran"] is False
    assert captured_runs == []


def test_cache_key_separates_mcp_plan_from_plain_install(fake_redis, captured_runs):
    plain = {"package_coordinate": {"surface": "npm", "name": "demo-mcp"}}
    mcp = dict(plain, artifact_scan={"is_mcp_server": True})
    asyncio.run(router._behavioral_block(plain, force=True))
    asyncio.run(router._behavioral_block(mcp, force=True))
    assert len(fake_redis.store) == 2
    assert router._behavioral_cache_key("npm", "demo-mcp", None, "npm-mcp") == \
        "behavioral:npm:demo-mcp:npm-mcp"
    assert router._behavioral_cache_key("npm", "demo-mcp", None, "npm") == "behavioral:npm:demo-mcp"
    assert router._behavioral_cache_key("npm", "demo-mcp") == "behavioral:npm:demo-mcp"
    cached = asyncio.run(router._behavioral_block(mcp, force=False))
    assert cached["plan"] == "npm-mcp" and len(captured_runs) == 2


def test_env_reads_flow_through_scan_result_dict_and_response():
    from src.scanner.scan import ScanResult
    r = ScanResult(repo="npm:x", stars=0, description="", framework="")
    assert r.env_reads == []
    r.env_reads = ["API_TOKEN"]
    data = router._scan_result_to_dict(r)
    assert data["env_reads"] == ["API_TOKEN"]
    resp = router._package_response("npm:x", data, jws="j", cached=False)
    assert resp.env_reads == ["API_TOKEN"]
    assert router._behavioral_env_names({"env_reads": "not a list"}) == []


def test_scan_package_env_reads_helper_is_fail_open():
    from dataclasses import dataclass

    from src.scanner.scan import _env_reads_from_artifact

    @dataclass
    class _F:
        path: str
        text: str | None = None

    files = {"index.js": _F("index.js", "process.env.SECRET_KEY; process.env.PATH")}
    assert _env_reads_from_artifact(files) == ["SECRET_KEY"]
    assert _env_reads_from_artifact(None) == []


# ── MCP connector: the sandbox section of the tool result ──────────────────────

def _scan_data(behavioral=None, **kw) -> dict:
    d = {"trust_score": 92, "findings": {"items": [], "total": 0}, "category_scores": {},
         "metadata": {"files_scanned": 40}, "jws": "x", "certified": {},
         "behavioral": behavioral}
    d.update(kw)
    return d


_ATT = {"jws": "eyJ...", "observed_at": "2026-09-30T12:00:00+00:00"}


def _exercised(**kw):
    b = {"ran": True, "plan": "npm-mcp", "egress_hosts": ["registry.npmjs.org", "api.x.com"],
         "vendor_egress": ["api.x.com"], "findings": [], "attestation": _ATT,
         "exercise": {"launch_ok": True, "tools": [{"name": f"t{i}"} for i in range(12)],
                      "calls": [{"tool": f"t{i}", "fs_writes": []} for i in range(9)]
                      + [{"tool": "t0", "fs_writes": ["/tmp/tmpab12cd/cache"]}],
                      "canary": {"env_names": ["X_API_KEY"], "seen_in_result": []}}}
    b.update(kw)
    return b


def _block(b, **kw) -> str:
    return _scan_block(_scan_data(b, **kw), "connect", "/check/pkg/npm/x", "x · npm",
                       install_hint="npm install x")


def test_sandbox_section_absent_without_a_behavioral_block():
    assert _sandbox_line(_scan_data(None)) is None
    assert _sandbox_line({}) is None
    assert _sandbox_line(_scan_data({"ran": False, "reason": "off"})) is None
    text = _scan_block(_scan_data(None), "use", "/check/pkg/npm/x", "x · npm")
    assert "sandbox" not in text.lower()


def test_pending_invites_a_follow_up():
    line = _sandbox_line(_scan_data({"ran": False, "pending": True}))
    assert line == ("**Sandbox:** running now — ask again in about a minute for the observed "
                    "behavior (tools called, network, files).")
    assert "signed" not in line and "static" not in line


def test_clean_exercised_server_reads_what_ran_network_files_credentials():
    lines = _sandbox_line(_scan_data(_exercised())).split("\n")
    assert lines == [
        "**Observed in the sandbox** (gVisor, signed 2026-09-30): started the server and "
        "called 9 of 12 tools with synthetic inputs.",
        "- Network: only api.x.com, registry.npmjs.org (vendor: api.x.com); file writes: "
        "none outside temp/cache dirs; credentials: canary values for X_API_KEY stayed put.",
    ]
    text = _block(_exercised())
    assert text.startswith("✅ Safe to connect")
    # clean: after the (static) findings, before the install line and Next
    assert text.index("Observed in the sandbox") < text.index("Ready to install")
    assert "clean run" not in text


def test_unsigned_block_and_no_egress_and_real_writes():
    b = _exercised(attestation=None, egress_hosts=[], vendor_egress=[])
    b["exercise"]["calls"].append({"tool": "t1", "fs_writes": ["/work/out.txt"]})
    lines = _sandbox_line(_scan_data(b)).split("\n")
    assert lines[0].startswith("**Observed in the sandbox** (gVisor): ")
    assert "network: no connections" in lines[1].lower()
    assert "file writes: 1 outside temp/cache dirs (e.g. /work/out.txt)" in lines[1]


def test_findings_name_the_tool_and_go_before_the_static_findings():
    b = _exercised(findings=[
        {"rule": "behavioral_undeclared_egress", "severity": "high",
         "evidence": "egress to evil.net"},
        {"rule": "annotation_readonly_violated", "severity": "high",
         "evidence": "browser_snapshot wrote /work/x"}], unexpected_egress=["evil.net"],
        egress_hosts=["registry.npmjs.org", "evil.net"])
    items = [{"severity": "medium", "name": "m", "file": "a.js", "line": 1}]
    text = _block(b, findings={"items": items, "total": 1})
    assert "- Caught (high): browser_snapshot declares read-only but wrote /work/x" in text
    assert "- Caught (high): contacted undeclared hosts: evil.net" in text
    assert "Network: undeclared evil.net (plus registry.npmjs.org)" in text
    assert text.index("Observed in the sandbox") < text.index("**Top findings:**")
    assert len(_sandbox_line(_scan_data(b)).split("\n")) <= 6


def test_canary_leak_leads_and_the_headline_is_not_safe():
    b = _exercised(canary_exfil=[{"via": "dns", "host": "c2.evil.net"}], findings=[
        {"rule": "annotation_readonly_violated", "severity": "high",
         "evidence": "a wrote /work/x; b wrote /work/y; c wrote /work/z"},
        {"rule": "credential_canary_exfiltrated", "severity": "critical",
         "evidence": "canary left the sandbox via dns:c2.evil.net"}])
    text = _block(b, behavioral_score_effect={"applied": True, "delta": -20,
                                              "reason": "a credential canary left the sandbox"})
    first = text.split("\n", 1)[0]
    assert first.startswith("⛔ Do not connect — a planted credential left the sandbox. ")
    assert ("Caught in the sandbox: a planted credential left the sandbox "
            "(dns:c2.evil.net)") in first
    assert "Safe" not in first and "clean" not in first.lower()
    sec = _sandbox_line(_scan_data(b, behavioral_score_effect={
        "applied": True, "delta": -20, "reason": "a credential canary left the sandbox"}))
    lines = sec.split("\n")
    assert lines[2] == ("- 🚨 Caught (critical): a planted credential left the sandbox "
                        "(dns:c2.evil.net)")
    assert lines[3] == ("- Caught (high): a declares read-only but wrote /work/x; b declares "
                        "read-only but wrote /work/y; +1 more tools")
    assert lines[-1] == ("- Included in the trust score: −20, a credential canary left the "
                         "sandbox.")
    assert "credentials: canary values" not in sec  # never "stayed put" next to a leak
    assert "Ready to install" not in text and "hold off" in text


def test_canary_hit_without_a_finding_still_alarms():
    b = _exercised(canary_exfil=[{"via": "http", "host": "x.net"}])
    first = _block(b).split("\n", 1)[0]
    assert first.startswith("⛔ Do not connect — a planted credential left the sandbox")
    assert "Caught in the sandbox: " in first


def test_critical_finding_overrides_a_deprecated_or_safe_headline():
    b = _exercised(findings=[{"rule": "behavioral_undeclared_egress", "severity": "critical",
                              "evidence": "egress to a.net, b.net, c.net"}])
    for extra in ({}, {"deprecation": "retired"}):
        first = _block(b, **extra).split("\n", 1)[0]
        assert first.startswith("⛔ Do not connect — the sandbox caught a critical behavior: "
                                "undeclared network call")
        assert "Caught in the sandbox: contacted undeclared hosts: a.net, b.net, c.net" in first
    # a high finding also takes over the headline (it pulls the score below the bar too)
    b["findings"][0]["severity"] = "high"
    first = _block(b).split("\n", 1)[0]
    assert first.startswith("⚠️ Review before you connect — one high finding: undeclared "
                            "network call")
    assert "Caught in the sandbox" in first
    # a medium/low one does not
    b["findings"][0]["severity"] = "low"
    assert _block(b).startswith("✅ Safe to connect")


def test_score_effect_line_only_when_applied():
    b = _exercised()
    assert "trust score" not in _sandbox_line(_scan_data(
        b, behavioral_score_effect={"applied": False, "delta": -20, "reason": "x"}))
    assert "Included in the trust score: −5, a tool wrote files." in _sandbox_line(_scan_data(
        b, behavioral_score_effect={"applied": True, "delta": -5, "reason": "a tool wrote files"}))
    assert "Included in the trust score (no change)." in _sandbox_line(_scan_data(
        b, behavioral_score_effect={"applied": True, "delta": 0}))
    assert _sandbox_line(_scan_data(b, behavioral_score_effect="junk"))  # ignored, no crash


def test_listed_but_not_called():
    b = _exercised()
    b["exercise"]["calls"] = []
    assert "started the server and listed 12 tools; none were called." in _sandbox_line(
        _scan_data(b))


def test_install_only_plans():
    b = {"ran": True, "plan": "npm", "egress_hosts": ["registry.npmjs.org"], "findings": [],
         "exercise": None}
    assert _sandbox_line(_scan_data(b)) == (
        "**Observed in the sandbox** (gVisor): installed and imported it; network: only "
        "registry.npmjs.org.")
    b.update(plan="docker", egress_hosts=[])
    assert "ran the container image; network: no connections." in _sandbox_line(_scan_data(b))
    b.update(plan="pypi", exit_code=1)
    assert "exited with code 1 (not a finding)" in _sandbox_line(_scan_data(b))


# ── start_reason: a server that could not start says why ──────────────────────

def _not_started(reason=None, findings=(), attestation=None, hosts=(), detail=None):
    b = {"ran": True, "plan": "npm-mcp", "egress_hosts": list(hosts), "findings": list(findings),
         "exercise": {"launch_ok": False, "calls": []}}
    if reason is not None:
        b["grade_summary"] = {"start_reason": reason}
        if detail:
            b["grade_summary"]["start_reason_detail"] = detail
    if attestation:
        b["attestation"] = attestation
    return b


@pytest.mark.parametrize("reason,phrase", [
    ("needs_credentials", "it needs credentials (an API key or token) to start"),
    ("needs_arguments", "it needs a startup argument, such as a URL or connection string"),
    ("missing_binary", "a program it depends on is not available in the sandbox"),
    ("no_entrypoint", "the package has no runnable entry point to start"),
    ("resource_limit", "it hit the sandbox memory/process limit before starting"),
    ("install_failed", "the package failed to install"),
    ("timeout", "it did not start within the sandbox time limit"),
    ("crashed", "it exited with an error on start"),
    (None, "the run did not record why"),
    ("unknown", "the run did not record why"),
    ("something_new", "the run did not record why"),
])
def test_not_started_says_why_in_plain_words_and_is_not_a_finding(reason, phrase):
    line = _sandbox_line(_scan_data(_not_started(reason, hosts=["registry.npmjs.org"])))
    first = line.split("\n")[0]
    assert f"the server did not start — {phrase}" in first
    assert first.endswith("Its tools were not exercised; this is not a finding.")
    assert "clean run" not in line
    assert line.split("\n")[1] == "- Network: only registry.npmjs.org (during install)."


def test_server_postgres_needs_a_database_url():
    b = _not_started("needs_arguments", attestation=_ATT, hosts=["registry.npmjs.org"],
                     detail="server_exited: Please provide a database URL as a command-line "
                            "argument")
    text = _block(b, deprecation="Package no longer supported.", package_version="0.6.2",
                  published_at="2024-12-03T18:00:00.000Z")
    assert ("**Observed in the sandbox** (gVisor, signed 2026-09-30): installed it, but the "
            "server did not start — it needs a database URL as a startup argument. Its tools "
            "were not exercised; this is not a finding.") in text
    assert "Version 0.6.2 · published 2024-12-03" in text
    assert "**Deprecated by its maintainer** (latest release 0.6.2, 2024-12-03):" in text
    assert text.startswith("⚠️ Review before you connect — the maintainer has deprecated this "
                           "package.")


def test_crashed_quotes_the_error_excerpt():
    b = _not_started("crashed", detail="server_exited: TypeError: boom")
    assert 'it exited with an error on start ("server_exited: TypeError: boom")' in \
        _sandbox_line(_scan_data(b))


def test_grade_summary_not_a_dict_falls_back():
    b = _not_started()
    b["grade_summary"] = "not-a-dict"
    assert "did not start — the run did not record why." in _sandbox_line(_scan_data(b))


def test_not_started_with_findings_still_lists_them_first():
    b = _not_started("needs_credentials", hosts=["evil.net"], findings=[
        {"rule": "behavioral_undeclared_egress", "severity": "high",
         "evidence": "egress to evil.net"}])
    b["unexpected_egress"] = ["evil.net"]
    text = _block(b)
    assert "- Caught (high): contacted undeclared hosts: evil.net" in text


# ── version + publish date ─────────────────────────────────────────────────────

def test_version_line_sources_and_fallbacks():
    from src.bridges.mcp_streamable import _version_line
    assert _version_line({}) is None
    assert _version_line({"package_version": "1.2.3"}) == "Version 1.2.3"
    assert _version_line({"published_at": "2024-01-02T00:00:00Z"}) == "Published 2024-01-02"
    assert _version_line({"artifact_scan": {"version": "4.0"}}) == "Version 4.0"
    assert _version_line({"surface_detail": {"version": "5.0"},
                          "published_at": "2025-05-05"}) == "Version 5.0 · published 2025-05-05"
    assert _version_line({"package_version": 7, "artifact_scan": "x"}) is None
    text = _block(None, package_version="1.2.3")
    assert text.index("```\nVersion 1.2.3") > 0  # right under the card


def test_repo_without_a_package_targets_git_install_by_language():
    from src.api.public_scan_router import _behavioral_plan, _behavioral_target
    js = {"repo_full_name": "acme/widget", "primary_language": "JavaScript/TypeScript",
          "package_coordinate": {}}
    assert _behavioral_target(js) == ("github", "acme/widget")
    assert _behavioral_plan(js, "github") == "npm-git"
    assert _behavioral_plan({**js, "is_mcp_server": True}, "github") == "npm-git-mcp"
    py = {"repo_full_name": "acme/tool", "primary_language": "Python"}
    assert _behavioral_target(py) == ("github", "acme/tool")
    assert _behavioral_plan(py, "github") == "pypi-git"
    assert _behavioral_target({"repo_full_name": "acme/book", "primary_language": "Rust"}) is None
    # a published package still wins over the repo
    both = {"repo_full_name": "acme/widget", "primary_language": "Python",
            "package_coordinate": {"surface": "npm", "name": "widget"}}
    assert _behavioral_target(both) == ("npm", "widget")



def test_a_high_sandbox_finding_is_never_headlined_clean():
    """Live 2026-10-02: exa-mcp-server (telemetry to api.agnost.ai, high) was headlined
    'Clean, limited coverage — No risks found' with an install prompt."""
    import inspect

    from src.bridges import mcp_streamable as m
    fn = next(v for v in vars(m).values() if callable(v)
              and "Shape a /public/scan response" in (getattr(v, "__doc__", "") or ""))
    data = {"trust_score": 70, "findings": {"critical": 0, "high": 0, "items": []},
            "metadata": {"files_scanned": 5},
            "behavioral": {"ran": True, "plan": "npm-mcp",
                           "unexpected_egress": ["api.agnost.ai"],
                           "egress_hosts": ["api.agnost.ai", "registry.npmjs.org"],
                           "findings": [{"rule": "behavioral_undeclared_egress",
                                         "severity": "high",
                                         "name": "Unexpected network egress during install/run",
                                         "evidence": "egress to api.agnost.ai"}],
                           "exercise": {"launch_ok": True, "tools": [{"name": "a"}],
                                        "calls": [{"tool": "a", "ok": True}]}}}
    required = [p for p in inspect.signature(fn).parameters.values()
                if p.default is inspect.Parameter.empty]
    kwargs = {}
    if "install_hint" in inspect.signature(fn).parameters:
        kwargs["install_hint"] = "npm install exa-mcp-server"
    out = fn(data, *[""] * (len(required) - 1), **kwargs)
    first = out.strip().splitlines()[0]
    assert first.startswith("⚠️ Review before you") and "sandbox" in first, first
    assert "Clean" not in first and "No risks found" not in out
    assert "npm install exa-mcp-server" not in out
