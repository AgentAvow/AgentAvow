"""The public scan router's behavioral block: plan selection from the static scan
(``artifact_scan.is_mcp_server`` → the MCP exerciser plan), the docker surface, env
names + README passthrough, the grade summary, the cache key, and the MCP connector's
one-line sandbox summary. Same style as test_behavioral_declared_scope.py: the sandbox
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


# ── MCP connector: one compact sandbox line ────────────────────────────────────

def _scan_data(behavioral=None) -> dict:
    return {"trust_score": 92, "findings": {"items": [], "total": 0}, "category_scores": {},
            "metadata": {"files_scanned": 40}, "jws": "x", "certified": {},
            "behavioral": behavioral}


def test_sandbox_line_absent_without_a_behavioral_block():
    assert _sandbox_line(_scan_data(None)) is None
    assert _sandbox_line({}) is None
    assert _sandbox_line(_scan_data({"ran": False, "reason": "off"})) is None
    text = _scan_block(_scan_data(None), "use", "/check/pkg/npm/x", "x · npm")
    assert "Sandbox:" not in text


def test_sandbox_line_pending():
    line = _sandbox_line(_scan_data({"ran": False, "pending": True}))
    assert line.startswith("Sandbox:") and "in progress" in line


def test_sandbox_line_with_findings_and_tools():
    b = {"ran": True, "egress_hosts": ["registry.npmjs.org", "evil.net"],
         "exercise": {"launch_ok": True,
                      "calls": [{"tool": "a"}, {"tool": "b"}, {"tool": "a"}]},
         "findings": [{"name": "Unexpected network egress during install/run",
                       "rule": "behavioral_undeclared_egress"},
                      {"rule": "annotation_readonly_violated"}]}
    line = _sandbox_line(_scan_data(b))
    assert line == ("Sandbox: ran 2 tools in gVisor; 2 behavioral findings: "
                    "Unexpected network egress during install/run, annotation_readonly_violated")
    text = _scan_block(_scan_data(b), "use", "/check/pkg/npm/x", "x · npm")
    assert text.count("Sandbox:") == 1
    assert text.index("Sandbox:") < text.index("Full report:")


def test_sandbox_line_clean_run_lists_egress_or_none():
    b = {"ran": True, "egress_hosts": ["registry.npmjs.org"], "findings": [], "exercise": None}
    assert _sandbox_line(_scan_data(b)) == (
        "Sandbox: clean run (install/run observed in gVisor), egress only to registry.npmjs.org")
    b = {"ran": True, "egress_hosts": [], "findings": [],
         "exercise": {"launch_ok": True, "calls": [{"tool": "only"}]}}
    assert _sandbox_line(_scan_data(b)) == (
        "Sandbox: clean run (ran 1 tool in gVisor), no network egress")
    b = {"ran": True, "egress_hosts": [], "findings": [],
         "exercise": {"launch_ok": False, "calls": []}}
    assert "failed to start" in _sandbox_line(_scan_data(b))
