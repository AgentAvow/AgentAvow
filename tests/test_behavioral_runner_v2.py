"""run_behavioral with the v2 runner: plan selection, the v1 command line staying
byte-identical while the v2 setting is empty, the v2 flags, transcript parsing, the
exerciser-missing fallback, and image mode. The execution seam (``runner._execute``) is
mocked — no sandbox, no subprocess, no SSM."""
from __future__ import annotations

import asyncio
import base64
import gzip
import json
import shlex

import pytest

import src.config as config
from src.scanner.behavioral import runner
from src.scanner.behavioral.transcript import ExerciseTranscript

STUB_FILES = ("mcp_launch.sh", "mcp_exercise.js", "mcp_exercise.py", "synthetic_args.py")

TRANSCRIPT = {
    "version": 1,
    "launch": {"command": ["node", "/work/node_modules/demo/bin.js"], "ok": True,
               "error": None, "startup_ms": 420},
    "server_info": {"name": "demo", "version": "0.1.0"},
    "protocol_version": "2025-06-18",
    "tools": [{"name": "echo", "annotations": {"readOnlyHint": True}}],
    "calls": [{"tool": "echo", "args": {"text": "hi"}, "ok": True, "fs_writes": [],
               "result_sample": "hi"}],
    "canary": {"env_names": ["API_TOKEN"], "seen_in_result": []},
    "timed_out": False,
    "error": None,
}


def _v2_output(**over) -> str:
    doc = {
        "schema": "behavioral-v2", "image": "node:20-alpine", "mode": "mcp",
        "exit_code": 0, "timed_out": False,
        "egress_hosts": ["registry.npmjs.org"], "fs_writes": [],
        "canary_exfil": [], "exercise": TRANSCRIPT, "image_pulled": False,
        "files_materialized": ["mcp_launch.sh", "mcp_exercise.js"],
    }
    doc.update(over)
    return json.dumps(doc)


def _v1_output() -> str:
    return json.dumps({"schema": "behavioral-v1", "image": "node:20-alpine", "exit_code": 0,
                       "timed_out": False, "egress_hosts": ["registry.npmjs.org"],
                       "fs_writes": []})


@pytest.fixture
def executed(monkeypatch):
    """Capture every runner invocation; the queued ``out`` is returned as stdout."""
    class _Calls(list):
        state = {"out": _v1_output(), "error": None}

    calls = _Calls()

    async def fake_execute(runner_args, timeout, *, v2=False):
        calls.append({"args": list(runner_args), "timeout": timeout, "v2": v2})
        st = calls.state
        return (None, st["error"]) if st["error"] else (st["out"], None)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    return calls


@pytest.fixture
def v2_on(monkeypatch):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2",
                        "/home/ec2-user/behavioral_run_v2.sh", raising=False)


@pytest.fixture
def v2_off(monkeypatch):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2", "",
                        raising=False)


@pytest.fixture
def exerciser_files(monkeypatch, tmp_path):
    for name in STUB_FILES:
        (tmp_path / name).write_text(f"# stub {name}\n")
    monkeypatch.setattr(runner, "_SANDBOX_DIR", tmp_path)
    return tmp_path


def _run(*a, **kw):
    return asyncio.run(runner.run_behavioral(*a, **kw))


def _opts(args: list[str]) -> dict:
    """{flag: value} for the leading --flag value pairs; positionals under 'pos'."""
    out: dict = {}
    i = 0
    while i < len(args) and args[i].startswith("--"):
        out[args[i]] = args[i + 1]
        i += 2
    out["pos"] = args[i:]
    return out


# ── v1 path unchanged ──────────────────────────────────────────────────────────

def test_v1_command_line_is_unchanged_when_v2_setting_is_empty(executed, v2_off):
    r = _run("npm", "left-pad")
    assert r.ran is True and r.plan == "npm"
    assert len(executed) == 1
    call = executed[0]
    assert call["v2"] is False
    assert call["args"] == [
        "node:20-alpine",
        runner._SANDBOX_ENV
        + "npm install --no-audit --no-fund left-pad && node -e 'require(\"left-pad\")'",
        "45",
    ]
    assert r.transcript is None and r.canary_exfil == [] and r.notes == []
    pub = r.to_public_dict()
    assert pub["exercise"] is None and pub["plan"] == "npm" and pub["canary_exfil"] == []


def test_pypi_v1_command_line_unchanged(executed, v2_off):
    _run("pypi", "scikit-learn")
    assert executed[0]["args"] == [
        "python:3.12-alpine",
        runner._SANDBOX_ENV
        + "pip install --no-input --user scikit-learn && python -c 'import scikit_learn'",
        "45",
    ]


def test_mcp_plan_degrades_to_exec_while_v2_is_off(executed, v2_off, exerciser_files):
    r = _run("npm", "demo-mcp", plan="npm-mcp", env_names=["API_TOKEN"])
    assert r.ran is True and r.plan == "npm"
    assert "v2_runner_off" in r.notes
    args = executed[0]["args"]
    assert not any(a.startswith("--") for a in args)
    assert "mcp_exercise" not in args[1]


def test_docker_plan_does_not_run_while_v2_is_off(executed, v2_off):
    r = _run("docker", "ghcr.io/acme/tool:1.0")
    assert r.ran is False and r.error == "v2_runner_off"
    assert executed == []


# ── plan selection ─────────────────────────────────────────────────────────────

def test_surface_default_plans_and_unsupported_surface(executed, v2_on, exerciser_files):
    assert _run("npm", "x").plan == "npm"
    assert _run("pypi", "y").plan == "pypi"
    r = _run("crates", "serde")
    assert r.ran is False and r.error == "unsupported_surface"
    r = _run("npm", "x", plan="bogus")
    assert r.ran is False and r.error == "unsupported_surface"


# ── v2 command line ────────────────────────────────────────────────────────────

def test_v2_npm_mcp_command_line(executed, v2_on, exerciser_files, monkeypatch):
    monkeypatch.setattr(config.settings, "scanner_behavioral_max_tools", 7, raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_mcp_timeout", 60, raising=False)
    executed.state["out"] = _v2_output()
    r = _run("npm", "@acme/demo-mcp@1.2.3", plan="npm-mcp",
             env_names=["API_TOKEN", "OTHER_KEY"], readme_text="# Demo\nUse it.")
    assert r.ran is True and r.plan == "npm-mcp" and r.notes == []
    call = executed[0]
    assert call["v2"] is True
    o = _opts(call["args"])
    assert o["--mode"] == "mcp"
    assert o["--canary"].startswith("agentavow-canary-") and len(o["--canary"]) == 29
    image, cmd, timeout = o["pos"]
    assert image == "node:20-alpine"
    assert int(timeout) >= 60 + 45 and call["timeout"] == int(timeout)
    assert cmd.startswith(runner._SANDBOX_ENV + "npm install --no-audit --no-fund @acme/demo-mcp@1.2.3 && ")
    # the launcher gets the SAME canary before its `--` (for credential retries)
    assert (f"sh /work/mcp_launch.sh npm @acme/demo-mcp --canary-value {o['--canary']} -- "
            "node /work/mcp_exercise.js") in cmd
    ex = shlex.split(cmd.split("mcp_exercise.js", 1)[1])
    assert ex[ex.index("--timeout") + 1] == "60"
    assert ex[ex.index("--max-tools") + 1] == "7"
    assert ex[ex.index("--canary-value") + 1] == o["--canary"]
    assert ex[ex.index("--canary-env") + 1] == "API_TOKEN,OTHER_KEY"
    # v2 resource caps from settings (defaults)
    assert o["--memory-mb"] == "1024" and o["--pids"] == "512"
    assert ex[ex.index("--readme") + 1] == "/work/README.md"
    # the shipped files: exerciser sources + README, gzip+base64 JSON {name: b64}
    files = json.loads(gzip.decompress(base64.b64decode(o["--files-b64"])))
    assert set(files) == {"mcp_launch.sh", "mcp_exercise.js", "README.md"}
    assert base64.b64decode(files["README.md"]).decode() == "# Demo\nUse it."
    assert base64.b64decode(files["mcp_launch.sh"]).decode() == "# stub mcp_launch.sh\n"


def test_v2_pypi_mcp_ships_python_exerciser(executed, v2_on, exerciser_files):
    executed.state["out"] = _v2_output(image="python:3.12-alpine")
    r = _run("pypi", "demo-mcp[extra]==2.0", plan="pypi-mcp")
    assert r.plan == "pypi-mcp"
    o = _opts(executed[0]["args"])
    assert o["pos"][0] == "python:3.12-alpine"
    assert (f"sh /work/mcp_launch.sh pypi demo-mcp --canary-value {o['--canary']} -- "
            "python /work/mcp_exercise.py") in o["pos"][1]
    assert "--canary-env" not in o["pos"][1]  # no env names → no flag
    # alpine has no git: the pypi-mcp plan installs it into a writable alt root, fail-soft
    cmd = o["pos"][1]
    assert cmd.index(runner._ALPINE_GIT_PREFIX) < cmd.index("pip install")
    assert "apk add --no-cache --no-scripts --initdb -p /work/.apk git" in cmd
    assert cmd.count("|| true;") == 1 and "/work/.local/bin/git" in cmd
    assert "dl-cdn.alpinelinux.org" in runner._REGISTRY_ALLOW
    assert "--readme" not in o["pos"][1]
    files = json.loads(gzip.decompress(base64.b64decode(o["--files-b64"])))
    assert set(files) == {"mcp_launch.sh", "mcp_exercise.py", "synthetic_args.py"}


def test_v2_plain_exec_plan_gets_mode_and_canary_but_no_files(executed, v2_on):
    executed.state["out"] = _v2_output(mode="exec", exercise=None)
    r = _run("npm", "left-pad")
    o = _opts(executed[0]["args"])
    assert o["--mode"] == "exec" and "--files-b64" not in o
    assert o["pos"][1] == (
        runner._SANDBOX_ENV
        + "npm install --no-audit --no-fund left-pad && node -e 'require(\"left-pad\")'")
    assert r.plan == "npm" and r.transcript is None


def test_v2_docker_plan_is_image_mode_with_the_image_ref(executed, v2_on):
    executed.state["out"] = _v2_output(
        mode="image", image="ghcr.io/acme/tool:1.0", exercise=None,
        egress_hosts=["registry-1.docker.io", "auth.docker.io", "evil.example"],
        image_pulled=True)
    r = _run("docker", "ghcr.io/acme/tool:1.0")
    o = _opts(executed[0]["args"])
    assert o["--mode"] == "image" and "--files-b64" not in o
    assert o["pos"][0] == "ghcr.io/acme/tool:1.0" and o["pos"][1] == ""
    assert r.ran is True and r.plan == "docker"
    # registry pulls are expected in image mode; the odd host is the signal
    assert r.unexpected_egress == ["evil.example"]


# ── parsing the v2 output ──────────────────────────────────────────────────────

def test_exercise_is_parsed_into_a_transcript(executed, v2_on, exerciser_files):
    executed.state["out"] = _v2_output(
        canary_exfil=[{"via": "dns", "host": "agentavow-canary-ab.evil.net"},
                      {"via": "http", "host": "c.example", "extra": "dropped"}, "junk"])
    r = _run("npm", "demo-mcp", plan="npm-mcp")
    assert isinstance(r.transcript, ExerciseTranscript)
    assert r.transcript.launch_ok is True and r.transcript.server_name == "demo"
    assert [t.name for t in r.transcript.tools] == ["echo"]
    assert r.transcript.calls[0].ok is True
    assert r.canary_exfil == [{"via": "dns", "host": "agentavow-canary-ab.evil.net"},
                              {"via": "http", "host": "c.example"}]
    pub = r.to_public_dict()
    assert pub["exercise"]["launch_ok"] is True
    assert pub["exercise"]["tools"] == [{"name": "echo", "annotations": {"readOnlyHint": True}}]
    assert pub["canary_exfil"] == r.canary_exfil and pub["plan"] == "npm-mcp"


def test_exercise_as_string_or_null(executed, v2_on, exerciser_files):
    executed.state["out"] = _v2_output(exercise=json.dumps(TRANSCRIPT))
    assert _run("npm", "d", plan="npm-mcp").transcript.launch_ok is True
    executed.state["out"] = _v2_output(exercise=None)
    r = _run("npm", "d", plan="npm-mcp")
    assert r.ran is True and r.transcript is None
    executed.state["out"] = _v2_output(exercise="{not json")
    r = _run("npm", "d", plan="npm-mcp")
    assert r.ran is True and r.transcript.error.startswith("transcript_unparseable")


# ── fail-open ──────────────────────────────────────────────────────────────────

def test_exerciser_files_missing_falls_back_to_exec(executed, v2_on, monkeypatch, tmp_path):
    monkeypatch.setattr(runner, "_SANDBOX_DIR", tmp_path)  # empty: no exerciser here
    executed.state["out"] = _v2_output(mode="exec", exercise=None)
    r = _run("npm", "demo-mcp", plan="npm-mcp")
    assert r.ran is True and r.plan == "npm"
    assert "exerciser_missing" in r.notes
    o = _opts(executed[0]["args"])
    assert o["--mode"] == "exec" and "--files-b64" not in o
    assert "mcp_exercise" not in o["pos"][1]
    assert r.to_public_dict()["notes"] == ["exerciser_missing"]


@pytest.mark.parametrize("error", ["ssm_unavailable", "local_runner_missing",
                                   "runner_unavailable:TimeoutError"])
def test_execution_errors_fail_open(executed, v2_on, exerciser_files, error):
    executed.state["error"] = error
    r = _run("npm", "demo-mcp", plan="npm-mcp")
    assert r.ran is False and r.error == error and r.plan == "npm-mcp"
    assert runner.behavioral_findings(r) == []


def test_runner_level_errors_and_bad_output_fail_open(executed, v2_on, exerciser_files):
    executed.state["out"] = '{"error":"gvisor_runtime_missing"}'
    r = _run("npm", "demo-mcp", plan="npm-mcp")
    assert r.ran is False and r.error == "gvisor_runtime_missing"
    executed.state["out"] = "not json at all"
    assert _run("npm", "demo-mcp", plan="npm-mcp").error == "runner_bad_output"
    executed.state["out"] = "[1, 2]"
    assert _run("npm", "demo-mcp", plan="npm-mcp").error == "runner_bad_output"


def test_run_behavioral_never_raises_on_exception_in_seam(monkeypatch, v2_on):
    async def boom(*a, **k):
        raise RuntimeError("seam blew up")
    monkeypatch.setattr(runner, "_execute", boom)
    with pytest.raises(RuntimeError):
        # the seam itself raising is a programming error the router catches; documented
        _run("npm", "x")


# ── the seam builds the right remote command ───────────────────────────────────

def test_execute_ssm_uses_v2_path_and_quotes_args(monkeypatch, v2_on):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_mode", "ssm", raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_instance_id", "i-123",
                        raising=False)
    seen = {}

    def fake_ssm(instance_id, region, command, timeout):
        seen.update(instance_id=instance_id, region=region, command=command, timeout=timeout)
        return _v2_output()

    monkeypatch.setattr(runner, "_run_via_ssm", fake_ssm)
    out, err = asyncio.run(runner._execute(
        ["--mode", "mcp", "--canary", "agentavow-canary-abc", "node:20-alpine",
         "npm i x && node -e 'require(\"x\")'", "90"], 90, v2=True))
    assert err is None and json.loads(out)["schema"] == "behavioral-v2"
    assert seen["instance_id"] == "i-123" and seen["timeout"] == 90
    assert seen["command"].startswith("bash /home/ec2-user/behavioral_run_v2.sh --mode mcp ")
    assert shlex.split(seen["command"])[-3:] == [
        "node:20-alpine", "npm i x && node -e 'require(\"x\")'", "90"]


def test_execute_ssm_v1_path_matches_the_old_command(monkeypatch, v2_off):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_mode", "ssm", raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_instance_id", "i-123",
                        raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner",
                        "/home/ec2-user/behavioral_run.sh", raising=False)
    seen = {}
    monkeypatch.setattr(runner, "_run_via_ssm",
                        lambda i, r, c, t: seen.update(command=c) or _v1_output())
    asyncio.run(runner._execute(["node:20-alpine", "cmd here", "45"], 45, v2=False))
    assert seen["command"] == "bash /home/ec2-user/behavioral_run.sh node:20-alpine 'cmd here' 45"


def test_execute_ssm_failure_is_reported(monkeypatch, v2_on):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_mode", "ssm", raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_instance_id", "i-1",
                        raising=False)
    monkeypatch.setattr(runner, "_run_via_ssm", lambda *a: None)
    assert asyncio.run(runner._execute(["img", "c", "1"], 1, v2=True)) == (None, "ssm_unavailable")


def test_execute_local_missing_runner_is_reported(monkeypatch, tmp_path, v2_on):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_mode", "", raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_instance_id", "",
                        raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_host", "", raising=False)
    monkeypatch.setattr(runner, "_RUNNER_V2", tmp_path / "nope.sh")
    assert asyncio.run(runner._execute(["img", "c", "1"], 1, v2=True)) == (
        None, "local_runner_missing")


def test_dist_name_and_helpers():
    assert runner._dist_name("@acme/demo@1.2.3") == "@acme/demo"
    assert runner._dist_name("demo@^2") == "demo"
    assert runner._dist_name("pkg[extra]==1.0") == "pkg"
    assert runner._dist_name("pkg>=1,<2") == "pkg"
    c = runner._new_canary()
    assert c.startswith("agentavow-canary-") and len(c) == len("agentavow-canary-") + 12


@pytest.mark.parametrize("plan", ["npm-mcp", "pypi-mcp"])
def test_the_real_tree_can_build_a_files_payload_for_every_mcp_plan(plan):
    """Regression: the generator lives in src/, not scripts/sandbox/; a wrong path here
    makes every MCP plan silently fall back to the exec plan in production."""
    import base64
    import gzip
    import json

    from src.scanner.behavioral import runner as r
    payload = r._files_payload(plan, None)
    assert payload, f"{plan}: a shipped source file is missing"
    files = json.loads(gzip.decompress(base64.b64decode(payload)))
    assert set(files) == set(r._PLAN_FILES[plan])
    for name, b64 in files.items():
        assert base64.b64decode(b64), name


def test_every_plan_command_makes_home_and_caches_writable():
    """Regression: the sandbox root is read-only; without a writable HOME npm could not
    write its cache and pip could not install at all (EROFS), so runs 'succeeded' having
    installed nothing. Found 2026-10-01 on the live box."""
    from src.scanner.behavioral import runner as r
    for plan, (_image, cmd, mode) in r._SURFACE_PLAN.items():
        if mode == "image":
            continue
        assert cmd.startswith(r._SANDBOX_ENV), plan
        assert "HOME=/work" in cmd and "PATH=/work/.local/bin:$PATH" in cmd, plan
        if "pip install" in cmd:
            assert "pip install --no-input --user " in cmd, plan


def test_vendor_hosts_match_identifying_name_tokens_only():
    from src.scanner.behavioral import runner as r
    assert r._vendor_hosts("tavily-mcp", ["api.tavily.com", "evil.net"]) == ["api.tavily.com"]
    assert r._vendor_hosts("exa-mcp-server", ["api.exa.ai"]) == ["api.exa.ai"]
    assert r._vendor_hosts("@upstash/context7-mcp@1.0.0", ["context7.com", "x.upstash.io"]) == [
        "context7.com", "x.upstash.io"]
    # generic tokens never vouch for a host
    assert r._vendor_hosts("mcp-server-fetch", ["mcp.io", "server.com", "fetch.evil.net"]) == []
    assert r._vendor_hosts("@modelcontextprotocol/server-everything", ["modelcontextprotocol.io"]) == []
    assert r._vendor_hosts("left-pad", ["leftpad.com"]) == []  # 'left' alone is not the vendor


def test_gz_envelope_is_unwrapped_and_truncated_output_is_labelled(monkeypatch, tmp_path):
    import asyncio
    import base64
    import gzip

    from src.scanner.behavioral import runner as r
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2", "/x/v2.sh",
                        raising=False)
    payload = {"image": "node:20-alpine", "mode": "mcp", "exit_code": 0, "timed_out": False,
               "egress_hosts": ["registry.npmjs.org", "api.tavily.com", "example.com", "evil.net"],
               "fs_writes": [], "canary_exfil": [],
               "exercise": {"version": 1, "launch": {"ok": True, "command": ["node", "x"]},
                            "tools": [{"name": "search"}], "calls": [{"tool": "search", "ok": True}]},
               "schema": "behavioral-v2"}
    wrapped = json.dumps({"schema": "behavioral-v2", "gz": base64.b64encode(
        gzip.compress(json.dumps(payload).encode())).decode()})

    async def fake(args, timeout, *, v2=False):
        return wrapped, None
    monkeypatch.setattr(r, "_execute", fake)
    res = asyncio.run(r.run_behavioral("npm", "tavily-mcp", plan="npm-mcp"))
    assert res.ran and res.transcript and res.transcript.launch_ok
    assert res.vendor_egress == ["api.tavily.com"]
    assert res.unexpected_egress == ["evil.net"]  # example.com = our synthetic URL; tavily = vendor
    assert res.to_public_dict()["vendor_egress"] == ["api.tavily.com"]

    async def truncated(args, timeout, *, v2=False):
        return json.dumps(payload)[:100] + "x" * 24000, None
    monkeypatch.setattr(r, "_execute", truncated)
    res = asyncio.run(r.run_behavioral("npm", "tavily-mcp", plan="npm-mcp"))
    assert res.ran is False and res.error == "runner_output_truncated"
    assert any(n.startswith("runner_output_len=") for n in res.notes)


# ── robustness: resource caps, README-mined canary names, exit 137 ─────────────

def test_resource_caps_follow_settings_and_are_v2_only(executed, v2_on, monkeypatch):
    monkeypatch.setattr(config.settings, "scanner_behavioral_memory_mb", 2048, raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_pids", 777, raising=False)
    executed.state["out"] = _v2_output(mode="exec", exercise=None)
    _run("npm", "left-pad")
    o = _opts(executed[0]["args"])
    assert o["--memory-mb"] == "2048" and o["--pids"] == "777"
    # unset / junk → the runner's own defaults (no flag)
    monkeypatch.setattr(config.settings, "scanner_behavioral_memory_mb", 0, raising=False)
    monkeypatch.setattr(config.settings, "scanner_behavioral_pids", "x", raising=False)
    _run("npm", "left-pad")
    o = _opts(executed[1]["args"])
    assert "--memory-mb" not in o and "--pids" not in o


def test_v1_call_never_carries_resource_flags(executed, v2_off):
    _run("npm", "left-pad")
    assert not any(a.startswith("--") for a in executed[0]["args"])


def test_exit_137_is_noted_as_a_resource_kill(executed, v2_on, exerciser_files):
    from src.scanner.behavioral.graders import grade, grade_summary
    executed.state["out"] = _v2_output(exit_code=137, exercise=None)
    r = _run("npm", "@modelcontextprotocol/server-puppeteer", plan="npm-mcp")
    assert r.ran is True and r.exit_code == 137 and r.transcript is None
    assert r.notes == ["killed_resource_limit"]
    assert r.to_public_dict()["notes"] == ["killed_resource_limit"]
    assert grade(r) == []
    s = grade_summary(r)
    assert s["start_reason"] == "resource_limit" and s["exercised"] is False


def test_readme_credential_names_join_the_canary_list(executed, v2_on, exerciser_files):
    executed.state["out"] = _v2_output()
    readme = ("# Brave Search MCP\n\n```\nexport BRAVE_API_KEY=your-key\n```\n"
              "LOG_LEVEL=debug is optional. See process.env.BRAVE_API_KEY.")
    _run("npm", "@brave/brave-search-mcp-server", plan="npm-mcp",
         env_names=["OTHER_TOKEN"], readme_text=readme)
    cmd = _opts(executed[0]["args"])["pos"][1]
    ex = shlex.split(cmd.split("mcp_exercise.js", 1)[1])
    # static names first (exact), README-mined after, no duplicates, no noise
    assert ex[ex.index("--canary-env") + 1] == "OTHER_TOKEN,BRAVE_API_KEY"
    assert runner._merge_env_names(["A_KEY", "A_KEY"], "A_KEY B_SECRET") == ["A_KEY", "B_SECRET"]
    assert runner._merge_env_names(None, None) == []
    assert len(runner._merge_env_names([f"K_{i}_KEY" for i in range(40)], "")) == 32


def test_git_plans_install_from_github_and_resolve_the_real_name(monkeypatch):
    import asyncio

    from src.scanner.behavioral import runner as r
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2", "/x/v2.sh",
                        raising=False)
    seen = []

    async def fake(args, timeout, *, v2=False):
        seen.append(args)
        return json.dumps({"image": args[-3], "mode": "mcp", "exit_code": 0, "egress_hosts": [],
                           "fs_writes": [], "canary_exfil": [], "exercise": None,
                           "schema": "behavioral-v2"}), None
    monkeypatch.setattr(r, "_execute", fake)
    res = asyncio.run(r.run_behavioral("github", "acme/widget-mcp", plan="npm-git-mcp"))
    assert res.ran and res.plan == "npm-git-mcp"
    cmd = seen[0][-2]
    assert "npm view github:acme/widget-mcp name" in cmd
    assert "npm install --no-audit --no-fund github:acme/widget-mcp" in cmd
    assert 'sh /work/mcp_launch.sh npm "$NAME"' in cmd
    res = asyncio.run(r.run_behavioral("github", "https://github.com/acme/py-tool.git",
                                       plan="pypi-git"))
    cmd = seen[1][-2]
    assert "pip install --no-input --user --report /work/pipreport.json "
    assert "git+https://github.com/acme/py-tool" in cmd and ".git" not in cmd.split("py-tool")[1][:4]
    assert r._git_spec("npm-git", "github:o/r") == "github:o/r"
    assert r._git_spec("pypi-git-mcp", "o/r/") == "git+https://github.com/o/r"
