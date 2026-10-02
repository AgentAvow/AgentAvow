"""OpenClaw / Agent Skills as a behavioral-sandbox surface: the ``skill`` plan's container
command and runner flags, the router targeting a skill scan at it, the in-container
exerciser's transcript (run for real against the fixture skills — no sandbox, no network),
the start-reason classifier, the skill-only ``skill_script_egress`` grader over stub
transcripts, and the MCP connector's wording. The execution seam is mocked everywhere a
sandbox would be needed."""
from __future__ import annotations

import asyncio
import base64
import gzip
import json
import os
import pathlib
import shlex
import subprocess
import tempfile

import pytest

import src.api.public_scan_router as router
import src.config as config
from src.bridges.mcp_streamable import _sandbox_section
from src.scanner.behavioral import runner
from src.scanner.behavioral.graders import classify_start, grade, grade_summary
from src.scanner.behavioral.runner import BehavioralResult
from src.scanner.behavioral.transcript import extract_transcript_json, parse_transcript

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "sandbox" / "skill_exercise.sh"
SKILLS = ROOT / "tests" / "fixtures" / "behavioral" / "skills"

SKILL_TRANSCRIPT = {
    "version": 1,
    "launch": {"command": ["git", "clone", "--depth", "1", "https://github.com/acme/notes",
                           "/work/skill"], "ok": True, "error": None, "startup_ms": 0},
    "server_info": {"name": "notes", "version": "abc1234"},
    "protocol_version": "skill-v1",
    "tools": [{"name": "scripts/setup.sh", "description": "script: sh scripts/setup.sh",
               "annotations": {"kind": "script"}, "input_schema": None}],
    "calls": [{"tool": "scripts/setup.sh", "args": {"kind": "script", "command": "sh scripts/setup.sh"},
               "ok": True, "is_error": False, "error": None, "duration_ms": 12,
               "fs_writes": ["/tmp/x"], "result_sample": "wrote /tmp/x"}],
    "canary": {"env_names": ["GITHUB_TOKEN"], "seen_in_result": []},
    "timed_out": False,
    "error": None,
}


def _v2_output(**over) -> str:
    doc = {"schema": "behavioral-v2", "image": "python:3.12-alpine", "mode": "exec",
           "exit_code": 0, "timed_out": False, "egress_hosts": ["github.com"],
           "fs_writes": [], "canary_exfil": [], "exercise": SKILL_TRANSCRIPT,
           "image_pulled": False, "files_materialized": ["skill_exercise.sh"]}
    doc.update(over)
    return json.dumps(doc)


@pytest.fixture
def v2_on(monkeypatch):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2",
                        "/home/ec2-user/behavioral_run_v2.sh", raising=False)


@pytest.fixture
def executed(monkeypatch):
    class _Calls(list):
        state = {"out": _v2_output(), "error": None}

    calls = _Calls()

    async def fake_execute(runner_args, timeout, *, v2=False):
        calls.append({"args": list(runner_args), "timeout": timeout, "v2": v2})
        st = calls.state
        return (None, st["error"]) if st["error"] else (st["out"], None)

    monkeypatch.setattr(runner, "_execute", fake_execute)
    return calls


def _opts(args: list[str]) -> dict:
    out: dict = {}
    i = 0
    while i < len(args) and args[i].startswith("--"):
        out[args[i]] = args[i + 1]
        i += 2
    out["pos"] = args[i:]
    return out


def _run(*a, **kw):
    return asyncio.run(runner.run_behavioral(*a, **kw))


# ── plan: image, command, runner flags ───────────────────────────────────────────

def test_skill_plan_command_and_runner_flags(executed, v2_on):
    res = _run("skill", "acme/notes-skill", plan="skill",
               env_names=["GITHUB_TOKEN", "AWS_REGION", "OPENAI_API_KEY", "bad name"])
    assert res.ran and res.plan == "skill" and res.surface == "skill"
    o = _opts(executed[0]["args"])
    assert o["--mode"] == "exec"
    canary = o["--canary"]
    assert canary.startswith("agentavow-canary-")
    shipped = json.loads(gzip.decompress(base64.b64decode(o["--files-b64"])))
    assert set(shipped) == {"skill_exercise.sh"}
    assert base64.b64decode(shipped["skill_exercise.sh"]).startswith(b"#!/bin/sh")
    image, cmd, timeout = o["pos"]
    assert image == "python:3.12-alpine"
    # the exact container command, after the alt-root apk prefix
    assert ("git clone --depth 1 https://github.com/acme/notes-skill /work/skill && "
            "cd /work/skill && sh /work/skill_exercise.sh ") in cmd
    tail = cmd.split("sh /work/skill_exercise.sh ", 1)[1]
    assert shlex.split(tail) == [
        "--timeout", "90", "--per-script-timeout", "20", "--max-scripts", "25",
        "--canary-value", canary, "--canary-env", "GITHUB_TOKEN,OPENAI_API_KEY"]
    assert cmd.startswith(runner._SANDBOX_ENV)
    assert "apk add --no-cache --no-scripts --initdb -p /work/.apk git" in cmd
    assert "apk add --no-cache --no-scripts -p /work/.apk nodejs npm bash" in cmd
    for wrapper in ("/work/.local/bin/git", "/work/.local/bin/node", "/work/.local/bin/npm",
                    "/work/.local/bin/bash"):
        assert wrapper in cmd
    assert int(timeout) == 150 and executed[0]["timeout"] == 150  # 90 s budget + headroom
    # the transcript came back and reads as "started"
    assert res.transcript is not None and res.transcript.launch_ok
    assert res.transcript.protocol_version == "skill-v1"
    assert res.transcript.server_name == "notes"
    assert [c.tool for c in res.transcript.calls] == ["scripts/setup.sh"]
    assert classify_start(res) == ("started", "")
    assert res.unexpected_egress == []  # github.com is where the clone goes


def test_skill_plan_without_env_names_sends_no_canary_env(executed, v2_on):
    _run("skill", "acme/notes", plan="skill")
    cmd = _opts(executed[0]["args"])["pos"][1]
    assert "--canary-env" not in cmd and "--canary-value" in cmd


def test_git_spec_for_the_skill_plan_is_the_bare_repo():
    assert runner._git_spec("skill", "acme/notes") == "acme/notes"
    assert runner._git_spec("skill", "https://github.com/acme/notes.git") == "acme/notes"
    assert runner._git_spec("skill", "github:acme/notes/") == "acme/notes"
    # the npm/pip git plans are untouched
    assert runner._git_spec("npm-git", "acme/notes") == "github:acme/notes"


def test_skill_plan_rejects_a_bad_coordinate(executed, v2_on):
    res = _run("skill", "not a repo", plan="skill")
    assert res.ran is False and res.error == "bad_coordinate" and executed == []
    res = _run("skill", "acme/notes;rm -rf /", plan="skill")
    assert res.ran is False and res.error == "bad_coordinate"


def test_skill_plan_needs_v2_and_the_shipped_exerciser(executed, monkeypatch, tmp_path):
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2", "",
                        raising=False)
    res = _run("skill", "acme/notes", plan="skill")
    assert res.ran is False and res.error == "v2_runner_off" and executed == []
    monkeypatch.setattr(config.settings, "scanner_behavioral_sandbox_runner_v2", "/x/v2.sh",
                        raising=False)
    monkeypatch.setattr(runner, "_SANDBOX_DIR", tmp_path)  # no skill_exercise.sh here
    res = _run("skill", "acme/notes", plan="skill")
    assert res.ran is False and res.error == "exerciser_missing"
    assert "exerciser_missing" in res.notes and executed == []


def test_skill_plan_is_registered_like_the_others():
    assert runner._SURFACE_PLAN["skill"][0] == "python:3.12-alpine"
    assert runner._SURFACE_PLAN["skill"][2] == "exec"
    assert runner._PLAN_FILES["skill"] == ("skill_exercise.sh",)
    assert runner._files_payload("skill", None) is not None
    assert "skill" not in runner._EXEC_FALLBACK


# ── router: a skill scan targets the skill plan ──────────────────────────────────

def test_router_targets_a_skill_scan_at_the_skill_plan():
    data = {"surface_kind": "skill", "repo_full_name": "acme/notes",
            "primary_language": "Agent Skill", "coverage": {"surface": "openclaw"}}
    assert router._behavioral_target(data) == ("skill", "acme/notes")
    assert router._behavioral_plan(data, "skill") == "skill"
    assert router._behavioral_cache_key("skill", "acme/notes", None, "skill") == \
        "behavioral:skill:acme/notes"
    # without the marker a skill-ish repo is NOT a sandbox target (no language → nothing)
    assert router._behavioral_target({"repo_full_name": "acme/notes",
                                      "primary_language": "Agent Skill"}) is None
    assert router._behavioral_target({"surface_kind": "skill"}) is None


class _FakeRedis:
    def __init__(self):
        self.store: dict[str, str] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value


def test_behavioral_block_runs_the_skill_plan_with_env_names(monkeypatch):
    r = _FakeRedis()
    monkeypatch.setattr("src.redis_client.get_redis", lambda: r)
    monkeypatch.setattr(router.settings, "scanner_behavioral_enabled", True, raising=False)
    seen: list[dict] = []

    async def fake_run(surface, coordinate, **kw):
        seen.append({"surface": surface, "coordinate": coordinate, **kw})
        return BehavioralResult(ran=True, surface=surface, coordinate=coordinate,
                                plan=kw["plan"], egress_hosts=["github.com"],
                                transcript=parse_transcript(SKILL_TRANSCRIPT))

    monkeypatch.setattr(runner, "run_behavioral", fake_run)
    data = {"surface_kind": "skill", "repo_full_name": "acme/notes",
            "env_reads": ["GITHUB_TOKEN"]}
    block = asyncio.run(router._behavioral_block(data, force=True))
    assert seen == [{"surface": "skill", "coordinate": "acme/notes", "expected_hosts": None,
                     "plan": "skill", "env_names": ["GITHUB_TOKEN"]}]
    assert block["ran"] is True and block["plan"] == "skill"
    assert block["exercise"]["launch_ok"] is True
    assert block["exercise"]["calls"][0]["tool"] == "scripts/setup.sh"
    assert block["findings"] == []
    gs = block["grade_summary"]
    assert gs["start_reason"] == "started" and gs["calls_total"] == 1
    assert "behavioral:skill:acme/notes" in r.store


def test_skill_endpoint_passes_the_marker_and_folds_the_block_in(monkeypatch):
    """Both branches of the endpoint call _behavioral_block with the skill marker and
    attach the block — cached (force=False) and fresh (?behavioral=true → force)."""
    calls: list[tuple[dict, bool]] = []
    block = {"ran": True, "plan": "skill", "findings": [], "egress_hosts": []}

    async def fake_block(data, force=False):
        calls.append((data, force))
        return block

    import src.scanner.scan as scan_mod
    from src.scanner.scan import ScanResult
    static = ScanResult(repo="skill:acme/notes", stars=0, description="", framework="")
    static.env_reads = ["GITHUB_TOKEN"]
    static.trust_score = 90
    cached = router._scan_result_to_dict(static)

    async def fake_get_cached(owner, repo):
        return cached if (owner, repo) == ("skill", "acme/notes") else None

    monkeypatch.setattr(router, "_behavioral_block", fake_block)
    monkeypatch.setattr(router, "_get_cached", fake_get_cached)
    monkeypatch.setattr(router, "create_jws", lambda b: "h.p.s")
    resp = asyncio.run(router.scan_skill_endpoint("acme", "notes", request=None, force=False,
                                                  behavioral=False, db=None))
    assert resp.behavioral == block
    data, force = calls[-1]
    assert force is False
    assert data["surface_kind"] == "skill" and data["repo_full_name"] == "acme/notes"
    assert data["env_reads"] == ["GITHUB_TOKEN"]

    # fresh branch: ?behavioral=true forces the run and bypasses the cache
    async def fake_scan_skill(owner, repo):
        res = ScanResult(repo=f"skill:{owner}/{repo}", stars=0, description="", framework="")
        res.env_reads = ["OPENAI_API_KEY"]
        res.trust_score = 80
        return res

    stored: list = []

    async def fake_set_cached(owner, repo, data):
        stored.append((owner, repo))

    monkeypatch.setattr(scan_mod, "scan_skill", fake_scan_skill)
    monkeypatch.setattr(router, "_set_cached", fake_set_cached)
    resp = asyncio.run(router.scan_skill_endpoint("acme", "notes", request=None, force=False,
                                                  behavioral=True, db=None))
    assert resp.behavioral == block and stored == [("skill", "acme/notes")]
    data, force = calls[-1]
    assert force is True and data["surface_kind"] == "skill"
    assert data["env_reads"] == ["OPENAI_API_KEY"]


@pytest.mark.asyncio
async def test_scan_skill_collects_env_reads_for_canaries(monkeypatch):
    import src.scanner.scan as scan_mod

    async def fake_token():
        return "tok"

    async def fake_tree(owner, repo, token):
        return ([{"path": "SKILL.md", "type": "blob"},
                 {"path": "scripts/sync.py", "type": "blob"}], False, True, "main")

    async def fake_content(owner, repo, path, token, ref=None):
        if path == "SKILL.md":
            return "---\nname: sync\ndescription: Syncs notes.\nallowed-tools: Read\n---\nrun"
        if path == "scripts/sync.py":
            return "import os\ntoken = os.environ['NOTES_API_TOKEN']\nregion = os.getenv('AWS_REGION')\n"
        return None

    monkeypatch.setattr(scan_mod, "get_github_token", fake_token, raising=False)
    monkeypatch.setattr(scan_mod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scan_mod, "_fetch_file_content", fake_content)
    res = await scan_mod.scan_skill("acme", "sync-skill")
    assert res.error is None
    assert "NOTES_API_TOKEN" in res.env_reads and "AWS_REGION" in res.env_reads
    # only the secret-named one becomes a canary
    assert runner._canary_env_names(res.env_reads) == ["NOTES_API_TOKEN"]


# ── the in-container exerciser, run for real against the fixture skills ──────────

def _exercise(skill_dir: pathlib.Path, *extra: str, env: dict | None = None):
    with tempfile.TemporaryDirectory(prefix="agentavow-skill-test-") as mount:
        e = dict(os.environ, AGENTAVOW_FIXTURE_TMP=mount, AGENTAVOW_FIXTURE_NET="0",
                 **(env or {}))
        cmd = ["sh", str(SCRIPT), "--timeout", "30", "--per-script-timeout", "5",
               "--root", str(skill_dir), "--mounts", mount,
               "--canary-value", "agentavow-canary-test00000001", *extra]
        proc = subprocess.run(cmd, capture_output=True, text=True, env=e, timeout=60)
        doc = extract_transcript_json(proc.stdout)
        return proc, json.loads(doc), parse_transcript(doc), mount


def test_exerciser_is_posix_sh():
    assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0


def test_benign_fixture_transcript_shape_and_file_write():
    proc, raw, tr, mount = _exercise(SKILLS / "benign-skill", "--canary-env",
                                     "GITHUB_TOKEN,API_KEY")
    assert proc.returncode == 0
    assert raw["version"] == 1 and raw["protocol_version"] == "skill-v1"
    assert set(raw) >= {"launch", "server_info", "tools", "calls", "canary", "timed_out", "error"}
    assert raw["launch"]["ok"] is True and raw["error"] is None
    assert raw["server_info"]["name"] == "benign-notes"
    assert raw["tools"] == [{"name": "scripts/setup.sh", "description": "script: sh scripts/setup.sh",
                             "annotations": {"kind": "script"}, "input_schema": None}]
    (call,) = raw["calls"]
    assert call["tool"] == "scripts/setup.sh" and call["ok"] and not call["is_error"]
    assert call["error"] is None and call["args"] == {"kind": "script",
                                                      "command": "sh scripts/setup.sh"}
    assert call["fs_writes"] == [f"{mount}/x"]  # the ONE write, attributed to the script
    assert call["result_sample"].startswith("wrote ")
    assert raw["canary"] == {"env_names": ["GITHUB_TOKEN", "API_KEY"], "seen_in_result": []}
    # parses into the shared dataclasses and grades clean
    assert tr.launch_ok and tr.present and [c.tool for c in tr.calls] == ["scripts/setup.sh"]
    res = BehavioralResult(ran=True, surface="skill", coordinate="x/benign", plan="skill",
                           egress_hosts=["github.com"], transcript=tr, fs_writes=tr.calls[0].fs_writes)
    assert grade(res) == []
    assert classify_start(res) == ("started", "")
    s = grade_summary(res)
    assert s["start_reason"] == "started" and s["tools_called"] == 1 and s["calls_failed"] == 0


def test_phones_home_fixture_runs_its_hook_once_and_is_attributed():
    proc, raw, tr, _ = _exercise(SKILLS / "phones-home-skill")
    assert [t["name"] for t in raw["tools"]] == ["hooks.json:SessionStart"]
    assert raw["tools"][0]["annotations"] == {"kind": "hook"}
    assert raw["tools"][0]["description"].startswith("hook: sh ")
    (call,) = raw["calls"]  # the script the hook names is NOT run a second time
    assert call["ok"] and call["args"]["kind"] == "hook"
    assert "skipped lookup" in call["result_sample"]
    # what the sandbox's capture would add → the grader names the hook
    res = BehavioralResult(ran=True, surface="skill", coordinate="x/phones-home", plan="skill",
                           egress_hosts=["github.com", "phone-home.agentavow-eval.invalid"],
                           unexpected_egress=["phone-home.agentavow-eval.invalid"],
                           transcript=tr)
    rules = [f.rule for f in grade(res)]
    assert rules == ["behavioral_undeclared_egress", "skill_script_egress"]
    f = grade(res)[1]
    assert f.severity == "medium" and f.category == "exfiltration"
    assert "hooks.json:SessionStart" in f.name and f.name.startswith("Lifecycle hook")
    assert "phone-home.agentavow-eval.invalid" in f.snippet


def test_empty_skill_reports_no_entrypoint(tmp_path):
    (tmp_path / "SKILL.md").write_text("---\nname: empty\n---\nnothing runs\n")
    (tmp_path / "notes.ts").write_text("export const x = 1\n")  # no runtime for .ts
    _, raw, tr, _ = _exercise(tmp_path)
    assert raw["tools"] == [] and raw["calls"] == []
    assert raw["launch"]["ok"] is False and raw["launch"]["error"] == "no_entrypoint_found"
    assert raw["error"] == "no_entrypoint_found"
    res = BehavioralResult(ran=True, surface="skill", coordinate="x/empty", plan="skill",
                           transcript=tr)
    assert classify_start(res) == ("no_entrypoint",
                                   "the skill ships no lifecycle hook or runnable script")
    assert grade(res) == []
    assert grade_summary(res)["server_failed_to_start"] is True


def test_canary_echo_timeout_failure_and_mcp_server(tmp_path):
    """One temp skill with the four other call outcomes: a script that prints the canary
    (seen_in_result), one that hangs (call_timeout), one that exits non-zero (is_error),
    and a .mcp.json stdio server that answers initialize (ok)."""
    (tmp_path / "SKILL.md").write_text("---\nname: mixed\n---\n")
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "a_echo.sh").write_text('#!/bin/bash\necho "token=$NOTES_TOKEN"\n')
    (tmp_path / "scripts" / "b_hang.py").write_text("import time\ntime.sleep(30)\n")
    (tmp_path / "scripts" / "c_fail.sh").write_text("#!/bin/sh\nexit 3\n")
    (tmp_path / "server.py").write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    req = json.loads(line)\n"
        "    if req.get('method') == 'initialize':\n"
        "        print(json.dumps({'jsonrpc': '2.0', 'id': req['id'], 'result': {\n"
        "            'protocolVersion': '2025-06-18', 'capabilities': {},\n"
        "            'serverInfo': {'name': 'tiny', 'version': '0.1'}}}), flush=True)\n")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"tiny": {
        "command": "python3", "args": ["${CLAUDE_PLUGIN_ROOT}/server.py"]}}}))
    _, raw, tr, _ = _exercise(tmp_path, "--per-script-timeout", "2", "--canary-env",
                              "NOTES_TOKEN")
    by = {c["tool"]: c for c in raw["calls"]}
    # MCP servers run before scripts; scripts in path order; server.py is NOT also run as
    # a bare script because the .mcp.json entry names it
    assert list(by) == [".mcp.json:tiny", "scripts/a_echo.sh", "scripts/b_hang.py",
                        "scripts/c_fail.sh"]
    assert by[".mcp.json:tiny"]["ok"] and "tiny" in by[".mcp.json:tiny"]["result_sample"]
    assert by["scripts/a_echo.sh"]["ok"] and "agentavow-canary-test00000001" in \
        by["scripts/a_echo.sh"]["result_sample"]
    assert raw["canary"]["seen_in_result"] == ["NOTES_TOKEN"]
    assert by["scripts/b_hang.py"]["ok"] is False
    assert by["scripts/b_hang.py"]["error"] == "call_timeout"
    assert by["scripts/c_fail.sh"]["ok"] and by["scripts/c_fail.sh"]["is_error"]
    assert by["scripts/c_fail.sh"]["error"] == "exited 3"
    assert raw["launch"]["ok"] is True
    res = BehavioralResult(ran=True, surface="skill", coordinate="x/mixed", plan="skill",
                           transcript=tr)
    assert [f.rule for f in grade(res)] == ["canary_echoed_in_result"]
    s = grade_summary(res)
    assert s["calls_total"] == 4 and s["calls_failed"] == 2


def test_exerciser_never_leaves_the_skill_root(tmp_path):
    """A symlink out of the tree and a script under node_modules are never run."""
    skill = tmp_path / "skill"
    skill.mkdir()
    (skill / "SKILL.md").write_text("---\nname: s\n---\n")
    outside = tmp_path / "outside.sh"
    outside.write_text("#!/bin/sh\necho OUTSIDE\n")
    os.symlink(outside, skill / "linked.sh")
    (skill / "node_modules" / "dep").mkdir(parents=True)
    (skill / "node_modules" / "dep" / "postinstall.sh").write_text("echo NM\n")
    _, raw, _, _ = _exercise(skill)
    assert raw["tools"] == [] and raw["launch"]["error"] == "no_entrypoint_found"


# ── graders over stub transcripts ───────────────────────────────────────────────

def _stub(calls: list[dict], **over) -> BehavioralResult:
    doc = dict(SKILL_TRANSCRIPT, tools=[{"name": c["tool"], "annotations": {"kind": c.get(
        "kind", "script")}} for c in calls], calls=[
        {"tool": c["tool"], "args": {"kind": c.get("kind", "script"), "command": "x"},
         "ok": c.get("ok", True), "error": c.get("error"), "fs_writes": []} for c in calls])
    kw = dict(ran=True, surface="skill", coordinate="acme/notes", plan="skill",
              egress_hosts=["github.com", "evil.example.net"],
              unexpected_egress=["evil.example.net"], transcript=parse_transcript(doc))
    kw.update(over)
    return BehavioralResult(**kw)


def test_skill_script_egress_attributes_only_when_exactly_one_entrypoint_ran():
    one = _stub([{"tool": "scripts/sync.sh"}])
    rules = [f.rule for f in grade(one)]
    assert rules == ["behavioral_undeclared_egress", "skill_script_egress"]
    f = grade(one)[1]
    assert f.name == "Bundled script 'scripts/sync.sh' contacted undeclared host(s)"
    assert f.snippet == "scripts/sync.sh was the only entrypoint that ran; egress to evil.example.net"
    # two ran → cannot attribute: the run-wide finding stands alone
    two = _stub([{"tool": "a.sh"}, {"tool": "b.py"}])
    assert [f.rule for f in grade(two)] == ["behavioral_undeclared_egress"]
    # one ran, one never spawned (missing interpreter) → attributed to the one that ran
    mixed = _stub([{"tool": "a.js", "ok": False, "error": "missing_binary: node not found"},
                   {"tool": "b.py"}])
    assert [f.rule for f in grade(mixed)] == ["behavioral_undeclared_egress", "skill_script_egress"]
    assert "'b.py'" in grade(mixed)[1].name
    # a hook that timed out still ran (and could have phoned home)
    hang = _stub([{"tool": "hooks.json:SessionStart", "kind": "hook", "ok": False,
                   "error": "call_timeout"}])
    assert grade(hang)[1].name.startswith("Lifecycle hook 'hooks.json:SessionStart'")
    mcp = _stub([{"tool": ".mcp.json:tiny", "kind": "mcp"}])
    assert grade(mcp)[1].name.startswith("Bundled MCP server '.mcp.json:tiny'")


def test_skill_script_egress_is_quiet_without_egress_or_off_plan():
    assert grade(_stub([{"tool": "a.sh"}], egress_hosts=["github.com"],
                       unexpected_egress=[])) == []
    # cloud metadata alone is the low-severity note, never attributed as egress
    imds = _stub([{"tool": "a.sh"}], unexpected_egress=["169.254.169.254"])
    assert [f.rule for f in grade(imds)] == ["cloud_metadata_probe"]
    # the MCP plans never get the skill grader, whatever the transcript says
    npm = _stub([{"tool": "a.sh"}], plan="npm-mcp", surface="npm")
    assert [f.rule for f in grade(npm)] == ["behavioral_undeclared_egress"]


def test_classify_start_for_the_skill_plan():
    # no transcript + non-zero exit = the clone (or apk) step failed
    res = BehavioralResult(ran=True, surface="skill", coordinate="a/b", plan="skill",
                           exit_code=128, transcript=None)
    assert classify_start(res) == ("install_failed", "clone step exited 128; nothing ran")
    # no transcript + wall clock = timeout (never "not_applicable", which is install-only)
    res = BehavioralResult(ran=True, surface="skill", coordinate="a/b", plan="skill",
                           timed_out=True, exit_code=124)
    assert classify_start(res)[0] == "timeout"
    # a skill whose only script needs an interpreter the image lacks
    doc = dict(SKILL_TRANSCRIPT, launch={"command": ["git"], "ok": False,
                                         "error": "missing_binary: node not found"},
               calls=[], error=None)
    res = BehavioralResult(ran=True, surface="skill", coordinate="a/b", plan="skill",
                           transcript=parse_transcript(doc))
    assert classify_start(res)[0] == "missing_binary"


def test_score_effect_applies_to_a_signed_skill_run():
    from src.scanner.behavioral.score_effect import behavioral_score_effect
    clean = {"ran": True, "plan": "skill", "attestation": {"jws": "h.p.s", "observed_at": "x"},
             "findings": [], "exercise": {"launch_ok": True, "calls": [{"tool": "a.sh", "ok": True}]}}
    eff = behavioral_score_effect(80, clean)
    assert eff["applied"] and eff["delta"] == 3 and "1 tool(s) exercised" in eff["reason"]
    caught = dict(clean, findings=[{"rule": "behavioral_undeclared_egress", "severity": "high"},
                                   {"rule": "skill_script_egress", "severity": "medium"}])
    eff = behavioral_score_effect(80, caught)
    assert eff["score"] == 70 and eff["delta"] == -10


# ── the MCP connector's one-line sandbox summary ────────────────────────────────

def test_connector_sandbox_section_for_skills():
    ran = {"behavioral": {"ran": True, "plan": "skill", "egress_hosts": ["github.com"],
                          "exercise": {"launch_ok": True,
                                       "tools": [{"name": "hooks.json:SessionStart"},
                                                 {"name": "scripts/setup.sh"}],
                                       "calls": [{"tool": "hooks.json:SessionStart", "ok": True},
                                                 {"tool": "scripts/setup.sh", "ok": True}],
                                       "canary": {"env_names": ["GITHUB_TOKEN"],
                                                  "seen_in_result": []}},
                          "findings": []}}
    lines = _sandbox_section(ran)
    assert "cloned the skill and ran 2 of 2 hooks/script(s) with canary credentials" in lines[0]
    assert "network: only github.com" in lines[1].lower()
    assert "canary values for GITHUB_TOKEN stayed put" in lines[1]
    empty = {"behavioral": {"ran": True, "plan": "skill", "egress_hosts": ["github.com"],
                            "exercise": {"launch_ok": False, "tools": [], "calls": [],
                                         "error": "no_entrypoint_found"},
                            "grade_summary": {"start_reason": "no_entrypoint"},
                            "findings": []}}
    lines = _sandbox_section(empty)
    assert "cloned the skill, but nothing ran — it ships no lifecycle hook or runnable script" \
        in lines[0]
    assert "This is not a finding" in lines[0]
