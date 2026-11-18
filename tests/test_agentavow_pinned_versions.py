"""Plugin 0.1.45: a server or package pinned to an exact version is graded at that
version, not at the latest one.

Before 0.1.45 the hooks dropped the version from ``npx -y name@1.0.15``,
``npm install name@1.0.15``, ``pip install name==1.2.3``, ``uvx name@1.2.3`` and the
like, and graded the latest release. An old release with a critical finding then read
"Safe to connect" because its newer release is clean. Now an exact pin asks the API for
that release (``?version=``); a range or a tag (``^1.2``, ``>=1``, ``latest``) is graded
at the latest release as before. Cache ids carry the pin, so a pinned grade never
answers for another release, or for the latest, and the other way round.

Also here: installer flags that take a value (``pip install --progress-bar off x``,
``npm i --omit dev x``, ``uvx --python 3.12 x``) are not read as package names, and
installer switches (``bun add -p x``, ``pnpm add -w x``) do not swallow the package.
"""
from __future__ import annotations

import json
import time
import urllib.error

import pytest

import tests.test_agentavow_claude_pins as pins
from tests.test_agentavow_claude_pins import SCRIPTS, _load, _Session
from tests.test_agentavow_codex import _bash as _codex_bash
from tests.test_agentavow_codex import _codex_accepts, _codex_session
from tests.test_agentavow_codex import _start as _codex_start

LATEST = pins._api(82, "safe", "no critical or high findings in 5 files", "trusted",
                   package_version="1.2.4")
OLD = pins._api(45, "do_not_connect",
                "one critical finding in its code: wallet private key sent over the network",
                "restricted", package_version="1.0.15",
                findings={"items": [{"severity": "critical", "name": "exfil"}]})

# (path, version) -> answer. Anything else is "offline".
ANSWERS = {
    ("/package/npm/gadgethumans-mcp", None): LATEST,
    ("/package/npm/gadgethumans-mcp", "1.0.15"): OLD,
    ("/package/npm/gadgethumans-mcp", "1.2.4"): LATEST,
    ("/package/npm/@scope/tool", None): LATEST,
    ("/package/npm/@scope/tool", "1.0.15"): OLD,
    ("/package/pypi/pytool", None): LATEST,
    ("/package/pypi/pytool", "1.0.15"): OLD,
}


@pytest.fixture
def api(monkeypatch):
    """The scan API, answering per (path, version), with every request recorded."""
    calls: list[tuple[str, str | None]] = []

    def factory(_answers):
        def fetch(path: str, params: dict) -> dict:
            key = (path, params.get("version"))
            calls.append(key)
            if key not in ANSWERS:
                raise urllib.error.URLError("offline in this test")
            return json.loads(json.dumps(ANSWERS[key]))
        return fetch

    monkeypatch.setattr(pins, "_fake_fetch", factory)
    return calls


@pytest.fixture
def pc():
    return _load("pinned_pc", SCRIPTS / "agentavow_precheck.py")


@pytest.fixture
def pi():
    return _load("pinned_pi", SCRIPTS / "agentavow_pre_install.py")


# --- what counts as an exact pin ------------------------------------------------------

@pytest.mark.parametrize("registry,spec,want", [
    ("npm", "1.0.15", "1.0.15"),
    ("npm", "=1.0.15", "1.0.15"),
    ("npm", "v1.0.15", "1.0.15"),
    ("npm", "2.0.0-beta.1", "2.0.0-beta.1"),
    ("npm", "1.0.0+build.5", "1.0.0+build.5"),
    ("npm", "", None),
    ("npm", "latest", None),
    ("npm", "next", None),
    ("npm", "^1.0.15", None),
    ("npm", "~1.0.15", None),
    ("npm", ">=1.0.15", None),
    ("npm", "1.0", None),          # a range: any 1.0.x
    ("npm", "1.x", None),
    ("npm", "*", None),
    ("npm", "1.0.0 - 2.0.0", None),
    ("npm", "1.0.0 || 2.0.0", None),
    ("pypi", "==1.2.3", "1.2.3"),
    ("pypi", "===1.2.3", "1.2.3"),
    ("pypi", "@1.2.3", "1.2.3"),   # uvx / uv tool run
    ("pypi", "== 1.2.3", "1.2.3"),
    ("pypi", "==1.2.3rc1", "1.2.3rc1"),
    ("pypi", "==1.2.3.post1", "1.2.3.post1"),
    ("pypi", "==1!2.0", "1!2.0"),
    ("pypi", "==2", "2"),
    ("pypi", "", None),
    ("pypi", ">=1.2", None),
    ("pypi", "~=1.2", None),
    ("pypi", "==1.2.*", None),
    ("pypi", "==1.2.3,<2", None),
    ("pypi", "!=1.2.3", None),
    ("pypi", "@latest", None),
    ("pypi", "@ https://example.com/pkg.whl", None),
    ("crates", "1.0.0", None),     # only npm and PyPI pins are passed on
])
def test_exact_version(pc, registry, spec, want):
    assert pc._exact_version(registry, spec) == want


@pytest.mark.parametrize("spec,want", [
    ("name", ("name", "")),
    ("name@1.0.15", ("name", "1.0.15")),
    ("name@latest", ("name", "latest")),
    ("@scope/name", ("@scope/name", "")),
    ("@scope/name@1.2.3", ("@scope/name", "1.2.3")),
    ("@scope/name@^1.2", ("@scope/name", "^1.2")),
])
def test_split_npm_spec(pc, spec, want):
    assert pc._split_npm_spec(spec) == want
    assert pc._strip_npm_version(spec) == want[0]


@pytest.mark.parametrize("spec,want", [
    ("pkg", ("pkg", "")),
    ("pkg==1.2.3", ("pkg", "==1.2.3")),
    ("pkg@1.2.3", ("pkg", "@1.2.3")),
    ("pkg[cli]==1.2.3", ("pkg", "==1.2.3")),
    ("pkg>=1,<2", ("pkg", ">=1,<2")),
    ("pkg==1.2.3; python_version>'3.8'", ("pkg", "==1.2.3")),
])
def test_split_pypi_spec(pc, spec, want):
    assert pc._split_pypi_spec(spec) == want
    assert pc._strip_pypi_version(spec) == want[0]


# --- server configs: npx / uvx / pipx, Claude Code and Codex ---------------------------

@pytest.mark.parametrize("cmd,args,want_id,want_version", [
    ("npx", ["-y", "gadgethumans-mcp@1.0.15"], "npm:gadgethumans-mcp==1.0.15", "1.0.15"),
    ("npx", ["-y", "gadgethumans-mcp"], "npm:gadgethumans-mcp", None),
    ("npx", ["-y", "gadgethumans-mcp@latest"], "npm:gadgethumans-mcp", None),
    ("npx", ["-y", "gadgethumans-mcp@^1.0.15"], "npm:gadgethumans-mcp", None),
    ("npx", ["-y", "@scope/tool@1.0.15"], "npm:@scope/tool==1.0.15", "1.0.15"),
    ("npx", ["-y", "@scope/tool"], "npm:@scope/tool", None),
    ("npx", ["-p", "@scope/tool@1.0.15", "tool"], "npm:@scope/tool==1.0.15", "1.0.15"),
    ("npx", ["--package=@scope/tool@1.0.15", "tool"], "npm:@scope/tool==1.0.15", "1.0.15"),
    ("npx", ["--registry", "https://r.example", "-y", "gadgethumans-mcp@1.0.15"],
     "npm:gadgethumans-mcp==1.0.15", "1.0.15"),
    ("bunx", ["gadgethumans-mcp@1.0.15"], "npm:gadgethumans-mcp==1.0.15", "1.0.15"),
    ("/usr/local/bin/npx", ["-y", "gadgethumans-mcp@1.0.15"],
     "npm:gadgethumans-mcp==1.0.15", "1.0.15"),
    ("uvx", ["pytool@1.0.15"], "pypi:pytool==1.0.15", "1.0.15"),
    ("uvx", ["pytool==1.0.15"], "pypi:pytool==1.0.15", "1.0.15"),
    ("uvx", ["pytool@latest"], "pypi:pytool", None),
    ("uvx", ["pytool>=1.0"], "pypi:pytool", None),
    ("uvx", ["pytool"], "pypi:pytool", None),
    ("uvx", ["--from", "pytool==1.0.15", "pytool-cli"], "pypi:pytool==1.0.15", "1.0.15"),
    ("uvx", ["--from=pytool==1.0.15", "pytool-cli"], "pypi:pytool==1.0.15", "1.0.15"),
    ("uvx", ["--python", "3.12", "pytool==1.0.15"], "pypi:pytool==1.0.15", "1.0.15"),
    ("uvx", ["--python", "3.12", "pytool"], "pypi:pytool", None),
    ("uvx", ["--with", "extra-dep", "pytool"], "pypi:pytool", None),
    ("pipx", ["run", "pytool==1.0.15"], "pypi:pytool==1.0.15", "1.0.15"),
    ("pipx", ["run", "--spec", "pytool==1.0.15", "pytool-cli"], "pypi:pytool==1.0.15",
     "1.0.15"),
])
def test_server_targets_carry_an_exact_pin(pc, cmd, args, want_id, want_version):
    t = pc._resolve_target("s", {"command": cmd, "args": args})
    assert t["id"] == want_id
    assert t.get("version") == want_version


def test_pinned_and_latest_ids_never_match(pc):
    pinned = pc._resolve_target("s", {"command": "npx", "args": ["-y", "x@1.0.15"]})
    other = pc._resolve_target("s", {"command": "npx", "args": ["-y", "x@1.0.16"]})
    latest = pc._resolve_target("s", {"command": "npx", "args": ["-y", "x"]})
    assert len({pinned["id"], other["id"], latest["id"]}) == 3
    # nor the ids 0.1.44 and earlier wrote for a dependency ('dep:npm:x@1.0.15', graded
    # at the latest release)
    assert pc._dep("npm", "x", "1.0.15")["id"] == "dep:npm:x==1.0.15"
    assert pc._dep("npm", "x", "^1.0.15")["id"] == "dep:npm:x@^1.0.15"
    assert pc._dep("npm", "x", "")["id"] == "dep:npm:x@"
    assert pc._dep("pypi", "x", "==1.0.15")["id"] == "dep:pypi:x==1.0.15"
    assert pc._dep("pypi", "x", ">=1")["id"] == "dep:pypi:x@>=1"


@pytest.mark.parametrize("cmd", [
    "claude mcp add gadget -- npx -y gadgethumans-mcp@1.0.15",
    "claude mcp add -s user gadget -- npx -y gadgethumans-mcp@1.0.15",
    "claude mcp add gadget npx -y gadgethumans-mcp@1.0.15",
])
def test_claude_mcp_add_keeps_the_pin(pc, pi, cmd):
    name, cfg = pi._server_from_mcp_add(cmd)
    t = pc._resolve_target(name, cfg)
    assert (t["id"], t["version"]) == ("npm:gadgethumans-mcp==1.0.15", "1.0.15")


@pytest.mark.parametrize("cmd", [
    "codex mcp add gadget -- npx -y gadgethumans-mcp@1.0.15",
    "codex mcp add --env K=v gadget -- npx -y gadgethumans-mcp@1.0.15",
])
def test_codex_mcp_add_keeps_the_pin(pc, pi, cmd):
    name, cfg = pi._server_from_codex_mcp_add(cmd)
    t = pc._resolve_target(name, cfg)
    assert (t["id"], t["version"]) == ("npm:gadgethumans-mcp==1.0.15", "1.0.15")


def test_scan_asks_for_the_pinned_version(pc, monkeypatch):
    seen = []
    monkeypatch.setattr(pc, "_fetch", lambda path, params: seen.append((path, params)) or
                        json.loads(json.dumps(LATEST)))
    pc._scan(pc._resolve_target("s", {"command": "npx", "args": ["-y", "@scope/tool@1.0.15"]}))
    pc._scan(pc._resolve_target("s", {"command": "npx", "args": ["-y", "@scope/tool"]}))
    pc._scan(pc._dep("pypi", "pytool", "==1.0.15"), stored=True)
    pc._scan(pc._dep("pypi", "pytool", ">=1"), stored=True)
    assert seen == [
        ("/package/npm/@scope/tool", {"version": "1.0.15"}),
        ("/package/npm/@scope/tool", {}),
        ("/package/pypi/pytool", {"stored": "true", "version": "1.0.15"}),
        ("/package/pypi/pytool", {"stored": "true"}),
    ]


def test_pinned_record_links_the_pinned_report(pc):
    t = pc._resolve_target("s", {"command": "npx", "args": ["-y", "@scope/tool@1.0.15"]})
    rec = pc._record(t, {"score": 45}, 1.0)
    assert rec["report_url"] == "https://agentavow.com/check/pkg/npm/@scope/tool?version=1.0.15"
    assert rec["version"] == "1.0.15"
    latest = pc._record(pc._resolve_target("s", {"command": "npx", "args": ["x"]}), {}, 1.0)
    assert latest["report_url"] == "https://agentavow.com/check/pkg/npm/x"
    assert "version" not in latest


# --- package installs: npm / pip / uv -------------------------------------------------

@pytest.mark.parametrize("cmd,want", [
    ("npm install gadgethumans-mcp@1.0.15", [("gadgethumans-mcp", "1.0.15")]),
    ("npm i @scope/tool@1.0.15", [("@scope/tool", "1.0.15")]),
    ("npm i @scope/tool@^1.0.15", [("@scope/tool", None)]),
    ("npm install gadgethumans-mcp@latest", [("gadgethumans-mcp", None)]),
    ("pnpm add gadgethumans-mcp@1.0.15", [("gadgethumans-mcp", "1.0.15")]),
    ("pip install pytool==1.0.15", [("pytool", "1.0.15")]),
    ("python -m pip install 'pytool==1.0.15'", [("pytool", "1.0.15")]),
    ("pip install 'pytool>=1.0'", [("pytool", None)]),
    ("uv pip install pytool==1.0.15", [("pytool", "1.0.15")]),
    ("uv add pytool==1.0.15", [("pytool", "1.0.15")]),
    ("pipx install pytool==1.0.15", [("pytool", "1.0.15")]),
])
def test_install_specs_carry_an_exact_pin(pc, pi, cmd, want):
    got = [(pkg, pc._dep(reg, pkg, spec).get("version"))
           for reg, pkg, spec in pi._package_installs(cmd, pc)]
    assert got == want


# --- flags that take a value are not packages (and switches do not eat one) -----------

@pytest.mark.parametrize("cmd,want", [
    # pip
    ("pip install -q pytest-xdist", ["pytest-xdist"]),
    ("pip install -q pytest-xdist 2>&1 | tail -2", ["pytest-xdist"]),
    ("python -m pip install pytest-xdist==3.8.0", ["pytest-xdist"]),
    ("pip install -i https://pypi.example/simple pytest-xdist", ["pytest-xdist"]),
    ("pip install --index-url https://pypi.example/simple pytest-xdist", ["pytest-xdist"]),
    ("pip install --index-url=https://pypi.example/simple pytest-xdist", ["pytest-xdist"]),
    ("pip install --extra-index-url https://x.example pytest-xdist", ["pytest-xdist"]),
    ("pip install -c constraints.txt pytest-xdist", ["pytest-xdist"]),
    ("pip install -r requirements.txt pytest-xdist", ["pytest-xdist"]),
    ("pip install -t vendor pytest-xdist", ["pytest-xdist"]),
    ("pip install --python-version 3.12 --only-binary :all: -t v pytest-xdist",
     ["pytest-xdist"]),
    ("pip install --platform manylinux2014_x86_64 pytest-xdist", ["pytest-xdist"]),
    ("pip install --retries 2 --timeout 30 pytest-xdist", ["pytest-xdist"]),
    ("pip install --progress-bar off pytest-xdist", ["pytest-xdist"]),
    ("pip install --upgrade-strategy eager pytest-xdist", ["pytest-xdist"]),
    ("pip install --root-user-action ignore pytest-xdist", ["pytest-xdist"]),
    ("pip install --no-binary numpy pytest-xdist", ["pytest-xdist"]),
    ("pip install --exists-action w pytest-xdist", ["pytest-xdist"]),
    ("pip install --log-file pip.log pytest-xdist", ["pytest-xdist"]),
    ("pip install -C key=value pytest-xdist", ["pytest-xdist"]),
    ("pip install --use-feature truststore pytest-xdist", ["pytest-xdist"]),
    ("pip install pytest-xdist && pytest -n 2", ["pytest-xdist"]),
    # uv
    ("uv pip install --python 3.12 pytest-xdist", ["pytest-xdist"]),
    ("uv pip install -p 3.12 pytest-xdist", ["pytest-xdist"]),
    ("uv pip install --index-strategy unsafe-best-match pytest-xdist", ["pytest-xdist"]),
    ("uv pip install --python-platform linux pytest-xdist", ["pytest-xdist"]),
    ("uv add --optional test pytest-xdist", ["pytest-xdist"]),
    ("uv add --group dev pytest-xdist", ["pytest-xdist"]),
    ("uv add -m \"sys_platform == 'linux'\" pytest-xdist", ["pytest-xdist"]),
    ("uv add --bounds exact pytest-xdist", ["pytest-xdist"]),
    ("uv add -e pytest-xdist", ["pytest-xdist"]),      # --editable is a switch for uv add
    # poetry / pipx
    ("poetry add -G dev pytest-xdist", ["pytest-xdist"]),
    ("poetry add --source internal pytest-xdist", ["pytest-xdist"]),
    ("pipx install --python 3.12 ruff", ["ruff"]),
    ("pipx install --pip-args=--no-cache-dir ruff", ["ruff"]),
    ("pipx install --suffix _dev ruff", ["ruff"]),
    ("pipx install -f ruff", ["ruff"]),                 # --force is a switch
    # npm family
    ("npm install --loglevel warn chalk", ["chalk"]),
    ("npm i --omit dev chalk", ["chalk"]),
    ("npm i --registry https://r.example chalk", ["chalk"]),
    ("npm i -w packages/app chalk", ["chalk"]),
    ("npm i --install-strategy nested chalk", ["chalk"]),
    ("npm i -f chalk", ["chalk"]),                      # --force is a switch
    ("pnpm add -w zod", ["zod"]),                       # -w is --workspace-root
    ("pnpm add --filter app zod", ["zod"]),
    ("pnpm add -F app zod", ["zod"]),
    ("pnpm add --reporter silent zod", ["zod"]),
    ("yarn add --cwd app react", ["react"]),
    ("yarn add --network-timeout 100000 react", ["react"]),
    ("bun add -p hono", ["hono"]),                      # -p is --production
    ("bun add --backend copyfile hono", ["hono"]),
])
def test_flag_values_are_not_package_names(pc, pi, cmd, want):
    assert [pkg for _, pkg, _ in pi._package_installs(cmd, pc)] == want


@pytest.mark.parametrize("cmd", [
    "pip install --progress-bar off -r requirements.txt",
    "pip install --retries 2",
    "npm install --loglevel silent",
    "uv add --group dev -r requirements.txt",
])
def test_flag_values_alone_install_nothing(pc, pi, cmd):
    assert pi._package_installs(cmd, pc) == []


# --- end to end: what Claude Code users see -------------------------------------------

def _claude_bash(s: _Session, cmd: str) -> dict:
    return pins._bash(s, cmd)


def _hso(out: str) -> dict:
    return json.loads(out)["hookSpecificOutput"] if out else {}


def test_claude_mcp_add_pinned_old_release_asks(tmp_path, api):
    s = _Session(tmp_path / "home")
    out = s.pre_install(_claude_bash(
        s, "claude mcp add gadget -- npx -y gadgethumans-mcp@1.0.15"))
    h = _hso(out)
    assert h["permissionDecision"] == "ask"
    assert "MCP 'gadget' (npm:gadgethumans-mcp@1.0.15): Do not connect" in h[
        "permissionDecisionReason"]
    assert "check/pkg/npm/gadgethumans-mcp?version=1.0.15" in h["permissionDecisionReason"]
    assert api == [("/package/npm/gadgethumans-mcp", "1.0.15")]


def test_claude_mcp_add_unpinned_stays_latest(tmp_path, api):
    s = _Session(tmp_path / "home")
    out = s.pre_install(_claude_bash(s, "claude mcp add gadget -- npx -y gadgethumans-mcp"))
    h = _hso(out)
    assert "permissionDecision" not in h
    assert "MCP 'gadget' (npm:gadgethumans-mcp): Safe to connect" in h["additionalContext"]
    assert api == [("/package/npm/gadgethumans-mcp", None)]


@pytest.mark.parametrize("cmd,coord", [
    ("npm install gadgethumans-mcp@1.0.15", "npm package 'gadgethumans-mcp@1.0.15'"),
    ("npm i @scope/tool@1.0.15", "npm package '@scope/tool@1.0.15'"),
    ("pip install pytool==1.0.15", "pypi package 'pytool==1.0.15'"),
    ("uv add pytool==1.0.15", "pypi package 'pytool==1.0.15'"),
])
def test_pinned_install_of_an_old_release_asks(tmp_path, api, cmd, coord):
    s = _Session(tmp_path / "home")
    h = _hso(s.pre_install(_claude_bash(s, cmd)))
    assert h["permissionDecision"] == "ask"
    assert f"⛔ {coord}: Do not connect" in h["permissionDecisionReason"]
    assert "?version=1.0.15" in h["permissionDecisionReason"]
    assert all(v == "1.0.15" for _, v in api)


@pytest.mark.parametrize("cmd", [
    "npm install gadgethumans-mcp", "npm install gadgethumans-mcp@^1.0.15",
    "npm install gadgethumans-mcp@latest", "pip install 'pytool>=1'",
])
def test_unpinned_install_is_graded_at_latest(tmp_path, api, cmd):
    s = _Session(tmp_path / "home")
    assert s.pre_install(_claude_bash(s, cmd)) == ""  # Safe: silent, as before
    assert api and all(v is None for _, v in api)


def test_install_cache_is_version_aware(tmp_path, api):
    s = _Session(tmp_path / "home")
    assert _hso(s.pre_install(_claude_bash(s, "npm i gadgethumans-mcp@1.0.15")))[
        "permissionDecision"] == "ask"
    # the latest release is asked about, not answered by the pinned grade
    assert s.pre_install(_claude_bash(s, "npm i gadgethumans-mcp")) == ""
    # and the pinned release is not answered by the latest grade
    assert _hso(s.pre_install(_claude_bash(s, "npm i gadgethumans-mcp@1.0.15")))[
        "permissionDecision"] == "ask"
    assert api == [("/package/npm/gadgethumans-mcp", "1.0.15"),
                   ("/package/npm/gadgethumans-mcp", None),
                   ("/package/npm/gadgethumans-mcp", "1.0.15")]
    # the same pin again is served from the cache
    s.pre_install(_claude_bash(s, "npm i gadgethumans-mcp@1.0.15"))
    assert len(api) == 3


def test_old_latest_graded_dependency_entry_is_not_reused_for_a_pin(tmp_path, api):
    """0.1.44 cached 'npm i x@1.0.15' as id 'dep:npm:x@1.0.15' with the LATEST grade."""
    s = _Session(tmp_path / "home")
    cache = s.home / ".cache" / "agentavow"
    cache.mkdir(parents=True)
    old = dict(id="dep:npm:gadgethumans-mcp@1.0.15", kind="package", approved_at=time.time(),
               epoch="2026-10-28", registry="npm", pkg="gadgethumans-mcp", score=82,
               decision="safe", decision_reason="clean", verdict="safe", spec="1.0.15")
    (cache / "scanned.json").write_text(json.dumps({"dep:npm:gadgethumans-mcp": old}))
    h = _hso(s.pre_install(_claude_bash(s, "npm i gadgethumans-mcp@1.0.15")))
    assert h["permissionDecision"] == "ask"
    assert api == [("/package/npm/gadgethumans-mcp", "1.0.15")]


def test_session_start_grades_a_pinned_configured_server(tmp_path, api):
    s = _Session(tmp_path / "home")
    (s.home / ".claude.json").write_text(json.dumps({"mcpServers": {
        "gadget": {"command": "npx", "args": ["-y", "gadgethumans-mcp@1.0.15"]},
        "latest": {"command": "npx", "args": ["-y", "gadgethumans-mcp"]}}}))
    (s.project / ".mcp.json").write_text(json.dumps({"mcpServers": {
        "py": {"command": "uvx", "args": ["--from", "pytool==1.0.15", "pytool-cli"]}}}))
    start = pins._claude_payload(s, "SessionStart", source="startup")
    ctx = _hso(s.precheck(start))["additionalContext"]
    assert "⛔ MCP 'gadget' (npm:gadgethumans-mcp@1.0.15): Do not connect" in ctx
    assert "✅ MCP 'latest' (npm:gadgethumans-mcp): Safe to connect" in ctx
    assert "⛔ MCP 'py' (pypi:pytool==1.0.15): Do not connect" in ctx
    assert sorted(api, key=str) == sorted([("/package/npm/gadgethumans-mcp", "1.0.15"),
                                           ("/package/npm/gadgethumans-mcp", None),
                                           ("/package/pypi/pytool", "1.0.15")], key=str)
    # the per-call gate reads the pinned record
    rec = json.loads((s.home / ".cache" / "agentavow" / "scanned.json").read_text())["gadget"]
    assert rec["decision"] == "do_not_connect" and rec["id"] == "npm:gadgethumans-mcp==1.0.15"
    gate = s.gate_call(pins._mcp(s, "mcp__gadget__do", {}))
    assert _hso(gate)["permissionDecision"] == "deny"

    # Unpinning the server re-grades it at the latest release (and back again).
    (s.home / ".claude.json").write_text(json.dumps({"mcpServers": {
        "gadget": {"command": "npx", "args": ["-y", "gadgethumans-mcp"]}}}))
    api.clear()
    s.precheck(start)
    assert api == [("/package/npm/gadgethumans-mcp", None)]
    rec = json.loads((s.home / ".cache" / "agentavow" / "scanned.json").read_text())["gadget"]
    assert rec["decision"] == "safe" and rec["id"] == "npm:gadgethumans-mcp"


def test_dependency_pinned_in_package_json_is_graded_at_that_version(tmp_path, api):
    s = _Session(tmp_path / "home")
    (s.project / "package.json").write_text(json.dumps(
        {"dependencies": {"gadgethumans-mcp": "1.0.15", "@scope/tool": "^1.0.0"}}))
    ctx = _hso(s.precheck(pins._claude_payload(s, "SessionStart", source="startup")))[
        "additionalContext"]
    assert "⛔ dependency 'gadgethumans-mcp' (npm:gadgethumans-mcp@1.0.15): Do not connect" in ctx
    assert "✅ dependency '@scope/tool' (npm:@scope/tool@^1.0.0): Safe to connect" in ctx
    assert sorted(api, key=str) == sorted([("/package/npm/gadgethumans-mcp", "1.0.15"),
                                           ("/package/npm/@scope/tool", None)], key=str)


# --- Codex ----------------------------------------------------------------------------

def test_codex_mcp_add_pinned_old_release_is_denied(tmp_path, api):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(_codex_bash(
        s, "codex mcp add gadget -- npx -y gadgethumans-mcp@1.0.15")))
    h = out["hookSpecificOutput"]
    assert h["permissionDecision"] == "deny"
    assert "(npm:gadgethumans-mcp@1.0.15): Do not connect" in h["permissionDecisionReason"]
    assert api == [("/package/npm/gadgethumans-mcp", "1.0.15")]


def test_codex_config_toml_pinned_server_is_graded_at_that_version(tmp_path, api):
    s = _codex_session(tmp_path, '[mcp_servers.gadget]\ncommand = "npx"\n'
                                 'args = ["-y", "gadgethumans-mcp@1.0.15"]\n')
    out = _codex_accepts("SessionStart", s.precheck(_codex_start(s)))
    assert ("⛔ MCP 'gadget' (npm:gadgethumans-mcp@1.0.15): Do not connect"
            in out["hookSpecificOutput"]["additionalContext"])
    assert api == [("/package/npm/gadgethumans-mcp", "1.0.15")]


def test_codex_npm_install_pinned_is_denied(tmp_path, api):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(_codex_bash(
        s, "npm install gadgethumans-mcp@1.0.15")))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "npm package 'gadgethumans-mcp@1.0.15'" in out["systemMessage"]


# --- one name, several versions: every release is checked, the worst answer counts -----

@pytest.mark.parametrize("cmd,want", [
    ("npm i foo@1.0.0 foo@1.0.15", [("foo", "1.0.0"), ("foo", "1.0.15")]),
    ("npm i foo@1.0.0 foo@1.0.0", [("foo", "1.0.0")]),            # same pin once
    ("npm i foo foo@1.0.15", [("foo", None), ("foo", "1.0.15")]),
    ("pip install foo==1.0 foo==1.0.15 foo==1.0", [("foo", "1.0"), ("foo", "1.0.15")]),
    # five pins of one name do not push a second name past the cap
    ("npm i a@1.0.1 a@1.0.2 a@1.0.3 a@1.0.4 a@1.0.5 b",
     [("a", f"1.0.{i}") for i in range(1, 6)] + [("b", None)]),
])
def test_every_pinned_release_of_a_name_is_kept(pc, pi, cmd, want):
    assert [(p["pkg"], p["version"]) for p in pi._parse_installs(cmd, pc)] == want


@pytest.mark.parametrize("cmd", [
    "npm i gadgethumans-mcp@1.2.4 gadgethumans-mcp@1.0.15",
    "npm i gadgethumans-mcp@1.0.15 gadgethumans-mcp@1.2.4",
])
def test_a_bad_release_among_several_versions_asks(tmp_path, api, cmd):
    s = _Session(tmp_path / "home")
    h = _hso(s.pre_install(_claude_bash(s, cmd)))
    assert h["permissionDecision"] == "ask"
    assert "⛔ npm package 'gadgethumans-mcp@1.0.15': Do not connect" in h[
        "permissionDecisionReason"]
    assert sorted(v for _, v in api) == ["1.0.15", "1.2.4"]


def test_a_single_good_pin_stays_silent(tmp_path, api):
    s = _Session(tmp_path / "home")
    assert s.pre_install(_claude_bash(s, "npm i gadgethumans-mcp@1.2.4")) == ""


def test_an_unchecked_release_among_several_versions_asks(tmp_path, api, pi):
    s = _Session(tmp_path / "home")
    h = _hso(s.pre_install(_claude_bash(
        s, "npm i gadgethumans-mcp@1.2.4 gadgethumans-mcp@9.9.9")))  # 9.9.9: no answer
    assert h["permissionDecision"] == "ask"
    reason = h["permissionDecisionReason"]
    assert "names more than one version (1.2.4, 9.9.9) and 9.9.9 could not be checked" in reason
    assert reason.endswith(f"AgentAvow says: {pi.UNCHECKED_PIN}. Continue anyway?")
    assert "Do not connect" not in reason


def test_codex_unchecked_release_among_several_versions_is_denied(tmp_path, api):
    s = _codex_session(tmp_path)
    out = _codex_accepts("PreToolUse", s.pre_install(_codex_bash(
        s, "npm i gadgethumans-mcp@1.2.4 gadgethumans-mcp@9.9.9")))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "could not be checked" in out["systemMessage"]


# --- npm aliases: the target is graded, never the alias name ----------------------------

@pytest.mark.parametrize("cmd,want", [
    ("npm i foo@npm:evil@1.0.15", [("evil", "1.0.15")]),
    ("npm i foo@npm:evil", [("evil", None)]),
    ("npm i @a/foo@npm:@b/evil@1.0.15", [("@b/evil", "1.0.15")]),
    ("npm i npm:evil@1.0.15", [("evil", "1.0.15")]),
    ("pnpm add foo@npm:evil@^1.0.0", [("evil", None)]),
    ("npm i foo@1.0.15", [("foo", "1.0.15")]),                     # control: no alias
])
def test_npm_install_aliases_grade_the_target(pc, pi, cmd, want):
    assert [(p["pkg"], p["version"]) for p in pi._parse_installs(cmd, pc)] == want


@pytest.mark.parametrize("args,want_id", [
    (["-y", "foo@npm:gadgethumans-mcp@1.0.15"], "npm:gadgethumans-mcp==1.0.15"),
    (["-y", "foo@npm:gadgethumans-mcp"], "npm:gadgethumans-mcp"),
    (["-p", "foo@npm:@scope/tool@1.0.15", "tool"], "npm:@scope/tool==1.0.15"),
    (["--package=foo@npm:@scope/tool@1.0.15", "tool"], "npm:@scope/tool==1.0.15"),
    (["-y", "npm:gadgethumans-mcp@1.0.15"], "npm:gadgethumans-mcp==1.0.15"),
    (["-y", "foo@1.0.15"], "npm:foo==1.0.15"),                     # control: no alias
])
def test_npx_aliases_grade_the_target(pc, args, want_id):
    assert pc._resolve_target("s", {"command": "npx", "args": args})["id"] == want_id


def test_package_json_alias_grades_the_target(pc):
    got = [(d["pkg"], d.get("version")) for d in pc._npm_dep_map(
        {"foo": "npm:evil@1.0.15", "bar": "npm:@s/evil@^1", "baz": "1.0.0"})]
    assert got == [("evil", "1.0.15"), ("@s/evil", None), ("baz", "1.0.0")]


def test_alias_install_of_a_bad_release_asks(tmp_path, api):
    s = _Session(tmp_path / "home")
    h = _hso(s.pre_install(_claude_bash(s, "npm i foo@npm:gadgethumans-mcp@1.0.15")))
    assert h["permissionDecision"] == "ask"
    assert "npm package 'gadgethumans-mcp@1.0.15': Do not connect" in h[
        "permissionDecisionReason"]
    assert api == [("/package/npm/gadgethumans-mcp", "1.0.15")]
    # control: the alias of the latest release is graded at latest
    assert s.pre_install(_claude_bash(s, "npm i foo@npm:gadgethumans-mcp")) == ""


def test_alias_server_and_dependency_are_graded_as_the_target(tmp_path, api):
    s = _Session(tmp_path / "home")
    (s.home / ".claude.json").write_text(json.dumps({"mcpServers": {
        "gadget": {"command": "npx", "args": ["-y", "harmless@npm:gadgethumans-mcp@1.0.15"]}}}))
    (s.project / "package.json").write_text(json.dumps(
        {"dependencies": {"harmless": "npm:@scope/tool@1.0.15"}}))
    ctx = _hso(s.precheck(pins._claude_payload(s, "SessionStart", source="startup")))[
        "additionalContext"]
    assert "⛔ MCP 'gadget' (npm:gadgethumans-mcp@1.0.15): Do not connect" in ctx
    assert "⛔ dependency '@scope/tool' (npm:@scope/tool@1.0.15): Do not connect" in ctx


# --- a pip environment marker inside one quoted argument ------------------------------

@pytest.mark.parametrize("cmd,want", [
    ("pip install 'pytool==1.0.15; python_version>\"3\"'", [("pytool", "==1.0.15")]),
    ("pip install \"pytool==1.0.15; sys_platform=='linux'\" rich",
     [("pytool", "==1.0.15"), ("rich", "")]),
    ("pip install 'pytool>=1; python_version>\"3\"'", [("pytool", ">=1")]),
    ("pip install pytool; echo done", [("pytool", "")]),           # control: a real ';'
    ("pip install pytool && npm i 'a|b'", [("pytool", "")]),
])
def test_quoted_marker_is_part_of_the_requirement(pc, pi, cmd, want):
    assert [(pkg, spec) for _, pkg, spec in pi._package_installs(cmd, pc)] == want


def test_quoted_marker_pin_of_a_bad_release_asks(tmp_path, api):
    s = _Session(tmp_path / "home")
    h = _hso(s.pre_install(_claude_bash(
        s, "pip install 'pytool==1.0.15; python_version>\"3\"'")))
    assert h["permissionDecision"] == "ask"
    assert s.pre_install(_claude_bash(s, "pip install 'pytool>=1; python_version>\"3\"'")) == ""


# --- another registry or index: named as not checked, never graded as if public -------

@pytest.mark.parametrize("cmd", [
    "npm i --registry https://npm.internal.example gadgethumans-mcp",
    "npm i --registry=https://npm.internal.example gadgethumans-mcp",
    "npm i --@acme:registry=https://npm.internal.example gadgethumans-mcp",
    "npm_config_registry=https://npm.internal.example npm i gadgethumans-mcp",
    "pnpm add --registry https://npm.internal.example gadgethumans-mcp",
    "pip install -i https://pypi.internal.example/simple pytool",
    "pip install --index-url https://pypi.internal.example/simple pytool",
    "pip install --extra-index-url=https://pypi.internal.example/simple pytool",
    "pip install -f https://wheels.internal.example pytool",
    "PIP_INDEX_URL=https://pypi.internal.example/simple pip install pytool",
    "uv pip install --index https://pypi.internal.example/simple pytool",
    "uv add --default-index https://pypi.internal.example/simple pytool",
    "poetry add --source internal pytool",
])
def test_another_index_is_named_not_graded(tmp_path, api, cmd):
    s = _Session(tmp_path / "home")
    out = json.loads(s.pre_install(_claude_bash(s, cmd)))
    msg = out["systemMessage"]
    assert "not checked — this command installs it from another" in msg
    assert "permissionDecision" not in out["hookSpecificOutput"]  # a note, never a stop
    assert "internal.example" not in msg  # the index address is never repeated
    assert api == []


@pytest.mark.parametrize("cmd", [
    "npm i gadgethumans-mcp", "pip install pytool", "uv add pytool",
    "pip install --retries 2 pytool", "npm i --loglevel warn gadgethumans-mcp",
])
def test_default_index_is_graded_as_before(tmp_path, api, cmd):
    s = _Session(tmp_path / "home")
    assert s.pre_install(_claude_bash(s, cmd)) == ""  # Safe at latest: silent
    assert len(api) == 1
