"""Printed install hints held in a variable, in a bundle chunk too large to scan whole.

@earendil-works/pi-coding-agent 1.3.0 read "Do not connect" for

    let installerCommand = process.platform === "win32" ? '… | iex' : "curl … | sh";
    console.log(`  ${source_default.bold(installerCommand)}`)

in a 3.5 MB esbuild chunk. Three things kept it critical: the finding came from the
tail window of the oversized file (line 0, so the package pass could not locate it),
``source_default`` is esbuild's name for chalk imported from another chunk, and the
package-wide "console replaced?" guard tripped on code that never replaces it for this
process (stdout redirected to stderr for a TUI, a ``new Console`` object, a QuickJS
prelude string). Each relaxation is paired with recall fixtures that must stay
critical: a variable that reaches a runner, a return, an export, an object / array /
other function, an alias or reassignment, a shadowing binding, and a console / stream
replacement or a prelude string that does run something.
"""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.package_context import _printed_hint
from src.scanner.patterns import DYNAMIC_REMOTE_LOAD_PATTERNS
from src.scanner.printed_hint import Hints
from src.scanner.scan import ScanResult, _calculate_trust_score, _scan_content, apply_artifact_scan

RULE = "curl/wget piped to shell"
PAT = next(p for n, p, _s in DYNAMIC_REMOTE_LOAD_PATTERNS if n == RULE)
CMD = "curl -fsSL https://pi.example/install.sh | sh"
PS = 'powershell -c "irm https://pi.example/install.ps1 | iex"'


def _pkg(files: dict[str, str], eco: str = "npm") -> ScanResult:
    if eco == "npm":
        files = {"package.json": '{"name":"p"}', **files}
    fetched = ArtifactFetchResult(
        ecosystem=eco, name="p", version="1", kind="tarball" if eco == "npm" else "wheel",
        ok=True, files={p: _make_file(p, t.encode()) for p, t in files.items()})
    r = ScanResult(repo=f"{eco}:p", stars=0, description="", framework="")
    apply_artifact_scan(r, eco, fetched)
    r.trust_score = _calculate_trust_score(r)
    return r


def _sev(r: ScanResult, path: str) -> set[str]:
    return {f.severity for f in r.findings if f.name == RULE and f.file_path == path}


def _single(text: str, path: str = "dist/a.js") -> set[str]:
    f, _p, _s = _scan_content(text, path)
    return {x.severity for x in f if x.name == RULE}


def _low(files: dict[str, str], path: str, eco: str = "npm") -> None:
    r = _pkg(files, eco)
    assert _sev(r, path) == {"low"}, [(f.severity, f.line_number, f.remediation)
                                      for f in r.findings if f.name == RULE]


def _crit(files: dict[str, str], path: str, eco: str = "npm") -> None:
    r = _pkg(files, eco)
    assert "critical" in _sev(r, path), [(f.severity, f.remediation)
                                         for f in r.findings if f.name == RULE]


# esbuild's chalk chunk: `var source_default = chalk` exported to every other chunk.
CHALK_CHUNK = (
    'var styles={bold:[1,22],yellow:[33,39]};function createChalk(o){return{}}'
    'var chalk=createChalk(),chalkStderr=createChalk({level:0});'
    'var source_default=chalk;export{source_default};\n'
)
PI_CHUNK = (
    'import{source_default}from"./chunk-CHALK.js";'
    'async function selfUpdate(installMethod){if(installMethod==="npm"){'
    'let installerCommand=process.platform==="win32"?\'' + PS + '\':"' + CMD + '";'
    'console.log(),console.log(source_default.yellow("This install does not pin its '
    'dependencies.")),console.log(source_default.yellow("Run the installer:")),'
    'console.log(),console.log(`  ${source_default.bold(installerCommand)}`)}return!0}'
    'export{selfUpdate};\n'
)


def _oversized(chunk: str) -> str:
    """Pad a chunk past the 500 KB per-file cap so the hint lands in the tail window
    (line 0), with varied short lines that do not read as filler."""
    head = "".join(f"var v{i}={i};\n" for i in range(45000))
    return head + chunk


# ---------------------------------------------------------------------------
# The pi-coding-agent shape: lowered
# ---------------------------------------------------------------------------

class TestPiCodingAgentShape:
    def test_variable_printed_through_chalk_alias_is_low(self):
        _low({"dist/chunks/chunk-CHALK.js": CHALK_CHUNK, "dist/chunks/chunk-PI.js": PI_CHUNK},
             "dist/chunks/chunk-PI.js")

    def test_oversized_bundle_tail_window_finding_is_located_and_low(self):
        big = _oversized(PI_CHUNK)
        assert len(big) > 500_000
        r = _pkg({"dist/chunks/chunk-CHALK.js": CHALK_CHUNK, "dist/chunks/chunk-PI.js": big})
        hits = [f for f in r.findings if f.name == RULE and f.file_path == "dist/chunks/chunk-PI.js"]
        assert hits and all(f.line_number == 0 for f in hits)  # the tail window's
        assert {f.severity for f in hits} == {"low"}

    def test_stdout_takeover_new_console_and_quickjs_prelude_do_not_block(self):
        # pi also redirects stdout to stderr for its TUI, builds a `new Console` on a
        # Transform, and ships a QuickJS prelude (a string) that defines its own console.
        tui = (
            'import{Transform}from"node:stream";import{Console}from"node:console";'
            'var stdoutTakeoverState;function takeOverStdout(){if(stdoutTakeoverState)return;'
            'let rawStdoutWrite=process.stdout.write.bind(process.stdout),'
            'rawStderrWrite=process.stderr.write.bind(process.stderr),'
            'originalStdoutWrite=process.stdout.write;'
            'process.stdout.write=((chunk,enc,callback)=>typeof enc=="function"?'
            'rawStderrWrite(String(chunk),enc):rawStderrWrite(String(chunk),callback)),'
            'stdoutTakeoverState={rawStdoutWrite,rawStderrWrite,originalStdoutWrite}}'
            'function restoreStdout(){stdoutTakeoverState&&(process.stdout.write='
            'stdoutTakeoverState.originalStdoutWrite,stdoutTakeoverState=void 0)}'
            'class L{constructor(disableColors){this.transform=new Transform({transform'
            '(chunk,_enc,cb){cb(null,chunk)}}),this.logger=new Console({stdout:this.transform,'
            'inspectOptions:{colors:!disableColors}})}}export{takeOverStdout,restoreStdout,L};\n'
        )
        worker = (
            'import{parentPort}from"node:worker_threads";'
            'var EXPECTS={a:1},PRELUDE_SOURCE=`(function (bridge) {\n'
            '\tif (!x) throw new TypeError(${JSON.stringify(EXPECTS)});\n'
            '\tconst console = {};\n\tfor (const level of ["log", "error"]) {\n'
            '\t\tconsole[level] = (...args) => { bridge.output(args.join(" ")); };\n\t}\n'
            '\tObject.defineProperty(globalThis, "console", { value: console });\n})`;'
            'function fnv1a(text){let h=2166136261;for(let i=0;i<text.length;i++)'
            'h^=text.charCodeAt(i),h=Math.imul(h,16777619);return(h>>>0).toString(16)}'
            'var PRELUDE_HASH=fnv1a(PRELUDE_SOURCE);'
            'class Ctx{evalCode(code,filename="<eval>"){return this.ffi.QTS_Eval(code,filename)}}'
            'function boot(vm){return vm.evalCode(PRELUDE_SOURCE,"prelude.js")}'
            'parentPort.on("message",m=>boot(m));\n'
        )
        _low({"dist/chunks/chunk-CHALK.js": CHALK_CHUNK, "dist/chunks/chunk-PI.js": PI_CHUNK,
              "dist/chunks/tui.js": tui, "dist/chunks/worker.js": worker},
             "dist/chunks/chunk-PI.js")


@pytest.mark.parametrize("src", [
    # ternary / || of literals, printed in a template, through chalk, by concatenation
    f'const chalk = require("chalk");\nfunction hint(win) {{\n'
    f'  const cmd = win ? \'{PS}\' : "{CMD}";\n  console.log(`  ${{chalk.bold(cmd)}}`);\n}}\n',
    f'function hint() {{\n  const cmd = process.env.PI_INSTALL || "{CMD}";\n'
    f'  console.error("Run: " + cmd);\n}}\n',
    f'let cmd = "{CMD}"; console.log(cmd), process.stderr.write(`${{cmd}}\\n`);\n',
    # minified: every use on the one line (a one-letter name that also occurs as a
    # word inside a string, `-c`, is not followed: see the recall list)
    f'function u(m){{if(m==="npm"){{let n1=process.platform==="win32"?\'{PS}\':"{CMD}";'
    f'console.log(),console.log(`  ${{n1}}`)}}return!0}}\n',
])
def test_js_variable_printed_shapes_are_low(src):
    assert _single(src) == {"low"}


@pytest.mark.parametrize("src", [
    f'import sys\n\ndef hint(win):\n    cmd = "irm x | iex" if win else "{CMD}"\n'
    '    print(f"  {cmd}")\n',
    f'import sys\n\ndef hint():\n    cmd = "{CMD}"\n    sys.stderr.write("run: " + cmd + "\\n")\n',
])
def test_python_variable_printed_shapes_are_low(src):
    assert _single(src, "pkg/cli.py") == {"low"}


# ---------------------------------------------------------------------------
# MUST STAY CRITICAL: where the variable goes
# ---------------------------------------------------------------------------

_DECL = f'const cp = require("child_process");\nfunction f(x, y) {{\n  let c = "{CMD}";\n'


@pytest.mark.parametrize("use", [
    # run sinks
    "cp.exec(c);", "cp.execSync(c);", 'cp.spawn("sh", ["-c", c]);', "cp.spawnSync(c);",
    'require("child_process").execSync(c);', "eval(c);", "new Function(c)();",
    "Function(c)();", "setTimeout(c, 0);",
    # printed AND run
    "console.log(c); cp.execSync(c);", "console.log(`${c}`), cp.exec(c);",
    # returned / exported / object / array / other function
    "return c;", "return `run ${c}`;", "module.exports.cmd = c;", "x.cmd = c;",
    "const o = { cmd: c }; console.log(o);", "const a = [c]; cp.execSync(a.join(' '));",
    "y(c);", "x.push(c);", "fetch(c);", "console.log(c), y.write(c);",
    # aliased / reassigned
    "const a = c; console.log(a);", "const a = x ? c : 'none'; console.log(a);",
    "let a; a = c; console.log(a);", "c = x; console.log(c);", 'c += " && rm -rf ~"; console.log(c);',
    "c ||= x; console.log(c);", "[c] = x; console.log(c);", "c++; console.log(c);",
    # shadowed inside the scope
    "console.log(c); { let c = x; cp.execSync(c); }",
    "console.log(c); function g(c) { cp.execSync(c); } g(x);",
    "console.log(c); const g = (c) => cp.execSync(c); g(x);",
    "console.log(c); try { y(); } catch (c) { cp.execSync(c); }",
    "console.log(c); [x].forEach(c => cp.execSync(c));",
    # the name used through a string / a computed read
    'console.log(c); cp.execSync(eval("c"));',
])
def test_js_variable_reaching_anything_but_output_stays_critical(use):
    src = _DECL + "  " + use + "\n}\nmodule.exports = { f };\n"
    assert _single(src) == {"critical"}
    _crit({"dist/a.js": src}, "dist/a.js")


@pytest.mark.parametrize("src", [
    # exported variable, per-file (the name leaves the file)
    f'export const CMD = "{CMD}";\nconsole.log(CMD);\n',
    f'const CMD = "{CMD}";\nconsole.log(CMD);\nexport {{ CMD }};\n',
    f'const CMD = "{CMD}";\nconsole.log(CMD);\nmodule.exports = {{ CMD }};\n',
    # a returned value the caller runs
    f'const cp = require("child_process");\nconst CMD = "{CMD}";\n'
    'function hint() { return CMD; }\ncp.execSync(hint());\n',
    # an anonymous function returns it
    f'const CMD = "{CMD}";\nmodule.exports = function () {{ return CMD; }};\n',
])
def test_js_variable_leaving_the_file_stays_critical(src):
    assert _single(src) == {"critical"}


def test_exported_variable_run_in_another_file_stays_critical():
    _crit({"dist/c.js": f'const c = "{CMD}";\nconsole.log(c);\nexport {{ c }};\n',
           "dist/u.js": 'import { c } from "./c.js";\nimport { execSync } from "child_process";\n'
                        'execSync(c);\n'}, "dist/c.js")


# ---------------------------------------------------------------------------
# MUST STAY CRITICAL: the print call is not really output
# ---------------------------------------------------------------------------

def _with_chunk(extra: dict[str, str], chunk: str = PI_CHUNK, chalk: str = CHALK_CHUNK) -> None:
    _crit({"dist/chunks/chunk-CHALK.js": chalk, "dist/chunks/chunk-PI.js": chunk, **extra},
          "dist/chunks/chunk-PI.js")


@pytest.mark.parametrize("chalk", [
    # the "chalk" source_default aliases is a runner
    'import{execSync}from"child_process";var chalk={bold:execSync,yellow:(s)=>s};'
    'var source_default=chalk;export{source_default};\n',
    'import cp from"child_process";var chalk={bold:(s)=>cp.execSync(s),yellow:(s)=>s};'
    'var source_default=chalk;export{source_default};\n',
    # source_default is not an alias of a colour library
    'import cp from"child_process";var runner={bold:cp.execSync,yellow:cp.execSync};'
    'var source_default=runner;export{source_default};\n',
    'import cp from"child_process";var source_default=cp;export{source_default};\n',
    # reassigned after the alias
    'import cp from"child_process";var chalk={};var source_default=chalk;'
    'source_default={bold:cp.execSync,yellow:cp.execSync};export{source_default};\n',
    'import cp from"child_process";var chalk={};var source_default=chalk;'
    'function source_default(){};export{source_default};\n',
    # adversarial round: the aliased "chalk" is a Proxy handing out a runner
    'import cp from"child_process";var chalk=new Proxy({},{get:()=>cp.execSync});'
    'var source_default=chalk;export{source_default};\n',
    'import cp from"child_process";function createChalk(){return{bold:cp.execSync}}'
    'var chalk=createChalk();var source_default=chalk;export{source_default};\n',
])
def test_colour_alias_that_runs_stays_critical(chalk):
    _with_chunk({}, chalk=chalk)


def test_colour_alias_is_not_trusted_per_file():
    # Without the package the imported receiver cannot be checked.
    assert _single(PI_CHUNK) == {"critical"}


@pytest.mark.parametrize("extra", [
    # console / stdout replaced by a runner, in another file
    'import{execSync}from"child_process";console.log=(m)=>execSync(m);\n',
    'import{execSync}from"child_process";process.stdout.write=(s)=>execSync(s);\n',
    'import cp from"child_process";const run=cp.execSync;process.stdout.write=run;\n',
    'import cp from"child_process";const run=(s)=>cp.execSync(s);'
    'process.stdout.write=(chunk)=>run(String(chunk));\n',
    # a "redirect" whose target is later rebound to a runner
    'import cp from"child_process";let rawStderrWrite=process.stderr.write.bind(process.stderr);'
    'rawStderrWrite=cp.execSync;process.stdout.write=(c)=>rawStderrWrite(String(c));\n',
    # a parameter name reused outside its function smuggles the runner in
    'import cp from"child_process";const s=cp.execSync;process.stdout.write=((s)=>s)(s);\n',
    # a new Console on a shell's stdin, installed as the global console
    'import{Console}from"node:console";import{spawn}from"child_process";'
    'const sh=spawn("sh");globalThis.console=new Console(sh.stdin);\n',
    'import{Console}from"node:console";import{spawn}from"child_process";'
    'const logger=new Console(spawn("sh").stdin);Object.assign(console,logger);\n',
    # Console / Transform that are not Node's own
    'import{Console}from"./evil.js";const l=new Console({stdout:process.stdout});\n',
    # stdout replaced through Object.assign / a computed key
    'import cp from"child_process";Object.assign(process.stdout,{write:cp.execSync});\n',
    'import cp from"child_process";process.stdout["write"]=cp.execSync;\n',
    # a prelude string that is evaluated in this realm
    'var P=`console.log = (m) => globalThis.run(m);`;eval(P);\n',
    'var P=`console.log = (m) => globalThis.run(m);`;new Function(P)();\n',
    'import vm from"node:vm";var P=`console.log = (m) => globalThis.run(m);`;'
    'vm.runInThisContext(P);\n',
    'var P=`console.log = (m) => globalThis.run(m);`;function boot(s){return eval(s)}boot(P);\n',
    'var P=`console.log = (m) => globalThis.run(m);`;export{P};\n',
    'var P=`console.log = (m) => run(m)`;var Q=P;eval(Q);\n',
    # prelude text handed straight to an evaluator / a function that evaluates it
    'eval(`console.log = (m) => globalThis.run(m);`);\n',
    'function boot(s){return new Function(s)()}boot(`console.log = (m) => run(m)`);\n',
    # adversarial round: a stream alias rebound through a destructuring pattern
    'import cp from"child_process";let rawStderrWrite=process.stderr.write.bind(process.stderr);'
    '[rawStderrWrite]=[cp.execSync];process.stdout.write=(c)=>rawStderrWrite(String(c));\n',
    # ... a prelude "evaluator" method that is really eval
    'var P=`console.log = (m) => run(m)`;const vm={evalCode:eval};'
    'class Q{evalCode(c){return c}}vm.evalCode(P);\n',
    # ... a console declared in another file (could be loaded as a classic script)
    'import{execSync}from"child_process";var console={log:(m)=>execSync(m)};\n',
    # a console replacement calling a function set in another file
    'console.log=(m)=>globalThis.run(m);\n',
    'console.log=(m)=>run(m);\n',
    'import cp from"child_process";var P=`${cp.execSync("id")}console.log = 1`;boot(P);\n',
])
def test_console_or_stream_replacement_that_runs_stays_critical(extra):
    _with_chunk({"dist/chunks/zz.js": extra})


@pytest.mark.parametrize("prefix", [
    # lexical rebinding of console in the file of the print call
    'import console from"./evil.js";',
    'import{log as x,evil as console}from"./evil.js";',
    'const console={log:(m)=>m};',
])
def test_console_rebound_in_the_same_file_stays_critical(prefix):
    _with_chunk({"dist/chunks/evil.js": 'export default {log(){}};export const evil={};'},
                chunk=prefix + PI_CHUNK)


def test_oversized_line_zero_with_a_run_copy_stays_critical():
    # The same snippet on two lines of the oversized file: one printed, one run.
    line = f'let installerCommand="{CMD}";console.log(installerCommand)'
    run = 'import cp from"child_process";\n' + line + ';cp.execSync(installerCommand)\n'
    big = _oversized(run + "\n" + line + "\n")
    _crit({"dist/chunks/chunk-PI.js": big}, "dist/chunks/chunk-PI.js")


def test_line_zero_without_the_snippet_in_the_text_stays_critical():
    class F:
        line_number = 0
        snippet = "something else entirely"
        file_path = "a.js"
    h = Hints({"a.js": f'console.log("{CMD}");\n'}, package=True)
    assert _printed_hint(h, f'console.log("{CMD}");\n', F()) is False


# ---------------------------------------------------------------------------
# Python
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    "    subprocess.run(cmd, shell=True)\n",
    "    os.system(cmd)\n",
    "    eval(cmd)\n",
    "    print(cmd)\n    os.system(cmd)\n",
    "    return cmd\n",
    "    a = cmd\n    print(a)\n",
    "    a = cmd if x else 'none'\n    print(a)\n",
    "    cmd = x\n    print(cmd)\n",
    "    cmd += ' && rm -rf ~'\n    print(cmd)\n",
    "    print(cmd)\n    def g(cmd):\n        os.system(cmd)\n    g(x)\n",
    "    print(cmd)\n    for cmd in x:\n        os.system(cmd)\n",
    "    print(cmd)\n    try:\n        pass\n    except Exception as cmd:\n        os.system(str(cmd))\n",
    "    d = {'c': cmd}\n    print(d)\n",
    "    y(cmd)\n",
])
def test_python_variable_reaching_anything_but_output_stays_critical(body):
    src = (f'import os\nimport subprocess\n\ndef f(x, y):\n    cmd = "{CMD}"\n' + body)
    assert _single(src, "pkg/up.py") == {"critical"}
    _crit({"pkg/up.py": src}, "pkg/up.py", eco="pypi")


def test_python_returned_hint_run_by_the_caller_stays_critical():
    src = (f'import os\n\ndef hint():\n    cmd = "{CMD}"\n    return "run: " + cmd\n\n'
           'def main():\n    os.system(hint())\n')
    _crit({"pkg/up.py": src}, "pkg/up.py", eco="pypi")
