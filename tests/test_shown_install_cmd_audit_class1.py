"""Install commands only shown to a person are not critical (verdict accuracy audit,
class 1).

Each fixture below is built from the tool's own source (the hint lines are verbatim;
the surrounding code is the part the walk has to read). Each one read critical
("curl/wget piped to shell") before this change and reads low now. Next to each one is
the same command reaching something that runs it, which must stay critical.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.local_scan import scan_local
from src.scanner.scan import ScanResult, _calculate_trust_score, apply_artifact_scan

RULE = "curl/wget piped to shell"


def _tree(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    subprocess.run(["git", "init", "-q"], cwd=root, check=True)
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


def _local(root: Path, files: dict[str, str], path: str, snippet: str = "") -> set[str]:
    _tree(root, files)
    r = scan_local(root)
    return {f.severity for f in r.findings if f.name == RULE and f.file_path == path
            and snippet in (f.snippet or "")}


def _pkg(files: dict[str, str], path: str) -> set[str]:
    files = {"package.json": '{"name":"p","main":"index.js"}', **files}
    fetched = ArtifactFetchResult(
        ecosystem="npm", name="p", version="1", kind="tarball", ok=True,
        files={p: _make_file(p, t.encode()) for p, t in files.items()})
    r = ScanResult(repo="npm:p", stars=0, description="", framework="")
    apply_artifact_scan(r, "npm", fetched)
    r.trust_score = _calculate_trust_score(r)
    return {f.severity for f in r.findings if f.name == RULE and f.file_path == path}


# ---------------------------------------------------------------------------------
# openclaw: an exported message formatter; callers put it in `fixHint` / `remedy`
# fields; vitest files mock the module (a namespace spread) and one test line has
# `"Setup trusted Node").with?.["node-version"]`.
# ---------------------------------------------------------------------------------

OC_NODE_VERSION = """export const SUPPORTED_NODE_VERSIONS = ">=24.16.0 <25 || >=26.1.0";

export function formatUnsupportedNodeVersionMessage(version) {
  return [
    `Node ${version ?? "unknown"} is unsupported; OpenClaw requires ${SUPPORTED_NODE_VERSIONS}.`,
    "npm can finish installing OpenClaw without running its preinstall check; a successful install does not mean Node is supported.",
    "Re-run the installer: curl -fsSL https://openclaw.ai/install.sh | bash",
    "On Windows: iwr -useb https://openclaw.ai/install.ps1 | iex",
    "Or with nvm: nvm install 26 && nvm use 26 && nvm alias default 26",
    "Then rerun openclaw update. See https://docs.openclaw.ai/install/node",
  ].join("\\n");
}
"""
OC_DOCTOR = """import { formatUnsupportedNodeVersionMessage } from "../../node-version.mjs";

export function checkRuntime(findings, runtime, ownerHint) {
  findings.push({
    checkId: "core/doctor/gateway-daemon",
    severity: runtime.status === "supported" ? "info" : "warning",
    ...(runtime.status !== "supported"
      ? {
          fixHint:
            ownerHint ??
            [
              ...(runtime.status === "unsupported"
                ? [formatUnsupportedNodeVersionMessage(runtime.version)]
                : []),
              "Repair the Node runtime, then run `openclaw gateway install`.",
            ].join("\\n"),
        }
      : {}),
  });
}
"""
OC_UPDATE = """import { formatUnsupportedNodeVersionMessage } from "../../../node-version.mjs";

export function preflight(createUpdatePreflightDiagnostics, runtimeFailure) {
  return createUpdatePreflightDiagnostics({
    check: "node-runtime",
    remedy: `${formatUnsupportedNodeVersionMessage(process.versions.node)}\\n${runtimeFailure}`,
  });
}
"""
OC_MOCK_TEST = """import { describe, expect, it, vi } from "vitest";
vi.mock("../../node-version.mjs", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../../node-version.mjs")>();
  return { ...actual };
});
describe("x", () => { it("y", () => { expect(1).toBe(1); }); });
"""
OC_WORKFLOW_TEST = """import { expect, it } from "vitest";
it("pins node", () => {
  expect(step(oidc, "Setup trusted Node").with?.["node-version"]).toBe("${{ env.NODE_VERSION }}");
});
"""


def test_openclaw_formatter_shown_in_fix_hints_is_low(tmp_path):
    assert _local(tmp_path, {
        "package.json": '{"name":"openclaw"}',
        "node-version.mjs": OC_NODE_VERSION,
        "src/flows/doctor-core-checks.runtime.ts": OC_DOCTOR,
        "src/cli/update-cli/update-command-run.ts": OC_UPDATE,
        "src/process/child-memory.test.ts": OC_MOCK_TEST,
        "test/scripts/plugin-npm-extended-stable-workflow.test.ts": OC_WORKFLOW_TEST,
    }, "node-version.mjs") == {"low"}


def test_openclaw_formatter_alone_in_view_is_low(tmp_path):
    # A repository scan reads a capped set of files: the callers may be out of view.
    assert _local(tmp_path, {"node-version.mjs": OC_NODE_VERSION},
                  "node-version.mjs") == {"low"}


@pytest.mark.parametrize("caller", [
    # A caller in view runs the message.
    'import { formatUnsupportedNodeVersionMessage } from "./node-version.mjs";\n'
    'import { execSync } from "node:child_process";\n'
    'execSync(formatUnsupportedNodeVersionMessage("1"));\n',
    # A field the code later hands to a runner.
    'import { formatUnsupportedNodeVersionMessage } from "./node-version.mjs";\n'
    'import { execSync } from "node:child_process";\n'
    'const f = { fixHint: formatUnsupportedNodeVersionMessage("1") };\n'
    'execSync(f.fixHint);\n',
    'import { formatUnsupportedNodeVersionMessage } from "./node-version.mjs";\n'
    'import { spawnSync } from "node:child_process";\n'
    'const f = { fixHint: formatUnsupportedNodeVersionMessage("1") };\n'
    'const { fixHint } = f;\n\n\n\nspawnSync("sh", ["-c", fixHint]);\n',
    # Every value of the object handed to a runner.
    'import { formatUnsupportedNodeVersionMessage } from "./node-version.mjs";\n'
    'import { execSync } from "node:child_process";\n'
    'const f = { fixHint: formatUnsupportedNodeVersionMessage("1") };\n'
    'Object.values(f).forEach((v) => execSync(v));\n',
    # A command-shaped field.
    'import { formatUnsupportedNodeVersionMessage } from "./node-version.mjs";\n'
    'import { run } from "./runner.js";\n'
    'run({ command: formatUnsupportedNodeVersionMessage("1") });\n',
])
def test_openclaw_formatter_that_reaches_a_runner_stays_critical(tmp_path, caller):
    assert _local(tmp_path, {
        "package.json": '{"name":"openclaw"}',
        "node-version.mjs": OC_NODE_VERSION,
        "caller.ts": caller,
        "runner.js": "import { execSync } from 'node:child_process';\n"
                     "export function run(o) { execSync(o.command); }\n",
    }, "node-version.mjs") == {"critical"}


def test_a_function_not_named_as_a_message_keeps_its_callers_rule(tmp_path):
    body = OC_NODE_VERSION.replace("formatUnsupportedNodeVersionMessage", "nodeFix")
    assert _local(tmp_path, {"node-version.mjs": body}, "node-version.mjs") == {"critical"}


# ---------------------------------------------------------------------------------
# freellmapi: `notes: [...]` of a generated client config, printed by the CLI; the
# repository's server (not loaded by the CLI) calls `stmt.run(…, x.notes, …)`.
# ---------------------------------------------------------------------------------

FL_TOOLS = """import type { GenerateContext } from './types.js';

export function mimoCode(ctx: GenerateContext) {
  return {
    files: [],
    notes: [
      'Install MiMo Code with: curl -fsSL https://mimo.xiaomi.com/install | bash',
      'Export FREELLMAPI_API_KEY before starting MiMo Code.',
      'One-shot check: mimo run "Say hello"',
    ],
  };
}
"""
FL_TYPES = "export interface GenerateContext { url: string }\n"
FL_INDEX = """import spawn from 'cross-spawn';
import { mimoCode } from './tools.js';

export function main(ctx) {
  const generation = mimoCode(ctx);
  for (const note of generation.notes) process.stdout.write(`\\n${note}\\n`);
  return generation;
}

export function checkClient() {
  return spawn.sync('mimo', ['--version'], { stdio: 'inherit' });
}
"""
FL_SERVER = """import Database from 'better-sqlite3';
export function save(db: Database, measured: { notes: string }) {
  const update = db.prepare('UPDATE t SET notes = ?');
  update.run(measured.notes);
}
"""


def test_freellmapi_notes_printed_by_the_cli_are_low(tmp_path):
    assert _local(tmp_path, {
        "cli/package.json": '{"name":"freellmapi"}',
        "cli/src/tools.ts": FL_TOOLS,
        "cli/src/types.ts": FL_TYPES,
        "cli/src/index.ts": FL_INDEX,
        "server/package.json": '{"name":"@freellmapi/server"}',
        "server/src/db.ts": FL_SERVER,
    }, "cli/src/tools.ts") == {"low"}


@pytest.mark.parametrize("index", [
    FL_INDEX.replace("process.stdout.write(`\\n${note}\\n`)", "spawn.sync('sh', ['-c', note])"),
    FL_INDEX + "export function run(ctx) {\n  const { notes } = mimoCode(ctx);\n\n\n"
               "  spawn.sync('sh', ['-c', notes[0]]);\n}\n",
    # A computed key, an entries loop and an alias chain.
    FL_INDEX + "export function run(ctx) {\n  const g = mimoCode(ctx);\n  const k = 'notes';\n"
               "  const list = g[k];\n  spawn.sync('sh', ['-c', list[0]]);\n}\n",
    FL_INDEX + "export function run(ctx) {\n"
               "  for (const [, v] of Object.entries(mimoCode(ctx))) spawn.sync('sh', ['-c', v[0]]);\n}\n",
    FL_INDEX + "export function run(ctx) {\n  const g = mimoCode(ctx);\n  const list = g.notes;\n"
               "  const a = list;\n  const b = a[0];\n  spawn.sync('sh', ['-c', b]);\n}\n",
])
def test_freellmapi_notes_run_by_the_cli_stay_critical(tmp_path, index):
    assert _local(tmp_path, {
        "cli/package.json": '{"name":"freellmapi"}',
        "cli/src/tools.ts": FL_TOOLS,
        "cli/src/types.ts": FL_TYPES,
        "cli/src/index.ts": index,
    }, "cli/src/tools.ts") == {"critical"}


def test_freellmapi_notes_with_an_unresolvable_dynamic_import_use_every_file(tmp_path):
    # `import(x)` in a file the CLI loads: any file may be in the same process, so the
    # server's runner counts too.
    idx = FL_INDEX + "export async function plugin(p) { return import(p); }\n"
    server = FL_SERVER + ("import { execSync } from 'node:child_process';\n"
                          "export function go(g) { execSync(g.notes[0]); }\n")
    assert _local(tmp_path, {
        "cli/package.json": '{"name":"freellmapi"}',
        "cli/src/tools.ts": FL_TOOLS,
        "cli/src/types.ts": FL_TYPES,
        "cli/src/index.ts": idx,
        "server/package.json": '{"name":"@freellmapi/server"}',
        "server/src/db.ts": server,
    }, "cli/src/tools.ts") == {"critical"}


# ---------------------------------------------------------------------------------
# OpenMausBot: `command_line` printf-s the re-run command; every caller captures it
# with `$(command_line …)` straight into a `say` / `fail` message.
# ---------------------------------------------------------------------------------

OMB = """#!/bin/sh
set -eu
ADMIN_URL="${MAUSBOT_ADMIN_URL:-@MAUSBOT_ADMIN_URL@}"

say() { printf '%s\\n' "$*"; }
fail() {
  printf '\\n%s\\n' "$*" >&2
  exit 1
}

command_line() { # what to run again, as the person ran it
  printf 'curl -fsSL %s/install.sh | sudo sh -s -- %s' "$ADMIN_URL" "$*"
}

need_root() {
  [ "$(id -u)" = 0 ] || fail "Please run this as root: put sudo before sh, like this: $(command_line "$@")"
}

uninstall() {
  need_root uninstall
  say "To delete the data too, run: $(command_line uninstall --delete-data)"
}

main() {
  case "${1:-}" in
    uninstall) uninstall ;;
    -*) fail "Unknown option $1. Usage: $(command_line '<code>')" ;;
    *)
      say "Usage: $(command_line '<code>')"
      say "       $(command_line uninstall) [--delete-data]"
      say "To start it again: $(command_line "--domain $(id -un)")"
      ;;
  esac
}

main "$@"
"""


def test_openmausbot_rerun_command_captured_into_messages_is_low(tmp_path):
    assert _local(tmp_path, {"connector/install.sh": OMB}, "connector/install.sh") == {"low"}


@pytest.mark.parametrize("line", [
    'eval "$(command_line x)"',
    'cmd="$(command_line x)"',
    'sh -c "$(command_line x)"',
    'say "$(command_line x | sh)"',
    'say "$(command_line x)" | sh',
    'x=$(command_line x)',
    'say "$(command_line x; id)" > /tmp/run.sh',
    'sudo say "$(command_line x)"',
    # A string spanning lines, then the output piped to sh on the line it closes on.
    'msg="hello\n"; command_line x | sh',
    # `printf -v` stores the output in a variable; it does not print it.
    'printf -v CMD "%s" "$(command_line x)"\neval "$CMD"',
])
def test_openmausbot_rerun_command_run_stays_critical(tmp_path, line):
    script = OMB.replace('main "$@"', line + '\nmain "$@"')
    assert _local(tmp_path, {"connector/install.sh": script},
                  "connector/install.sh") == {"critical"}


# ---------------------------------------------------------------------------------
# OpenClawInstaller: `echo "  curl … | bash"` under a "to reinstall" heading in a
# menu function reached through 40+ menu functions, case arms like `a|A) f ;;`, and
# embedded `python3 -c "…"` text that mentions a function name.
# ---------------------------------------------------------------------------------

def _oci_script(extra: str = "") -> str:
    menus = "\n".join(
        f"config_{i}() {{\n    echo \"menu {i}\"\n    openclaw_uninstall_menu\n}}\n"
        for i in range(45))
    arms = "\n".join(f"        {i}|M{i}) config_{i} ;;" for i in range(45))
    return f"""#!/bin/bash
CYAN='\\033[0;36m'
NC='\\033[0m'
INSTALLER_RAW_URL="https://raw.githubusercontent.com/miaoxworld/OpenClawInstaller/main"

log_info() {{ echo -e "$1"; }}
press_enter() {{ read -r _; }}

openclaw_uninstall_menu() {{
    echo ""
    echo -e "${{CYAN}}如需重新安装:${{NC}}"
    echo "  curl -fsSL ${{INSTALLER_RAW_URL}}/install.sh | bash"
    press_enter
}}

{menus}

read_feishu() {{
    app_id=$(python3 -c "
import json
feishu = {{}}
print(feishu.get('accounts', {{}}).get('main', {{}}).get('appId', ''))
" 2>/dev/null)
}}

main() {{
    read -r choice
    case $choice in
{arms}
        *) log_info "无效选择" ;;
    esac
}}
{extra}
main "$@"
"""


# install.sh writes a channel guide with a quoted heredoc; the guide names the menu
# script in backticks (Markdown), which the shell never expands.
OCI_INSTALL = """#!/bin/bash
doc_file="$HOME/.openclaw/docs/channels.md"
cat > "$doc_file" <<'EOF'
# OpenClaw 渠道配置文档（自动安装器）

请优先使用：
1) `openclaw onboard`（官方模型配置）
2) `bash ~/.openclaw/config-menu.sh`（渠道配置）
EOF
"""


def test_openclawinstaller_reinstall_echo_in_a_long_menu_script_is_low(tmp_path):
    assert _local(tmp_path, {"config-menu.sh": _oci_script(), "install.sh": OCI_INSTALL},
                  "config-menu.sh") == {"low"}


@pytest.mark.parametrize("install", [
    OCI_INSTALL.replace("<<'EOF'", "<<EOF"),  # unquoted: the backticks run
    OCI_INSTALL + 'eval "$(bash ~/.openclaw/config-menu.sh)"\n',
    OCI_INSTALL + "bash ~/.openclaw/config-menu.sh | sh\n",
])
def test_openclawinstaller_menu_output_run_by_another_script_stays_critical(tmp_path,
                                                                           install):
    assert _local(tmp_path, {"config-menu.sh": _oci_script(), "install.sh": install},
                  "config-menu.sh") == {"critical"}


@pytest.mark.parametrize("extra", [
    "openclaw_uninstall_menu | bash",
    "x=$(config_7)",
    'eval "$(config_3)"',
    "r) config_9 | sh ;;",
])
def test_openclawinstaller_menu_output_run_stays_critical(tmp_path, extra):
    assert _local(tmp_path, {"config-menu.sh": _oci_script(extra)},
                  "config-menu.sh") == {"critical"}


# ---------------------------------------------------------------------------------
# coder: `defaultUpgradeMessage` (Go) builds the upgrade hint with fmt.Sprintf; the
# caller formats it into a warning written to stderr.
# ---------------------------------------------------------------------------------

CODER = """package cli

import (
\t"fmt"
\t"runtime"
\t"strings"
)

func defaultUpgradeMessage(version string) string {
\t// Our installation script doesn't work on Windows, so instead we direct the user
\t// to the GitHub release page to download the latest installer.
\tversion = strings.TrimPrefix(version, "v")
\tif runtime.GOOS == "windows" {
\t\treturn fmt.Sprintf("download the server version from: https://github.com/coder/coder/releases/v%s", version)
\t}
\treturn fmt.Sprintf("download the server version with: 'curl -fsSL https://coder.com/install.sh | sh -s -- --version %s'", version)
}

func checkVersions(inv *Invocation, clientVersion, serverVersion string, serverInfo BuildInfo) {
\tupgradeMessage := defaultUpgradeMessage(serverVersion)
\tswitch {
\tcase serverInfo.UpgradeMessage != "":
\t\tupgradeMessage = serverInfo.UpgradeMessage
\tcase serverInfo.DashboardURL != "":
\t\tupgradeMessage = fmt.Sprintf("download %s with: 'curl -fsSL %s/install.sh | sh'", serverVersion, serverInfo.DashboardURL)
\t}
\tfmtWarningText := "version mismatch: client %s, server %s\\n%s"
\twarning := fmt.Sprintf(fmtWarningText, clientVersion, serverVersion, upgradeMessage)

\t_, _ = fmt.Fprintln(inv.Stderr, warning)
}
"""


def test_coder_go_upgrade_message_is_low(tmp_path):
    assert _local(tmp_path, {"cli/root.go": CODER}, "cli/root.go") == {"low"}


@pytest.mark.parametrize("tail", [
    '\nfunc upgrade(v string) error {\n\treturn exec.Command("sh", "-c", defaultUpgradeMessage(v)).Run()\n}\n',
    '\nfunc upgrade(v string) error {\n\tmsg := defaultUpgradeMessage(v)\n'
    '\tcmd := exec.Command("sh", "-c", msg)\n\treturn cmd.Run()\n}\n',
    '\nfunc upgrade(v string) {\n\tmsg := defaultUpgradeMessage(v)\n'
    '\tfmt.Fprintln(stdinPipe, msg)\n}\n',
    '\nvar Upgrade = defaultUpgradeMessage\n',
    # An error's text reaches a process under a name the walk cannot know.
    '\nfunc upgrade(v string) error {\n\tproblem := fmt.Errorf("%s", defaultUpgradeMessage(v))\n'
    '\ts := problem.Error()\n\treturn exec.Command("sh", "-c", s).Run()\n}\n',
    '\nfunc upgrade(v string) {\n\tproblem := fmt.Errorf("%s", defaultUpgradeMessage(v))\n'
    '\tlog.SetOutput(sink)\n\tlog.Println(problem)\n}\n',
])
def test_coder_go_upgrade_message_run_stays_critical(tmp_path, tail):
    assert _local(tmp_path, {"cli/root.go": CODER + tail}, "cli/root.go",
                  "download the server version with") == {"critical"}


def test_go_exported_function_result_stays_critical(tmp_path):
    body = CODER.replace("defaultUpgradeMessage", "DefaultUpgradeMessage")
    assert _local(tmp_path, {"cli/root.go": body}, "cli/root.go",
                  "download the server version with") == {"critical"}


# ---------------------------------------------------------------------------------
# sem: the self-update returns `Err(format!("… or reinstall:\n  curl … | sh"))`.
# ---------------------------------------------------------------------------------

SEM = """use std::fs;
use std::path::Path;

const REPO: &str = "Ataraxy-Labs/sem";

pub fn run(exe: &Path, staged: &Path, tmp: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Err(e) = stage(tmp, staged) {
        let _ = fs::remove_file(&staged);
        return Err(format!(
            "Cannot write next to {} ({e}). Try with elevated permissions, or reinstall:\\n  curl -fsSL https://raw.githubusercontent.com/{REPO}/main/install.sh | sh",
            exe.display()
        )
        .into());
    }
    let status = std::process::Command::new("tar")
        .arg("xzf")
        .arg(&tmp)
        .status()?;
    if !status.success() {
        return Err("Failed to extract release archive".into());
    }
    Ok(())
}

fn stage(a: &Path, b: &Path) -> std::io::Result<()> {
    fs::copy(a, b).map(|_| ())
}
"""
SEM_MAIN = """mod update;
fn main() {
    if let Err(e) = update::run(&std::env::current_exe().unwrap(), std::path::Path::new("x"), std::path::Path::new("y")) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
"""


def test_sem_rust_error_message_is_low(tmp_path):
    assert _local(tmp_path, {"crates/sem-cli/src/commands/update.rs": SEM,
                             "crates/sem-cli/src/main.rs": SEM_MAIN},
                  "crates/sem-cli/src/commands/update.rs") == {"low"}


@pytest.mark.parametrize("files", [
    # Some code hands an error's text to a process.
    {"crates/sem-cli/src/main.rs": SEM_MAIN.replace(
        'eprintln!("error: {e}");',
        'std::process::Command::new("sh").arg("-c").arg(e.to_string()).status().ok();')},
    # The message itself goes to a process.
    {"crates/sem-cli/src/commands/update.rs": SEM.replace(
        "return Err(format!(", "let m = format!(").replace(
        ".into());\n    }\n    let status", ";\n        std::process::Command::new(\"sh\")"
        ".arg(m).status()?;\n    }\n    let status", 1)},
    # The error bound under another name, or formatted first.
    {"crates/sem-cli/src/main.rs": SEM_MAIN.replace(
        'Err(e) = update', 'Err(msg) = update').replace(
        'eprintln!("error: {e}");',
        'std::process::Command::new("sh").arg("-c").arg(msg.to_string()).status().ok();')},
    {"crates/sem-cli/src/main.rs": SEM_MAIN.replace(
        'eprintln!("error: {e}");',
        'let s = format!("{e}"); std::process::Command::new("sh").arg(&s).status().ok();')},
])
def test_sem_rust_error_text_run_stays_critical(tmp_path, files):
    tree = {"crates/sem-cli/src/commands/update.rs": SEM,
            "crates/sem-cli/src/main.rs": SEM_MAIN, **files}
    assert _local(tmp_path, tree, "crates/sem-cli/src/commands/update.rs") == {"critical"}


# ---------------------------------------------------------------------------------
# firebase-tools (VS Code extension): the "to install it, run …" message goes to
# vscode.window.showWarningMessage; the same function runs other commands through
# a login shell.
# ---------------------------------------------------------------------------------

FB = """import * as vscode from "vscode";
import { spawnSync } from "child_process";

async function checkCLIInstallation(): Promise<void> {
  let message = "";
  try {
    const shell = process.env.SHELL || "/bin/bash";
    const runCommand = (cmd: string) => {
      return spawnSync(shell, ["-l", "-c", cmd], {});
    };

    const versionRes = runCommand("firebase --version");
    const currentVersion = versionRes.status === 0 ? versionRes.stdout?.toString().trim() : "";
    const npmVersion = runCommand("npm --version").status === 0;

    if (!currentVersion) {
      message = `The Firebase CLI is not installed (or not available on $PATH). If you would like to install it, run ${
        npmVersion
          ? "npm install -g firebase-tools"
          : "curl -sL https://firebase.tools | bash"
      }`;
    }
  } catch (err: any) {
    message = "";
  }

  if (message) {
    vscode.window.showWarningMessage(message);
  }
}
export { checkCLIInstallation };
"""


def test_firebase_vscode_install_message_is_low(tmp_path):
    assert _local(tmp_path, {"firebase-vscode/src/extension.ts": FB},
                  "firebase-vscode/src/extension.ts") == {"low"}


@pytest.mark.parametrize("old,new", [
    ("vscode.window.showWarningMessage(message);", "runCommand(message);"),
    # Shown AND typed into a terminal (`sendText` runs it).
    ("vscode.window.showWarningMessage(message);",
     "vscode.window.showWarningMessage(message);\n"
     "    vscode.window.createTerminal().sendText(message);"),
    ("vscode.window.showWarningMessage(message);",
     "vscode.window.showWarningMessage(\"x\", message).then(runCommand);"),
    ('import * as vscode from "vscode";', 'import * as vscode from "./fake-vscode";'),
])
def test_firebase_vscode_install_message_run_stays_critical(tmp_path, old, new):
    assert _local(tmp_path, {"firebase-vscode/src/extension.ts": FB.replace(old, new)},
                  "firebase-vscode/src/extension.ts") == {"critical"}


# ---------------------------------------------------------------------------------
# openclaw101: a Next.js client page's copy (`command: 'curl … | bash'`), rendered
# in a <pre> and copied to the clipboard.
# ---------------------------------------------------------------------------------

OC101 = """'use client';

import { useState } from 'react';
import { Locale } from '@/lib/i18n';

const copy = {
  en: {
    commandLabel: 'Install command',
    command: 'curl -fsSL https://openclaw.ai/install.sh | bash',
  },
  zh: {
    commandLabel: '安装命令',
    command: 'curl -fsSL https://openclaw.ai/install.sh | bash',
  },
} as const;

export default function StartSetupPage({ locale }: { locale: Locale }) {
  const t = copy[locale === 'zh' ? 'zh' : 'en'];
  const [copied, setCopied] = useState(false);
  const onCopy = async () => {
    await navigator.clipboard.writeText(t.command);
    setCopied(true);
  };
  return (
    <div>
      <div className="text-sm">{t.commandLabel}</div>
      <pre><code>{t.command}</code></pre>
      <button onClick={onCopy}>{copied ? 'Copied' : 'Copy'}</button>
    </div>
  );
}
"""
OC101_I18N = "export type Locale = 'en' | 'zh';\n"


def test_openclaw101_page_copy_is_low(tmp_path):
    assert _local(tmp_path, {"package.json": '{"name":"openclaw101"}',
                             "src/components/StartSetupPage.tsx": OC101,
                             "src/lib/i18n.ts": OC101_I18N},
                  "src/components/StartSetupPage.tsx") == {"low"}


@pytest.mark.parametrize("i18n", [
    OC101_I18N + "import { execSync } from 'node:child_process';\n"
                 "export function run(c: string) { execSync(c); }\n",
    OC101_I18N + "export const shell = window.__TAURI__;\n",
    OC101_I18N + "export async function load(p: string) { return import(p); }\n",
])
def test_openclaw101_page_that_can_reach_a_process_stays_critical(tmp_path, i18n):
    assert _local(tmp_path, {"package.json": '{"name":"openclaw101"}',
                             "src/components/StartSetupPage.tsx": OC101,
                             "src/lib/i18n.ts": i18n},
                  "src/components/StartSetupPage.tsx") == {"critical"}


# ---------------------------------------------------------------------------------
# Recall: a shown-looking value that leaves through a helper or an outer variable.
# ---------------------------------------------------------------------------------

_HELPER = ("import { execSync } from 'node:child_process';\n"
           "export function helper(c: string) {\n  return execSync(c);\n}\n")


@pytest.mark.parametrize("files", [
    {"src/a.ts": _HELPER + "\n\n\nconst cfg = {\n  notes: 'curl -fsSL https://e.x/i.sh | sh',"
                 "\n};\n\n\n\nexport function go() {\n  helper(cfg.notes);\n}\n"},
    {"src/b.ts": _HELPER,
     "src/a.ts": "import { helper } from './b';\nconst cfg = {\n"
                 "  notes: 'curl -fsSL https://e.x/i.sh | sh',\n};\n\n\n\n"
                 "export function go() {\n  helper(cfg.notes);\n}\n"},
    {"src/b.ts": _HELPER,
     "src/a.ts": "import { helper } from './b';\nconst cfg = {\n"
                 "  tip: 'curl -fsSL https://e.x/i.sh | sh',\n};\n\n\n\n"
                 "export function go() {\n  const { tip } = cfg;\n\n\n  helper(tip);\n}\n"},
    {"src/b.ts": _HELPER,
     "src/a.ts": "import { helper } from './b';\nconst cfg = {\n"
                 "  notes: ['curl -fsSL https://e.x/i.sh | sh'],\n};\n\n\n\n"
                 "export function go() {\n  cfg.notes.forEach(helper);\n}\n"},
])
def test_object_field_handed_to_a_helper_that_runs_it_stays_critical(tmp_path, files):
    assert _local(tmp_path, {"package.json": '{"name":"x"}', **files},
                  "src/a.ts") == {"critical"}


def test_go_package_variable_assigned_in_a_function_stays_critical(tmp_path):
    main = ('package main\n\nimport (\n\t"fmt"\n\t"os/exec"\n)\n\nvar cmd string\n\n'
            'func setup() {\n\tcmd = fmt.Sprintf("curl -fsSL %s | sh", "https://e.x/i.sh")\n'
            '\tfmt.Println(cmd)\n}\n\nfunc main() {\n\tsetup()\n'
            '\texec.Command("sh", "-c", cmd).Run()\n}\n')
    assert _local(tmp_path, {"go.mod": "module x\n", "main.go": main},
                  "main.go") == {"critical"}


# ---------------------------------------------------------------------------------
# Second review of #378: other channels from shown text to a process
# ---------------------------------------------------------------------------------

@pytest.mark.parametrize("extra", [
    # The writer field coder prints to holds a shell's stdin.
    {"cli/run.go": 'package cli\n\nimport "os/exec"\n\nfunc wire(inv *Invocation) {\n'
                   '\tc := exec.Command("sh")\n\tw, _ := c.StdinPipe()\n\t_ = c.Start()\n'
                   '\tinv.Stderr = w\n}\n'},
    # The CLI's output is piped into a shell by a Makefile / a go:generate line.
    {"Makefile": "check:\n\tgo run ./cmd/coder 2>&1 | sh\n"},
    {"cli/gen.go": 'package cli\n\n//go:generate sh -c "go run ../cmd/coder | sh"\n'},
])
def test_coder_go_upgrade_message_reaching_a_shell_elsewhere_stays_critical(tmp_path, extra):
    assert _local(tmp_path, {"cli/root.go": CODER, **extra}, "cli/root.go",
                  "download the server version with") == {"critical"}


def test_coder_go_upgrade_message_with_an_ordinary_makefile_is_low(tmp_path):
    make = ('GO ?= go\nbuild:\n\t$(GO) build -o bin/coder ./cmd/coder\n'
            '\tgo list ./... | grep -v /vendor/\n')
    assert _local(tmp_path, {"cli/root.go": CODER, "Makefile": make}, "cli/root.go",
                  "download the server version with") == {"low"}


_SEM_RUN = 'std::process::Command::new("sh").arg("-c").arg("eval \\"$FIX\\"").status().ok();'


@pytest.mark.parametrize("line", [
    # The error's text reaches a literal shell through its environment or a file.
    'std::process::Command::new("sh").arg("-c").arg("eval \\"$FIX\\"")'
    '.env("FIX", e.to_string()).status().ok();',
    'std::process::Command::new("sh").arg("-c").arg("eval \\"$FIX\\"")'
    '.envs([("FIX", e.to_string())]).status().ok();',
    'std::env::set_var("FIX", e.to_string()); ' + _SEM_RUN,
    'std::fs::write("/tmp/fix.sh", e.to_string()).ok(); '
    'std::process::Command::new("sh").arg("/tmp/fix.sh").status().ok();',
    # The process is started with the path split by spaces.
    'let _ = std::process::Command :: new ( e.to_string() ) . status();',
])
def test_sem_rust_error_text_to_a_process_by_another_channel_stays_critical(tmp_path, line):
    tree = {"crates/sem-cli/src/commands/update.rs": SEM,
            "crates/sem-cli/src/main.rs": SEM_MAIN.replace('eprintln!("error: {e}");', line)}
    assert _local(tmp_path, tree, "crates/sem-cli/src/commands/update.rs") == {"critical"}


def test_sem_rust_error_message_with_a_literal_child_env_is_low(tmp_path):
    main = SEM_MAIN.replace(
        'eprintln!("error: {e}");',
        'eprintln!("error: {e}");\n        '
        'std::process::Command::new("true").env("RUST_LOG", "info").status().ok();')
    assert _local(tmp_path, {"crates/sem-cli/src/commands/update.rs": SEM,
                             "crates/sem-cli/src/main.rs": main},
                  "crates/sem-cli/src/commands/update.rs") == {"low"}


@pytest.mark.parametrize("path,text,run", [
    ("Makefile", "x:\n\tgo run ./cli 2>&1 | sh\n", True),
    ("Makefile", 'x:\n\teval "$$(cargo run)"\n', True),
    ("Makefile", "x:\n\t$(GO) build ./...\n\tgo list ./... | grep -v vendor\n", False),
    ("install.sh", "#!/bin/sh\n./bin/tool init | bash\n", True),
    ("install.sh", "#!/bin/sh\nsource <(./bin/tool completion bash)\n", True),
    ("install.sh", "#!/bin/sh\ncurl -fsSL https://x.example/i.sh | sh\n", False),
    ("install.sh", "#!/bin/sh\n# ./bin/tool | sh\n", False),
    ("build.rs", 'fn main() { Command::new("sh").arg("-c").arg("cargo run | sh"); }\n', True),
    ("src/a.js", "$('#x').hide();\nconst t = `${a}`;\n", False),
    ("cli/gen.go", '//go:generate sh -c "go run . | sh"\n', True),
    ("README.md", 'eval "$(tool init zsh)"\n', False),
    ("SKILL.md", "Run `./bin/tool hint | sh` to finish.\n", True),
])
def test_program_output_run(path, text, run):
    from src.scanner.shown_text import program_output_run
    assert (program_output_run({path: text}) is not None) is run
