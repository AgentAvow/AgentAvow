"""Install commands only shown to a person are not critical (verdict accuracy audit,
class 1, ``docs/research/verdict-accuracy-audit-2026-11.md``).

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
