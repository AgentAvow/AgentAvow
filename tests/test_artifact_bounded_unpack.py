"""Big packages are graded, not refused (ledger #22).

The artifact unpack is bounded rather than all-or-nothing: past the soft budget it skips
or evicts binaries, media and test data so code and manifests are still scanned, and
records every skip so the scan reports partial coverage. Only a real bomb (implausible
compression ratio, hard ceiling) fails. PyPI scans read a wheel first. All offline.
"""
from __future__ import annotations

import io
import os
import tarfile
import zipfile

import httpx
import pytest

from src.scanner import artifact_fetch as af
from src.scanner.artifact_fetch import (
    ArtifactFetchError,
    SkipReport,
    _pick_pypi_url,
    _unpack_tar_gz,
    _unpack_zip,
    npm_result_from_tarball,
    pypi_result_from_archive,
)

# ── builders ────────────────────────────────────────────────────────────────────


def _targz(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in members:
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _zip(members: list[tuple[str, bytes]]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, data in members:
            zf.writestr(name, data)
    return buf.getvalue()


def _py(i: int) -> bytes:
    return f"def f{i}():\n    return {i}\n".encode()


def _scan(eco: str, fetched):
    from src.scanner.scan import ScanResult, apply_artifact_scan

    result = ScanResult(repo=f"{eco}:x", stars=0, description="", framework="")
    apply_artifact_scan(result, eco, fetched)
    return result


# ── bomb defence: still rejected ─────────────────────────────────────────────────


def test_zip_member_with_absurd_ratio_is_rejected():
    # 4MB of zeros deflates to a few KB: ~1000:1, the classic zip bomb shape. Rejected
    # before a byte is inflated, even though the member is also over the size cap.
    raw = _zip([("pkg/__init__.py", b"x = 1\n"), ("pkg/bomb.dat", b"\0" * (4 * 1024 * 1024))])
    with pytest.raises(ArtifactFetchError, match="zip bomb"):
        _unpack_zip(raw)


def test_small_member_with_high_ratio_is_not_a_bomb():
    # Under the 1MB floor a highly compressible file is ordinary (a padded table).
    raw = _zip([("pkg/table.py", b"x" * 200_000)])
    assert "pkg/table.py" in _unpack_zip(raw)


def test_targz_with_absurd_archive_ratio_is_rejected(monkeypatch):
    monkeypatch.setattr(af, "_RATIO_ARCHIVE_FLOOR", 1024 * 1024)
    raw = _targz([("package/index.js", b"1"), ("package/z.bin", b"\0" * (4 * 1024 * 1024))])
    with pytest.raises(ArtifactFetchError, match="zip bomb"):
        _unpack_tar_gz(raw)


def test_hard_ceiling_on_bytes_walked_is_rejected(monkeypatch):
    monkeypatch.setattr(af, "HARD_UNPACKED_BYTES", 1000)
    raw = _targz([(f"package/f{i}.js", os.urandom(300)) for i in range(5)])
    with pytest.raises(ArtifactFetchError, match="hard ceiling"):
        _unpack_tar_gz(raw)


def test_hard_entry_count_is_rejected(monkeypatch):
    monkeypatch.setattr(af, "HARD_ENTRY_COUNT", 10)
    raw = _zip([(f"pkg/f{i}.py", _py(i)) for i in range(11)])
    with pytest.raises(ArtifactFetchError, match="entries"):
        _unpack_zip(raw)


def test_path_traversal_still_rejected_under_budget_pressure(monkeypatch):
    monkeypatch.setattr(af, "MAX_FILE_COUNT", 1)
    raw = _targz([("package/a.js", b"a"), ("package/../../etc/passwd", b"x")])
    with pytest.raises(ArtifactFetchError, match="unsafe"):
        _unpack_tar_gz(raw)


# ── a big package with big binaries: scanned, binaries skipped ─────────────────


def test_large_npm_tarball_with_big_binaries_is_scanned(monkeypatch):
    # esbuild-shaped: a native binary over the per-member cap, plus .node/.so blobs that
    # fill the budget BEFORE the code in archive order. Code and manifest still win.
    monkeypatch.setattr(af, "MAX_MEMBER_BYTES", 64 * 1024)
    monkeypatch.setattr(af, "MAX_UNPACKED_BYTES", 60 * 1024)
    members = [
        ("package/bin/esbuild", os.urandom(80 * 1024)),         # > per-member cap
        ("package/lib/native.node", os.urandom(50 * 1024)),
        ("package/lib/helper.so", os.urandom(45 * 1024)),
        ("package/package.json", b'{"name":"big","version":"1.0.0"}'),
        ("package/lib/main.js", b"module.exports = function(){ return 1 };\n"),
        ("package/install.js", b"console.log('postinstall');\n"),
    ]
    fetched = npm_result_from_tarball("big", "1.0.0", _targz(members))
    assert {"package.json", "lib/main.js", "install.js"} <= set(fetched.files)
    assert "bin/esbuild" not in fetched.files
    assert fetched.packaged_manifest == {"name": "big", "version": "1.0.0"}
    sk = fetched.skipped
    assert sk is not None and sk.count >= 2 and sk.scannable == 0
    assert sk.reasons.get("too large") == 1
    # Paths in the report have the wrapper prefix stripped, like the file map.
    assert any(ex["path"] == "bin/esbuild" for ex in sk.examples)
    # file_count / unpacked_size describe the whole artifact, not just what was kept.
    assert fetched.file_count == len(members)
    assert fetched.unpacked_size == sum(len(d) for _n, d in members)

    result = _scan("npm", fetched)
    # Only binaries were skipped: nothing the engine reads is missing → not sampled.
    assert result.files_scanned >= 2 and result.sampled is False
    assert result.artifact_scan["skipped"]["count"] == sk.count


def test_skipped_source_marks_the_scan_sampled(monkeypatch):
    # More code than the budget holds: the scan grades what fit and SAYS it is partial.
    monkeypatch.setattr(af, "MAX_UNPACKED_BYTES", 400)
    members = [(f"package/lib/m{i}.js", b"module.exports = %d;\n" % i + b"/*" + b"x" * 60 + b"*/")
               for i in range(20)]
    fetched = npm_result_from_tarball("many", "1.0.0", _targz(members))
    sk = fetched.skipped
    assert sk is not None and sk.scannable > 0
    result = _scan("npm", fetched)
    assert result.sampled is True
    assert result.files_scanned == len(fetched.files)
    assert result.total_scannable_files == result.files_scanned + sk.scannable
    # The signed metadata carries it, and Certified's full-coverage check fails.
    from src.api.public_scan_router import _scan_result_to_dict
    from src.scanner.scan import _calculate_trust_score, _certified_status

    result.trust_score = _calculate_trust_score(result)
    result.certified = _certified_status(result)
    meta = _scan_result_to_dict(result)["metadata"]
    assert meta["sampled"] is True and meta["files_total"] > meta["files_scanned"]
    assert result.certified["checks"]["full_coverage"] is False


def test_wheel_reads_code_before_binaries_whatever_the_order(monkeypatch):
    monkeypatch.setattr(af, "MAX_UNPACKED_BYTES", 64 * 1024)
    members = [
        ("numpy/_core/_multiarray.cpython-312-x86_64-linux-gnu.so", os.urandom(60 * 1024)),
        ("numpy/fonts/DejaVu.ttf", os.urandom(30 * 1024)),
        ("numpy/__init__.py", b"from ._core import *\n"),
        ("numpy/_core/__init__.py", b"x = 1\n"),
        ("numpy-2.0.dist-info/METADATA", b"Name: numpy\n"),
    ]
    raw = _zip(members)
    fetched = pypi_result_from_archive(
        "numpy", "2.0", "wheel", "https://files.pythonhosted.org/x/numpy-2.0-cp312.whl", raw,
        installed_paths=None,
    )
    assert {"numpy/__init__.py", "numpy/_core/__init__.py",
            "numpy-2.0.dist-info/METADATA"} <= set(fetched.files)
    assert fetched.skipped is not None and fetched.skipped.scannable == 0
    assert _scan("pypi", fetched).sampled is False


def test_eviction_never_drops_code_for_a_binary(monkeypatch):
    monkeypatch.setattr(af, "MAX_UNPACKED_BYTES", 1000)
    code = [(f"package/c{i}.js", b"x" * 200) for i in range(5)]       # exactly fills it
    raw = _targz(code + [("package/z.so", os.urandom(300))])
    report = SkipReport()
    out = _unpack_tar_gz(raw, report)
    assert set(out) == {n for n, _ in code}
    assert report.reasons == {"over budget": 1} and report.scannable == 0


def test_small_archive_is_read_whole():
    fetched = npm_result_from_tarball("s", "1.0.0", _targz([
        ("package/package.json", b"{}"), ("package/logo.png", b"\x89PNG\x00"),
    ]))
    assert fetched.skipped is None and "logo.png" in fetched.files
    result = _scan("npm", fetched)
    assert result.sampled is False and "skipped" not in result.artifact_scan


# ── file-count overflow ──────────────────────────────────────────────────────────


def test_file_count_overflow_keeps_code_over_test_data(monkeypatch):
    # botocore / ruff shape: thousands of data / test members. Past the count cap, test
    # fixtures make room for code that comes later in the archive.
    monkeypatch.setattr(af, "MAX_FILE_COUNT", 10)
    fixtures = [(f"pkg-1.0/tests/data/case{i}.bin", b"\x00\x01" * 4) for i in range(30)]
    code = [(f"pkg-1.0/pkg/mod{i}.py", _py(i)) for i in range(5)]
    report = SkipReport()
    out = _unpack_tar_gz(_targz(fixtures + code), report)
    assert len(out) == 10
    assert all(f"pkg-1.0/pkg/mod{i}.py" in out for i in range(5))
    assert report.count == 25 and report.scannable == 0


def test_file_count_overflow_of_code_is_partial_not_an_error(monkeypatch):
    monkeypatch.setattr(af, "MAX_FILE_COUNT", 10)
    members = [(f"pkg/mod{i}.py", _py(i)) for i in range(15)]
    fetched = pypi_result_from_archive(
        "pkg", "1.0", "wheel", "https://files.pythonhosted.org/x/pkg-1.0-py3-none-any.whl",
        _zip(members), installed_paths=None,
    )
    assert len(fetched.files) == 10 and fetched.file_count == 15
    result = _scan("pypi", fetched)
    assert result.sampled is True
    assert (result.files_scanned, result.total_scannable_files) == (10, 15)


# ── wheel selection order ──────────────────────────────────────────────────────────

_F = "https://files.pythonhosted.org/packages/aa/"


def _w(fn: str, size: int, pt: str = "bdist_wheel") -> dict:
    return {"packagetype": pt, "url": _F + fn, "filename": fn, "size": size}


def test_pure_wheel_is_preferred_over_smaller_platform_wheels_and_the_sdist():
    urls = [
        _w("demo-1.0.tar.gz", 10, "sdist"),
        _w("demo-1.0-cp312-cp312-manylinux_x86_64.whl", 100),
        _w("demo-1.0-py3-none-any.whl", 5000),
    ]
    assert _pick_pypi_url(urls) == (_F + "demo-1.0-py3-none-any.whl", "wheel")


def test_smallest_platform_wheel_when_no_pure_wheel():
    urls = [
        _w("np-2.0.tar.gz", 20_000_000, "sdist"),
        _w("np-2.0-cp312-cp312-win_amd64.whl", 12_000_000),
        _w("np-2.0-cp312-cp312-macosx_arm64.whl", 5_000_000),
        _w("np-2.0-cp312-cp312-manylinux_x86_64.whl", 16_000_000),
    ]
    assert _pick_pypi_url(urls) == (_F + "np-2.0-cp312-cp312-macosx_arm64.whl", "wheel")


def test_wheel_over_the_download_cap_falls_back_to_the_sdist():
    urls = [
        _w("big-1.0-cp312-cp312-manylinux_x86_64.whl", af.MAX_DOWNLOAD_BYTES + 1),
        _w("big-1.0.tar.gz", 1000, "sdist"),
    ]
    assert _pick_pypi_url(urls) == (_F + "big-1.0.tar.gz", "sdist")


def test_sdist_only_release_reads_the_sdist():
    assert _pick_pypi_url([_w("x-1.0.tar.gz", 10, "sdist")]) == (_F + "x-1.0.tar.gz", "sdist")


def test_nothing_fits_tries_the_smallest_wheel():
    cap = af.MAX_DOWNLOAD_BYTES
    urls = [_w("t-1-cp312-cp312-a.whl", cap + 9), _w("t-1-cp312-cp312-b.whl", cap + 5)]
    assert _pick_pypi_url(urls) == (_F + "t-1-cp312-cp312-b.whl", "wheel")


def test_wheel_pick_is_deterministic_on_ties():
    a = _w("t-1-cp312-cp312-a.whl", 7)
    b = _w("t-1-cp312-cp312-b.whl", 7)
    assert _pick_pypi_url([b, a]) == _pick_pypi_url([a, b]) == (a["url"], "wheel")


def test_no_files_is_none():
    assert _pick_pypi_url([]) is None


# ── memory / disk: the download spools and is cleaned up ─────────────────────────


@pytest.mark.asyncio
async def test_download_spools_to_disk_and_hashes_the_file(monkeypatch):
    monkeypatch.setattr(af, "_SPOOL_BYTES", 16)
    body = os.urandom(5000)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=body)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        fh = await af._download_spooled("https://registry.npmjs.org/x.tgz", client)
    with fh:
        assert fh._rolled  # past the spool size it lives in an anonymous temp file
        import hashlib
        assert af._digest(fh) == "sha256:" + hashlib.sha256(body).hexdigest()
        assert fh.read() == body  # _digest rewinds
    assert fh.closed


@pytest.mark.asyncio
async def test_download_over_cap_closes_the_spool(monkeypatch):
    monkeypatch.setattr(af, "MAX_DOWNLOAD_BYTES", 10)
    created = []
    real = af.tempfile.SpooledTemporaryFile

    def spy(*a, **kw):
        f = real(*a, **kw)
        created.append(f)
        return f

    monkeypatch.setattr(af.tempfile, "SpooledTemporaryFile", spy)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 100)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(ArtifactFetchError):
            await af._download_spooled("https://registry.npmjs.org/x.tgz", client)
    assert created and created[0].closed


@pytest.mark.asyncio
async def test_download_still_refuses_off_allowlist_hosts():
    async with httpx.AsyncClient() as client:
        with pytest.raises(ArtifactFetchError):
            await af._download_spooled("https://93.184.216.34/evil.tgz", client)


# ── drift: a wheel lines up with a src-layout repo ──────────────────────────────────


def test_wheel_drift_matches_src_layout_repo():
    from src.scanner.artifact_scan import compute_drift

    fetched = pypi_result_from_archive(
        "demo", "1.0", "wheel", "https://files.pythonhosted.org/x/demo-1.0-py3-none-any.whl",
        _zip([("demo/__init__.py", b"x = 1\n"), ("demo/core.py", b"y = 2\n"),
              ("demo-1.0.dist-info/METADATA", b"Name: demo\n")]),
        installed_paths=None,
    )
    shas = {
        "src/demo/__init__.py": fetched.files["demo/__init__.py"].git_blob_sha,
        "src/demo/core.py": fetched.files["demo/core.py"].git_blob_sha,
    }
    drift, findings = compute_drift(fetched, None, None, has_install_hook=False,
                                    release_blob_shas=shas)
    assert drift["compared"] is True
    assert drift["added_files"] == [] and drift["modified_files"] == []
    assert findings == []


# ── precision: a base64 blob is not an AWS key (pillow, newly scannable) ────────────


def test_aws_key_pattern_ignores_akia_inside_base64():
    from src.scanner.patterns import SECRET_PATTERNS

    pat = next(p for n, p, _s in SECRET_PATTERNS if n == "AWS Access Key")
    assert not pat.search("QAHAEwAAQAAAAAAAgAHAGQAAQAwAaAKIAABCDEFGHIJ0123QAAAAA")
    assert pat.search('key = "AKIAABCDEFGHIJKLMNOP"')
    assert pat.search("AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP\n")
