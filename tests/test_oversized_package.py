"""A package whose every file is over the 50 MB download cap answers Review with its size.

Sentry AGENTGRAPH-BACKEND-2D (11-12): GET /public/scan/package/pypi/pymupdf was a 502
"Scan error: artifact Content-Length exceeds cap" (65 MB wheels, 84 MB sdist). The cap
stays; the answer is a coverage gap, not an error page.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from src.scanner import artifact_fetch as af
from src.scanner.verdict import coverage_gap_notes, decide

MB = 1024 * 1024


def _urls(*sizes_mb, sdist_mb=84):
    out = [{"packagetype": "bdist_wheel", "url": f"https://files.pythonhosted.org/w{i}.whl",
            "filename": f"pymupdf-2.1-cp39-abi3-plat{i}.whl", "size": int(s * MB)}
           for i, s in enumerate(sizes_mb)]
    out.append({"packagetype": "sdist", "url": "https://files.pythonhosted.org/s.tar.gz",
                "filename": "pymupdf-2.1.tar.gz", "size": int(sdist_mb * MB)})
    return out


@pytest.mark.asyncio
async def test_pypi_all_files_over_cap_raises_too_large_without_downloading():
    meta = {"info": {"version": "2.1"}, "urls": _urls(70, 65)}
    dl = AsyncMock()
    with patch.object(af, "_get_json", new=AsyncMock(return_value=meta)), \
            patch.object(af, "_download_spooled", new=dl):
        with pytest.raises(af.ArtifactTooLargeError) as e:
            await af.fetch_pypi_artifact("pymupdf", client=object())
    assert e.value.version == "2.1" and e.value.size_bytes == 65 * MB   # the smallest
    dl.assert_not_called()
    assert isinstance(e.value, af.ArtifactFetchError)                    # old callers


@pytest.mark.asyncio
async def test_pypi_streamed_over_cap_keeps_the_version():
    meta = {"info": {"version": "2.1"}, "urls": _urls(10)}               # listed small
    with patch.object(af, "_get_json", new=AsyncMock(return_value=meta)), \
            patch.object(af, "_download_spooled",
                         new=AsyncMock(side_effect=af.ArtifactTooLargeError("x"))):
        with pytest.raises(af.ArtifactTooLargeError) as e:
            await af.fetch_pypi_artifact("pymupdf", client=object())
    assert e.value.version == "2.1" and e.value.size_bytes == 10 * MB


def _settings():
    return SimpleNamespace(scanner_scan_artifact=True, scanner_verify_provenance=False)


@pytest.mark.asyncio
async def test_scan_package_answers_review_with_the_size_not_an_error():
    from src.scanner import scan
    err = af.ArtifactTooLargeError("artifact Content-Length exceeds cap",
                                   size_bytes=65 * MB, version="2.1")
    with patch("src.config.settings", _settings()), \
            patch.object(af, "fetch_pypi_artifact", new=AsyncMock(side_effect=err)), \
            patch("src.scanner.incident_history.fetch_incident_history",
                  new=AsyncMock(return_value={"checked": True, "advisories": []})):
        r = await scan.scan_package("pypi", "pymupdf")
    assert r.error is None
    assert r.coverage_gaps["package_too_large"] is True
    assert r.coverage_gaps["package_size_mb"] == 65
    assert r.files_scanned == 0 and r.certified is False
    assert r.artifact_scan["version"] == "2.1"
    data = {"trust_score": r.trust_score, "findings": {"items": []},
            "metadata": {"files_scanned": 0}, "coverage_gaps": r.coverage_gaps}
    d = decide(data)
    assert d.decision == "review"
    assert d.reason == ("the package is 65 MB, over our 50 MB download limit, so its code "
                        "was not read")
    assert "the package (65 MB) is over the 50 MB download limit; its code was not read" \
        in coverage_gap_notes(data)


@pytest.mark.asyncio
async def test_a_published_advisory_still_counts_on_an_oversized_package():
    from src.scanner import scan
    err = af.ArtifactTooLargeError("cap", size_bytes=65 * MB, version="2.1")
    adv = {"checked": True, "advisories": [{"id": "GHSA-xxxx-yyyy-zzzz"}]}
    finding = scan.Finding(category="known_vulnerability", name="Published advisory",
                           severity="high", file_path="osv", line_number=0, snippet="")
    with patch("src.config.settings", _settings()), \
            patch.object(af, "fetch_pypi_artifact", new=AsyncMock(side_effect=err)), \
            patch("src.scanner.incident_history.fetch_incident_history",
                  new=AsyncMock(return_value=adv)), \
            patch.object(scan, "_own_advisory_findings", return_value=[finding]):
        r = await scan.scan_package("pypi", "pymupdf")
    assert r.error is None and [f.severity for f in r.findings] == ["high"]


@pytest.mark.asyncio
async def test_other_fetch_errors_are_unchanged():
    from src.scanner import scan
    with patch("src.config.settings", _settings()), \
            patch.object(af, "fetch_pypi_artifact",
                         new=AsyncMock(side_effect=af.ArtifactFetchError("download status 500"))):
        r = await scan.scan_package("pypi", "pymupdf")
    assert r.error == "download status 500"
