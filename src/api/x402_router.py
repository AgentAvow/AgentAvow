"""x402 Bazaar trust surface — free re-scan + explorer data.

Two endpoints, both read-only from the caller's perspective:

  * POST /x402/rescan?endpoint=... — probe a declared x402 endpoint and
    return its surface posture (status, content-type, x402 header presence,
    observed redirects). Rate-limited at the public-scan tier.
  * GET  /x402/explorer — list the scan results from the most recent
    scripts/launch_scans/scan_x402.py run. Reads from
    data/launch-scans/x402-results.json on disk.

Heavy lifting (actual static analysis, code review) does NOT happen here —
x402 endpoints are HTTP surfaces, not repos. The grade is a posture grade.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

from src.api.rate_limit import rate_limit_reads

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/x402", tags=["x402"])

# Where scan_x402.py writes its output
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
_RESULTS_PATH = _PROJECT_ROOT / "data" / "launch-scans" / "x402-results.json"
_TARGETS_PATH = _PROJECT_ROOT / "data" / "launch-scans" / "x402-targets.json"


# ── response models ───────────────────────────────────────────────────


class X402RescanResponse(BaseModel):
    endpoint_url: str
    http_status: int | None = None
    head_status: int | None = None
    has_x402_header: bool = False
    content_type: str = ""
    content_length: int = 0
    tls_verified: bool = True
    final_url: str | None = None
    error: str | None = None


class X402ExplorerEntry(BaseModel):
    endpoint_url: str
    http_status: int | None = None
    has_x402_header: bool = False
    content_type: str = ""
    scanned: bool = True


class X402ExplorerResponse(BaseModel):
    count: int
    results: list[X402ExplorerEntry]


# ── helpers ───────────────────────────────────────────────────────────


def _safe_endpoint(url: str) -> str:
    """The caller supplies this URL and nobody is logged in, so it goes through the
    shared guard: http(s) only, no internal address, including one a hostname
    resolves to."""
    from src.ssrf import validate_url

    try:
        return validate_url(url, field_name="endpoint")
    except ValueError:
        raise HTTPException(400, "endpoint must be a public http(s) URL")


def _read_results_file() -> list[dict[str, Any]]:
    if not _RESULTS_PATH.exists():
        return []
    try:
        payload = json.loads(_RESULTS_PATH.read_text())
    except json.JSONDecodeError:
        logger.warning("x402 results file is not valid JSON: %s", _RESULTS_PATH)
        return []
    return payload.get("results", []) if isinstance(payload, dict) else []


# ── endpoints ─────────────────────────────────────────────────────────


@router.post(
    "/rescan",
    response_model=X402RescanResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def rescan_x402_endpoint(
    endpoint: str = Query(..., min_length=8, max_length=1000),
) -> X402RescanResponse:
    """Probe a declared x402 endpoint and return its observable surface.

    This is a re-scan helper for x402 operators to refresh their live posture
    without going through the full /gateway/re-verify path. Does NOT return
    a letter grade — the grade is derived server-side and published at /x402.
    """
    url = _safe_endpoint(endpoint)
    from src.ssrf import ssrf_safe_async_client, ssrf_safe_follow

    try:
        # Pinned to the validated address; every redirect hop is validated too.
        async with ssrf_safe_async_client(timeout=10.0, follow_redirects=False) as client:
            head, _ = await ssrf_safe_follow(client, "HEAD", url)
            probe, final_url = await ssrf_safe_follow(
                client, "GET", url, headers={"Accept": "application/json"})
        lowered = {k.lower() for k in probe.headers}
        has_x402 = (
            "x-402-payment" in lowered or "www-authenticate" in lowered
        )
        return X402RescanResponse(
            endpoint_url=url,
            http_status=probe.status_code,
            head_status=head.status_code,
            has_x402_header=has_x402,
            content_type=probe.headers.get("content-type", ""),
            content_length=int(probe.headers.get("content-length", 0) or 0),
            final_url=final_url,
        )
    except ValueError:
        return X402RescanResponse(endpoint_url=url, error="blocked")
    except httpx.TimeoutException:
        return X402RescanResponse(endpoint_url=url, error="timeout")
    except httpx.RequestError as exc:
        return X402RescanResponse(endpoint_url=url, error=f"request_error: {exc}")


@router.get(
    "/explorer",
    response_model=X402ExplorerResponse,
    dependencies=[Depends(rate_limit_reads)],
)
async def list_x402_explorer() -> X402ExplorerResponse:
    """Return the most recent x402 scan batch for the /x402 frontend."""
    rows = _read_results_file()
    entries = [
        X402ExplorerEntry(
            endpoint_url=row.get("endpoint_url", ""),
            http_status=row.get("http_status"),
            has_x402_header=bool(row.get("has_x402_header", False)),
            content_type=row.get("content_type", ""),
            scanned="error" not in row,
        )
        for row in rows
        if row.get("endpoint_url")
    ]
    return X402ExplorerResponse(count=len(entries), results=entries)
