"""MCP claims, second proof method: an owners.json on the endpoint's domain lists the
claimant's verified account email (the convention VerifyMCP documents, so one file
serves both). Fetched through the SSRF guard: https on every hop, at most 3 redirects,
8 s timeout, 64 KB cap; anything else proves nothing."""
from __future__ import annotations

import json

import httpx
import pytest

from src import ssrf
from src.api import account_claims_router as acr

EP = "https://tools.example.com/mcp"
PATH_URL = "https://tools.example.com/mcp/.well-known/owners.json"
HOST_URL = "https://tools.example.com/.well-known/owners.json"


def _serve(monkeypatch, routes: dict[str, httpx.Response]) -> list[str]:
    """Answer GETs from `routes` (404 otherwise); returns the URLs asked for."""
    seen: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return routes.get(str(req.url), httpx.Response(404))

    monkeypatch.setattr(ssrf, "_check_resolved_ips", lambda *a, **k: None)
    monkeypatch.setattr(ssrf, "ssrf_safe_async_client",
                        lambda **kw: httpx.AsyncClient(transport=httpx.MockTransport(handler), **kw))
    return seen


def _doc(*owners: str) -> httpx.Response:
    return httpx.Response(200, content=json.dumps(
        {"$schema": "https://verifymcp.io/schemas/owners.json", "owners": list(owners)}).encode())


def test_owners_json_urls_path_level_first_then_host():
    assert acr.owners_json_urls(EP) == [PATH_URL, HOST_URL]
    assert acr.owners_json_urls("https://tools.example.com/") == [HOST_URL]


@pytest.mark.asyncio
async def test_host_level_file_listing_the_email_proves_it(monkeypatch):
    seen = _serve(monkeypatch, {HOST_URL: _doc("Ops@Example.com")})
    assert await acr._owners_json_ok(EP, "ops@example.com") is True
    assert seen == [PATH_URL, HOST_URL]      # the path-level file is tried first


@pytest.mark.asyncio
async def test_path_level_file_is_enough(monkeypatch):
    _serve(monkeypatch, {PATH_URL: _doc("ops@example.com")})
    assert await acr._owners_json_ok(EP, "ops@example.com") is True


@pytest.mark.asyncio
async def test_a_file_listing_someone_else_proves_nothing(monkeypatch):
    _serve(monkeypatch, {PATH_URL: _doc("other@example.com"), HOST_URL: _doc()})
    assert await acr._owners_json_ok(EP, "ops@example.com") is False


@pytest.mark.asyncio
async def test_no_email_proves_nothing(monkeypatch):
    seen = _serve(monkeypatch, {HOST_URL: _doc("")})
    assert await acr._owners_json_ok(EP, None) is False
    assert seen == []


@pytest.mark.asyncio
async def test_an_internal_host_is_never_fetched(monkeypatch):
    seen = _serve(monkeypatch, {})
    monkeypatch.undo()  # the real guard, real DNS checks
    hits: list[str] = []
    monkeypatch.setattr(ssrf, "ssrf_safe_async_client", lambda **kw: httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: hits.append(str(r.url)) or _doc("a@b.c")), **kw))
    assert await acr._owners_json_ok("https://127.0.0.1/mcp", "a@b.c") is False
    assert await acr._owners_json_ok("https://localhost/mcp", "a@b.c") is False
    assert hits == [] and seen == []


@pytest.mark.asyncio
async def test_a_redirect_to_plain_http_is_refused(monkeypatch):
    _serve(monkeypatch, {
        PATH_URL: httpx.Response(302, headers={"location": "http://tools.example.com/o.json"}),
        HOST_URL: httpx.Response(404),
        "http://tools.example.com/o.json": _doc("ops@example.com"),
    })
    assert await acr._owners_json_ok(EP, "ops@example.com") is False


@pytest.mark.asyncio
async def test_an_https_redirect_is_followed(monkeypatch):
    _serve(monkeypatch, {
        HOST_URL: httpx.Response(301, headers={"location": "https://cdn.example.com/owners.json"}),
        "https://cdn.example.com/owners.json": _doc("ops@example.com"),
    })
    assert await acr._owners_json_ok(EP, "ops@example.com") is True


@pytest.mark.asyncio
async def test_an_oversized_file_proves_nothing(monkeypatch):
    big = json.dumps({"owners": ["ops@example.com"], "pad": "x" * acr.OWNERS_JSON_MAX_BYTES})
    _serve(monkeypatch, {HOST_URL: httpx.Response(200, content=big.encode())})
    assert await acr._owners_json_ok(EP, "ops@example.com") is False


@pytest.mark.parametrize("raw", [
    b"not json", b"<html>{\"owners\": [\"ops@example.com\"]}</html>",
    b'["ops@example.com"]', b'{"owners": "ops@example.com"}', b"\xff\xfe",
])
def test_invalid_documents_list_nobody(raw):
    assert acr.owners_from_doc(raw) == set()


def test_owners_are_matched_lowercased_and_trimmed():
    assert acr.owners_from_doc(b'{"owners": [" Ops@Example.COM ", 7, ""]}') == {"ops@example.com"}


# ── wired into POST /account/claims/{id}/verify for MCP claims ─────────────────
def _claim_and_db(entity_id):
    import uuid
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, MagicMock

    claim = SimpleNamespace(
        id=uuid.uuid4(), entity_id=entity_id, surface="mcp", owner=EP, repo=EP,
        full_name=EP, status="pending", verify_code="abc123", verified_at=None,
        proof_method=None, is_private=False)
    db = MagicMock()
    db.get = AsyncMock(return_value=claim)
    db.flush = AsyncMock()
    from datetime import datetime, timezone

    async def _refresh(obj):  # what the DB would hand back for func.now()
        obj.verified_at = datetime(2026, 11, 14, tzinfo=timezone.utc)
    db.refresh = AsyncMock(side_effect=_refresh)
    return claim, db


async def _verify(monkeypatch, *, email_verified: bool, owners_ok: bool):
    import uuid
    from types import SimpleNamespace
    from unittest.mock import AsyncMock

    entity = SimpleNamespace(id=uuid.uuid4(), email="ops@example.com",
                             email_verified=email_verified)
    claim, db = _claim_and_db(entity.id)
    owners = AsyncMock(return_value=owners_ok)
    monkeypatch.setattr(acr, "_mcp_challenge_ok", AsyncMock(return_value=False))
    monkeypatch.setattr(acr, "_owners_json_ok", owners)
    monkeypatch.setattr(acr, "_ensure_watch", AsyncMock())
    out = await acr.verify_claim(claim.id, None, entity, db, None)
    return out, claim, owners


@pytest.mark.asyncio
async def test_verify_accepts_owners_json_for_a_verified_email(monkeypatch):
    out, claim, owners = await _verify(monkeypatch, email_verified=True, owners_ok=True)
    assert out["verified"] is True
    assert claim.proof_method == "owners-json"
    owners.assert_awaited_once_with(EP, "ops@example.com")


@pytest.mark.asyncio
async def test_verify_ignores_owners_json_for_an_unverified_email(monkeypatch):
    out, claim, owners = await _verify(monkeypatch, email_verified=False, owners_ok=True)
    assert out["verified"] is False
    owners.assert_not_awaited()
    assert out["owners_json"] == [PATH_URL, HOST_URL]


@pytest.mark.asyncio
async def test_verify_says_where_the_file_goes_when_neither_proof_is_found(monkeypatch):
    out, _, _ = await _verify(monkeypatch, email_verified=True, owners_ok=False)
    assert out["verified"] is False
    assert out["owners_json"] == [PATH_URL, HOST_URL]
    assert "owners.json" in out["detail"]
