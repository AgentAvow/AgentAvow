"""POST /api/v1/public/send-setup: one fixed setup email, no stored address, strict limits."""
from __future__ import annotations

import logging
from unittest.mock import AsyncMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from src.api import send_setup_router as mod
from src.config import settings
from src.database import get_db
from src.main import app
from src.models import Base

URL = "/api/v1/public/send-setup"
ADDRESS = "Setup.Tester@Example.com"
UTM = {
    "utm_source": "x", "utm_medium": "paid-social", "utm_campaign": "2026-11-test-x",
    "utm_content": "x5-wallet-home", "utm_term": "native",
}


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


@pytest.fixture
def sent():
    with patch("src.email.send_email", new_callable=AsyncMock, return_value=True) as m:
        yield m


@pytest.mark.asyncio
async def test_sends_one_fixed_email_with_the_ad_tags(client, sent):
    resp = await client.post(URL, json={"email": ADDRESS, "utm": UTM})
    assert resp.status_code == 202
    assert resp.json() == {"status": "sent"}
    sent.assert_awaited_once()
    (to, subject, body), kwargs = sent.await_args
    assert to.lower() == ADDRESS.lower()
    assert subject == mod.SUBJECT
    assert kwargs == {"private": True}
    for line in mod.PLUGIN_LINES:
        assert line in body
    base = settings.base_url.rstrip("/")
    assert (
        f"{base}/claude-code?utm_source=x&amp;utm_medium=paid-social"
        "&amp;utm_campaign=2026-11-test-x&amp;utm_content=x5-wallet-home&amp;utm_term=native"
    ) in body
    # Nothing the caller typed shows up in the body: not even the address.
    assert "setup.tester" not in body.lower()


@pytest.mark.asyncio
async def test_unknown_or_odd_tags_are_dropped(client, sent):
    utm = {
        "utm_source": "x", "utm_content": "<b>hi</b>", "utm_term": "two words",
        "utm_campaign": "a" * 65, "ref": "evil.example",
    }
    resp = await client.post(URL, json={"email": "a@example.com", "utm": utm})
    assert resp.status_code == 202
    body = sent.await_args.args[2]
    assert "/claude-code?utm_source=x\"" in body
    for bad in ("hi", "two", "evil.example", "a" * 65):
        assert bad not in body.split("/claude-code", 1)[1].split('"', 1)[0]


@pytest.mark.asyncio
async def test_no_tags_links_to_the_plain_page(client, sent):
    resp = await client.post(URL, json={"email": "a@example.com"})
    assert resp.status_code == 202
    assert f'{settings.base_url.rstrip("/")}/claude-code"' in sent.await_args.args[2]


@pytest.mark.asyncio
@pytest.mark.parametrize("email", [
    "", "not-an-address", "a@b", "a@example.com\r\nBcc: x@example.com",
    "x" * 250 + "@example.com",
])
async def test_bad_addresses_are_refused(client, sent, email):
    resp = await client.post(URL, json={"email": email})
    assert resp.status_code == 422
    sent.assert_not_awaited()


@pytest.mark.asyncio
async def test_per_address_limit_ignores_case(client, sent, monkeypatch):
    monkeypatch.setattr(settings, "send_setup_per_address_per_day", 2)
    monkeypatch.setattr(settings, "send_setup_per_ip_per_hour", 50)
    for email in ("same@example.com", "SAME@example.com"):
        assert (await client.post(URL, json={"email": email})).status_code == 202
    resp = await client.post(URL, json={"email": "Same@Example.com"})
    assert resp.status_code == 429
    assert sent.await_count == 2
    # Another address from the same IP still works.
    assert (await client.post(URL, json={"email": "other@example.com"})).status_code == 202


@pytest.mark.asyncio
async def test_per_ip_hourly_limit(client, sent, monkeypatch):
    monkeypatch.setattr(settings, "send_setup_per_ip_per_hour", 3)
    for i in range(3):
        resp = await client.post(URL, json={"email": f"p{i}@example.com"})
        assert resp.status_code == 202
    resp = await client.post(URL, json={"email": "p9@example.com"})
    assert resp.status_code == 429
    assert sent.await_count == 3


@pytest.mark.asyncio
async def test_per_ip_daily_limit(client, sent, monkeypatch):
    monkeypatch.setattr(settings, "send_setup_per_ip_per_hour", 50)
    monkeypatch.setattr(settings, "send_setup_per_ip_per_day", 2)
    for i in range(2):
        assert (await client.post(URL, json={"email": f"d{i}@example.com"})).status_code == 202
    assert (await client.post(URL, json={"email": "d9@example.com"})).status_code == 429


@pytest.mark.asyncio
async def test_turned_off_answers_404(client, sent, monkeypatch):
    monkeypatch.setattr(settings, "send_setup_enabled", False)
    resp = await client.post(URL, json={"email": "a@example.com"})
    assert resp.status_code == 404
    sent.assert_not_awaited()


@pytest.mark.asyncio
async def test_send_failure_is_a_502(client):
    with patch("src.email.send_email", new_callable=AsyncMock, return_value=False):
        resp = await client.post(URL, json={"email": "a@example.com"})
    assert resp.status_code == 502


# --- The address is not kept ---------------------------------------------------


async def _row_counts(db) -> dict[str, int]:
    counts = {}
    for name, table in sorted(Base.metadata.tables.items()):
        counts[name] = (await db.execute(select(func.count()).select_from(table))).scalar()
    return counts


@pytest.mark.asyncio
async def test_address_is_not_persisted(client, db, caplog):
    """Through the real send path (dev mode, no provider): no database row is written,
    no Redis key or value holds the address, the limit keys expire, and no log line
    names the address."""
    from src.redis_client import get_redis

    before = await _row_counts(db)
    caplog.set_level(logging.DEBUG)
    with (
        patch.object(settings, "resend_api_key", None),
        patch.object(settings, "smtp_host", None),
    ):
        resp = await client.post(URL, json={"email": ADDRESS, "utm": UTM})
    assert resp.status_code == 202
    assert await _row_counts(db) == before

    r = get_redis()
    needle = ADDRESS.lower()
    keys = [k async for k in r.scan_iter(match="*")]
    limit_keys = [k for k in keys if "send_setup" in str(k)]
    assert limit_keys, "the rate-limit keys should exist"
    for key in keys:
        assert needle not in str(key).lower()
    for key in limit_keys:
        ttl = await r.ttl(key)
        assert 0 < ttl <= mod.DAY + 1
        for member in await r.zrange(key, 0, -1):
            assert needle not in str(member).lower()
    addr_keys = [k for k in limit_keys if ":addr:" in str(k)]
    assert addr_keys and mod.address_key(ADDRESS) in str(addr_keys[0])

    logged = "\n".join(rec.getMessage() for rec in caplog.records).lower()
    assert needle not in logged
    assert "<private recipient>" in logged


def test_address_key_is_keyed_and_normalized():
    assert mod.address_key("A@Example.com ") == mod.address_key("a@example.com")
    import hashlib

    assert mod.address_key("a@example.com") != hashlib.sha256(b"a@example.com").hexdigest()[:32]


def test_other_emails_still_log_the_address(caplog):
    from src.email_queue import recipient_for_log

    assert recipient_for_log("a@example.com", False) == "a@example.com"
    assert recipient_for_log("a@example.com", True) == "<private recipient>"
