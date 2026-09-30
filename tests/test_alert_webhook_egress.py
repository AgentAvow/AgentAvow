"""Alert webhook egress — the account holder supplies the URL, so the backend must
never POST to it with a plain client.

Without a guard, any logged-in account could point its webhook at an internal
address, press "test", and read the status code back: a probe of the network the
backend sits in. The URL must be a public https:// address when it is saved and
again when it is delivered to, and the connection goes through the rebind-safe
client with redirects off.
"""
from __future__ import annotations

import socket

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.api import account_webhook_router
from src.api.account_webhook_router import deliver_alert_webhook
from src.database import get_db
from src.main import app
from src.models import AlertWebhook


@pytest_asyncio.fixture
async def client(db):
    async def override_get_db():
        yield db

    app.dependency_overrides[get_db] = override_get_db
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac
    app.dependency_overrides.clear()


WEBHOOK_URL = "/api/v1/account/alert-webhook"
USER = {"email": "hook@test.com", "password": "Str0ngP@ss", "display_name": "HookUser"}
# A public IP literal: passes the guard without a DNS lookup.
PUBLIC_URL = "https://93.184.216.34/hook"


async def _auth(client: AsyncClient) -> dict:
    await client.post("/api/v1/auth/register", json=USER)
    resp = await client.post(
        "/api/v1/auth/login", json={"email": USER["email"], "password": USER["password"]},
    )
    return {"Authorization": f"Bearer {resp.json()['access_token']}"}


class _FakeClient:
    """Stands in for the rebind-safe client; records what was asked of it."""

    def __init__(self, calls: list, status: int = 204):
        self._calls, self._status = calls, status

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, content=None, headers=None):
        self._calls.append(("post", url, content, headers or {}))

        class _Resp:
            status_code = self._status

        return _Resp()


@pytest.fixture
def egress(monkeypatch):
    """Replace the outbound client. ``calls`` stays empty unless a request is made."""
    calls: list = []
    created: list = []

    def fake_factory(**kwargs):
        created.append(kwargs)
        return _FakeClient(calls)

    monkeypatch.setattr("src.ssrf.ssrf_safe_async_client", fake_factory)
    return calls, created


# ── saving the URL ───────────────────────────────────────────────────────────
@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "http://93.184.216.34/hook",                 # not https
    "https://localhost/hook",
    "https://127.0.0.1/hook",
    "https://10.0.0.5/hook",
    "https://192.168.1.10/hook",
    "https://169.254.169.254/latest/meta-data/",  # cloud metadata
    "https://[::1]/hook",
])
async def test_internal_or_plain_http_url_is_refused(client, url):
    headers = await _auth(client)
    resp = await client.put(WEBHOOK_URL, json={"url": url}, headers=headers)
    assert resp.status_code == 422
    assert (await client.get(WEBHOOK_URL, headers=headers)).json()["url"] is None


@pytest.mark.asyncio
async def test_hostname_that_resolves_internally_is_refused(client, monkeypatch):
    def fake_getaddrinfo(host, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    headers = await _auth(client)
    resp = await client.put(
        WEBHOOK_URL, json={"url": "https://rebind.example.com/hook"}, headers=headers)
    assert resp.status_code == 422


@pytest.mark.asyncio
async def test_public_https_url_is_saved(client):
    headers = await _auth(client)
    resp = await client.put(WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)
    assert resp.status_code == 200
    assert resp.json()["url"] == PUBLIC_URL


# ── delivery ─────────────────────────────────────────────────────────────────
@pytest.mark.asyncio
async def test_delivery_uses_the_rebind_safe_client_without_redirects(egress):
    calls, created = egress
    status = await deliver_alert_webhook(PUBLIC_URL, {"type": "agentavow.alert.test"})
    assert status == 204
    assert [(c[0], c[1], c[2]) for c in calls] == [
        ("post", PUBLIC_URL, b'{"type":"agentavow.alert.test"}')]
    assert created[0]["follow_redirects"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "https://127.0.0.1:8000/api/v1/admin",
    "https://169.254.169.254/latest/meta-data/",
    "http://93.184.216.34/hook",
])
async def test_delivery_refuses_a_blocked_url_without_sending(egress, url):
    calls, created = egress
    assert await deliver_alert_webhook(url, {"x": 1}) == 0
    assert calls == [] and created == []


@pytest.mark.asyncio
async def test_delivery_failure_is_status_zero(monkeypatch):
    def boom(**kwargs):
        raise RuntimeError("connect failed")

    monkeypatch.setattr("src.ssrf.ssrf_safe_async_client", boom)
    assert await deliver_alert_webhook(PUBLIC_URL, {"x": 1}) == 0


@pytest.mark.asyncio
async def test_test_endpoint_does_not_probe_an_internal_url_saved_before_the_guard(
    client, db, egress,
):
    """A row written before the guard existed may hold an internal URL. "Test" must
    not send to it, and must not report a status that came from the network."""
    calls, created = egress
    headers = await _auth(client)
    me = (await client.get("/api/v1/auth/me", headers=headers)).json()
    db.add(AlertWebhook(
        entity_id=me["id"], url="https://127.0.0.1:8000/api/v1/admin", active=True))
    await db.flush()

    resp = await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert resp.status_code == 200
    assert resp.json() == {"delivered": False, "status": 0}
    assert calls == [] and created == []


@pytest.mark.asyncio
async def test_test_endpoint_delivers_to_a_public_url(client, egress):
    calls, _ = egress
    headers = await _auth(client)
    await client.put(WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)
    resp = await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert resp.json() == {"delivered": True, "status": 204}
    assert len(calls) == 1 and calls[0][1] == PUBLIC_URL


def test_watch_loop_delivers_through_the_guarded_helper():
    """The re-scan loop must not build its own client for the account's URL."""
    import inspect

    from src.jobs import scheduler

    src = inspect.getsource(scheduler._run_watch_rescan)
    assert "deliver_to_hook" in src
    assert "httpx" not in src
    assert "deliver_alert_webhook(" in inspect.getsource(account_webhook_router.deliver_to_hook)


# ── signing ──────────────────────────────────────────────────────────────────
def _verify(secret: str, headers: dict, body: bytes) -> bool:
    """What a receiver does: recompute the MAC over ``<timestamp>.<body>``."""
    import hashlib
    import hmac

    expected = "sha256=" + hmac.new(
        secret.encode(), headers["X-AgentAvow-Timestamp"].encode() + b"." + body,
        hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, headers["X-AgentAvow-Signature"])


@pytest.mark.asyncio
async def test_saving_a_webhook_issues_a_secret_once(client):
    headers = await _auth(client)
    created = (await client.put(WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)).json()
    assert created["signing_secret"].startswith("whsec_")
    assert created["signed"] is True
    # Never shown again: not on read, not when the URL is changed.
    assert "signing_secret" not in (await client.get(WEBHOOK_URL, headers=headers)).json()
    again = await client.put(
        WEBHOOK_URL, json={"url": "https://93.184.216.34/other"}, headers=headers)
    assert "signing_secret" not in again.json() and again.json()["signed"] is True


@pytest.mark.asyncio
async def test_test_delivery_is_signed_with_the_issued_secret(client, egress):
    calls, _ = egress
    headers = await _auth(client)
    secret = (await client.put(
        WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)).json()["signing_secret"]
    await client.post(f"{WEBHOOK_URL}/test", headers=headers)

    _, _, body, sent = calls[0]
    assert _verify(secret, sent, body)
    assert not _verify("whsec_wrong", sent, body)
    assert not _verify(secret, sent, body + b" ")           # any changed byte fails
    stale = {**sent, "X-AgentAvow-Timestamp": "1"}
    assert not _verify(secret, stale, body)                  # timestamp is inside the MAC


@pytest.mark.asyncio
async def test_rotating_replaces_the_secret(client, egress):
    calls, _ = egress
    headers = await _auth(client)
    old = (await client.put(
        WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)).json()["signing_secret"]
    new = (await client.post(
        f"{WEBHOOK_URL}/rotate-secret", headers=headers)).json()["signing_secret"]
    assert new != old and new.startswith("whsec_")

    await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    _, _, body, sent = calls[0]
    assert _verify(new, sent, body) and not _verify(old, sent, body)


@pytest.mark.asyncio
async def test_rotate_without_a_webhook_is_404(client):
    headers = await _auth(client)
    assert (await client.post(f"{WEBHOOK_URL}/rotate-secret", headers=headers)).status_code == 404


@pytest.mark.asyncio
async def test_webhook_saved_before_signing_is_unsigned_until_rotated(client, db, egress):
    calls, _ = egress
    headers = await _auth(client)
    me = (await client.get("/api/v1/auth/me", headers=headers)).json()
    db.add(AlertWebhook(entity_id=me["id"], url=PUBLIC_URL, active=True))
    await db.flush()

    assert (await client.get(WEBHOOK_URL, headers=headers)).json()["signed"] is False
    await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert "X-AgentAvow-Signature" not in calls[0][3]

    secret = (await client.post(
        f"{WEBHOOK_URL}/rotate-secret", headers=headers)).json()["signing_secret"]
    await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert _verify(secret, calls[1][3], calls[1][2])


@pytest.mark.asyncio
async def test_unreadable_secret_is_not_delivered_unsigned(client, db, egress, monkeypatch):
    calls, _ = egress
    headers = await _auth(client)
    await client.put(WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)

    def broken(hook):
        raise ValueError("cannot decrypt")

    monkeypatch.setattr(account_webhook_router, "webhook_secret", broken)
    resp = await client.post(f"{WEBHOOK_URL}/test", headers=headers)
    assert resp.json() == {"delivered": False, "status": 0}
    assert calls == []


@pytest.mark.asyncio
async def test_secret_is_not_stored_in_the_clear_when_encryption_is_configured(
    client, db, monkeypatch,
):
    from cryptography.fernet import Fernet
    from sqlalchemy import select

    from src import encryption
    from src.config import settings

    monkeypatch.setattr(settings, "webhook_encryption_key", Fernet.generate_key().decode())
    monkeypatch.setattr(encryption, "_fernet", None)
    headers = await _auth(client)
    secret = (await client.put(
        WEBHOOK_URL, json={"url": PUBLIC_URL}, headers=headers)).json()["signing_secret"]
    stored = (await db.execute(select(AlertWebhook.signing_key))).scalar_one()
    assert stored.startswith("enc:") and secret not in stored
    monkeypatch.setattr(encryption, "_fernet", None)  # do not leak the test key

