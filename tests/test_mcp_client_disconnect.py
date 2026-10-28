"""A client that hangs up mid-request is not a server error (Sentry AGENTGRAPH-BACKEND-2C).

The /mcp front door answers 499 when no response was started (a ClientDisconnect, or the
SDK returning without answering), so neither the SDK's ClientDisconnect nor Starlette's
"No response returned." reaches Sentry; real errors still propagate and are counted.
"""
from __future__ import annotations

import pytest
from starlette.requests import ClientDisconnect

from src.bridges import mcp_response_counter as counter
from src.bridges import mcp_streamable as m

SCOPE = {"type": "http", "method": "POST", "path": "/mcp",
         "headers": [(b"user-agent", b"claude-code/2.1.305 (cli)")], "client": ("1.2.3.4", 1)}


class _SM:
    def __init__(self, behaviour):
        self.behaviour = behaviour

    async def handle_request(self, scope, receive, send):
        await self.behaviour(send)


@pytest.fixture
def harness(monkeypatch):
    recorded: list[int] = []
    monkeypatch.setattr(counter, "counting_enabled", lambda: True)
    monkeypatch.setattr(counter, "record_response",
                        lambda status, body=b"", **kw: recorded.append(status))

    async def run(behaviour):
        sent: list[dict] = []

        async def send(msg):
            sent.append(msg)

        async def receive():
            return {"type": "http.disconnect"}

        monkeypatch.setattr(m, "session_manager", _SM(behaviour))
        await m.mcp_asgi_app(dict(SCOPE), receive, send)
        return sent

    return run, recorded


@pytest.mark.asyncio
async def test_client_disconnect_is_answered_499_and_not_raised(harness):
    run, recorded = harness

    async def hang_up(send):
        raise ClientDisconnect()

    sent = await run(hang_up)
    assert sent[0]["type"] == "http.response.start" and sent[0]["status"] == 499
    assert recorded == []  # the client left; not a server reject


@pytest.mark.asyncio
async def test_no_response_started_is_answered_499(harness):
    run, recorded = harness

    async def silent(send):
        return None

    sent = await run(silent)
    assert [x.get("status") for x in sent if x["type"] == "http.response.start"] == [499]
    assert recorded == []


@pytest.mark.asyncio
async def test_real_errors_still_raise_and_count_as_500(harness):
    run, recorded = harness

    async def boom(send):
        raise RuntimeError("handler bug")

    with pytest.raises(RuntimeError):
        await run(boom)
    assert recorded == [500]


@pytest.mark.asyncio
async def test_a_normal_answer_is_passed_through_and_counted(harness):
    run, recorded = harness

    async def ok(send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"{}", "more_body": False})

    sent = await run(ok)
    assert sent[0]["status"] == 200 and len(sent) == 2
    assert recorded == [200]


@pytest.mark.asyncio
async def test_send_failing_after_disconnect_never_raises(harness, monkeypatch):
    async def closed_send(msg):
        raise OSError("connection closed")

    await m._answer_client_closed(closed_send)  # must not raise
