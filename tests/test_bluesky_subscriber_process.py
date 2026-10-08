"""Bluesky Jetstream subscriber: web-lifespan gate and the standalone process."""
from __future__ import annotations

import ast
import asyncio
import inspect
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

import src.main as main_mod
from src.config import settings
from src.feeds.bluesky import run_subscriber_process as proc
from src.feeds.bluesky.subscriber import BLUESKY_JETSTREAM_LOCK

REPO = Path(__file__).resolve().parent.parent


@pytest.fixture
def flags(monkeypatch):
    def _set(feed: bool, in_web: bool) -> None:
        monkeypatch.setattr(settings, "bluesky_feed_enabled", feed)
        monkeypatch.setattr(settings, "bluesky_subscriber_in_web", in_web)
    return _set


def test_lock_name_unchanged():
    assert BLUESKY_JETSTREAM_LOCK == "ag:lock:bluesky-jetstream"


def test_setting_defaults_to_in_web():
    from src.config import Settings

    assert Settings.model_fields["bluesky_subscriber_in_web"].default is True


async def test_web_does_not_start_subscriber_when_in_web_false(flags):
    flags(feed=True, in_web=False)
    with patch("src.worker_lock.run_exclusively", new=AsyncMock()) as rx:
        assert main_mod._start_bluesky_subscriber_in_web() is None
    rx.assert_not_called()


async def test_web_does_not_start_subscriber_when_feed_disabled(flags):
    flags(feed=False, in_web=True)
    with patch("src.worker_lock.run_exclusively", new=AsyncMock()) as rx:
        assert main_mod._start_bluesky_subscriber_in_web() is None
    rx.assert_not_called()


async def test_web_starts_subscriber_when_in_web_true(flags):
    flags(feed=True, in_web=True)
    with patch("src.worker_lock.run_exclusively", new=AsyncMock()) as rx:
        task = main_mod._start_bluesky_subscriber_in_web()
        assert task is not None
        await task
    rx.assert_awaited_once()
    args, kwargs = rx.call_args
    from src.feeds.bluesky.subscriber import run_subscriber

    assert args[0] == "ag:lock:bluesky-jetstream"
    assert args[2] is run_subscriber
    assert kwargs.get("retry") == 30


def test_lifespan_uses_the_gate():
    """The lifespan starts the subscriber only through the gated helper."""
    src = inspect.getsource(main_mod.lifespan)
    assert "_start_bluesky_subscriber_in_web()" in src
    assert "run_subscriber" not in src
    assert "bluesky_feed_enabled" not in src


def test_feed_enabled_still_has_one_use_in_main():
    """bluesky_feed_enabled semantics unchanged: still the master switch in main."""
    tree = ast.parse(inspect.getsource(main_mod))
    names = [
        n.value for n in ast.walk(tree)
        if isinstance(n, ast.Constant) and n.value == "bluesky_feed_enabled"
    ]
    assert len(names) == 1


async def test_process_runs_exclusively_with_same_lock(monkeypatch):
    monkeypatch.setattr(settings, "bluesky_feed_enabled", True)

    async def fake_rx(key, ttl, work, *, retry):
        await work()

    with patch.object(proc, "run_exclusively", side_effect=fake_rx) as rx, \
            patch.object(proc, "run_subscriber", new=AsyncMock()) as rs, \
            patch.object(proc, "_release_lock", new=AsyncMock()) as rel:
        await proc.main()
    rx.assert_called_once()
    args, kwargs = rx.call_args
    assert args[0] == "ag:lock:bluesky-jetstream"
    assert args[1] == 60
    assert kwargs["retry"] == 30
    rs.assert_awaited_once()
    rel.assert_awaited_once()  # held the lock -> hands it back on exit


async def test_process_does_not_release_lock_it_never_held(monkeypatch):
    monkeypatch.setattr(settings, "bluesky_feed_enabled", True)

    async def waiting_rx(key, ttl, work, *, retry):
        await asyncio.sleep(3600)  # lost the race, waiting

    with patch.object(proc, "run_exclusively", side_effect=waiting_rx), \
            patch.object(proc, "_release_lock", new=AsyncMock()) as rel:
        t = asyncio.create_task(proc.main())
        await asyncio.sleep(0)
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
    rel.assert_not_awaited()


async def test_process_idles_when_feed_disabled(monkeypatch):
    monkeypatch.setattr(settings, "bluesky_feed_enabled", False)
    with patch.object(proc, "run_exclusively", new=AsyncMock()) as rx:
        t = asyncio.create_task(proc.main())
        await asyncio.sleep(0.01)
        assert not t.done()
        t.cancel()
        with pytest.raises(asyncio.CancelledError):
            await t
    rx.assert_not_called()


async def test_run_wrapper_exits_cleanly_on_cancel():
    """SIGTERM cancels the task; _run swallows it and closes Redis."""
    async def forever():
        await asyncio.sleep(3600)

    with patch.object(proc, "main", side_effect=forever), \
            patch("src.redis_client.close_redis", new=AsyncMock()) as close:
        t = asyncio.create_task(proc._run())
        await asyncio.sleep(0)
        t.cancel()
        await t  # no CancelledError escapes
    close.assert_awaited_once()


def test_compose_runs_subscriber_in_its_own_service():
    import yaml

    with open(REPO / "docker-compose.prod.yml") as f:
        cfg = yaml.safe_load(f)
    svc = cfg["services"]
    be, sub = svc["backend"], svc["bluesky-subscriber"]
    assert be["environment"]["BLUESKY_SUBSCRIBER_IN_WEB"] == "false"
    assert "--workers 2" in be["command"]
    assert sub["environment"]["BLUESKY_SUBSCRIBER_IN_WEB"] == "true"
    assert sub["entrypoint"] == [
        "python", "-m", "src.feeds.bluesky.run_subscriber_process",
    ]
    assert sub["image"] == be["image"]
    assert "build" not in sub
    assert sub["env_file"] == be["env_file"]
    assert "ports" not in sub and "expose" not in sub and "healthcheck" not in sub
    assert sub["restart"] == "unless-stopped"
    assert sub["depends_on"]["redis"]["condition"] == "service_healthy"


def test_subscriber_module_imports_websockets_exceptions_standalone():
    """In a bare interpreter (no uvicorn) `websockets.exceptions` must resolve."""
    import subprocess
    import sys

    code = (
        "import src.feeds.bluesky.run_subscriber_process as m; "
        "import src.feeds.bluesky.subscriber as s; "
        "print(s.websockets.exceptions.ConnectionClosed.__name__)"
    )
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         timeout=60, cwd=REPO)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "ConnectionClosed"
