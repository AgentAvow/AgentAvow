"""WebSocket connection manager with Redis pub/sub for cross-worker broadcasting.

Each Gunicorn worker maintains its own local WebSocket connections.
When a broadcast is needed, the message is published to a Redis channel
so all workers can relay it to their connected clients.
"""
from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections import defaultdict
from typing import Any

from fastapi import WebSocket

logger = logging.getLogger(__name__)

# Redis channel prefix for WebSocket broadcasts
_REDIS_WS_CHANNEL = "agentgraph:ws"

# Unique ID for this worker process (prevents double-delivery)
_WORKER_ID = str(uuid.uuid4())


class ConnectionManager:
    """Manages WebSocket connections with per-entity channels.

    Local connections are tracked in-memory per worker process.
    Cross-worker messaging uses Redis pub/sub.
    """

    def __init__(self) -> None:
        # channel:entity_id -> set of WebSocket connections (local to this worker)
        self._connections: dict[str, set[WebSocket]] = defaultdict(set)
        # Secondary index: channel_name -> set of WebSocket connections (O(1) lookup)
        self._channel_subscribers: dict[str, set[WebSocket]] = defaultdict(set)
        # All connections for broadcast (local to this worker)
        self._all: set[WebSocket] = set()
        # Whether the Redis subscriber background task is running
        self._subscriber_task: asyncio.Task | None = None
        self._subscriber_lock = asyncio.Lock()

    async def connect(
        self, websocket: WebSocket, entity_id: str, channels: list[str] | None = None,
    ) -> None:
        """Register an already-accepted WebSocket connection."""
        self._all.add(websocket)
        for ch in channels or ["feed"]:
            key = f"{ch}:{entity_id}"
            self._connections[key].add(websocket)
            self._channel_subscribers[ch].add(websocket)
        # Start Redis subscriber if not already running
        self._ensure_subscriber()

    def disconnect(self, websocket: WebSocket, entity_id: str) -> None:
        """Remove a WebSocket connection from all channels."""
        self._all.discard(websocket)
        keys_to_remove = []
        for key, sockets in self._connections.items():
            sockets.discard(websocket)
            if not sockets:
                keys_to_remove.append(key)
        for key in keys_to_remove:
            del self._connections[key]
        # Clean up channel subscriber index
        ch_keys_to_remove = []
        for ch, sockets in self._channel_subscribers.items():
            sockets.discard(websocket)
            if not sockets:
                ch_keys_to_remove.append(ch)
        for ch in ch_keys_to_remove:
            del self._channel_subscribers[ch]

    async def send_to_entity(
        self, entity_id: str, channel: str, data: dict[str, Any],
    ) -> int:
        """Send a message to all connections of an entity on a channel, across all workers."""
        # Always deliver locally first for immediate feedback
        sent = await self._local_send_to_entity(entity_id, channel, data)
        # Then publish to Redis for other workers
        await self._publish({
            "target": "entity",
            "channel": channel,
            "entity_id": entity_id,
            "data": data,
            "origin": _WORKER_ID,
        })
        return sent

    async def broadcast_to_channel(
        self, channel: str, data: dict[str, Any],
    ) -> int:
        """Broadcast to all connections subscribed to a channel, across all workers."""
        # Always deliver locally first
        sent = await self._local_broadcast_to_channel(channel, data)
        # Then publish to Redis for other workers
        await self._publish({
            "target": "channel",
            "channel": channel,
            "data": data,
            "origin": _WORKER_ID,
        })
        return sent

    async def broadcast(self, data: dict[str, Any]) -> int:
        """Broadcast to all connected clients across all workers."""
        # Always deliver locally first
        sent = await self._local_broadcast(data)
        # Then publish to Redis for other workers
        await self._publish({
            "target": "all",
            "data": data,
            "origin": _WORKER_ID,
        })
        return sent

    @property
    def active_connections(self) -> int:
        return len(self._all)

    # --- Redis pub/sub ---

    async def _publish(self, message: dict[str, Any]) -> bool:
        """Publish a message to the Redis WebSocket channel."""
        try:
            from src.redis_client import get_redis

            r = get_redis()
            await r.publish(_REDIS_WS_CHANNEL, json.dumps(message, default=str))
            return True
        except Exception:
            logger.debug("Redis pub/sub unavailable, using local-only delivery")
            return False

    def _ensure_subscriber(self) -> None:
        """Start the Redis subscriber task if not already running."""
        if self._subscriber_task is None or self._subscriber_task.done():
            try:
                loop = asyncio.get_running_loop()
                self._subscriber_task = loop.create_task(
                    self._subscribe_with_retry(),
                )
            except RuntimeError:
                pass

    async def _subscribe_with_retry(self) -> None:
        """Retry subscriber loop with exponential backoff."""
        delay = 1.0
        max_delay = 30.0
        while True:
            try:
                await self._subscribe_loop()
            except asyncio.CancelledError:
                return
            except Exception:
                logger.warning(
                    "Redis subscriber disconnected, retrying in %.0fs",
                    delay,
                )
                await asyncio.sleep(delay)
                delay = min(delay * 2, max_delay)

    async def _subscribe_loop(self) -> None:
        """Background task that listens for Redis pub/sub messages."""
        from src.redis_client import get_redis

        r = get_redis()
        pubsub = r.pubsub()
        try:
            await pubsub.subscribe(_REDIS_WS_CHANNEL)

            async for raw_message in pubsub.listen():
                if raw_message["type"] != "message":
                    continue
                try:
                    msg = json.loads(raw_message["data"])
                    await self._handle_pubsub_message(msg)
                except Exception:
                    logger.exception("Error handling pub/sub message")
        finally:
            try:
                await pubsub.unsubscribe(_REDIS_WS_CHANNEL)
                await pubsub.close()
            except Exception:
                pass

    async def _handle_pubsub_message(self, msg: dict[str, Any]) -> None:
        """Route an incoming pub/sub message to local WebSocket connections.

        Skip messages from this worker (already delivered locally).
        """
        if msg.get("origin") == _WORKER_ID:
            return

        target = msg.get("target")
        data = msg.get("data", {})

        if target == "entity":
            await self._local_send_to_entity(
                msg["entity_id"], msg["channel"], data,
            )
        elif target == "channel":
            await self._local_broadcast_to_channel(msg["channel"], data)
        elif target == "all":
            await self._local_broadcast(data)

    # --- Local delivery (this worker only) ---

    async def _safe_send(self, ws: Any, message: str) -> bool:
        """Send with timeout — disconnect slow clients after 5 seconds."""
        try:
            await asyncio.wait_for(ws.send_text(message), timeout=5.0)
            return True
        except asyncio.TimeoutError:
            logger.debug("WebSocket send timeout, disconnecting slow client")
            return False
        except RuntimeError as e:
            # Log ASGI state errors that were previously silent
            err_str = str(e).lower()
            if "websocket.accept" in err_str or "websocket.send" in err_str:
                logger.debug("WebSocket ASGI state error (stale connection): %s", e)
            return False
        except Exception:
            return False

    async def _local_send_to_entity(
        self, entity_id: str, channel: str, data: dict[str, Any],
    ) -> int:
        key = f"{channel}:{entity_id}"
        sockets = self._connections.get(key, set())
        sent = 0
        dead = []
        message = json.dumps(data, default=str)
        # Snapshot: _safe_send awaits, and a concurrent connect/disconnect can mutate
        # the live set mid-iteration ("Set changed size during iteration"). Iterate a copy.
        for ws in list(sockets):
            if await self._safe_send(ws, message):
                sent += 1
            else:
                dead.append(ws)
        for ws in dead:
            self._connections[key].discard(ws)
            self._all.discard(ws)
        return sent

    async def _local_broadcast_to_channel(
        self, channel: str, data: dict[str, Any],
    ) -> int:
        message = json.dumps(data, default=str)
        sent = 0
        dead = []
        # Use O(1) channel index instead of iterating all connections
        for ws in list(self._channel_subscribers.get(channel, set())):
            if await self._safe_send(ws, message):
                sent += 1
            else:
                dead.append(ws)
        for ws in dead:
            self._channel_subscribers.get(channel, set()).discard(ws)
            self._all.discard(ws)
        return sent

    async def _local_broadcast(self, data: dict[str, Any]) -> int:
        message = json.dumps(data, default=str)
        sent = 0
        dead = []
        for ws in list(self._all):  # snapshot — _safe_send awaits; set can mutate mid-loop
            if await self._safe_send(ws, message):
                sent += 1
            else:
                dead.append(ws)
        for ws in dead:
            self._all.discard(ws)
        return sent


# Global singleton
manager = ConnectionManager()
