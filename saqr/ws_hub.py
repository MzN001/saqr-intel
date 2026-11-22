"""Module 6 — Live WebSocket hub for the Police Command Center."""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from typing import Any

from fastapi import WebSocket

from .db import iso

log = logging.getLogger("saqr.ws")


class LiveHub:
    def __init__(self, replay_size: int = 50):
        self._clients: dict[WebSocket, set[str] | None] = {}
        self._lock = asyncio.Lock()
        self.recent: deque[dict[str, Any]] = deque(maxlen=replay_size)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket, topics: set[str] | None = None) -> None:
        await ws.accept()
        async with self._lock:
            self._clients[ws] = topics

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.pop(ws, None)

    def set_topics(self, ws: WebSocket, topics: set[str] | None) -> None:
        if ws in self._clients:
            self._clients[ws] = topics

    @staticmethod
    def _wants(topics: set[str] | None, event: str) -> bool:
        return not topics or any(event == t or event.startswith(t + ".") for t in topics)

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        """Fan an event out to all subscribers. Slow / dead sockets are dropped."""
        msg = {"event": event, "ts": iso(), "data": data}
        self.recent.append(msg)
        payload = json.dumps(msg, ensure_ascii=False, default=str)
        async with self._lock:
            targets = [ws for ws, t in self._clients.items() if self._wants(t, event)]

        async def _send(ws: WebSocket) -> WebSocket | None:
            try:
                await asyncio.wait_for(ws.send_text(payload), timeout=3)
                return None
            except Exception:  # noqa: BLE001
                return ws

        dead = [ws for ws in await asyncio.gather(*(_send(w) for w in targets)) if ws]
        for ws in dead:
            await self.disconnect(ws)
        log.debug("broadcast %s -> %d clients", event, len(targets) - len(dead))

    def emit(self, event: str, data: dict[str, Any]) -> None:
        """Fire-and-forget broadcast from sync-ish code paths."""
        asyncio.get_running_loop().create_task(self.broadcast(event, data))


hub = LiveHub()
