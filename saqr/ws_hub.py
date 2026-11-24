"""Module 6 — Live WebSocket hub for the Police Command Center.

Two kinds of client: authorised (police key, or no key configured) get every event in full; public
(citizen, keyless while POLICE_API_KEY is set) get only `PUBLIC_WS_TOPICS`, trimmed by `public_view`.
"""
from __future__ import annotations

import asyncio
import json
import logging
from collections import deque
from typing import Any

from fastapi import WebSocket

from .db import iso
from .security import PUBLIC_WS_TOPICS

log = logging.getLogger("saqr.ws")


def _in(event: str, topic: str) -> bool:
    return event == topic or event.startswith(topic + ".")


def public_view(event: str, data: dict[str, Any]) -> dict[str, Any] | None:
    """A citizen-safe copy of an event payload, or None when the event is police-only.

    Kept on purpose (the citizen LiveCrowdShield reads them): scan_id, verdict, risk_score, domain,
    impersonated_entity, interception_channel, created_at, harvested_fields, red_flags, top_flags,
    listing.website_domain.
    """
    if not any(_in(event, t) for t in PUBLIC_WS_TOPICS):
        return None
    out = dict(data) if isinstance(data, dict) else {}
    if _in(event, "url_scan"):
        out.pop("ip_addresses", None)
        out.pop("syndicate", None)
    elif _in(event, "email_scan"):
        if "target" in out:
            out["target"] = None  # "sender | subject": personal data of the citizen who scanned it
    elif _in(event, "maps_scan"):
        out.pop("syndicate", None)
    return out


class LiveHub:
    def __init__(self, replay_size: int = 50):
        # ws -> (topics, public)
        self._clients: dict[WebSocket, tuple[set[str] | None, bool]] = {}
        self._lock = asyncio.Lock()
        self.recent: deque[dict[str, Any]] = deque(maxlen=replay_size)

    @property
    def client_count(self) -> int:
        return len(self._clients)

    async def connect(self, ws: WebSocket, topics: set[str] | None = None, public: bool = False) -> None:
        await ws.accept()
        async with self._lock:
            self._clients[ws] = (topics, public)

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.pop(ws, None)

    def set_topics(self, ws: WebSocket, topics: set[str] | None) -> None:
        if ws in self._clients:
            self._clients[ws] = (topics, self._clients[ws][1])

    @staticmethod
    def _wants(topics: set[str] | None, event: str) -> bool:
        return not topics or any(_in(event, t) for t in topics)

    def recent_for(self, topics: set[str] | None, public: bool) -> list[dict[str, Any]]:
        """Replay buffer filtered by topic, and trimmed to the public view for citizen clients."""
        out = []
        for msg in self.recent:
            if not self._wants(topics, msg["event"]):
                continue
            if public:
                data = public_view(msg["event"], msg["data"])
                if data is None:
                    continue
                msg = {**msg, "data": data}
            out.append(msg)
        return out

    async def broadcast(self, event: str, data: dict[str, Any]) -> None:
        """Fan an event out to all subscribers. Slow / dead sockets are dropped."""
        msg = {"event": event, "ts": iso(), "data": data}
        self.recent.append(msg)
        async with self._lock:
            full_targets = [ws for ws, (t, pub) in self._clients.items() if not pub and self._wants(t, event)]
            pub_targets = [ws for ws, (t, pub) in self._clients.items() if pub and self._wants(t, event)]

        sends: list[tuple[WebSocket, str]] = []
        if full_targets:
            payload = json.dumps(msg, ensure_ascii=False, default=str)
            sends += [(ws, payload) for ws in full_targets]
        if pub_targets:
            pdata = public_view(event, data)
            if pdata is not None:
                ppayload = json.dumps({**msg, "data": pdata}, ensure_ascii=False, default=str)
                sends += [(ws, ppayload) for ws in pub_targets]

        async def _send(ws: WebSocket, text: str) -> WebSocket | None:
            try:
                await asyncio.wait_for(ws.send_text(text), timeout=3)
                return None
            except Exception:  # noqa: BLE001
                return ws

        dead = [ws for ws in await asyncio.gather(*(_send(w, p) for w, p in sends)) if ws]
        for ws in dead:
            await self.disconnect(ws)
        log.debug("broadcast %s -> %d clients", event, len(sends) - len(dead))

    def emit(self, event: str, data: dict[str, Any]) -> None:
        """Fire-and-forget broadcast from sync-ish code paths."""
        asyncio.get_running_loop().create_task(self.broadcast(event, data))


hub = LiveHub()
