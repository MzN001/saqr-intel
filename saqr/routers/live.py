"""WS /ws/live  (Module 6) — real-time Police Command Center feed.

Query params: `topics=citizen_report,url_scan,maps_scan,email_scan,graph,ct,takedown,awareness` (optional filter),
`token=<POLICE_API_KEY>` when a key is configured.
Email events: `email_scan.completed` {scan_id, kind:"email", target, risk_score, verdict, channel,
interception_channel, impersonated_entity, created_at, top_flags} and `email_scan.failed` {scan_id, error}.
Client messages: "ping" | {"action": "subscribe", "topics": [...]} | {"action": "snapshot"}
"""
from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import self_hosts
from ..db import iso
from ..security import ws_authorized
from ..ws_hub import hub
from .system import collect_stats

router = APIRouter(tags=["Live"])


def _topics(raw: str | list | None) -> set[str] | None:
    if isinstance(raw, list):
        vals = raw
    else:
        vals = (raw or "").split(",")
    t = {v.strip() for v in vals if isinstance(v, str) and v.strip()}
    return t or None


@router.websocket("/ws/live")
async def live(ws: WebSocket):
    if not ws_authorized(ws):
        await ws.close(code=4401)
        return
    await self_hosts.remember(ws.headers.get("host"))
    await hub.connect(ws, _topics(ws.query_params.get("topics")))
    try:
        await ws.send_json({"event": "hello", "ts": iso(),
                            "data": {"stats": await collect_stats(), "recent": list(hub.recent)[-20:]}})
        while True:
            raw = await ws.receive_text()
            if raw.strip().lower() == "ping":
                await ws.send_json({"event": "pong", "ts": iso(), "data": {}})
                continue
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            action = msg.get("action") if isinstance(msg, dict) else None
            if action == "subscribe":
                hub.set_topics(ws, _topics(msg.get("topics")))
                await ws.send_json({"event": "subscribed", "ts": iso(), "data": {"topics": msg.get("topics")}})
            elif action == "snapshot":
                await ws.send_json({"event": "snapshot", "ts": iso(), "data": await collect_stats()})
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(ws)
