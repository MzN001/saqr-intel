"""WS /ws/live  (Module 6) — real-time Police Command Center feed.

Query params: `topics=citizen_report,url_scan,maps_scan,email_scan,graph,ct,takedown,awareness` (optional filter),
`token=<POLICE_API_KEY>` (or an `X-API-Key` header) when a key is configured. Without a valid token
a configured server still accepts the socket as a *public* (citizen) client: it only gets
`security.PUBLIC_WS_TOPICS` (police.warning, url_scan.*, maps_scan.*, email_scan.*), trimmed by
`ws_hub.public_view` (no IPs, no syndicate, no email sender/subject).
Email events: `email_scan.completed` {scan_id, kind:"email", target, risk_score, verdict, channel,
interception_channel, impersonated_entity, created_at, top_flags} and `email_scan.failed` {scan_id, error}.
Client messages: "ping" | {"action": "subscribe", "topics": [...]} | {"action": "snapshot"}
"""
from __future__ import annotations

import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from .. import self_hosts
from ..db import iso
from ..security import PUBLIC_WS_TOPICS, police_key_configured, ws_authorized
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


def _public_topics(requested: set[str] | None) -> set[str]:
    """Topics a public client may have: each requested one must be a public topic or a sub-topic of
    one (`url_scan.completed`); a parent like `police` is NOT widened. Nothing valid -> all public."""
    allowed = {t for t in (requested or ()) if any(t == p or t.startswith(p + ".") for p in PUBLIC_WS_TOPICS)}
    return allowed or set(PUBLIC_WS_TOPICS)


@router.websocket("/ws/live")
async def live(ws: WebSocket):
    public = police_key_configured() and not ws_authorized(ws)
    await self_hosts.remember(ws.headers.get("host"))
    topics = _topics(ws.query_params.get("topics"))
    if public:
        topics = _public_topics(topics)
    await hub.connect(ws, topics, public=public)
    try:
        # /api/stats is open to everyone, so the same stats are fine for public clients too.
        await ws.send_json({"event": "hello", "ts": iso(),
                            "data": {"stats": await collect_stats(), "recent": hub.recent_for(topics, public)[-20:]}})
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
                topics = _topics(msg.get("topics"))
                if public:
                    topics = _public_topics(topics)
                hub.set_topics(ws, topics)
                shown = sorted(topics) if public else msg.get("topics")
                await ws.send_json({"event": "subscribed", "ts": iso(), "data": {"topics": shown}})
            elif action == "snapshot":
                await ws.send_json({"event": "snapshot", "ts": iso(), "data": await collect_stats()})
    except WebSocketDisconnect:
        pass
    finally:
        await hub.disconnect(ws)
