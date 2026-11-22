"""GET /api/ct-stream  (Module 1 — zero-hour CT detections)."""
from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import StreamingResponse

from ..db import db
from ..intel.ct_monitor import ct_monitor
from ..security import require_police
from ..ws_hub import hub

router = APIRouter(prefix="/api", tags=["Certificate Transparency"], dependencies=[Depends(require_police)])


async def _recent(limit: int, min_score: int) -> list[dict]:
    rows = await db.fetchall(
        "SELECT id, domain, seen_at, score, entity, source, data_json FROM ct_events WHERE score >= ? "
        "ORDER BY seen_at DESC LIMIT ?", (min_score, limit))
    for r in rows:
        r.update(json.loads(r.pop("data_json") or "{}"))
        r["impersonated_entity"] = r.pop("entity")
    return rows


@router.get("/ct-stream")
async def ct_stream(limit: int = Query(50, ge=1, le=500), min_score: int = Query(0, ge=0, le=100)):
    """Snapshot of recent lookalike-certificate detections + monitor status.
    For push updates subscribe to `/ws/live?topics=ct` or `/api/ct-stream/sse`."""
    return {"monitor": ct_monitor.status(), "detections": await _recent(limit, min_score)}


@router.get("/ct-stream/sse")
async def ct_stream_sse(request: Request):
    """Server-Sent Events stream of `ct.detection` events (EventSource-friendly)."""
    async def gen():
        last_id = (await db.fetchone("SELECT COALESCE(MAX(id), 0) AS m FROM ct_events"))["m"]
        yield f"event: status\ndata: {json.dumps(ct_monitor.status())}\n\n"
        while not await request.is_disconnected():
            rows = await db.fetchall("SELECT * FROM ct_events WHERE id > ? ORDER BY id", (last_id,))
            for r in rows:
                last_id = r["id"]
                r.update(json.loads(r.pop("data_json") or "{}"))
                yield f"id: {r['id']}\nevent: ct.detection\ndata: {json.dumps(r, ensure_ascii=False)}\n\n"
            yield ": keep-alive\n\n"
            await asyncio.sleep(2)

    _ = hub  # imported for symmetry; SSE polls the DB so it also works across workers
    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
