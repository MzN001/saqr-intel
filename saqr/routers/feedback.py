"""Citizen "Report a false alarm" + the officer review queue.

POST /api/feedback/false-alarm          public: shared rate limit + own bucket (FEEDBACK_RATE_LIMIT_PER_MINUTE)
GET  /api/feedback/false-alarms         police: queue, newest first, with counts
POST /api/feedback/false-alarms/{id}    police: {"status": "confirmed" | "dismissed"} (records the decision only)
"""
from __future__ import annotations

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from ..config import settings
from ..db import db
from ..feedback_state import MAX_NOTE, feedback_state
from ..security import RateLimiter, rate_limit, require_police
from ..ws_hub import hub
from .email import rate_limit_bucket

router = APIRouter(prefix="/api/feedback", tags=["Citizen feedback"])

feedback_limiter = RateLimiter(settings.feedback_rate_limit_per_minute)
feedback_rate_limit = rate_limit_bucket(feedback_limiter)


class FalseAlarmReport(BaseModel):
    scan_id: str = Field(min_length=1, max_length=64)
    note: str | None = Field(default=None, max_length=MAX_NOTE)


class FalseAlarmDecision(BaseModel):
    status: Literal["confirmed", "dismissed"]


@router.post("/false-alarm", dependencies=[Depends(rate_limit), Depends(feedback_rate_limit)])
async def report_false_alarm(req: FalseAlarmReport, request: Request):
    scan = await db.fetchone("SELECT id AS scan_id, kind, domain, verdict, risk_score FROM scans WHERE id=?",
                             (req.scan_id.strip(),))
    if not scan:
        raise HTTPException(404, "Scan not found.")
    client = request.client.host if request.client else "unknown"
    item, dup = await feedback_state.report(scan, req.note or "", client)
    if not dup:
        await hub.broadcast("police.false_alarm", {
            "id": item["id"], "label": item["label"], "verdict": item["verdict"], "score": item["score"],
            "reports": item["reports"], "status": item["status"], "created_at": item["created_at"]})
    return {"ok": True, "id": item["id"], "status": item["status"], "deduplicated": dup}


@router.get("/false-alarms", dependencies=[Depends(require_police)])
async def list_false_alarms():
    return await feedback_state.listing()


@router.post("/false-alarms/{report_id}", dependencies=[Depends(require_police)])
async def resolve_false_alarm(report_id: str, req: FalseAlarmDecision):
    item = await feedback_state.resolve(report_id, req.status)
    if item is None:
        raise HTTPException(404, "Report not found.")
    return item
