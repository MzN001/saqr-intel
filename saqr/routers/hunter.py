"""Proactive Hunter API: scam domains SAQR found before any citizen visited or reported them.

GET  /api/hunter/detections   newest detections with lead-time fields (citizen_visits, lead_time_hours)
GET  /api/hunter/status       mode, sources, last cycle, counts per source (real vs simulated)
POST /api/hunter/sweep        run one hunting cycle now (police only)
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query

from ..intel.hunter import hunter, latest_detections, pre_victim_count
from ..security import require_police

router = APIRouter(prefix="/api/hunter", tags=["Proactive Hunter"], dependencies=[Depends(require_police)])


@router.get("/detections")
async def detections(limit: int = Query(50, ge=1, le=200),
                     include_cleared: bool = Query(False, description="Also list leads the full scan cleared.")):
    rows = await latest_detections(limit, include_cleared)
    return {"mode": hunter.mode, "data": {"live": "real", "simulated": "simulated"}.get(hunter.mode, "none"),
            "pre_victim_detections": await pre_victim_count(), "count": len(rows), "detections": rows}


@router.get("/status")
async def status():
    return await hunter.status()


@router.post("/sweep")
async def sweep(wait: bool = Query(False, description="Wait for the cycle and return its summary "
                                                      "(a live cycle can take minutes).")):
    """Trigger one cycle now. Without `wait` it runs in the background: follow it on /ws/live
    (`hunter.detection`, `hunter.cycle`) or GET /api/hunter/status."""
    if hunter.mode == "off":
        raise HTTPException(409, "The proactive hunter is switched off (HUNTER_MODE=off).")
    if hunter.running:
        return {"started": False, "reason": "a cycle is already running", "mode": hunter.mode}
    if wait or not hunter.kick():
        return {"started": True, "mode": hunter.mode, "cycle": await hunter.run_cycle()}
    return {"started": True, "mode": hunter.mode, "cycle": None}
