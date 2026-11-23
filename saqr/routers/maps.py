"""POST /api/scan-maps  (Module 2)."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from ..config import settings
from ..db import db, iso
from ..intel import graph_engine, maps_sentinel
from ..intel.nextdns_sync import nextdns_sync
from ..pipeline import new_scan_id
from ..police_state import police_state
from ..schemas import ScanMapsRequest
from ..security import rate_limit
from ..ws_hub import hub

router = APIRouter(prefix="/api", tags=["Maps geo-spoof sentinel"])


@router.post("/scan-maps", dependencies=[Depends(rate_limit)])
async def scan_maps(req: ScanMapsRequest):
    scan_id = new_scan_id("MAP")
    target = req.maps_url or req.business_name or req.query or f"{req.lat},{req.lng}"
    await hub.broadcast("citizen_report.received", {
        "scan_id": scan_id, "kind": "maps", "target": target, "channel": "maps",
        "interception_channel": req.interception_channel, "received_at": iso()})
    try:
        res = await maps_sentinel.scan_listing(
            maps_url=req.maps_url, business_name=req.business_name, query=req.query,
            website=req.website, phone=req.phone, lat=req.lat, lng=req.lng)
    except ValueError as exc:
        await hub.broadcast("maps_scan.failed", {"scan_id": scan_id, "error": str(exc)})
        raise HTTPException(422, str(exc)) from exc

    scan = {"scan_id": scan_id, "kind": "maps", "created_at": iso(), "target": target,
            "domain": res["listing"].get("website_domain"), "channel": "maps", "reporter": req.reporter_id,
            "interception_channel": req.interception_channel,
            "technical_indicators": {}, **res}
    await db.save_scan(scan)
    if scan["verdict"] != "SAFE":
        delta = await graph_engine.ingest_map_scan(scan)
        scan["graph_delta"] = delta
        scan["syndicate"] = delta.get("syndicate")
        await db.save_scan(scan)
        await hub.broadcast("graph.updated", {"scan_id": scan_id, **delta})
    await hub.broadcast("maps_scan.completed", {
        "scan_id": scan_id, "kind": "maps", "verdict": scan["verdict"], "risk_score": scan["risk_score"],
        "impersonated_entity": scan.get("impersonated_entity"), "listing": scan["listing"],
        "syndicate": scan.get("syndicate"), "created_at": scan["created_at"],
        "interception_channel": req.interception_channel,
        "red_flags": [f["code"] for f in scan["red_flags"]],
        "citizen_explanation_en": scan["citizen_explanation_en"], "citizen_explanation_ar": scan["citizen_explanation_ar"],
    })
    if ev := police_state.record_scan(scan):
        await hub.broadcast("police.event", ev)
    if scan["risk_score"] >= settings.nextdns_min_score:
        nextdns_sync.kick()
    return scan
