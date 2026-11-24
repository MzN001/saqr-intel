"""POST /api/analyze-url  (Modules 1 + 3) and scan history."""
from __future__ import annotations

import base64

from fastapi import APIRouter, Depends, HTTPException, Query, Response

from ..config import settings
from ..db import db, iso
from ..message_pipeline import analyze_message
from ..intel.nextdns_sync import nextdns_sync
from ..pipeline import analyze_url, extract_url, new_scan_id
from ..police_state import police_state
from ..schemas import AnalyzeMessageRequest, AnalyzeURLRequest
from ..security import rate_limit, require_police
from ..ws_hub import hub

router = APIRouter(prefix="/api", tags=["URL analysis"])


def _summary(r: dict) -> dict:
    ti = r.get("technical_indicators", {})
    return {
        "scan_id": r["scan_id"], "kind": r["kind"], "domain": r.get("domain"), "verdict": r["verdict"],
        "risk_score": r["risk_score"], "impersonated_entity": r.get("impersonated_entity"),
        "channel": r.get("channel"), "created_at": r["created_at"],
        "ip_addresses": ti.get("ip_addresses", []), "harvested_fields": ti.get("harvested_fields", []),
        "syndicate": r.get("syndicate"), "citizen_explanation_en": r.get("citizen_explanation_en"),
        "citizen_explanation_ar": r.get("citizen_explanation_ar"), "engine": r.get("analyzer", {}).get("engine"),
        "has_screenshot": bool(r.get("screenshot_base64")),
        "interception_channel": r.get("interception_channel"),
    }


@router.post("/analyze-url", dependencies=[Depends(rate_limit)])
async def analyze_url_endpoint(req: AnalyzeURLRequest):
    url = req.url or extract_url(req.message_text or "")
    if not url:
        raise HTTPException(422, "No URL found in message_text")
    scan_id = new_scan_id()
    # 1) Instant push to the command centre — before any slow analysis
    await hub.broadcast("citizen_report.received", {
        "scan_id": scan_id, "kind": "url", "target": url, "channel": req.channel,
        "interception_channel": req.interception_channel, "received_at": iso()})
    try:
        result = await analyze_url(url, scan_id=scan_id, channel=req.channel, reporter=req.reporter_id,
                                   message_text=req.message_text, run_sandbox=req.run_sandbox,
                                   profile=req.device_profile, use_llm=req.use_llm,
                                   interception_channel=req.interception_channel)
    except ValueError as exc:
        await hub.broadcast("url_scan.failed", {"scan_id": scan_id, "error": str(exc)})
        raise HTTPException(422, str(exc)) from exc
    # 2) Completed verdict + graph delta
    await hub.broadcast("url_scan.completed", _summary(result))
    if ev := police_state.record_scan(result):
        await hub.broadcast("police.event", ev)
    if result["risk_score"] >= settings.nextdns_min_score:
        nextdns_sync.kick()  # push to phones' DNS shield within seconds
    if result.get("graph_delta", {}).get("new_nodes") or result.get("graph_delta", {}).get("new_edges"):
        await hub.broadcast("graph.updated", {"scan_id": scan_id, **result["graph_delta"]})
    if not req.include_screenshot:
        result.pop("screenshot_base64", None)
    return result


def _message_summary(r: dict) -> dict:
    """WebSocket summary of a message scan: police-only topic, and never the text, excerpt or numbers."""
    top = sorted((f for f in r.get("red_flags", []) if f.get("points", 0) > 0), key=lambda f: -f["points"])
    return {"scan_id": r["scan_id"], "kind": "message", "target": r["target"], "risk_score": r["risk_score"],
            "verdict": r["verdict"], "channel": r.get("channel"), "interception_channel": r.get("interception_channel"),
            "impersonated_entity": r.get("impersonated_entity"), "created_at": r["created_at"],
            "top_flags": [f["code"] for f in top[:5]],
            "link_domains": sorted({l["domain"] for l in r.get("links", [])
                                    if l.get("verdict") in ("SUSPICIOUS", "HIGH-RISK SCAM")})}


@router.post("/analyze-message", dependencies=[Depends(rate_limit)])
async def analyze_message_endpoint(req: AnalyzeMessageRequest):
    """Scan a pasted SMS / WhatsApp message: its links, phone numbers, sender and wording."""
    scan_id = new_scan_id("MSG")
    await hub.broadcast("citizen_report.received", {
        "scan_id": scan_id, "kind": "message", "target": "text message", "channel": req.channel,
        "interception_channel": req.interception_channel, "received_at": iso()})
    try:
        result = await analyze_message(req.text, sender=req.sender, channel=req.channel, reporter=req.reporter_id,
                                       interception_channel=req.interception_channel, use_llm=req.use_llm,
                                       follow_links=req.follow_links, scan_id=scan_id)
    except ValueError as exc:
        await hub.broadcast("message_scan.failed", {"scan_id": scan_id, "error": str(exc)[:300]})
        raise HTTPException(422, str(exc)[:300]) from exc
    await hub.broadcast("message_scan.completed", _message_summary(result))
    if ev := police_state.record_scan(result):
        await hub.broadcast("police.event", ev)
    if any((l.get("risk_score") or 0) >= settings.nextdns_min_score for l in result.get("links", [])):
        nextdns_sync.kick()  # a scam LINK (saved as its own URL scan) reaches phones' DNS shield fast
    delta = result.get("graph_delta") or {}
    if delta.get("new_nodes") or delta.get("new_edges"):
        await hub.broadcast("graph.updated", {"scan_id": scan_id, **delta})
    return result


@router.get("/scans", dependencies=[Depends(require_police)])
async def list_scans(limit: int = Query(50, ge=1, le=500), kind: str | None = Query(None, pattern="^(url|maps|email|message)$")):
    return {"scans": await db.list_scans(limit, kind)}


@router.get("/scans/{scan_id}", dependencies=[Depends(require_police)])
async def get_scan(scan_id: str, include_screenshot: bool = False):
    scan = await db.get_scan(scan_id, with_screenshot=include_screenshot)
    if not scan:
        raise HTTPException(404, "Scan not found")
    return scan


@router.get("/scans/{scan_id}/screenshot", dependencies=[Depends(require_police)],
            responses={200: {"content": {"image/jpeg": {}}}})
async def get_screenshot(scan_id: str):
    scan = await db.get_scan(scan_id)
    if not scan or not scan.get("screenshot_base64"):
        raise HTTPException(404, "No screenshot for this scan")
    return Response(base64.b64decode(scan["screenshot_base64"]), media_type="image/jpeg")
