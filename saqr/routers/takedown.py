"""POST /api/generate-takedown/{scan_id}  &  GET /api/awareness-alert  (Module 5)."""
from __future__ import annotations

import json

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse

from ..db import db
from ..intel import awareness, takedown
from ..schemas import TakedownRequest
from ..security import require_police
from ..police_state import police_state
from ..ws_hub import hub

router = APIRouter(prefix="/api", tags=["Takedown & awareness"], dependencies=[Depends(require_police)])


@router.post("/generate-takedown/{scan_id}")
async def generate_takedown(scan_id: str, body: TakedownRequest | None = Body(None),
                            format: str = Query("json", pattern="^(json|markdown)$")):  # noqa: A002
    scan = await db.get_scan(scan_id, with_screenshot=False)
    if not scan:
        raise HTTPException(404, "Scan not found")
    if scan["verdict"] == "SAFE":
        raise HTTPException(409, "Scan verdict is SAFE — takedown not warranted")
    dossier = await takedown.build_dossier(scan, officer=body.officer_id if body else None)
    await hub.broadcast("takedown.generated", {
        "dossier_id": dossier["dossier_id"], "case_reference": dossier["case_reference"], "scan_id": scan_id,
        "target": dossier["summary"]["target"], "syndicate": (dossier.get("syndicate") or {}).get("name")})
    if format == "markdown":
        return PlainTextResponse(takedown.dossier_markdown(dossier), media_type="text/markdown")
    return dossier


@router.get("/dossiers/{dossier_id}")
async def get_dossier(dossier_id: str, format: str = Query("json", pattern="^(json|markdown)$")):  # noqa: A002
    row = await db.fetchone("SELECT dossier_json FROM dossiers WHERE id=?", (dossier_id,))
    if not row:
        raise HTTPException(404, "Dossier not found")
    d = json.loads(row["dossier_json"])
    return PlainTextResponse(takedown.dossier_markdown(d), media_type="text/markdown") if format == "markdown" else d


@router.get("/awareness-alert")
async def awareness_alert(hours: int = Query(72, ge=1, le=720), entity: str | None = None, use_llm: bool = True):
    """Detect the trending scam wave and draft a bilingual AD Police public warning."""
    alert = await awareness.generate_alert(hours, entity, use_llm)
    alert["official_police_warning"] = police_state.warnings[0] if police_state.warnings else None
    if alert.get("status") == "active_wave":
        await hub.broadcast("awareness.drafted", {"entity": alert["trending_entity"], "severity": alert["severity"],
                                                  "title_en": alert["title_en"], "title_ar": alert["title_ar"]})
    return alert
