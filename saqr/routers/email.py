"""POST /api/analyze-email — scan an email for fraud (email workstream B, frozen contract section 1).

* JSON only; files come as base64. The whole request body is capped at 4 MB while it is being read
  (a custom route class), before any JSON parsing.
* Own rate-limit bucket, separate from URL scans (one email scan can start up to 5 link scans and
  an AI call). EMAIL_RATE_LIMIT_PER_MINUTE (default: RATE_LIMIT_PER_MINUTE; 0 = off).
* The optional "llm" settings (the citizen's own AI key) are used for this one request: they are
  never stored, logged or echoed, and validation errors never repeat the submitted values.
* WebSocket: "citizen_report.received" at once, "email_scan.completed" when done.
"""
from __future__ import annotations

import base64
import binascii
import os
from typing import Any, Callable

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute

from ..config import settings
from ..db import iso
from ..email_pipeline import EmailEngineUnavailable, analyze_email
from ..intel.nextdns_sync import nextdns_sync
from ..pipeline import new_scan_id
from ..schemas import AnalyzeEmailRequest
from ..security import RateLimiter
from ..ws_hub import hub

MAX_BODY_BYTES = 4 * 1024 * 1024
TOO_BIG = "The email is too large (limit 4 MB). / الرسالة كبيرة جداً (الحد الأقصى 4 ميغابايت)."


def _safe_errors(errors: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Validation errors without the submitted values (they could contain the user's API key)."""
    return [{"loc": list(e.get("loc", ())), "msg": str(e.get("msg", ""))[:200], "type": e.get("type")}
            for e in errors[:20]]


class CappedJSONRoute(APIRoute):
    """Reads the request body with a hard size cap and returns value-free validation errors."""

    def get_route_handler(self) -> Callable:
        original = super().get_route_handler()

        async def handler(request: Request):
            length = request.headers.get("content-length", "")
            if length.isdigit() and int(length) > MAX_BODY_BYTES:
                raise HTTPException(413, TOO_BIG)
            body = bytearray()
            async for chunk in request.stream():
                body += chunk
                if len(body) > MAX_BODY_BYTES:
                    raise HTTPException(413, TOO_BIG)
            request._body = bytes(body)  # noqa: SLF001 — Starlette's documented body cache
            try:
                return await original(request)
            except RequestValidationError as exc:
                return JSONResponse(status_code=422, content={"detail": _safe_errors(exc.errors())})

        return handler


router = APIRouter(prefix="/api", tags=["Email analysis"], route_class=CappedJSONRoute)


def _per_minute() -> int:
    try:
        return int(os.getenv("EMAIL_RATE_LIMIT_PER_MINUTE", settings.rate_limit_per_minute))
    except ValueError:
        return settings.rate_limit_per_minute


def rate_limit_bucket(limiter: RateLimiter) -> Callable:
    """A rate-limit dependency with its own bucket (security.rate_limit shares one for URL scans)."""
    async def _dep(request: Request) -> None:
        client = request.client.host if request.client else "unknown"
        if not limiter.check(client):
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded — try again in a minute.")
    return _dep


email_limiter = RateLimiter(_per_minute())
email_rate_limit = rate_limit_bucket(email_limiter)


def _summary(r: dict[str, Any]) -> dict[str, Any]:
    top = sorted((f for f in r.get("red_flags", []) if f.get("points", 0) > 0), key=lambda f: -f["points"])
    return {"scan_id": r["scan_id"], "kind": "email", "target": r["target"], "risk_score": r["risk_score"],
            "verdict": r["verdict"], "channel": r.get("channel"), "interception_channel": r.get("interception_channel"),
            "impersonated_entity": r.get("impersonated_entity"), "created_at": r["created_at"],
            "top_flags": [f["code"] for f in top[:5]]}


def _preview_target(req: AnalyzeEmailRequest) -> str:
    """Best guess at "<sender> | <subject>" before the email is parsed (for the live feed)."""
    m = req.meta
    if m and (m.from_address or m.subject):
        return f"{(m.from_address or m.from_name or 'unknown sender')[:120]} | {m.subject[:80]}"
    return req.file_name[:120] if req.file_name else "(email)"


@router.post("/analyze-email", dependencies=[Depends(email_rate_limit)])
async def analyze_email_endpoint(req: AnalyzeEmailRequest):
    file_bytes = None
    if req.file_base64:
        data = req.file_base64.strip()
        if data.startswith("data:") and "," in data:
            data = data.split(",", 1)[1]  # a browser data: URL
        try:
            file_bytes = base64.b64decode(data + "=" * (-len(data) % 4), validate=False)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(422, "The attached file could not be read (bad base64).") from exc
        if len(file_bytes) > MAX_BODY_BYTES:
            raise HTTPException(413, TOO_BIG)

    scan_id = new_scan_id("EML")
    await hub.broadcast("citizen_report.received", {
        "scan_id": scan_id, "kind": "email", "target": _preview_target(req), "channel": req.channel or "email",
        "interception_channel": req.interception_channel, "received_at": iso()})
    try:
        result = await analyze_email(
            source=req.source, text=req.text, file_bytes=file_bytes, file_name=req.file_name, html=req.html,
            meta=req.meta.model_dump() if req.meta else None, channel=req.channel or "email",
            reporter_id=req.reporter_id, interception_channel=req.interception_channel, use_llm=req.use_llm,
            follow_links=req.follow_links, use_user_model=req.use_user_model,
            llm=req.llm.to_cfg() if req.llm else None, scan_id=scan_id)
    except ValueError as exc:
        await hub.broadcast("email_scan.failed", {"scan_id": scan_id, "error": str(exc)[:300]})
        raise HTTPException(422, str(exc)[:300]) from exc
    except EmailEngineUnavailable as exc:
        await hub.broadcast("email_scan.failed", {"scan_id": scan_id, "error": "unavailable"})
        raise HTTPException(503, str(exc)) from exc

    await hub.broadcast("email_scan.completed", _summary(result))
    if any((l.get("risk_score") or 0) >= settings.nextdns_min_score for l in result.get("links", [])):
        nextdns_sync.kick()  # a scam LINK (saved as its own URL scan) reaches phones' DNS shield fast
    delta = result.get("graph_delta") or {}
    if delta.get("new_nodes") or delta.get("new_edges"):
        await hub.broadcast("graph.updated", {"scan_id": scan_id, **delta})
    return result
