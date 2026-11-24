"""Scam-alert push notifications + the verdict a notification opens.

GET  /api/push/vapid-public-key
POST /api/push/subscribe     {subscription, lang}
POST /api/push/unsubscribe   {endpoint}
POST /api/push/test          {endpoint}           -> sends a sample alert to that phone only
GET  /api/alerts/verdict?domain=...                -> latest high-risk verdict for a blocked domain
"""
from __future__ import annotations

import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from .. import push
from ..db import db
from ..security import rate_limit

router = APIRouter(prefix="/api", tags=["Scam alerts"])


class SubKeys(BaseModel):
    p256dh: str = Field(..., max_length=200)
    auth: str = Field(..., max_length=100)


class Subscription(BaseModel):
    endpoint: str = Field(..., max_length=1000, pattern=r"^https://")
    keys: SubKeys
    expirationTime: float | None = None


class SubscribeRequest(BaseModel):
    subscription: Subscription
    lang: Literal["en", "ar"] = "en"
    device: str | None = Field(None, pattern=r"^[a-z0-9]{6,24}$", description="This phone's Saqr device tag.")


class EndpointRequest(BaseModel):
    endpoint: str = Field(..., max_length=1000)


@router.get("/push/vapid-public-key")
async def vapid_public_key():
    return {"publicKey": push.public_key_b64()}


@router.post("/push/subscribe", dependencies=[Depends(rate_limit)])
async def subscribe(req: SubscribeRequest):
    await push.save_subscription(req.subscription.model_dump(exclude_none=True), req.lang, req.device)
    return {"ok": True, "subscribers": await push.count_subscriptions()}


@router.post("/push/unsubscribe")
async def unsubscribe(req: EndpointRequest):
    await push.delete_subscription(req.endpoint)
    return {"ok": True}


@router.post("/push/test", dependencies=[Depends(rate_limit)])
async def test_alert(req: EndpointRequest):
    row = await push.get_subscription(req.endpoint)
    if not row:
        raise HTTPException(404, "This phone is not subscribed to Saqr alerts yet.")
    ok = await push.send(row, push.alert_payload("tamm-smart-pay.net", "TAMM Abu Dhabi", row["lang"], test=True))
    if not ok:
        raise HTTPException(502, "The phone's push service did not accept the alert. Try turning alerts off and on.")
    return {"ok": True}


@router.get("/alerts/verdict")
async def alert_verdict(domain: str = Query(..., min_length=3, max_length=253)):
    row = await db.fetchone(
        "SELECT result_json FROM scans WHERE domain=? AND verdict != 'SAFE' ORDER BY risk_score DESC, created_at DESC LIMIT 1",
        (domain.strip().lower(),))
    if not row:
        raise HTTPException(404, "No Saqr verdict for this domain.")
    result = json.loads(row["result_json"])
    result.pop("screenshot_base64", None)
    return result
