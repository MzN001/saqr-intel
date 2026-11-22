"""Web Push scam alerts for iPhone (iOS 16.4+, Home Screen app) and Android (Chrome / Samsung Internet).

VAPID keys are generated once and kept in the data folder (never committed). Subscriptions that the
push service reports as gone (404/410) are deleted automatically.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from pywebpush import WebPushException, webpush

from .config import settings
from .db import db, iso
from .intel.registry import ENTITIES

log = logging.getLogger("saqr.push")

VAPID_SUB = "https://saqr-intel.vercel.app"  # contact claim required by push services (no personal data)
_ENTITY_AR = {e.name_en: e.name_ar for e in ENTITIES}


def _key_path() -> Path:
    base = Path(settings.database_path).parent if settings.database_path != ":memory:" else Path("data")
    base.mkdir(parents=True, exist_ok=True)
    return base / "vapid_private.pem"


_vapid: Vapid | None = None


def vapid() -> Vapid:
    global _vapid
    if _vapid is None:
        path = _key_path()
        if not path.exists():
            v = Vapid()
            v.generate_keys()
            v.save_key(str(path))
            log.info("Generated VAPID keys for scam alerts at %s", path)
        _vapid = Vapid.from_file(str(path))
    return _vapid


def public_key_b64() -> str:
    raw = vapid().public_key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


# -- subscriptions ----------------------------------------------------------------
async def save_subscription(sub: dict[str, Any], lang: str) -> None:
    await db.execute(
        "INSERT OR REPLACE INTO push_subscriptions (endpoint, sub_json, lang, created_at) VALUES (?,?,?,?)",
        (sub["endpoint"], json.dumps(sub), "ar" if lang == "ar" else "en", iso()))


async def delete_subscription(endpoint: str) -> None:
    await db.execute("DELETE FROM push_subscriptions WHERE endpoint=?", (endpoint,))


async def get_subscription(endpoint: str) -> dict[str, Any] | None:
    return await db.fetchone("SELECT * FROM push_subscriptions WHERE endpoint=?", (endpoint,))


async def count_subscriptions() -> int:
    row = await db.fetchone("SELECT COUNT(*) AS n FROM push_subscriptions")
    return int(row["n"]) if row else 0


# -- messages ---------------------------------------------------------------------
def alert_payload(domain: str, entity_en: str | None, lang: str, test: bool = False) -> dict[str, Any]:
    masked = domain.replace(".", "[.]")
    if lang == "ar":
        who = f"موقع {_ENTITY_AR.get(entity_en or '', entity_en)} المزيف" if entity_en else "موقع احتيالي"
        title = "🛑 صقر حظر موقعاً احتيالياً" + (" (تجربة)" if test else "")
        body = f"تم حظر {who} ({masked}) على هاتفك. لا تُدخل أبداً بيانات البطاقة أو رمز التحقق. اضغط للتفاصيل."
    else:
        who = f"fake {entity_en} website" if entity_en else "scam website"
        title = "🛑 SAQR blocked a scam website" + (" (test)" if test else "")
        body = f"A {who} ({masked}) was blocked on your phone. Never enter card or OTP details. Tap for details."
    return {"title": title, "body": body, "url": f"/citizen?alert={domain}", "tag": f"saqr-{domain}",
            "lang": lang, "ts": int(time.time() * 1000)}


def _send_sync(sub: dict[str, Any], payload: dict[str, Any]) -> int:
    resp = webpush(
        subscription_info=sub,
        data=json.dumps(payload, ensure_ascii=False),
        vapid_private_key=vapid(),
        vapid_claims={"sub": VAPID_SUB},
        ttl=600,
        headers={"Urgency": "high"},
    )
    return getattr(resp, "status_code", 201)


async def send(row: dict[str, Any], payload: dict[str, Any]) -> bool:
    try:
        await asyncio.to_thread(_send_sync, json.loads(row["sub_json"]), payload)
        return True
    except WebPushException as exc:
        status = getattr(exc.response, "status_code", None)
        if status in (404, 410):
            await delete_subscription(row["endpoint"])
            log.info("Removed expired push subscription")
        else:
            log.warning("Push failed (HTTP %s): %s", status, str(exc)[:200])
        return False


async def alert_all(domain: str, entity_en: str | None) -> int:
    rows = await db.fetchall("SELECT * FROM push_subscriptions")
    sent = 0
    for row in rows:
        if await send(row, alert_payload(domain, entity_en, row["lang"])):
            sent += 1
    if rows:
        log.info("Scam alert for %s sent to %d/%d phone(s)", domain, sent, len(rows))
    return sent
