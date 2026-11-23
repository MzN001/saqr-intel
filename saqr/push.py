"""Web Push scam alerts for iPhone (iOS 16.4+, Home Screen app) and Android (Chrome / Samsung Internet).

VAPID keys are generated once and kept in the data folder (never committed). Subscriptions that the
push service reports as gone (404/410) are deleted automatically.
"""
from __future__ import annotations

import asyncio
import base64
import json
import logging
import os
import time
from pathlib import Path
from typing import Any

import requests
import requests.adapters
from cryptography.hazmat.primitives import serialization
from py_vapid import Vapid
from pywebpush import WebPushException, webpush

from .config import settings
from .db import db, iso
from .intel.registry import ALL_BRANDS

log = logging.getLogger("saqr.push")

VAPID_SUB = "https://saqr-intel.vercel.app"  # contact claim required by push services (no personal data)
_ENTITY_AR = {e.name_en: e.name_ar for e in ALL_BRANDS}


def _key_path() -> Path:
    base = Path(settings.database_path).parent if settings.database_path != ":memory:" else Path("data")
    base.mkdir(parents=True, exist_ok=True)
    return base / "vapid_private.pem"


_vapid: Vapid | None = None


def vapid() -> Vapid:
    """The push signing key. On hosts with a wiped disk (Render free tier) set VAPID_PRIVATE_KEY to the
    PEM text (newlines may be written as \\n), otherwise phones' alert subscriptions break on restart."""
    global _vapid
    if _vapid is None and os.getenv("VAPID_PRIVATE_KEY", "").strip():
        pem = os.environ["VAPID_PRIVATE_KEY"].strip().replace("\\n", "\n")
        _vapid = Vapid.from_pem(pem.encode())
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


# Keep-alive HTTPS session to the push services (Apple / Google / Mozilla): reusing the TLS
# connection cuts ~0.7 s off alerts sent close together. A stale connection is retried fresh.
def _new_session() -> requests.Session:
    s = requests.Session()
    s.mount("https://", requests.adapters.HTTPAdapter(pool_connections=4, pool_maxsize=8))
    return s


_session = _new_session()
last_error: str | None = None  # last failed delivery, shown in /api/nextdns-status (no secrets)


def _note_error(text: str) -> None:
    global last_error
    last_error = f"{iso()} {text}"


def _send_sync(sub: dict[str, Any], payload: dict[str, Any], session: requests.Session) -> int:
    resp = webpush(
        subscription_info=sub,
        data=json.dumps(payload, ensure_ascii=False),
        vapid_private_key=vapid(),
        vapid_claims={"sub": VAPID_SUB},
        ttl=600,
        timeout=6,
        headers={"Urgency": "high"},
        requests_session=session,
    )
    return getattr(resp, "status_code", 201)


async def send(row: dict[str, Any], payload: dict[str, Any]) -> bool:
    """Deliver one alert. Never raises: returns False if the push service refused or was unreachable."""
    global _session
    sub = json.loads(row["sub_json"])
    for attempt in (1, 2):
        try:
            await asyncio.to_thread(_send_sync, sub, payload, _session)
            return True
        except WebPushException as exc:
            status = getattr(exc.response, "status_code", None)
            if status in (404, 410):
                await delete_subscription(row["endpoint"])
                log.info("Removed expired push subscription")
                return False
            log.warning("Push failed (HTTP %s): %s", status, str(exc)[:200])
            _note_error(f"push service HTTP {status}")
        except requests.RequestException as exc:  # stale/broken connection: retry once on a fresh one
            log.info("Push connection problem (%s), retrying fresh", type(exc).__name__)
            _note_error(f"connection: {type(exc).__name__}")
        except Exception as exc:  # noqa: BLE001
            log.exception("Unexpected push error")
            _note_error(f"unexpected: {type(exc).__name__}")
            return False
        if attempt == 1:
            _session.close()
            _session = _new_session()
    return False


async def alert_all(domain: str, entity_en: str | None) -> int:
    rows = await db.fetchall("SELECT * FROM push_subscriptions")
    results = await asyncio.gather(*(send(row, alert_payload(domain, entity_en, row["lang"])) for row in rows))
    sent = sum(1 for ok in results if ok)
    if rows:
        log.info("Scam alert for %s sent to %d/%d phone(s)", domain, sent, len(rows))
    return sent
