"""Personal email model ("email-v1") — the citizen teaches SAQR which emails are scams FOR THEM.

POST   /api/email-model/label          {reporter_id, scan_id, label: "scam"|"ham"}
GET    /api/email-model/{reporter_id}   -> download the model JSON (saqr-my-model.json)
PUT    /api/email-model/{reporter_id}   <- import a model JSON (merged into the stored one; ?mode=replace overwrites)
DELETE /api/email-model/{reporter_id}   -> erase it

reporter_id is a random id (>= 16 characters) the browser generates and keeps; it is the only key to
the model, so it is never stored in clear here (user_models.reporter_hash = SHA-256 of it).

Privacy: labelling uses the scan's stored "model_features" (hashed bucket numbers) and sender address
hash — the server never needs, and never keeps, the email's text. The model holds counts only.
"""
from __future__ import annotations

import asyncio
import hmac
import json
from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from ..db import db
from ..intel import user_model as um
from ..security import rate_limit

router = APIRouter(prefix="/api/email-model", tags=["Personal email model"])

REPORTER_ID_PATTERN = r"^[A-Za-z0-9_-]{16,128}$"
MAX_IMPORT_BYTES = 2 * 1024 * 1024  # 2 MB: a full 65,536-bucket model is ~1.5 MB
DOWNLOAD_NAME = "saqr-my-model.json"

# One lock for every read-modify-write of a model: two quick label taps must not lose one of them.
# (The backend runs a single worker; the critical section is a couple of small SQLite statements.)
_lock = asyncio.Lock()


def _err(status: int, en: str, ar: str) -> HTTPException:
    """Citizen-facing error: FastAPI clients read "detail" as one string, so carry both languages in it."""
    return HTTPException(status, f"{en} — {ar}")


ReporterId = Path(..., pattern=REPORTER_ID_PATTERN,
                  description="Random id kept in the citizen's browser (16-128 letters, digits, - or _).")


class LabelRequest(BaseModel):
    reporter_id: str = Field(..., pattern=REPORTER_ID_PATTERN)
    scan_id: str = Field(..., min_length=4, max_length=64)
    label: Literal["scam", "ham"]


def _summary(model: dict | None) -> dict:
    """What the UI shows: how many emails were labelled and whether the model can give an opinion yet."""
    if not model:
        return {"labels": 0, "scam": 0, "ham": 0, "available": False, "needed_per_class": um.MIN_DOCS}
    sd, hd = model["classes"]["scam"]["docs"], model["classes"]["ham"]["docs"]
    return {"labels": sd + hd, "scam": sd, "ham": hd, "available": sd >= um.MIN_DOCS and hd >= um.MIN_DOCS,
            "needed_per_class": um.MIN_DOCS}


def _stored_reporter(row: dict, result: dict) -> str:
    """The reporter saved with a scan: the scans.reporter column (db.save_scan writes scan["reporter"])."""
    return str(row.get("reporter") or result.get("reporter") or result.get("reporter_id") or "")


def _owns(stored: str, reporter_id: str) -> bool:
    """True when the scan was made by this browser. The pipeline may store the raw reporter_id or, for more
    privacy, user_model.reporter_key(reporter_id); both are accepted (constant-time comparison)."""
    if not stored:
        return False
    s = stored.encode()
    return hmac.compare_digest(s, reporter_id.encode()) or hmac.compare_digest(s, um.reporter_key(reporter_id).encode())


@router.post("/label", dependencies=[Depends(rate_limit)])
async def label_scan(req: LabelRequest):
    """Teach the model one email. Idempotent per scan: labelling the same scan again REPLACES its label."""
    row = await db.fetchone("SELECT kind, reporter, result_json FROM scans WHERE id=?", (req.scan_id,))
    if not row:
        raise _err(404, "Scan not found.", "لم يتم العثور على الفحص.")
    if row["kind"] != "email":
        raise _err(422, "Only email scans can be used to teach your personal filter.",
                   "يمكن استخدام فحوصات البريد الإلكتروني فقط لتعليم الفلتر الشخصي.")
    result = json.loads(row["result_json"] or "{}")
    stored = _stored_reporter(row, result)
    if not _owns(stored, req.reporter_id):
        raise _err(403, "This email was checked on another device, so it cannot be labelled here.",
                   "تم فحص هذه الرسالة على جهاز آخر، لذلك لا يمكن تصنيفها هنا.")
    feats = um.clean_features(result.get("model_features") or [])
    if not feats:
        raise _err(422, "This scan has no learning data. Please check the email again, then label it.",
                   "لا يحتوي هذا الفحص على بيانات للتعلّم. يرجى فحص الرسالة مرة أخرى ثم تصنيفها.")
    sender = (((result.get("email") or {}).get("from") or {}).get("address")) or ""

    async with _lock:
        model, labelled = await um.load_record(req.reporter_id)
        model = model or um.new_model()
        previous = labelled.get(req.scan_id)
        changed = previous != req.label
        if changed:
            if previous in ("scam", "ham"):
                um.untrain(model, feats, previous, sender)
            um.train(model, feats, req.label, sender)
            labelled.pop(req.scan_id, None)
            labelled[req.scan_id] = req.label  # re-insert: newest last (oldest are dropped first)
            await um.save_record(req.reporter_id, model, labelled)
    return {"ok": True, "scan_id": req.scan_id, "label": req.label, "previous": previous, "changed": changed,
            **_summary(model)}


@router.get("/{reporter_id}", dependencies=[Depends(rate_limit)])
async def download_model(reporter_id: str = ReporterId):
    model = await um.load(reporter_id)
    if not model:
        raise _err(404, "You have not labelled any emails yet, so there is no personal model to download.",
                   "لم تقم بتصنيف أي رسائل بعد، لذلك لا يوجد نموذج شخصي للتنزيل.")
    return JSONResponse(model, headers={"Content-Disposition": f'attachment; filename="{DOWNLOAD_NAME}"',
                                        "Cache-Control": "no-store"})


async def _read_capped(request: Request) -> bytes:
    """The request body, refusing anything over MAX_IMPORT_BYTES without reading it all into memory."""
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_IMPORT_BYTES:
        raise _err(413, "The model file is too big (2 MB maximum).", "ملف النموذج كبير جداً (الحد الأقصى 2 ميغابايت).")
    chunks, size = [], 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_IMPORT_BYTES:
            raise _err(413, "The model file is too big (2 MB maximum).", "ملف النموذج كبير جداً (الحد الأقصى 2 ميغابايت).")
        chunks.append(chunk)
    return b"".join(chunks)


@router.put("/{reporter_id}", dependencies=[Depends(rate_limit)])
async def import_model(request: Request, reporter_id: str = ReporterId,
                       mode: Literal["merge", "replace"] = Query("merge")):
    """Import a downloaded model (e.g. from another browser). Default: ADD its counts to the stored model."""
    body = await _read_capped(request)
    try:
        incoming = um.validate_model(json.loads(body.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):  # RecursionError: "[[[[..." bombs
        raise _err(422, "This file is not a valid Saqr model (it is not JSON).",
                   "هذا الملف ليس نموذج صقر صالحاً (ليس بصيغة JSON).") from None
    except ValueError as exc:
        raise _err(422, f"This file is not a valid Saqr model: {exc}",
                   "هذا الملف ليس نموذج صقر صالحاً.") from None

    async with _lock:
        stored, labelled = await um.load_record(reporter_id)
        if mode == "replace" or not stored:
            # A replaced model no longer contains the earlier labels, so forget which scans they came from.
            model, labelled = incoming, {}
        else:
            model = um.merge(stored, incoming)
            try:  # the sum must stay a file this server (and the extension) can import again
                um.validate_model(model)
            except ValueError:
                raise _err(422, "Your personal filter would become too big after adding this file.",
                           "سيصبح الفلتر الشخصي كبيراً جداً بعد إضافة هذا الملف.") from None
        await um.save_record(reporter_id, model, labelled)
    return {"ok": True, "mode": mode, **_summary(model)}


@router.delete("/{reporter_id}", dependencies=[Depends(rate_limit)])
async def erase_model(reporter_id: str = ReporterId):
    async with _lock:
        deleted = await um.delete_record(reporter_id)
    return {"ok": True, "deleted": deleted}
