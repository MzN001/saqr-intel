"""Abu Dhabi Police Cyber-Patrol Command Center API (`/police` page).

GET  /api/police/state                 KPIs, clustered campaigns, last 25 interceptions, Maps pins
POST /api/police/log-x-alert           a citizen opened X to post a warning (public, rate limited)
POST /api/police/sync-telecom          publish a campaign's domain to the e& / du RPZ feed + NextDNS
POST /api/police/broadcast-warning     push an official bilingual warning to every open /citizen page
GET  /api/police/takedown/{campaign}   court / registrar takedown dossier (JSON) + the full evidence dossier
GET  /api/police/detections/{id}/dossier  evidence for a Proactive Hunter detection (lead time, triage reasons)
GET  /api/police/warning/latest        latest official warning (public; /citizen polls it)

Officer actions need the X-API-Key header when POLICE_API_KEY is set (open in the demo otherwise).
Every change is broadcast on /ws/live as a `police.*` event, which both /police and /citizen hear.
"""
from __future__ import annotations

import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from ..db import db, iso
from ..intel import ai_inspector, takedown as takedown_intel
from ..intel.domain_intel import analyze_lexical
from ..intel.nextdns_sync import nextdns_sync
from ..police_state import campaign_id_for, defang, police_state
from ..security import rate_limit, require_police
from ..seed_data import DEMO_INTEL
from ..ws_hub import hub
from .blocklist import _publishable

router = APIRouter(prefix="/api/police", tags=["Police Command Center"])


class XAlertLog(BaseModel):
    domain: str = Field(..., min_length=3, max_length=253)
    impersonated_entity: str | None = Field(None, max_length=120)


class TelecomSync(BaseModel):
    campaign_id: str | None = Field(None, max_length=40)
    domain: str = Field(..., min_length=3, max_length=253)


class OfficialWarning(BaseModel):
    title_en: str = Field(..., min_length=3, max_length=160)
    title_ar: str = Field(..., min_length=3, max_length=160)
    message_en: str = Field(..., min_length=3, max_length=1200)
    message_ar: str = Field(..., min_length=3, max_length=1200)
    domain: str | None = Field(None, max_length=253)


def _clean_domain(raw: str) -> str:
    d = raw.strip().lower().replace("[.]", ".")
    d = d.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return d[4:] if d.startswith("www.") else d


async def _evidence(scan_id: str | None, detection: dict | None = None) -> dict | None:
    """The full takedown dossier (WHOIS, DNS, TLS, redirect chain, hashes, notices) of a flagged scan."""
    scan = await db.get_scan(scan_id, with_screenshot=False) if scan_id else None
    if not scan or scan.get("verdict") == "SAFE":
        return None
    return await takedown_intel.build_dossier(scan, detection=detection)


@router.get("/state", dependencies=[Depends(require_police)])
async def state():
    snap = await police_state.snapshot()
    for det in snap.get("proactive_detections", []):  # "all blocked" must be measured, not assumed
        det["citizen_visits_blocked"] = 0
        if det.get("citizen_visits"):
            ctx = await takedown_intel.detection_context(detection_id=det["id"])
            det["citizen_visits_blocked"] = ctx["citizen_visits_blocked"] if ctx else 0
    return snap


@router.post("/log-x-alert", dependencies=[Depends(rate_limit)])
async def log_x_alert(body: XAlertLog):
    domain = _clean_domain(body.domain)
    if not domain or "." not in domain:
        raise HTTPException(422, "Not a domain")
    ev = police_state.log_x_alert(domain, body.impersonated_entity)
    await hub.broadcast("police.x_alert", {"event": ev, "x_alerts_dispatched": police_state.x_alerts})
    return {"ok": True, "x_alerts_dispatched": police_state.x_alerts, "campaign_id": ev["campaign_id"]}


@router.post("/sync-telecom", dependencies=[Depends(require_police)])
async def sync_telecom(body: TelecomSync):
    domain = _publishable(_clean_domain(body.domain))
    if not domain:
        raise HTTPException(422, "This domain can't be published (official / trusted site, IP or invalid name).")
    cid = body.campaign_id or campaign_id_for(domain)
    police_state.sync_telecom(cid, domain)
    nextdns_sync.kick()  # shielded phones block it within seconds
    data = {"campaign_id": cid, "domain": domain, "defanged_domain": defang(domain), "status": "SYNCED_TO_TELECOM_DNS",
            "rpz_record": f"{domain} CNAME .", "synced_at": iso()}
    await hub.broadcast("police.telecom_sync", data)
    return {"ok": True, **data}


@router.post("/broadcast-warning", dependencies=[Depends(require_police)])
async def broadcast_warning(body: OfficialWarning):
    w = police_state.add_warning({**body.model_dump(), "domain": _clean_domain(body.domain) if body.domain else None})
    await hub.broadcast("police.warning", w)
    return {"ok": True, "warning": w}


@router.get("/warning/latest")
async def latest_warning():
    return {"warning": police_state.warnings[0] if police_state.warnings else None}


@router.get("/takedown/{campaign_id}", dependencies=[Depends(require_police)])
async def takedown(campaign_id: str):
    camp = next((c for c in await police_state.campaigns() if c["campaign_id"] == campaign_id.upper()), None)
    if not camp:
        raise HTTPException(404, "Campaign not found")
    dom = camp["domain"]
    net = await police_state._net(dom)  # noqa: SLF001
    intel = DEMO_INTEL.get(dom, {})
    row = await db.fetchone("SELECT result_json FROM scans WHERE domain=? AND verdict != 'SAFE' "
                            "ORDER BY risk_score DESC, created_at DESC LIMIT 1", (dom,))
    flags: list[dict] = []
    if row:
        res = json.loads(row["result_json"])
        flags = [{"code": f["code"], "severity": f["severity"], "en": f["en"], "ar": f["ar"]}
                 for f in res.get("red_flags", []) if f.get("points", 0) > 0]
    if not flags:
        flags = [{"code": "BRAND_IMPERSONATION", "severity": "critical",
                  "en": f"Impersonates {camp['impersonated_entity'] or 'a UAE entity'} on an unofficial domain.",
                  "ar": "ينتحل صفة جهة إماراتية على نطاق غير رسمي."}]
    best = await db.fetchone("SELECT id FROM scans WHERE domain=? AND verdict != 'SAFE' "
                             "ORDER BY risk_score DESC, created_at DESC LIMIT 1", (dom,))
    evidence = await _evidence(best["id"] if best else None)
    ips = net.get("ip_addresses") or ([intel["ip"]] if intel.get("ip") else [])
    abuse = net.get("abuse_emails") or intel.get("abuse_emails") or []
    year = iso()[:4]
    ref = f"AMAN-{year}-{int(hashlib.sha1(dom.encode()).hexdigest()[:6], 16) % 1000000:06d}"
    return {
        "aman_ref_id": ref, "campaign_id": camp["campaign_id"], "issuing_unit": "Abu Dhabi Police — Cyber-Patrol",
        "issuing_unit_ar": "شرطة أبوظبي — الدوريات الإلكترونية",
        "target_domain": dom, "defanged_domain": camp["defanged_domain"],
        "impersonated_entity": camp["impersonated_entity"], "risk_score": camp["risk_score"],
        "ip_address": ips[0] if ips else None, "all_ip_addresses": ips,
        "asn": " ".join(x for x in [net.get("asn") or intel.get("asn"), net.get("asn_org") or intel.get("asn_org")] if x) or None,
        "registrar": net.get("registrar") or intel.get("registrar"),
        "registrar_abuse_email": abuse[0] if abuse else None, "all_abuse_contacts": abuse,
        "ssl_age": camp["ssl_age"], "channels": camp["channels"], "status": camp["status"],
        "red_flags": flags, "citizen_reports_count": camp["hit_count"], "last_seen": camp["last_seen"],
        "requested_actions": [
            "Suspend / place the domain on clientHold (registrar abuse obligations).",
            "Remove hosting and take down the phishing content (hosting provider abuse desk).",
            "Preserve WHOIS, hosting and payment logs for the Abu Dhabi Public Prosecution.",
        ],
        "generated_at": iso(),
        "scan_id": best["id"] if best else None,
        "evidence": evidence,
    }


@router.get("/detections/{detection_id}/dossier", dependencies=[Depends(require_police)])
async def detection_dossier(detection_id: int):
    """A Proactive Hunter detection: where and when SAQR found it, how many citizens met it since,
    the triage reasons (offline lexical rules + URL model, EN/AR) and, when it was fully scanned,
    the full evidence dossier. Simulated leads have no scan and say so."""
    det = await takedown_intel.detection_context(detection_id=detection_id)
    if not det:
        raise HTTPException(404, "Detection not found")
    try:
        lex = analyze_lexical(det["domain"])
        reasons = [{"code": f.code, "severity": f.severity, "points": f.points, "en": f.en, "ar": f.ar}
                   for f in [*lex.flags, *ai_inspector.intel_flags(lex)]]
    except ValueError:
        reasons = []
    evidence = await _evidence(det["scan_id"], det)
    note = None
    if not evidence:
        note = ("Simulated lead (HUNTER_MODE=simulated): no live WHOIS / DNS / TLS / page evidence exists."
                if det["simulated"] else "This lead has no flagged full scan yet; only the triage evidence is shown.")
    return {"detection": det, "triage_reasons": reasons, "evidence": evidence, "note": note, "generated_at": iso()}
