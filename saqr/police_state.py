"""Live state of the Abu Dhabi Police Cyber-Patrol Command Center (`/police`).

Everything is kept in memory (Render free tier: no persistent disk, no extra services) and is
pre-seeded with realistic Abu Dhabi threat data so the dashboard looks active on a cold boot.
Every citizen interception (`/api/analyze-url`, `/api/scan-maps`, X alerts, browser extension)
updates it, and officer actions (telecom sync, official warning) change campaign status.

Campaigns are the citizen alerts clustered by domain; their hit counts, channels and hosting data
come from the scans database plus the seeded intelligence.
"""
from __future__ import annotations

import hashlib
import itertools
import json
import secrets
import time
from collections import Counter, deque
from datetime import timedelta
from typing import Any

from .db import db, iso, utcnow
from .seed_data import CITIZEN_REPORTS, DEMO_INTEL, MAP_PINS

CHANNELS = ("AUTO_TELECOM_DNS", "AUTO_SMS_GUARD", "CITIZEN_MANUAL_CHECK", "MOBILE_OS_SHARE_SHEET",
            "PC_BROWSER_EXTENSION", "X_COMMUNITY_ALERT")
_CHANNEL_OF = {"sms": "AUTO_SMS_GUARD", "whatsapp": "MOBILE_OS_SHARE_SHEET", "email": "CITIZEN_MANUAL_CHECK",
               "maps": "CITIZEN_MANUAL_CHECK", "web": "CITIZEN_MANUAL_CHECK"}
ENTITY_OF_DOMAIN = {
    "adpolice-fines-ae.info": "Abu Dhabi Police", "tamm-smart-pay.net": "TAMM Abu Dhabi",
    "emiratespost-track-uae.com": "Emirates Post", "fab-secure-update.top": "First Abu Dhabi Bank (FAB)",
    "adcb-card-verify.xyz": "ADCB", "uaepass-login-verify2290.xyz": "UAE PASS", "du-prize-winner.top": "du",
}

_SEQ = itertools.count(1)

# Demo baselines: "today" at the moment the backend booted (demo numbers, not real statistics).
# The KPIs add the live counts on top; /api/police/state also returns both parts separately
# (`demo_baseline`, `live_counts`) so the dashboard can say how much of each figure is real.
BASE_PROTECTED = 1284
BASE_X_ALERTS = 37


def defang(domain: str | None) -> str:
    return (domain or "").replace(".", "[.]")


def campaign_id_for(domain: str) -> str:
    return "CMP-" + hashlib.sha1(domain.lower().encode()).hexdigest()[:8].upper()


class PoliceState:
    def __init__(self) -> None:
        self.protected = BASE_PROTECTED
        self.x_alerts = BASE_X_ALERTS
        self.events: deque[dict[str, Any]] = deque(maxlen=25)
        self.status: dict[str, str] = {}  # campaign_id -> ACTIVE | SYNCED_TO_TELECOM_DNS | COMMUNITY_FLAGGED_X
        self.extra_hits: Counter[str] = Counter()  # domain -> X alerts etc. not stored as scans
        self.telecom_synced: dict[str, str] = {}  # domain -> synced_at (published in /api/dns-blocklist)
        self.warnings: deque[dict[str, Any]] = deque(maxlen=10)
        self.live_pins: dict[str, dict[str, Any]] = {}
        self._seeded = False

    # -- seeding -------------------------------------------------------------------------------
    def seed(self) -> None:
        """Pre-load the interception stream with realistic events (idempotent)."""
        if self._seeded:
            return
        self._seeded = True
        now = utcnow()
        demo = [
            ("AUTO_TELECOM_DNS", "tamm-smart-pay.net", 96, 3), ("AUTO_SMS_GUARD", "adpolice-fines-ae.info", 98, 5),
            ("PC_BROWSER_EXTENSION", "emiratespost-track-uae.com", 91, 8),
            ("CITIZEN_MANUAL_CHECK", "tamm-smart-pay.net", 96, 11),
            ("MOBILE_OS_SHARE_SHEET", "adcb-card-verify.xyz", 88, 14),
            ("X_COMMUNITY_ALERT", "adpolice-fines-ae.info", 98, 19), ("AUTO_TELECOM_DNS", "fab-secure-update.top", 90, 23),
            ("AUTO_SMS_GUARD", "emiratespost-track-uae.com", 91, 31), ("AUTO_TELECOM_DNS", "uaepass-login-verify2290.xyz", 93, 38),
            ("PC_BROWSER_EXTENSION", "du-prize-winner.top", 84, 46), ("AUTO_SMS_GUARD", "tamm-smart-pay.net", 96, 52),
            ("CITIZEN_MANUAL_CHECK", "adpolice-fines-ae.info", 98, 64),
        ]
        for ch, dom, score, mins in reversed(demo):
            self.events.appendleft(self._event(ch, dom, score, "HIGH-RISK SCAM", ENTITY_OF_DOMAIN.get(dom),
                                               iso(now - timedelta(minutes=mins)), seeded=True))

    # -- recording ------------------------------------------------------------------------------
    def _event(self, channel: str, domain: str | None, score: int, verdict: str, entity: str | None, ts: str,
               kind: str = "url", seeded: bool = False, title: str | None = None) -> dict[str, Any]:
        return {"id": f"EV-{next(_SEQ):06d}-{secrets.token_hex(2)}",  # unique, even within one millisecond
                "ts": ts, "channel": channel if channel in CHANNELS else "CITIZEN_MANUAL_CHECK", "kind": kind,
                "domain": domain, "defanged_domain": defang(domain), "risk_score": int(score), "verdict": verdict,
                "impersonated_entity": entity, "campaign_id": campaign_id_for(domain) if domain else None,
                "title": title, "seeded": seeded}

    def record_scan(self, result: dict[str, Any]) -> dict[str, Any] | None:
        """A citizen interception finished (URL or Maps). Returns the stream event, or None if SAFE."""
        if result.get("verdict") == "SAFE":
            return None
        self.protected += 1
        ch = result.get("interception_channel") or _CHANNEL_OF.get(result.get("channel") or "", "CITIZEN_MANUAL_CHECK")
        listing = result.get("listing") or {}
        domain = result.get("domain") or listing.get("website_domain")
        ev = self._event(ch, domain, result.get("risk_score", 0), result["verdict"], result.get("impersonated_entity"),
                         result.get("created_at") or iso(), kind=result.get("kind", "url"), title=listing.get("name"))
        self.events.appendleft(ev)
        if listing.get("lat") is not None and listing.get("lng") is not None:
            self.live_pins[listing.get("pin_id") or ev["id"]] = {
                "id": listing.get("pin_id") or ev["id"], "lat": float(listing["lat"]), "lng": float(listing["lng"]),
                "title": listing.get("name") or "Reported listing", "type": "SPOOFED", "domain": domain,
                "registry_note": (result.get("citizen_explanation_en") or "Failed official registry verification.")[:400],
                "risk_score": result.get("risk_score")}
        return ev

    def log_x_alert(self, domain: str, entity: str | None) -> dict[str, Any]:
        self.x_alerts += 1
        self.extra_hits[domain] += 1
        cid = campaign_id_for(domain)
        if self.status.get(cid) != "SYNCED_TO_TELECOM_DNS":  # a telecom block outranks a community flag
            self.status[cid] = "COMMUNITY_FLAGGED_X"
        ev = self._event("X_COMMUNITY_ALERT", domain, 90, "HIGH-RISK SCAM", entity, iso())
        self.events.appendleft(ev)
        return ev

    def sync_telecom(self, campaign_id: str, domain: str) -> None:
        self.status[campaign_id] = "SYNCED_TO_TELECOM_DNS"
        self.telecom_synced[domain] = iso()

    def add_warning(self, w: dict[str, Any]) -> dict[str, Any]:
        warning = {"id": f"ADP-WARN-{len(self.warnings) + 1:03d}-{int(time.time()) % 100000:05d}", "issued_at": iso(),
                   "issuer_en": "Abu Dhabi Police — Cyber-Patrol", "issuer_ar": "شرطة أبوظبي — الدوريات الإلكترونية",
                   "verified": True, **w, "defanged_domain": defang(w.get("domain"))}
        self.warnings.appendleft(warning)
        return warning

    # -- views ----------------------------------------------------------------------------------
    async def campaigns(self) -> list[dict[str, Any]]:
        rows = await db.fetchall(
            "SELECT domain, COUNT(*) n, MAX(risk_score) score, MAX(created_at) last_seen, "
            "MAX(impersonated_entity) entity, GROUP_CONCAT(DISTINCT channel) chans "
            "FROM scans WHERE verdict != 'SAFE' AND domain IS NOT NULL AND domain != '' GROUP BY domain")
        found: dict[str, dict[str, Any]] = {}
        for r in rows:
            found[r["domain"]] = {"n": r["n"], "score": r["score"], "last_seen": r["last_seen"], "entity": r["entity"],
                                  "chans": {c for c in (r["chans"] or "").split(",") if c}}
        reports = Counter(c["target"] for c in CITIZEN_REPORTS)
        seeded_ev = Counter(e["domain"] for e in self.events if e["seeded"])
        domains = set(found) | set(DEMO_INTEL) | set(self.telecom_synced) | set(self.extra_hits)
        out = []
        for dom in domains:
            f = found.get(dom, {})
            intel = DEMO_INTEL.get(dom, {})
            net = await self._net(dom)
            chans = set(f.get("chans", set())) | {e["channel"] for e in self.events if e["domain"] == dom}
            chans = sorted(_CHANNEL_OF.get(c, c) for c in chans if c)
            cid = campaign_id_for(dom)
            ssl = net.get("cert_age_hours", intel.get("cert_age_hours"))
            hits = f.get("n", 0) + reports.get(dom, 0) + seeded_ev.get(dom, 0) + self.extra_hits.get(dom, 0)
            out.append({
                "campaign_id": cid, "domain": dom, "defanged_domain": defang(dom),
                "impersonated_entity": f.get("entity") or ENTITY_OF_DOMAIN.get(dom),
                "risk_score": int(f.get("score") or (100 if intel else 70)), "hit_count": max(1, hits),
                "channels": sorted(set(chans)),
                "ip_asn": " · ".join(x for x in [(net.get("ip_addresses") or [intel.get("ip")])[0] if (net.get("ip_addresses") or intel.get("ip")) else None,
                                                 net.get("asn") or intel.get("asn"), net.get("asn_org") or intel.get("asn_org")] if x) or "unknown",
                "ssl_age": f"{ssl:.0f} h" if isinstance(ssl, (int, float)) else "unknown",
                "status": self.status.get(cid, "ACTIVE"),
                "last_seen": f.get("last_seen") or max((e["ts"] for e in self.events if e["domain"] == dom), default=iso()),
                "syndicate": intel.get("syndicate"),
            })
        out.sort(key=lambda c: (-c["risk_score"] * c["hit_count"], -c["hit_count"]))
        return out

    async def _net(self, domain: str) -> dict[str, Any]:
        row = await db.fetchone(
            "SELECT result_json FROM scans WHERE domain=? AND verdict != 'SAFE' ORDER BY created_at DESC LIMIT 1", (domain,))
        if not row:
            return {}
        try:
            return json.loads(row["result_json"]).get("technical_indicators") or {}
        except (ValueError, TypeError):
            return {}

    def map_pins(self) -> list[dict[str, Any]]:
        pins = [
            {"id": "pin:mussafah-m37-emiratespost", "lat": 24.3712, "lng": 54.5115,
             "title": "Emirates Post Customer Center - Mussafah M-37", "type": "SPOOFED",
             "domain": "emiratespost-track-uae.com",
             "registry_note": "Not an Emirates Post branch: the pin sits on a residential plot in Mussafah M-37, its "
                              "website emiratespost-track-uae.com is not emiratespost.ae, and the mobile number is "
                              "shared with 2 other fake pins (Sand Viper network)."},
            {"id": "pin:almaryah-verified", "lat": 24.5015, "lng": 54.3896,
             "title": "Al Maryah Island — verified government service point", "type": "VERIFIED",
             "domain": "tamm.abudhabi",
             "registry_note": "Matches the official registry: official .abudhabi / .gov.ae website and landline. (Demo registry data.)"},
            {"id": "pin:corniche-verified", "lat": 24.4672, "lng": 54.3210,
             "title": "Abu Dhabi Corniche — verified Abu Dhabi Police service point", "type": "VERIFIED",
             "domain": "adpolice.gov.ae",
             "registry_note": "Matches the official registry: adpolice.gov.ae and official numbers 999 / 8002626. (Demo registry data.)"},
        ]
        for p in MAP_PINS:
            pins.append({"id": p["id"], "lat": p["lat"], "lng": p["lng"], "title": p["name"], "type": "SPOOFED",
                         "domain": p["website"],
                         "registry_note": f"{p['area']}: unofficial website {p['website']}, mobile number "
                                          f"{p['phone']}, {p['reviews']} reviews. Linked to {p['syndicate']}."})
        pins.extend(self.live_pins.values())
        return pins

    async def snapshot(self) -> dict[str, Any]:
        from .intel import hunter  # local: hunter -> pipeline -> heavy imports

        campaigns = await self.campaigns()
        pins = self.map_pins()
        cutoff = iso(utcnow() - timedelta(hours=72))
        entities = {c["impersonated_entity"] for c in campaigns if c["impersonated_entity"] and c["last_seen"] >= cutoff}
        entities |= {c["impersonated_entity"] for c in campaigns if c["impersonated_entity"] and c["status"] == "ACTIVE"}
        return {
            "kpis": {"citizens_protected": self.protected, "active_entities": len(entities),
                     "hijacked_pins": sum(1 for p in pins if p["type"] == "SPOOFED"),
                     "x_alerts_dispatched": self.x_alerts,
                     "pre_victim_detections": await hunter.pre_victim_count()},
            # kpis.citizens_protected / x_alerts_dispatched = demo_baseline + live_counts.
            "demo_baseline": {"citizens_protected": BASE_PROTECTED, "x_alerts_dispatched": BASE_X_ALERTS},
            "live_counts": {"citizens_protected": max(0, self.protected - BASE_PROTECTED),
                            "x_alerts_dispatched": max(0, self.x_alerts - BASE_X_ALERTS)},
            "proactive_detections": await hunter.latest_detections(20),
            "hunter_mode": hunter.hunter.mode,
            "campaigns": campaigns,
            "recent_events": list(self.events)[:25],
            "map_pins": pins,
            "telecom_synced": sorted(self.telecom_synced),
            "latest_warning": self.warnings[0] if self.warnings else None,
            "generated_at": iso(),
        }


police_state = PoliceState()
