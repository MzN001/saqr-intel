"""GET /api/dns-blocklist — live threat feed for telecom DNS resolvers (e& / du).

Publishes every high-confidence scam domain SAQR-INTEL knows about as a DNS Response Policy Zone
(RPZ). A resolver that loads this zone answers NXDOMAIN (`CNAME .`) for those domains and all their
sub-domains, so the scam site never loads on any phone on that network.

Safety rules: official / trusted UAE domains, IP addresses and local hosts are never published,
and every name is validated before it is written into the zone file.
"""
from __future__ import annotations

import re
import time
from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, Query
from fastapi.responses import PlainTextResponse

from .. import self_hosts
from ..config import settings
from ..db import db, iso
from ..intel.domain_intel import analyze_lexical
from ..seed_data import DEMO_INTEL

router = APIRouter(prefix="/api", tags=["Telecom DNS feed"])

HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})$")
ZONE = "rpz.saqr-intel.ae"
# Shared hosting roots: one scam sub-domain (x.vercel.app) is blocked on its own, never the whole platform.
SHARED_HOSTING_ROOTS = frozenset({
    "vercel.app", "onrender.com", "trycloudflare.com", "github.io", "netlify.app", "pages.dev",
    "workers.dev", "herokuapp.com", "web.app", "firebaseapp.com", "azurewebsites.net", "ngrok.io",
    "ngrok-free.app", "glitch.me", "replit.app", "fly.dev", "railway.app",
})


def _publishable(domain: str | None) -> str | None:
    if not domain:
        return None
    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    if not HOSTNAME.match(d) or d.endswith((".localhost", ".local", ".internal")):
        return None
    if d in SHARED_HOSTING_ROOTS or analyze_lexical(d).is_whitelisted:  # never block official / trusted UAE sites
        return None
    return d


async def collect(min_score: int) -> list[dict[str, Any]]:
    entries: dict[str, dict[str, Any]] = {}
    own = await self_hosts.all_self_hosts()  # e.g. the tunnel the Vercel site uses to reach us

    def add(domain: str | None, score: int, entity: str | None, source: str, seen: str | None, reports: int = 0) -> None:
        d = _publishable(domain)
        if not d or score < min_score or d in own:
            return
        e = entries.setdefault(d, {"domain": d, "risk_score": 0, "impersonated_entity": None,
                                   "sources": [], "last_seen": None, "reports": 0})
        e["risk_score"] = max(e["risk_score"], int(score))
        e["impersonated_entity"] = e["impersonated_entity"] or entity
        if source not in e["sources"]:
            e["sources"].append(source)
        if seen and (not e["last_seen"] or seen > e["last_seen"]):
            e["last_seen"] = seen
        e["reports"] += reports

    rows = await db.fetchall(
        "SELECT domain, MAX(risk_score) AS score, MAX(created_at) AS seen, MAX(impersonated_entity) AS entity, "
        "COUNT(*) AS n FROM scans WHERE verdict != 'SAFE' AND domain IS NOT NULL GROUP BY domain")
    for r in rows:
        add(r["domain"], r["score"], r["entity"], "citizen_scan", r["seen"], int(r["n"]))

    for domain in DEMO_INTEL:  # confirmed hostile infrastructure (seeded intelligence)
        add(domain, 100, None, "syndicate_intel", None)

    for domain in settings.demo_scam_domains:  # the phone-demo fake TAMM page (demo-scam-site/)
        add(domain, 70, "TAMM Abu Dhabi", "demo_scam_page", None)

    from ..police_state import police_state  # local: police_state -> seed_data at import

    for domain, at in police_state.telecom_synced.items():  # officer "Sync to e& / du" in /police
        add(domain, 100, None, "police_telecom_sync", at)

    ct = await db.fetchall(
        "SELECT domain, MAX(score) AS score, MAX(seen_at) AS seen, MAX(entity) AS entity FROM ct_events "
        "WHERE entity IS NOT NULL GROUP BY domain")
    for r in ct:
        add(r["domain"], r["score"], r["entity"], "certificate_transparency", r["seen"])

    return sorted(entries.values(), key=lambda e: (-e["risk_score"], e["domain"]))


def build_rpz(domains: list[dict[str, Any]], generated: datetime) -> str:
    serial = int(time.time())
    lines = [
        f"; SAQR-INTEL Response Policy Zone ({ZONE}) - Abu Dhabi Police anti-fraud feed",
        f"; generated {generated.isoformat(timespec='seconds')}  entries: {len(domains)}",
        "; Load as a response-policy zone in the resolver (BIND: response-policy { zone \"" + ZONE + "\"; };).",
        "; 'CNAME .' = answer NXDOMAIN; the wildcard line also covers every sub-domain.",
        "$TTL 300",
        f"@ IN SOA {ZONE}. hostmaster.{ZONE}. ({serial} 3600 600 86400 300)",
        "@ IN NS localhost.",
        "",
    ]
    for e in domains:
        tag = f"; risk {e['risk_score']}" + (f", impersonating {e['impersonated_entity']}" if e["impersonated_entity"] else "")
        lines += [f"{e['domain']} CNAME . {tag}", f"*.{e['domain']} CNAME ."]
    return "\n".join(lines) + "\n"


@router.get("/dns-blocklist")
async def dns_blocklist(
    format: Literal["json", "rpz"] = Query("json", description="json (with metadata) or rpz (plain zone file)."),
    min_score: int = Query(65, ge=0, le=100, description="Only publish domains at or above this risk score."),
):
    generated = datetime.now(timezone.utc)
    domains = await collect(min_score)
    rpz = build_rpz(domains, generated)
    if format == "rpz":
        return PlainTextResponse(rpz, headers={"Content-Disposition": 'inline; filename="saqr-intel.rpz"',
                                               "Cache-Control": "no-store"})
    return {
        "zone": ZONE,
        "format": "DNS RPZ (Response Policy Zone)",
        "generated_at": iso(generated),
        "min_score": min_score,
        "count": len(domains),
        "consumers": ["e& (Etisalat) DNS resolvers", "du DNS resolvers"],
        "rpz_url": "/api/dns-blocklist?format=rpz",
        "domains": domains,
        "rpz": rpz,
        "ct_mode": settings.ct_mode,
    }
