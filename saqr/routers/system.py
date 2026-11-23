"""Health, stats and registry endpoints."""
from __future__ import annotations

from datetime import timedelta

from fastapi import APIRouter

from .. import __version__, keepalive
from ..config import settings
from ..db import db, iso, utcnow
from ..intel.ct_monitor import ct_monitor
from ..intel.registry import ENTITIES
from ..intel.sandbox import sandbox
from ..intel import ai_inspector, url_model
from ..intel.threat_feeds import threat_feeds
from ..ws_hub import hub

router = APIRouter(tags=["System"])


async def collect_stats() -> dict:
    since = iso(utcnow() - timedelta(hours=24))
    by_verdict = {r["verdict"]: r["c"] for r in await db.fetchall(
        "SELECT verdict, COUNT(*) c FROM scans WHERE created_at >= ? GROUP BY verdict", (since,))}
    totals = await db.fetchone(
        "SELECT (SELECT COUNT(*) FROM scans) scans, (SELECT COUNT(*) FROM graph_nodes) nodes, "
        "(SELECT COUNT(*) FROM graph_edges) edges, (SELECT COUNT(*) FROM ct_events) ct_events, "
        "(SELECT COUNT(*) FROM dossiers) dossiers")
    top = await db.fetchall(
        "SELECT impersonated_entity entity, COUNT(*) c FROM scans WHERE created_at >= ? AND verdict != 'SAFE' "
        "AND impersonated_entity IS NOT NULL GROUP BY impersonated_entity ORDER BY c DESC LIMIT 5", (since,))
    return {"last_24h": {"by_verdict": by_verdict, "top_impersonated": top}, "totals": totals,
            "ct_monitor": ct_monitor.status(), "ws_clients": hub.client_count,
            "llm_engine": settings.active_llm, "sandbox_available": sandbox.available,
            "sandbox_error": sandbox.error, "generated_at": iso()}


@router.get("/health")
async def health():
    return {"status": "ok", "app": settings.app_name, "version": __version__, "llm_engine": settings.active_llm,
            "playwright_enabled": settings.sandbox_enabled, "keep_awake": bool(keepalive.public_url()),
            "offline_mode": settings.offline_mode,
            "ct_mode": ct_monitor.mode, "url_model": url_model.available(), "llm": ai_inspector.llm_status,
            "threat_feeds": threat_feeds.status()}


@router.get("/api/stats")
async def stats():
    return await collect_stats()


@router.get("/api/whitelist")
async def whitelist():
    return {"entities": [{"id": e.id, "name_en": e.name_en, "name_ar": e.name_ar, "category": e.category,
                          "domains": list(e.domains), "phones": list(e.phones)} for e in ENTITIES],
            "extra_domains": settings.extra_whitelist}
