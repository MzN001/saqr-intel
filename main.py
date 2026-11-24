"""SAQR-INTEL — Autonomous anti-fraud & cybercrime intelligence backend.

Run:  uvicorn main:app --reload --port 8000
Docs: http://localhost:8000/docs
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from saqr import __version__, keepalive, self_hosts
from saqr.config import settings
from saqr.db import db, seed_if_empty
from saqr.intel.campaigns import campaign_feed
from saqr.intel.ct_monitor import ct_monitor
from saqr.intel.domain_intel import shutdown_pools
from saqr.intel.hunter import hunter
from saqr.intel.nextdns_sync import block_watcher, nextdns_sync
from saqr.intel.sandbox import sandbox
from saqr.intel.threat_feeds import threat_feeds
from saqr.pipeline import seed_historical_scans
from saqr.seed_data import MOCK_SCAM_SLUGS, replica_html
from saqr.feedback_state import feedback_state
from saqr.police_state import police_state
from saqr.routers import (analysis, batch, blocklist, campaigns, ct, email, feedback, graph, live, maps, mobile, police,
                          public, push, system, takedown, user_model)
from saqr.routers import hunter as hunter_router
from saqr.routers import model as model_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("saqr")


async def _retention_loop() -> None:
    """Privacy: prune old scans (SCAN_RETENTION_DAYS) on start, then every 6 hours."""
    while True:
        try:
            if n := await db.prune_scans():
                log.info("Retention: deleted %d scans older than %d days", n, settings.scan_retention_days)
        except Exception:  # noqa: BLE001
            log.warning("scan retention prune failed", exc_info=True)
        await asyncio.sleep(6 * 3600)


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.connect()
    if await seed_if_empty():
        log.info("Seeded syndicate intelligence (Sand Viper, Desert Mirage)")
    await feedback_state.load()
    seed_task = asyncio.create_task(seed_historical_scans(), name="seed-scans")
    retention_task = asyncio.create_task(_retention_loop(), name="scan-retention")
    police_state.seed()  # /police looks active on a cold boot
    ct_monitor.start()
    threat_feeds.start()
    campaign_feed.start()
    nextdns_sync.start()
    block_watcher.start()
    await hunter.start()
    keepalive_task = asyncio.create_task(keepalive.run(), name="keep-awake")
    log.info("SAQR-INTEL %s ready — LLM engine: %s, CT mode: %s", __version__, settings.active_llm, settings.ct_mode)
    log.info("Proactive hunter mode: %s", hunter.mode)
    try:
        yield
    finally:
        seed_task.cancel()
        retention_task.cancel()
        keepalive_task.cancel()
        await hunter.stop()
        await ct_monitor.stop()
        await threat_feeds.stop()
        await campaign_feed.stop()
        await nextdns_sync.stop()
        await block_watcher.stop()
        await sandbox.close()
        await db.close()
        shutdown_pools()


app = FastAPI(
    title="SAQR-INTEL API",
    version=__version__,
    description="Autonomous anti-fraud & cybercrime intelligence system — Abu Dhabi Police Hackathon.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex or None,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path.startswith(("/api/", "/ws/")):
        try:
            await self_hosts.remember(request.headers.get("host"))  # never blocklist our own public address
        except Exception:  # noqa: BLE001
            log.debug("could not record self host", exc_info=True)
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.exception_handler(ValueError)
async def value_error_handler(_: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/", include_in_schema=False)
async def demo_console(request: Request):
    """Browsers get the built-in demo console; uptime monitors / health checks get a small JSON 200."""
    if "text/html" in request.headers.get("accept", ""):
        return FileResponse(Path(__file__).parent / "saqr" / "static" / "index.html")
    return {"status": "ok", "app": settings.app_name, "version": __version__, "health": "/health", "docs": "/docs"}


@app.get("/mock-scam/{slug}", include_in_schema=False, response_class=HTMLResponse)
async def mock_scam(slug: str):
    """Harmless training replica of a seeded phishing page (forms post nowhere)."""
    domain = MOCK_SCAM_SLUGS.get(slug)
    if not domain:
        return HTMLResponse("Not found", status_code=404)
    html = replica_html(domain).replace(
        "<body>", '<body><div style="background:#0B192C;color:#fff;font:12px system-ui;padding:6px 10px;'
                  'text-align:center">SAQR-INTEL training replica of a real scam pattern &mdash; not a real website. '
                  'Do not enter real data.</div>', 1).replace('<form action="', '<form data-original-action="')
    return HTMLResponse(html, headers={"X-Robots-Tag": "noindex", "Content-Security-Policy": "form-action 'none'"})


for r in (system.router, analysis.router, maps.router, ct.router, graph.router, takedown.router, live.router,
          mobile.router, blocklist.router, push.router, email.router, campaigns.router, user_model.router,
          police.router, hunter_router.router, batch.router, public.router, feedback.router):
    app.include_router(r)
app.include_router(model_router.router)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
