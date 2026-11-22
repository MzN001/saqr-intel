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

from saqr import __version__
from saqr.config import settings
from saqr.db import db, seed_if_empty
from saqr.intel.ct_monitor import ct_monitor
from saqr.intel.domain_intel import shutdown_pools
from saqr.intel.sandbox import sandbox
from saqr.pipeline import seed_historical_scans
from saqr.seed_data import MOCK_SCAM_SLUGS, replica_html
from saqr.routers import analysis, blocklist, ct, graph, live, maps, mobile, system, takedown

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("saqr")


@asynccontextmanager
async def lifespan(_: FastAPI):
    await db.connect()
    if await seed_if_empty():
        log.info("Seeded syndicate intelligence (Sand Viper, Desert Mirage)")
    seed_task = asyncio.create_task(seed_historical_scans(), name="seed-scans")
    ct_monitor.start()
    log.info("SAQR-INTEL %s ready — LLM engine: %s, CT mode: %s", __version__, settings.active_llm, settings.ct_mode)
    try:
        yield
    finally:
        seed_task.cancel()
        await ct_monitor.stop()
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
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.exception_handler(ValueError)
async def value_error_handler(_: Request, exc: ValueError):
    return JSONResponse(status_code=422, content={"detail": str(exc)})


@app.get("/", include_in_schema=False)
async def demo_console():
    """Built-in demo console (no internet needed). The real dashboard runs on :3000."""
    return FileResponse(Path(__file__).parent / "saqr" / "static" / "index.html")


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
          mobile.router, blocklist.router):
    app.include_router(r)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
