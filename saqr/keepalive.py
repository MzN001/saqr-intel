"""Keep a Render free-tier instance awake.

Render puts free web services to sleep after 15 minutes without inbound traffic, which would pause
SAQR's background jobs (NextDNS sync, scam-alert watcher). Render sets RENDER_EXTERNAL_URL
automatically; while it is present we request our own public /health every few minutes. The request
leaves the instance and comes back through Render's edge, so it counts as inbound traffic. It is a
plain async httpx call, so it cannot deadlock the single Uvicorn worker.

Disable with KEEP_AWAKE=false. One service running all month (~720 h) fits the 750 free hours.
"""
from __future__ import annotations

import asyncio
import logging
import os

import httpx

log = logging.getLogger("saqr.keepalive")
INTERVAL_SECONDS = float(os.getenv("KEEP_AWAKE_INTERVAL_SECONDS", "600"))  # < Render's 15-min idle limit


def public_url() -> str | None:
    if os.getenv("KEEP_AWAKE", "true").strip().lower() in {"0", "false", "no", "off"}:
        return None
    url = (os.getenv("RENDER_EXTERNAL_URL") or os.getenv("KEEP_AWAKE_URL") or "").strip().rstrip("/")
    return url if url.startswith("https://") else None


async def run() -> None:
    url = public_url()
    if not url:
        return
    log.info("Keep-awake enabled: pinging %s/health every %.0f s", url, INTERVAL_SECONDS)
    async with httpx.AsyncClient(timeout=20, headers={"User-Agent": "saqr-keepalive/1.0"}) as client:
        while True:
            await asyncio.sleep(INTERVAL_SECONDS)
            try:
                await client.get(f"{url}/health")
            except Exception as exc:  # noqa: BLE001
                log.debug("keep-awake ping failed: %s", exc)
