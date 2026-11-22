"""Push SAQR-INTEL's high-risk domains to a NextDNS denylist (real phone protection).

Phones that use the NextDNS profile (iPhone .mobileconfig / Android Private DNS hostname) then
cannot resolve those domains in any app. Runs every NEXTDNS_SYNC_INTERVAL_SECONDS and immediately
after any HIGH-RISK scan (`kick()`).

Only adds entries (never deletes the owner's own denylist items). The API key is never logged or
returned by the status endpoint.
"""
from __future__ import annotations

import asyncio
import logging
from typing import Any

import httpx

from ..config import settings
from ..db import iso

log = logging.getLogger("saqr.nextdns")

MAX_PER_SYNC = 60  # stay well inside NextDNS API rate limits


class NextDNSSync:
    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._kick = asyncio.Event()
        self.pushed: set[str] = set()
        self.last_sync: str | None = None
        self.last_error: str | None = None
        self.last_added: list[str] = []

    @property
    def configured(self) -> bool:
        return bool(settings.nextdns_api_key and settings.nextdns_profile_id)

    def status(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "profile_id": settings.nextdns_profile_id or None,
            "android_dot_hostname": f"{settings.nextdns_profile_id}.dns.nextdns.io" if settings.nextdns_profile_id else None,
            "ios_doh_url": f"https://dns.nextdns.io/{settings.nextdns_profile_id}" if settings.nextdns_profile_id else None,
            "synced_domains": len(self.pushed),
            "last_sync": self.last_sync,
            "last_added": self.last_added[-10:],
            "last_error": self.last_error,
            "min_score": settings.nextdns_min_score,
            "interval_seconds": settings.nextdns_sync_interval_s,
        }

    def start(self) -> None:
        if not self.configured:
            log.info("NextDNS sync disabled (set NEXTDNS_API_KEY and NEXTDNS_PROFILE_ID in .env to enable)")
            return
        self._task = asyncio.create_task(self._loop(), name="nextdns-sync")
        log.info("NextDNS sync enabled for profile %s", settings.nextdns_profile_id)

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    def kick(self) -> None:
        """Sync now (called after a HIGH-RISK verdict)."""
        if self.configured:
            self._kick.set()

    async def _loop(self) -> None:
        while True:
            try:
                await self.sync_once()
            except Exception as exc:  # noqa: BLE001
                self.last_error = f"{type(exc).__name__}: {exc}"[:300]
                log.warning("NextDNS sync failed: %s", self.last_error)
            self._kick.clear()
            try:
                await asyncio.wait_for(self._kick.wait(), timeout=settings.nextdns_sync_interval_s)
                await asyncio.sleep(1.5)  # let the scan finish saving before collecting
            except asyncio.TimeoutError:
                pass

    async def _wanted(self) -> list[str]:
        from ..routers.blocklist import collect  # local import avoids a router <-> intel cycle

        entries = await collect(settings.nextdns_min_score)
        keep = []
        for e in entries:
            sources = set(e["sources"])
            if sources == {"certificate_transparency"} and not settings.nextdns_include_ct:
                continue
            keep.append(e["domain"])
        return keep

    async def sync_once(self) -> list[str]:
        if not self.configured:
            return []
        base = f"{settings.nextdns_api_base.rstrip('/')}/profiles/{settings.nextdns_profile_id}/denylist"
        headers = {"X-Api-Key": settings.nextdns_api_key, "Content-Type": "application/json"}
        async with httpx.AsyncClient(timeout=15, headers=headers) as client:
            r = await client.get(base)
            if r.status_code in (401, 403):
                raise RuntimeError("NextDNS rejected the API key (check NEXTDNS_API_KEY)")
            if r.status_code == 404:
                raise RuntimeError("NextDNS profile not found (check NEXTDNS_PROFILE_ID)")
            r.raise_for_status()
            existing = {item.get("id", "").lower() for item in r.json().get("data", [])}
            self.pushed |= existing & set(await self._wanted())

            added: list[str] = []
            for domain in [d for d in await self._wanted() if d not in existing][:MAX_PER_SYNC]:
                resp = await client.post(base, json={"id": domain, "active": True})
                if resp.status_code < 300:
                    added.append(domain)
                    self.pushed.add(domain)
                else:
                    log.warning("NextDNS refused %s: HTTP %s", domain, resp.status_code)
        self.last_sync = iso()
        self.last_error = None
        if added:
            self.last_added = (self.last_added + added)[-50:]
            log.info("NextDNS: added %d domain(s): %s", len(added), ", ".join(added[:5]))
        return added


nextdns_sync = NextDNSSync()
