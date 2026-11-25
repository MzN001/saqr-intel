"""Push SAQR-INTEL's high-risk domains to a NextDNS denylist (real phone protection).

Phones that use the NextDNS profile (iPhone .mobileconfig / Android Private DNS hostname) then
cannot resolve those domains in any app. Runs every NEXTDNS_SYNC_INTERVAL_SECONDS and immediately
after any HIGH-RISK scan (`kick()`).

Only adds entries (never deletes the owner's own denylist items). The API key is never logged or
returned by the status endpoint.
"""
from __future__ import annotations

import asyncio
import json
import logging
import time
from typing import Any

import httpx

from .. import self_hosts
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
        self.removed: list[str] = []

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
            "protected_removed": self.removed[-10:],
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

            # Never block SAQR's own public address (the Vercel site's tunnel): remove if present.
            # Same for official / trusted domains (e.g. one added to the trust list after it was pushed).
            from .domain_intel import official_match

            protected = (existing & await self_hosts.all_self_hosts()) | {d for d in existing if official_match(d)}
            for own in sorted(protected):
                resp = await client.delete(f"{base}/{own}")
                if resp.status_code < 300 or resp.status_code == 404:
                    existing.discard(own)
                    self.pushed.discard(own)
                    self.removed.append(own)
                    log.info("NextDNS: removed protected host %s (own / official / trusted) from the denylist", own)

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


def _retry_after(resp: httpx.Response, default: float) -> float:
    try:
        return min(300.0, max(1.0, float(resp.headers.get("retry-after", default))))
    except ValueError:
        return default


class BlockWatcher:
    """Turns 'a phone just tried to open a SAQR-flagged scam' (NextDNS logs) into a push alert.

    Needs logging enabled in the NextDNS profile (Settings -> Logs). Only domains SAQR itself
    flagged trigger alerts, so ordinary ad/tracker blocks never notify anyone.
    """

    # NextDNS's live stream delivers entries in ~1.3 s but ends after 10-40 s and can only be reopened
    # about once a minute; the plain logs endpoint tolerates polling every few seconds. So: stream
    # whenever allowed, poll in between.
    POLL_SECONDS = 2.5
    STREAM_RETRY_SECONDS = 60.0
    REPEAT_AFTER_SECONDS = 120
    # A tab left open on a blocked scam (Safari) retries it every few minutes. Those retries are the
    # same attempt, not a new one: a phone is alerted again only after it left the site alone this long.
    QUIET_SECONDS = 600
    RETRY_DELAYS = (2.0, 5.0, 15.0)

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._last_ts: str | None = None  # None until the first look at the logs
        # Every blocked log line already handled (stream or poll). A timestamp "high-water mark"
        # alone skipped lines that NextDNS wrote a moment late, so each line is matched by its key.
        self._seen: dict[str, None] = {}
        self._retrying: set[str] = set()
        self.alerts_failed = 0
        self._recent: dict[str, float] = {}
        self._last_attempt: dict[str, float] = {}  # domain|device -> when that phone last asked for it
        self.alerts_sent = 0
        self.last_alert: str | None = None
        self.last_error: str | None = None
        self.mode = "idle"  # stream | polling | idle
        self._flagged_cache: dict[str, dict[str, Any]] = {}
        self._flagged_at = -1e9
        self._last_event_id: str | None = None

    def start(self) -> None:
        if settings.nextdns_api_key and settings.nextdns_profile_id:
            self._task = asyncio.create_task(self._loop(), name="nextdns-block-watcher")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def _loop(self) -> None:
        """Live log stream (Server-Sent Events, ~1 s) with polling as a fallback when it drops."""
        from .. import push

        headers = {"X-Api-Key": settings.nextdns_api_key}
        next_stream = 0.0
        async with httpx.AsyncClient(timeout=httpx.Timeout(10, read=None), headers=headers) as client:
            while True:
                if not await push.count_subscriptions():
                    self.mode = "idle"
                    await asyncio.sleep(2)
                    continue
                if time.monotonic() >= next_stream:
                    next_stream = time.monotonic() + self.STREAM_RETRY_SECONDS
                    try:
                        await self.stream(client)  # instant alerts while it lasts
                    except httpx.HTTPStatusError as exc:
                        if exc.response.status_code != 429:
                            self.last_error = f"stream: HTTP {exc.response.status_code}"
                    except Exception as exc:  # noqa: BLE001
                        self.last_error = f"stream: {type(exc).__name__}: {exc}"[:200]
                self.mode = "polling"
                try:
                    await self.poll_once(client)
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 429:
                        self.last_error = "NextDNS rate limit on logs; slowing down"
                        await asyncio.sleep(_retry_after(exc.response, default=15))
                    else:
                        self.last_error = f"poll: HTTP {exc.response.status_code}"
                except Exception as exc:  # noqa: BLE001
                    self.last_error = f"poll: {type(exc).__name__}: {exc}"[:200]
                await asyncio.sleep(self.POLL_SECONDS)

    async def stream(self, client: httpx.AsyncClient) -> None:
        url = f"{settings.nextdns_api_base.rstrip('/')}/profiles/{settings.nextdns_profile_id}/logs/stream"
        params = {"id": self._last_event_id} if self._last_event_id else None
        async with client.stream("GET", url, params=params) as r:
            if r.status_code == 400 and params:  # resume id expired: start fresh next time
                self._last_event_id = None
                return
            r.raise_for_status()
            if self.mode != "stream":
                log.info("NextDNS live log stream connected (scam alerts in ~1 s)")
            self.mode = "stream"
            self.last_error = None
            async for line in r.aiter_lines():
                if line.startswith("id:"):
                    self._last_event_id = line[3:].strip() or self._last_event_id
                    continue
                if not line.startswith("data:"):
                    continue
                try:
                    item = json.loads(line[5:].strip())
                except json.JSONDecodeError:
                    continue
                ts = item.get("timestamp", "")
                if ts and (self._last_ts is None or ts > self._last_ts):
                    self._last_ts = ts  # so polling afterwards doesn't re-process stream entries
                if item.get("status") == "blocked" and self._first_time(item):
                    await self.handle([item])

    async def _flagged(self) -> dict[str, dict[str, Any]]:
        """SAQR-flagged domains, cached for a few seconds so each event is handled instantly."""
        from ..routers.blocklist import collect

        now = time.monotonic()
        if now - self._flagged_at > 5 or not self._flagged_cache:
            self._flagged_cache = {e["domain"]: e for e in await collect(settings.nextdns_min_score)}
            self._flagged_at = now
        return self._flagged_cache

    @staticmethod
    def _key(item: dict[str, Any]) -> str:
        device = item.get("device")
        device_id = device.get("id", "") if isinstance(device, dict) else ""
        domain = (item.get("domain") or "").lower().rstrip(".")
        return "|".join(str(x) for x in (item.get("timestamp", ""), domain, device_id, item.get("clientIp", "")))

    def _first_time(self, item: dict[str, Any]) -> bool:
        """True the first time a log line is seen (the stream and the poll can both deliver it)."""
        key = self._key(item)
        if key in self._seen:
            return False
        self._seen[key] = None
        if len(self._seen) > 2000:  # keep the newest keys only
            for old in list(self._seen)[:1000]:
                del self._seen[old]
        return True

    @staticmethod
    def _device(item: dict[str, Any]) -> str | None:
        """The phone's SAQR device tag, from the device name NextDNS logged (None if unnamed)."""
        from .. import push

        device = item.get("device")
        return push.normalise_device(device.get("name")) if isinstance(device, dict) else None

    async def _deliver(self, domain: str, entity: str | None, device: str | None = None) -> bool:
        """Send the alert; if no phone got it, keep retrying in the background. The phone caches the
        block for ~5 minutes, so it will not ask NextDNS again (and give us a second chance) soon."""
        from .. import push

        if await push.alert_device(domain, entity, device):
            return True
        self.alerts_failed += 1
        key = f"{domain}|{device or ''}"
        if key not in self._retrying and await push.count_subscriptions():
            self._retrying.add(key)
            asyncio.create_task(self._retry(domain, entity, device), name=f"alert-retry-{key}")
        return False

    async def _retry(self, domain: str, entity: str | None, device: str | None) -> None:
        from .. import push

        key = f"{domain}|{device or ''}"
        try:
            for delay in self.RETRY_DELAYS:
                await asyncio.sleep(delay)
                if await push.alert_device(domain, entity, device):
                    self._mark_alerted(key)
                    return
                self.alerts_failed += 1
        finally:
            self._retrying.discard(key)

    def _mark_alerted(self, key: str) -> None:
        self._recent[key] = time.monotonic()
        self.alerts_sent += 1
        self.last_alert = iso()

    async def handle(self, items: list[dict[str, Any]]) -> list[str]:
        from .. import push

        flagged = await self._flagged()
        alerted: list[str] = []
        done: set[str] = set()
        now = time.monotonic()
        for item in items:
            names = [(item.get("domain") or "").lower().rstrip("."), (item.get("root") or "").lower().rstrip(".")]
            hit = next((n for n in names if n in flagged), None)
            if not hit and names[0]:
                hit = next((d for d in flagged if names[0].endswith("." + d)), None)
            if not hit and now - self._flagged_at > 1:
                # Maybe flagged in the last few seconds (e.g. the live phone demo): refresh once.
                self._flagged_at = -1e9
                flagged = await self._flagged()
                hit = next((n for n in names if n in flagged), None)
            if not hit:
                continue
            device = self._device(item)
            key = f"{hit}|{device or ''}"  # each phone gets its own alert, and only its own
            previous = self._last_attempt.get(key)
            self._last_attempt[key] = now
            if len(self._last_attempt) > 2000:
                for old in list(self._last_attempt)[:1000]:
                    del self._last_attempt[old]
            if key in self._recent and previous is not None and now - previous < self.QUIET_SECONDS:
                continue  # the same phone still retrying the same scam (open tab): already alerted
            if now - self._recent.get(key, -1e9) < self.REPEAT_AFTER_SECONDS or key in done or key in self._retrying:
                continue
            if not await self._deliver(hit, flagged[hit].get("impersonated_entity"), device):
                continue  # retried in the background; a later blocked attempt may also retry
            self._mark_alerted(key)
            done.add(key)
            alerted.append(hit)
        return alerted

    async def poll_once(self, client: httpx.AsyncClient) -> list[str]:
        url = f"{settings.nextdns_api_base.rstrip('/')}/profiles/{settings.nextdns_profile_id}/logs"
        r = await client.get(url, params={"status": "blocked", "limit": 50})
        r.raise_for_status()
        items = r.json().get("data", [])
        newest = max((i.get("timestamp", "") for i in items), default=self._last_ts or "")
        if self._last_ts is None:  # first look: remember what is there, don't alert on old history
            for i in items:
                self._first_time(i)
            self._last_ts = newest
            return []
        self._last_ts = max(self._last_ts, newest)
        fresh = [i for i in items if self._first_time(i)]
        return await self.handle(fresh) if fresh else []


block_watcher = BlockWatcher()
