"""Global threat-intelligence feeds + popular-site list.

* Phishing Army (aggregates PhishTank, OpenPhish, CERT.PL, Phishunt, urlscan.io, PhishStats) and
  the OpenPhish community feed: confirmed, currently active phishing hosts. Downloaded at start and
  every 6 hours, kept in memory (~150k hosts, ~15 MB).
* Popular sites (Tranco top 100k, shipped in data/popular_domains.txt.gz): the URL classifier
  never flags them on its own, so a strange-looking but famous address is not a false alarm.

Safety: a feed can never list a whole platform (vercel.app, pages.dev ...), an official / trusted
domain, or one of the 10,000 most popular sites; only the exact host (and its sub-domains) matches.
"""
from __future__ import annotations

import asyncio
import gzip
import logging
import time
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from ..config import settings
from .url_model import FREE_HOSTING

log = logging.getLogger("saqr.feeds")

FEEDS = {
    "Phishing Army": "https://phishing.army/download/phishing_army_blocklist.txt",
    "OpenPhish": "https://openphish.com/feed.txt",
}
REFRESH_SECONDS = 6 * 3600
POPULAR_PATH = Path(__file__).with_name("data") / "popular_domains.txt.gz"
NEVER_LIST = frozenset({
    "vercel.app", "onrender.com", "trycloudflare.com", "github.io", "netlify.app", "pages.dev", "workers.dev",
    "herokuapp.com", "web.app", "firebaseapp.com", "azurewebsites.net", "ngrok.io", "ngrok-free.app",
    "glitch.me", "replit.app", "fly.dev", "railway.app", *FREE_HOSTING,
})


@lru_cache(maxsize=1)
def _popular() -> dict[str, int]:
    try:
        with gzip.open(POPULAR_PATH, "rt", encoding="utf-8") as f:
            return {d.strip(): i for i, d in enumerate(f, start=1) if d.strip()}
    except OSError:
        return {}


def popularity_rank(registered_domain: str) -> int | None:
    """Tranco rank (1 = most popular) if the site is in the top 100k, else None."""
    return _popular().get((registered_domain or "").lower())


def on_free_hosting(host: str) -> bool:
    h = (host or "").lower()
    return any(h == p or h.endswith("." + p) for p in FREE_HOSTING)


def _host(entry: str) -> str:
    entry = entry.strip().lower()
    if "://" in entry:
        try:
            entry = urlsplit(entry).hostname or ""
        except ValueError:
            return ""
    entry = entry.rstrip(".")
    return entry[4:] if entry.startswith("www.") else entry


class ThreatFeeds:
    def __init__(self) -> None:
        self.hosts: dict[str, str] = {}  # host -> feed name
        self.updated: str | None = None
        self.counts: dict[str, int] = {}
        self.last_error: str | None = None
        self._task: asyncio.Task | None = None

    # -- data --------------------------------------------------------------------------------
    def load(self, entries: dict[str, list[str]]) -> int:
        """Replace the feed contents ({feed name: [hosts or URLs]}), applying the safety rules."""
        from .domain_intel import official_match

        hosts: dict[str, str] = {}
        counts: dict[str, int] = {}
        for name, items in entries.items():
            n = 0
            for raw in items:
                h = _host(raw)
                if (not h or "." not in h or h in NEVER_LIST or official_match(h)
                        or (popularity_rank(h) or 10**9) <= 10_000):
                    continue
                hosts.setdefault(h, name)
                n += 1
            counts[name] = n
        self.hosts, self.counts = hosts, counts
        self.updated = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return len(hosts)

    def lookup(self, host: str) -> str | None:
        """Feed name if this host (or a parent domain that is itself listed) is known phishing."""
        h = _host(host)
        parts = h.split(".")
        for i in range(len(parts) - 1):
            cand = ".".join(parts[i:])
            if cand in NEVER_LIST:
                break
            if cand in self.hosts:
                return self.hosts[cand]
        return None

    def status(self) -> dict:
        return {"hosts": len(self.hosts), "by_feed": self.counts, "updated": self.updated, "error": self.last_error}

    # -- refresh loop -----------------------------------------------------------------------
    async def refresh(self) -> None:
        entries: dict[str, list[str]] = {}
        async with httpx.AsyncClient(timeout=60, follow_redirects=True,
                                     headers={"User-Agent": "SAQR-INTEL threat-feed client"}) as client:
            for name, url in FEEDS.items():
                try:
                    r = await client.get(url)
                    r.raise_for_status()
                    entries[name] = [ln for ln in r.text.splitlines() if ln.strip() and not ln.startswith("#")]
                except Exception as exc:  # noqa: BLE001
                    self.last_error = f"{name}: {type(exc).__name__}"
                    log.warning("Threat feed %s failed: %s", name, exc)
        if entries:
            n = self.load(entries)
            if len(entries) == len(FEEDS):
                self.last_error = None
            log.info("Threat feeds loaded: %d phishing hosts %s", n, self.counts)

    def start(self) -> None:
        if not settings.offline_mode and settings.threat_feeds_enabled:
            self._task = asyncio.create_task(self._loop(), name="threat-feeds")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    async def _loop(self) -> None:
        while True:
            await self.refresh()
            await asyncio.sleep(REFRESH_SECONDS)


threat_feeds = ThreatFeeds()
