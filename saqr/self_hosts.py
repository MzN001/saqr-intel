"""Public hostnames this backend is reached through (e.g. the Cloudflare tunnel Vercel calls).

They must never end up in the DNS blocklist / NextDNS denylist, even if a training page was once
scanned through them, or phones using the SAQR shield could no longer reach SAQR itself.
A hostname is recorded the first time /api or /ws traffic arrives through it.
"""
from __future__ import annotations

import os

from .db import db, iso

_LOCAL = {"localhost", "127.0.0.1", "0.0.0.0", "::1", "[::1]", "testserver"}
_known: set[str] = set()


def _normalise(host_header: str | None) -> str | None:
    if not host_header:
        return None
    host = host_header.strip().lower()
    if host.startswith("["):
        return None
    host = host.split(":", 1)[0]
    if host in _LOCAL or host.replace(".", "").isdigit():
        return None
    return host


async def remember(host_header: str | None) -> None:
    host = _normalise(host_header)
    if not host or host in _known:
        return
    _known.add(host)
    await db.execute("INSERT OR REPLACE INTO self_hosts (host, seen_at) VALUES (?, ?)", (host, iso()))


def configured_hosts() -> set[str]:
    """SAQR's own public addresses from settings: OWN_HOSTS, Render's URL and the CORS origins."""
    from urllib.parse import urlsplit

    from .config import settings

    hosts = {h.strip().lower() for h in settings.own_hosts if h.strip()}
    for url in [os.getenv("RENDER_EXTERNAL_URL", ""), *settings.cors_origins]:
        h = _normalise(urlsplit(url).hostname or "") if url.startswith("https://") else None
        if h:
            hosts.add(h)
    return hosts


def known_hosts() -> set[str]:
    """Hosts seen so far in this process plus the configured ones (synchronous, no DB access)."""
    return set(_known) | configured_hosts()


async def all_self_hosts() -> set[str]:
    rows = await db.fetchall("SELECT host FROM self_hosts")
    _known.update(r["host"] for r in rows)
    return set(_known) | configured_hosts()
