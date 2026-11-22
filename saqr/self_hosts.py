"""Public hostnames this backend is reached through (e.g. the Cloudflare tunnel Vercel calls).

They must never end up in the DNS blocklist / NextDNS denylist, even if a training page was once
scanned through them, or phones using the SAQR shield could no longer reach SAQR itself.
A hostname is recorded the first time /api or /ws traffic arrives through it.
"""
from __future__ import annotations

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


async def all_self_hosts() -> set[str]:
    rows = await db.fetchall("SELECT host FROM self_hosts")
    _known.update(r["host"] for r in rows)
    return set(_known)
