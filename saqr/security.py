"""Security controls: SSRF guard, rate limiting, police API key."""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import socket
import time
from collections import defaultdict, deque

from fastapi import Header, HTTPException, Request, WebSocket, status

from .config import settings


# ---------------------------------------------------------------------------
# SSRF guard — the sandbox must never be pointed at internal infrastructure.
# ---------------------------------------------------------------------------
def ip_is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


async def host_is_safe_target(host: str) -> tuple[bool, list[str]]:
    """Resolve `host` and ensure every address is publicly routable."""
    if settings.allow_private_targets:
        return True, []
    if host in {"localhost", "metadata.google.internal"} or host.endswith((".local", ".internal", ".localhost")):
        return False, []
    try:
        ipaddress.ip_address(host)
        return ip_is_public(host), [host]
    except ValueError:
        pass
    try:
        infos = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM), timeout=4
        )
    except Exception:  # noqa: BLE001 — unresolvable: nothing to fetch, but not "unsafe"
        return True, []
    ips = sorted({i[4][0] for i in infos})
    return all(ip_is_public(i) for i in ips), ips


# ---------------------------------------------------------------------------
# Sliding-window rate limiter (per client IP) for citizen-facing endpoints.
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = per_minute
        self.hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str) -> bool:
        if self.per_minute <= 0:
            return True
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= self.per_minute:
            return False
        q.append(now)
        return True


_limiter = RateLimiter(settings.rate_limit_per_minute)


async def rate_limit(request: Request) -> None:
    client = request.client.host if request.client else "unknown"
    if not _limiter.check(client):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Rate limit exceeded — try again in a minute.")


# ---------------------------------------------------------------------------
# Police-only endpoints (graph, dossiers). Open when POLICE_API_KEY is unset.
# ---------------------------------------------------------------------------
# WebSocket topics a citizen (keyless) client may receive once POLICE_API_KEY is set. Payloads are
# trimmed by `ws_hub.public_view` before they reach such a client.
PUBLIC_WS_TOPICS = frozenset({"police.warning", "url_scan", "maps_scan", "email_scan"})


def police_key_configured() -> bool:
    return bool(settings.police_api_key)


def _key_ok(provided: str | None) -> bool:
    if not settings.police_api_key:
        return True
    return bool(provided) and hmac.compare_digest(provided, settings.police_api_key)


async def require_police(x_api_key: str | None = Header(default=None)) -> None:
    if not _key_ok(x_api_key):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Valid X-API-Key header required.")


def ws_authorized(ws: WebSocket) -> bool:
    return _key_ok(ws.query_params.get("token") or ws.headers.get("x-api-key"))
