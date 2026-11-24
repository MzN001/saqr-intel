"""Evasion resistance: follow a link to where it really goes.

Scammers hide the real address behind URL shorteners (bit.ly), open redirects (?url=...), HTTP 30x
chains, <meta refresh> pages and one-line JavaScript redirects. resolve_chain() walks that chain hop
by hop, without a browser, so every host on the way can be judged and the verdict names the real
destination instead of the harmless-looking first link.

Safety: every hop passes the SSRF guard before it is contacted; official and seeded demo domains are
never fetched; loops, private targets, timeouts and the hop limit end the chain cleanly.
"""
from __future__ import annotations

import html
import logging
import re
import time
from typing import Any
from urllib.parse import urldefrag, urljoin, urlsplit

import httpx

from ..config import settings
from ..security import host_is_safe_target
from ..seed_data import DEMO_INTEL
from .domain_intel import RedFlag, official_match
from .email_rules import host_of, regdom, unwrap_url
from .threat_feeds import on_free_hosting, popularity_rank

log = logging.getLogger("saqr.redirects")

# Public link shorteners and brand short domains: the host says nothing about the destination.
SHORTENERS = frozenset({
    "bit.ly", "j.mp", "bitly.ws", "tinyurl.com", "tiny.cc", "tiny.one", "tiny.pl", "t.co", "goo.gl",
    "maps.app.goo.gl", "forms.gle", "g.co", "youtu.be", "is.gd", "v.gd", "cutt.ly", "cutt.us", "rebrand.ly",
    "ow.ly", "ht.ly", "buff.ly", "rb.gy", "shorturl.at", "shorturl.asia", "shorturl.com", "s.id", "t.ly",
    "lnkd.in", "qr.link", "qrco.de", "q-r.to", "l.ead.me", "me-qr.com", "short.gy", "shorter.me", "bl.ink",
    "t2m.io", "dub.sh", "kutt.it", "shrtco.de", "clck.ru", "vk.cc", "u.to", "soo.gd", "clicky.me", "bc.vc",
    "adf.ly", "ouo.io", "shorte.st", "snip.ly", "hyperurl.co", "smarturl.it", "urlz.fr", "zpr.io", "1url.com",
    "2.gp", "tny.im", "chilp.it", "gg.gg", "mcaf.ee", "db.tt", "amzn.to", "amzn.eu", "a.co", "ebay.us",
    "fb.me", "apple.co", "spoti.fi", "msft.it", "aka.ms", "wp.me", "redd.it", "pin.it", "vm.tiktok.com",
    "vt.tiktok.com", "trib.al", "dlvr.it", "ift.tt", "shor.by", "rotf.lol", "zws.im", "qps.ru", "goo.su",
    "surl.li", "urlis.net", "n9.cl", "acortar.link", "lnnk.in", "han.gl", "me2.do", "reurl.cc", "lihi1.com",
    "pse.is", "ppt.cc", "wa.link", "ulvis.net", "xurl.es", "v.ht", "da.gd", "grabify.link", "2no.co",
    "hubs.ly", "hubs.la", "eepurl.com", "engt.co",
})

USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")
BODY_LIMIT = 65_536
# Tests inject an httpx.MockTransport here; with one set, the chain is walked even in OFFLINE_MODE.
TRANSPORT: httpx.AsyncBaseTransport | None = None

_META_TAG = re.compile(r"<meta\b[^>]*http-equiv\s*=\s*[\"']?refresh[\"']?[^>]*>", re.I)
_META_CONTENT = re.compile(r"content\s*=\s*[\"']?\s*(\d+(?:\.\d+)?)\s*[;,]\s*(?:url\s*=\s*)?[\"']?\s*([^\"'>\s]+)", re.I)
_JS_URL = r"[\"']((?:https?:)?\\?/\\?/?[^\"'\s]+)[\"']"
_JS_REDIRECT = re.compile(
    r"\blocation(?:\.href)?\s*=\s*" + _JS_URL + r"|\blocation\.(?:replace|assign)\(\s*" + _JS_URL + r"\s*\)", re.I)
_TAGS = re.compile(r"<script.*?</script>|<style.*?</style>|<[^>]+>", re.S | re.I)


def is_shortener(host: str | None) -> bool:
    h = (host or "").lower().rstrip(".")
    return (h[4:] if h.startswith("www.") else h) in SHORTENERS


def is_trusted_passthrough(host: str, registered_domain: str) -> bool:
    """Hosts that are never the destination to blame: shorteners, official sites and very popular
    sites (google.com/url?q=..., a Facebook link wrapper). Pages on free hosting are not exempt."""
    if is_shortener(host) or official_match(host):
        return True
    return bool(popularity_rank(registered_domain)) and not on_free_hosting(host)


def html_redirect(body: str) -> tuple[str | None, str | None]:
    """(target, 'meta'|'js') for a page that only exists to forward the visitor, else (None, None)."""
    tag = _META_TAG.search(body)
    if tag:
        m = _META_CONTENT.search(tag.group(0))
        if m and float(m.group(1)) <= 10:
            return html.unescape(m.group(2)), "meta"
    # A script that sets location on a real page is usually a button handler; a redirect stub has
    # almost no visible text.
    if len(re.sub(r"\s+", " ", _TAGS.sub(" ", body)).strip()) < 400:
        m = _JS_REDIRECT.search(body)
        if m:
            return (m.group(1) or m.group(2)).replace("\\/", "/"), "js"
    return None, None


def _hop(url: str, via: str) -> dict[str, Any]:
    return {"url": url[:2048], "host": host_of(url), "status": None, "via": via}


def _never_fetch(host: str) -> bool:
    h = host.lower()
    return bool(official_match(h)) or any(h == d or h.endswith("." + d) for d in DEMO_INTEL)


async def _fetch_next(client: httpx.AsyncClient, url: str, timeout: float,
                      allow_get: bool) -> tuple[int | None, str | None, str | None]:
    """One hop: (status, next_url, via). HEAD first; GET only when HEAD cannot answer."""
    status: int | None = None
    try:
        r = await client.head(url, timeout=timeout)
        status = r.status_code
        if 300 <= status < 400 and r.headers.get("location"):
            return status, r.headers["location"], "http"
        ctype = r.headers.get("content-type", "")
        want_body = allow_get and (status >= 400 or not ctype or "html" in ctype)
    except httpx.TimeoutException:
        raise
    except httpx.HTTPError:
        if not allow_get:
            raise
        want_body = True
    if not want_body:
        return status, None, None
    async with client.stream("GET", url, timeout=timeout) as r:
        status = r.status_code
        if 300 <= status < 400 and r.headers.get("location"):
            return status, r.headers["location"], "http"
        ctype = r.headers.get("content-type", "")
        if ctype and "html" not in ctype:
            return status, None, None
        chunks, size = [], 0
        async for chunk in r.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= BODY_LIMIT:
                break
    nxt, via = html_redirect(b"".join(chunks)[:BODY_LIMIT].decode("utf-8", "replace"))
    return status, nxt, via


async def resolve_chain(url: str, max_hops: int = 8, timeout: float = 5.0, *, fast: bool = False) -> list[dict[str, Any]]:
    """Follow url to its real destination. Returns the hops in order, the input first:
    {url, host, status, via: input|http|meta|js|param} plus note (loop, blocked_private, timeout,
    unreachable, max_hops) on the hop where the chain was cut.

    fast=True is for the browser extension's instant check: the network is only used to expand a
    shortener (HEAD requests, a short overall deadline). Redirect parameters are always unwrapped
    (no network needed)."""
    cur = urldefrag(url.strip()).url
    hops = [_hop(cur, "input")]
    seen = {cur}
    network = TRANSPORT is not None or not settings.offline_mode
    deadline = time.monotonic() + (4.0 if fast else 12.0)
    expanding = False
    client: httpx.AsyncClient | None = None
    try:
        while True:
            hop = hops[-1]
            nxt, via = unwrap_url(cur, depth=1)[0], "param"
            if nxt == cur:
                nxt = via = None
                host = hop["host"]
                if not network or not host or _never_fetch(host) or (fast and not (expanding or is_shortener(host))):
                    break
                safe, _ = await host_is_safe_target(host)
                if not safe:
                    hop["note"] = "blocked_private"
                    break
                remaining = deadline - time.monotonic()
                if remaining < 0.2:
                    hop["note"] = "timeout"
                    break
                if client is None:
                    client = httpx.AsyncClient(
                        follow_redirects=False, verify=False, transport=TRANSPORT,
                        headers={"User-Agent": USER_AGENT, "Accept-Language": "ar-AE,ar;q=0.9,en-US;q=0.8,en;q=0.7",
                                 "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"})
                popular = bool(popularity_rank(regdom(host) or host))
                try:
                    hop["status"], nxt, via = await _fetch_next(
                        client, cur, min(timeout, remaining),
                        allow_get=is_shortener(host) or not (fast or popular))
                except httpx.TimeoutException:
                    hop["note"] = "timeout"
                    break
                except (httpx.HTTPError, ValueError, UnicodeError):
                    hop["note"] = "unreachable"
                    break
                expanding = True
            if not nxt:
                break
            try:
                nxt = urldefrag(urljoin(cur, nxt.strip())).url
                scheme = urlsplit(nxt).scheme.lower()
            except ValueError:
                break
            if scheme not in ("http", "https") or not host_of(nxt):
                break
            if nxt in seen:
                hop["note"] = "loop"
                break
            if len(hops) > max_hops:
                hop["note"] = "max_hops"
                break
            seen.add(nxt)
            cur = nxt
            hops.append(_hop(cur, via or "http"))
    finally:
        if client is not None:
            await client.aclose()
    return hops


def distinct_hosts(hops: list[dict[str, Any]]) -> list[str]:
    return list(dict.fromkeys(h["host"] for h in hops if h.get("host")))


def flags_for(hops: list[dict[str, Any]], input_host: str, judged_host: str, verdict: str) -> list[RedFlag]:
    """Evidence flags for a link that does not stay on its own website. They carry no points: the
    risk comes from the destination, which is what the verdict is about."""
    hosts = distinct_hosts(hops)
    if len(hosts) < 2:
        return []
    out: list[RedFlag] = []
    if judged_host != input_host and verdict != "SAFE":
        out.append(RedFlag(
            "REDIRECTS_TO_FLAGGED", "high", 0,
            f"The link you received ({input_host}) is a disguise: it really leads to {judged_host}, "
            f"which Saqr flags as dangerous.",
            f"الرابط الذي وصلك ({input_host}) مجرد واجهة: يقود فعلياً إلى {judged_host} الذي يصنّفه صقر موقعاً خطيراً."))
    short = next((h for h in hosts if is_shortener(h)), None)
    if short:
        out.append(RedFlag(
            "URL_SHORTENER", "info", 0,
            f"The link was shortened with {short}, which hides the real address. Saqr followed it to {hosts[-1]}.",
            f"تم اختصار الرابط عبر {short} مما يخفي العنوان الحقيقي. تتبّعه صقر حتى {hosts[-1]}."))
    if len(hosts) > 2 or not short:
        path = " → ".join(hosts[:6])
        out.append(RedFlag(
            "REDIRECT_CHAIN", "info", 0,
            f"The link passes through {len(hosts) - 1} redirect(s) across different websites: {path}.",
            f"يمر الرابط عبر {len(hosts) - 1} تحويل(ات) بين مواقع مختلفة: {path}."))
    return out
