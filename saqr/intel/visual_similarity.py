"""Optional screenshot similarity: 64-bit difference hash (dHash) of a page screenshot vs the official
portals' stored dHashes. similarity = 100 x (1 - hamming / 64).

It is CORROBORATION only. A whole-page hash is fragile (a cookie banner, a carousel slide or a loading
spinner changes it) and many pages share a white layout, so the brand fingerprint
(brand_fingerprint.py) is the primary signal; a matching hash only raises it.

Screenshot source, in order:
1. the sandbox's own Playwright screenshot (ENABLE_PLAYWRIGHT=true; JPEG, needs Pillow to decode);
2. https://image.thum.io (PNG, decoded by the pure-Python reader below, so no Pillow is needed);
3. https://s0.wp.com/mshots (JPEG, only when Pillow is installed; the first answer is a "generating"
   placeholder, retried once).

PRIVACY: steps 2 and 3 SEND THE SUSPICIOUS URL TO THOSE THIRD-PARTY SERVICES. That is why this runs
only for deep scans of non-official links that already look suspicious, never for SAFE / official /
private / loopback / /mock-scam/ addresses, never in OFFLINE_MODE, and can be switched off with
VISUAL_SCREENSHOTS=false. Everything fails silently within VISUAL_SCREENSHOT_TIMEOUT_SECONDS (<= 6 s).

Runtime cost: the thumbnail is requested 160 px wide (dHash only needs 9 x 8 pixels, and decoding a
1200 px PNG in pure Python would take seconds on a 0.1-CPU host); Pillow, if present, is imported
lazily inside decode only.
"""
from __future__ import annotations

import asyncio
import base64
import io
import logging
import struct
import time
import zlib
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

log = logging.getLogger("saqr.visual")

THUMB_WIDTH = 160
THUMIO_URL = "https://image.thum.io/get/png/width/%d/{url}" % THUMB_WIDTH
MSHOTS_URL = "https://s0.wp.com/mshots/v1/{encoded}?w=%d" % THUMB_WIDTH
IMAGE_LIMIT = 600_000
MAX_PIXELS = 1_000_000  # pure-Python decode budget (a 160 x 160 thumbnail is 25 600)
BROWSER_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
              "Chrome/131.0.0.0 Safari/537.36")
# Tests inject an httpx.MockTransport here.
TRANSPORT: httpx.AsyncBaseTransport | None = None
RETRY_DELAY_S = 1.5
# Measured on the captured baselines (2026-11-25): unrelated portals score 39-75 against each other, a
# re-capture of the same portal 100. Only >= 88 corroborates the fingerprint.
CORROBORATE_AT = 88


# ---------------------------------------------------------------------------
# Image decoding -> grayscale
# ---------------------------------------------------------------------------
def _paeth(a: int, b: int, c: int) -> int:
    p = a + b - c
    pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
    if pa <= pb and pa <= pc:
        return a
    return b if pb <= pc else c


def png_gray(data: bytes) -> tuple[int, int, list[int]] | None:
    """(width, height, grayscale pixels) of a non-interlaced 8-bit PNG (gray / RGB / palette / alpha),
    pure Python. None for anything else (16-bit, interlaced, too large, corrupt)."""
    if not data.startswith(b"\x89PNG\r\n\x1a\n"):
        return None
    pos, idat, palette = 8, [], b""
    width = height = depth = ctype = interlace = 0
    try:
        while pos + 8 <= len(data):
            length, kind = struct.unpack(">I4s", data[pos:pos + 8])
            chunk = data[pos + 8:pos + 8 + length]
            pos += 12 + length
            if kind == b"IHDR":
                width, height, depth, ctype, _, _, interlace = struct.unpack(">IIBBBBB", chunk)
            elif kind == b"PLTE":
                palette = chunk
            elif kind == b"IDAT":
                idat.append(chunk)
            elif kind == b"IEND":
                break
        if depth != 8 or interlace or not width or not height or width * height > MAX_PIXELS:
            return None
        channels = {0: 1, 2: 3, 3: 1, 4: 2, 6: 4}.get(ctype)
        if channels is None or (ctype == 3 and not palette):
            return None
        raw = zlib.decompress(b"".join(idat))
    except (struct.error, zlib.error, ValueError):
        return None
    stride = width * channels
    if len(raw) < height * (stride + 1):
        return None
    prev = bytearray(stride)
    gray: list[int] = []
    bpp = channels
    for y in range(height):
        off = y * (stride + 1)
        ftype = raw[off]
        line = bytearray(raw[off + 1: off + 1 + stride])
        if ftype == 1:
            for i in range(bpp, stride):
                line[i] = (line[i] + line[i - bpp]) & 0xFF
        elif ftype == 2:
            for i in range(stride):
                line[i] = (line[i] + prev[i]) & 0xFF
        elif ftype == 3:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ftype == 4:
            for i in range(stride):
                left = line[i - bpp] if i >= bpp else 0
                up_left = prev[i - bpp] if i >= bpp else 0
                line[i] = (line[i] + _paeth(left, prev[i], up_left)) & 0xFF
        elif ftype != 0:
            return None
        prev = line
        if ctype == 0:
            gray.extend(line)
        elif ctype == 4:
            gray.extend(line[0::2])
        elif ctype == 3:
            for idx in line:
                r, g, b = palette[idx * 3: idx * 3 + 3] or b"\0\0\0"
                gray.append((r * 299 + g * 587 + b * 114) // 1000)
        else:
            for i in range(0, stride, channels):
                gray.append((line[i] * 299 + line[i + 1] * 587 + line[i + 2] * 114) // 1000)
    return width, height, gray


def _pillow_gray(data: bytes) -> tuple[int, int, list[int]] | None:
    try:
        from PIL import Image  # lazy: optional dependency, only for JPEG sources
    except ImportError:
        return None
    try:
        with Image.open(io.BytesIO(data)) as im:
            im.draft("L", (THUMB_WIDTH * 2, THUMB_WIDTH * 2))  # JPEG: decode at reduced size
            g = im.convert("L")
            g.thumbnail((THUMB_WIDTH, THUMB_WIDTH * 4))
            return g.width, g.height, list(g.getdata())
    except Exception:  # noqa: BLE001
        return None


def decode_gray(data: bytes) -> tuple[int, int, list[int]] | None:
    if not data:
        return None
    return png_gray(data) if data.startswith(b"\x89PNG") else _pillow_gray(data)


# ---------------------------------------------------------------------------
# dHash
# ---------------------------------------------------------------------------
def dhash_gray(width: int, height: int, gray: list[int]) -> int | None:
    """9 x 8 area-averaged grid of the top square of the image (thum.io and Playwright frames have
    different heights), each bit = left pixel brighter than its right neighbour. None for a blank /
    nearly uniform image (a loading spinner, an empty single-page app shell)."""
    side = min(width, height)
    cols, rows = 9, 8
    sums = [0] * (cols * rows)
    counts = [0] * (cols * rows)
    for y in range(side):
        ry = y * rows // side
        base = y * width
        for x in range(side):
            idx = ry * cols + x * cols // side
            sums[idx] += gray[base + x]
            counts[idx] += 1
    cells = [s / c if c else 0 for s, c in zip(sums, counts)]
    if max(cells) - min(cells) < 8:
        return None
    bits = 0
    for r in range(rows):
        for c in range(cols - 1):
            bits = (bits << 1) | (1 if cells[r * cols + c] > cells[r * cols + c + 1] else 0)
    return bits


def dhash_bytes(data: bytes) -> int | None:
    decoded = decode_gray(data)
    return dhash_gray(*decoded) if decoded else None


def hamming(a: int, b: int) -> int:
    return bin(a ^ b).count("1")


def similarity(a: int | str, b: int | str) -> int:
    a_i = int(a, 16) if isinstance(a, str) else a
    b_i = int(b, 16) if isinstance(b, str) else b
    return int(round(100 * (1 - hamming(a_i, b_i) / 64)))


def to_hex(h: int) -> str:
    return f"{h:016x}"


# ---------------------------------------------------------------------------
# Screenshots
# ---------------------------------------------------------------------------
def eligible(url: str) -> bool:
    """Never for official / private / loopback / own hosts or the /mock-scam/ replicas."""
    from ..seed_data import DEMO_INTEL, _is_own_host
    from .domain_intel import official_match

    try:
        parts = urlsplit(url)
    except ValueError:
        return False
    host = (parts.hostname or "").lower()
    if not host or parts.scheme not in ("http", "https") or "/mock-scam/" in (parts.path or ""):
        return False
    if _is_own_host(host) or official_match(host) or host.endswith((".local", ".localhost", ".internal")):
        return False
    if any(host == d or host.endswith("." + d) for d in DEMO_INTEL):
        return False
    try:
        import ipaddress

        ip = ipaddress.ip_address(host)
        return ip.is_global
    except ValueError:
        return True


async def _get(client: httpx.AsyncClient, url: str, deadline: float) -> httpx.Response | None:
    remaining = deadline - time.monotonic()
    if remaining < 0.3:
        return None
    try:
        r = await asyncio.wait_for(client.get(url), timeout=remaining)
    except Exception:  # noqa: BLE001
        return None
    if len(r.content) > IMAGE_LIMIT:
        return None
    return r


def _is_mshots_placeholder(r: httpx.Response) -> bool:
    ctype = r.headers.get("content-type", "")
    return (300 <= r.status_code < 400 and "default" in r.headers.get("location", "")) \
        or "gif" in ctype or "/mshots/v1/default" in str(r.url)


async def capture_hash(url: str, page: dict[str, Any] | None = None, timeout: float = 6.0) -> dict[str, Any] | None:
    """{"hash": hex, "source": playwright|thumio|mshots} or None. Silent on every failure."""
    from ..config import settings

    timeout = max(0.5, min(6.0, timeout))
    shot = (page or {}).get("screenshot_b64")
    if shot:
        try:
            h = dhash_bytes(base64.b64decode(shot))
        except (ValueError, TypeError):
            h = None
        if h is not None:
            return {"hash": to_hex(h), "source": "playwright"}
    if (settings.offline_mode and TRANSPORT is None) or not eligible(url):
        return None
    deadline = time.monotonic() + timeout
    try:
        async with httpx.AsyncClient(follow_redirects=False, transport=TRANSPORT, timeout=timeout,
                                     headers={"User-Agent": BROWSER_UA}) as client:
            r = await _get(client, THUMIO_URL.format(url=url), deadline)
            if r is not None and r.status_code == 200 and "image" in r.headers.get("content-type", ""):
                h = dhash_bytes(r.content)
                if h is not None:
                    return {"hash": to_hex(h), "source": "thumio"}
            try:
                import PIL  # noqa: F401  # lazy probe: mshots answers JPEG
            except ImportError:
                return None
            mshots = MSHOTS_URL.format(encoded=quote(url, safe=""))
            for attempt in range(2):
                r = await _get(client, mshots, deadline)
                if r is None:
                    return None
                if not _is_mshots_placeholder(r) and r.status_code == 200:
                    h = dhash_bytes(r.content)
                    return {"hash": to_hex(h), "source": "mshots"} if h is not None else None
                if attempt == 0 and deadline - time.monotonic() > RETRY_DELAY_S + 0.5:
                    await asyncio.sleep(RETRY_DELAY_S)
                else:
                    return None
    except Exception as exc:  # noqa: BLE001
        log.debug("screenshot capture failed: %s", exc)
    return None


def best_screenshot_match(probe: dict[str, Any] | None, baselines: tuple[dict[str, Any], ...],
                          host: str | None = None) -> dict[str, Any] | None:
    """Most similar official screenshot captured by the SAME source (like with like)."""
    if not probe:
        return None
    best = None
    for b in baselines:
        if host and any(host == d or host.endswith("." + d) for d in b.get("official_domains") or []):
            continue
        ref = (b.get("dhash") or {}).get(probe["source"] if probe["source"] != "playwright" else "thumio")
        if not ref:
            continue
        sim = similarity(probe["hash"], ref)
        if best is None or sim > best["score"]:
            best = {"id": b["id"], "score": sim}
    return best
