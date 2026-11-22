"""Generate the extension's toolbar icons (16, 48, 128 px PNG) with the Python standard library only.

Draws the SAQR-INTEL mark: a deep-navy rounded square with a gold ring, a gold shield and an
emerald check — the same look as the /citizen header logo.

Run from the repository root:   python extension/generate_icons.py
"""
from __future__ import annotations

import struct
import zlib
from pathlib import Path

NAVY = (11, 25, 44)
GOLD = (197, 165, 114)
EMERALD = (16, 185, 129)
SIZES = (16, 48, 128)
SUPERSAMPLE = 4
OUT_DIR = Path(__file__).resolve().parent / "icons"


def _rounded_square(x: float, y: float, radius: float) -> bool:
    cx = min(max(x, radius), 1 - radius)
    cy = min(max(y, radius), 1 - radius)
    return (x - cx) ** 2 + (y - cy) ** 2 <= radius ** 2


def _shield(x: float, y: float) -> bool:
    """Shield outline in unit coordinates: flat top, straight sides, pointed bottom."""
    top, mid, bottom = 0.22, 0.52, 0.84
    half_w = 0.27
    if y < top or y > bottom or abs(x - 0.5) > half_w:
        return False
    if y <= mid:
        return True
    # Taper from full width at `mid` to a point at `bottom` along a gentle curve.
    t = (y - mid) / (bottom - mid)
    return abs(x - 0.5) <= half_w * (1 - t ** 1.6)


def _segment_distance(px: float, py: float, ax: float, ay: float, bx: float, by: float) -> float:
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((px - ax) * dx + (py - ay) * dy) / (dx * dx + dy * dy)))
    return ((px - ax - t * dx) ** 2 + (py - ay - t * dy) ** 2) ** 0.5


def _check(x: float, y: float, thickness: float) -> bool:
    a, b, c = (0.39, 0.52), (0.47, 0.61), (0.63, 0.43)
    return min(_segment_distance(x, y, *a, *b), _segment_distance(x, y, *b, *c)) <= thickness


def _pixel(x: float, y: float, size: int) -> tuple[int, int, int, int]:
    if not _rounded_square(x, y, 0.22):
        return (0, 0, 0, 0)
    ring = 0.055 if size >= 48 else 0.0
    if ring and not _rounded_square((x - ring) / (1 - 2 * ring), (y - ring) / (1 - 2 * ring), 0.2):
        return (*GOLD, 255)
    if _shield(x, y):
        # Shield body in gold, inner area navy so the check reads clearly at small sizes.
        inner = _shield(0.5 + (x - 0.5) / 0.78, 0.22 + (y - 0.25) / 0.8)
        if size >= 48 and _check(x, y, 0.045):
            return (*EMERALD, 255)
        if size >= 48 and inner:
            return (*NAVY, 255)
        return (*GOLD, 255)
    return (*NAVY, 255)


def render(size: int) -> bytes:
    rows = []
    n = SUPERSAMPLE
    for py in range(size):
        row = bytearray([0])  # PNG filter type 0 (none)
        for px in range(size):
            r = g = b = a = 0
            for sy in range(n):
                for sx in range(n):
                    x = (px + (sx + 0.5) / n) / size
                    y = (py + (sy + 0.5) / n) / size
                    pr, pg, pb, pa = _pixel(x, y, size)
                    r += pr * pa
                    g += pg * pa
                    b += pb * pa
                    a += pa
            if a:
                row += bytes((r // a, g // a, b // a, a // (n * n)))
            else:
                row += bytes((0, 0, 0, 0))
        rows.append(bytes(row))
    return _png(size, size, b"".join(rows))


def _png(width: int, height: int, raw: bytes) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    header = struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0)  # 8-bit RGBA
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(raw, 9)) + chunk(b"IEND", b"")


def main() -> None:
    OUT_DIR.mkdir(exist_ok=True)
    for size in SIZES:
        path = OUT_DIR / f"icon{size}.png"
        path.write_bytes(render(size))
        print(f"wrote {path.relative_to(OUT_DIR.parent.parent)} ({size}x{size}, {path.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
