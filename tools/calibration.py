"""Probability calibration for the URL model (standard library only: runs in either venv).

The raw model score is trained on class-balanced data, so "0.96" is a ranking score, not a frequency.
This module fits a monotone map raw -> calibrated on the VALIDATION split (never on a holdout set) and
exports it as a small lookup table {"x": [...], "y": [...]} that saqr/intel/url_model.py applies in pure
Python (piecewise-linear interpolation, clamped to the end points).

  isotonic  pool-adjacent-violators on (raw, label); the table holds the block edges
  platt     sigmoid(a * logit(raw) + b), sampled on a logit grid

choose() cross-fits both on two site-disjoint halves of the validation rows and keeps the one with the lower
Brier score on the half it did not see; the final table is then fitted on all validation rows.
"""
from __future__ import annotations

import math
import zlib
from bisect import bisect_right

EPS = 1e-6


def _logit(p: float) -> float:
    p = min(1 - EPS, max(EPS, p))
    return math.log(p / (1 - p))


def _sig(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-35.0, min(35.0, z))))


def apply(table: dict | None, p: float) -> float | None:
    """Calibrated probability for raw score p (same code as url_model.calibrate)."""
    if not table:
        return None
    xs, ys = table["x"], table["y"]
    if p <= xs[0]:
        return ys[0]
    if p >= xs[-1]:
        return ys[-1]
    i = bisect_right(xs, p) - 1
    x0, x1, y0, y1 = xs[i], xs[i + 1], ys[i], ys[i + 1]
    return y0 if x1 <= x0 else y0 + (y1 - y0) * (p - x0) / (x1 - x0)


def fit_isotonic(p: list[float], y: list[int], w: list[float] | None = None) -> dict:
    """Pool-adjacent-violators; table = (first, last) raw score of every block with the block mean."""
    order = sorted(range(len(p)), key=lambda i: p[i])
    w = w or [1.0] * len(p)
    blocks: list[list[float]] = []  # [sum_wy, sum_w, x_lo, x_hi]
    for i in order:
        blocks.append([w[i] * y[i], w[i], p[i], p[i]])
        while len(blocks) > 1 and blocks[-2][0] / blocks[-2][1] >= blocks[-1][0] / blocks[-1][1]:
            b = blocks.pop()
            a = blocks[-1]
            a[0] += b[0]
            a[1] += b[1]
            a[3] = b[3]
    xs: list[float] = []
    ys: list[float] = []
    for swy, sw, lo, hi in blocks:
        v = swy / sw
        for x in ((lo,) if hi == lo else (lo, hi)):
            if xs and x <= xs[-1]:
                x = xs[-1] + 1e-12
            xs.append(x)
            ys.append(v)
    return _compress({"method": "isotonic", "x": xs, "y": ys})


def fit_platt(p: list[float], y: list[int], iters: int = 50) -> dict:
    """Logistic regression of the label on logit(raw) (Newton's method, Platt's smoothed targets)."""
    z = [_logit(v) for v in p]
    n1 = sum(y)
    n0 = len(y) - n1
    t1, t0 = (n1 + 1) / (n1 + 2), 1 / (n0 + 2)
    t = [t1 if v else t0 for v in y]
    a, b = 1.0, 0.0
    for _ in range(iters):
        g_a = g_b = h_aa = h_ab = h_bb = 0.0
        for zi, ti in zip(z, t):
            q = _sig(a * zi + b)
            d = q - ti
            s = q * (1 - q) + 1e-12
            g_a += d * zi
            g_b += d
            h_aa += s * zi * zi
            h_ab += s * zi
            h_bb += s
        det = h_aa * h_bb - h_ab * h_ab
        if abs(det) < 1e-18:
            break
        da = (h_bb * g_a - h_ab * g_b) / det
        db = (h_aa * g_b - h_ab * g_a) / det
        a, b = a - da, b - db
        if abs(da) + abs(db) < 1e-9:
            break
    grid = [x / 10 for x in range(-140, 141)]
    xs = [_sig(g) for g in grid]
    ys = [_sig(a * g + b) for g in grid]
    return _compress({"method": "platt", "a": a, "b": b, "x": xs, "y": ys})


def _compress(table: dict, tol: float = 2e-4) -> dict:
    """Drop interior points that linear interpolation reproduces within tol (keeps the table small)."""
    xs, ys = table["x"], table["y"]
    if len(xs) <= 2:
        return table
    kx, ky = [xs[0]], [ys[0]]
    for i in range(1, len(xs) - 1):
        x0, y0 = kx[-1], ky[-1]
        x2, y2 = xs[i + 1], ys[i + 1]
        pred = y0 + (y2 - y0) * (xs[i] - x0) / (x2 - x0) if x2 > x0 else y0
        if abs(pred - ys[i]) > tol:
            kx.append(xs[i])
            ky.append(ys[i])
    kx.append(xs[-1])
    ky.append(ys[-1])
    for i in range(1, len(ky)):  # monotone by construction; guard against float noise
        ky[i] = max(ky[i], ky[i - 1])
    out = dict(table)
    out["x"] = [round(v, 9) for v in kx]
    out["y"] = [round(v, 6) for v in ky]
    for i in range(1, len(out["x"])):
        if out["x"][i] <= out["x"][i - 1]:
            out["x"][i] = out["x"][i - 1] + 1e-9
    return out


def brier(p: list[float], y: list[int]) -> float:
    return sum((a - b) ** 2 for a, b in zip(p, y)) / max(1, len(p))


def ece(p: list[float], y: list[int], bins: int = 15) -> float:
    """Expected calibration error, equal-width bins."""
    tot = [0.0] * bins
    pos = [0.0] * bins
    cnt = [0] * bins
    for a, b in zip(p, y):
        k = min(bins - 1, int(a * bins))
        tot[k] += a
        pos[k] += b
        cnt[k] += 1
    n = max(1, len(p))
    return sum(abs(tot[k] - pos[k]) for k in range(bins) if cnt[k]) / n


def reliability(p: list[float], y: list[int]) -> dict:
    return {"rows": len(p), "positives": int(sum(y)), "ece": round(ece(p, y), 4), "brier": round(brier(p, y), 4)}


def choose(p: list[float], y: list[int], groups: list[str]) -> tuple[dict, dict]:
    """(final table, report). Cross-fit on two site-disjoint halves, keep the lower held-out Brier."""
    half = [zlib.crc32(g.encode("utf-8", "ignore")) % 2 for g in groups]
    report: dict = {"raw": reliability(p, y)}
    for name, fit in (("isotonic", fit_isotonic), ("platt", fit_platt)):
        cal = [0.0] * len(p)
        for k in (0, 1):
            tr = [i for i in range(len(p)) if half[i] != k]
            tab = fit([p[i] for i in tr], [y[i] for i in tr])
            for i in range(len(p)):
                if half[i] == k:
                    cal[i] = apply(tab, p[i])
        report[name] = reliability(cal, y)
    best = min(("isotonic", "platt"), key=lambda m: report[m]["brier"])
    table = (fit_isotonic if best == "isotonic" else fit_platt)(p, y)
    report["chosen"] = best
    report["table_points"] = len(table["x"])
    return table, report
