"""SAQR's phishing URL model v2: scores a FULL address (host + path + query), pure Python at runtime.

Two stages, both trained offline by tools/train_url_model.py (see docs/MODEL_CARD.md for data and
measured accuracy):
1. Logistic regression over hashed character n-grams and tokens, with separate namespaces for the
   host, the path and the query (each block normalised on its own, so a deep link does not dilute
   the host evidence). File: url_model.bin (int16 weights).
2. Gradient-boosted trees (LightGBM, exported to JSON) over ~50 named, human-readable features from
   url_features.py plus the stage-1 score. A small tree walker runs them here; the same walk gives
   per-feature contributions, which become the plain-language reasons shown to citizens.
If the tree file is missing, stage 1 alone is used.
"""
from __future__ import annotations

import json
import math
import re
import struct
import zlib
from array import array
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote

from . import url_features as uf
from .url_features import FREE_HOSTING, FEATURES, parse

__all__ = ["FREE_HOSTING", "available", "phishing_probability", "score_url", "features", "normalise_host"]

MODEL_PATH = Path(__file__).with_name("url_model.bin")
TREES_PATH = Path(__file__).with_name("url_model_trees.json")
METRICS_PATH = Path(__file__).with_name("data") / "model_metrics.json"
MAGIC = b"SQM2"
N_BITS = 19
N_FEATURES = 1 << N_BITS
STAGE1 = "s1_logit"
PATH_CAP = 80
QUERY_CAP = 120


def normalise_host(host: str) -> str:
    h = (host or "").strip().lower().rstrip(".")
    h = re.sub(r"^www\d*\.", "", h)
    return h.split(":")[0]


def _h(token: str) -> int:
    return zlib.crc32(token.encode("utf-8", "ignore")) & (N_FEATURES - 1)


def _block(tokens: list[str]) -> dict[int, float]:
    out: dict[int, float] = {}
    for t in tokens:
        i = _h(t)
        out[i] = out.get(i, 0.0) + 1.0
    norm = math.sqrt(sum(v * v for v in out.values())) or 1.0
    return {k: v / norm for k, v in out.items()}


def _shape(tok: str) -> str:
    """Token shape: 'a8x0d1' -> 'mix8', 'login' -> 'w', '2024' -> 'd4'."""
    if tok.isdigit():
        return f"d{min(len(tok), 9)}"
    if tok.isalpha():
        return "w" if len(tok) <= 12 else f"W{min(len(tok) // 8, 6)}"
    return f"mix{min(len(tok) // 4, 9)}"


def host_tokens(p: uf.Parts) -> list[str]:
    h = p.host
    out: list[str] = []
    s = f"^{h}$"
    for n in (3, 4, 5):
        out.extend(f"c{n}:{s[i:i + n]}" for i in range(len(s) - n + 1))
    out.append(f"tld:{h.rsplit('.', 1)[-1] if '.' in h else ''}")
    out.append(f"sfx:{p.suffix}")
    if p.platform:
        out += ["free_hosting", f"platform:{p.platform}"]
        own = h[: -len(p.platform) - 1] if h != p.platform else ""
        labels = own.split(".") if own else []
    else:
        labels = (p.sub.split(".") if p.sub else []) + [p.label]
    for lab in labels:
        for t in re.split(r"[-_]", lab):
            if t:
                out.append(f"tok:{t}")
                if t in uf.LURE_WORDS:
                    out.append("lure")
                if re.fullmatch(r"[a-z]*\d+[a-z\d]*", t) and re.search(r"[a-z]", t):
                    out.append("alnum_mix")
    out += [f"len:{min(len(h) // 8, 10)}", f"labels:{min(len(h.split('.')), 7)}",
            f"hyphens:{min(h.count('-'), 6)}", f"digits:{min(sum(c.isdigit() for c in h), 8)}"]
    if uf._IPV4.match(h):
        out.append("raw_ip")
    if "xn--" in h:
        out.append("punycode")
    return out


def path_tokens(p: uf.Parts) -> list[str]:
    path = unquote(p.path)[:PATH_CAP].lower()
    if not path:
        return []
    out = [f"p3:{path[i:i + 3]}" for i in range(len(path) - 2)]
    segs = [s for s in path.split("/") if s]
    out.append(f"pdepth:{min(len(segs), 8)}")
    if segs:
        out.append(f"p1:{segs[0][:24]}")
        last = segs[-1]
        if "." in last:
            out.append(f"pext:{last.rsplit('.', 1)[-1][:8]}")
    for t in uf.tokens_of(path):
        out.append(f"pt:{t}" if len(t) <= 20 else f"pshape:{_shape(t)}")
        out.append(f"ps:{_shape(t)}")
    return out


def query_tokens(p: uf.Parts) -> list[str]:
    q = p.query[:QUERY_CAP]
    if not q:
        return []
    out = [f"qn:{min(q.count('&') + 1, 8)}"]
    for kv in q.split("&"):
        k, _, val = kv.partition("=")
        out.append(f"qk:{k.lower()[:20]}")
        val = unquote(val).lower()
        if "http" in val or "www." in val:
            out.append("qv:url")
        elif "@" in val:
            out.append("qv:email")
        elif val:
            out.append(f"qv:{_shape(val)}")
    return out


def hashed(url: str) -> dict[int, float]:
    """Sparse stage-1 vector: host, path and query namespaces, each normalised to unit length."""
    p = parse(url)
    feats = _block(host_tokens(p))
    for block in (_block(path_tokens(p)), _block(query_tokens(p))):
        for k, v in block.items():
            feats[k] = feats.get(k, 0.0) + v
    return feats


def features(host: str) -> dict[int, float]:
    """Stage-1 vector of a bare hostname (kept for callers of the v1 API)."""
    return hashed(normalise_host(host))


@lru_cache(maxsize=1)
def _linear() -> tuple[array, float, float] | None:
    if not MODEL_PATH.exists():
        return None
    raw = MODEL_PATH.read_bytes()
    if raw[:4] != MAGIC:
        return None
    bits, scale, bias = struct.unpack("<iff", raw[4:16])
    if bits != N_BITS:
        return None
    w = array("h")
    w.frombytes(raw[16: 16 + 2 * N_FEATURES])
    return w, scale, bias


@lru_cache(maxsize=1)
def _trees() -> dict | None:
    if not TREES_PATH.exists():
        return None
    model = json.loads(TREES_PATH.read_text(encoding="utf-8"))
    if model.get("features") != [*FEATURES, STAGE1]:
        return None
    return model


def available() -> bool:
    return _linear() is not None


def stage1_logit(url: str) -> float | None:
    m = _linear()
    if not m:
        return None
    w, scale, bias = m
    return bias + scale * sum(w[i] * v for i, v in hashed(url).items())


def _sigmoid(z: float) -> float:
    return 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, z))))


def _walk(model: dict, x: list[float]) -> tuple[float, list[float]]:
    """Raw tree-ensemble score and per-feature contributions (Saabas: value change along the path)."""
    contrib = [0.0] * len(x)
    raw = 0.0
    for tree in model["trees"]:
        feat, thr, left, right, value = tree
        node = 0
        while feat[node] >= 0:
            f = feat[node]
            nxt = left[node] if x[f] <= thr[node] else right[node]
            contrib[f] += value[nxt] - value[node]
            node = nxt
        raw += value[node]
    return raw, contrib


@lru_cache(maxsize=4096)
def _score(url: str) -> tuple[float, tuple[tuple[str, float], ...], str] | None:
    s1 = stage1_logit(url)
    if s1 is None:
        return None
    trees = _trees()
    if not trees:
        return _sigmoid(s1), (), "linear"
    x, _ctx = uf.extract(url)
    x.append(s1)
    raw, contrib = _walk(trees, x)
    names = trees["features"]
    top = sorted(((names[i], c) for i, c in enumerate(contrib) if c > 0), key=lambda t: -t[1])
    # Named, human-readable evidence first; the n-gram score ("looks like known phishing") last.
    named = [t for t in top if t[0] not in (STAGE1, "pop_bucket") and t[1] >= 0.05]
    return _sigmoid(raw), tuple(named + [t for t in top if t not in named]), "ensemble"


def score_url(url: str, max_reasons: int = 3) -> dict | None:
    """{probability, reasons: [{feature, en, ar, weight}], stage} for a full URL, None without a model."""
    res = _score(url)
    if res is None:
        return None
    prob, top, stage = res
    _x, ctx = uf.extract(url)
    if stage == "linear":
        top = tuple((n, 1.0) for n in _fallback_order(_x))
    reasons = []
    for name, weight in top:
        text = reason_text(name, _x, ctx)
        if text and all(r["en"] != text[0] for r in reasons):
            reasons.append({"feature": name, "en": text[0], "ar": text[1], "weight": round(weight, 3)})
        if len(reasons) >= max_reasons:
            break
    return {"probability": prob, "reasons": reasons, "stage": stage}


@lru_cache(maxsize=4096)
def phishing_probability(host: str) -> float | None:
    """0..1 probability that this bare hostname is a phishing site (None if no model is installed)."""
    if not host:
        return None
    res = _score(normalise_host(host))
    return None if res is None else res[0]


_RISKY_ORDER = ("brand_in_sub", "brand_in_label", "brand_sim", "brand_common_in_host", "raw_ip", "at_userinfo",
                "punycode", "brand_in_path", "sensitive_path", "host_lures", "path_lures", "susp_tld",
                "email_in_url", "embedded_url", "ext_exe", "path_random_tokens", "free_hosting", "host_hyphens")


def _fallback_order(x: list[float]) -> list[str]:
    return [n for n in _RISKY_ORDER if x[uf.INDEX[n]] > 0] + [STAGE1]


def reason_text(name: str, x: list[float], ctx: dict) -> tuple[str, str] | None:
    """Plain-language EN / AR reason for one contributing feature (None = not worth showing)."""
    val = x[uf.INDEX[name]] if name in uf.INDEX else None
    brand, near, tld = ctx.get("brand"), ctx.get("brand_near"), ctx.get("tld") or ""
    reg = ctx.get("reg_domain") or ""
    if name == STAGE1:
        return ("the letter patterns of the address match known phishing addresses",
                "تشابه أنماط حروف العنوان عناوين تصيّد معروفة")
    if name in ("brand_in_sub", "brand_in_label", "brand_common_in_host") and val and brand:
        return (f'the address imitates "{brand}" on an unrelated domain ({reg})',
                f'العنوان يقلّد "{brand}" على نطاق لا علاقة له بها ({reg})')
    if name == "brand_in_path" and val and brand:
        return (f'"{brand}" appears in the page path of an unrelated site', f'يظهر اسم "{brand}" في مسار صفحة على موقع لا علاقة له به')
    if name == "brand_sim" and val and near:
        if val >= 0.999:
            return (f'look-alike letters imitate "{near}" ({ctx.get("host")})', f'أحرف مشابهة تقلّد "{near}" ({ctx.get("host")})')
        if ctx.get("own") == near:
            return (f'same name as "{near}" but a different domain ending (.{tld})', f'نفس اسم "{near}" ولكن بامتداد مختلف (.{tld})')
        return (f'the name is spelled almost like "{near}" ({round(val * 100)}% similar)',
                f'الاسم مكتوب بشكل قريب جداً من "{near}" (تشابه {round(val * 100)}٪)')
    words = list(dict.fromkeys((ctx.get("host_lures") or []) + (ctx.get("path_lures") or [])))
    if name in ("host_lures", "path_lures") and val and words:
        return (f"scam words in the address: {' + '.join(words[:3])}", f"كلمات احتيال في العنوان: {' + '.join(words[:3])}")
    if name == "sensitive_path" and val and ctx.get("sensitive"):
        s = " + ".join(ctx["sensitive"][:3])
        return (f"sensitive page words in the path: {s}", f"كلمات صفحات حساسة في المسار: {s}")
    if name == "susp_tld" and val:
        return (f"cheap domain ending .{tld.split('.')[-1]} often abused by scammers",
                f"امتداد رخيص .{tld.split('.')[-1]} يستغله المحتالون كثيراً")
    if name == "free_hosting" and val:
        return (f"hosted on a free website platform ({ctx.get('platform')})", f"مستضاف على منصة مواقع مجانية ({ctx.get('platform')})")
    if name == "raw_ip" and val:
        return ("the link points to a raw IP address, not a named website", "الرابط يشير إلى عنوان IP مباشر وليس إلى اسم موقع")
    if name == "punycode" and val:
        return ("the address uses encoded international look-alike letters", "يستخدم العنوان أحرفاً دولية مُرمّزة مشابهة")
    if name == "at_userinfo" and val:
        return ('an "@" trick hides the real site in the address', 'خدعة "@" تُخفي الموقع الحقيقي في العنوان')
    if name == "email_in_url" and val:
        return ("an e-mail address is built into the link (targeted phishing)", "عنوان بريد إلكتروني مُضمَّن في الرابط (تصيّد موجّه)")
    if name == "embedded_url" and val:
        return ("another web address is hidden inside the link", "عنوان ويب آخر مخفي داخل الرابط")
    if name == "ext_exe" and val:
        return (f"the link downloads a .{ctx.get('ext')} file", f"الرابط يُنزّل ملفاً بامتداد .{ctx.get('ext')}")
    if name == "ext_php" and val:
        return ("the link opens a .php script page", "الرابط يفتح صفحة برمجية .php")
    if name == "wp_path" and val:
        return ("the page sits inside a website's WordPress folders (often a hacked site)",
                "الصفحة داخل مجلدات ووردبريس لموقع آخر (غالباً موقع مخترق)")
    if name == "path_random_tokens" and val:
        return ("the path contains random-looking codes", "يحتوي المسار على رموز عشوائية")
    if name == "host_hyphens" and val and val >= 2:
        return (f"a long hyphenated name ({int(val)} hyphens) built to look official", f"اسم طويل مليء بالشرطات ({int(val)}) ليبدو رسمياً")
    if (name == "sub_depth" and val and val >= 3) or (name == "n_labels" and val and val >= 5):
        return ("an unusually deep chain of sub-domains hides the real site", "سلسلة نطاقات فرعية طويلة تُخفي الموقع الحقيقي")
    if name in ("host_len", "url_len") and val and val >= 40:
        return (f"an unusually long address ({int(val)} characters)", f"عنوان طويل بشكل غير معتاد ({int(val)} حرفاً)")
    if name in ("host_digit_ratio", "host_digit_letter_switches") and val and val > 0.1:
        return ("random-looking letters and digits in the site name", "أحرف وأرقام عشوائية في اسم الموقع")
    lab_ent, run = x[uf.INDEX["label_entropy"]], x[uf.INDEX["host_max_consonant_run"]]
    if name in ("label_entropy", "host_entropy", "host_max_consonant_run", "label_vowel_ratio") and (
            lab_ent >= 3.6 or run >= 5 or (x[uf.INDEX["label_vowel_ratio"]] < 0.15 and x[uf.INDEX["label_len"]] >= 6)):
        return ("the site name looks machine-generated", "يبدو اسم الموقع مُولَّداً آلياً")
    if name == "shortener" and val:
        return ("a link shortener hides the destination", "رابط مختصر يُخفي الوجهة الحقيقية")
    if name == "nonstd_port" and val:
        return ("the link uses an unusual network port", "يستخدم الرابط منفذ شبكة غير معتاد")
    if name == "pop_bucket" and not val:
        return ("the site is not among the 100,000 most visited websites", "الموقع ليس ضمن أكثر 100 ألف موقع زيارة")
    return None
