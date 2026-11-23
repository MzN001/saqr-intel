r"""Personal email model "email-v1" — a tiny per-citizen spam filter that learns from their own labels.

The citizen labels an email "scam" or "not a scam"; this model learns which words, senders and
signals THEY see in each kind of mail and adds a personal opinion (p_scam) to later scans.

Privacy: the model stores COUNTS ONLY — integers per hashed bucket — never mail text, subjects or
addresses (a sender is kept as an 8-hex-digit FNV hash). It can be downloaded, imported and erased.

This file is the Python half of a pair: extension/lib/email_features.js + user_model.js implement
the very same maths (frozen contract, section 4). tests/fixtures/model_vectors.json is the parity
oracle both sides must reproduce, so change NOTHING here without changing the JS twin and the vectors.

Feature recipe (contract section 4):
    tokens(s): NFKC -> lowercase -> strip invisible / bidi characters -> split on anything that is
               not a Unicode letter (\p{L}) or number (\p{N}) -> keep tokens of 2..30 CODE POINTS
               (JS must count code points, not UTF-16 units: "𐌰" is 1 code point but .length 2).
    feature strings: "fd:" sender regdom, "fx:1|0" freemail, "rd:same|diff|none" reply-to,
               "dn:" display-name tokens, "s:" subject tokens, "b:" first 300 body tokens,
               "ld:" first 20 link regdoms, "a:spf=", "a:dkim=", "a:dmarc=", "f:" flag codes.
    bucket   = FNV-1a-32(UTF-8 bytes) & 0xFFFF ;  features = sorted unique buckets.

Classifier: Bernoulli-style naive Bayes over the PRESENT features only, plus a per-sender prior,
available once the citizen has labelled >= 10 scams AND >= 10 normal emails.
"""
from __future__ import annotations

import math
import re
import unicodedata
from datetime import datetime, timezone
from typing import Any, Iterable

SPEC = "email-v1"
FORMAT = "saqr-user-model"
VERSION = 1
BUCKETS = 65536
MIN_DOCS = 10  # per class, before the model gives an opinion
MAX_BODY_TOKENS = 300
MAX_LINK_DOMAINS = 20
MIN_TOKEN_LEN, MAX_TOKEN_LEN = 2, 30  # in Unicode code points
LOGIT_CLAMP = 30.0
SCAM_FLAG_P = 0.9  # USER_MODEL_SCAM when p_scam >= this
TRUSTED_FLAG_P = 0.1  # USER_MODEL_TRUSTED when p_scam <= this

# Characters removed before tokenising: soft hyphen, combining grapheme joiner, zero-width
# space/non-joiner/joiner, LRM/RLM, bidi embeddings/overrides, word joiner + invisible operators +
# bidi isolates, BOM. Same class as the campaign matcher (contract section 3).
_STRIP_RE = re.compile("[\u00ad\u034f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")

# Two-label public suffixes after which the registered domain is the last THREE labels.
# A fixed list on purpose (no tldextract), so Python and JS always agree.
THREE_LABEL_SUFFIXES = frozenset("""
co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.za co.in co.jp co.kr com.br com.mx com.tr
com.sa com.eg com.kw com.qa com.bh com.om com.pk com.sg com.my com.hk com.cn gov.ae co.ae ac.ae
net.ae org.ae sch.ae mil.ae
""".split())

FREEMAIL = frozenset("""
gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com icloud.com
me.com aol.com proton.me protonmail.com gmx.com mail.com zoho.com yandex.com yandex.ru mail.ru
""".split())

_LONE_SURROGATE_RE = re.compile("[\ud800-\udfff]")

# Exactly what JavaScript's String.prototype.trim() removes (Python's str.strip() differs: it keeps
# U+FEFF and also removes U+001C..U+001F and U+0085), so trimming agrees with the JS twin.
_JS_WS = "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a" \
         "\u2028\u2029\u202f\u205f\u3000\ufeff"
_ANGLE_RE = re.compile(r"<([^<>]*)>")


# ---------------------------------------------------------------------------
# Hashing + text helpers (must match the JS twin bit for bit)
# ---------------------------------------------------------------------------
def _utf8(s: str) -> bytes:
    # JSON can smuggle in a lone surrogate (e.g. "\ud83d"); JS TextEncoder turns it into U+FFFD,
    # so do the same instead of crashing.
    return _LONE_SURROGATE_RE.sub("\ufffd", s).encode("utf-8")


def fnv1a32(s: str) -> int:
    """32-bit FNV-1a over the UTF-8 bytes of s."""
    h = 0x811C9DC5
    for byte in _utf8(s):
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def bucket(feature: str) -> int:
    return fnv1a32(feature) & 0xFFFF


def _s(v: Any) -> str:
    return "" if v is None else str(v)


def _trim(s: str) -> str:
    return s.strip(_JS_WS)


def sender_key(from_address: str | None) -> str:
    """Key of the per-sender prior: FNV-1a-32 (8 lowercase hex digits) of the trimmed, lowercased address."""
    return format(fnv1a32(_trim(_s(from_address)).lower()), "08x")


def _has_sender(from_address: str | None) -> bool:
    # An empty address (pasted text without a From line) is NOT a sender: otherwise every such
    # email would share one fake "sender" and its prior. Same rule in the JS twin.
    return _trim(_s(from_address)) != ""


def _is_letter_or_number(ch: str) -> bool:
    # \p{L} = Lu Ll Lt Lm Lo ; \p{N} = Nd Nl No.  Combining marks (Mn/Mc, e.g. Arabic harakat)
    # are NOT letters, so they split words — same as the JS regex /[^\p{L}\p{N}]+/u.
    return unicodedata.category(ch)[0] in "LN"


def tokens(s: str | None) -> list[str]:
    """NFKC -> lowercase -> strip invisibles -> split on non letters/numbers -> keep 2..30 code points."""
    if not s:
        return []
    text = _STRIP_RE.sub("", unicodedata.normalize("NFKC", _s(s)).lower())
    out: list[str] = []
    cur: list[str] = []
    for ch in text + " ":  # trailing separator flushes the last token
        if _is_letter_or_number(ch):
            cur.append(ch)
            continue
        if cur:
            if MIN_TOKEN_LEN <= len(cur) <= MAX_TOKEN_LEN:  # len of a Python str = code points
                out.append("".join(cur))
            cur = []
    return out


def regdom(host: str | None) -> str:
    """Registered domain: trim, lowercase, drop trailing dots, keep the last 2 labels (3 after co.uk & co)."""
    h = _trim(_s(host)).lower().rstrip(".")
    labels = h.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in THREE_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _domain_of(address: str | None) -> str:
    """Host part of "a@b.com" or "Name <a@b.com>": text after the LAST '@', trimmed + lowercased;
    "" when there is no '@' (then there is no domain)."""
    a = _trim(_s(address))
    m = _ANGLE_RE.search(a)
    if m:
        a = _trim(m.group(1))
    at = a.rfind("@")
    return _trim(a[at + 1:]).lower() if at >= 0 else ""


def _flag_code(flag: Any) -> str:
    if isinstance(flag, dict):
        return str(flag.get("code") or "")
    return str(getattr(flag, "code", flag) or "")


# ---------------------------------------------------------------------------
# Features
# ---------------------------------------------------------------------------
def feature_strings(inp: dict[str, Any] | None) -> list[str]:
    """The binary feature SET of one email, sorted (for readable test vectors).

    inp = {from_address, from_name, reply_to, subject, body_text, link_domains[], auth:{spf,dkim,dmarc},
           flags[]} ; anything missing counts as "" / [] / "none".  flags may be codes or {code: ...}.
    Details the contract leaves open, settled identically in the JS twin (and pinned by the vectors):
    an address without '@' has no domain; "rd:none" whenever the reply-to has no domain; trailing dots
    and surrounding whitespace are dropped from hosts; empty flag codes are skipped.
    """
    inp = inp or {}
    from_dom = regdom(_domain_of(inp.get("from_address")))
    reply_dom = regdom(_domain_of(inp.get("reply_to")))
    rd = "none" if not reply_dom else ("same" if reply_dom == from_dom else "diff")
    auth = inp.get("auth") if isinstance(inp.get("auth"), dict) else {}

    feats: set[str] = {
        "fd:" + from_dom,
        "fx:1" if from_dom in FREEMAIL else "fx:0",
        "rd:" + rd,
        "a:spf=" + (_s(auth.get("spf")) or "none"),
        "a:dkim=" + (_s(auth.get("dkim")) or "none"),
        "a:dmarc=" + (_s(auth.get("dmarc")) or "none"),
    }
    feats.update("dn:" + t for t in tokens(inp.get("from_name")))
    feats.update("s:" + t for t in tokens(inp.get("subject")))
    feats.update("b:" + t for t in tokens(inp.get("body_text"))[:MAX_BODY_TOKENS])
    links = inp.get("link_domains")
    feats.update("ld:" + regdom(d) for d in (links if isinstance(links, list) else [])[:MAX_LINK_DOMAINS])
    flags = inp.get("flags")
    feats.update("f:" + c for c in map(_flag_code, flags if isinstance(flags, list) else []) if c)
    return sorted(feats)


def features(inp: dict[str, Any] | None) -> list[int]:
    """Sorted unique bucket numbers (0..65535) — what a scan stores as "model_features"."""
    return sorted({bucket(s) for s in feature_strings(inp)})


def clean_features(feats: Iterable[Any]) -> list[int]:
    """Sorted unique valid buckets from untrusted input (stored scans, API bodies); drops junk."""
    out = set()
    for b in feats or []:
        if isinstance(b, int) and not isinstance(b, bool) and 0 <= b < BUCKETS:
            out.add(b)
    return sorted(out)


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------
def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def new_model() -> dict[str, Any]:
    return {"format": FORMAT, "version": VERSION, "spec": SPEC, "buckets": BUCKETS, "updated_at": _now(),
            "classes": {"scam": {"docs": 0, "total": 0, "counts": {}},
                        "ham": {"docs": 0, "total": 0, "counts": {}}},
            "senders": {}}


def labels(model: dict[str, Any] | None) -> int:
    """How many emails the citizen has labelled in total."""
    if not model:
        return 0
    c = model["classes"]
    return int(c["scam"]["docs"]) + int(c["ham"]["docs"])


def _check_label(label: str) -> None:
    if label not in ("scam", "ham"):
        raise ValueError('label must be "scam" or "ham"')


def train(model: dict[str, Any], feats: Iterable[int], label: str, from_address: str | None) -> dict[str, Any]:
    """Learn one labelled email (in place; also returned). feats = its model_features."""
    _check_label(label)
    fs = clean_features(feats)
    cls = model["classes"][label]
    cls["docs"] += 1
    counts = cls["counts"]
    for b in fs:
        k = str(b)
        counts[k] = counts.get(k, 0) + 1
    cls["total"] += len(fs)
    if _has_sender(from_address):
        s = model["senders"].setdefault(sender_key(from_address), {"scam": 0, "ham": 0})
        s[label] = s.get(label, 0) + 1
    model["updated_at"] = _now()
    return model


def untrain(model: dict[str, Any], feats: Iterable[int], label: str, from_address: str | None) -> dict[str, Any]:
    """Undo an earlier train() with the same arguments (used when a citizen changes a label).

    Never goes below zero, so undoing after an import/merge or a partial reset stays valid."""
    _check_label(label)
    fs = clean_features(feats)
    cls = model["classes"][label]
    if cls["docs"] <= 0:
        return model
    cls["docs"] -= 1
    counts = cls["counts"]
    removed = 0
    for b in fs:
        k = str(b)
        n = counts.get(k, 0)
        if n > 0:
            removed += 1
            if n == 1:
                del counts[k]
            else:
                counts[k] = n - 1
    cls["total"] = max(0, cls["total"] - removed)
    key = sender_key(from_address)
    s = model["senders"].get(key) if _has_sender(from_address) else None
    if s and s.get(label, 0) > 0:
        s[label] -= 1
        if not s.get("scam") and not s.get("ham"):
            del model["senders"][key]
    model["updated_at"] = _now()
    return model


def predict(model: dict[str, Any] | None, feats: Iterable[int], from_address: str | None) -> dict[str, Any]:
    """{available, p_scam, labels, spec}. p_scam is None until >= 10 scam AND >= 10 normal labels."""
    n = labels(model)
    if not model:
        return {"available": False, "p_scam": None, "labels": 0, "spec": SPEC}
    scam, ham = model["classes"]["scam"], model["classes"]["ham"]
    sd, hd = int(scam["docs"]), int(ham["docs"])
    if sd < MIN_DOCS or hd < MIN_DOCS:
        return {"available": False, "p_scam": None, "labels": n, "spec": SPEC}
    cs, ch = scam["counts"], ham["counts"]
    logit = math.log((sd + 1) / (hd + 1))
    for b in clean_features(feats):  # ascending order, same as the JS twin
        k = str(b)
        logit += math.log((cs.get(k, 0) + 1) / (sd + 2)) - math.log((ch.get(k, 0) + 1) / (hd + 2))
    s = model["senders"].get(sender_key(from_address)) if _has_sender(from_address) else None
    if s is not None:
        logit += math.log((s.get("scam", 0) + 1) / (s.get("ham", 0) + 1))
    logit = max(-LOGIT_CLAMP, min(LOGIT_CLAMP, logit))
    return {"available": True, "p_scam": 1.0 / (1.0 + math.exp(-logit)), "labels": n, "spec": SPEC}


def merge(a: dict[str, Any] | None, b: dict[str, Any] | None) -> dict[str, Any]:
    """A new model holding the counts of both (import = merge). Inputs are not changed."""
    out = new_model()
    for m in (a, b):
        if not m:
            continue
        for label in ("scam", "ham"):
            src, dst = m["classes"][label], out["classes"][label]
            dst["docs"] += int(src["docs"])
            dst["total"] += int(src["total"])
            for k, v in src["counts"].items():
                if v:
                    dst["counts"][k] = dst["counts"].get(k, 0) + int(v)
        for k, s in m["senders"].items():
            d = out["senders"].setdefault(k, {"scam": 0, "ham": 0})
            d["scam"] += int(s.get("scam", 0))
            d["ham"] += int(s.get("ham", 0))
    return out


def flag_for(p_scam: float | None) -> str | None:
    """Flag code the email rules add for a personal verdict (None when the model has no opinion)."""
    if p_scam is None:
        return None
    if p_scam >= SCAM_FLAG_P:
        return "USER_MODEL_SCAM"
    if p_scam <= TRUSTED_FLAG_P:
        return "USER_MODEL_TRUSTED"
    return None


# ---------------------------------------------------------------------------
# Strict validation of an uploaded model (PUT /api/email-model/{id})
# ---------------------------------------------------------------------------
_BUCKET_KEY_RE = re.compile(r"^(0|[1-9][0-9]{0,4})$")
_SENDER_KEY_RE = re.compile(r"^[0-9a-f]{8}$")
_MAX_COUNT = 10**9
MAX_SENDERS = 100_000
TOP_KEYS = {"format", "version", "spec", "buckets", "updated_at", "classes", "senders"}


def _int(v: Any, what: str, lo: int = 0, hi: int = _MAX_COUNT) -> int:
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise ValueError(f"{what} must be a whole number between {lo} and {hi}")
    return v


def validate_model(obj: Any) -> dict[str, Any]:
    """Check an imported model JSON strictly and return a clean copy. Raises ValueError (safe to show)."""
    if not isinstance(obj, dict):
        raise ValueError("This is not a SAQR model file.")
    if obj.get("format") != FORMAT:
        raise ValueError("This is not a SAQR model file (format must be saqr-user-model).")
    if obj.get("version") != VERSION or obj.get("spec") != SPEC or obj.get("buckets") != BUCKETS:
        raise ValueError("This model was made by a different SAQR version (needs version 1, spec email-v1, 65536 buckets).")
    extra = set(obj) - TOP_KEYS
    if extra:
        raise ValueError(f"Unknown field(s) in the model file: {', '.join(sorted(extra))[:200]}")
    updated = obj.get("updated_at", "")
    if not isinstance(updated, str) or len(updated) > 40:
        raise ValueError("updated_at must be a short date text")
    classes = obj.get("classes")
    if not isinstance(classes, dict) or set(classes) != {"scam", "ham"}:
        raise ValueError('classes must contain exactly "scam" and "ham"')

    out = new_model()
    out["updated_at"] = updated or out["updated_at"]
    for label in ("scam", "ham"):
        src = classes[label]
        if not isinstance(src, dict) or set(src) != {"docs", "total", "counts"}:
            raise ValueError(f'classes.{label} must have exactly "docs", "total" and "counts"')
        docs = _int(src["docs"], f"classes.{label}.docs")
        total = _int(src["total"], f"classes.{label}.total", hi=_MAX_COUNT * 10)
        counts = src["counts"]
        if not isinstance(counts, dict):
            raise ValueError(f"classes.{label}.counts must be an object")
        clean: dict[str, int] = {}
        for k, v in counts.items():
            if not isinstance(k, str) or not _BUCKET_KEY_RE.match(k) or int(k) >= BUCKETS:
                raise ValueError(f"classes.{label}.counts has a bad bucket number: {str(k)[:20]}")
            n = _int(v, f"classes.{label}.counts[{k}]", hi=docs)  # a bucket counts once per email
            if n:
                clean[k] = n
        out["classes"][label] = {"docs": docs, "total": total, "counts": clean}

    senders = obj.get("senders")
    if not isinstance(senders, dict):
        raise ValueError("senders must be an object")
    if len(senders) > MAX_SENDERS:
        raise ValueError("Too many senders in the model file.")
    for k, s in senders.items():
        if not isinstance(k, str) or not _SENDER_KEY_RE.match(k):
            raise ValueError(f"senders has a bad key: {str(k)[:20]}")
        if not isinstance(s, dict) or set(s) != {"scam", "ham"}:
            raise ValueError('each sender must have exactly "scam" and "ham"')
        sc = _int(s["scam"], f"senders[{k}].scam", hi=out["classes"]["scam"]["docs"])
        hm = _int(s["ham"], f"senders[{k}].ham", hi=out["classes"]["ham"]["docs"])
        if sc or hm:
            out["senders"][k] = {"scam": sc, "ham": hm}
    return out


# ---------------------------------------------------------------------------
# Storage: one row per citizen in the user_models table, keyed by a SHA-256 of the reporter_id
# (the raw id stays in the browser; the row holds counts only).
# ---------------------------------------------------------------------------
MAX_LABELLED = 5000  # remembered scan_id -> label pairs (so a relabel replaces, not adds)


def reporter_key(reporter_id: str) -> str:
    import hashlib

    return hashlib.sha256(("saqr-user-model:" + reporter_id).encode("utf-8")).hexdigest()


async def load_record(reporter_id: str) -> tuple[dict[str, Any] | None, dict[str, str]]:
    """(model or None, {scan_id: label}) for this citizen."""
    import json

    from ..db import db

    row = await db.fetchone("SELECT model_json, labelled_json FROM user_models WHERE reporter_hash=?",
                            (reporter_key(reporter_id),))
    if not row:
        return None, {}
    return json.loads(row["model_json"]), json.loads(row["labelled_json"] or "{}")


async def save_record(reporter_id: str, model: dict[str, Any], labelled: dict[str, str] | None = None) -> None:
    """Upsert the model; labelled=None keeps the stored scan-label record as it is."""
    import json

    from ..db import db

    model_json = json.dumps(model, separators=(",", ":"))
    key = reporter_key(reporter_id)
    if labelled is None:
        await db.execute(
            """INSERT INTO user_models (reporter_hash, model_json, labelled_json, updated_at) VALUES (?,?,'{}',?)
               ON CONFLICT(reporter_hash) DO UPDATE SET model_json=excluded.model_json, updated_at=excluded.updated_at""",
            (key, model_json, _now()))
        return
    if len(labelled) > MAX_LABELLED:  # dicts keep insertion order: drop the oldest labels
        labelled = dict(list(labelled.items())[-MAX_LABELLED:])
    await db.execute(
        """INSERT INTO user_models (reporter_hash, model_json, labelled_json, updated_at) VALUES (?,?,?,?)
           ON CONFLICT(reporter_hash) DO UPDATE SET model_json=excluded.model_json,
               labelled_json=excluded.labelled_json, updated_at=excluded.updated_at""",
        (key, model_json, json.dumps(labelled, separators=(",", ":")), _now()))


async def delete_record(reporter_id: str) -> bool:
    from ..db import db

    existed = await db.fetchone("SELECT 1 FROM user_models WHERE reporter_hash=?", (reporter_key(reporter_id),))
    await db.execute("DELETE FROM user_models WHERE reporter_hash=?", (reporter_key(reporter_id),))
    return bool(existed)


async def load(reporter_id: str) -> dict[str, Any] | None:
    """This citizen's model, or None if they never labelled anything."""
    model, _ = await load_record(reporter_id)
    return model


async def save(reporter_id: str, model: dict[str, Any]) -> None:
    await save_record(reporter_id, model)


async def predict_for(reporter_id: str | None, feats: Iterable[int], from_address: str | None) -> dict[str, Any]:
    """Personal opinion for one scan (used by the email pipeline). Never raises: no id / no model /
    a database hiccup all mean "no opinion"."""
    if not reporter_id:
        return predict(None, feats, from_address)
    try:
        model = await load(reporter_id)
    except Exception:  # noqa: BLE001 — the personal model is optional extra evidence
        model = None
    return predict(model, feats, from_address)
