"""Email Unicode-trick detector (pure, offline, no I/O).

Scammers hide fake brand names from filters and from people with Unicode tricks:

* look-alike letters from another alphabet   "PаyPal" (Cyrillic "а"), "аdcb-secure.com"
* punycode / international domain names     xn--dcb-secure-yqi.test  ->  аdcb-secure.test
* invisible characters inside a word        "Pay​Pal" (zero-width space)
* right-to-left override in a file name     "Invoice_‮fdp.exe" shows as "Invoice_exe.pdf"
* "fancy" styled letters                    "𝐏𝐚𝐲𝐏𝐚𝐥" (mathematical bold), "ＰａｙＰａｌ" (full-width)

Each scan_* function returns a list of *findings* (frozen contract, section 2):

    {"where": "from.domain|from.address|reply_to|return_path|subject|display_name|body|link|attachment",
     "kind": "punycode|mixed_script|whole_script_confusable|invisible|bidi|fancy",
     "sample_escaped": "P\\u0430yPal",   # the suspicious text with every non-ASCII char escaped
     "skeleton": "paypal"}               # what it looks like to a person (Latin skeleton)

email_rules turns findings into red flags. What is NEVER reported (real mail is full of it):
ordinary Arabic / Persian / any non-Latin text, ZWNJ / ZWJ / LRM / RLM next to Arabic or Indic
letters, emoji ZWJ sequences, "preheader padding" (runs of invisible characters next to spaces or
at line ends) and soft hyphens used for word hyphenation.
"""
from __future__ import annotations

import re
import unicodedata
from functools import lru_cache
from typing import Any

from .domain_intel import CONFUSABLES, skeleton as _domain_skeleton, to_unicode_host

# ---------------------------------------------------------------------------
# Character classes
# ---------------------------------------------------------------------------
# Invisible characters scammers put inside words (contract: U+200B-200D, 2060, FEFF, 00AD, 034F).
INVISIBLE = frozenset("​‌‍⁠﻿­͏")
# Bidirectional embedding / override / isolate controls (U+202A-202E, U+2066-2069).
BIDI = frozenset("‪‫‬‭‮⁦⁧⁨⁩")
# The two that really reverse what you see: LEFT-TO-RIGHT / RIGHT-TO-LEFT OVERRIDE.
BIDI_OVERRIDES = frozenset("‭‮")
SOFT_HYPHEN = "­"
# Everything stripped before brand / campaign matching (the contract's norm() set).
STRIP_RE = re.compile("[­͏​-‏‪-‮⁠-⁩﻿]")
INVISIBLE_RUN = re.compile("[​‌‍⁠﻿­͏]+")
BIDI_RE = re.compile("[‪-‮⁦-⁩]")
# A "word": letters, digits, combining marks and the invisible characters hidden inside them.
TOKEN_RE = re.compile("[\\ẁ-ͯ­͏​-‍⁠﻿]+")
URL_SPAN = re.compile(r"(?:https?://|www\.)[^\s<>\"']+", re.I)

# Letters of other alphabets that look like Latin letters (Unicode TR39 confusables most used in
# phishing; upper and lower case), mapped to the Latin letter a person sees. Extends
# domain_intel.CONFUSABLES, which only lists the lower-case ones used in domain names.
LOOKALIKE: dict[str, str] = {
    **CONFUSABLES,
    # Cyrillic
    "А": "a", "В": "b", "Е": "e", "К": "k", "М": "m", "Н": "h", "О": "o", "Р": "p", "С": "c", "Т": "t",
    "Х": "x", "У": "y", "І": "i", "Ј": "j", "Ѕ": "s", "Ԛ": "q", "Ԝ": "w", "Ү": "y", "Һ": "h", "Ӏ": "l",
    "Ԁ": "d", "Ѵ": "v", "ԛ": "q", "ү": "y", "ѵ": "v", "ӏ": "l",
    # Greek
    "Α": "a", "Β": "b", "Ε": "e", "Ζ": "z", "Η": "h", "Ι": "i", "Κ": "k", "Μ": "m", "Ν": "n", "Ο": "o",
    "Ρ": "p", "Τ": "t", "Υ": "y", "Χ": "x", "Ϲ": "c", "ϲ": "c", "ϳ": "j", "χ": "x", "γ": "y",
    # Armenian
    "օ": "o", "Օ": "o", "Ս": "u", "հ": "h", "զ": "q", "ց": "g",
    # Cherokee capitals
    "Ꭺ": "a", "Ᏼ": "b", "Ꮯ": "c", "Ꭰ": "d", "Ꭼ": "e", "Ꮐ": "g", "Ꮋ": "h", "Ꭻ": "j", "Ꮶ": "k", "Ꮮ": "l",
    "Ꮇ": "m", "Ꮲ": "p", "Ꮪ": "s", "Ꭲ": "t", "Ꮩ": "v", "Ꮃ": "w", "Ꮓ": "z",
}
# Scripts whose letters are used to fake Latin text.
CONFUSABLE_SCRIPTS = frozenset({"Cyrillic", "Greek", "Armenian", "Cherokee", "Coptic"})
# Chinese / Japanese / Korean scripts are mixed with each other (and with Latin) in normal names.
CJK_WORDS = frozenset({"CJK", "HIRAGANA", "KATAKANA", "HANGUL", "BOPOMOFO", "IDEOGRAPHIC"})
# Styled "fancy" letters that normalise to plain Latin letters (math bold, full-width, circled ...).
FANCY_NAME = re.compile(r"^(MATHEMATICAL |FULLWIDTH LATIN |CIRCLED LATIN |NEGATIVE CIRCLED LATIN |"
                        r"PARENTHESIZED LATIN |SQUARED LATIN |NEGATIVE SQUARED LATIN |BLACK-LETTER |"
                        r"DOUBLE-STRUCK |SCRIPT (SMALL|CAPITAL) |LATIN LETTER SMALL CAPITAL )")

MAX_FINDINGS = 40  # per scan_* call; a hostile mail cannot blow up the response
MAX_SAMPLE = 80

ADDRESS_WHERES = frozenset({"from.domain", "from.address", "reply_to", "return_path", "link"})
TEXT_WHERES = frozenset({"subject", "display_name", "body", "attachment"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
@lru_cache(maxsize=4096)
def script_of(ch: str) -> str | None:
    """Writing system of a letter ("Latin", "Cyrillic", "Arabic", "Cjk", ...); None for digits,
    punctuation, marks, emoji and other characters shared by every script."""
    if not unicodedata.category(ch).startswith("L"):
        return None
    norm = unicodedata.normalize("NFKC", ch)
    if len(norm) == 1:
        if norm.isascii():
            return "Latin"  # styled letters (math bold P, full-width P, Kelvin sign) look Latin
        ch = norm
    words = unicodedata.name(ch, "").split()
    if words and words[0] in ("FULLWIDTH", "HALFWIDTH"):
        words = words[1:]
    if not words:
        return None
    if words[0] in CJK_WORDS:
        return "Cjk"
    if words[0] == "MODIFIER":
        return None
    return words[0].capitalize()


def is_fancy(ch: str) -> bool:
    """A styled letter/digit (math bold, full-width, circled ...) that normalises to plain ASCII."""
    if ch.isascii():
        return False
    norm = unicodedata.normalize("NFKC", ch)
    if not (norm.isascii() and norm.isalnum()):
        return False
    return bool(FANCY_NAME.match(unicodedata.name(ch, "")))


def escape(s: str, limit: int = MAX_SAMPLE) -> str:
    """Printable ASCII kept, everything else as \\uXXXX (\\UXXXXXXXX outside the BMP)."""
    out = []
    for ch in s[:limit]:
        o = ord(ch)
        if 32 <= o < 127:
            out.append(ch)
        elif o <= 0xFFFF:
            out.append(f"\\u{o:04x}")
        else:
            out.append(f"\\U{o:08x}")
    return "".join(out) + ("..." if len(s) > limit else "")


def strip_invisible(s: str) -> str:
    """Remove invisible and bidi control characters (and LRM/RLM)."""
    return STRIP_RE.sub("", s or "")


def deconfuse(text: str) -> str:
    """Text as a person reads it: invisible/bidi characters removed, styled letters normalised
    (NFKC) and look-alike Cyrillic/Greek letters replaced by the Latin letter they imitate.
    Used for brand / campaign matching ("PаyPal" -> "PayPal")."""
    t = unicodedata.normalize("NFKC", strip_invisible(text or ""))
    return "".join(LOOKALIKE.get(ch, ch) for ch in t)


def text_skeleton(s: str) -> str:
    """Latin skeleton of a word as a person sees it (no leetspeak folding: "Invoice_88412" stays)."""
    t = unicodedata.normalize("NFKD", deconfuse(s)).lower()
    t = "".join(ch for ch in t if not unicodedata.combining(ch))
    return "".join(CONFUSABLES.get(ch, ch) for ch in t)


def host_skeleton(unicode_host: str) -> str:
    """Latin skeleton of a host name (look-alikes and leetspeak folded, as domain_intel does)."""
    return _domain_skeleton("".join(LOOKALIKE.get(ch, ch) for ch in strip_invisible(unicode_host)))


def _letters(s: str) -> list[str]:
    return [ch for ch in s if unicodedata.category(ch).startswith("L")]


def _maps_to_latin(ch: str) -> bool:
    """Would a person read this letter as a plain Latin letter?"""
    if ch in LOOKALIKE:
        return True
    t = unicodedata.normalize("NFKD", ch)
    t = "".join(c for c in t if not unicodedata.combining(c))
    return bool(t) and t.isascii()


def _latinish(ch: str | None) -> bool:
    """Latin letter or ASCII digit (the neighbours that make an invisible character a trick)."""
    if not ch:
        return False
    if ch.isascii():
        return ch.isalnum()
    return script_of(ch) == "Latin"


def _finding(where: str, kind: str, sample: str, skel: str) -> dict[str, Any]:
    return {"where": where, "kind": kind, "sample_escaped": escape(sample), "skeleton": skel[:MAX_SAMPLE]}


def _dedupe(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen: set[tuple[str, str, str]] = set()
    out = []
    for f in findings:
        key = (f["where"], f["kind"], f["sample_escaped"])
        if key not in seen:
            seen.add(key)
            out.append(f)
        if len(out) >= MAX_FINDINGS:
            break
    return out


@lru_cache(maxsize=1)
def _brand_words() -> frozenset[str]:
    """Brand names / keywords (4+ letters) that a word written fully in look-alikes may imitate."""
    from .registry import ALL_BRANDS

    words: set[str] = set()
    for ent in ALL_BRANDS:
        for w in (ent.name_en, *ent.keywords, *ent.common_keywords):
            w = re.sub(r"[^a-z0-9]", "", w.lower())
            if len(w) >= 4:
                words.add(w)
    return frozenset(words)


# ---------------------------------------------------------------------------
# Per-token checks (shared by text and addresses)
# ---------------------------------------------------------------------------
def _token_confusable(token: str) -> str | None:
    """'mixed_script' for a Latin-looking word containing Cyrillic/Greek/... look-alike letters,
    'whole_script_confusable' for a word written fully in look-alikes that spells a brand."""
    clean = strip_invisible(token)
    letters = _letters(clean)
    if len(letters) < 2:
        return None
    scripts = {script_of(ch) for ch in letters} - {None}
    others = scripts - {"Latin"}
    if not others or not (others & CONFUSABLE_SCRIPTS):
        return None
    # Every letter must still read as Latin: a Russian word with one Latin letter, or "αβc",
    # is not a disguised Latin word; "PаyPal" is.
    if not all(_maps_to_latin(ch) for ch in letters):
        return None
    if "Latin" in scripts:
        return "mixed_script"
    skel = re.sub(r"[^a-z0-9]", "", text_skeleton(clean))
    return "whole_script_confusable" if skel in _brand_words() else None


def _word_around(text: str, start: int, end: int) -> str:
    """The whole word (token) containing text[start:end]."""
    for m in TOKEN_RE.finditer(text, max(0, start - 64), min(len(text), end + 64)):
        if m.start() <= start and m.end() >= end:
            return m.group(0)
    return text[max(0, start - 20):end + 20]


def _invisible_hits(text: str) -> list[tuple[int, int]]:
    """Spans of invisible characters used as tricks in free text: a run with a Latin letter or
    digit on BOTH sides ("Pay​Pal"). Runs next to spaces, line ends, Arabic/Indic letters or
    emoji are normal. A soft hyphen between Latin letters is normal hyphenation unless the joined
    word is a brand name."""
    hits = []
    for m in INVISIBLE_RUN.finditer(text):
        prev = text[m.start() - 1] if m.start() > 0 else None
        nxt = text[m.end()] if m.end() < len(text) else None
        if not (_latinish(prev) and _latinish(nxt)):
            continue
        if set(m.group(0)) == {SOFT_HYPHEN}:
            word = _word_around(text, m.start(), m.end())
            if re.sub(r"[^a-z0-9]", "", text_skeleton(word)) not in _brand_words():
                continue
        hits.append((m.start(), m.end()))
    return hits


def _context(text: str, start: int, end: int, pad: int = 16) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    return text[a:b].replace("\n", " ").replace("\r", " ")


def _skip_controls(text: str, i: int, step: int) -> str | None:
    """First character from position i (going by step) that is not an invisible/bidi control."""
    while 0 <= i < len(text):
        ch = text[i]
        if ch not in INVISIBLE and ch not in BIDI and ch not in "‎‏":
            return ch
        i += step
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def scan_text(text: str | None, where: str) -> list[dict[str, Any]]:
    """Scan free text: a subject, display name, body or attachment file name.

    Reports look-alike words, invisible characters inside words, right-to-left overrides next to
    Latin text (any bidi control in a file name), styled letters, and invisible / bidi characters
    inside any URL written in the text."""
    if not text:
        return []
    text = text[:250_000]
    out: list[dict[str, Any]] = []

    # 1. Look-alike letters inside a Latin-looking word
    for m in TOKEN_RE.finditer(text):
        tok = m.group(0)
        if tok.isascii():
            continue
        kind = _token_confusable(tok)
        if kind:
            out.append(_finding(where, kind, strip_invisible(tok), text_skeleton(tok)))
            if len(out) >= MAX_FINDINGS:
                break

    # 2. Invisible characters inside words
    for a, b in _invisible_hits(text):
        word = _word_around(text, a, b)
        out.append(_finding(where, "invisible", word, text_skeleton(word)))

    # 3. Invisible / bidi characters inside URLs written in the text
    for m in URL_SPAN.finditer(text):
        url = m.group(0).rstrip(".,;:!?)")
        if any(ch in INVISIBLE for ch in url):
            out.append(_finding(where, "invisible", url, strip_invisible(url).lower()))
        if any(ch in BIDI for ch in url):
            out.append(_finding(where, "bidi", url, strip_invisible(url).lower()))

    # 4. Bidi controls
    for m in BIDI_RE.finditer(text):
        ch = m.group(0)
        if where == "attachment":
            hit = True  # a file name never needs one ("Invoice_‮fdp.exe")
        elif ch in BIDI_OVERRIDES:
            hit = (_latinish(_skip_controls(text, m.start() - 1, -1))
                   or _latinish(_skip_controls(text, m.end(), 1)))
        else:
            hit = False  # embeddings / isolates around right-to-left text are normal formatting
        if hit:
            if where == "attachment":
                sample = text
            else:
                sample = _word_around(text, m.start(), m.end())
                if len(strip_invisible(sample).strip()) < 2:
                    sample = _context(text, m.start(), m.end())
            out.append(_finding(where, "bidi", sample, strip_invisible(sample).lower()))

    # 5. Styled "fancy" letters (needs a few of them: one decorative symbol is not a trick)
    fancy_tokens = [m.group(0) for m in TOKEN_RE.finditer(text) if any(is_fancy(c) for c in m.group(0))]
    if sum(sum(1 for c in t if is_fancy(c)) for t in fancy_tokens) >= 3:
        for tok in fancy_tokens[:5]:
            out.append(_finding(where, "fancy", tok, text_skeleton(tok)))
    return _dedupe(out)


def scan_domain(host: str | None, where: str) -> list[dict[str, Any]]:
    """Scan a domain name (ASCII/punycode or Unicode).

    * every international (xn-- / non-ASCII) domain -> "punycode"
    * a label mixing writing systems ("аdcb-secure": Cyrillic + Latin) -> "mixed_script"
    * a label written fully in look-alike letters ("аррӏе") -> "whole_script_confusable"
    * invisible / bidi characters in the name -> "invisible" / "bidi"
    Chinese/Japanese/Korean labels mixing their own scripts (and Latin) are allowed (UTS #39).
    """
    h = (host or "").strip().strip("[]<>").rstrip(".")
    if not h:
        return []
    if "@" in h:
        h = h.rsplit("@", 1)[1]
    h = h[:253]
    out: list[dict[str, Any]] = []
    if any(ch in INVISIBLE for ch in h):
        out.append(_finding(where, "invisible", h, strip_invisible(h).lower()))
    if any(ch in BIDI for ch in h):
        out.append(_finding(where, "bidi", h, strip_invisible(h).lower()))
    h = strip_invisible(h).lower()
    uhost = to_unicode_host(h) if h.isascii() else unicodedata.normalize("NFC", h)
    if "xn--" not in h and uhost.isascii():
        return out
    skel = host_skeleton(uhost)
    for label in uhost.split("."):
        letters = _letters(label)
        scripts = {script_of(ch) for ch in letters} - {None}
        if len(scripts) > 1 and not scripts <= {"Cjk", "Latin"}:
            out.append(_finding(where, "mixed_script", uhost, skel))
            break
        if (len(letters) >= 2 and scripts and scripts != {"Latin"}
                and all(ch in LOOKALIKE for ch in letters)):
            out.append(_finding(where, "whole_script_confusable", uhost, skel))
            break
    out.append(_finding(where, "punycode", uhost, skel))
    return _dedupe(out)


def scan_address(address: str | None, where: str) -> list[dict[str, Any]]:
    """Scan an email address. Domain findings of the From address use where="from.domain"; every
    other address keeps its own where for both parts. Any invisible or bidi character in an
    address is a trick (no real address needs one)."""
    a = (address or "").strip().strip("<>")
    if not a:
        return []
    local, at, domain = a.rpartition("@")
    if not at:
        local, domain = a, ""
    out: list[dict[str, Any]] = []
    if local:
        if any(ch in INVISIBLE for ch in local):
            out.append(_finding(where, "invisible", local, strip_invisible(local).lower()))
        if any(ch in BIDI for ch in local):
            out.append(_finding(where, "bidi", local, strip_invisible(local).lower()))
        for part in re.split(r"[._+\-]", strip_invisible(local)):
            kind = _token_confusable(part) if part and not part.isascii() else None
            if kind:
                out.append(_finding(where, kind, local, text_skeleton(local)))
                break
    if domain:
        out += scan_domain(domain, "from.domain" if where == "from.address" else where)
    return _dedupe(out)


def scan_url(url: str | None, where: str = "link") -> list[dict[str, Any]]:
    """Scan a link: any invisible / bidi character anywhere in it, plus its host name."""
    u = (url or "").strip()
    if not u:
        return []
    out: list[dict[str, Any]] = []
    if any(ch in INVISIBLE for ch in u):
        out.append(_finding(where, "invisible", u, strip_invisible(u).lower()))
    if any(ch in BIDI for ch in u):
        out.append(_finding(where, "bidi", u, strip_invisible(u).lower()))
    clean = strip_invisible(u)
    m = re.match(r"^(?:[a-z][a-z0-9+.-]*:)?//([^/?#\s]+)", clean, re.I)
    netloc = m.group(1) if m else clean.split("/", 1)[0]
    host = re.sub(r":\d+$", "", netloc.rsplit("@", 1)[-1])
    out += scan_domain(host, where)
    return _dedupe(out)
