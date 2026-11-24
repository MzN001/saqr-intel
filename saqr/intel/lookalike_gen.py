"""Look-alike domain generator for the proactive hunter.

For every official UAE entity it lists the addresses a scammer is most likely to register next:
typos (a dropped, swapped, doubled or fat-fingered letter), look-alike characters (0 for o, rn for m,
Cyrillic letters), hyphenated names, brand + lure words (tamm-fine-pay, uaepass-verify,
adcb-secure-login) and the same name on the cheap domain endings scammers abuse.

Pure standard library and fully deterministic: the same call always returns the same list in the
same order, so the hunter can sweep it in slices. An official or trusted domain is never returned.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from itertools import zip_longest

from .registry import ENTITIES, OFFICIAL_DOMAINS, Entity

TECHNIQUES = ("tld_swap", "brand_lure", "hyphenation", "omission", "transposition", "doubling", "homoglyph",
              "insertion")
# Endings seen most in phishing reports, cheapest first after the classic three.
ABUSED_TLDS = ("com", "net", "org", "info", "xyz", "top", "online", "site", "live", "shop", "click", "vip",
               "app", "co", "icu", "cfd", "sbs", "link", "help", "support")
COMBO_TLDS = ("com", "net", "info", "xyz", "top", "online", "site", "live", "shop", "click")
TYPO_TLDS = ("com", "net")
OPEN_ENDINGS = frozenset({"ae", "com", "net", "org"})  # anyone can register here (unlike .gov.ae / .abudhabi)
LURES_BY_CATEGORY: dict[str, tuple[str, ...]] = {
    "government": ("fines", "fine-pay", "pay", "payment", "refund", "services", "portal", "verify", "gov", "online"),
    "identity": ("verify", "login", "auth", "update", "secure", "account", "verification", "signin", "app", "id"),
    "bank": ("secure", "secure-login", "login", "verify", "card-verify", "update", "online", "account", "kyc", "rewards"),
    "courier": ("track", "tracking", "parcel", "delivery", "redelivery", "customs", "pay", "fee", "uae", "post"),
    "telecom": ("rewards", "prize", "bill", "pay", "recharge", "points", "offer", "verify", "login", "account"),
}
COMBO_PATTERNS = ("{brand}-{lure}", "{lure}-{brand}", "{brand}{lure}", "{brand}-uae-{lure}", "my-{brand}-{lure}")
ASCII_HOMOGLYPHS: dict[str, tuple[str, ...]] = {
    "o": ("0",), "l": ("1", "i"), "i": ("1", "l"), "e": ("3",), "a": ("4",), "s": ("5",), "m": ("rn",),
    "w": ("vv",), "d": ("cl",), "u": ("v",), "n": ("m",), "b": ("d",), "t": ("7",),
}
UNICODE_HOMOGLYPHS = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с", "i": "і", "s": "ѕ"}
KEYBOARD_NEIGHBOURS = {
    "a": "sq", "b": "vn", "c": "xv", "d": "sf", "e": "wr", "f": "dg", "g": "fh", "h": "gj", "i": "uo", "j": "hk",
    "k": "jl", "l": "k", "m": "n", "n": "bm", "o": "ip", "p": "o", "q": "w", "r": "et", "s": "ad", "t": "ry",
    "u": "yi", "v": "cb", "w": "qe", "x": "zc", "y": "tu", "z": "x",
}
MIN_TYPO_LEN = 5  # shorter names (du, fab, tamm, adcb) collide with real words: tam, tammy, adc
_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


@dataclass(frozen=True)
class Candidate:
    domain: str
    entity_id: str
    technique: str
    base: str  # the official name the candidate imitates


def is_official(domain: str) -> bool:
    d = domain.lower().rstrip(".")
    return any(d == o or d.endswith("." + o) for o in OFFICIAL_DOMAINS)


def official_labels(entity: Entity) -> list[tuple[str, str]]:
    """(registrable label, ending) of each official domain: tamm.abudhabi -> ("tamm", "abudhabi")."""
    out = []
    for d in entity.domains:
        label, _, suffix = d.partition(".")
        out.append((label, suffix))
    return out


def brand_names(entity: Entity) -> list[str]:
    """Official labels first, then the registry's brand keywords, without duplicates."""
    names = [label for label, _ in official_labels(entity)] + list(entity.keywords)
    return list(dict.fromkeys(n.lower() for n in names if n))


def typo_roots(entity: Entity) -> list[str]:
    return [n for n in brand_names(entity) if "-" not in n and len(n) >= MIN_TYPO_LEN]


def omissions(name: str) -> list[str]:
    return [name[:i] + name[i + 1:] for i in range(len(name))]


def transpositions(name: str) -> list[str]:
    return [name[:i] + name[i + 1] + name[i] + name[i + 2:] for i in range(len(name) - 1) if name[i] != name[i + 1]]


def doublings(name: str) -> list[str]:
    return [name[:i] + name[i] + name[i:] for i in range(len(name))]


def insertions(name: str) -> list[str]:
    return [name[:i + 1] + k + name[i + 1:] for i, ch in enumerate(name) for k in KEYBOARD_NEIGHBOURS.get(ch, "")]


def hyphenations(name: str) -> list[str]:
    return [name[:i] + "-" + name[i:] for i in range(2, len(name) - 1)]


def homoglyphs(name: str) -> list[str]:
    """ASCII swaps first (0 for o, rn for m), then one Cyrillic letter as a punycode label."""
    out = [name[:i] + sub + name[i + 1:] for i, ch in enumerate(name) for sub in ASCII_HOMOGLYPHS.get(ch, ())]
    for i, ch in enumerate(name):
        twin = UNICODE_HOMOGLYPHS.get(ch)
        if twin:
            try:
                out.append((name[:i] + twin + name[i + 1:]).encode("idna").decode("ascii"))
            except UnicodeError:
                continue
    return out


def _typo_domains(entity: Entity, variants) -> list[tuple[str, str]]:
    own_endings = [suffix for _, suffix in official_labels(entity) if suffix in OPEN_ENDINGS]
    endings = list(dict.fromkeys([*own_endings, *TYPO_TLDS]))
    return [(f"{label}.{tld}", root) for root in typo_roots(entity) for label in variants(root) for tld in endings]


def _tld_swaps(entity: Entity) -> list[tuple[str, str]]:
    return [(f"{label}.{tld}", label) for tld in ABUSED_TLDS for label, _ in official_labels(entity)]


def _brand_lures(entity: Entity) -> list[tuple[str, str]]:
    lures = LURES_BY_CATEGORY.get(entity.category, LURES_BY_CATEGORY["government"])
    combos = []
    for bi, brand in enumerate(brand_names(entity)):
        for li, lure in enumerate(lures):
            for pi, pattern in enumerate(COMBO_PATTERNS):
                for ti, tld in enumerate(COMBO_TLDS):
                    # diagonal order: a small cap still mixes brands, lure words, shapes and endings
                    combos.append((bi + li + pi + ti, bi, li, pi, ti,
                                   f"{pattern.format(brand=brand, lure=lure)}.{tld}", brand))
    combos.sort()
    return [(domain, brand) for *_, domain, brand in combos]


def _valid(domain: str) -> bool:
    labels = domain.split(".")
    return len(domain) <= 253 and len(labels) >= 2 and all(_LABEL.match(lab) for lab in labels)


def generate(entity: Entity, max_count: int = 300) -> list[Candidate]:
    """Up to max_count look-alike candidates for one entity, techniques interleaved so that a small
    cap still covers every technique."""
    if max_count <= 0:
        return []
    by_technique = {
        "tld_swap": _tld_swaps(entity),
        "brand_lure": _brand_lures(entity),
        "hyphenation": _typo_domains(entity, hyphenations),
        "omission": _typo_domains(entity, omissions),
        "transposition": _typo_domains(entity, transpositions),
        "doubling": _typo_domains(entity, doublings),
        "homoglyph": _typo_domains(entity, homoglyphs),
        "insertion": _typo_domains(entity, insertions),
    }
    out: list[Candidate] = []
    seen: set[str] = set()
    for row in zip_longest(*(by_technique[t] for t in TECHNIQUES)):
        for technique, item in zip(TECHNIQUES, row):
            if item is None:
                continue
            domain, base = item
            if domain in seen or not _valid(domain) or is_official(domain):
                continue
            seen.add(domain)
            out.append(Candidate(domain, entity.id, technique, base))
            if len(out) >= max_count:
                return out
    return out


def generate_all(max_per_brand: int = 300, entities: tuple[Entity, ...] = ENTITIES) -> list[Candidate]:
    """Candidates for every entity, interleaved brand by brand; a domain is listed once."""
    per_entity = [generate(e, max_per_brand) for e in entities]
    out: list[Candidate] = []
    seen: set[str] = set()
    for row in zip_longest(*per_entity):
        for cand in row:
            if cand is not None and cand.domain not in seen:
                seen.add(cand.domain)
                out.append(cand)
    return out
