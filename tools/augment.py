"""Augmentation sets for the phishing-URL classifier -> datasets/augmented/*.csv (url,label,source,variant).

Standard library only, deterministic for a given --seed (the network harvest is cached in
datasets/augmented/harvest_cache.json; --refresh-harvest fetches again). Run in the runtime venv:

  .venv/bin/python -I tools/augment.py                # everything
  .venv/bin/python -I tools/augment.py --no-harvest   # offline parts only (uses the cache if present)

Files written (label 1 = phishing, 0 = legitimate):
  legit_deep_links.csv     real login / pay / account / service pages of UAE official sites, global brands
                           and a rank-spread Tranco sample (homepage + sitemap.xml, same site only)
  legit_free_hosting.csv   real sites on free hosting (github.io, blogspot.com ...) from the datasets' legit rows
                           (Tranco lists registrable domains only, so it adds almost none)
  legit_lure_hosts.csv     real popular hosts whose name contains a lure word (login, secure, pay ...)
  synthetic_phishing.csv   look-alike permutations of brand domains + real phishing-kit paths, source "synthetic"
  evasion_variants.csv     scheme / www / case / slash / percent-encoding / port / userinfo rewrites
"""
from __future__ import annotations

import argparse
import csv
import http.client
import json
import random
import re
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, urljoin, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(1, str(ROOT))
import url_datasets  # noqa: E402
from url_datasets import has_path, host_of, is_popular, load_labelled, load_popular  # noqa: E402

DATASETS = ROOT / "datasets"
OUT = DATASETS / "augmented"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0 Safari/537.36"
FETCH_TIMEOUT = 8
MAX_BODY = 700_000
CONCURRENCY = 20

CHEAP_TLDS = ("xyz", "top", "online", "site", "club", "icu", "live", "shop", "vip", "buzz", "rest", "cfd", "sbs",
              "click", "link", "monster", "quest", "lol", "cyou", "support", "help", "info", "cc", "pw", "tk", "ml",
              "ga", "cf", "gq", "work", "fun", "store", "app", "page", "today", "world", "life", "pro", "bond")
COMMON_TLDS = ("com", "net", "org", "co", "ae", "me", "io")
LURE_WORDS = ("login", "signin", "verify", "verification", "secure", "security", "account", "update", "confirm",
              "support", "service", "services", "billing", "payment", "pay", "wallet", "recover", "unlock", "alert",
              "auth", "claim", "reward", "refund", "invoice", "delivery", "parcel", "track", "tracking", "customs",
              "fine", "fines", "portal", "online", "official", "help", "center", "id", "my", "app", "otp", "kyc",
              "renew", "smart", "eservices", "gov", "uae", "ae", "dubai", "abudhabi")
# Arabic words in Latin letters, as UAE-targeted kits spell them.
ARABIC_TRANSLIT = ("mukhalafat", "mokhalafat", "mukhalfat", "tasdid", "tasdeed", "sadad", "hawiya", "hawiyah",
                   "hawiyati", "gharamat", "gharama", "murur", "moroor", "shurta", "shorta", "tajdid", "tajdeed",
                   "iqama", "rasid", "raseed", "tawseel", "tawsil", "barid", "bareed", "hisab", "hesab", "khadamat",
                   "khidmat", "fatura", "fatora", "fawateer", "tahdith", "tahdeeth", "tawtheeq", "jawaz", "tashira",
                   "rukhsa", "rokhsa", "mawaqif", "dafa", "istilam", "tafeel", "istirdad", "jumruk", "shahn",
                   "taawun", "musaada", "ruyati", "daman")
UAE_WORDS = ("uae", "ae", "abudhabi", "dubai", "emirates", "imarat", "gov", "adp", "sharjah")
ASCII_GLYPHS = {"o": ["0"], "l": ["1", "i"], "i": ["1", "l"], "e": ["3"], "a": ["4"], "s": ["5"], "m": ["rn"],
                "w": ["vv"], "d": ["cl"], "g": ["q"], "b": ["6"], "t": ["7"], "u": ["v"], "n": ["m"], "c": ["k"]}
UNICODE_GLYPHS = {"a": "аàáạä", "c": "сç", "e": "еéėẹ", "i": "іíı", "o": "оöọó", "p": "р", "s": "ѕș", "x": "х",
                  "y": "уý", "u": "üú", "d": "ԁ", "h": "һ", "n": "ñ", "t": "ț", "l": "ł", "k": "ķ", "m": "ṃ"}
KEYBOARD = {"q": "wa", "w": "qes", "e": "wrd", "r": "etf", "t": "ryg", "y": "tuh", "u": "yij", "i": "uok", "o": "ipl",
            "p": "o", "a": "qsz", "s": "awdx", "d": "sefc", "f": "drgv", "g": "fthb", "h": "gyjn", "j": "hukm",
            "k": "jil", "l": "ko", "z": "asx", "x": "zsdc", "c": "xdfv", "v": "cfgb", "b": "vghn", "n": "bhjm",
            "m": "njk"}
UNRELATED_WORDS = ("cloud", "host", "web", "site", "page", "net", "digital", "media", "group", "world", "zone", "hub",
                   "tech", "data", "link", "express", "global", "direct", "center", "point", "plus", "now")
FALLBACK_PATHS = ("", "", "/", "/login", "/login.php", "/index.php", "/verify", "/secure/login", "/account/verify",
                  "/pay", "/payment/index.html", "/track", "/ae/", "/en/login", "/wp-content/plugins/x/index.php",
                  "/auth/signin", "/update/billing", "/app/index.html", "/id/login.php?cmd=login", "/uae/pay")
INTEREST_RE = re.compile(
    r"log-?in|sign-?in|sign-?up|sso|auth|account|profile|dashboard|pay|bill|checkout|cart|recharge|topup|top-up|"
    r"service|eservice|portal|register|verify|secure|track|fine|renew|apply|booking|transfer|card|loan|otp|"
    r"/ar(?:-[a-z]{2})?/|/ar$|lang=ar|%d8|%d9|[؀-ۿ]", re.IGNORECASE)
STATIC_RE = re.compile(r"\.(?:css|js|mjs|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|eot|mp4|webm|mp3|zip|gz|xml|"
                       r"json|rss|atom|pdf|docx?|xlsx?|pptx?|apk|exe|dmg)(?:$|\?)", re.IGNORECASE)
HREF_RE = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']([^"'<>\s]{1,400})["']""", re.IGNORECASE)
LOC_RE = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]{1,400})", re.IGNORECASE)


def registry_data() -> dict:
    """Brand domains / keywords from the app's registry (project code, imported from the repo root)."""
    try:
        from saqr.intel import registry
        from saqr.intel.url_model import FREE_HOSTING
    except ImportError as exc:
        raise SystemExit(f"augment.py needs the runtime venv (.venv/bin/python): {exc}") from exc
    brands = []
    for entity in registry.ALL_BRANDS:
        keywords = [k.lower() for k in (*entity.keywords, *entity.common_keywords)
                    if re.fullmatch(r"[a-z0-9-]{2,}", k.lower())]
        brands.append({"id": entity.id, "uae": entity.category != "global", "domains": list(entity.domains),
                       "keywords": sorted(set(keywords))})
    official = sorted({d.lower() for b in brands for d in b["domains"]} | set(registry.TRUSTED_UAE_DOMAINS)
                      | set(registry.ENTITY_EXTRA_DOMAINS))
    return {"brands": brands, "official": official, "free_hosting": tuple(FREE_HOSTING),
            "uae_official": sorted({d for b in brands if b["uae"] for d in b["domains"]}
                                   | set(registry.TRUSTED_UAE_DOMAINS) | set(registry.ENTITY_EXTRA_DOMAINS))}


def on_suffix(host: str, suffixes) -> bool:
    return any(host == s or host.endswith("." + s) for s in suffixes)


def read_tranco(limit: int = 1_000_000) -> list[str]:
    path = DATASETS / "tranco" / "top-1m.csv"
    if not path.exists():
        return []
    out = []
    with open(path, encoding="utf-8") as f:
        for row in csv.reader(f):
            if len(row) == 2:
                out.append(row[1].strip().lower())
                if len(out) >= limit:
                    break
    return out


def dataset_rows(per_file: int | None = None) -> list[tuple[str, int, str]]:
    """Rows of every downloaded dataset that loads (Tranco and the augmented folder excluded)."""
    rows: list[tuple[str, int, str]] = []
    for folder in sorted(p for p in DATASETS.iterdir() if p.is_dir() and p.name not in ("augmented", "tranco")):
        for path in sorted(folder.iterdir()):
            if path.suffix.lower() not in (".csv", ".txt", ".json", ".tsv", ".jsonl"):
                continue
            try:
                rows.extend(load_labelled(path, source=folder.name, limit=per_file, quiet=True))
            except (ValueError, OSError) as exc:
                print(f"  skipped {path.name}: {exc}", file=sys.stderr)
    return rows


# ---------------------------------------------------------------- a) legitimate hard negatives

def _get(url: str) -> tuple[str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "text/html,application/xml;q=0.9,*/*;q=0.5",
                                               "Accept-Language": "en,ar;q=0.8"})
    with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
        body = resp.read(MAX_BODY)
        return resp.geturl(), body.decode("utf-8", "replace")


FETCH_ERRORS = (OSError, ValueError, http.client.HTTPException)


def harvest_site(domain: str, deadline: float, try_www: bool = False) -> list[str] | None:
    """Same-site links from the homepage and sitemap.xml of one domain (at most 2 requests, 3 with try_www).

    None = not tried (time budget used up), so the site is not cached as empty.
    """
    if time.monotonic() > deadline:
        return None
    links: list[str] = []
    base = ""
    for start in [f"https://{domain}/"] + ([f"https://www.{domain}/"] if try_www else []):
        try:
            final, html = _get(start)
        except FETCH_ERRORS:
            continue
        if not on_suffix(host_of(final), (domain,)):
            return []
        base = final
        if has_path(final):
            links.append(final)
        for href in HREF_RE.findall(html):
            if not href.lower().startswith(("javascript:", "mailto:", "tel:", "#", "data:")):
                try:
                    links.append(urljoin(final, href.replace("&amp;", "&")))
                except ValueError:
                    continue
        break
    if not base or time.monotonic() > deadline:
        return _same_site(links, domain)
    try:
        parts = urlsplit(base)
        _, xml = _get(f"{parts.scheme}://{parts.netloc}/sitemap.xml")
        links.extend(loc.replace("&amp;", "&") for loc in LOC_RE.findall(xml))
    except FETCH_ERRORS:
        pass
    return _same_site(links, domain)


def _same_site(links: list[str], domain: str) -> list[str]:
    out: dict[str, None] = {}
    for link in links:
        try:
            parts = urlsplit(link.strip())
        except ValueError:
            continue
        if parts.scheme not in ("http", "https") or "@" in parts.netloc or len(link) > 300:
            continue
        if not on_suffix(host_of(link), (domain,)) or STATIC_RE.search(parts.path):
            continue
        clean = urlunsplit((parts.scheme, parts.netloc, parts.path, parts.query, ""))
        if has_path(clean):
            out[clean] = None
    return list(out)


def tranco_sample(tranco: list[str], count: int, rng: random.Random, exclude) -> list[str]:
    """Sites spread evenly (in log rank) over ranks 1k-500k."""
    lo, hi = 1_000, min(500_000, len(tranco))
    if hi <= lo:
        return []
    picked: dict[str, None] = {}
    for i in range(count):
        a = lo * (hi / lo) ** (i / count)
        b = lo * (hi / lo) ** ((i + 1) / count)
        for _ in range(6):
            site = tranco[min(int(rng.uniform(a, b)), hi - 1)]
            if site not in picked and not exclude(site):
                picked[site] = None
                break
    return list(picked)


def harvest(sites: list[tuple[str, str]], seconds: float, cache: dict, cache_path: Path) -> None:
    """Fill 'cache' (site -> links); saved every 250 sites so an interrupted run keeps its work."""
    deadline = time.monotonic() + seconds
    with ThreadPoolExecutor(max_workers=CONCURRENCY) as pool:
        jobs = [(site, pool.submit(harvest_site, site, deadline, kind != "tranco")) for site, kind in sites]
        for n, (site, job) in enumerate(jobs, 1):
            links = job.result()
            if links is not None:
                cache[site] = links
            if n % 250 == 0 or n == len(jobs):
                cache_path.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
                print(f"  {n}/{len(jobs)} sites, {sum(1 for v in cache.values() if v)} with links", flush=True)


def choose_links(links: list[str], cap: int, rng: random.Random) -> list[str]:
    """Up to 'cap' links: login / pay / account / Arabic pages first, then a random rest."""
    interesting = [u for u in links if INTEREST_RE.search(urlsplit(u).path + "?" + urlsplit(u).query)]
    rest = [u for u in links if u not in set(interesting)]
    rng.shuffle(interesting)
    rng.shuffle(rest)
    keep = interesting[: max((cap * 2 + 2) // 3, cap - len(rest))]
    return keep + rest[: cap - len(keep)]


def legit_deep_links(reg: dict, tranco: list[str], bad_hosts: set[str], args, rng: random.Random) -> list[tuple]:
    OUT.mkdir(parents=True, exist_ok=True)
    cache_path = OUT / "harvest_cache.json"
    cache: dict = json.loads(cache_path.read_text(encoding="utf-8")) if cache_path.exists() else {}
    sample = tranco_sample(tranco, args.tranco_sample, rng,
                           lambda s: s in bad_hosts or on_suffix(s, reg["free_hosting"]) or s in reg["official"])
    sites = [(d, "uae_official" if d in reg["uae_official"] else "brand_official") for d in reg["official"]]
    sites += [(s, "tranco") for s in sample]
    todo = [(s, k) for s, k in sites if args.refresh_harvest or s not in cache]
    if todo and not args.no_harvest:
        print(f"harvesting {len(todo)} sites (concurrency {CONCURRENCY}, {FETCH_TIMEOUT}s timeout, "
              f"budget {args.harvest_seconds}s)", flush=True)
        harvest(todo, args.harvest_seconds, cache, cache_path)
    rows = []
    reached = {"uae_official": 0, "brand_official": 0, "tranco": 0}
    for site, kind in sites:
        links = cache.get(site) or []
        reached[kind] += bool(links)
        cap = args.links_per_official if kind != "tranco" else args.links_per_site
        for url in choose_links(sorted(links), cap, rng):
            rows.append((url, 0, f"harvest_{kind}", "deep_link"))
    print(f"  sites with links: {reached} of uae/brand {len(reg['official'])}, tranco {len(sample)}")
    return rows


def legit_free_hosting(reg: dict, tranco: list[str], data: list[tuple], bad_hosts: set[str]) -> list[tuple]:
    rows: dict[str, tuple] = {}
    for rank, site in enumerate(tranco[:300_000], 1):
        if on_suffix(site, reg["free_hosting"]) and site not in reg["free_hosting"] and site not in bad_hosts:
            rows[f"https://{site}/"] = (f"https://{site}/", 0, "tranco_free_hosting", f"rank_{rank}")
    for url, label, source in data:
        host = host_of(url)
        if label == 0 and on_suffix(host, reg["free_hosting"]) and host not in reg["free_hosting"] \
                and host not in bad_hosts:
            rows.setdefault(url, (url, 0, f"{source}_free_hosting", "dataset_legit"))
    return list(rows.values())


def legit_lure_hosts(tranco: list[str], data: list[tuple], bad_hosts: set[str]) -> list[tuple]:
    lure = re.compile(r"(?:^|[.-])(?:" + "|".join(sorted(set(LURE_WORDS) - {"ae", "my", "id", "app", "uae", "gov"},
                                                         key=len, reverse=True)) + r")(?:$|[.-])")
    rows: dict[str, tuple] = {}
    for rank, site in enumerate(tranco[:200_000], 1):
        if site not in bad_hosts and lure.search(site.rsplit(".", 1)[0]):
            rows[f"https://{site}/"] = (f"https://{site}/", 0, "tranco_lure_host", f"rank_{rank}")
    popular = load_popular(100_000)
    for url, label, source in data:
        host = host_of(url)
        if label == 0 and host not in bad_hosts and is_popular(host, popular) and lure.search(host.rsplit(".", 1)[0]):
            rows.setdefault(url, (url, 0, f"{source}_lure_host", "dataset_legit"))
    return list(rows.values())


# ---------------------------------------------------------------- b) synthetic phishing

def punycode(label: str) -> str:
    return label if label.isascii() else "xn--" + label.encode("punycode").decode("ascii")


def permutations(word: str, rng: random.Random) -> list[tuple[str, str]]:
    """dnstwist-style variants of one brand label: (variant, technique)."""
    out: list[tuple[str, str]] = []
    idx = list(range(len(word)))
    for i in idx:
        for glyph in ASCII_GLYPHS.get(word[i], []):
            out.append((word[:i] + glyph + word[i + 1:], "homoglyph"))
        for glyph in UNICODE_GLYPHS.get(word[i], ""):
            out.append((punycode(word[:i] + glyph + word[i + 1:]), "idn_homoglyph"))
    if len(word) >= 5:
        for i in idx[1:]:
            out.append((word[:i] + word[i + 1:], "omission"))
        for i in idx[1:-1]:
            if word[i] != word[i + 1]:
                out.append((word[:i] + word[i + 1] + word[i] + word[i + 2:], "transposition"))
        for i in idx[1:]:
            out.append((word[:i] + rng.choice("abcdefghijklmnopqrstuvwxyz") + word[i:], "insertion"))
            out.append((word[:i] + word[i] + word[i:], "repetition"))
            if word[i] in KEYBOARD:
                out.append((word[:i] + rng.choice(KEYBOARD[word[i]]) + word[i + 1:], "replacement"))
        for i in idx[2:-1]:
            out.append((word[:i] + "-" + word[i:], "hyphenation"))
    return [(v, t) for v, t in out if v != word and re.fullmatch(r"[a-z0-9-]+", v) and not v.startswith("-")]


def synthetic_hosts(brand: dict, reg: dict, rng: random.Random, count: int) -> list[tuple[str, str]]:
    """Look-alike hostnames for one brand: (host, technique)."""
    keywords = brand["keywords"] or [brand["domains"][0].split(".")[0]]
    long_words = [k for k in keywords if len(k) >= 4] or keywords
    domains = brand["domains"]
    cheap = lambda: rng.choice(CHEAP_TLDS)  # noqa: E731
    any_tld = lambda: rng.choice(CHEAP_TLDS + COMMON_TLDS)  # noqa: E731
    lure = lambda: rng.choice(LURE_WORDS)  # noqa: E731
    hosts: list[tuple[str, str]] = []

    typos = [p for w in long_words for p in permutations(w, rng)]
    rng.shuffle(typos)
    for variant, technique in typos[: count * 3 // 10]:
        tld = any_tld() if technique != "idn_homoglyph" else rng.choice(("com", "net", "ae", "org", cheap()))
        hosts.append((f"{variant}.{tld}", technique))

    makers = (
        ("tld_swap", lambda k: f"{k}.{cheap()}"),
        ("tld_swap", lambda k: f"{rng.choice(domains).rsplit('.', 1)[0].replace('.', '-')}.{cheap()}"),
        ("brand_lure", lambda k: f"{k}-{lure()}.{any_tld()}"),
        ("brand_lure", lambda k: f"{lure()}-{k}.{any_tld()}"),
        ("brand_lure", lambda k: f"{k}-{lure()}-{lure()}.{any_tld()}"),
        ("brand_lure", lambda k: f"{k}{lure()}.{any_tld()}"),
        ("brand_lure", lambda k: f"{lure()}.{k}-{rng.choice(UAE_WORDS)}.{cheap()}"),
        ("brand_lure_digits", lambda k: f"{k}-{lure()}{rng.randint(1, 999)}.{cheap()}"),
        ("brand_subdomain", lambda k: f"{rng.choice(domains)}.{lure()}-{rng.choice(UNRELATED_WORDS)}.{any_tld()}"),
        ("brand_subdomain", lambda k: f"{k}.{lure()}.{rng.choice(UNRELATED_WORDS)}{rng.randint(1, 99)}.{cheap()}"),
        ("brand_subdomain", lambda k: f"{rng.choice(domains).replace('.', '-')}.{rng.choice(UNRELATED_WORDS)}"
                                      f"{rng.choice(UNRELATED_WORDS)}.{any_tld()}"),
        ("free_hosting", lambda k: f"{k}-{lure()}.{rng.choice(reg['free_hosting'])}"),
        ("free_hosting", lambda k: f"{lure()}-{k}-{rng.randint(10, 9999)}.{rng.choice(reg['free_hosting'])}"),
        ("free_hosting", lambda k: f"{k}{rng.choice(('', '-ae', '-uae', '-online'))}.{rng.choice(reg['free_hosting'])}"),
    )
    if brand["uae"]:
        makers += (
            ("arabic_translit", lambda k: f"{rng.choice(ARABIC_TRANSLIT)}-{k}.{any_tld()}"),
            ("arabic_translit", lambda k: f"{k}-{rng.choice(ARABIC_TRANSLIT)}.{any_tld()}"),
            ("arabic_translit", lambda k: f"{rng.choice(ARABIC_TRANSLIT)}-{rng.choice(UAE_WORDS)}.{any_tld()}"),
            ("arabic_translit", lambda k: f"{rng.choice(ARABIC_TRANSLIT)}{rng.choice(ARABIC_TRANSLIT)}.{cheap()}"),
            ("arabic_translit", lambda k: f"{rng.choice(ARABIC_TRANSLIT)}-{rng.choice(ARABIC_TRANSLIT)}-"
                                          f"{rng.choice(UAE_WORDS)}.{rng.choice(reg['free_hosting'])}"),
            ("arabic_translit", lambda k: f"{k}.{rng.choice(ARABIC_TRANSLIT)}-{rng.choice(UAE_WORDS)}.{cheap()}"),
        )
    while len(hosts) < count:
        technique, make = rng.choice(makers)
        hosts.append((make(rng.choice(keywords)), technique))
    return hosts


def kit_paths(data: list[tuple], rng: random.Random, cap: int = 60_000) -> list[str]:
    """Path + query of real phishing URLs (anything that could carry a victim's address is dropped)."""
    paths = []
    for url, label, source in data:
        if label != 1 or source == "urlhaus":
            continue
        try:
            parts = urlsplit(url)
        except ValueError:
            continue
        tail = parts.path + ("?" + parts.query if parts.query else "")
        if len(tail) <= 160 and "@" not in tail and "%40" not in tail.lower() and tail.isascii():
            paths.append(tail)
    rng.shuffle(paths)
    return paths[:cap] or list(FALLBACK_PATHS)


def synthetic_phishing(reg: dict, data: list[tuple], per_brand: int, rng: random.Random) -> list[tuple]:
    paths = kit_paths(data, rng)
    popular = load_popular(100_000)
    official = set(reg["official"])
    rows: dict[str, tuple] = {}
    for brand in reg["brands"]:
        for host, technique in synthetic_hosts(brand, reg, rng, per_brand * (2 if brand["uae"] else 1)):
            host = host.lower().strip(".-")
            if host in official or on_suffix(host, official) or is_popular(host, popular) \
                    or host in reg["free_hosting"] or not re.fullmatch(r"[a-z0-9.-]+\.[a-z0-9-]{2,}", host):
                continue
            scheme = "https" if rng.random() < 0.8 else "http"
            url = f"{scheme}://{host}{rng.choice(paths)}"
            rows.setdefault(url, (url, 1, "synthetic", f"{technique}:{brand['id']}"))
    return list(rows.values())


# ---------------------------------------------------------------- c) evasion variants

def _swap_scheme(p, rng, reg):
    return p._replace(scheme="http" if p.scheme == "https" else "https")


def _toggle_www(p, rng, reg):
    host = p.netloc
    if re.fullmatch(r"[\d.:]+", host):
        return None
    return p._replace(netloc=host[4:] if host.lower().startswith("www.") else "www." + host)


def _upper_host(p, rng, reg):
    host = p.netloc.upper() if rng.random() < 0.5 else "".join(
        c.upper() if rng.random() < 0.4 else c for c in p.netloc)
    return p._replace(netloc=host) if host != p.netloc else None


def _toggle_slash(p, rng, reg):
    if p.query or p.fragment:
        return None
    if p.path.endswith("/"):
        return p._replace(path=p.path.rstrip("/"))
    if "." in p.path.rsplit("/", 1)[-1]:
        return None
    return p._replace(path=p.path + "/")


def _percent_encode(p, rng, reg):
    spots = [i for i, c in enumerate(p.path) if c.isalnum() and (i < 2 or p.path[i - 2] != "%") and p.path[i - 1] != "%"]
    if not spots:
        return None
    chosen = set(rng.sample(spots, min(len(spots), rng.randint(1, 3))))
    return p._replace(path="".join(f"%{ord(c):02X}" if i in chosen else c for i, c in enumerate(p.path)))


def _default_port(p, rng, reg):
    if ":" in p.netloc.rsplit("@", 1)[-1].rsplit("]", 1)[-1]:
        return None
    return p._replace(netloc=f"{p.netloc}:{443 if p.scheme == 'https' else 80}")


def _fqdn_dot(p, rng, reg):
    if ":" in p.netloc or p.netloc.endswith(".") or re.fullmatch(r"[\d.]+", p.netloc):
        return None
    return p._replace(netloc=p.netloc + ".")


def _userinfo(p, rng, reg):
    if "@" in p.netloc:
        return None
    official = rng.choice(reg["official"])
    decoy = rng.choice((official, f"www.{official}", f"{official}%2F{rng.choice(LURE_WORDS)}", f"{official}:443"))
    return p._replace(netloc=f"{decoy}@{p.netloc}")


EVASIONS = {"scheme": _swap_scheme, "www": _toggle_www, "case": _upper_host, "slash": _toggle_slash,
            "percent": _percent_encode, "port": _default_port, "fqdn_dot": _fqdn_dot}
PHISHING_ONLY_EVASIONS = {"userinfo": _userinfo}


def evade(url: str, label: int, rng: random.Random, reg: dict) -> tuple[str, str] | None:
    """One rewritten form of the URL that points at the same site: (new url, technique)."""
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return None
    options = dict(EVASIONS)
    if label == 1:
        options.update(PHISHING_ONLY_EVASIONS)
    names = sorted(options)
    rng.shuffle(names)
    for name in names:
        changed = options[name](parts, rng, reg)
        if changed is not None:
            new = urlunsplit(changed)
            if new != url:
                return new, name
    return None


def evasion_variants(base: list[tuple], reg: dict, per_group: int, rng: random.Random) -> list[tuple]:
    groups: dict[tuple[str, int], list[str]] = {}
    for url, label, source in base:
        groups.setdefault((source, label), []).append(url)
    rows: dict[str, tuple] = {}
    for (source, label), urls in sorted(groups.items()):
        urls = sorted(set(urls))
        for url in rng.sample(urls, min(per_group, len(urls))):
            result = evade(url, label, rng, reg)
            if result:
                rows.setdefault(result[0], (result[0], label, f"{source}+evasion", result[1]))
    return list(rows.values())


# ---------------------------------------------------------------- output

def write(name: str, rows: list[tuple]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / name, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label", "source", "variant"])
        writer.writerows(rows)
    with_path = sum(has_path(r[0]) for r in rows)
    share = f"{with_path / len(rows):.1%}" if rows else "-"
    print(f"{name:28} rows={len(rows):>7}  phishing={sum(r[1] for r in rows):>7}  with_path={share}", flush=True)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=11)
    ap.add_argument("--no-harvest", action="store_true", help="no network: use harvest_cache.json only")
    ap.add_argument("--refresh-harvest", action="store_true", help="fetch every site again")
    ap.add_argument("--tranco-sample", type=int, default=3000)
    ap.add_argument("--harvest-seconds", type=int, default=600, help="stop starting new sites after this long")
    ap.add_argument("--links-per-site", type=int, default=12)
    ap.add_argument("--links-per-official", type=int, default=80)
    ap.add_argument("--per-brand", type=int, default=200, help="synthetic hosts per global brand (UAE brands: x2)")
    ap.add_argument("--evasion-per-group", type=int, default=4000, help="rows rewritten per (source, label)")
    args = ap.parse_args()

    reg = registry_data()
    tranco = read_tranco()
    data = dataset_rows()
    bad_hosts = {host_of(u) for u, label, _ in data if label == 1}
    print(f"brands {len(reg['brands'])}, official domains {len(reg['official'])}, tranco {len(tranco)}, "
          f"dataset rows {len(data)}, phishing hosts {len(bad_hosts)}", flush=True)

    deep = legit_deep_links(reg, tranco, bad_hosts, args, random.Random(args.seed))
    write("legit_deep_links.csv", deep)
    free = legit_free_hosting(reg, tranco, data, bad_hosts)
    write("legit_free_hosting.csv", free)
    lure = legit_lure_hosts(tranco, data, bad_hosts)
    write("legit_lure_hosts.csv", lure)
    synthetic = synthetic_phishing(reg, data, args.per_brand, random.Random(args.seed + 1))
    write("synthetic_phishing.csv", synthetic)
    base = data + [(u, y, s) for u, y, s, _ in deep + free + lure + synthetic]
    write("evasion_variants.csv", evasion_variants(base, reg, args.evasion_per_group, random.Random(args.seed + 2)))


if __name__ == "__main__":
    main()
