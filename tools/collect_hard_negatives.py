"""Legitimate "hard negative" URLs -> datasets/augmented/legit_hard_negatives.csv (url,label,source,variant).

Hard negatives are REAL pages of legitimate sites whose address contains the words phishing addresses
use: news and advisory articles ABOUT scams and brands ("/uae/beware-of-fake-salik-sms-scam"), bank and
government "beware of fraud" pages, and the official deep links of UAE entities and banks. A URL model that
only saw bare legitimate homepages learns "brand / lure word in the path = phishing"; these teach it that the
host matters.

Collection is polite and search-free: robots.txt is honoured for our User-Agent, only robots.txt-listed
sitemaps, /sitemap.xml-style files and RSS feeds are read (no page crawling), one request per site per
REQUEST_GAP seconds, at most MAX_REQUESTS_PER_SITE requests and --cap URLs per site. Fetched bodies are
untrusted data: only <loc> / <link> values are extracted with a regular expression, nothing is executed,
gzip bodies are size-capped.

Sites in tools/holdout_sites.txt.gz (the sealed false-positive suite and every other holdout set) are
dropped, so the training hard negatives stay site-disjoint from the evaluation sets. Sites where real
collection yields fewer than --min-real URLs get clearly synthetic article paths on the real host
(variant "synthetic", source suffix "_synthetic": the trainer caps their weight).

  .venv-train/Scripts/python -I tools/collect_hard_negatives.py            # Windows
  .venv-train/bin/python -I tools/collect_hard_negatives.py --offline      # Linux, cache only
"""
from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import random
import re
import sys
import threading
import time
import urllib.error
import urllib.request
import urllib.robotparser
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit, urlunsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "datasets" / "augmented"
CACHE = OUT / "hardneg_cache.json"
EXCLUDE_PATH = ROOT / "tools" / "holdout_sites.txt.gz"
UA = "SaqrResearchBot/1.0 (phishing-model false-positive research; reads sitemaps/RSS only; low rate)"
TIMEOUT = 15
MAX_BODY = 8_000_000
REQUEST_GAP = 1.5
MAX_REQUESTS_PER_SITE = 14
SEED = 20261125

# (registered domain, kind). kind: uae_news | uae_news_ar | global_news | advisory | uae_entity | bank
SITES: tuple[tuple[str, str], ...] = (
    # UAE outlets (English)
    ("khaleejtimes.com", "uae_news"), ("gulfnews.com", "uae_news"), ("thenationalnews.com", "uae_news"),
    ("wam.ae", "uae_news"), ("gulftoday.ae", "uae_news"), ("emirates247.com", "uae_news"),
    ("arabianbusiness.com", "uae_news"), ("zawya.com", "uae_news"), ("gulfbusiness.com", "uae_news"),
    ("whatson.ae", "uae_news"), ("timeoutdubai.com", "uae_news"), ("lovin.co", "uae_news"),
    ("dubaieye1038.com", "uae_news"), ("arabnews.com", "uae_news"),
    # UAE outlets (Arabic: Arabic-script, percent-encoded article slugs)
    ("alkhaleej.ae", "uae_news_ar"), ("albayan.ae", "uae_news_ar"), ("emaratalyoum.com", "uae_news_ar"),
    ("alittihad.ae", "uae_news_ar"), ("alroeya.com", "uae_news_ar"), ("24.ae", "uae_news_ar"),
    ("eremnews.com", "uae_news_ar"),
    # Global outlets and security news
    ("bbc.com", "global_news"), ("theguardian.com", "global_news"), ("apnews.com", "global_news"),
    ("independent.co.uk", "global_news"), ("aljazeera.com", "global_news"), ("bleepingcomputer.com", "global_news"),
    ("krebsonsecurity.com", "global_news"), ("theverge.com", "global_news"), ("techcrunch.com", "global_news"),
    ("which.co.uk", "global_news"), ("thehackernews.com", "global_news"), ("malwarebytes.com", "global_news"),
    ("welivesecurity.com", "global_news"), ("helpnetsecurity.com", "global_news"),
    # Consumer-protection / fraud advisories
    ("consumer.ftc.gov", "advisory"), ("ncsc.gov.uk", "advisory"), ("actionfraud.police.uk", "advisory"),
    ("scamwatch.gov.au", "advisory"), ("cisa.gov", "advisory"), ("ic3.gov", "advisory"),
    ("getsafeonline.org", "advisory"), ("ukfinance.org.uk", "advisory"), ("aarp.org", "advisory"),
    # UAE government entities (training only; the sealed suite's sites are dropped automatically)
    ("salik.ae", "uae_entity"), ("itc.gov.ae", "uae_entity"), ("mof.gov.ae", "uae_entity"),
    ("moec.gov.ae", "uae_entity"), ("sca.gov.ae", "uae_entity"), ("dubaicustoms.gov.ae", "uae_entity"),
    ("dm.gov.ae", "uae_entity"), ("dubailand.gov.ae", "uae_entity"), ("dha.gov.ae", "uae_entity"),
    ("doh.gov.ae", "uae_entity"), ("adek.gov.ae", "uae_entity"), ("mohap.gov.ae", "uae_entity"),
    ("gdrfad.gov.ae", "uae_entity"), ("shjpolice.gov.ae", "uae_entity"), ("rakpolice.gov.ae", "uae_entity"),
    ("ajmanpolice.gov.ae", "uae_entity"), ("dc.gov.ae", "uae_entity"), ("addc.ae", "uae_entity"),
    ("sewa.gov.ae", "uae_entity"), ("etihadwe.ae", "uae_entity"), ("uaecabinet.ae", "uae_entity"),
    ("dubaicourts.gov.ae", "uae_entity"), ("ded.ae", "uae_entity"), ("visitdubai.com", "uae_entity"),
    ("visitabudhabi.ae", "uae_entity"), ("centralbank.ae", "uae_entity"), ("nol.ae", "uae_entity"),
    # Banks (UAE and global) with security / fraud-awareness pages
    ("mashreq.com", "bank"), ("rakbank.ae", "bank"), ("nbf.ae", "bank"), ("sib.ae", "bank"),
    ("ajmanbank.ae", "bank"), ("cbi.ae", "bank"), ("alhilalbank.ae", "bank"), ("emiratesislamic.ae", "bank"),
    ("bankofsharjah.com", "bank"), ("uab.ae", "bank"), ("wio.io", "bank"), ("liv.me", "bank"),
    ("hsbc.co.uk", "bank"), ("barclays.co.uk", "bank"), ("lloydsbank.com", "bank"), ("santander.co.uk", "bank"),
    ("natwest.com", "bank"), ("nationwide.co.uk", "bank"), ("monzo.com", "bank"), ("starlingbank.com", "bank"),
)
# Words that make a legitimate article / help page look like a lure (English + Arabic script).
PRIORITY_RE = re.compile(
    r"scam|fraud|phish|fake|bogus|beware|warn|alert|smish|vish|impersonat|cyber|hack|steal|stolen|police|"
    r"bank|card|otp|pin|password|login|sign-?in|account|verify|verification|secure|security|pay|payment|"
    r"refund|fine|fines|toll|salik|darb|tamm|uae-?pass|emirates-?id|icp|moi|tdra|etisalat|e-and|\bdu\b|"
    r"mashreq|adcb|fab|adib|dib|rakbank|enbd|emirates-?nbd|emirates-?post|aramex|dhl|parcel|delivery|"
    r"customs|track|invoice|wallet|crypto|paypal|microsoft|apple|amazon|netflix|whatsapp|"
    r"احتيال|نصب|محتال|تحذير|مزيف|وهمي|رسائل|رسالة|الشرطة|بنك|بطاقة|حساب|مخالفة|مخالفات|غرامة|سالك|"
    r"الهوية|توصيل|طرد|استرداد|دفع|رابط|روابط|اختراق|قرصنة|سرقة",
    re.IGNORECASE)
LOC_RE = re.compile(r"<loc>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]{1,600})", re.IGNORECASE)
LINK_RE = re.compile(r"<link>\s*(?:<!\[CDATA\[)?\s*([^<\]\s]{1,600})", re.IGNORECASE)
STATIC_RE = re.compile(r"\.(?:css|js|png|jpe?g|gif|svg|ico|webp|avif|woff2?|ttf|mp4|webm|mp3|zip|gz|xml|json|"
                       r"rss|atom|pdf|docx?|xlsx?|pptx?|apk|exe)(?:$|\?)", re.IGNORECASE)
FALLBACK_SITEMAPS = ("/sitemap.xml", "/sitemap_index.xml", "/news-sitemap.xml", "/sitemap-news.xml",
                     "/feed", "/rss", "/rss.xml", "/feed.xml")
SITEMAP_PREF = re.compile(r"news|article|post|story|latest|recent|2026|2025", re.IGNORECASE)

# Clearly synthetic article / help paths for real hosts where collection found too little.
SYN_SECTIONS = ("news/uae", "uae", "business/banking", "technology/cyber", "news", "lifestyle/consumer",
                "en/media-centre/news", "help/security", "en/security", "awareness")
SYN_SLUGS = (
    "beware-of-fake-{b}-sms-asking-you-to-pay-{l}", "{b}-warns-residents-of-{l}-phishing-messages",
    "how-to-spot-a-fake-{b}-{l}-link", "police-arrest-gang-behind-fake-{b}-{l}-websites",
    "{b}-customers-targeted-by-{l}-scam", "do-not-click-fake-{b}-{l}-links-says-police",
    "new-{b}-{l}-scam-what-you-need-to-know", "{b}-{l}-fraud-alert-{y}",
)
SYN_BRANDS = ("salik", "darb", "tamm", "uae-pass", "icp", "moi", "tdra", "dib", "mashreq", "adib", "rakbank",
              "etisalat", "du", "emirates-post", "ad-police", "adcb", "fab", "emirates-nbd", "aramex", "dewa")
SYN_LURES = ("toll", "fine", "refund", "parcel-delivery", "account-update", "otp", "card-verification",
             "login", "payment", "reward-points", "emirates-id-update", "customs-fee")
SYN_AR = ("احذر رسائل {b} المزيفة", "تحذير من روابط احتيال باسم {b}", "شرطة أبوظبي تحذر من رسائل {b} الاحتيالية",
          "كيف تكشف رابط {b} المزيف", "احتيال إلكتروني باسم {b} لسداد المخالفات")
SYN_AR_BRANDS = ("سالك", "درب", "تم", "الهوية الرقمية", "بريد الإمارات", "اتصالات", "دو", "شرطة أبوظبي",
                 "بنك أبوظبي التجاري", "المشرق", "الإمارات دبي الوطني")


def registered(host: str) -> str:
    from saqr.intel import url_features as uf
    return uf.parse("http://" + host + "/").reg_domain


def excluded_sites() -> set[str]:
    if not EXCLUDE_PATH.exists():
        return set()
    with gzip.open(EXCLUDE_PATH, "rt", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


class Site:
    """One site's polite fetcher: robots.txt honoured, REQUEST_GAP between requests, request budget."""

    def __init__(self, domain: str):
        self.domain = domain
        self.requests = 0
        self.last = 0.0
        self.robots: urllib.robotparser.RobotFileParser | None = None
        self.base = f"https://{domain}"

    def _wait(self) -> None:
        gap = time.monotonic() - self.last
        if gap < REQUEST_GAP:
            time.sleep(REQUEST_GAP - gap)
        self.last = time.monotonic()

    def get(self, url: str, check_robots: bool = True) -> tuple[str, str] | None:
        if self.requests >= MAX_REQUESTS_PER_SITE:
            return None
        if check_robots and self.robots is not None and not self.robots.can_fetch(UA, url):
            return None
        self._wait()
        self.requests += 1
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "application/xml,text/xml,"
                                                   "application/rss+xml,text/html;q=0.5,*/*;q=0.3"})
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = resp.read(MAX_BODY)
                final = resp.geturl()
        except (OSError, ValueError, urllib.error.HTTPError):
            return None
        if body[:2] == b"\x1f\x8b":
            try:
                body = gzip.GzipFile(fileobj=io.BytesIO(body)).read(MAX_BODY)
            except (OSError, EOFError):
                return None
        return final, body.decode("utf-8", "replace")

    def load_robots(self) -> list[str]:
        """Sitemaps listed in robots.txt (and the parsed rules for later requests)."""
        for base in (f"https://{self.domain}", f"https://www.{self.domain}"):
            got = self.get(base + "/robots.txt", check_robots=False)
            if got is None:
                continue
            final, text = got
            if "<html" in text[:500].lower():
                continue
            rp = urllib.robotparser.RobotFileParser()
            rp.parse(text.splitlines())
            self.robots = rp
            self.base = f"{urlsplit(final).scheme}://{urlsplit(final).netloc}"
            return [ln.split(":", 1)[1].strip() for ln in text.splitlines()
                    if ln.lower().startswith("sitemap:") and ln.split(":", 1)[1].strip().startswith("http")]
        return []


def same_site(url: str, domain: str) -> bool:
    try:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
    except ValueError:
        return False
    return host == domain or host.endswith("." + domain)


def clean(url: str) -> str | None:
    url = url.strip().replace("&amp;", "&")
    try:
        p = urlsplit(url)
    except ValueError:
        return None
    if p.scheme not in ("http", "https") or "@" in p.netloc or len(url) > 400 or STATIC_RE.search(p.path):
        return None
    if not (p.path.strip("/") or p.query):
        return None
    return urlunsplit((p.scheme, p.netloc, p.path, p.query, ""))


def collect_site(domain: str, cap_requests: int = MAX_REQUESTS_PER_SITE) -> dict:
    site = Site(domain)
    sitemaps = site.load_robots()
    queue = list(dict.fromkeys(sitemaps)) or [site.base + p for p in FALLBACK_SITEMAPS]
    queue.sort(key=lambda u: (not SITEMAP_PREF.search(u), u))
    seen: set[str] = set()
    pages: dict[str, None] = {}
    while queue and site.requests < cap_requests:
        sm = queue.pop(0)
        if sm in seen or not same_site(sm, domain):
            continue
        seen.add(sm)
        got = site.get(sm)
        if got is None:
            continue
        _final, body = got
        locs = LOC_RE.findall(body) or LINK_RE.findall(body)
        children = [u for u in locs if re.search(r"\.xml(?:\.gz)?(?:$|\?)|sitemap", u, re.I)]
        if children and len(children) >= len(locs) // 2:
            kids = sorted(dict.fromkeys(children), key=lambda u: (not SITEMAP_PREF.search(u), -len(re.findall(r"\d", u)), u))
            queue = kids[:10] + queue
            continue
        for u in locs:
            c = clean(u)
            if c and same_site(c, domain):
                pages[c] = None
        if len(pages) >= 3000:
            break
    return {"domain": domain, "requests": site.requests, "robots": site.robots is not None,
            "fetched": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "urls": list(pages)[:3000]}


def choose(urls: list[str], cap: int, rng: random.Random) -> list[str]:
    """Up to cap URLs: lure / brand / scam-topic paths first (2/3), then a random rest."""
    pri = [u for u in urls if PRIORITY_RE.search(unquote(urlsplit(u).path + "?" + urlsplit(u).query))]
    pri_set = set(pri)
    rest = [u for u in urls if u not in pri_set]
    rng.shuffle(pri)
    rng.shuffle(rest)
    keep = pri[: max((cap * 2) // 3, cap - len(rest))]
    return keep + rest[: cap - len(keep)]


def synthetic_paths(domain: str, kind: str, n: int, rng: random.Random) -> list[str]:
    out = []
    for i in range(n):
        y = rng.choice((2024, 2025, 2026))
        if kind == "uae_news_ar" or rng.random() < 0.2:
            slug = quote(rng.choice(SYN_AR).format(b=rng.choice(SYN_AR_BRANDS)).replace(" ", "-"))
        else:
            slug = rng.choice(SYN_SLUGS).format(b=rng.choice(SYN_BRANDS), l=rng.choice(SYN_LURES), y=y)
        sec = rng.choice(SYN_SECTIONS)
        tail = f"/{sec}/{y}/{rng.randint(1, 12):02d}/{rng.randint(1, 28):02d}/{slug}" if rng.random() < 0.5 \
            else f"/{sec}/{slug}-1.{rng.randint(1000000, 9999999)}"
        out.append(f"https://www.{domain}{tail}" if rng.random() < 0.6 else f"https://{domain}{tail}")
    return list(dict.fromkeys(out))


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--offline", action="store_true", help="use hardneg_cache.json only")
    ap.add_argument("--refresh", action="store_true", help="fetch every site again")
    ap.add_argument("--cap", type=int, default=200, help="URLs kept per site")
    ap.add_argument("--min-real", type=int, default=40, help="below this, add synthetic paths on the real host")
    ap.add_argument("--synthetic-per-site", type=int, default=60)
    ap.add_argument("--workers", type=int, default=6, help="sites fetched in parallel (one request at a time each)")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    cache: dict = json.loads(CACHE.read_text(encoding="utf-8")) if CACHE.exists() else {}
    sealed = excluded_sites()
    sites = [(d, k) for d, k in SITES if registered(d) not in sealed and d not in sealed]
    dropped = [d for d, _ in SITES if (d, dict(SITES)[d]) not in sites]
    print(f"{len(sites)} sites ({len(dropped)} dropped: in the sealed holdout sets: {dropped})", flush=True)
    todo = [d for d, _ in sites if args.refresh or d not in cache]
    if todo and not args.offline:
        lock = threading.Lock()
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            for res in pool.map(collect_site, todo):
                with lock:
                    cache[res["domain"]] = res
                    CACHE.write_text(json.dumps(cache, ensure_ascii=False), encoding="utf-8")
                print(f"  {res['domain']:28s} requests {res['requests']:2d} robots {res['robots']!s:5s} "
                      f"urls {len(res['urls'])}", flush=True)
    rng = random.Random(SEED)
    rows: list[tuple[str, int, str, str]] = []
    stats: dict = {}
    for domain, kind in sites:
        urls = (cache.get(domain) or {}).get("urls") or []
        picked = choose(sorted(urls), args.cap, rng)
        rows += [(u, 0, f"hardneg_{kind}", "real") for u in picked]
        syn = []
        if len(picked) < args.min_real:
            syn = synthetic_paths(domain, kind, args.synthetic_per_site, rng)
            rows += [(u, 0, f"hardneg_{kind}_synthetic", "synthetic") for u in syn]
        stats[domain] = {"kind": kind, "real": len(picked), "synthetic": len(syn),
                         "priority": sum(bool(PRIORITY_RE.search(unquote(urlsplit(u).path))) for u in picked)}
    seen: set[str] = set()
    with open(OUT / "legit_hard_negatives.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "source", "variant"])
        for r in rows:
            if r[0] not in seen:
                seen.add(r[0])
                w.writerow(r)
    (OUT / "legit_hard_negatives.stats.json").write_text(json.dumps(stats, indent=1), encoding="utf-8")
    real = sum(s["real"] for s in stats.values())
    syn = sum(s["synthetic"] for s in stats.values())
    print(f"legit_hard_negatives.csv: {len(seen)} rows ({real} real, {syn} synthetic) from {len(sites)} sites")


if __name__ == "__main__":
    main()
