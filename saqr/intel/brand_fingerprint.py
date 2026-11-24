"""Brand fingerprint: does this page dress up as an official UAE portal?

A phishing kit copies the real portal's look: its title and name, logo and favicon (often HOTLINKED
straight from the official site), colours, and the shape of its log-in form. extract() reads those
traits from HTML that was already fetched (no browser, no third-party service); similarity() compares
them with baselines captured from the real portals (`data/brand_fingerprints.json`, built by
`tools/build_brand_fingerprints.py`).

Designed so ordinary pages do not score high:
* Only brand-specific evidence (the page presenting itself under the brand's name, the brand's own
  assets, its exact favicon) can lift a page above 40. Colours and form shape are generic: they only
  corroborate.
* >= 75 needs at least two independent components to agree.
* A page that names several brands (comparison sites), or whose own site name / copyright line is
  another organisation (news, partners), is discounted.

Page content is attacker-controlled data: it is only parsed and compared, never executed or followed.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

log = logging.getLogger("saqr.brand_fingerprint")

DATA_PATH = Path(__file__).resolve().parent / "data" / "brand_fingerprints.json"
CLONE_THRESHOLD = 75      # strong: VISUAL_BRAND_CLONE_DETECTED
WEAK_THRESHOLD = 50       # weak corroboration only: VISUAL_BRAND_SIMILARITY
FAVICON_LIMIT = 50_000
HTML_LIMIT = 300_000
# Tests inject an httpx.MockTransport here (favicon fetch).
TRANSPORT: httpx.AsyncBaseTransport | None = None

_AR_DIACRITICS = re.compile(r"[ؐ-ًؚ-ٰٟۖ-ۭـ]")
_AR_FOLD = str.maketrans({"أ": "ا", "إ": "ا", "آ": "ا", "ٱ": "ا", "ة": "ه", "ى": "ي", "ؤ": "و", "ئ": "ي"})
_SEGMENT_SPLIT = re.compile(r"\s+[-–—|:·•»/]+\s+|[|–—·•»]")
STOPWORDS = frozenset("""
a an and the of for to in on at by with from your you our my is are be or as it this that
home page official website site welcome portal online login log sign signin services service
uae abu dhabi dubai emirates united arab
في من الى على عن مع او ثم هذا هذه التي الذي الصفحه الرئيسيه الموقع الرسمي خدمات خدمه
""".split())
GENERIC_ASSET_STEMS = frozenset("""
logo favicon main style styles app index bundle vendor vendors common site theme jquery bootstrap
polyfills polyfill runtime chunk script scripts global globals custom default icon apple-touch-icon
manifest font fonts fontawesome all core base print responsive layout header footer image img banner
rtl ltr min pinned tab safari touch apple android chrome mstile thumbnail teams microsoft autocomplete
classic white black red blue dark light ver hor en ar svg png webp
""".split())
# Hosts that serve assets for every website: never brand evidence.
GENERIC_ASSET_HOSTS = (
    "googleapis.com", "gstatic.com", "googletagmanager.com", "google-analytics.com", "google.com",
    "doubleclick.net", "jsdelivr.net", "cdnjs.cloudflare.com", "unpkg.com", "jquery.com", "bootstrapcdn.com",
    "fontawesome.com", "facebook.net", "facebook.com", "twitter.com", "x.com", "linkedin.com", "youtube.com",
    "hotjar.com", "clarity.ms", "cloudflare.com", "cloudflareinsights.com", "w3.org", "schema.org",
    "typekit.net", "fonts.net", "adobedtm.com", "newrelic.com", "nr-data.net", "onetrust.com", "cookielaw.org",
    "recaptcha.net", "hcaptcha.com", "akamaihd.net", "azureedge.net", "cloudfront.net", "amazonaws.com",
)
_HEX = re.compile(r"#([0-9a-fA-F]{6}|[0-9a-fA-F]{3})(?![0-9a-fA-F])")
_RGB = re.compile(r"rgba?\(\s*(\d{1,3})\s*,\s*(\d{1,3})\s*,\s*(\d{1,3})")
_BRAND_VAR = re.compile(r"--[\w-]*(?:primary|brand|main|accent|theme|secondary)[\w-]*\s*:\s*([^;{}]+)", re.I)
_COPYRIGHT = re.compile(r"(?:©|&copy;|\(c\)\s*\d{4}|copyright|all rights reserved|جميع الحقوق|حقوق النشر)", re.I)
_UAEPASS_BUTTON = re.compile(r"uae\s?pass|الهويه الرقميه", re.I)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def norm(text: str | None) -> str:
    """Lower-case, NFKC, Arabic diacritics / tatweel removed and letter variants folded (أ→ا, ة→ه);
    punctuation becomes a space ("&" is kept for e&)."""
    t = unicodedata.normalize("NFKC", text or "").lower()
    t = _AR_DIACRITICS.sub("", t).translate(_AR_FOLD)
    t = re.sub(r"[^\w&\s]", " ", t)
    return re.sub(r"\s+", " ", t).strip()


def tokens(text: str | None) -> list[str]:
    return [t for t in norm(text).split() if len(t) >= 2 and t not in STOPWORDS and not t.isdigit()]


def segments(title: str | None) -> list[str]:
    return [s for s in (norm(p) for p in _SEGMENT_SPLIT.split(title or "")) if s]


def _short(term: str) -> bool:
    return len(term.replace(" ", "")) <= 3


def term_in(term: str, text: str) -> bool:
    """Whole-word / whole-phrase match of a normalised brand term in normalised text."""
    return bool(term) and re.search(rf"(?<![\w&]){re.escape(term)}(?![\w&])", text) is not None


def _short_term_hit(term: str, segs: list[str], site_name: str, copyright_: str) -> bool:
    """Short brand names (du, fab, icp, تم, دو) are ordinary words in running text (French "du", Arabic
    "تم" = "done"): they only count as a whole title segment, the whole site name, or the copyright line."""
    return (any(s == term or s.startswith(term + " ") for s in segs) or term == site_name
            or (bool(copyright_) and term_in(term, copyright_)))


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------
def _clean_basename(path: str) -> str:
    base = (path.rsplit("/", 1)[-1] or "").split("?")[0].split("#")[0].lower()
    base = re.sub(r"[.\-_~][0-9a-f]{6,}(?=[.\-_~])", "", base)  # main.3f2a1b9c.css -> main.css
    return base[:80]


def asset_stem(name: str) -> str:
    stem = re.sub(r"\.(min|bundle)(?=\.)", "", name or "")
    return stem.rsplit(".", 1)[0] if "." in stem else stem


def distinctive_asset(name: str) -> bool:
    stem = asset_stem(name)
    parts = [p for p in re.split(r"[.\-_~]", stem) if p]
    if len(stem) < 5 or not parts or all(p in GENERIC_ASSET_STEMS or re.fullmatch(r"\d+|\d+x\d+|[a-z]?\d+[a-z]?", p)
                                          for p in parts):
        return False
    return not re.fullmatch(r"[0-9a-f\-_.]+", stem)  # content hashes / numeric ids


def generic_host(host: str) -> bool:
    h = (host or "").lower()
    return any(h == g or h.endswith("." + g) for g in GENERIC_ASSET_HOSTS)


def _colour(raw: str) -> tuple[int, int, int] | None:
    raw = raw.strip()
    m = _HEX.search(raw)
    if m:
        h = m.group(1)
        if len(h) == 3:
            h = "".join(c * 2 for c in h)
        return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
    m = _RGB.search(raw)
    if m:
        return tuple(min(255, int(x)) for x in m.groups())  # type: ignore[return-value]
    return None


def _chromatic(rgb: tuple[int, int, int]) -> bool:
    """Brand colours, not greys / near-white tints / near-black."""
    hi, lo = max(rgb), min(rgb)
    return hi - lo >= 30 and lo <= 200 and hi >= 35


def colour_distance(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    return sum((x - y) ** 2 for x, y in zip(a, b)) ** 0.5


def hex_of(rgb: tuple[int, int, int]) -> str:
    return "#%02x%02x%02x" % rgb


def dominant_colours(css_text: str, theme: list[str] = (), limit: int = 6) -> list[str]:
    counts: list[list[Any]] = []  # [rgb, weight]

    def add(rgb: tuple[int, int, int] | None, w: float) -> None:
        if rgb is None or not _chromatic(rgb):
            return
        for c in counts:
            if colour_distance(c[0], rgb) <= 24:
                c[1] += w
                return
        counts.append([rgb, w])

    for t in theme:
        add(_colour(t), 6)
    for m in _BRAND_VAR.finditer(css_text):
        add(_colour(m.group(1)), 4)
    for m in _HEX.finditer(css_text):
        add(_colour(m.group(0)), 1)
    for m in _RGB.finditer(css_text):
        add(_colour(m.group(0)), 1)
    counts.sort(key=lambda c: -c[1])
    return [hex_of(c[0]) for c in counts[:limit]]


def _forms(soup: Any) -> list[dict[str, Any]]:
    from .sandbox import form_fields  # local: sandbox imports this module's callers

    return form_fields(soup)


def extract(html: str | None, base_url: str) -> dict[str, Any]:
    """Fingerprint of a page from its HTML (already fetched). Never raises on bad markup."""
    from bs4 import BeautifulSoup

    from .sandbox import classify_fields

    html = (html or "")[:HTML_LIMIT]
    soup = BeautifulSoup(html, "html.parser")
    base_host = (urlsplit(base_url).hostname or "").lower()

    def meta(*names: str) -> str:
        for n in names:
            tag = soup.find("meta", attrs={"property": n}) or soup.find("meta", attrs={"name": n})
            if tag and tag.get("content"):
                return str(tag["content"])[:300]
        return ""

    title = soup.title.get_text(" ", strip=True)[:300] if soup.title else ""
    site_name = meta("og:site_name", "application-name", "apple-mobile-web-app-title")
    description = meta("description", "og:description")
    theme = [t for t in (meta("theme-color"), meta("msapplication-TileColor")) if t]

    styles = " ".join(s.get_text(" ") for s in soup.find_all("style"))[:200_000]
    inline = " ".join(str(t.get("style")) for t in soup.find_all(style=True))[:100_000]

    phrases: list[str] = []
    for tag in soup.find_all(["h1", "h2", "header"], limit=12):
        phrases.append(tag.get_text(" ", strip=True)[:120])
    for tag in soup.find_all(True, attrs={"class": re.compile("logo|brand", re.I)}, limit=10):
        phrases.append(" ".join(filter(None, [tag.get_text(" ", strip=True)[:80], tag.get("alt") or "",
                                              tag.get("aria-label") or "", tag.get("title") or ""])))
    for img in soup.find_all("img", alt=True, limit=40):
        alt = str(img.get("alt") or "")
        if "logo" in alt.lower() or "logo" in str(img.get("src") or "").lower() or "شعار" in alt:
            phrases.append(alt[:80])
    phrases = [p for p in dict.fromkeys(norm(p) for p in phrases) if p][:30]

    for t in soup(["script", "style", "noscript", "template"]):
        t.decompose()
    text = re.sub(r"\s+", " ", soup.get_text(" ", strip=True))[:20_000]
    copyright_ = ""
    m = _COPYRIGHT.search(text)
    if m:
        copyright_ = norm(text[m.start(): m.end() + 90])  # the owner named after the sign, not the text before

    assets: list[dict[str, str]] = []

    def add_asset(kind: str, src: str | None) -> None:
        if not src or src.startswith("data:") or len(assets) >= 80:
            return
        try:
            u = urljoin(base_url, src.strip())
            host = (urlsplit(u).hostname or "").lower()
        except ValueError:
            return
        assets.append({"kind": kind, "name": _clean_basename(urlsplit(u).path), "host": host})

    favicon = ""
    for link in soup.find_all("link", href=True):
        rel = " ".join(link.get("rel") or []).lower() if isinstance(link.get("rel"), list) else str(link.get("rel") or "").lower()
        if "icon" in rel:
            add_asset("favicon", link["href"])
            favicon = favicon or urljoin(base_url, link["href"].strip())
        elif "stylesheet" in rel:
            add_asset("css", link["href"])
    for s in soup.find_all("script", src=True):
        add_asset("js", s["src"])
    for img in soup.find_all("img", src=True, limit=60):
        blob = " ".join(str(img.get(k) or "") for k in ("src", "alt", "class", "id")).lower()
        add_asset("logo" if "logo" in blob or "شعار" in blob else "img", img["src"])
    og = meta("og:image")
    if og:
        add_asset("og", og)
    if not favicon and base_host:
        favicon = urljoin(base_url, "/favicon.ico")

    forms = _forms(BeautifulSoup(html, "html.parser"))
    kinds = classify_fields(forms)
    action_hosts = sorted({(urlsplit(urljoin(base_url, f.get("action") or "")).hostname or "").lower()
                           for f in forms if f.get("action")} - {""})
    root = soup.find("html")
    return {
        "url": base_url[:300], "host": base_host,
        "title": title, "title_segments": segments(title)[:8], "title_tokens": sorted(set(tokens(title)))[:30],
        "site_name": norm(site_name), "description_tokens": sorted(set(tokens(description)))[:40],
        "phrases": phrases, "copyright": copyright_[:200], "text": norm(text[:6000]),
        "form": {"kinds": kinds, "action_hosts": action_hosts,
                 "field_count": sum(len(f.get("fields") or []) for f in forms),
                 "uaepass_button": bool(_UAEPASS_BUTTON.search(norm(text)))},
        "assets": assets, "colours": dominant_colours(styles + " " + inline, theme),
        "lang": (root.get("lang") or "")[:10].lower() if root else "",
        "dir": (root.get("dir") or "")[:5].lower() if root else "",
        "favicon": favicon[:300], "favicon_hash": None,
    }


# ---------------------------------------------------------------------------
# Baselines
# ---------------------------------------------------------------------------
@lru_cache(maxsize=1)
def baselines() -> tuple[dict[str, Any], ...]:
    try:
        data = json.loads(DATA_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        log.warning("brand fingerprints unavailable: %s", exc)
        return ()
    out = []
    for b in data.get("baselines") or []:
        b = dict(b)
        b["brand_terms"] = [norm(t) for t in b.get("brand_terms") or [] if norm(t)]
        out.append(b)
    return tuple(out)


def _owns(baseline: dict[str, Any], host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in baseline.get("official_domains") or [])


def _brand_named(baseline: dict[str, Any], fp: dict[str, Any], where: str) -> bool:
    segs, site, copy_ = fp.get("title_segments") or [], fp.get("site_name") or "", fp.get("copyright") or ""
    title = " ".join(segs)
    for term in baseline["brand_terms"]:
        if _short(term):
            if where == "identity" and _short_term_hit(term, segs, site, copy_):
                return True
            continue
        if where == "identity" and (term_in(term, title) or term_in(term, site)):
            return True
    return False


def brands_named(fp: dict[str, Any], pool: tuple[dict[str, Any], ...] | None = None) -> set[str]:
    """Baseline ids whose brand the page names in its title or site name."""
    return {b["id"] for b in (pool if pool is not None else baselines()) if _brand_named(b, fp, "identity")}


def _title_component(fp: dict[str, Any], b: dict[str, Any], n_brands: int) -> int:
    segs = fp.get("title_segments") or []
    title = " ".join(segs)
    site, copy_ = fp.get("site_name") or "", fp.get("copyright") or ""
    phrases = " | ".join(fp.get("phrases") or [])
    text = fp.get("text") or ""
    terms = b["brand_terms"]

    def hit(where: str) -> bool:
        for t in terms:
            if _short(t):
                if where == "title" and any(s == t or s.startswith(t + " ") for s in segs):
                    return True
                if where == "site" and t == site:
                    return True
                if where == "copyright" and copy_ and term_in(t, copy_):
                    return True
                if where == "phrases" and t in (fp.get("phrases") or []):
                    return True
                continue
            src = {"title": title, "site": site, "copyright": copy_, "phrases": phrases, "text": text}[where]
            if term_in(t, src):
                return True
        return False

    score = 0.0
    if hit("title"):
        score = 75 if any(any(s == t or s.startswith(t + " ") for t in terms) for s in segs) else 60
    if hit("site"):
        score = score + 25 if score else 75
    if hit("copyright"):
        score += 20
    if hit("phrases"):
        score += 15
    if not score and hit("text"):
        score = 20
    if not score:
        return 0
    base_tokens = set(b.get("title_tokens") or [])
    page_tokens = set(fp.get("title_tokens") or [])
    brand_tok = {w for t in terms for w in t.split()}
    shared = (base_tokens & page_tokens) - brand_tok
    if base_tokens:
        score += min(15, 5 * len(shared))
    # The page says it is someone else: a news site's name, a partner's copyright line.
    if site and not hit("site"):
        score *= 0.6
    if copy_ and not hit("copyright"):
        score *= 0.6
    if n_brands >= 2:  # comparison / aggregator pages name several brands at once
        score *= 0.5
    return int(min(100, round(score)))


def _asset_component(fp: dict[str, Any], b: dict[str, Any], hotlinked_brands: int) -> int:
    page_host = fp.get("host") or ""
    brand_hosts = set(b.get("asset_hosts") or [])
    names = set(b.get("asset_names") or [])
    kinds_hot: set[str] = set()
    named = 0
    for a in fp.get("assets") or []:
        host = a.get("host") or ""
        if host and host != page_host and not generic_host(host) and (
                _owns(b, host) or host in brand_hosts):
            kinds_hot.add(a.get("kind") or "img")
        elif a.get("name") in names and distinctive_asset(a.get("name") or ""):
            named += 1
    score = 0
    strong = kinds_hot & {"css", "js", "favicon", "logo"}
    if len(strong) >= 2:
        score = 100
    elif strong:
        score = 85 if strong & {"css", "favicon"} else 75
    elif kinds_hot:
        score = 40  # an image from the official site: partners and news embed those
    if named:
        score = max(score, min(90, 60 + 15 * (named - 1)))
    if hotlinked_brands >= 2:
        score = int(score * 0.4)
    return score


def _colour_component(fp: dict[str, Any], b: dict[str, Any]) -> int | None:
    base = [_colour(c) for c in (b.get("colours") or [])[:5]]
    base = [c for c in base if c]
    if not base:
        return None
    page = [_colour(c) for c in fp.get("colours") or []]
    page = [c for c in page if c]
    if not page:
        return 0
    matched = sum(1 for c in base if any(colour_distance(c, p) <= 30 for p in page))
    return int(round(100 * min(matched, 3) / min(3, len(base))))


def _form_component(fp: dict[str, Any], b: dict[str, Any]) -> int | None:
    base = set(b.get("form_kinds") or [])
    if not base:
        return None
    page = set((fp.get("form") or {}).get("kinds") or [])
    if not page:
        return 0
    common = base & page
    if not common:
        return 0
    coverage = len(common) / len(base)
    specific = common & {"UAE_PASS", "EMIRATES_ID", "OTP", "CARD_NUMBER", "CVV", "ATM_PIN", "IBAN"}
    return int(round(100 * coverage if specific else 60 * coverage))


def _favicon_component(fp: dict[str, Any], b: dict[str, Any]) -> int | None:
    page, base = fp.get("favicon_hash"), b.get("favicon_sha256")
    if not page or not base:
        return None
    return 100 if page == base else 0


def similarity(fp: dict[str, Any], baseline: dict[str, Any],
               pool: tuple[dict[str, Any], ...] | None = None) -> dict[str, Any]:
    """0-100 likeness of a page fingerprint to one official baseline, with the per-component breakdown.
    Generic evidence (colours, form shape) alone never exceeds 40; >= 75 needs two components that
    agree, one of them brand-specific (title / phrases, assets, favicon)."""
    pool = pool if pool is not None else baselines()
    named = brands_named(fp, pool)
    hot_brands = {x["id"] for x in pool for a in fp.get("assets") or []
                  if a.get("host") and a.get("host") != fp.get("host") and not generic_host(a["host"])
                  and (_owns(x, a["host"]) or a["host"] in set(x.get("asset_hosts") or []))}
    comps: dict[str, int | None] = {
        "title": _title_component(fp, baseline, len(named)),
        "assets": _asset_component(fp, baseline, len(hot_brands)),
        "colours": _colour_component(fp, baseline),
        "form": _form_component(fp, baseline),
        "favicon": _favicon_component(fp, baseline),
    }
    vals = sorted((v for v in comps.values() if v is not None), reverse=True) + [0, 0, 0]
    score = 0.55 * vals[0] + 0.30 * vals[1] + 0.15 * vals[2]
    agree = [k for k, v in comps.items() if v is not None and v >= 50]
    brand_specific = any((comps.get(k) or 0) >= 50 for k in ("title", "assets", "favicon"))
    if not brand_specific:
        score = min(score, 40)
    elif len(agree) < 2:
        score = min(score, CLONE_THRESHOLD - 1)
    return {"score": int(round(score)), "components": comps, "agreeing": agree}


def best_match(fp: dict[str, Any], host: str | None = None) -> dict[str, Any] | None:
    """The official portal this page looks most like (never one that owns `host`), or None."""
    pool = baselines()
    best: dict[str, Any] | None = None
    for b in pool:
        if host and _owns(b, host):
            continue
        sim = similarity(fp, b, pool)
        if best is None or sim["score"] > best["score"]:
            best = {**sim, "id": b["id"], "entity_id": b.get("entity_id"), "name_en": b.get("name_en"),
                    "name_ar": b.get("name_ar"), "matched_domain": (b.get("official_domains") or [None])[0],
                    "official_domains": list(b.get("official_domains") or []), "status": b.get("status")}
    return best


def favicon_candidate(fp: dict[str, Any]) -> str | None:
    """Favicon URL worth fetching: on the page's own (or another non-official) host only. A favicon
    hotlinked from an official domain is already asset evidence and is never fetched."""
    url = fp.get("favicon") or ""
    host = (urlsplit(url).hostname or "").lower()
    if not url.startswith(("http://", "https://")) or not host:
        return None
    if any(_owns(b, host) for b in baselines()):
        return None
    from .domain_intel import official_match

    return None if official_match(host) else url


async def fetch_favicon_hash(url: str, timeout: float = 3.0) -> str | None:
    """sha256 of the favicon bytes (<= 50 KB), one SSRF-guarded GET. Failure is silent (None)."""
    from ..config import settings
    from ..security import host_is_safe_target

    if settings.offline_mode and TRANSPORT is None:
        return None
    host = urlsplit(url).hostname or ""
    try:
        ok, _ = await host_is_safe_target(host)
        if not ok:
            return None
        async with httpx.AsyncClient(follow_redirects=False, verify=False, transport=TRANSPORT, timeout=timeout,
                                     headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                                                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                                                            "Chrome/131.0.0.0 Safari/537.36"}) as c:
            async with c.stream("GET", url) as r:
                if r.status_code != 200:
                    return None
                data = b""
                async for chunk in r.aiter_bytes():
                    data += chunk
                    if len(data) > FAVICON_LIMIT:
                        return None
        return hashlib.sha256(data).hexdigest() if data else None
    except Exception:  # noqa: BLE001 - optional evidence
        return None
