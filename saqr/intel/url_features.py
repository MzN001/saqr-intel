"""Human-readable URL features for SAQR's phishing model (shared by training and inference).

Every number here has a name a citizen or an analyst can read ("brand name in a sub-domain of an
unrelated site", "cheap TLD .xyz", "login + verify words in the path"), so the model's decision can
always be explained. Pure Python, standard library + tldextract (already a runtime dependency).

Canonical form: scheme, "www." and default ports are dropped and the host is lower-cased, because in
public datasets they are artefacts of how each list was collected, not evidence of fraud.
"""
from __future__ import annotations

import gzip
import math
import re
import unicodedata
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from urllib.parse import unquote, urlsplit

import tldextract

from .registry import ALL_BRANDS, SUSPICIOUS_TLDS

POPULAR_PATH = Path(__file__).with_name("data") / "popular_domains.txt.gz"
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)

# Free hosting / website builders / file shares: legitimate platforms, but most "brand on a free
# sub-domain" phishing lives here (abc-login.web.app, wallet-sync.vercel.app ...).
FREE_HOSTING = (
    "web.app", "firebaseapp.com", "vercel.app", "netlify.app", "pages.dev", "workers.dev", "github.io",
    "gitlab.io", "glitch.me", "herokuapp.com", "onrender.com", "repl.co", "replit.app", "replit.dev",
    "weebly.com", "wixsite.com", "wix.com", "square.site", "godaddysites.com", "blogspot.com",
    "wordpress.com", "webflow.io", "framer.app", "framer.website", "carrd.co", "strikingly.com",
    "jimdosite.com", "site123.me", "mystrikingly.com", "000webhostapp.com", "azurewebsites.net",
    "web.core.windows.net", "blob.core.windows.net", "appspot.com", "ipfs.io", "infura-ipfs.io",
    "dweb.link", "cloudflare-ipfs.com", "fleek.co", "surge.sh", "translate.goog", "sharepoint.com",
    "trycloudflare.com", "ngrok-free.app", "ngrok.io", "codeanyapp.com", "r2.dev", "my.canva.site",
    "notion.site", "typedream.app", "teachable.com", "myshopify.com", "hubspotpagebuilder.com",
    "sites.google.com",
)
SHORTENER_HOSTS = frozenset({
    "bit.ly", "j.mp", "tinyurl.com", "tiny.cc", "t.co", "goo.gl", "is.gd", "v.gd", "cutt.ly", "rebrand.ly",
    "ow.ly", "buff.ly", "rb.gy", "shorturl.at", "s.id", "t.ly", "lnkd.in", "qrco.de", "short.gy", "bl.ink",
    "t2m.io", "dub.sh", "clck.ru", "vk.cc", "u.to", "adf.ly", "ouo.io", "shorte.st", "surl.li", "goo.su",
    "rotf.lol", "n9.cl", "acortar.link", "me2.do", "reurl.cc", "wa.link", "da.gd", "grabify.link", "2no.co",
    "tiny.one", "shorturl.asia", "bitly.ws", "kutt.it", "urlz.fr", "qps.ru", "lnnk.in", "han.gl", "ppt.cc",
})
# Words phishing pages put in their address. English plus the Arabic transliterations seen in UAE
# fine / refund / delivery lures.
LURE_WORDS = frozenset({
    "login", "logon", "signin", "verify", "verification", "validate", "secure", "security", "account",
    "update", "confirm", "billing", "payment", "pay", "wallet", "recover", "recovery", "unlock", "suspend",
    "suspended", "alert", "auth", "authenticate", "claim", "reward", "rewards", "bonus", "gift", "refund",
    "invoice", "delivery", "redelivery", "parcel", "track", "tracking", "customs", "fine", "fines", "kyc",
    "otp", "sso", "webmail", "airdrop", "seed", "support", "helpdesk", "service", "portal", "official",
    "prize", "winner", "renew", "expire", "expired", "reactivate", "restore", "limited", "locked", "unusual",
    "mukhalafa", "mukhalafat", "mukhalafat", "ghrama", "gharama", "gharamat", "sadad", "tasdeed", "tasdid",
    "istirdad", "mukafaa", "jaiza", "tawseel", "shahna", "hukumi",
})
SENSITIVE_PATH = frozenset({
    "login", "logon", "signin", "sign-in", "verify", "verification", "account", "accounts", "secure",
    "update", "confirm", "webscr", "cmd", "auth", "authentication", "session", "billing", "payment",
    "invoice", "unlock", "recover", "password", "passwd", "reset", "kyc", "otp", "wallet", "claim",
    "refund", "redeliver", "redelivery", "track", "tracking", "parcel", "customs", "fine", "fines",
    "validate", "validation", "suspend", "suspended", "restore", "card", "cvv", "pin", "banking", "ebanking",
    "netbanking", "office365", "owa", "outlook", "wp-admin", "wp-includes", "wp-content", "admin",
})
EXT_GROUPS = {"php": "ext_php", "html": "ext_html", "htm": "ext_html", "exe": "ext_exe", "apk": "ext_exe",
              "zip": "ext_exe", "rar": "ext_exe", "scr": "ext_exe", "msi": "ext_exe", "js": "ext_other",
              "asp": "ext_other", "aspx": "ext_other", "jsp": "ext_other", "cgi": "ext_other"}
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a"})
_IPV4 = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_HEXISH = re.compile(r"^[a-z0-9_-]{16,}$", re.I)
_EMAIL = re.compile(r"[\w.+-]+(?:@|%40)[\w-]+\.[\w.]+")
_SPLIT = re.compile(r"[^a-z0-9\u0080-￿]+")
VOWELS = frozenset("aeiou")
# Look-alike letters from other scripts (Cyrillic / Greek / IPA) that punycode homoglyph domains use.
CONFUSABLE = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
                            "ј": "j", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ӏ": "l", "ο": "o", "α": "a",
                            "ν": "v", "ı": "i", "κ": "k", "т": "t", "м": "m", "н": "h", "в": "b", "ь": "b"})


def ascii_skeleton(label: str) -> str:
    """The plain a-z letters a (possibly punycode) label looks like: xn--pypal-4ve -> paypal."""
    if label.startswith("xn--"):
        try:
            label = label.encode("ascii").decode("idna")
        except UnicodeError:
            return label
    label = unicodedata.normalize("NFKD", label.translate(CONFUSABLE))
    return "".join(c for c in label if not unicodedata.combining(c))

FEATURES: tuple[str, ...] = (
    "host_len", "path_len", "query_len", "url_len", "n_labels", "sub_depth", "label_len",
    "host_digit_ratio", "host_hyphens", "host_entropy", "label_entropy", "label_vowel_ratio",
    "host_max_token", "host_digit_letter_switches", "host_max_consonant_run",
    "path_depth", "path_digit_ratio", "path_max_token", "path_random_tokens", "path_entropy",
    "n_params", "pct_density", "embedded_url", "double_slash", "at_userinfo", "nonstd_port",
    "brand_in_sub", "brand_in_label", "brand_common_in_host", "brand_in_path", "brand_sim", "brand_official",
    "susp_tld", "tld_ae", "tld_gov", "free_hosting", "shortener", "raw_ip", "punycode", "non_ascii",
    "host_lures", "path_lures", "sensitive_path", "ext_php", "ext_html", "ext_exe", "ext_other",
    "wp_path", "email_in_url", "pop_bucket",
)
INDEX = {n: i for i, n in enumerate(FEATURES)}


@dataclass
class Parts:
    host: str          # canonical ASCII host, no "www."
    reg_domain: str    # registered domain (example.co.uk)
    label: str         # registrable label (example)
    sub: str           # sub-domain part without www ("" if none)
    suffix: str        # public suffix (co.uk)
    path: str          # raw path ("" for a bare homepage)
    query: str
    port: int | None
    userinfo: bool
    platform: str | None  # free-hosting platform the host sits on

    @property
    def site(self) -> str:
        """Grouping key: the registered domain, or the full host on a shared hosting platform."""
        return self.host if self.platform else self.reg_domain


def canonical(url: str) -> str:
    """URL without scheme / www / default port / fragment (what the models read)."""
    p = parse(url)
    return p.host + (f":{p.port}" if p.port else "") + (p.path or "") + (f"?{p.query}" if p.query else "")


@lru_cache(maxsize=8192)
def parse(url: str) -> Parts:
    raw = (url or "").strip().replace("\\", "/")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", raw, re.I):
        raw = "http://" + raw.lstrip("/")
    try:
        sp = urlsplit(raw)
        host = (sp.hostname or "")
        port = sp.port
    except ValueError:
        sp = urlsplit("http://invalid")
        host, port = "", None
        rest = raw.split("://", 1)[-1]
        host = re.split(r"[/:?#]", rest.split("@")[-1], maxsplit=1)[0]
    host = host.strip().rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii") if any(ord(c) > 127 for c in host) else host
    except UnicodeError:
        pass
    host = re.sub(r"^www\d*\.", "", host)
    if port in (80, 443):
        port = None
    path = sp.path if sp.path not in ("", "/") else ""
    ext = _EXTRACT(host)
    suffix = ext.suffix or (host.rsplit(".", 1)[-1] if "." in host else "")
    label = ext.domain or host.split(".")[0]
    reg = f"{ext.domain}.{suffix}" if ext.domain and suffix else host
    sub = ext.subdomain
    if _IPV4.match(host):
        reg, label, sub, suffix = host, host, "", ""
    platform = next((p for p in FREE_HOSTING if host == p or host.endswith("." + p)), None)
    return Parts(host, reg, label, sub, suffix, path, sp.query, port, "@" in (sp.netloc or ""), platform)


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def levenshtein(a: str, b: str, limit: int) -> int:
    """Edit distance, cut off at limit + 1 (enough to tell 'close to a brand' from 'unrelated')."""
    if abs(len(a) - len(b)) > limit:
        return limit + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        best = i
        for j, cb in enumerate(b, 1):
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            cur.append(v)
            best = min(best, v)
        if best > limit:
            return limit + 1
        prev = cur
    return prev[-1]


@dataclass(frozen=True)
class _Brand:
    name: str
    official: frozenset[str]   # official registered domains
    tokens: frozenset[str]     # distinctive tokens (paypal, adcb, uaepass)
    common: frozenset[str]     # ordinary words (apple, amazon): count next to a lure word only
    labels: tuple[str, ...]    # official labels used for the look-alike distance


@lru_cache(maxsize=1)
def brands() -> tuple[_Brand, ...]:
    out = []
    for e in ALL_BRANDS:
        official = frozenset(d.lower() for d in e.domains)
        toks = {k.lower().replace("-", "") for k in e.keywords if k}
        out.append(_Brand(e.name_en, official, frozenset(t for t in toks if t),
                          frozenset(k.lower() for k in e.common_keywords),
                          tuple(sorted({d.split(".")[0] for d in official if len(d.split(".")[0]) >= 4}))))
    return tuple(out)


@lru_cache(maxsize=1)
def popular_ranks() -> dict[str, int]:
    try:
        with gzip.open(POPULAR_PATH, "rt", encoding="utf-8") as f:
            return {d.strip(): i for i, d in enumerate(f, start=1) if d.strip()}
    except OSError:
        return {}


def tokens_of(text: str) -> list[str]:
    return [t for t in _SPLIT.split(text.lower()) if t]


def _brand_hits(tokens: list[str], joined: str, has_lure: bool, reg: str) -> tuple[str | None, str | None]:
    """(distinctive brand, common-word brand) named in these tokens on a site that is not the brand's."""
    strong = common = None
    tokset = set(tokens)
    for b in brands():
        if reg in b.official:
            continue
        if strong is None and any((t in tokset) if len(t) < 5 else (t in tokset or t in joined) for t in b.tokens):
            strong = b.name
        if common is None and has_lure and b.common & tokset:
            common = b.name
    return strong, common


def extract(url: str) -> tuple[list[float], dict]:
    """Named feature vector (order = FEATURES) and the context used to explain it."""
    p = parse(url)
    host, path, query = p.host, p.path, p.query
    ctx: dict = {"host": host, "reg_domain": p.reg_domain, "tld": p.suffix, "platform": p.platform}
    v = [0.0] * len(FEATURES)

    def put(name: str, value: float) -> None:
        v[INDEX[name]] = float(value)

    is_ip = bool(_IPV4.match(host))
    labels = host.split(".") if host else []
    # On a free-hosting platform the customer's part is the sub-domain: judge that, not "vercel".
    own = host[: -len(p.platform) - 1] if p.platform and host != p.platform else (p.label if not is_ip else "")
    host_tokens = tokens_of(p.sub if not p.platform else "") + tokens_of(own)
    letters = [c for c in own if c.isalpha()]
    digits = sum(c.isdigit() for c in host)
    put("host_len", len(host))
    put("path_len", len(path))
    put("query_len", len(query))
    put("url_len", len(host) + len(path) + (len(query) + 1 if query else 0))
    put("n_labels", len(labels))
    sub_labels = [s for s in (own.split(".") if p.platform else p.sub.split(".")) if s] if not is_ip else []
    put("sub_depth", len(sub_labels))
    put("label_len", len(own))
    put("host_digit_ratio", digits / max(1, len(host)))
    put("host_hyphens", host.count("-"))
    put("host_entropy", entropy(host))
    put("label_entropy", entropy(own))
    put("label_vowel_ratio", sum(c in VOWELS for c in letters) / max(1, len(letters)))
    put("host_max_token", max((len(t) for t in host_tokens), default=0))
    put("host_digit_letter_switches", sum(1 for a, b in zip(own, own[1:]) if a.isdigit() != b.isdigit()
                                          and (a.isalnum() and b.isalnum())))
    put("host_max_consonant_run", max((len(m) for m in re.findall(r"[bcdfghjklmnpqrstvwxz]+", own)), default=0))

    dpath = unquote(path)
    segs = [s for s in dpath.split("/") if s]
    path_tokens = tokens_of(dpath)
    put("path_depth", len(segs))
    put("path_digit_ratio", sum(c.isdigit() for c in path) / max(1, len(path)))
    put("path_max_token", max((len(t) for t in path_tokens), default=0))
    put("path_random_tokens", sum(1 for s in re.split(r"[/?&=.]", dpath + "&" + query)
                                  if _HEXISH.match(s) and re.search(r"\d", s) and re.search(r"[a-z]", s, re.I)))
    put("path_entropy", entropy(dpath))
    params = [kv for kv in query.split("&") if kv]
    put("n_params", len(params))
    whole = path + "?" + query
    put("pct_density", whole.count("%") / max(1, len(whole)))
    low_q = unquote(query).lower()
    put("embedded_url", int(bool(re.search(r"(?:https?:)?//|www\.", low_q + " " + dpath.lower()[1:]))))
    put("double_slash", int("//" in path))
    put("at_userinfo", int(p.userinfo))
    put("nonstd_port", int(p.port is not None))

    host_lure = sorted({t for t in host_tokens if t in LURE_WORDS})
    path_lure = sorted({t for t in path_tokens if t in LURE_WORDS})
    joined_host = "".join(host_tokens)
    s_brand, c_brand = _brand_hits(host_tokens, joined_host, bool(host_lure), p.reg_domain)
    sub_tokens = tokens_of(p.sub) if not p.platform else []
    sub_brand, _ = _brand_hits(sub_tokens, "".join(sub_tokens), False, p.reg_domain) if sub_tokens else (None, None)
    label_tokens = tokens_of(own if p.platform else p.label)
    label_brand, _ = _brand_hits(label_tokens, "".join(label_tokens), False, p.reg_domain)
    path_brand, _ = _brand_hits([t for t in path_tokens if len(t) >= 4], "", False, p.reg_domain)
    official = next((b.name for b in brands() if p.reg_domain in b.official), None)
    put("brand_in_sub", int(bool(sub_brand)))
    put("brand_in_label", int(bool(label_brand)))
    put("brand_common_in_host", int(bool(c_brand)))
    put("brand_in_path", int(bool(path_brand)))
    put("brand_official", int(bool(official)))
    ctx["brand"] = s_brand or c_brand or path_brand
    ctx["brand_where"] = ("sub" if sub_brand else "label" if label_brand else "host" if c_brand else
                          "path" if path_brand else None)

    sim, near = 0.0, None
    skel = ascii_skeleton(own).translate(_LEET).replace("rn", "m").replace("vv", "w").replace("-", "")
    if not official and not is_ip and len(skel) >= 4:
        for b in brands():
            for lab in b.labels:
                if skel == lab:
                    s = 1.0 if own != lab else 0.99
                else:
                    lim = 1 if len(lab) < 7 else 2
                    d = levenshtein(skel, lab, lim)
                    s = 1.0 - d / max(len(skel), len(lab)) if d <= lim else 0.0
                if s > sim:
                    sim, near = s, lab
    put("brand_sim", sim if sim < 1.0 or own != near else 0.0)
    ctx["brand_near"] = near if sim > 0 else None
    ctx["own"] = own

    tld = p.suffix.split(".")[-1] if p.suffix else ""
    put("susp_tld", int(tld in SUSPICIOUS_TLDS))
    put("tld_ae", int(tld == "ae" or tld == "abudhabi"))
    put("tld_gov", int(".gov." in f".{p.suffix}." or p.suffix in ("gov", "gov.ae", "mil", "edu")))
    put("free_hosting", int(bool(p.platform)))
    put("shortener", int(host in SHORTENER_HOSTS))
    put("raw_ip", int(is_ip))
    put("punycode", int("xn--" in host))
    put("non_ascii", int(any(ord(c) > 127 for c in unquote(path + query))))
    put("host_lures", len(host_lure))
    put("path_lures", len(path_lure))
    sens = sorted({t for t in tokens_of(dpath.replace("-", "")) + [s.lower() for s in segs] if t in SENSITIVE_PATH})
    put("sensitive_path", len(sens))
    last = segs[-1].lower() if segs else ""
    ext = last.rsplit(".", 1)[-1] if "." in last else ""
    if ext in EXT_GROUPS:
        put(EXT_GROUPS[ext], 1)
    put("wp_path", int(bool(re.search(r"/wp-(?:content|includes|admin)/", path.lower()))))
    put("email_in_url", int(bool(_EMAIL.search(unquote(path + "?" + query)))))
    rank = popular_ranks().get(p.reg_domain) if not p.platform else None
    put("pop_bucket", 1 + int(math.log10(rank)) if rank else 0)
    ctx.update(host_lures=host_lure, path_lures=path_lure, sensitive=sens, ext=ext, rank=rank)
    return v, ctx
