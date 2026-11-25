"""Module 1 — Lookalike domain detection + live network intelligence.

* URL normalisation (incl. refanging `hxxp://evil[.]com`)
* Whitelist check (exact domain or sub-domain of an official UAE domain)
* Fuzzy similarity (rapidfuzz), homoglyph / punycode / leetspeak spoofing
* Suspicious TLD + lure keyword heuristics
* WHOIS age, DNS (A/MX/NS), ASN (Team Cymru DNS), TLS certificate issuer/age
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
import ssl
import unicodedata
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import tldextract
from rapidfuzz import fuzz

from ..config import settings
from .registry import (
    ALL_BRANDS,
    GOV_AE_SUFFIX,
    LURE_KEYWORDS,
    OFFICIAL_DOMAINS,
    SHARED_INFRA_ASNS,
    SUSPICIOUS_TLDS,
    Entity,
)

log = logging.getLogger("saqr.domain")

# Dedicated pool so a hung WHOIS socket can never block the default executor / app shutdown.
_WHOIS_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="whois")


def shutdown_pools() -> None:
    _WHOIS_POOL.shutdown(wait=False, cancel_futures=True)


# Offline-capable PSL extractor (bundled snapshot, no network fetch).
_EXTRACT = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None)


@lru_cache(maxsize=512)
def _official_parts(domain: str):
    """tldextract of an official brand domain, parsed once (it ran ~170x per lexical check)."""
    return _EXTRACT(domain)

# Confusable characters -> Latin skeleton (subset of Unicode TR39 most used in phishing)
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j",
    "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ⅼ": "l", "ӏ": "l", "ո": "n", "ս": "u", "ԝ": "w",
    "α": "a", "ο": "o", "ρ": "p", "ε": "e", "ι": "i", "κ": "k", "ν": "v", "τ": "t", "υ": "u",
    "ı": "i", "ℓ": "l", "ß": "b", "ø": "o", "đ": "d", "ł": "l",
}
LEET = {"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "@": "a", "$": "s"}
MULTI_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("cl", "d"))


@dataclass
class RedFlag:
    code: str
    severity: str  # low | medium | high | critical
    points: int
    en: str
    ar: str


@dataclass
class LexicalReport:
    input: str
    normalized_url: str
    host: str
    registered_domain: str
    label: str  # registrable label (e.g. "tamm-smart-pay")
    tld: str
    is_whitelisted: bool
    official_match: str | None
    impersonated: Entity | None
    is_punycode: bool
    unicode_host: str
    similarity: float
    flags: list[RedFlag] = field(default_factory=list)

    @property
    def score(self) -> int:
        return min(100, sum(f.points for f in self.flags))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["impersonated"] = self.impersonated.name_en if self.impersonated else None
        d["score"] = self.score
        return d


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def refang(raw: str) -> str:
    s = raw.strip().strip("<>\"'")
    s = re.sub(r"\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)", ".", s, flags=re.I)
    s = re.sub(r"^hxxp", "http", s, flags=re.I)
    s = s.replace("[:]", ":").replace("[://]", "://")
    return s


def normalize_url(raw: str) -> tuple[str, str]:
    """Return (normalised_url, ascii_host). Raises ValueError on garbage input."""
    s = refang(raw)
    if not re.match(r"^[a-z][a-z0-9+.-]*://", s, re.I):
        s = "http://" + s
    parts = urlsplit(s)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only http(s) URLs are supported")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host or len(host) > 253:
        raise ValueError("URL has no valid host")
    try:
        ascii_host = host.encode("idna").decode("ascii")
    except UnicodeError:
        ascii_host = host
    netloc = ascii_host + (f":{parts.port}" if parts.port else "")
    return urlunsplit((parts.scheme.lower(), netloc, parts.path or "/", parts.query, "")), ascii_host


def to_unicode_host(ascii_host: str) -> str:
    out = []
    for label in ascii_host.split("."):
        if label.startswith("xn--"):
            try:
                out.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        out.append(label)
    return ".".join(out)


def skeleton(text: str, multi: bool = False) -> str:
    """Map homoglyphs + leetspeak to a Latin skeleton for spoof comparison.
    `multi` also folds multi-char confusables (rn->m, vv->w) — only for label comparison."""
    t = unicodedata.normalize("NFKD", text.lower())
    t = "".join(ch for ch in t if not unicodedata.combining(ch))
    t = "".join(CONFUSABLES.get(ch, ch) for ch in t)
    t = "".join(LEET.get(ch, ch) for ch in t)
    if multi:
        for a, b in MULTI_CONFUSABLES:
            t = t.replace(a, b)
    return t


def official_match(host: str) -> str | None:
    for d in OFFICIAL_DOMAINS:
        if host == d or host.endswith("." + d):
            return d
    return gov_ae_domain(host)


def gov_ae_domain(host: str) -> str | None:
    """The registered domain when `host` is under the gov.ae public suffix (restricted to UAE government
    entities, see registry.GOV_AE_SUFFIX). Only a true registration counts: adpolice-gov.ae.evil.com,
    gov.ae.example.com and the bare suffix "gov.ae" do not."""
    h = (host or "").lower().rstrip(".")
    if not h.endswith("." + GOV_AE_SUFFIX):
        return None
    ext = _EXTRACT(h)
    if ext.suffix != GOV_AE_SUFFIX or not ext.domain:
        return None
    return f"{ext.domain}.{ext.suffix}"


def _tokens(label: str) -> list[str]:
    return [t for t in re.split(r"[-_.]", label) if t]


def _keyword_hit(keyword: str, host_skel: str, tokens: list[str]) -> bool:
    kw = keyword.replace("-", "")
    if len(kw) <= 4:
        # Short brands (du, fab, tamm, adcb) must be a whole token, or fused only with a lure word
        # ("tammpay", "paydu") — so "dubai", "fabric", "tammy" don't fire.
        for t in tokens:
            if t == kw:
                return True
            if t.startswith(kw) and t[len(kw):] in LURE_KEYWORDS:
                return True
            if t.endswith(kw) and t[: -len(kw)] in LURE_KEYWORDS:
                return True
        return False
    return kw in host_skel.replace("-", "").replace(".", "")


def _lure_token(tokens: list[str]) -> bool:
    return any(t in LURE_KEYWORDS or any(t.startswith(k) or t.endswith(k) for k in LURE_KEYWORDS if len(k) > 3)
               for t in tokens)


def _global_brand_hit(ent: Entity, tokens: list[str]) -> bool:
    """Global brands match whole tokens only ("paypal-login", "secure.paypal.x", "paypalverify"), never
    inside another word ("pineapple"). Ordinary-word brands (apple, chase) also need a lure word."""
    def fused(kw: str) -> bool:
        return any(t == kw or (t.startswith(kw) and t[len(kw):] in LURE_KEYWORDS)
                   or (t.endswith(kw) and t[: -len(kw)] in LURE_KEYWORDS) for t in tokens)
    if any(fused(k) for k in ent.keywords):
        return True
    return any(fused(k) for k in ent.common_keywords) and _lure_token(tokens)


# ---------------------------------------------------------------------------
# Lexical analysis (fast — also used on the CT firehose)
# ---------------------------------------------------------------------------
def analyze_lexical(raw: str) -> LexicalReport:
    normalized, host = normalize_url(raw)
    ext = _EXTRACT(host)
    suffix = ext.suffix or host.rsplit(".", 1)[-1]
    reg_domain = f"{ext.domain}.{suffix}" if ext.domain else host
    label = ext.domain or host.split(".")[0]
    unicode_host = to_unicode_host(host)
    is_puny = "xn--" in host

    rep = LexicalReport(
        input=raw, normalized_url=normalized, host=host, registered_domain=reg_domain,
        label=label, tld=suffix, is_whitelisted=False, official_match=None, impersonated=None,
        is_punycode=is_puny, unicode_host=unicode_host, similarity=0.0,
    )

    match = official_match(host)
    if match:
        rep.is_whitelisted = True
        rep.official_match = match
        rep.impersonated = OFFICIAL_DOMAINS.get(match)
        return rep

    full_skel = skeleton(to_unicode_host(host))
    label_skel = skeleton(to_unicode_host(label), multi=True)
    # tokens span sub-domains too (e.g. tamm.abudhabi.pay-now.xyz)
    host_wo_tld = ".".join(unicode_host.split(".")[:-1]) or label
    tokens = _tokens(skeleton(host_wo_tld))
    raw_tokens = _tokens(host_wo_tld.lower())

    from .threat_feeds import popularity_rank  # local: threat_feeds -> domain_intel at load time
    from .page_signals import user_content  # local: page_signals imports this module

    # A Tranco top-100k site of its own (not a page on a hosting platform) is not a brand trap: brands own
    # far more addresses than any registry lists (ebay.de, airbnb.it, yahoo.co.jp, adobe.io ...).
    popular_own_site = bool(popularity_rank(reg_domain)) and not user_content(host)

    best: tuple[float, Entity | None, str] = (0.0, None, "")
    for ent in ALL_BRANDS:
        is_global = ent.category == "global"
        for od in ent.domains:
            od_ext = _official_parts(od)
            od_label = od_ext.domain
            sim = fuzz.ratio(label_skel, od_label)
            # Global brands: only long names count as typos (steamcommunite ~ steamcommunity), short
            # ones collide with real words (chaser ~ chase, applea ~ apple).
            if sim > best[0] and (not is_global or (len(od_label) >= 7 and sim >= 88)):
                best = (sim, ent, od)
            # spoof: skeleton equals official label but raw differs (homoglyph / leet / punycode)
            if label_skel == od_label and label != od_label and not popular_own_site:  # m3.com is not me.com
                rep.impersonated = ent
                rep.flags.append(RedFlag(
                    "HOMOGLYPH_SPOOF", "critical", 50,
                    f"The address uses look-alike characters to imitate {od} ({unicode_host}).",
                    f"يستخدم العنوان أحرفاً مشابهة لتقليد الموقع الرسمي {od} ({unicode_host}).",
                ))
            elif label_skel == od_label and suffix != od_ext.suffix and not is_global:
                # (global brands own many endings: google.fr, amazon.eg; a missing one is not a scam)
                rep.impersonated = ent
                rep.flags.append(RedFlag(
                    "TLD_SWAP", "high", 40,
                    f"Same name as the official site but a different ending (.{suffix} instead of .{od_ext.suffix}).",
                    f"نفس اسم الموقع الرسمي ولكن بامتداد مختلف (.{suffix} بدلاً من .{od_ext.suffix}).",
                ))

    rep.similarity = round(best[0], 1)
    sim_ent = best[1]

    # Brand keyword embedded in an unofficial domain (combosquatting)
    if not rep.flags and not popular_own_site:
        for ent in ALL_BRANDS:
            hit = (_global_brand_hit(ent, tokens) if ent.category == "global"
                   else any(_keyword_hit(k, full_skel, tokens) for k in ent.keywords))
            if hit:
                rep.impersonated = ent
                pts = 40 if ent.category in {"government", "identity"} else 35
                if ent.category == "global" and _lure_token(tokens):
                    pts = 50  # brand + "login/verify/secure..." on a non-brand domain: classic phishing
                rep.flags.append(RedFlag(
                    "BRAND_IMPERSONATION", "high", pts,
                    f"Uses the name of {ent.name_en} but is NOT an official {ent.name_en} website "
                    f"(official: {', '.join(ent.domains)}).",
                    f"يستخدم اسم {ent.name_ar} لكنه ليس موقعاً رسمياً (الموقع الرسمي: {'، '.join(ent.domains)}).",
                ))
                break

    if (not rep.impersonated and sim_ent and 75 <= best[0] < 100
            and not popularity_rank(reg_domain)):  # a top-100k site is not a typo trap (adac.de vs adcb)
        rep.impersonated = sim_ent
        rep.flags.append(RedFlag(
            "TYPOSQUAT", "high", 35,
            f"The address is spelled almost like {best[2]} ({best[0]:.0f}% similar) — a classic typo trap.",
            f"العنوان مكتوب بشكل قريب جداً من {best[2]} (تشابه {best[0]:.0f}٪) — فخ أخطاء إملائية معروف.",
        ))

    if is_puny and not any(f.code == "HOMOGLYPH_SPOOF" for f in rep.flags):
        rep.flags.append(RedFlag(
            "PUNYCODE", "medium", 15,
            f"The address contains encoded international characters ({unicode_host}).",
            f"يحتوي العنوان على أحرف دولية مُرمّزة ({unicode_host}).",
        ))

    if suffix.split(".")[-1] in SUSPICIOUS_TLDS:
        rep.flags.append(RedFlag(
            "SUSPICIOUS_TLD", "medium", 15,
            f"Ends in .{suffix}, a cheap domain ending widely abused by scammers. UAE government sites use .gov.ae or .abudhabi.",
            f"ينتهي بـ .{suffix} وهو امتداد رخيص يستغله المحتالون بكثرة. المواقع الحكومية تستخدم .gov.ae أو .abudhabi.",
        ))

    plain_label = skeleton(to_unicode_host(label))
    lures = sorted({k for k in LURE_KEYWORDS
                    if k in tokens or k in raw_tokens or (len(k) > 4 and k in plain_label)})
    if lures:
        rep.flags.append(RedFlag(
            "LURE_KEYWORDS", "low", min(20, 6 * len(lures)),
            f"Contains pressure words used in scams: {', '.join(lures[:5])}.",
            f"يحتوي على كلمات ضغط شائعة في الاحتيال: {', '.join(lures[:5])}.",
        ))

    if to_unicode_host(label).count("-") >= 2:
        rep.flags.append(RedFlag(
            "HYPHEN_STUFFING", "low", 5,
            "Long hyphenated name built to look official.",
            "اسم طويل مليء بالشرطات صُمّم ليبدو رسمياً.",
        ))
    if len(host.split(".")) >= 5:
        rep.flags.append(RedFlag(
            "DEEP_SUBDOMAIN", "low", 5,
            "Unusually deep sub-domain chain, often used to hide the real domain.",
            "سلسلة نطاقات فرعية طويلة بشكل غير معتاد لإخفاء النطاق الحقيقي.",
        ))
    try:
        ipaddress.ip_address(host)
        rep.flags.append(RedFlag(
            "RAW_IP_HOST", "medium", 20,
            "Link points to a raw IP address instead of a named website.",
            "الرابط يشير إلى عنوان IP مباشر بدلاً من اسم موقع.",
        ))
    except ValueError:
        pass
    return rep


# ---------------------------------------------------------------------------
# Live network intelligence
# ---------------------------------------------------------------------------
def _first_dt(value: Any) -> datetime | None:
    if isinstance(value, list):
        value = [v for v in value if isinstance(v, datetime)]
        value = min(value) if value else None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    return None


async def whois_lookup(domain: str) -> dict[str, Any]:
    if settings.offline_mode:
        return {"status": "skipped_offline"}

    def _do() -> dict[str, Any]:
        import whois  # python-whois

        w = whois.whois(domain, quiet=True, timeout=int(settings.whois_timeout_s))
        created = _first_dt(w.get("creation_date"))
        expires = _first_dt(w.get("expiration_date"))
        emails = w.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        ns = w.get("name_servers") or []
        if isinstance(ns, str):
            ns = [ns]
        return {
            "status": "ok",
            "registrar": w.get("registrar"),
            "creation_date": created.isoformat() if created else None,
            "expiration_date": expires.isoformat() if expires else None,
            "registrant_country": w.get("country"),
            "abuse_emails": sorted({e.lower() for e in emails if "abuse" in e.lower()}) or sorted(
                {e.lower() for e in emails})[:3],
            "name_servers": sorted({n.lower() for n in ns}),
        }

    try:
        loop = asyncio.get_running_loop()
        return await asyncio.wait_for(loop.run_in_executor(_WHOIS_POOL, _do), timeout=settings.whois_timeout_s + 2)
    except Exception as exc:  # noqa: BLE001 — WHOIS is notoriously flaky
        return {"status": "error", "error": type(exc).__name__}


async def dns_lookup(host: str) -> dict[str, Any]:
    if settings.offline_mode:
        return {"status": "skipped_offline", "a": [], "aaaa": [], "mx": [], "ns": []}
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    res = dns.asyncresolver.Resolver()
    res.lifetime = settings.dns_timeout_s
    out: dict[str, Any] = {"status": "ok", "a": [], "aaaa": [], "mx": [], "ns": []}

    async def q(name: str, rtype: str) -> list[str]:
        try:
            ans = await res.resolve(name, rtype)
            return sorted({r.to_text().rstrip(".") for r in ans})
        except dns.resolver.NXDOMAIN:
            out["status"] = "nxdomain"
            return []
        except (dns.exception.DNSException, OSError):
            return []

    reg = _EXTRACT(host)
    apex = f"{reg.domain}.{reg.suffix}" if reg.domain and reg.suffix else host
    out["a"], out["aaaa"], out["mx"], out["ns"] = await asyncio.gather(
        q(host, "A"), q(host, "AAAA"), q(apex, "MX"), q(apex, "NS")
    )
    if out["a"] and out["status"] == "nxdomain":
        out["status"] = "ok"
    return out


async def asn_lookup(ip: str) -> dict[str, Any]:
    """Team Cymru IP->ASN over DNS (no API key)."""
    if settings.offline_mode:
        return {"status": "skipped_offline"}
    import dns.asyncresolver

    try:
        addr = ipaddress.ip_address(ip)
        if addr.version != 4 or not addr.is_global:
            return {"status": "non_global"}
        res = dns.asyncresolver.Resolver()
        res.lifetime = settings.dns_timeout_s
        rev = ".".join(reversed(ip.split(".")))
        txt = (await res.resolve(f"{rev}.origin.asn.cymru.com", "TXT"))[0].to_text().strip('"')
        asn, prefix, cc, *_ = [p.strip() for p in txt.split("|")]
        asn = asn.split()[0]
        org = ""
        try:
            t2 = (await res.resolve(f"AS{asn}.asn.cymru.com", "TXT"))[0].to_text().strip('"')
            org = t2.split("|")[-1].strip()
        except Exception:  # noqa: BLE001
            pass
        return {"status": "ok", "asn": f"AS{asn}", "prefix": prefix, "country": cc, "org": org,
                "shared_infrastructure": asn in SHARED_INFRA_ASNS}
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": type(exc).__name__}


async def tls_lookup(host: str, port: int = 443) -> dict[str, Any]:
    if settings.offline_mode:
        return {"status": "skipped_offline"}
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    async def grab(verify: bool) -> bytes:
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=settings.tls_timeout_s,
        )
        try:
            return writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        finally:
            writer.close()

    valid = True
    try:
        try:
            der = await grab(True)
        except ssl.SSLCertVerificationError:
            valid = False
            der = await grab(False)
        cert = x509.load_der_x509_certificate(der)

        def _name(n: x509.Name) -> str:
            parts = {a.oid._name: a.value for a in n}  # noqa: SLF001
            return ", ".join(f"{k}={v}" for k, v in parts.items() if k in {"commonName", "organizationName"})

        try:
            sans = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
                x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []
        nb = cert.not_valid_before_utc
        return {
            "status": "ok",
            "valid": valid,
            "issuer": _name(cert.issuer),
            "subject": _name(cert.subject),
            "not_before": nb.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "cert_age_hours": round((datetime.now(timezone.utc) - nb).total_seconds() / 3600, 1),
            "san_count": len(sans),
            "sans_sample": sans[:10],
            "sha256": cert.fingerprint(hashes.SHA256()).hex(),
        }
    except Exception as exc:  # noqa: BLE001
        return {"status": "error", "error": type(exc).__name__}


def age_hours(iso: str | None) -> float | None:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso)
        if not dt.tzinfo:
            dt = dt.replace(tzinfo=timezone.utc)
        return round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
    except ValueError:
        return None


def human_age(hours: float | None) -> tuple[str, str]:
    """Return (en, ar) human-readable age."""
    if hours is None:
        return "an unknown time ago", "منذ مدة غير معروفة"
    if hours < 1:
        return "less than an hour ago", "قبل أقل من ساعة"
    if hours < 48:
        h = max(1, int(round(hours)))
        return f"{h} hour{'s' if h != 1 else ''} ago", "قبل " + _ar_count(h, "ساعة", "ساعتين", "ساعات", "ساعة")
    d = int(hours // 24)
    return f"{d} days ago", "قبل " + _ar_count(d, "يوم", "يومين", "أيام", "يوماً")


def _ar_count(n: int, one: str, two: str, few: str, many: str) -> str:
    """Arabic number agreement: 1 -> singular, 2 -> dual, 3-10 -> plural, 11+ -> singular accusative."""
    if n == 1:
        return one
    if n == 2:
        return two
    if 3 <= n <= 10:
        return f"{n} {few}"
    return f"{n} {many}"


def sha256_text(text: str | bytes) -> str:
    data = text.encode() if isinstance(text, str) else text
    return hashlib.sha256(data).hexdigest()
