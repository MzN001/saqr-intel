"""Phishing-campaign intelligence: which scam waves are spreading right now (email, SMS, web).

A *campaign* is one recognisable scam wave, e.g. "fake Emirates Post AED 3 redelivery fee" or
"Microsoft 365 device-code phishing". Each one carries:

* the brands it abuses ('brands') and tell-tale wording ('terms', English + Arabic), so an
  email that uses the same lure can be recognised even when the scam links are brand new;
* indicators ('indicators.sender_domains' / 'url_domains'): registered domains that a cited
  public source listed for the campaign. A hit is near-certain proof (CAMPAIGN_IOC_MATCH).

Where campaigns come from (merged, seed first):

1. data/campaigns_seed.json - researched by hand from public advisories (police, UAE Cyber
   Security Council, vendors' threat research). Every entry cites the pages it came from.
   Re-generate / extend with tools/build_campaign_seed.py.
2. Live public feeds (RSS / Atom headlines of security researchers and government advisories),
   refreshed every 6 hours. Headlines are mapped onto a FIXED brand x lure taxonomy: fetched text
   is untrusted data and never becomes matching wording itself.
3. SAQR's own detections (awareness.trending_waves): brands being impersonated by scam sites
   SAQR flagged in the last 72 hours, with those sites as indicators.

Safety: an indicator can never be a whole hosting platform (vercel.app, workers.dev ...), a free
mail provider, an official / trusted UAE domain, SAQR's own host or one of the 10,000 most popular
sites - otherwise one bad feed entry could flag every Gmail user.

The matching rule (match_campaign / regdom) is part of the frozen contract and has an exact
JavaScript twin in the browser extension (extension/lib/campaign_match.js). Both are tested against
the shared vectors in tests/fixtures/campaign_vectors.json - change them together or not at all.

Environment (read here so config.py stays untouched):
    CAMPAIGN_FEEDS=true|false        live feed refresh on/off (default on; OFFLINE_MODE also stops it)
    CAMPAIGN_REFRESH_HOURS=6         refresh interval
"""
from __future__ import annotations

import asyncio
import copy
import hashlib
import html
import json
import logging
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Iterable
from xml.etree import ElementTree as ET
from xml.parsers import expat

import httpx

from ..config import settings

log = logging.getLogger("saqr.campaigns")

SEED_PATH = Path(__file__).with_name("data") / "campaigns_seed.json"
FORMAT, VERSION, TTL_HOURS = "saqr-campaigns", 1, 6
IOC_POINTS, LURE_POINTS = 65, 20


# CAMPAIGN_FEEDS / CAMPAIGN_REFRESH_HOURS (saqr/config.py).
FEEDS_ENABLED = settings.campaign_feeds_enabled
REFRESH_SECONDS = max(0.25, settings.campaign_refresh_hours) * 3600


# =============================================================================================
# 1. Frozen matching rule (contract sections 3 + 4). Keep identical to campaign_match.js.
# =============================================================================================
# Soft hyphen, CGJ, zero-width / direction marks, bidi embeddings + overrides, word joiner and
# invisible operators, bidi isolates, BOM: stripped before matching so "re\u200bdelivery" still hits.
_INVISIBLE = re.compile("[\u00ad\u034f\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
# Whitespace = exactly what Python's str.split() splits on (str.isspace()); the JavaScript twin
# spells out the same class because JavaScript's \s lacks \x1c-\x1f and \x85.
_WS = re.compile("[\t\n\u000b\u000c\r\u001c-\u001f \u0085\u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000]+")

# Registered domain = last 2 labels, or last 3 when the last two are one of these (no tldextract,
# so Python and JavaScript always agree).
THREE_LABEL_SUFFIXES = frozenset(
    "co.uk org.uk ac.uk gov.uk com.au net.au org.au co.nz co.za co.in co.jp co.kr com.br com.mx com.tr "
    "com.sa com.eg com.kw com.qa com.bh com.om com.pk com.sg com.my com.hk com.cn gov.ae co.ae ac.ae "
    "net.ae org.ae sch.ae mil.ae".split())


def norm(text: str | None) -> str:
    """NFKC -> lowercase -> strip invisible / bidi characters -> collapse whitespace."""
    s = unicodedata.normalize("NFKC", text or "").lower()
    s = _INVISIBLE.sub("", s)
    return _WS.sub(" ", s).strip(" ")


def regdom(host: str | None) -> str:
    """Registered domain of a host name (contract section 4): 'mail.dhl.co.uk' -> 'dhl.co.uk'."""
    h = (host or "").strip().lower().rstrip(".")
    labels = h.split(".")
    if len(labels) <= 2:
        return h
    if ".".join(labels[-2:]) in THREE_LABEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _is_word_char(ch: str) -> bool:
    return unicodedata.category(ch)[0] in ("L", "N")  # \p{L} or \p{N}


def contains_word(hay: str, needle: str) -> bool:
    """True if needle occurs in hay with a non-letter/non-digit (or the edge) on both sides.
    Both arguments must already be norm()-alised. Every occurrence is tried, so "dhl" is found in
    "xdhl dhl" even though the first occurrence is glued to a letter."""
    if not needle:
        return False
    start = hay.find(needle)
    while start != -1:
        end = start + len(needle)
        if (start == 0 or not _is_word_char(hay[start - 1])) and (end == len(hay) or not _is_word_char(hay[end])):
            return True
        start = hay.find(needle, start + 1)
    return False


def _prepare_input(inp: dict[str, Any]) -> dict[str, Any]:
    links = inp.get("link_domains") or []
    return {
        "sender": regdom(inp.get("sender_domain") or ""),
        "links": [regdom(d) for d in links if isinstance(d, str) and d.strip()],
        "text": norm(f"{inp.get('subject') or ''} {inp.get('body_text') or ''}"),
        # a brand may also be in the display name: norm(subject + " " + body + " " + from_name)
        "brand_text": norm(f"{inp.get('subject') or ''} {inp.get('body_text') or ''} "
                           f"{inp.get('from_name') or inp.get('display_name') or ''}"),
    }


def _prepare_campaign(c: dict[str, Any]) -> dict[str, Any]:
    ind = c.get("indicators") or {}
    terms: list[tuple[str, str]] = []
    seen: set[str] = set()
    for t in c.get("terms") or []:
        n = norm(t)
        if n and n not in seen:  # "distinct terms": two spellings that normalise alike count once
            seen.add(n)
            terms.append((t, n))
    return {
        "senders": {d.strip().lower().rstrip(".") for d in ind.get("sender_domains") or [] if d},
        "urls": {d.strip().lower().rstrip(".") for d in ind.get("url_domains") or [] if d},
        "terms": terms,
        "brands": [n for n in (norm(b) for b in c.get("brands") or []) if n],
        "min_terms": max(1, int(c.get("min_terms") or 1)),
    }


def _match_prepared(pc: dict[str, Any], pi: dict[str, Any]) -> dict[str, Any] | None:
    # IOC: the sender's or a link's registered domain is a listed indicator.
    hits: list[str] = []
    if pi["sender"] and pi["sender"] in pc["senders"]:
        hits.append(pi["sender"])
    for d in pi["links"]:
        if d in pc["urls"] and d not in hits:
            hits.append(d)
    if hits:
        return {"match": "ioc", "points": IOC_POINTS, "matched": hits}
    # Lure: enough distinct campaign phrases + (no brand needed, or one of its brands named).
    found = [orig for orig, n in pc["terms"] if contains_word(pi["text"], n)]
    if len(found) < pc["min_terms"]:
        return None
    if pc["brands"] and not any(contains_word(pi["brand_text"], b) for b in pc["brands"]):
        return None
    return {"match": "lure", "points": LURE_POINTS, "matched": found}


def match_campaign(campaign: dict[str, Any], input: dict[str, Any]) -> dict[str, Any] | None:  # noqa: A002
    """Contract match rule. input = {sender_domain, link_domains[], subject, body_text,
    from_name (optional display name)}. Returns {"match": "ioc"|"lure", "points", "matched"} or None."""
    return _match_prepared(_prepare_campaign(campaign), _prepare_input(input or {}))


# =============================================================================================
# 2. Indicator safety rules
# =============================================================================================
FREEMAIL = frozenset(
    "gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com icloud.com me.com "
    "aol.com proton.me protonmail.com gmx.com mail.com zoho.com yandex.com yandex.ru mail.ru".split())
# Shared services that phishing kits *abuse* but whose registered domain is used by millions of
# legitimate senders / sites (bulk-mail click trackers, cloud storage, URL shorteners, public
# suffixes regdom() can't see). Never an indicator.
SHARED_SERVICES = frozenset(
    "my.id web.id biz.id or.id co.id sendgrid.net mcdlv.net mailchimp.com list-manage.com constantcontact.com "
    "constantcontactpages.com rs6.net hubspot.com hs-sites.com amazonaws.com cloudfront.net oraclecloud.com "
    "googleusercontent.com googleapis.com azure.com windows.net cloudapp.net zpr.io bit.ly tinyurl.com "
    "t.co ow.ly is.gd cutt.ly rebrand.ly paps.jp qrco.de linktr.ee forms.gle dropboxusercontent.com "
    "1drv.ms sharepoint.com notion.site typeform.com jotform.com wufoo.com surveymonkey.com canva.com "
    "facebookmail.com gotowebinar.com zoom.us".split())
HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})$")
_ROOTS: frozenset[str] | None = None


def _platform_roots() -> frozenset[str]:
    global _ROOTS
    if _ROOTS is None:
        from .threat_feeds import NEVER_LIST

        roots = set(NEVER_LIST) | SHARED_SERVICES | FREEMAIL
        try:  # the DNS blocklist's own list of shared hosting platforms
            from ..routers.blocklist import SHARED_HOSTING_ROOTS

            roots |= set(SHARED_HOSTING_ROOTS)
        except Exception:  # noqa: BLE001 - optional, the threat-feed list already covers them
            pass
        _ROOTS = frozenset(roots)
    return _ROOTS


def refang_host(raw: str) -> str:
    """'hxxps://evil[.]example(.)com/x' -> 'evil.example.com' (host part only, lowercased)."""
    s = (raw or "").strip().lower()
    s = re.sub(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", ".", s)
    s = re.sub(r"^h[x*]{2}p", "http", s)
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = re.split(r"[/?#\s]", s, maxsplit=1)[0]
    s = s.rsplit("@", 1)[-1].split(":", 1)[0]  # user@host:port -> host
    s = s.rstrip(".")
    return s[4:] if s.startswith("www.") else s


def ioc_allowed(domain: str) -> str | None:
    """The registered domain to publish as an indicator, or None if it must never be one."""
    from .domain_intel import official_match
    from .threat_feeds import popularity_rank

    d = regdom(refang_host(domain))
    if not d or "." not in d or not HOSTNAME.match(d):
        return None
    for p in _platform_roots():
        # the platform itself, a sub-domain of it, or a parent of it (windows.net -> all of Azure)
        if d == p or d.endswith("." + p) or p.endswith("." + d):
            return None
    if d in THREE_LABEL_SUFFIXES or official_match(d) or (popularity_rank(d) or 10**9) <= 10_000:
        return None
    try:
        from ..self_hosts import known_hosts

        if any(h == d or h.endswith("." + d) for h in known_hosts()):  # SAQR's own public address
            return None
    except Exception:  # noqa: BLE001
        pass
    return d


# =============================================================================================
# 3. Safe RSS / Atom parsing (fetched feeds are untrusted)
# =============================================================================================
MAX_FEED_BYTES = 3_000_000
_ATOM = "{http://www.w3.org/2005/Atom}"
_CTRL = re.compile("[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]")


def safe_xml(data: bytes) -> ET.Element:
    """Parse XML with expat directly, refusing entity declarations and external entities (what
    defusedxml does): no "billion laughs", no file / network reads. A DOCTYPE without entities is fine."""
    if len(data) > MAX_FEED_BYTES:
        raise ValueError("feed too large")
    builder = ET.TreeBuilder()
    p = expat.ParserCreate(namespace_separator="}")

    def forbid(*_: Any) -> None:
        raise ValueError("XML entities are not allowed in feeds")

    p.EntityDeclHandler = forbid
    p.UnparsedEntityDeclHandler = forbid
    p.ExternalEntityRefHandler = forbid
    p.SetParamEntityParsing(expat.XML_PARAM_ENTITY_PARSING_NEVER)

    def fix(name: str) -> str:
        return "{" + name if "}" in name else name

    p.StartElementHandler = lambda tag, attrs: builder.start(fix(tag), {fix(k): v for k, v in attrs.items()})
    p.EndElementHandler = lambda tag: builder.end(fix(tag))
    p.CharacterDataHandler = builder.data
    p.Parse(data, True)
    return builder.close()


def _clean_text(s: str | None, limit: int) -> str:
    """Untrusted text -> plain, single-line, length-capped (tags, entities, control chars removed)."""
    s = html.unescape(re.sub(r"<[^>]{0,2000}>", " ", s or ""))
    s = _INVISIBLE.sub("", _CTRL.sub(" ", s))
    return _WS.sub(" ", s).strip()[:limit]


def _safe_url(u: str | None) -> str:
    u = (u or "").strip()
    return u[:500] if re.match(r"^https?://[^\s\"'<>]+$", u) else ""


def _parse_date(s: str | None) -> datetime | None:
    s = (s or "").strip()
    if not s:
        return None
    try:
        dt = parsedate_to_datetime(s)  # RSS: RFC 822
    except (TypeError, ValueError, IndexError):
        try:
            dt = datetime.fromisoformat(s.replace("Z", "+00:00"))  # Atom: RFC 3339
        except ValueError:
            return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def parse_feed(data: bytes) -> list[dict[str, Any]]:
    """RSS 2.0 / Atom bytes -> [{title, url, summary, published (datetime | None)}], max 100 items."""
    root = safe_xml(data)
    items: list[dict[str, Any]] = []
    for it in root.iter("item"):
        items.append({
            "title": _clean_text(it.findtext("title"), 200),
            "url": _safe_url(it.findtext("link")),
            "summary": _clean_text(it.findtext("description"), 1500),
            "published": _parse_date(it.findtext("pubDate") or it.findtext("{http://purl.org/dc/elements/1.1/}date")),
        })
    for it in root.iter(f"{_ATOM}entry"):
        link = ""
        for ln in it.findall(f"{_ATOM}link"):
            if ln.get("rel", "alternate") == "alternate":
                link = ln.get("href", "")
                break
        items.append({
            "title": _clean_text(it.findtext(f"{_ATOM}title"), 200),
            "url": _safe_url(link),
            "summary": _clean_text(it.findtext(f"{_ATOM}summary") or it.findtext(f"{_ATOM}content"), 1500),
            "published": _parse_date(it.findtext(f"{_ATOM}published") or it.findtext(f"{_ATOM}updated")),
        })
    return [i for i in items if i["title"]][:100]


# =============================================================================================
# 4. Live sources + the fixed brand x lure taxonomy
# =============================================================================================
# Verified 2026-11-23 (HTTP 200, valid RSS). Only headlines + links are used; the articles stay
# with their publishers. Tried the same day and NOT wired: FTC consumer-alert RSS (404 on every
# known URL), abuse.ch URLhaus / ThreatFox (410 / 401 - need an Auth-Key now), Sophos (timeout),
# UAE Cyber Security Council / TDRA / aeCERT (no RSS or JSON feed published).
SOURCES: tuple[dict[str, str], ...] = (
    {"id": "malwarebytes-labs", "name": "Malwarebytes Labs blog", "url": "https://www.malwarebytes.com/blog/feed/index.xml",
     "license": "Headlines and links only; content (c) Malwarebytes"},
    {"id": "cofense", "name": "Cofense phishing intelligence blog", "url": "https://cofense.com/feed/",
     "license": "Headlines and links only; content (c) Cofense"},
    {"id": "bleepingcomputer", "name": "BleepingComputer security news", "url": "https://www.bleepingcomputer.com/feed/",
     "license": "Headlines and links only; content (c) BleepingComputer"},
    {"id": "fbi-ic3", "name": "FBI IC3 public service announcements", "url": "https://www.ic3.gov/PSA/RSS",
     "license": "US Government work (public domain)"},
    {"id": "ncsc-uk", "name": "UK NCSC news and advisories", "url": "https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml",
     "license": "Headlines and links only; Crown copyright"},
)
CURATED_SOURCE = {"id": "saqr-research", "name": "SAQR analyst research (public advisories, cited per campaign)",
                  "url": "https://saqr-intel-api.onrender.com/api/campaigns",
                  "license": "Summaries CC BY 4.0; facts from the cited sources"}
DETECTIONS_SOURCE = {"id": "saqr-detections", "name": "SAQR-INTEL live detections (last 72 h)",
                     "url": "https://saqr-intel-api.onrender.com/api/awareness-alert", "license": "CC BY 4.0"}
FEED_MAX_AGE_DAYS = 120
MAX_FEED_CAMPAIGNS = 40

# A headline is only used if it is about phishing / scams at all.
_PHISH_WORDS = ("phish", "scam", "smish", "quish", "fraud", "fake ", "impersonat", "lure", "spoof", "credential",
                "account takeover", "device code", "clickfix", "احتيال", "تصيد", "مزيف")

# lure id -> words that reveal it in a headline ("spot") and the FIXED wording used to match emails.
LURES: dict[str, dict[str, Any]] = {
    "devicecode": {
        "spot": ("device code", "device-code", "devicelogin"),
        "title_en": "device-code sign-in phishing", "title_ar": "تصيّد عبر رمز تسجيل دخول الجهاز",
        "summary_en": "Emails pretending to come from {brand} ask you to type a short code into a real sign-in page. Doing so hands your account to the attacker.",
        "summary_ar": "رسائل تنتحل صفة {brand_ar} تطلب كتابة رمز قصير في صفحة تسجيل دخول حقيقية، وبذلك يحصل المحتال على حسابك.",
        "terms": ["device code", "enter the code", "authentication code", "devicelogin", "verify your identity",
                  "password expiration", "action required", "voicemail", "review document", "رمز التحقق", "أدخل الرمز"],
        "channels": ["email"]},
    "qr": {
        "spot": ("qr code", "quishing", "qr-code", "رمز qr", "رمز الاستجابة"),
        "title_en": "QR-code phishing (quishing)", "title_ar": "تصيّد عبر رمز QR",
        "summary_en": "Messages using the {brand} name ask you to scan a QR code with your phone, which opens a fake login or payment page.",
        "summary_ar": "رسائل باسم {brand_ar} تطلب مسح رمز QR بالهاتف، فيفتح صفحة دخول أو دفع مزيفة.",
        "terms": ["qr code", "scan the code", "scan the qr", "scan with your phone", "rescan", "امسح الرمز", "رمز qr",
                  "verify your account", "expire"],
        "channels": ["email", "sms"]},
    "esign": {
        "spot": ("docusign", "e-signature", "esignature", "signing request", "envelope", "توقيع"),
        "title_en": "fake document-to-sign notice", "title_ar": "إشعار مزيف بمستند للتوقيع",
        "summary_en": "Fake {brand} notices say a document is waiting for your signature. The link leads to a page that steals your email password.",
        "summary_ar": "إشعارات مزيفة باسم {brand_ar} تزعم وجود مستند بانتظار توقيعك، والرابط يقود إلى صفحة تسرق كلمة مرور بريدك.",
        "terms": ["review document", "signature required", "awaiting your signature", "view document", "sign the document",
                  "envelope", "completed document", "payment advice", "مستند", "توقيع"],
        "channels": ["email"]},
    "fine": {
        "spot": ("traffic fine", "toll", "parking ticket", "speeding", "traffic violation", "unpaid fine", "مخالف", "رسوم الطريق"),
        "title_en": "unpaid fine / toll payment scam", "title_ar": "احتيال دفع مخالفة أو رسوم طريق غير مدفوعة",
        "summary_en": "Messages using the {brand} name claim you have an unpaid fine or toll and must pay quickly through a link to avoid extra charges.",
        "summary_ar": "رسائل باسم {brand_ar} تدّعي وجود مخالفة أو رسوم طريق غير مدفوعة وتطلب الدفع سريعاً عبر رابط لتجنب غرامات إضافية.",
        "terms": ["unpaid fine", "traffic fine", "traffic violation", "toll", "overdue", "avoid additional", "late fee",
                  "pay now", "مخالفة", "مخالفات", "غرامة", "رسوم الطريق"],
        "channels": ["sms", "email"]},
    "delivery": {
        "spot": ("parcel", "package", "delivery", "courier", "shipment", "customs fee", "redelivery", "postal", "شحن", "طرد", "توصيل"),
        "title_en": "parcel delivery-fee scam", "title_ar": "احتيال رسوم توصيل الشحنات",
        "summary_en": "Messages using the {brand} name say a parcel is on hold until you pay a small fee or update your address through a link.",
        "summary_ar": "رسائل باسم {brand_ar} تزعم أن شحنتك محتجزة حتى تدفع رسوماً بسيطة أو تحدّث عنوانك عبر رابط.",
        "terms": ["parcel", "package", "redelivery", "could not be delivered", "customs fee", "delivery fee", "update your address",
                  "tracking number", "شحنة", "شحنتك", "التوصيل", "رسوم"],
        "channels": ["sms", "email"]},
    "tax": {
        "spot": ("tax refund", "tax rebate", "tax return", "tax repayment", "irs ", "hmrc", "refund", "استرداد", "ضريب"),
        "title_en": "fake tax / refund notice", "title_ar": "إشعار مزيف باسترداد ضريبة أو مبلغ",
        "summary_en": "Messages using the {brand} name promise a refund and ask you to confirm your identity and card details to receive it.",
        "summary_ar": "رسائل باسم {brand_ar} تَعِد باسترداد مبلغ وتطلب تأكيد هويتك وبيانات بطاقتك لاستلامه.",
        "terms": ["tax refund", "tax rebate", "refund", "repayment", "you are entitled", "verify your identity", "claim",
                  "استرداد", "مستحق", "ضريبة"],
        "channels": ["email", "sms"]},
    "crypto": {
        "spot": ("crypto", "wallet", "seed phrase", "recovery phrase", "bitcoin", "drainer", "محفظ", "عملات رقمية"),
        "title_en": "crypto wallet phishing", "title_ar": "تصيّد محافظ العملات الرقمية",
        "summary_en": "Messages using the {brand} name ask you to 'verify' or 'migrate' your wallet. Anyone who asks for your recovery phrase is a thief.",
        "summary_ar": "رسائل باسم {brand_ar} تطلب «التحقق» من محفظتك أو «ترحيلها». من يطلب عبارة الاسترداد هو لص.",
        "terms": ["recovery phrase", "seed phrase", "wallet", "migrate", "verify your wallet", "withdrawal", "unusual activity",
                  "عبارة الاسترداد", "محفظة"],
        "channels": ["email", "sms"]},
    "job": {
        "spot": ("job offer", "job scam", "recruit", "remote job", "hiring", "employment", "وظيف"),
        "title_en": "fake job offer", "title_ar": "عرض عمل مزيف",
        "summary_en": "Fake recruiters use the {brand} name to offer easy, well-paid remote work and then ask for personal data or fees.",
        "summary_ar": "مجنِّدون مزيفون يستخدمون اسم {brand_ar} لعرض عمل عن بُعد سهل وبأجر مرتفع ثم يطلبون بيانات شخصية أو رسوماً.",
        "terms": ["job offer", "remote", "work from home", "per month", "a month", "hr team", "application", "hiring",
                  "وظيفة", "عمل عن بعد", "راتب"],
        "channels": ["email", "web"]},
    "shopping": {
        "spot": ("black friday", "cyber monday", "white friday", "holiday shopping", "fake store", "deal", "discount", "giveaway",
                 "تخفيض", "خصم", "الجمعة البيضاء"),
        "title_en": "fake shopping deal", "title_ar": "عرض تسوّق مزيف",
        "summary_en": "Too-good-to-be-true offers using the {brand} name lead to fake shops or login pages that steal card details.",
        "summary_ar": "عروض مغرية جداً باسم {brand_ar} تقود إلى متاجر أو صفحات دخول مزيفة تسرق بيانات البطاقة.",
        "terms": ["black friday", "white friday", "cyber monday", "deal", "discount", "% off", "limited time", "free gift",
                  "تخفيضات", "خصم", "الجمعة البيضاء"],
        "channels": ["email", "sms", "web"]},
    "prize": {
        "spot": ("prize", "reward", "you have won", "gift card", "lottery", "winner", "free ", "جائز", "ربحت", "مكافأ"),
        "title_en": "fake prize / reward", "title_ar": "جائزة أو مكافأة مزيفة",
        "summary_en": "Messages using the {brand} name say you won a prize or reward and must 'claim' it, which steals your login or card.",
        "summary_ar": "رسائل باسم {brand_ar} تزعم أنك ربحت جائزة أو مكافأة ويجب «المطالبة» بها، فتُسرق بيانات دخولك أو بطاقتك.",
        "terms": ["you have won", "winner", "prize", "reward", "claim", "gift", "congratulations", "points",
                  "ربحت", "جائزة", "مبروك", "نقاط"],
        "channels": ["email", "sms"]},
    "bank": {
        "spot": ("bank", "card", "kyc", "account suspended", "account blocked", "payment", "بنك", "مصرف", "بطاق"),
        "title_en": "account / card verification scam", "title_ar": "احتيال التحقق من الحساب أو البطاقة",
        "summary_en": "Messages using the {brand} name claim your account or card is blocked and must be 'verified' through a link that steals your details and OTP.",
        "summary_ar": "رسائل باسم {brand_ar} تدّعي أن حسابك أو بطاقتك موقوفة ويجب «التحقق» منها عبر رابط يسرق بياناتك ورمز التحقق.",
        "terms": ["verify your account", "account suspended", "account has been blocked", "card blocked", "update your details",
                  "unusual activity", "otp", "kyc", "حسابك", "تحديث البيانات", "رمز التحقق", "إيقاف"],
        "channels": ["email", "sms"]},
    "account": {
        "spot": ("phish", "credential", "login", "sign-in", "password", "account", "تسجيل الدخول", "كلمة المرور", "حساب"),
        "title_en": "account login phishing", "title_ar": "تصيّد بيانات تسجيل الدخول",
        "summary_en": "Emails pretending to come from {brand} ask you to sign in through a link to fix a problem with your account. The page steals your password.",
        "summary_ar": "رسائل تنتحل صفة {brand_ar} تطلب تسجيل الدخول عبر رابط لحل مشكلة في حسابك، والصفحة تسرق كلمة المرور.",
        "terms": ["verify your account", "sign in", "password", "account will be", "suspended", "unusual activity",
                  "confirm your identity", "action required", "حسابك", "كلمة المرور", "تسجيل الدخول"],
        "channels": ["email"]},
}
LURE_ORDER = ("devicecode", "qr", "esign", "fine", "delivery", "tax", "crypto", "job", "shopping", "prize", "bank", "account")
CATEGORY_LURE = {"courier": "delivery", "government": "fine", "telecom": "prize", "bank": "bank", "identity": "account",
                 "global": "account"}


def _plain_name(e: Any) -> str:
    return re.sub(r"\s*\(.*?\)", "", e.name_en)  # "e& (Etisalat)" -> "e&"


_ALIASES: list[tuple[Any, list[str]]] | None = None
_AMBIGUOUS = frozenset({"fab", "eand", "meta", "noon", "wise", "steam", "booking", "ledger", "crypto", "emirates"})


def _brand_aliases() -> list[tuple[Any, list[str]]]:
    """(entity, [normalised names to spot in a headline]) for every known brand. Ordinary words
    (apple, chase, ups ...), names shorter than 3 letters and a few ambiguous short words are left
    out: a headline about "ups and downs" or "fab deals" must not become a UPS / FAB campaign."""
    global _ALIASES
    if _ALIASES is None:
        from .registry import ALL_BRANDS

        out = []
        for e in ALL_BRANDS:
            names = {norm(_plain_name(e)), norm(e.name_ar), *(norm(a) for a in e.aliases), *(norm(k) for k in e.keywords)}
            names -= {norm(k) for k in e.common_keywords}
            out.append((e, sorted(n for n in names if len(n) >= 3 and n not in _AMBIGUOUS)))
        _ALIASES = out
    return _ALIASES


def _brand_terms(e: Any) -> list[str]:
    """Brand names used to recognise the brand inside an email (EN + AR, ordinary words left out)."""
    common = {k.lower() for k in e.common_keywords}
    out: list[str] = []
    for n in [_plain_name(e).lower(), *(a.lower() for a in e.aliases), *(k.lower() for k in e.keywords), e.name_ar]:
        if n and n not in common and n not in out and len(norm(n)) >= 2:
            out.append(n)
    return out


def classify(title: str, summary: str = "") -> tuple[Any | None, str | None]:
    """Map an (untrusted) headline + summary to (brand entity, lure id) of the fixed taxonomy.
    The brand must be in the headline itself: summaries often name brands only in passing."""
    head, full = norm(title), norm(f"{title} {summary}")
    if not any(w in full for w in _PHISH_WORDS):
        return None, None
    brand = next((e for e, names in _brand_aliases() if any(contains_word(head, n) for n in names)), None)
    lure = (next((lid for lid in LURE_ORDER if any(s in head for s in LURES[lid]["spot"])), None)
            or next((lid for lid in LURE_ORDER if any(s in full for s in LURES[lid]["spot"])), None))
    return brand, lure


_DEFANGED = re.compile(r"\b(?:hxxps?://)?((?:[a-z0-9-]+(?:\[\.\]|\(\.\)|\[dot\]))+[a-z]{2,24})\b", re.I)


def defanged_domains(text: str) -> list[str]:
    """Indicators written in defanged form ("evil[.]com") - the way researchers mark malicious
    names. Plain domains in prose are ignored (they are usually the real brand)."""
    out: list[str] = []
    for m in _DEFANGED.finditer(text or ""):
        d = ioc_allowed(m.group(1))
        if d and d not in out:
            out.append(d)
    return out


def campaign_id(key: str) -> str:
    """Stable id: the same brand x lure (or seed key) always gets the same cmp-xxxxxxxx."""
    return "cmp-" + hashlib.sha1(key.encode()).hexdigest()[:8]


def _iso(dt: datetime | None = None) -> str:
    return (dt or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def campaigns_from_items(items: list[tuple[str, dict[str, Any]]], *, now: datetime | None = None,
                         skip_urls: Iterable[str] = ()) -> list[dict[str, Any]]:
    """Group feed items [(source_id, item)] into brand x lure campaigns (a brand is required:
    brand-less lure wording alone would match too much ordinary mail)."""
    now = now or datetime.now(timezone.utc)
    cutoff = now - timedelta(days=FEED_MAX_AGE_DAYS)
    skip = set(skip_urls)
    groups: dict[tuple[str, str], dict[str, Any]] = {}
    for source_id, it in items:
        pub = it.get("published")
        if (pub and pub < cutoff) or (it.get("url") and it["url"] in skip):
            continue
        text = f"{it.get('title', '')} {it.get('summary', '')}"
        brand, lure = classify(it.get("title", ""), it.get("summary", ""))
        if not brand or not lure:
            continue
        g = groups.setdefault((brand.id, lure), {"brand": brand, "items": [], "iocs": []})
        g["items"].append((source_id, it))
        for d in defanged_domains(text):
            if d not in g["iocs"]:
                g["iocs"].append(d)
    out = []
    for (bid, lid), g in groups.items():
        e, lure = g["brand"], LURES[lid]
        dates = [it["published"] for _, it in g["items"] if it.get("published")] or [now]
        refs = [{"source_id": s, "url": it["url"], "title": it["title"]} for s, it in g["items"] if it.get("url")][:5]
        name = _plain_name(e)
        out.append({
            "id": campaign_id(f"feed:{bid}:{lid}"),
            "title_en": f"{name}: {lure['title_en']}", "title_ar": f"{e.name_ar}: {lure['title_ar']}",
            "summary_en": lure["summary_en"].format(brand=name), "summary_ar": lure["summary_ar"].format(brand_ar=e.name_ar),
            "brands": _brand_terms(e), "terms": list(lure["terms"]), "min_terms": 2, "channels": list(lure["channels"]),
            "regions": ["global"] if e.category == "global" else ["AE"],
            "severity": "high" if g["iocs"] else "medium",
            "first_seen": _iso(min(dates)), "last_seen": _iso(max(dates)), "references": refs,
            "indicators": {"sender_domains": [], "url_domains": g["iocs"][:50]},
        })
    out.sort(key=lambda c: c["last_seen"], reverse=True)
    return out[:MAX_FEED_CAMPAIGNS]


def campaigns_from_waves(waves: list[dict[str, Any]], *, now: datetime | None = None) -> list[dict[str, Any]]:
    """SAQR's own trending scam waves (awareness.trending_waves) -> campaigns, with the sites SAQR
    flagged as indicators (after the safety rules: never a platform such as vercel.app)."""
    from .registry import ALL_BRANDS

    by_name = {e.name_en: e for e in ALL_BRANDS}
    stamp = _iso(now)
    out = []
    for w in waves:
        e = by_name.get(w.get("entity") or "")
        if not e or int(w.get("score") or 0) < 3:  # one stray scan is not a wave
            continue
        lid = "tax" if e.id == "tamm" else CATEGORY_LURE.get(e.category, "account")  # TAMM lures = refunds / fees
        lure = LURES[lid]
        iocs: list[str] = []
        for d in w.get("domains") or []:
            r = ioc_allowed(d or "")
            if r and r not in iocs:
                iocs.append(r)
        name = _plain_name(e)
        out.append({
            "id": campaign_id(f"saqr:{e.id}"),
            "title_en": f"Fake {name} sites detected by SAQR", "title_ar": f"مواقع مزيفة تنتحل صفة {e.name_ar} رصدها صقر",
            "summary_en": f"SAQR-INTEL flagged scam sites impersonating {name} in the last 72 hours"
                          + (f". The lure: {e.lure_en}." if e.lure_en else "."),
            "summary_ar": f"رصد صقر خلال آخر 72 ساعة مواقع احتيالية تنتحل صفة {e.name_ar}"
                          + (f". الطُّعم: {e.lure_ar}." if e.lure_ar else "."),
            "brands": _brand_terms(e), "terms": list(lure["terms"]), "min_terms": 2, "channels": list(lure["channels"]),
            "regions": ["AE"], "severity": "high", "first_seen": stamp, "last_seen": stamp,
            "references": [{"source_id": DETECTIONS_SOURCE["id"], "url": f"https://{e.domains[0]}",
                            "title": f"Official {name} website"}] if e.domains else [],
            "indicators": {"sender_domains": [], "url_domains": iocs[:50]},
        })
    return out


# =============================================================================================
# 5. Validation of campaign records (seed file, feed output)
# =============================================================================================
_ID = re.compile(r"^cmp-[0-9a-f]{8}$")
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


def _str_list(v: Any, limit: int = 60, item_len: int = 120) -> list[str]:
    if not isinstance(v, list):
        return []
    out: list[str] = []
    for x in v:
        if isinstance(x, str) and x.strip() and x.strip()[:item_len] not in out:
            out.append(x.strip()[:item_len])
    return out[:limit]


def _safe_iocs(v: Any) -> list[str]:
    out: list[str] = []
    for d in _str_list(v, 200, 253):
        r = ioc_allowed(d)
        if r and r not in out:
            out.append(r)
    return out


def clean_campaign(c: Any) -> dict[str, Any] | None:
    """A campaign dict in exactly the contract shape, or None if unusable. Indicators that break
    the safety rules are dropped silently; text is length-capped and stripped of control chars."""
    if not isinstance(c, dict) or not isinstance(c.get("id"), str) or not _ID.match(c["id"]):
        return None
    ind = c.get("indicators") if isinstance(c.get("indicators"), dict) else {}
    try:
        min_terms = max(1, min(10, int(c.get("min_terms", 2))))
    except (TypeError, ValueError):
        min_terms = 2
    refs = []
    for r in c.get("references") or []:
        if isinstance(r, dict) and _safe_url(r.get("url")):
            refs.append({"source_id": str(r.get("source_id") or "")[:60], "url": _safe_url(r.get("url")),
                         "title": _clean_text(str(r.get("title") or ""), 200)})
    out = {
        "id": c["id"],
        "title_en": _clean_text(str(c.get("title_en") or ""), 160),
        "title_ar": _clean_text(str(c.get("title_ar") or ""), 160),
        "summary_en": _clean_text(str(c.get("summary_en") or ""), 600),
        "summary_ar": _clean_text(str(c.get("summary_ar") or ""), 600),
        "brands": _str_list(c.get("brands")), "terms": _str_list(c.get("terms")), "min_terms": min_terms,
        "channels": _str_list(c.get("channels"), 6, 20), "regions": _str_list(c.get("regions"), 20, 20),
        "severity": c.get("severity") if c.get("severity") in _SEVERITIES else "medium",
        "first_seen": str(c.get("first_seen") or "")[:25], "last_seen": str(c.get("last_seen") or "")[:25],
        "references": refs[:10],
        "indicators": {"sender_domains": _safe_iocs(ind.get("sender_domains")),
                       "url_domains": _safe_iocs(ind.get("url_domains"))},
    }
    has_ioc = out["indicators"]["sender_domains"] or out["indicators"]["url_domains"]
    if not out["title_en"] or not out["title_ar"] or not (out["terms"] or has_ioc):
        return None
    return out


def load_seed(path: Path = SEED_PATH) -> dict[str, Any]:
    """The seed feed file ({format, sources, campaigns ...}); an empty feed if missing / broken."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or data.get("format") != FORMAT:
            raise ValueError("not a saqr-campaigns file")
    except (OSError, ValueError) as exc:
        log.warning("Campaign seed not loaded (%s): %s", path.name, exc)
        return {"format": FORMAT, "version": VERSION, "generated_at": _iso(), "ttl_hours": TTL_HOURS,
                "sources": [], "campaigns": []}
    return data


def _etag_of(campaigns: list[dict[str, Any]], sources: list[dict[str, Any]]) -> str:
    # fetched_at changes on every refresh; the ETag only changes when the content clients use changes.
    stable = [{k: v for k, v in s.items() if k != "fetched_at"} for s in sources]
    blob = json.dumps({"c": campaigns, "s": stable}, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return 'W/"' + hashlib.sha256(blob.encode()).hexdigest()[:32] + '"'


def etag_matches(if_none_match: str | None, etag: str) -> bool:
    """Weak comparison (RFC 9110 section 13.1.2) of an If-None-Match header with our ETag."""
    if not if_none_match:
        return False
    want = etag.removeprefix("W/")
    for tag in if_none_match.split(","):
        tag = tag.strip()
        if tag == "*" or tag.removeprefix("W/") == want:
            return True
    return False


# =============================================================================================
# 6. The feed singleton
# =============================================================================================
class CampaignFeed:
    """Seed + live feeds + SAQR detections, merged. Modelled on threat_feeds.ThreatFeeds."""

    def __init__(self, seed_path: Path | None = SEED_PATH) -> None:
        self.seed_path = seed_path
        self.seed_campaigns: list[dict[str, Any]] = []
        self.seed_sources: list[dict[str, Any]] = []
        self.feed_campaigns: list[dict[str, Any]] = []
        self.wave_campaigns: list[dict[str, Any]] = []
        self.source_status: dict[str, dict[str, Any]] = {}
        self.campaigns: list[dict[str, Any]] = []
        self.sources: list[dict[str, Any]] = []
        self.generated_at: str = _iso()
        self.etag: str = 'W/"0"'
        self.updated: str | None = None
        self.last_error: str | None = None
        self._prepared: list[tuple[dict[str, Any], dict[str, Any]]] = []
        self._task: asyncio.Task | None = None
        self.load_seed()

    # -- data --------------------------------------------------------------------------------
    def load_seed(self) -> int:
        """(Re)load the researched seed file; seed_path=None starts empty (tools, tests)."""
        data = load_seed(self.seed_path) if self.seed_path else {}
        self.seed_campaigns = [c for c in (clean_campaign(x) for x in data.get("campaigns") or []) if c]
        self.seed_sources = [dict(s) for s in data.get("sources") or [] if isinstance(s, dict) and s.get("id")]
        self._rebuild(generated_at=str(data.get("generated_at") or _iso()))
        return len(self.seed_campaigns)

    def _rebuild(self, generated_at: str | None = None) -> None:
        merged: dict[str, dict[str, Any]] = {}
        for c in [*self.seed_campaigns, *self.wave_campaigns, *self.feed_campaigns]:
            merged.setdefault(c["id"], c)  # the researched seed wins over live data with the same id
        campaigns = list(merged.values())
        by_id: dict[str, dict[str, Any]] = {s["id"]: dict(s) for s in self.seed_sources}
        by_id.update({sid: dict(st) for sid, st in self.source_status.items()})  # live status beats build-time status
        if self.wave_campaigns:
            by_id[DETECTIONS_SOURCE["id"]] = {**DETECTIONS_SOURCE, "ok": True, "fetched_at": self.updated or _iso(),
                                              "items": len(self.wave_campaigns)}
        sources = list(by_id.values())
        etag = _etag_of(campaigns, sources)
        if etag != self.etag:
            self.generated_at = generated_at or _iso()
        self.campaigns, self.sources, self.etag = campaigns, sources, etag
        self._prepared = [(c, _prepare_campaign(c)) for c in campaigns]

    def snapshot(self) -> dict[str, Any]:
        """The public feed JSON (GET /api/campaigns). A deep copy: callers may change it freely."""
        return {"format": FORMAT, "version": VERSION, "generated_at": self.generated_at, "ttl_hours": TTL_HOURS,
                "sources": copy.deepcopy(self.sources), "campaigns": copy.deepcopy(self.campaigns)}

    def match(self, input: dict[str, Any], channel: str | None = "email") -> list[dict[str, Any]]:  # noqa: A002
        """Every campaign this message matches, IOC hits first (then feed order):
        [{"id", "title_en", "title_ar", "match", "points", "matched"}].
        Campaigns seen only on other channels (an SMS-only toll scam) are skipped for email, as in
        the extension's matchFeed(); channel=None matches every campaign."""
        pi = _prepare_input(input or {})
        out = []
        for c, pc in self._prepared:
            if channel and c["channels"] and channel not in c["channels"]:
                continue
            m = _match_prepared(pc, pi)
            if m:
                out.append({"id": c["id"], "title_en": c["title_en"], "title_ar": c["title_ar"], **m})
        out.sort(key=lambda x: x["match"] != "ioc")
        return out

    def status(self) -> dict[str, Any]:
        return {"campaigns": len(self.campaigns), "seed": len(self.seed_campaigns), "live": len(self.feed_campaigns),
                "saqr_detections": len(self.wave_campaigns), "etag": self.etag, "generated_at": self.generated_at,
                "updated": self.updated, "error": self.last_error,
                "enabled": FEEDS_ENABLED and not settings.offline_mode,
                "sources": [{k: s.get(k) for k in ("id", "ok", "items", "fetched_at")} for s in self.sources]}

    # -- refresh -----------------------------------------------------------------------------
    async def fetch_sources(self, transport: httpx.AsyncBaseTransport | None = None
                            ) -> tuple[list[tuple[str, dict[str, Any]]], dict[str, dict[str, Any]]]:
        """Download + parse every live source: ([(source_id, item)], {source_id: status})."""
        items: list[tuple[str, dict[str, Any]]] = []
        status: dict[str, dict[str, Any]] = {}
        headers = {"User-Agent": "SAQR-INTEL campaign-feed client",
                   "Accept": "application/rss+xml, application/atom+xml, application/xml;q=0.9, */*;q=0.5"}
        async with httpx.AsyncClient(timeout=30, follow_redirects=True, transport=transport, headers=headers) as client:

            async def one(src: dict[str, str]) -> None:
                st: dict[str, Any] = {**src, "ok": False, "fetched_at": _iso(), "items": 0}
                try:
                    r = await client.get(src["url"])
                    r.raise_for_status()
                    parsed = await asyncio.to_thread(parse_feed, r.content)  # size-capped inside
                    items.extend((src["id"], it) for it in parsed)
                    st.update(ok=True, items=len(parsed))
                except Exception as exc:  # noqa: BLE001 - one broken feed must not stop the others
                    st["error"] = type(exc).__name__
                    log.warning("Campaign source %s failed: %s", src["id"], exc)
                status[src["id"]] = st

            await asyncio.gather(*(one(s) for s in SOURCES))
        return items, status

    async def refresh(self, *, transport: httpx.AsyncBaseTransport | None = None, fetch: bool | None = None,
                      waves: list[dict[str, Any]] | None = None) -> None:
        """Rebuild the live part. fetch defaults to "online and CAMPAIGN_FEEDS on" (passing a test
        transport forces it); waves defaults to awareness.trending_waves() from the database."""
        if fetch is None:
            fetch = transport is not None or (FEEDS_ENABLED and not settings.offline_mode)
        errors: list[str] = []
        if fetch:
            items, status = await self.fetch_sources(transport)
            seed_urls = {r["url"] for c in self.seed_campaigns for r in c["references"]}
            built = [c for c in (clean_campaign(x) for x in campaigns_from_items(items, skip_urls=seed_urls)) if c]
            if any(s["ok"] for s in status.values()):  # all feeds down: keep the last good live set
                self.feed_campaigns = built
            self.source_status = {k: {kk: vv for kk, vv in v.items() if kk != "error"} for k, v in status.items()}
            errors += [f"{k}: {v['error']}" for k, v in status.items() if v.get("error")]
        if waves is None:
            try:
                from .awareness import trending_waves

                waves = await trending_waves(72)
            except Exception as exc:  # noqa: BLE001 - DB not connected yet (tests, start-up)
                log.debug("trending waves unavailable: %s", exc)
        if waves is not None:
            self.wave_campaigns = [c for c in (clean_campaign(x) for x in campaigns_from_waves(waves)) if c]
        self.last_error = "; ".join(errors) or None
        self.updated = _iso()
        self._rebuild()
        log.info("Campaign feed: %d campaigns (%d seed, %d live, %d SAQR) %s", len(self.campaigns),
                 len(self.seed_campaigns), len(self.feed_campaigns), len(self.wave_campaigns), self.etag)

    def start(self) -> None:
        if not settings.offline_mode and FEEDS_ENABLED:
            self._task = asyncio.create_task(self._loop(), name="campaign-feed")

    async def stop(self) -> None:
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self._task = None

    async def _loop(self) -> None:
        await asyncio.sleep(20)  # let the DB seed + historical scans settle first
        while True:
            try:
                await self.refresh()
            except Exception:  # noqa: BLE001
                log.exception("campaign feed refresh failed")
            await asyncio.sleep(REFRESH_SECONDS)


campaign_feed = CampaignFeed()
