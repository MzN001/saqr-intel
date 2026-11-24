"""Email rules engine (explainable, offline, never fails) -> risk floor for email scans.

Same principle as ai_inspector.run_rules for websites:

* STRONG flags are evidence that on its own points to fraud (look-alike letters in an address, a
  link that SAQR scanned as a scam, a brand name sent from a free Gmail account, an .exe file).
* WEAK flags are things real mail shows all the time (urgent words, "sign in", a failed SPF check
  on a forwarded mail). They add points ONLY when at least one strong flag is present.
* INFO flags (0 points) explain what was checked (DMARC pass, mailing list, official sender).

Score = min(100, max(sum(strong) + (sum(weak) if any strong else 0), highest linked-site score)),
then the contract's floor (brand claim + credential/payment/DMARC/link evidence => at least 70) and
cap (authenticated mail from an official / top-10k sender with no link, Unicode, attachment or
campaign-IOC evidence => at most 20).

Every flag carries English + Arabic citizen text. Inputs are the shared types from email_types.
"""
from __future__ import annotations

import html as _html
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qs, unquote, urlsplit

from .ai_inspector import STRONG_LEXICAL, URGENCY, RuleResult, _entity_in_text, verdict_for
from .domain_intel import _EXTRACT, RedFlag, analyze_lexical, to_unicode_host
from .email_types import Address, AuthReport, ParsedEmail
from .email_unicode import ADDRESS_WHERES, TEXT_WHERES, deconfuse, strip_invisible, unescape
from .registry import ALL_BRANDS, ENTITY_EXTRA_DOMAINS, Entity
from .threat_feeds import popularity_rank, threat_feeds

# ---------------------------------------------------------------------------
# Reference lists
# ---------------------------------------------------------------------------
# Free webmail providers (contract section 4 list: identical in the extension's JS).
FREEMAIL = frozenset({
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com",
    "ymail.com", "icloud.com", "me.com", "aol.com", "proton.me", "protonmail.com", "gmx.com", "mail.com",
    "zoho.com", "yandex.com", "yandex.ru", "mail.ru",
})
# Bulk-mail services whose bounce address (Return-Path) differs from the From domain by design.
ESP_BOUNCE_DOMAINS = frozenset({
    "sendgrid.net", "amazonses.com", "mailgun.org", "mailgun.net", "mcsv.net", "mcdlv.net", "rsgsv.net",
    "mandrillapp.com", "sparkpostmail.com", "mktomail.com", "exacttarget.com", "exct.net", "sendinblue.com",
    "brevosend.com", "sender-sib.com", "postmarkapp.com", "mtasv.net", "hubspotemail.net", "mailjet.com",
    "cmail19.com", "cmail20.com", "createsend.com", "constantcontact.com", "salesforce.com",
    "messagegears.net", "emarsys.net", "zendesk.com", "freshdesk.com", "intercom-mail.com", "sailthru.com",
    "customeriomail.com", "klaviyomail.com", "iterable.com", "mailchimpapp.net", "list-manage.com",
    "google.com", "googlegroups.com", "outbound.protection.outlook.com", "bounce.linkedin.com",
    "facebookmail.com", "smtp-out.amazonses.com", "elasticemail.com", "sendpulse.com", "mailerlite.com",
})
# Click-tracking hosts of bulk-mail services: the real destination is hidden inside an opaque
# token, so these links are neither "mismatched" nor worth scanning.
ESP_CLICK_TRACKERS = (
    "sendgrid.net", "list-manage.com", "rs6.net", "hubspotlinks.com", "hubspotemail.net", "mandrillapp.com",
    "sparkpostmail.com", "spmailtechnol.com", "exacttarget.com", "exct.net", "awstrack.me", "aweber.com",
    "createsend1.com", "cmail19.com", "cmail20.com", "iterable.com", "pstmrk.it", "klclick.com",
    "klclick1.com", "klclick2.com", "klclick3.com", "sender-sib.com", "sendibt2.com", "sendibt3.com",
    "sendibm1.com", "mjt.lu", "mailerlite.com", "mlsend.com", "customeriomail.com", "mailgun.org",
    "emltrk.com", "mailchimp.com", "salesforce.com", "marketo.com", "mktoweb.com", "mkt.com", "eloqua.com",
    "sailthru.com", "braze.com", "linkedin.com", "mailtrack.io", "constantcontact.com", "elasticemail.com",
)
# Extra sending domains brands really use for notifications (otherwise "Facebook" <x@facebookmail.com>
# would look like a fake display name).
BRAND_MAIL_DOMAINS: dict[str, tuple[str, ...]] = {
    "facebook": ("facebookmail.com",), "instagram": ("facebookmail.com", "mail.instagram.com"),
    "whatsapp": ("facebookmail.com",), "microsoft": ("microsoftstoreemail.com", "microsoftonline.com"),
    "amazon": ("amazon.ae", "amazon.com", "amazon.sa"), "google": ("youtube.com",),
    "linkedin": ("linkedin.com",), "apple": ("apple.com", "icloud.com"),
    "dhl": ("dhl.co.uk", "dhlparcel.co.uk", "dhlparcel.nl", "dpdhl.com"),
}
DANGEROUS_EXTS = frozenset({
    # contract list
    "exe", "scr", "js", "vbs", "hta", "iso", "img", "lnk", "html", "htm", "svg", "docm", "xlsm", "jar",
    "bat", "cmd", "ps1",
    # same family (Windows programs / scripts / disk images / macro documents)
    "msi", "com", "pif", "vbe", "jse", "wsf", "wsh", "cpl", "reg", "vhd", "vhdx", "xll", "one", "shtml",
    "xhtml", "dotm", "pptm", "xlam", "chm", "appx", "msix", "url",
})
ARCHIVE_EXTS = frozenset({"zip", "rar", "7z", "gz", "tgz", "tar", "cab", "ace", "arj", "bz2", "xz", "z", "lzh"})
DOC_EXTS = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "rtf", "jpg", "jpeg",
                      "png", "gif", "csv", "odt", "mp3", "mp4", "wav"})

# Codes of each strength (the contract table). Anything not listed is INFO.
STRONG_CODES = {
    "IDN_MIXED_SCRIPT", "DISPLAY_NAME_CONFUSABLE", "BIDI_OVERRIDE", "CAMPAIGN_IOC_MATCH", "LINK_HIGH_RISK",
    "KNOWN_PHISHING_LINK", "SENDER_LOOKALIKE", "DANGEROUS_ATTACHMENT", "INVISIBLE_IN_TOKEN",
    "PUNYCODE_DOMAIN", "DISPLAY_NAME_ADDRESS_SPOOF", "DMARC_FAIL", "DISPLAY_NAME_BRAND_SPOOF",
    "FREEMAIL_BRAND_SENDER", "LINK_TEXT_MISMATCH", "SENDER_NEW_DOMAIN", "LINK_SUSPICIOUS",
    "REPLY_TO_FREEMAIL_BRAND", "OFFICIAL_SENDER_UNAUTHENTICATED",
    # a call-back number in a mail that claims a UAE institution: personal mobile / foreign number
    "CALLBACK_MOBILE_FOR_INSTITUTION", "CALLBACK_FOREIGN_FOR_INSTITUTION",
}
WEAK_CODES = {
    "SPF_FAIL", "DKIM_FAIL", "CREDENTIAL_REQUEST", "USER_MODEL_SCAM", "CAMPAIGN_LURE_MATCH",
    "DMARC_FAIL_P_NONE", "NO_AUTHENTICATION", "REPLY_TO_MISMATCH", "URGENCY_LANGUAGE", "PAYMENT_REQUEST",
    "FANCY_UNICODE", "BRAND_MENTION", "SPF_SOFTFAIL", "RETURN_PATH_MISMATCH", "ATTACHMENT_ARCHIVE",
    "SENDER_NO_MX",
}
BRAND_CLAIM = {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER", "SENDER_LOOKALIKE", "OFFICIAL_SENDER_UNAUTHENTICATED"}
# Weak flags that, next to a confident personal-model scam opinion (USER_MODEL_SCAM), may lift a mail
# from an untrusted sender to SUSPICIOUS (never higher). NO_AUTHENTICATION / URGENCY / BRAND_MENTION are
# too common in real mail to count here.
MODEL_CORROBORATION = {"PAYMENT_REQUEST", "CREDENTIAL_REQUEST", "CAMPAIGN_LURE_MATCH", "REPLY_TO_MISMATCH",
                       "SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL_P_NONE", "FANCY_UNICODE"}
# Naive Bayes saturates: with ~40 labels per class it gave p >= 0.9 to 15 of 20 tricky legit mails in
# testing, so the verdict lift needs a much surer opinion than the 0.9 that shows USER_MODEL_SCAM.
MODEL_FLOOR_P = 0.99
# Strong evidence that an authenticated official sender cannot "vouch away" (no cap at 20).
CAP_BLOCKERS = {
    "LINK_HIGH_RISK", "LINK_SUSPICIOUS", "KNOWN_PHISHING_LINK", "LINK_TEXT_MISMATCH", "IDN_MIXED_SCRIPT",
    "DISPLAY_NAME_CONFUSABLE", "BIDI_OVERRIDE", "INVISIBLE_IN_TOKEN", "PUNYCODE_DOMAIN",
    "DANGEROUS_ATTACHMENT", "CAMPAIGN_IOC_MATCH", "CALLBACK_MOBILE_FOR_INSTITUTION", "CALLBACK_FOREIGN_FOR_INSTITUTION",
}
UNICODE_CODES = {"IDN_MIXED_SCRIPT", "DISPLAY_NAME_CONFUSABLE", "BIDI_OVERRIDE", "INVISIBLE_IN_TOKEN",
                 "PUNYCODE_DOMAIN", "FANCY_UNICODE"}

CREDENTIAL_RE = re.compile(
    r"\b(passwords?|passcodes?|otp|one[- ]time (?:password|code|pin)|verification code|cvv|cvc|"
    r"security code|card (?:number|details)|expiry date|atm pin|pin (?:code|number)|emirates id|uae ?pass|"
    r"(?:log|sign) ?in (?:here|now|to|below)|verify your (?:account|identity|card|details|information)|"
    r"confirm your (?:account|identity|details|card|information)|"
    r"update your (?:account|details|payment|billing|information))\b|"
    r"كلمة المرور|كلمة السر|رمز التحقق|الرقم السري|بيانات البطاقة|رقم البطاقة|تأكيد هويتك|تحديث بياناتك|"
    r"تسجيل الدخول|رمز (?:ال)?OTP", re.I)
PAYMENT_RE = re.compile(
    r"\b(customs (?:fee|duty|charges?)|(?:re)?delivery fee|processing fee|outstanding (?:amount|balance|fine)|"
    r"unpaid (?:fine|bill|invoice|fee)s?|pay (?:now|the fee|the fine|your fine|a small)|settle (?:the|your)|"
    r"wire transfer|gift ?cards?|bitcoin|usdt|crypto(?:currency)? wallet|fees? of (?:aed|usd|\$|eur))\b|"
    r"\b(?:aed|usd|eur|\$)\s?[\d,.]+[^\n.]{0,30}\b(?:is due|due now|due today|to pay|fee)\b|"
    r"ادفع|دفع الرسوم|رسوم جمركية|رسوم التوصيل|رسوم إعادة التوصيل|سداد المبلغ|تحويل مبلغ|مخالفات غير مدفوعة",
    re.I)
# "We will never ask for your password" is advice, not a request.
NEGATION_RE = re.compile(r"\b(never|not|don't|do not|won't|will not|no one)\b|لن |لا |أبدا|ابدا|أبداً", re.I)
SENTENCE_SPLIT = re.compile(r"[.!?\n؟。]+")
FORWARDED_RE = re.compile(r"^\s*(fwd?|fw)\s*:", re.I)
VIA_RE = re.compile(r"\bvia\b", re.I)
EMAIL_IN_TEXT = re.compile(r"[\w.+-]+@((?:[\w-]+\.)+[a-z]{2,24})", re.I)
DOMAIN_IN_TEXT = re.compile(r"(?<![\w@.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24})(?![\w-])", re.I)


# ---------------------------------------------------------------------------
# Small helpers (also used by email_pipeline)
# ---------------------------------------------------------------------------
def regdom(host: str | None) -> str:
    """Registered domain (public-suffix aware, offline snapshot): mail.bankfab.com -> bankfab.com."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return ""
    ext = _EXTRACT(h)
    return f"{ext.domain}.{ext.suffix}" if ext.domain and ext.suffix else h


def is_freemail(host: str | None) -> bool:
    return regdom(host) in FREEMAIL


def is_esp_tracker(host: str | None) -> bool:
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in ESP_CLICK_TRACKERS)


def same_owner(a: str, b: str) -> bool:
    """Two hosts belong to the same organisation: same registered domain, or both official domains
    of one brand (amazon.ae / amazon.com)."""
    ra, rb = regdom(a), regdom(b)
    if not ra or not rb:
        return False
    if ra == rb:
        return True
    for ent in ALL_BRANDS:
        doms = {*ent.domains, *BRAND_MAIL_DOMAINS.get(ent.id, ()),
                *(d for d, i in ENTITY_EXTRA_DOMAINS.items() if i == ent.id)}
        if ra in doms and rb in doms:
            return True
    return False


def host_of(url: str) -> str:
    """ASCII (punycode) host of a URL, '' when there is none."""
    try:
        h = (urlsplit(url.strip()).hostname or "").rstrip(".").lower()
    except ValueError:
        return ""
    if not h:
        return ""
    if "%" in h and not re.search(r"[/@?#\\\s%:]", unquote(h)):
        h = unquote(h)  # browsers decode a percent-encoded host: "p%D0%B0ypal.com" opens xn--pypal-4ve.com
    try:
        return h.encode("idna").decode("ascii")
    except UnicodeError:
        return h


def _qs_first(query: str, *names: str) -> str | None:
    q = parse_qs(query, keep_blank_values=False)
    for n in names:
        if q.get(n):
            return q[n][0]
    return None


REDIRECT_PARAMS = ("url", "u", "q", "target", "dest", "destination", "redirect", "redirect_url", "goto", "link", "to")


def unwrap_url(url: str, depth: int = 4) -> tuple[str, str | None]:
    """Unwrap link-protection / redirect wrappers to the real destination.

    Outlook Safe Links (*.safelinks.protection.outlook.com/?url=), google.com/url?q=, Google AMP,
    Facebook l.php, YouTube redirect, Proofpoint URL Defense v2/v3, Barracuda, FireEye, and any
    redirect-style query parameter (url=, u=, q=, target=...) that holds a full http(s) URL.
    Returns (final_url, original_url_or_None)."""
    original = url
    cur = (url or "").strip()
    for _ in range(depth):
        try:
            p = urlsplit(cur)
        except ValueError:
            break
        host = (p.hostname or "").lower()
        nxt: str | None = None
        if host.endswith("safelinks.protection.outlook.com"):
            nxt = _qs_first(p.query, "url")
        elif re.match(r"^(www\.)?google\.[a-z.]{2,8}$", host) and p.path in ("/url", "/url/"):
            nxt = _qs_first(p.query, "q", "url")
        elif re.match(r"^(www\.)?google\.[a-z.]{2,8}$", host) and p.path.startswith("/amp/s/"):
            nxt = "https://" + p.path[len("/amp/s/"):] + (f"?{p.query}" if p.query else "")
        elif host in ("l.facebook.com", "lm.facebook.com", "l.instagram.com") and p.path == "/l.php":
            nxt = _qs_first(p.query, "u")
        elif host.endswith("urldefense.proofpoint.com") and p.path.startswith("/v2/url"):
            raw = _qs_first(p.query, "u")
            nxt = unquote(raw.replace("-", "%").replace("_", "/")) if raw else None
        elif host.endswith("urldefense.com") and "/v3/__" in p.path:
            m = re.search(r"/v3/__(.+?)__;", cur)
            nxt = m.group(1) if m else None
        elif host.endswith("linkprotect.cudasvc.com"):
            nxt = _qs_first(p.query, "a")
        if nxt is None and p.query and not is_esp_tracker(host):
            cand = _qs_first(p.query, *REDIRECT_PARAMS)
            if cand and re.match(r"^https?://", cand.strip(), re.I):
                nxt = cand
        if not nxt or not re.match(r"^https?://", nxt.strip(), re.I):
            break
        cur = nxt.strip()
    return (cur, original) if cur != original else (cur, None)


def link_text_mismatch(display_text: str | None, href_host: str) -> tuple[bool, str | None]:
    """True when the visible link text is itself a web address whose registered domain differs from
    where the link really goes ("https://www.paypal.com/signin" -> paypal-account-review.test).
    Text that is not an address ("Verify my card") is never a mismatch; ESP click trackers are exempt.
    Returns (mismatch, domain shown in the text)."""
    if not display_text or not href_host or is_esp_tracker(href_host):
        return False, None
    t = deconfuse(display_text).strip().strip("<>()[]\"'").lower()
    if " " in t.strip() or len(t) > 300:
        return False, None
    m = re.match(r"^(?:https?://)?(?:[^/@\s]+@)?([a-z0-9.-]+\.[a-z]{2,24})(?::\d+)?(?:[/?#]\S*)?$", t)
    if not m:
        return False, None
    shown = m.group(1).rstrip(".")
    ext = _EXTRACT(shown)
    if not (ext.domain and ext.suffix):
        return False, None
    return (not same_owner(shown, href_host)), shown


def html_to_text(html: str | None) -> str:
    """Crude visible-text extraction (scripts/styles dropped, tags removed, entities decoded)."""
    if not html:
        return ""
    t = re.sub(r"(?is)<(script|style|head|title)[^>]*>.*?</\1>", " ", html[:400_000])
    t = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</li>|</h\d>|</tr>", "\n", t)
    t = re.sub(r"(?s)<[^>]+>", " ", t)
    t = _html.unescape(t)
    t = re.sub(r"[ \t\r\f\v]+", " ", t)
    return re.sub(r"\n\s*\n+", "\n\n", t).strip()


def email_text(parsed: ParsedEmail) -> str:
    """The message body as plain text (text part, else the HTML part's visible text)."""
    return parsed.text_body or html_to_text(parsed.html_body)


def attachment_risk(name: str | None) -> tuple[str | None, str | None]:
    """('dangerous'|'archive'|None, reason) for an attachment file name."""
    n = strip_invisible(deconfuse(name or "")).strip().rstrip(". ").lower()
    n = re.sub(r"\s+", " ", n)
    parts = [p.strip() for p in n.split(".")]
    if len(parts) < 2:
        return None, None
    ext = parts[-1]
    if ext in DANGEROUS_EXTS:
        return "dangerous", f".{ext} file"
    if len(parts) >= 3 and parts[-2] in DOC_EXTS and ext not in DOC_EXTS and not (parts[-2] == "tar"):
        return "dangerous", f"double extension .{parts[-2]}.{ext}"
    if ext in ARCHIVE_EXTS:
        return "archive", f".{ext} archive"
    return None, None


def address_info(addr: Address | None) -> dict[str, Any] | None:
    """The response's per-address block ("from", "reply_to", ...)."""
    if not addr or not (addr.address or addr.domain or addr.display_name):
        return None
    dom = (addr.domain or (addr.address.rpartition("@")[2] if "@" in addr.address else "")).lower()
    lex = _lex(dom)
    return {
        "display_name": addr.display_name or "", "address": addr.address or "", "domain": dom,
        "registered_domain": regdom(dom), "unicode_domain": _unicode_domain(addr, dom),
        "is_freemail": is_freemail(dom),
        "is_official": bool(lex and lex.is_whitelisted and not is_freemail(dom)),
    }


def _unicode_domain(addr: Address, dom: str) -> str:
    """The domain as the email really spelled it (a disguised "pаypal.com" keeps its Cyrillic "а")."""
    try:
        from .email_parse import unicode_domain

        return unicode_domain(addr)
    except Exception:  # noqa: BLE001 — parser module missing: fall back to decoding the punycode
        return to_unicode_host(dom) if dom else ""


def _lex(domain: str | None):
    if not domain:
        return None
    try:
        return analyze_lexical(domain)
    except ValueError:
        return None


def _domain_of(addr: Address | None) -> str:
    if not addr:
        return ""
    return (addr.domain or (addr.address.rpartition("@")[2] if "@" in (addr.address or "") else "")).lower()


# Short global brands that ai_inspector._entity_in_text skips (DHL, UPS: under 4 letters). EMAIL display
# name / subject only (website scanning is unchanged): a whole word next to courier wording ("DHL Express",
# "UPS: package on hold") or the whole display name. A brand that is also an ordinary word (ups) must be in
# capitals, so "ups and downs", "follow-ups" or a UPS battery offer never count as a brand claim.
SHORT_BRANDS = tuple(e for e in ALL_BRANDS if e.category == "global" and e.name_en.isalpha() and len(e.name_en) < 4)
COURIER_CONTEXT_RE = re.compile(
    r"\b(express|deliver(y|ies|ed)?|redelivery|shipping|shipment|parcel|package|courier|tracking|waybill|"
    r"customs|duties|clearance|logistics|e-?commerce|freight|my choice)\b|شحن|طرد|توصيل|جمارك|جمرك", re.I)
NOT_COURIER_RE = re.compile(r"\b(battery|batteries|backup|power supply|uninterruptible|inverter|kva)\b", re.I)
# A subject ABOUT a scam ("Be careful: fake DHL customs emails") is someone warning you, not a brand claim.
ABOUT_SCAM_RE = re.compile(r"\b(scams?|scammers?|beware|watch out|be careful)\b|احتيال", re.I)


def short_brand_claim(text: str, context: str) -> Entity | None:
    """DHL / UPS named as the sender in a display name or subject (see SHORT_BRANDS)."""
    for ent in SHORT_BRANDS:
        flags = 0 if ent.name_en.lower() in ent.common_keywords else re.I
        name = re.escape(ent.name_en)
        if re.fullmatch(rf"\W*{name}\W*", text or "", flags):
            return ent
        if (re.search(rf"(?<![\w&@.-]){name}(?![\w&@])", text or "", flags)
                and COURIER_CONTEXT_RE.search(context or "") and not NOT_COURIER_RE.search(context or "")):
            return ent
    return None


# Brands whose name is also an ordinary word (Amazon, Apple, Chase, Wise, noon, Google ...): _entity_in_text
# never matches them in free text. In an EMAIL display name they still count when the name is used like a
# company department: the brand as a whole word right next to a corporate role word ("Amazon Recruitment
# Team", "Apple Support", "Team Google"). People's names and casual names ("Chase Smith", "Apple Martin",
# "Wise Guy", "Amazon rainforest trip") have no role word next to the brand.
ROLE_WORDS = frozenset({
    "support", "team", "security", "service", "services", "billing", "account", "accounts", "recruitment",
    "recruiting", "careers", "career", "hr", "pay", "prime", "store", "id", "delivery", "customer", "customers",
    "care", "help", "helpdesk", "verification", "notice", "notices", "alert", "alerts", "notification",
    "notifications",
    "الدعم", "دعم", "فريق", "الأمن", "أمن", "خدمة", "خدمات", "الفواتير", "الحساب", "حساب", "الحسابات",
    "التوظيف", "توظيف", "الوظائف", "الموارد", "المتجر", "متجر", "التوصيل", "توصيل", "العملاء", "عملاء",
    "المساعدة", "مساعدة", "التحقق", "تحقق", "تنبيه", "تنبيهات", "إشعار", "إشعارات", "رعاية",
})
_ROLE_FILLERS = frozenset({"and", "&", "of", "the", "-", "و"})
# Arabic brand names that are ordinary Arabic words / letters ("نون" is the letter N).
_AMBIGUOUS_AR = frozenset({"نون"})
COMMON_NAME_BRANDS = tuple(e for e in ALL_BRANDS if e.category == "global" and e.name_en.isalpha()
                           and len(e.name_en) >= 4 and e.name_en.lower() in e.common_keywords)
_WORD_RE = re.compile(r"[^\W_]+|&", re.U)


def common_brand_claim(display: str) -> Entity | None:
    """A common-word brand used as a department name in a display name (see COMMON_NAME_BRANDS)."""
    words = [w.lower() for w in _WORD_RE.findall(display or "")][:20]
    if len(words) < 2:
        return None
    for ent in COMMON_NAME_BRANDS:
        names = {ent.name_en.lower()} | ({ent.name_ar} if ent.name_ar not in _AMBIGUOUS_AR else set())
        for i, w in enumerate(words):
            if w not in names:
                continue
            # a role word within two words after the brand ("Amazon Recruitment Team", "Apple ID") or right
            # before it ("Team Amazon", "فريق دعم أمازون"), skipping "and" / "of" fillers
            after = [x for x in words[i + 1:i + 4] if x not in _ROLE_FILLERS][:2]
            before = [x for x in words[max(0, i - 3):i] if x not in _ROLE_FILLERS][-2:]
            if any(x in ROLE_WORDS for x in after + before):
                return ent
    return None


# A subject only claims to come FROM a brand when it reads like the brand's notice: the brand plus an
# account / payment / delivery / security word ("Your Aramex parcel is waiting", "PayPal: account limited"),
# or the brand as a "Brand:" / "Brand -" prefix. "DHL vs Aramex prices?" just mentions them.
SUBJECT_NOTICE_RE = re.compile(
    r"\b(support|team|security|service|services|billing|accounts?|alerts?|notices?|notifications?|"
    r"verif(?:y|ied|ication)|confirm(?:ation)?|update[sd]?|suspend(?:ed)?|suspension|lock(?:ed)?|limited|"
    r"restrict(?:ed|ion)|block(?:ed)?|unusual|sign[- ]?in|log[- ]?in|password|payments?|paid|unpaid|invoices?|"
    r"receipts?|refunds?|fees?|fines?|bills?|due|overdue|expir(?:e|ed|es|ing|y)|parcels?|packages?|shipments?|"
    r"deliver(?:y|ed)|redelivery|tracking|customs|orders?|rewards?|prizes?|winner|claim|cards?|transactions?|"
    r"statements?|wallet|subscription|renewal|membership|id|otp|code|action required|important|urgent|final|"
    r"reminder|recruitment|job offer|hr|on hold|held|waiting|pending)\b|"
    r"حساب|تحديث|تأكيد|تحقق|إيقاف|ايقاف|تعليق|مخالف|غرامة|دفع|رسوم|فاتورة|استرداد|شحن|طرد|توصيل|جمارك|"
    r"تنبيه|إشعار|عاجل|بطاقة|مكافأة|جائزة|طلبك", re.I)


def _entity_names(ent: Entity) -> set[str]:
    if ent.category == "global":
        n = ent.name_en.lower()
        return set() if n in ent.common_keywords or len(n) < 4 else {n}
    return {n for n in (ent.name_en.lower(), ent.name_ar, *[a.lower() for a in ent.aliases]) if len(n) >= 3}


def subject_brand_claim(subject: str) -> Entity | None:
    """_entity_in_text(subject), but only when the subject reads like a notice from that brand."""
    ent = _entity_in_text(subject or "")
    if not ent:
        return None
    if SUBJECT_NOTICE_RE.search(subject):
        return ent
    low = subject.lower()
    for n in _entity_names(ent):
        if re.match(rf"^\W*{re.escape(n)}(?!\w)\s*[:\-–—|]", low):
            return ent
    return None


# Styled letters (math bold, small capitals, full-width ...) that spell a BRAND name: the owner's rule is
# that a disguised brand name is flagged at once. Styled text that is not a brand (newsletter headings in
# bold Unicode) stays the weak FANCY_UNICODE note.
_STYLED_WHERES = ("subject", "display_name", "body")


def _brand_terms() -> list[tuple[str, Entity, bool]]:
    """(term, brand, needs_capitals) for every brand name / alias / keyword that is not an ordinary word."""
    global _BRAND_TERMS
    if _BRAND_TERMS is None:
        out: dict[str, tuple[str, Entity, bool]] = {}
        for ent in ALL_BRANDS:
            common = {c.lower() for c in ent.common_keywords}
            for raw in (ent.name_en, *ent.aliases, *ent.keywords):
                t = re.sub(r"\s+", " ", re.sub(r"[^a-z0-9]+", " ", raw.lower())).strip()
                letters = t.replace(" ", "")
                if not t or not raw.isascii() or t in common or len(letters) < 3:
                    continue
                out.setdefault(t, (t, ent, len(letters) < 4))
        _BRAND_TERMS = sorted(out.values(), key=lambda x: -len(x[0]))  # longest first ("emirates post")
    return _BRAND_TERMS


_BRAND_TERMS: list[tuple[str, Entity, bool]] | None = None


def styled_brand(findings: Iterable[dict[str, Any]]) -> tuple[Entity, str] | None:
    """(brand, styled text) when the "fancy" letters in a subject / display name / body spell a brand."""
    by_where: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        if f.get("kind") == "fancy" and f.get("where") in _STYLED_WHERES:
            by_where.setdefault(f["where"], []).append(f)
    for where in _STYLED_WHERES:
        toks = by_where.get(where) or []
        if not toks:
            continue
        plain = [deconfuse(unescape(f["sample_escaped"])) for f in toks]
        joined = " ".join(re.sub(r"[^a-z0-9]+", " ", p.lower()).strip() for p in plain)
        caps = " ".join(re.sub(r"[^a-z0-9]+", " ", p.lower()).strip() for p in plain if p.isupper())
        for term, ent, needs_caps in _brand_terms():
            hay = caps if needs_caps else joined
            if hay and re.search(rf"(?<![a-z0-9]){re.escape(term)}(?![a-z0-9])", hay):
                shown = " ".join(unescape(f["sample_escaped"]) for f in toks)[:60]
                return ent, shown
    return None


def sender_is_brand(ent: Entity, domain: str) -> bool:
    """Is this sending domain one the brand really uses?"""
    rd = regdom(domain)
    if rd in FREEMAIL:  # anyone can open a gmail.com / outlook.com account
        return False
    doms = {*ent.domains, *BRAND_MAIL_DOMAINS.get(ent.id, ()),
            *(d for d, i in ENTITY_EXTRA_DOMAINS.items() if i == ent.id)}
    return any(domain == d or domain.endswith("." + d) or rd == d for d in doms)


def _matches(rx: re.Pattern, text: str, limit: int = 4) -> list[str]:
    """Distinct matches of rx in sentences that are not advice ("we will never ask for ...")."""
    found: list[str] = []
    for sent in SENTENCE_SPLIT.split(text[:60_000]):
        if not sent.strip() or NEGATION_RE.search(sent):
            continue
        for m in rx.finditer(sent):
            w = m.group(0).strip().lower()
            if w and w not in found:
                found.append(w)
            if len(found) >= limit:
                return found
    return found


# ---------------------------------------------------------------------------
# Result types
# ---------------------------------------------------------------------------
@dataclass
class EmailFlag(RedFlag):
    """RedFlag plus the contract's "strength" (strong|weak|info) and a short evidence string."""
    strength: str = "info"
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "points": self.points, "strength": self.strength,
                "en": self.en, "ar": self.ar, "evidence": self.evidence}


@dataclass
class EmailRuleResult(RuleResult):
    """ai_inspector.RuleResult-compatible (score, verdict, entity, flags, harvested) + email details."""
    official_entity: Entity | None = None
    is_official_sender: bool = False
    trusted_sender: bool = False
    is_list: bool = False
    is_bulk: bool = False
    capped: bool = False
    verified_official: bool = False   # authenticated official sender, nothing contradicting it
    max_link_score: int = 0
    rule_codes: list[str] = field(default_factory=list)  # every code produced (for model features)

    @property
    def strong_present(self) -> bool:
        return any(f.points > 0 and getattr(f, "strength", "") == "strong" for f in self.flags)

    def flags_dicts(self) -> list[dict[str, Any]]:
        return [f.to_dict() if isinstance(f, EmailFlag) else
                {"code": f.code, "severity": f.severity, "points": f.points, "strength": "info",
                 "en": f.en, "ar": f.ar, "evidence": None} for f in self.flags]


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------
def _samples(findings: Iterable[dict[str, Any]], n: int = 3) -> str:
    return "; ".join(f"{f['where']}: {f['sample_escaped']}" for f in list(findings)[:n])


def _unicode_flags(findings: list[dict[str, Any]], add) -> None:
    idn = [f for f in findings if f["where"] in ADDRESS_WHERES and f["kind"] in ("mixed_script", "whole_script_confusable")]
    text = [f for f in findings if f["where"] in TEXT_WHERES and f["kind"] in ("mixed_script", "whole_script_confusable")]
    bidi = [f for f in findings if f["kind"] == "bidi"]
    invis = [f for f in findings if f["kind"] == "invisible"]
    idn_keys = {(f["where"], f["skeleton"]) for f in idn + text}  # a look-alike domain is not counted twice
    puny = [f for f in findings if f["kind"] == "punycode" and (f["where"], f["skeleton"]) not in idn_keys]
    fancy = [f for f in findings if f["kind"] == "fancy"]
    if idn:
        add("IDN_MIXED_SCRIPT", "critical", 65,
            "An email address or web link in this message uses look-alike letters from another alphabet "
            f"(for example a Cyrillic \"а\" instead of a Latin \"a\") to imitate a real name: {idn[0]['skeleton']}.",
            "يستخدم عنوان بريد أو رابط في هذه الرسالة أحرفاً مشابهة من أبجدية أخرى (مثل حرف \"а\" السيريلي بدلاً من "
            f"\"a\" اللاتيني) لتقليد اسم حقيقي: {idn[0]['skeleton']}.", _samples(idn))
    if text:
        add("DISPLAY_NAME_CONFUSABLE", "critical", 65,
            f"The text spells \"{text[0]['skeleton']}\" with letters from another alphabet that only look like "
            "Latin letters. Real companies never do this; scammers do it to slip past filters.",
            f"يكتب النص كلمة \"{text[0]['skeleton']}\" بأحرف من أبجدية أخرى تشبه الأحرف اللاتينية فقط. "
            "الشركات الحقيقية لا تفعل ذلك؛ المحتالون يفعلونه لتجاوز أنظمة الحماية.", _samples(text))
    if bidi:
        add("BIDI_OVERRIDE", "critical", 65,
            "A hidden right-to-left control character reverses part of a name, so a file or link is not what "
            "it looks like (for example \"invoice_exe.pdf\" is really a program).",
            "يحتوي الاسم على رمز تحكم مخفي يعكس اتجاه جزء منه، فيبدو الملف أو الرابط مختلفاً عن حقيقته "
            "(مثلاً \"invoice_exe.pdf\" هو في الحقيقة برنامج).", _samples(bidi))
    if invis:
        add("INVISIBLE_IN_TOKEN", "high", 45,
            "Invisible characters are hidden inside words, addresses or links to trick security filters.",
            "توجد أحرف غير مرئية مخفية داخل الكلمات أو العناوين أو الروابط لخداع أنظمة الحماية.", _samples(invis))
    if puny:
        add("PUNYCODE_DOMAIN", "high", 40,
            f"An address or link uses an international (encoded) domain name: {unescape(puny[0]['sample_escaped'])}. "
            "Check carefully that it is the real website before you trust it.",
            f"يستخدم عنوان أو رابط اسم نطاق دولياً مُرمّزاً: {unescape(puny[0]['sample_escaped'])}. "
            "تحقّق جيداً من أنه الموقع الحقيقي قبل أن تثق به.", _samples(puny))
    if fancy:
        add("FANCY_UNICODE", "low", 10,
            "The text uses decorated look-alike letters (like 𝐁𝐎𝐋𝐃 or ｗｉｄｅ letters) to hide words from filters.",
            "يستخدم النص أحرفاً مزخرفة مشابهة لإخفاء الكلمات عن أنظمة الفلترة.", _samples(fancy))


def run_email_rules(parsed: ParsedEmail, auth: AuthReport | None, *, unicode_findings: list[dict[str, Any]] | None,
                    link_results: list[dict[str, Any]] | None, campaign_matches: list[dict[str, Any]] | None,
                    user_model: dict[str, Any] | None, sender_age_hours: float | None = None,
                    phone_numbers: list[Any] | None = None, sender_mx: str | None = None) -> EmailRuleResult:
    """Score one email. Pure and offline (threat_feeds.lookup is an in-memory lookup).

    phone_numbers = phone_intel.PhoneInfo of the numbers in the body / tel: links; sender_mx = "found",
    "none" (the sender domain has no mail server at all) or None (not looked up / lookup failed)."""
    auth = auth or AuthReport.not_checked()
    findings = unicode_findings or []
    links = link_results or []
    campaigns = campaign_matches or []
    flags: list[EmailFlag] = []

    def add(code: str, severity: str, points: int, en: str, ar: str, evidence: str | None = None) -> None:
        if any(f.code == code for f in flags):
            return
        strength = "strong" if code in STRONG_CODES else "weak" if code in WEAK_CODES else "info"
        flags.append(EmailFlag(code, severity, points if strength != "info" else 0, en, ar,
                               strength=strength, evidence=(evidence or None) and evidence[:300]))

    # -- who sent it -----------------------------------------------------------------
    from_dom = _domain_of(parsed.from_)
    from_rd = regdom(from_dom)
    from_free = from_rd in FREEMAIL
    from_lex = _lex(from_dom)
    is_official = bool(from_lex and from_lex.is_whitelisted and not from_free)
    official_entity = from_lex.impersonated if is_official and from_lex else None
    rank = popularity_rank(from_rd) if from_rd else None
    trusted = is_official or (bool(rank) and rank <= 10_000 and not from_free)
    dmarc_pass = auth.dmarc.result == "pass"
    # ARC: anyone can build a VALID seal for any mail, so a pass counts only when the citizen's own provider
    # vouches for it (email_auth sets arc.trusted). Even then it only excuses weak forwarding side effects,
    # and never a DMARC failure that the trusted provider itself reported.
    arc_trusted = auth.arc.result == "pass" and bool(getattr(auth.arc, "trusted", False))
    provider_dmarc_fail = auth.dmarc.result == "fail" and auth.dmarc.source == "auth_results"
    arc_vouch = arc_trusted and not provider_dmarc_fail
    is_list = bool(parsed.list_id) or arc_trusted
    # Delivered mail always carries Received headers (every server adds one). A source without any is a
    # draft, a template or an export: nothing in it can show where a real copy came from.
    delivered = bool(parsed.headers_all("Received"))
    precedence = (parsed.header("Precedence") or "").strip().lower()
    is_bulk = is_list or bool(parsed.header("List-Unsubscribe")) or precedence in ("bulk", "list", "junk")
    display = deconfuse(parsed.from_.display_name if parsed.from_ else "")
    subject = deconfuse(parsed.subject or "")
    body = deconfuse(email_text(parsed))
    content = f"{subject}\n{body}"
    via_form = bool(VIA_RE.search(display))
    forwarded = bool(FORWARDED_RE.match(subject))

    # -- brand claims -------------------------------------------------------------------
    ent_display = (_entity_in_text(display) or short_brand_claim(display, f"{display}\n{subject}\n{body[:3000]}")
                   or common_brand_claim(display) if display else None)
    ent_subject = (subject_brand_claim(subject) or short_brand_claim(subject, subject)
                   if subject and not forwarded and not ABOUT_SCAM_RE.search(subject) else None)
    claimed: Entity | None = None
    for ent in (ent_display, ent_subject):
        if ent and not (from_dom and sender_is_brand(ent, from_dom)):
            claimed = claimed or ent

    if ent_display and from_dom and not via_form and not sender_is_brand(ent_display, from_dom):
        add("DISPLAY_NAME_BRAND_SPOOF", "high", 35,
            f"The sender calls itself \"{parsed.from_.display_name[:60]}\" but the email was not sent from an "
            f"address that belongs to {ent_display.name_en}.",
            f"يسمي المرسل نفسه \"{parsed.from_.display_name[:60]}\" لكن الرسالة لم تُرسل من عنوان تابع لـ"
            f"{ent_display.name_ar}.",
            f"display name \"{parsed.from_.display_name[:60]}\", from domain {from_dom}")
    brand_any = claimed
    if brand_any and from_free:
        add("FREEMAIL_BRAND_SENDER", "high", 35,
            f"A message claiming to be from {brand_any.name_en} was sent from a free email account ({from_rd}). "
            "Real companies use their own email domain.",
            f"رسالة تدّعي أنها من {brand_any.name_ar} أُرسلت من حساب بريد مجاني ({from_rd}). "
            "الشركات الحقيقية تستخدم نطاق بريدها الخاص.", parsed.from_.address)

    # Look-alike sender / reply-to domains (paypa1-security.com, adcb-secure.test)
    rt_dom = _domain_of(parsed.reply_to)
    for dom, label_en, label_ar in ((from_dom, "sender's", "المرسل"), (rt_dom, "reply-to", "الرد")):
        if not dom:
            continue
        lex = from_lex if dom == from_dom else _lex(dom)
        if not lex or lex.is_whitelisted or (lex.impersonated and sender_is_brand(lex.impersonated, dom)):
            continue
        r = popularity_rank(lex.registered_domain)
        if r and r <= 10_000:
            continue
        hits = [f for f in lex.flags if f.code in STRONG_LEXICAL and f.code != "PUNYCODE"]
        if hits:
            if lex.impersonated and not claimed:
                claimed = lex.impersonated
            add("SENDER_LOOKALIKE", "critical", 50,
                f"The {label_en} address ({lex.unicode_host}) imitates a real brand: {hits[0].en}",
                f"عنوان {label_ar} ({lex.unicode_host}) يقلّد علامة تجارية حقيقية: {hits[0].ar}",
                f"{dom}: {', '.join(f.code for f in hits)}")
            break

    # Display name hides another address / domain: "service@paypal.com" <x@evil.test>
    if display and from_dom and not via_form:
        shown = [m.group(1) for m in EMAIL_IN_TEXT.finditer(display)]
        shown += [m.group(1) for m in DOMAIN_IN_TEXT.finditer(EMAIL_IN_TEXT.sub(" ", display))]
        for d in shown:
            ext = _EXTRACT(d.lower())
            if ext.domain and ext.suffix and not same_owner(d.lower(), from_dom):
                add("DISPLAY_NAME_ADDRESS_SPOOF", "high", 40,
                    f"The sender's name shows the address \"{d}\", but the email really came from {from_dom}.",
                    f"يُظهر اسم المرسل العنوان \"{d}\"، لكن الرسالة جاءت فعلياً من {from_dom}.",
                    f"display name \"{parsed.from_.display_name[:60]}\" vs {from_dom}")
                break

    if parsed.reply_to and rt_dom and from_rd and regdom(rt_dom) != from_rd and not same_owner(rt_dom, from_dom):
        if claimed and is_freemail(rt_dom):
            add("REPLY_TO_FREEMAIL_BRAND", "high", 25,
                f"Replies to this \"{claimed.name_en}\" message go to a free email account ({parsed.reply_to.address}).",
                f"الردود على هذه الرسالة المنسوبة إلى {claimed.name_ar} تذهب إلى حساب بريد مجاني ({parsed.reply_to.address}).",
                parsed.reply_to.address)
        if not is_list:
            add("REPLY_TO_MISMATCH", "low", 10,
                f"Your reply would go to a different address ({parsed.reply_to.address}) than the sender.",
                f"سيذهب ردّك إلى عنوان مختلف ({parsed.reply_to.address}) عن عنوان المرسل.",
                f"{from_rd} -> {regdom(rt_dom)}")

    rp_dom = _domain_of(parsed.return_path)
    if (rp_dom and from_rd and regdom(rp_dom) != from_rd and not is_list and not dmarc_pass
            and regdom(rp_dom) not in ESP_BOUNCE_DOMAINS and not same_owner(rp_dom, from_dom)):
        add("RETURN_PATH_MISMATCH", "low", 5,
            f"The technical sender ({regdom(rp_dom)}) differs from the visible sender ({from_rd}).",
            f"المرسل التقني ({regdom(rp_dom)}) يختلف عن المرسل الظاهر ({from_rd}).", f"{rp_dom} vs {from_dom}")

    if sender_age_hours is not None and sender_age_hours < 24 * 30 and not is_official and not trusted:
        days = max(0, int(sender_age_hours // 24))
        add("SENDER_NEW_DOMAIN", "high", 30,
            f"The sender's domain {from_rd} was created only {days} day(s) ago. Scammers use brand-new domains.",
            f"تم إنشاء نطاق المرسل {from_rd} قبل {days} يوم فقط. المحتالون يستخدمون نطاقات جديدة تماماً.",
            f"{from_rd}: {round(sender_age_hours)} h old")

    # An exact official address (adpolice.gov.ae, paypal.com ...) is only proof when the mail passed
    # an aligned check: anyone can type any From address, and forged Authentication-Results headers
    # are ignored by email_auth. Not for pasted visible text (no headers) or ARC-vouched forwards.
    aligned_pass = (dmarc_pass
                    or any(d.result == "pass" and d.aligned for d in auth.dkim)
                    or (auth.spf.result == "pass" and bool(auth.dmarc.alignment.get("spf"))))
    # A List-Id header alone is no proof (anyone can type one); a list forward must carry an ARC pass that
    # the citizen's own provider vouches for. A source that was never delivered (no Received header: a
    # draft or exported template) proves nothing either way: it gets an info note instead.
    if is_official and parsed.has_headers and not aligned_pass and not arc_vouch and delivered:
        if official_entity and not claimed:
            claimed = official_entity
        add("OFFICIAL_SENDER_UNAUTHENTICATED", "high", 40,
            f"This email claims to come from an official address ({from_rd}), but it did not pass the checks "
            "that prove it really came from there. Anyone can fake the sender address.",
            f"تدّعي هذه الرسالة أنها صادرة من عنوان رسمي ({from_rd})، لكنها لم تجتز الفحوصات التي تثبت أنها "
            "جاءت منه فعلاً. يمكن لأي شخص تزوير عنوان المرسل.",
            f"from {from_dom}: spf={auth.spf.result} dmarc={auth.dmarc.result} "
            f"dkim={','.join(d.result for d in auth.dkim) or 'none'}")

    # -- authentication (SPF / DKIM / DMARC / ARC) -------------------------------------------------
    if parsed.has_headers and not delivered:
        add("HEADERS_NOT_AVAILABLE", "info", 0,
            "This copy has no delivery headers (for example a draft or an exported template), so SAQR could not "
            "check where it really came from. To check that, paste the original of the email you received "
            "(\"Show original\").",
            "لا تحتوي هذه النسخة على ترويسات التسليم (مثل مسودة أو قالب مُصدَّر)، لذلك لم يتمكن صقر من التحقق من "
            "مصدرها الحقيقي. للتحقق، الصق النسخة الأصلية من الرسالة التي وصلتك («إظهار الأصل»).",
            "no Received header")
    if not parsed.has_headers:
        add("HEADERS_NOT_AVAILABLE", "info", 0,
            "Only the visible text was checked. Paste the full original message (\"Show original\") to also "
            "check where it really came from.",
            "تم فحص النص الظاهر فقط. الصق الرسالة الأصلية كاملة («إظهار الأصل») للتحقق أيضاً من مصدرها الحقيقي.")
    dm = auth.dmarc
    strict_policy = (dm.policy or "").lower() in ("reject", "quarantine")
    if dm.result == "fail" and not (arc_vouch if strict_policy else arc_trusted):
        if strict_policy:
            add("DMARC_FAIL", "high", 35,
                f"The email claims to be from {from_rd or 'a domain'} but failed that domain's anti-forgery check (DMARC).",
                f"تدّعي الرسالة أنها من {from_rd or 'نطاق ما'} لكنها فشلت في فحص مكافحة التزوير الخاص بهذا النطاق (DMARC).",
                f"dmarc=fail p={dm.policy}")
        else:
            add("DMARC_FAIL_P_NONE", "low", 10,
                f"The email failed the sender domain's anti-forgery check (DMARC), although {from_rd or 'the domain'} "
                "does not ask for such mail to be blocked.",
                f"فشلت الرسالة في فحص مكافحة التزوير (DMARC)، مع أن النطاق {from_rd or ''} لا يطلب حظر هذه الرسائل.",
                f"dmarc=fail p={dm.policy or 'none'}")
    spf = auth.spf.result
    # permerror (broken SPF record) / temperror (DNS timeout) say nothing about THIS sender: no flag.
    if spf == "fail":
        add("SPF_FAIL", "medium", 15,
            "The server that sent this email is not allowed to send mail for that address (SPF fail).",
            "الخادم الذي أرسل هذه الرسالة غير مسموح له بالإرسال باسم هذا العنوان (فشل SPF).",
            f"spf={spf} {auth.spf.domain}".strip())
    elif spf == "softfail":
        add("SPF_SOFTFAIL", "low", 5,
            "The sending server is probably not allowed to send for that address (SPF soft fail).",
            "على الأرجح أن خادم الإرسال غير مسموح له بالإرسال باسم هذا العنوان (SPF soft fail).",
            f"spf=softfail {auth.spf.domain}".strip())
    dkim_pass = any(d.result == "pass" for d in auth.dkim)
    dkim_fail = [d for d in auth.dkim if d.result == "fail" and (d.source == "auth_results" or parsed.byte_exact)]
    if dkim_fail and not dkim_pass and not is_list:
        add("DKIM_FAIL", "medium", 15,
            "The email's digital signature (DKIM) is broken: it may have been changed or forged.",
            "التوقيع الرقمي للرسالة (DKIM) غير صالح: ربما تم تعديلها أو تزويرها.",
            ", ".join(f"d={d.domain}" for d in dkim_fail[:3]))
    any_pass = spf == "pass" or dkim_pass or dmarc_pass or arc_trusted
    if (parsed.has_headers and not any_pass and spf not in ("fail", "softfail", "permerror")
            and not parsed.headers_all("DKIM-Signature") and dm.result != "fail"):
        add("NO_AUTHENTICATION", "low", 10,
            "The email has no sender authentication at all (no DKIM signature, no SPF or DMARC pass).",
            "لا تحتوي الرسالة على أي توثيق للمرسل (لا توقيع DKIM ولا نجاح في SPF أو DMARC).")
    if dmarc_pass:
        if from_free:
            add("DMARC_PASS", "info", 0,
                f"The sending address ({from_rd}) is genuine, but anyone can open a free {from_rd} account.",
                f"عنوان الإرسال ({from_rd}) حقيقي، لكن أي شخص يستطيع إنشاء حساب مجاني على {from_rd}.",
                f"dmarc=pass header.from={from_rd}")
        else:
            add("DMARC_PASS", "info", 0,
                f"The email really comes from {from_rd} (it passed the domain's anti-forgery check).",
                f"الرسالة صادرة فعلاً من {from_rd} (نجحت في فحص مكافحة التزوير الخاص بالنطاق).",
                f"dmarc=pass header.from={from_rd}")
    if arc_trusted:
        add("ARC_PASS", "info", 0, "A mail server that forwarded this email vouches that it passed checks (ARC).",
            "خادم البريد الذي أعاد توجيه هذه الرسالة يؤكد أنها اجتازت الفحوصات (ARC).")
    if is_bulk:
        add("BULK_SENDER", "info", 0, "This looks like a newsletter or mailing-list message.",
            "تبدو هذه رسالة نشرة بريدية أو قائمة مراسلات.", parsed.list_id)
    if is_official and dmarc_pass:
        name_en = official_entity.name_en if official_entity else from_rd
        name_ar = official_entity.name_ar if official_entity else from_rd
        add("OFFICIAL_SENDER", "info", 0, f"Sent from an official address of {name_en} ({from_rd}).",
            f"أُرسلت من عنوان رسمي تابع لـ{name_ar} ({from_rd}).")

    # -- Unicode tricks --------------------------------------------------------------------------
    _unicode_flags(findings, add)
    styled = styled_brand(findings)
    if styled and not (from_dom and sender_is_brand(styled[0], from_dom) and aligned_pass):
        ent_s, shown = styled
        add("DISPLAY_NAME_CONFUSABLE", "critical", 65,
            f"The text writes the name \"{shown}\" ({ent_s.name_en}) in decorated look-alike letters (like 𝐁𝐎𝐋𝐃 or "
            "ｗｉｄｅ letters). Real companies never do this; scammers do it to slip past filters.",
            f"يكتب النص اسم \"{shown}\" ({ent_s.name_ar}) بأحرف مزخرفة مشابهة. الشركات الحقيقية لا تفعل ذلك؛ "
            "المحتالون يفعلونه لتجاوز أنظمة الحماية.",
            _samples([f for f in findings if f["kind"] == "fancy"]))
        claimed = claimed or ent_s

    # -- links ------------------------------------------------------------------------------------
    max_link = 0
    hi = [l for l in links if l.get("verdict") == "HIGH-RISK SCAM"]
    sus = [l for l in links if l.get("verdict") == "SUSPICIOUS"]
    for l in links:
        if isinstance(l.get("risk_score"), int):
            max_link = max(max_link, l["risk_score"])
    feed_hits = [(l["domain"], l.get("feed") or threat_feeds.lookup(l["domain"]))
                 for l in links if l.get("domain")]
    feed_hits = [(d, f) for d, f in feed_hits if f]
    if feed_hits:
        add("KNOWN_PHISHING_LINK", "critical", 70,
            f"A link in this email goes to {feed_hits[0][0]}, a site listed as active phishing by global threat intelligence.",
            f"يؤدي رابط في هذه الرسالة إلى {feed_hits[0][0]}، وهو موقع مُدرج كموقع تصيّد نشط في قوائم استخبارات التهديدات العالمية.",
            ", ".join(f"{d} ({f})" for d, f in feed_hits[:3]))
    if hi:
        add("LINK_HIGH_RISK", "critical", 65,
            f"A website linked in this email ({hi[0]['domain']}) was scanned by SAQR and is a scam.",
            f"تم فحص موقع مرتبط في هذه الرسالة ({hi[0]['domain']}) وتبيّن أنه احتيالي.",
            ", ".join(f"{l['domain']} ({l['verdict']} {l.get('risk_score')})" for l in hi[:3]))
    if sus:
        add("LINK_SUSPICIOUS", "medium", 30,
            f"A website linked in this email ({sus[0]['domain']}) was scanned and looks suspicious.",
            f"تم فحص موقع مرتبط في هذه الرسالة ({sus[0]['domain']}) ويبدو مشبوهاً.",
            ", ".join(f"{l['domain']} ({l['verdict']} {l.get('risk_score')})" for l in sus[:3]))
    mism = [l for l in links if l.get("text_mismatch")]
    if mism:
        l0 = mism[0]
        shown = (l0.get("display_text") or "")[:80]
        add("LINK_TEXT_MISMATCH", "high", 30,
            f"A link shows \"{shown}\" but actually opens {l0['domain']}.",
            f"يظهر الرابط على أنه \"{shown}\" لكنه يفتح فعلياً الموقع {l0['domain']}.",
            "; ".join(f"text {(l.get('display_text') or '')[:60]} -> href {l['domain']}" for l in mism[:3]))

    # -- attachments ------------------------------------------------------------------------------
    danger, archive = [], []
    for a in parsed.attachments:
        kind, reason = attachment_risk(a.name)
        if kind == "dangerous":
            danger.append(f"{a.name[:80]} ({reason})")
        elif kind == "archive":
            archive.append(a.name[:80])
    if danger:
        add("DANGEROUS_ATTACHMENT", "critical", 50,
            "The email has an attachment that can run a program or open a fake login page on your device. Do not open it.",
            "تحتوي الرسالة على مرفق يمكنه تشغيل برنامج أو فتح صفحة دخول مزيفة على جهازك. لا تفتحه.", "; ".join(danger[:3]))
    if archive:
        add("ATTACHMENT_ARCHIVE", "low", 5, "The email has a compressed (zip) attachment, often used to hide malware.",
            "تحتوي الرسالة على مرفق مضغوط (zip)، وغالباً ما يُستخدم لإخفاء البرامج الضارة.", "; ".join(archive[:3]))

    # -- campaigns --------------------------------------------------------------------------------
    for c in campaigns:
        matched = ", ".join(str(x) for x in (c.get("matched") or [])[:5])
        if c.get("match") == "ioc":
            add("CAMPAIGN_IOC_MATCH", "critical", int(c.get("points") or 65),
                f"This email uses an address or website from a known scam campaign: \"{c.get('title_en', '')}\".",
                f"تستخدم هذه الرسالة عنواناً أو موقعاً من حملة احتيال معروفة: «{c.get('title_ar') or c.get('title_en', '')}».",
                f"{c.get('id')}: {matched}")
    for c in campaigns:
        if c.get("match") == "lure":
            add("CAMPAIGN_LURE_MATCH", "medium", int(c.get("points") or 20),
                f"The wording matches a known scam campaign: \"{c.get('title_en', '')}\".",
                f"تتطابق صياغة الرسالة مع حملة احتيال معروفة: «{c.get('title_ar') or c.get('title_en', '')}».",
                f"{c.get('id')}: {matched}")

    # -- content ---------------------------------------------------------------------------------
    creds = _matches(CREDENTIAL_RE, content)
    if creds:
        add("CREDENTIAL_REQUEST", "medium", 15, "The email asks you to sign in or give your password, codes or card details.",
            "تطلب الرسالة تسجيل الدخول أو إدخال كلمة المرور أو الرموز أو بيانات البطاقة.", ", ".join(creds))
    pays = _matches(PAYMENT_RE, content)
    if pays:
        add("PAYMENT_REQUEST", "medium", 10, "The email asks you to pay a fee or send money.",
            "تطلب الرسالة دفع رسوم أو تحويل أموال.", ", ".join(pays))
    urg = sorted({m.group(0).lower() for m in URGENCY.finditer(content[:60_000])})[:4]
    if urg:
        add("URGENCY_LANGUAGE", "low", 10, "It pressures you to act fast (deadlines, threats to block or suspend).",
            "تضغط عليك للتصرف بسرعة (مهل زمنية أو تهديد بالإيقاف أو الحظر).", "; ".join(urg))
    ent_body = _entity_in_text(content[:60_000]) if content.strip() else None
    mention = claimed or ent_body
    if mention and not (from_dom and sender_is_brand(mention, from_dom)):
        add("BRAND_MENTION", "low", 10, f"The email talks about {mention.name_en}.",
            f"تتحدث الرسالة عن {mention.name_ar}.", mention.name_en)

    # -- call-back numbers (only next to a claimed UAE institution) --------------------------------
    if claimed and phone_numbers:
        from .maps_sentinel import classify_phone
        from .phone_intel import mask

        for info in phone_numbers[:5]:
            status, _ = classify_phone(info, claimed)
            if status == "mobile_for_institution":
                add("CALLBACK_MOBILE_FOR_INSTITUTION", "high", 35,
                    f"The email asks you to contact {claimed.name_en} on a personal mobile number. Institutions "
                    "never use personal mobiles.",
                    f"تطلب الرسالة التواصل مع {claimed.name_ar} على رقم هاتف متحرك شخصي. الجهات الرسمية لا تستخدم "
                    "أرقاماً شخصية.", mask(info))
            elif status == "foreign_for_institution":
                add("CALLBACK_FOREIGN_FOR_INSTITUTION", "high", 35,
                    f"The email gives a foreign phone number ({info.region or 'abroad'}) for {claimed.name_en}, a UAE "
                    "institution that only uses UAE numbers.",
                    f"تذكر الرسالة رقم هاتف أجنبياً ({info.region or 'خارج الدولة'}) باسم {claimed.name_ar}، وهي جهة "
                    "إماراتية تستخدم أرقاماً إماراتية فقط.", mask(info))

    # -- sender domain has no mail server --------------------------------------------------------------
    if sender_mx == "none" and from_rd and not from_free and not is_official and not trusted:
        add("SENDER_NO_MX", "low", 10,
            f"The sender's domain ({from_rd}) has no mail server: replies cannot reach it, which is common for "
            "throw-away scam domains.",
            f"نطاق المرسل ({from_rd}) لا يملك خادم بريد: لا يمكن أن تصل الردود إليه، وهذا شائع في نطاقات الاحتيال "
            "المؤقتة.", f"{from_rd}: no MX")

    # -- personal model ----------------------------------------------------------------------------
    um = user_model or {}
    p = um.get("p_scam")
    if um.get("available") and isinstance(p, (int, float)):
        if p >= 0.9:
            add("USER_MODEL_SCAM", "medium", 15, "It looks like emails you marked as scams before.",
                "تشبه رسائل سبق أن صنّفتها كاحتيال.", f"p_scam={p:.2f}")
        elif p <= 0.1:
            add("USER_MODEL_TRUSTED", "info", 0, "It looks like emails you marked as safe before.",
                "تشبه رسائل سبق أن صنّفتها كآمنة.", f"p_scam={p:.2f}")

    # -- score ---------------------------------------------------------------------------------------
    rule_codes = sorted({f.code for f in flags})
    strong = [f for f in flags if f.strength == "strong" and f.points > 0]
    # The personal model is a weak signal: alone it changes nothing. With a scam-typical request the rules
    # also saw (money, credentials, campaign wording, failed checks) it can make an untrusted sender's mail
    # SUSPICIOUS — capped at 64, so it never makes HIGH-RISK on its own.
    personal = (not strong and not trusted and (p or 0) >= MODEL_FLOOR_P
                and any(f.code == "USER_MODEL_SCAM" for f in flags)
                and any(f.code in MODEL_CORROBORATION for f in flags))
    if not strong and not personal:  # weak signals alone are normal in real mail: keep them as notes, 0 points
        flags = [EmailFlag(f.code, "info", 0, f.en, f.ar, strength=f.strength, evidence=f.evidence)
                 if f.strength == "weak" else f for f in flags]
    total = sum(f.points for f in flags if f.strength in ("strong", "weak"))
    score = min(100, max(total, max_link))
    if personal:
        score = min(64, max(30, score))
    codes = {f.code for f in flags if f.points > 0}
    if codes & BRAND_CLAIM and (codes & {"DMARC_FAIL", "CREDENTIAL_REQUEST", "PAYMENT_REQUEST"} or max_link >= 30):
        score = max(score, 70)
    capped = False
    uncontradicted = dmarc_pass and trusted and not (codes & CAP_BLOCKERS) and max_link < 30
    if uncontradicted and score > 20:
        score, capped = 20, True
    entity = claimed if strong else None
    return EmailRuleResult(score, verdict_for(score), entity, flags, [], official_entity=official_entity,
                           is_official_sender=is_official, trusted_sender=trusted, is_list=is_list, is_bulk=is_bulk,
                           capped=capped, verified_official=uncontradicted and is_official and score < 30,
                           max_link_score=max_link, rule_codes=rule_codes)


# ---------------------------------------------------------------------------
# LLM blend + citizen explanations
# ---------------------------------------------------------------------------
def _lv(llm: Any, key: str, default: Any = None) -> Any:
    if llm is None:
        return default
    if isinstance(llm, dict):
        return llm.get(key, default)
    return getattr(llm, key, default)


def blend_email(rr: EmailRuleResult, llm: Any) -> int:
    """Combine the rules score with an LLM verdict (dict or ai_inspector.LLMVerdict).

    * The rules score is always the floor: a "SAFE" LLM never lowers strong evidence.
    * A confident (>= 0.7) LLM scam verdict next to at least one strong flag escalates:
      0.25 * rules + 0.75 * LLM.
    * Without strong evidence a confident LLM can raise the mail to SUSPICIOUS at most (64), never
      to HIGH-RISK. Authenticated official mail that the rules capped at 20 stays capped.
    """
    if llm is None:
        return rr.score
    verdict = _lv(llm, "verdict")
    try:
        risk = max(0, min(100, int(float(_lv(llm, "risk_score", 0)))))
        conf = float(_lv(llm, "confidence", 0.5))
    except (TypeError, ValueError):
        return rr.score
    if verdict not in ("SUSPICIOUS", "HIGH-RISK SCAM") or conf < 0.7 or rr.capped:
        return rr.score  # (an authenticated official sender is never escalated by the AI alone)
    if rr.strong_present:
        return min(100, max(rr.score, round(0.25 * rr.score + 0.75 * risk)))
    return max(rr.score, min(64, round(0.5 * rr.score + 0.5 * risk)))


def template_explanations(rr: EmailRuleResult, score: int | None = None) -> tuple[str, str]:
    """Plain-language English + Arabic explanation built from the flags (no LLM needed)."""
    score = rr.score if score is None else score
    verdict = verdict_for(score)
    ent = rr.entity
    tail_en = "Never share OTP codes, passwords or card details by email. Report fraud to Abu Dhabi Police (Aman 8002626)."
    tail_ar = "لا تشارك أبداً رموز التحقق أو كلمات المرور أو بيانات البطاقة عبر البريد الإلكتروني. أبلغ شرطة أبوظبي عن الاحتيال (أمان 8002626)."
    if verdict == "SAFE":
        if rr.is_official_sender and any(f.code == "OFFICIAL_SENDER" for f in rr.flags):
            o = rr.official_entity
            name_en = o.name_en if o else "the sender"
            name_ar = o.name_ar if o else "المرسل"
            return (f"This email really comes from {name_en} and passed the anti-forgery checks. No warning signs "
                    f"were found. {tail_en}",
                    f"هذه الرسالة صادرة فعلاً من {name_ar} واجتازت فحوصات مكافحة التزوير. لم يتم العثور على علامات "
                    f"تحذيرية. {tail_ar}")
        return ("No major red flags were found in this email. Still, do not open links or attachments you did not "
                f"expect. {tail_en}",
                "لم يتم العثور على مؤشرات خطر كبيرة في هذه الرسالة. ومع ذلك، لا تفتح روابط أو مرفقات لم تكن تتوقعها. "
                f"{tail_ar}")
    if verdict == "HIGH-RISK SCAM":
        if ent:
            head_en = f"DANGER — This email is very likely a scam pretending to be {ent.name_en}. Do NOT click its links, open its attachments or reply."
            head_ar = f"خطر — من المرجح جداً أن هذه الرسالة احتيالية تنتحل صفة {ent.name_ar}. لا تضغط على روابطها ولا تفتح مرفقاتها ولا ترد عليها."
        else:
            head_en = "DANGER — This email is very likely a scam. Do NOT click its links, open its attachments or reply."
            head_ar = "خطر — من المرجح جداً أن هذه الرسالة احتيالية. لا تضغط على روابطها ولا تفتح مرفقاتها ولا ترد عليها."
    else:
        head_en = "CAUTION — This email shows warning signs of fraud. Do not click links or enter any details until you are sure."
        head_ar = "تنبيه — تُظهر هذه الرسالة علامات تحذيرية على الاحتيال. لا تضغط على الروابط ولا تُدخل أي بيانات حتى تتأكد."
        if ent:
            head_en += f" It may be pretending to be {ent.name_en}."
            head_ar += f" قد تكون منتحلة لصفة {ent.name_ar}."
    top = sorted((f for f in rr.flags if f.points > 0), key=lambda f: -f.points)[:4]
    bullets_en = "\n".join(f"• {f.en}" for f in top)
    bullets_ar = "\n".join(f"• {f.ar}" for f in top)
    if ent:
        tail_en = (f"If you are worried, contact {ent.name_en} yourself through its official website "
                   f"({', '.join(ent.domains[:3])}) — not through this email. " + tail_en)
        tail_ar = (f"إذا كنت قلقاً فتواصل مع {ent.name_ar} بنفسك عبر موقعه الرسمي ({'، '.join(ent.domains[:3])}) "
                   "وليس عبر هذه الرسالة. " + tail_ar)
    return (f"{head_en}\n\nRed flags:\n{bullets_en}\n\n{tail_en}", f"{head_ar}\n\nعلامات الخطر:\n{bullets_ar}\n\n{tail_ar}")
