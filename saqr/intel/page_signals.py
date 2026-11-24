"""Page-content evidence for phishing that hides on platforms and hacked sites (HTTP-only path too).

The address of a page on a website builder or a hacked old site looks ordinary, so the URL model and
the look-alike rules cannot see it. What gives it away is the page itself:

* A security provider already shows its own phishing warning instead of the page (Cloudflare's
  "Suspected Phishing" interstitial, a link shortener that disabled the link for abuse).
* A website-builder / form-service form (Weebly formSubmit, Formspree, Google Apps Script, Telegram
  bot ...) that asks for a password, card number, CVV, OTP or PIN. Legitimate log-ins post to the
  site's own back end, never to a contact-form service.
* The page title claims a well-known brand's log-in or account page, on a user-content platform or
  next to a password / card form, on a domain that is not the brand's.

Each of these is a STRONG signal in ai_inspector.run_rules; ordinary page words ("sign in", a brand
mentioned in passing, "verify") remain weak. Measured on the live sample: docs/MODEL_CARD.md.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any
from urllib.parse import urlsplit

from dataclasses import replace

from .domain_intel import LexicalReport, RedFlag, analyze_lexical
from .threat_feeds import on_free_hosting

# Shared hosting where anyone can publish a page, but which is not in url_features.FREE_HOSTING (the
# trained model's feature list must not change without retraining). Seen in the live phishing sample.
USER_CONTENT_HOSTS = (
    "weeblysite.com", "gitbook.io", "cloudfront.net", "storage.googleapis.com", "firebasestorage.googleapis.com",
    "backblazeb2.com", "qrcodechimp.page", "hostingersite.com", "edgeone.dev", "edgeone.app",
    "s3.amazonaws.com", "wixstudio.com", "webcindario.com", "ukit.me", "tilda.ws", "mystrikingly.com",
)

PROVIDER_WARNING = re.compile(
    r"suspected phishing\s*\|\s*cloudflare|warning\s+suspected phishing\s+this (web)?site has been reported"
    r"|this link has been (flagged|disabled|blocked) (as|for) (possibly )?(malicious|phishing|abuse|spam)", re.I)
SHORTLINK_TERMINATED = re.compile(r"\burl terminated\b|link (has been )?(disabled|removed|terminated) for (abuse|spam|"
                                  r"violat)|this link has been disabled", re.I)
FORM_SERVICES = re.compile(
    r"weebly\.com/weebly/apps/formsubmit|formspree\.io|formsubmit\.co|getform\.io|submit-form\.com|web3forms\.com"
    r"|api\.telegram\.org/bot|script\.google\.com/macros|docs\.google\.com/forms/[^\s\"']*formresponse|jotform\.com"
    r"|usebasin\.com|formcarry\.com|123formbuilder\.com|formbold\.com|staticforms\.xyz|getsimpleform\.com", re.I)
CREDENTIAL_FIELDS = {"PASSWORD", "OTP", "CARD_NUMBER", "CVV", "ATM_PIN", "UAE_PASS"}
LOGIN_WORDS = re.compile(
    r"\blog\s?-?in\b|\bsign\s?-?in\b|\blogon\b|\bverify\b|\bverification\b|\baccount\b|\bwallet\b|\bsecure\b"
    r"|\bupdate\b|\bunlock\b|\bsuspended\b|\bconnexion\b|\banmelden\b|\biniciar sesi[oó]n\b|\bentrar\b"
    r"|تسجيل الدخول|تحقق|حسابك|تحديث البيانات", re.I)


# Hosted payment pages (UAE + global gateways). Every merchant's checkout shares these hosts, so a page
# there is judged by its content, never trusted outright, and its host is never published to the DNS
# blocklist (that would block every merchant's payments). Card fields and the merchant's own brand are
# the normal content of such a page, not evidence. ngenius-payments.com = Network International's
# N-Genius hosted pay page (network.ae's gateway).
PAYMENT_GATEWAY_HOSTS = (
    "network.ae", "ngenius-payments.com", "payfort.com", "telr.com", "magnati.com", "noonpayments.com",
    "paytabs.com", "checkout.com", "stripe.com",
)


def user_content(host: str) -> bool:
    """Anyone can publish a page on this host (free hosting, website builders, cloud buckets)."""
    h = (host or "").lower().rstrip(".")
    return on_free_hosting(h) or any(h == p or h.endswith("." + p) for p in USER_CONTENT_HOSTS)


def payment_gateway(host: str) -> bool:
    """A payment gateway's hosted page: any merchant's checkout (see PAYMENT_GATEWAY_HOSTS)."""
    h = (host or "").lower().rstrip(".")
    return any(h == p or h.endswith("." + p) for p in PAYMENT_GATEWAY_HOSTS)


def shared_platform(host: str) -> bool:
    """Pages of many unrelated owners share this host: judged by content, never trusted outright."""
    return user_content(host) or payment_gateway(host)


def unofficial_user_content(lex: LexicalReport) -> LexicalReport:
    """A page that anyone can publish on an official company's platform (a Google Cloud Storage bucket,
    Google Sites, SharePoint ...) is not that company's own site: it must be judged, not whitelisted."""
    if lex.is_whitelisted and shared_platform(lex.host):
        return replace(lex, is_whitelisted=False, official_match=None, impersonated=None)
    return lex


def lexical(url: str) -> LexicalReport:
    """analyze_lexical + unofficial_user_content: the address report every verdict path should use."""
    return unofficial_user_content(analyze_lexical(url))


def _platform_of(host: str) -> str | None:
    from .url_features import FREE_HOSTING

    h = (host or "").lower().rstrip(".")
    return next((p for p in (*FREE_HOSTING, *USER_CONTENT_HOSTS) if h == p or h.endswith("." + p)), None)


def platform_named_only(lex: LexicalReport) -> bool:
    """The impersonated brand is only named by the hosting platform itself (Microsoft's
    tenant.sharepoint.com, Google's sites.google.com), not by the customer's own part of the host."""
    ent = lex.impersonated
    platform = _platform_of(lex.host)
    if ent is None or platform is None:
        return False
    own = lex.host[: -len(platform)].rstrip(".")
    words = {ent.name_en.lower(), *(k.lower() for k in ent.keywords), *(k.lower() for k in ent.common_keywords)}
    return not any(w and len(w) >= 3 and w in own for w in words)


def fold(text: str) -> str:
    """Strip accents so "Róbinhood" / "Ⅿetamask" style titles still name the brand."""
    norm = unicodedata.normalize("NFKD", text or "")
    return "".join(c for c in norm if not unicodedata.combining(c))


def _form_service_actions(page: dict[str, Any]) -> bool:
    actions = " ".join(str(f.get("action") or "") for f in page.get("forms") or [])
    return bool(FORM_SERVICES.search(actions) or FORM_SERVICES.search(page.get("html") or ""))


def page_flags(host: str, page: dict[str, Any] | None, title_brand: Any = None,
               popular: bool = False) -> list[RedFlag]:
    """Strong page evidence (see module doc). title_brand = registry entity named in the page title
    (already checked by the caller not to own this host); popular = Tranco top-100k off user content."""
    page = page or {}
    out: list[RedFlag] = []
    title = page.get("page_title") or ""
    text = page.get("text") or ""
    head = f"{title} {text[:600]}"
    if PROVIDER_WARNING.search(head):
        out.append(RedFlag("PROVIDER_PHISHING_WARNING", "critical", 70,
                           "A security provider (e.g. Cloudflare) already shows its own phishing warning instead of this page.",
                           "يعرض مزوّد أمني (مثل Cloudflare) تحذيره الخاص من التصيّد بدلاً من هذه الصفحة."))
    final_host = (urlsplit(page.get("final_url") or "").hostname or host or "").lower()
    from .url_features import SHORTENER_HOSTS
    if (host in SHORTENER_HOSTS or final_host in SHORTENER_HOSTS) and SHORTLINK_TERMINATED.search(head):
        out.append(RedFlag("SHORTLINK_DISABLED", "high", 45,
                           "The link shortener has disabled this link (usually for spam or phishing reports).",
                           "قام موقع اختصار الروابط بتعطيل هذا الرابط (غالباً بسبب بلاغات احتيال أو رسائل مزعجة)."))
    fields = set(page.get("harvested_fields") or [])
    creds = fields & CREDENTIAL_FIELDS
    if creds and _form_service_actions(page):
        out.append(RedFlag("FORM_SERVICE_CREDENTIALS", "critical", 45,
                           "A website-builder or form-service form asks for a password or card details; real log-ins never work this way.",
                           "نموذج من منصة إنشاء مواقع أو خدمة نماذج يطلب كلمة مرور أو بيانات بطاقة؛ صفحات الدخول الحقيقية لا تعمل بهذه الطريقة."))
    if title_brand is not None:
        loginish = bool(LOGIN_WORDS.search(fold(title)) or LOGIN_WORDS.search(fold(text[:1500])))
        on_platform = user_content(final_host or host)
        if (on_platform and (loginish or creds)) or (creds and LOGIN_WORDS.search(fold(title)) and not popular):
            name = title_brand.name_en
            out.append(RedFlag("BRAND_LOGIN_PAGE", "critical", 25,
                               f"The page presents itself as a {name} sign-in / account page on a website that is not {name}'s.",
                               f"تقدّم الصفحة نفسها كصفحة دخول أو حساب لـ{title_brand.name_ar} على موقع لا يتبع لها."))
    return out
