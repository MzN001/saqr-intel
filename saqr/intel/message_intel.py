"""SMS / WhatsApp message forensics (POST /api/analyze-message): pure, offline rules.

Same principle as ai_inspector.run_rules (websites) and email_rules (email):

* STRONG signals point to fraud on their own: a link SAQR scanned as a scam, a look-alike link, a
  personal UAE mobile or a foreign number used as the sender or call-back number of a message that
  claims to come from a UAE institution, a request to SEND / REPLY WITH an OTP, PIN, CVV, card number or
  UAE PASS code.
* WEAK signals are in real messages every day ("fine", "OTP", "Emirates ID", "pay today", "refund"): they
  add points ONLY next to a strong signal. A genuine bank OTP SMS ("Your OTP is 123456. Never share it.")
  and a genuine TAMM receipt are SAFE.
* An alphanumeric sender id ("ADPolice", "TAMM", a bank's name) can be spoofed, so it is never proof of
  safety; but a message with no link, no call-back number, no credential request and no contradicting
  sender number is SAFE whatever its wording.

Score = min(100, max(sum(strong) + (sum(weak) if any strong else 0), worst linked-site score)); a claimed
institution + a credential request or a scam link => at least 70. Thresholds as everywhere: >= 65
HIGH-RISK SCAM, >= 30 SUSPICIOUS.

This module only reads text and evidence handed to it (link sub-scan verdicts, phone check results);
the orchestration (link scans, storage, AI opinion) lives in saqr/message_pipeline.py.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import page_signals, phone_intel
from .ai_inspector import STRONG_LEXICAL, URGENCY, _entity_in_text, verdict_for
from .domain_intel import _EXTRACT, RedFlag
from .email_rules import NEGATION_RE, ROLE_WORDS, host_of
from .email_unicode import deconfuse, scan_text, unescape
from .maps_sentinel import INSTITUTION_CATEGORIES, is_official_uae, match_entity
from .registry import ENTITIES, Entity

MAX_TEXT = 4000
EXCERPT_CHARS = 300
MAX_LINKS = 10

# ---------------------------------------------------------------------------
# Links
# ---------------------------------------------------------------------------
_EMAIL_ADDR = re.compile(r"[\w.+-]+@(?:[\w-]+\.)+[a-z]{2,24}", re.I)
_URL_IN_TEXT = re.compile(
    r"(?:hxxps?|https?)://(?:\[\.\]|[^\s<>\"'()\[\]])+|(?<![\w@.-])(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,24}(?:/[^\s<>\"']*)?",
    re.I)
_TRAIL = ".,;:!?)\"'»،؛"


def extract_links(text: str) -> list[dict[str, Any]]:
    """Links written in the message: full URLs and bare domains (tamm-pay.info/x), refanged, de-duplicated.

    A bare word.Word with a capital after the dot ("fine.Pay" from two sentences pasted without a space) is
    not a link, and a bare domain needs a real public suffix."""
    t = _EMAIL_ADDR.sub(" ", text or "")
    out: dict[str, dict[str, Any]] = {}
    for m in _URL_IN_TEXT.finditer(t):
        raw = m.group(0).rstrip(_TRAIL)
        url = raw.replace("[.]", ".")
        if re.match(r"^hxxps?://", url, re.I):
            url = "http" + url[4:]
        if not re.match(r"^https?://", url, re.I):
            host_part = url.split("/", 1)[0]
            if re.search(r"\.[A-Z]", host_part) and not host_part.isupper():
                continue
            ext = _EXTRACT(host_part.lower())
            if not ext.domain or not ext.suffix:
                continue
            url = "https://" + url
        host = host_of(url)
        if not host or url in out:
            continue
        out[url] = {"url": url[:2048], "domain": host, "shown": raw[:300]}
        if len(out) >= MAX_LINKS:
            break
    return list(out.values())


def strip_links(text: str) -> str:
    """The text with links and e-mail addresses blanked (phone numbers are looked for in what is left)."""
    t = _EMAIL_ADDR.sub(" ", text or "")
    return _URL_IN_TEXT.sub(lambda m: " " * len(m.group(0)), t)


# ---------------------------------------------------------------------------
# Who the message claims to be from
# ---------------------------------------------------------------------------
# A brand named in a message only counts as the claimed SENDER when the message reads like that brand's
# own notice: the name opens the message ("TAMM: ...", "[ADCB] ...", "Abu Dhabi Police - ..."), the sender
# id is that brand, or the text introduces itself ("this is", "from", "Dear customer", "<brand> team").
# "I paid my Abu Dhabi Police fine today, call me on 050..." is a friend, not the police.
_SELF_INTRO = re.compile(
    r"\b(?:this is|from|on behalf of|regards,?|sincerely,?|dear (?:customer|client|citizen|resident|user|"
    r"cardholder|member|valued customer|sir|madam))\b|عزيزي|عزيزتي|عميلنا|المتعامل|المتعاملين|مع تحيات|من فريق|"
    r"نود إعلامك|نود اعلامك|نحيطكم|نحيطك", re.I)
_OPENING = 48


def _names(ent: Entity) -> list[str]:
    if ent.category == "global":
        n = ent.name_en.lower()
        return [] if n in ent.common_keywords or len(n) < 4 else [n]
    return [n for n in {ent.name_en.lower(), ent.name_ar, *[a.lower() for a in ent.aliases]} if len(n) >= 3]


def _opens_with(text: str, ent: Entity) -> bool:
    head = re.sub(r"^[\W_]+", "", text.lower())[:_OPENING]
    return any(re.match(rf"{re.escape(n)}(?!\w)", head) for n in _names(ent))


def _role_next_to(text: str, ent: Entity) -> bool:
    low = text.lower()
    for n in _names(ent):
        for m in re.finditer(rf"(?<!\w){re.escape(n)}(?!\w)", low):
            near = re.findall(r"[^\W_]+", low[max(0, m.start() - 20):m.end() + 24])
            if any(w in ROLE_WORDS for w in near):
                return True
    return False


def sender_entity(sender: str | None) -> Entity | None:
    """The brand an alphanumeric sender id names ("ADPolice", "TAMM", "ADCB"), else None."""
    s = (sender or "").strip()
    if not s or re.fullmatch(r"[+\d\s().-]+", s):
        return None
    ent, score = match_entity(re.sub(r"[_\-.]+", " ", s))
    return ent if ent and score >= 90 else None


def claimed_entity(text: str, sender: str | None) -> tuple[Entity | None, str | None]:
    """(entity, how) the message claims to be from: "sender_id", "opening" or "self_intro"."""
    ent = sender_entity(sender)
    if ent:
        return ent, "sender_id"
    # as a person reads it: "Dubai P\u043eli\u0441\u0435" (Cyrillic look-alike letters) is "Dubai Police"
    text = deconfuse(text or "")
    found = _entity_in_text(text)
    if not found:
        return None, None
    if _opens_with(text, found):
        return found, "opening"
    if _SELF_INTRO.search(text) or _role_next_to(text, found):
        return found, "self_intro"
    return None, None


def lookalike_entity(links: list[dict[str, Any]]) -> Entity | None:
    """The brand a look-alike link in the message imitates (tamm-smart-pay.net -> TAMM)."""
    for l in links:
        if l.get("whitelisted"):
            continue
        try:
            lex = page_signals.lexical(l["url"])
        except ValueError:
            continue
        if lex.impersonated and any(f.code in STRONG_LEXICAL for f in lex.flags):
            return lex.impersonated
    return None


def is_uae_body(ent: Entity | None) -> bool:
    """A UAE government / courier / identity body or bank: they never text from a personal mobile."""
    return bool(ent and ent in ENTITIES and ent.category in INSTITUTION_CATEGORIES)


# ---------------------------------------------------------------------------
# Credential requests ("send us the OTP") vs advice ("never share your OTP") vs delivery ("Your OTP is 1234")
# ---------------------------------------------------------------------------
_SECRET_EN = (r"(?:otp|one[- ]time (?:password|passcode|code|pin)|verification code|security code|activation code|"
              r"pin(?: code| number)?|atm pin|cvv|cvc|cvv2|card (?:number|details|no\.?)|full card details|"
              r"uae ?pass (?:code|pin|password|credentials|login|details)|password|passcode)")
_FILL_EN = r"(?:\s+(?:us|me|back|with|over|the|your|this|that|its|a|an|\d[- ]?digit|six[- ]digit|new|received|it|to us|to me))*"
_HANDOVER_EN = r"(?:send|reply|respond|forward|share|tell|give|provide|text|whatsapp|pass|read(?: out)?)"
_ENTER_EN = r"(?:enter|type|submit|input|key in|fill in|update|confirm|verify)"
_HANDOVER_RE = re.compile(rf"\b{_HANDOVER_EN}\b{_FILL_EN}\s+{_SECRET_EN}\b", re.I)
_ENTER_RE = re.compile(rf"\b{_ENTER_EN}\b{_FILL_EN}\s+{_SECRET_EN}\b", re.I)
# "send me the code" / "forward the code you received" (WhatsApp account take-over): a plain "code" counts
# only with a "to me / to us" or a "you received" next to it, so "share the code SAVE20" stays a promo.
_HANDOVER_CODE_RE = re.compile(
    rf"\b{_HANDOVER_EN}\s+(?:it\s+)?(?:to\s+)?(?:me|us)\b(?:\s+\w+){{0,2}}\s+(?:the\s+|that\s+|this\s+)?code\b|"
    rf"\b{_HANDOVER_EN}\b(?:\s+\w+){{0,2}}\s+code\b[^.\n]{{0,30}}\b(?:you (?:just )?(?:received|got)|sent to (?:you|your))|"
    # "I sent you a code by mistake, can you pass it to me", "reply with the code"
    r"\bcode\b[^.\n]{0,40}\bby mistake\b|\b(?:reply|respond|answer) with (?:the |that |this )?(?:\d[- ]?digit )?code\b|"
    # the same request in French, Hindi / Urdu (Latin script) and Tagalog, as UAE residents receive them
    r"\b(?:communiquer|envoyer|donner|transmettre)\b[^.\n]{0,25}\bcode\b|"
    r"\b(?:otp|code)\b[^.\n]{0,45}\b(?:bhej|bhejo|bhejiye|bata|batao|bataiye|whatsapp kar)|"
    r"\b(?:i-?reply|ibigay|ipadala|i-?send)\b[^.\n]{0,40}\b(?:mpin|otp|pin|code)\b",
    re.I)
_SECRET_AR = (r"(?:كود التحقق|كود التفعيل|رمز التحقق|رمز التحقيق|رمز OTP|الرمز السري|الرقم السري|رمز التفعيل|الرمز المؤقت|كلمة المرور|"
              r"كلمة السر|رقم البطاقة|بيانات البطاقة|رمز CVV|الرمز المكون من|رمز (?:ال)?(?:أمان|امان)|رمز UAE ?PASS)")
_HANDOVER_AR = r"(?:أرسل|ارسل|أرسلي|ارسلي|أرسلوا|ارسلوا|ابعث|إبعث|ابعثي|ابعثلي|رد|ردّ|ردي|شارك|زودنا|زوّدنا|زودني|أخبرنا|اخبرنا|أعطنا|اعطنا|أعطني|اعطني|قل لنا)"
_ENTER_AR = r"(?:أدخل|ادخل|أدخلي|ادخلي|اكتب|حدّث|حدث|قم بتحديث|قم بإدخال|قم بادخال|أكّد|أكد|اكد)"
_FILL_AR = r"(?:\s+(?:لنا|لي|إلينا|الينا|علينا|مع|ب|بـ|على|هنا|الآن|الان|لنا\s+على))*"
# Polite requests use a verbal noun after a request word ("يرجى إرسال رمز التحقق", "الرجاء مشاركة الرقم السري",
# "قم بإرسال ..."). The request word is required: "تم / سيتم إرسال رمز التحقق إلى هاتفك" is a delivery notice.
_REQUEST_AR = r"(?:يرجى|يُرجى|الرجاء|رجاء|نرجو|نرجوك|نرجو منك|يجب|عليك|قم ب|قم بـ|قومي ب)"
_HANDOVER_NOUN_AR = r"(?:إرسال|ارسال|مشاركة|إعطاء|اعطاء|تزويدنا ب|تزويدنا بـ|إخبارنا ب|اخبارنا ب)"
_HANDOVER_AR_RE = re.compile(rf"{_HANDOVER_AR}{_FILL_AR}\s+(?:ب|بـ)?{_SECRET_AR}|{_HANDOVER_AR}\s+(?:لنا|لي)\s+(?:ال)?رمز|"
                             rf"{_REQUEST_AR}\s*{_HANDOVER_NOUN_AR}{_FILL_AR}\s*{_SECRET_AR}")
_ENTER_AR_RE = re.compile(rf"{_ENTER_AR}{_FILL_AR}\s+{_SECRET_AR}")
# A message that itself delivers a one-time code ("Your OTP is 482913", "رمز التحقق: 4829")
_DELIVERY_RE = re.compile(
    r"\b(?:otp|code|passcode|pin|password)\b[^.\n\d]{0,25}\b\d{4,8}\b|\b\d{4,8}\b[^.\n\d]{0,25}\b(?:is your|is the)\b|"
    r"(?:رمز|الرمز|كلمة المرور)[^.\n\d]{0,25}\d{4,8}", re.I)
_SENTENCE = re.compile(r"[.!?\n؟]+")


def delivers_code(text: str) -> bool:
    return bool(_DELIVERY_RE.search((text or "").translate(phone_intel._ARABIC_DIGITS)))  # noqa: SLF001


def credential_requests(text: str, *, enter_counts: bool) -> list[str]:
    """What the message asks you to hand over, from sentences that are not advice ("never share ...").

    Hand-over verbs (send / reply with / share / tell / forward) always count. Enter-type verbs ("enter your
    card details", "update your PIN") count only when `enter_counts` (the message has a link that is not
    an official site): real banks also write "enter this code" and "enter your PIN at the ATM"."""
    found: list[str] = []
    for sent in _SENTENCE.split((text or "")[:MAX_TEXT]):
        if not sent.strip() or NEGATION_RE.search(sent):
            continue
        rxs = [_HANDOVER_RE, _HANDOVER_CODE_RE, _HANDOVER_AR_RE] + ([_ENTER_RE, _ENTER_AR_RE] if enter_counts else [])
        for rx in rxs:
            for m in rx.finditer(sent):
                w = re.sub(r"\s+", " ", m.group(0).strip().lower())[:60]
                if w not in found:
                    found.append(w)
    return found[:4]


# ---------------------------------------------------------------------------
# Weak wording (only counts next to a strong signal)
# ---------------------------------------------------------------------------
_URGENCY_MORE = re.compile(
    r"\b(?:today|tonight|final (?:notice|warning|reminder)|last (?:notice|warning|reminder)|within \d+|urgent(?:ly)?|"
    r"act now|right away|before it is too late|legal action|arrest|court)\b|عاجل|اليوم|آخر إنذار|اخر انذار|إنذار نهائي|"
    r"خلال \d+|إجراء قانوني|اجراء قانوني|القبض|المحكمة", re.I)
_PAYMENT = re.compile(
    r"\b(?:fines?|penalt(?:y|ies)|unpaid|outstanding|overdue|fees?|customs (?:duty|charges?)|pay(?:ment)? (?:now|today|the|your|a)|"
    r"settle|due amount|amount due)\b|\b(?:aed|dhs?)\s?[\d,.]+|[\d,.]+\s?(?:aed|dhs?)\b|غرامة|غرامات|مخالفة|مخالفات|"
    r"رسوم|ادفع|سداد|تسديد|درهم|مبلغ مستحق|المبلغ المستحق", re.I)
_EMIRATES_ID = re.compile(
    r"(?:\bemirates id\b|\beid\b|الهوية الإماراتية|الهوية الاماراتية|بطاقة الهوية)[^.\n]{0,40}"
    r"(?:updat|expir|suspend|block|renew|verif|deactivat|تحديث|منتهي|إيقاف|ايقاف|تعليق|تجديد|تحقق|حظر)|"
    r"(?:updat|expir|suspend|block|renew|verif|deactivat|تحديث|إيقاف|ايقاف|تعليق|تجديد)[^.\n]{0,40}"
    r"(?:\bemirates id\b|\beid\b|الهوية الإماراتية|الهوية الاماراتية|بطاقة الهوية)", re.I)
_PRIZE = re.compile(
    r"\b(?:prize|you(?:'ve| have)? won|winner|congratulations|reward(?:s| points)?|refund|cash ?back|claim (?:your|now)|"
    r"gift|lucky draw|raffle|compensation)\b|ربحت|فزت|جائزة|مبروك|استرداد|مكافأة|مكافآة|مبلغ مسترد|تعويض|سحب", re.I)


# ---------------------------------------------------------------------------
# Scam scripts that need no link (call-back, job, "new number", gift cards, investment)
# ---------------------------------------------------------------------------
# "call / WhatsApp / contact ... <a phone number>" (7+ digits, any formatting)
_CALL_NUMBER = re.compile(
    r"(?:\b(?:call|contact|phone|dial|ring|whatsapp|text|message|reach)\b|اتصل|الاتصال|تواصل|التواصل|واتساب)"
    r"[^.\n]{0,60}?(\+?\(?\d[\d\s().-]{6,18}\d)", re.I)
# the account / card / number / case is in trouble
_ACCOUNT_THREAT = re.compile(
    r"\b(?:blocked|suspended|deactivated|frozen|locked|restricted|disconnected|terminated|has expired|"
    r"will be (?:blocked|suspended|closed|deleted|deactivated|disconnected|cancelled|canceled)|"
    r"(?:been )?charged|unauthori[sz]ed|did not authori[sz]e|was not you|not you\b|suspicious (?:activity|transaction|"
    r"login|sign[- ]?in)|case (?:has been |was |is )?(?:registered|opened|filed)|money laundering|arrest warrant|"
    r"legal action)\b|تم إيقاف|تم ايقاف|تم حظر|تم تعليق|سيتم إيقاف|سيتم ايقاف|سيتم حظر|معاملة مشبوهة|قضية", re.I)
_JOB_OFFER = re.compile(
    r"\b(?:part[- ]?time|remote (?:job|role|work|position|task)|work from home|online (?:job|work|workers?|assessor)|"
    r"flexible (?:online )?job|task role|we are hiring|hiring (?:kami|for)|recruit(?:er|ment)|reviewed your (?:cv|resume|"
    r"profile)|job offer)\b|ghar baithe|kaam\b", re.I)
_EASY_PAY = re.compile(
    r"\b(?:earn|income|paying|pays|salary|kamao|kumita)\b[^.\n]{0,45}\b(?:daily|per day|a day|every day|each day|"
    r"kada araw|roz)\b|\b(?:daily|roz)\b[^.\n]{0,25}\b(?:income|earn|kamao)\b|"
    r"[\d,.]+\s?(?:-|to|–)\s?[\d,.]+\s?(?:aed|dhs?|usd|gbp|php|inr)?\s?(?:per day|a day|daily|kada araw)", re.I)
_UNSOLICITED_JOB = re.compile(
    r"\breviewed your (?:cv|resume|profile)\b[^\n]{0,120}\b(?:job|role|position)\b|"
    r"\b(?:selected|shortlisted) for a (?:remote|part[- ]?time|online)\b", re.I)
_NEW_NUMBER = re.compile(
    r"\b(?:my |a )?new (?:number|phone)\b|\bfriend'?s (?:old )?(?:phone|one)\b|\b(?:broke|broken|smashed|lost|dropped) "
    r"(?:my |mine)|\bphone (?:fell|broke|is broken|got stolen)\b|رقمي الجديد|رقم جديد|تلفوني انكسر|جوالي انكسر", re.I)
_FAMILY = re.compile(r"\b(?:mum|mom|mam|mummy|mommy|dad|daddy|papa|mama|mother|father)\b|ماما|بابا|أمي|امي|يمه|يبه", re.I)
_MONEY_ASK = re.compile(
    r"\b(?:bank transfer|transfer (?:me|some)|send (?:me )?(?:some )?money|lend me|pay (?:a|this|my) bill|need (?:some )?money|"
    r"quick transfer)\b|تحول|تحولين|حوّل|حول لي|حوالة|احتاج فلوس", re.I)
_GIFT_CARDS = re.compile(
    r"\bgift ?cards?\b[^\n]{0,90}\b(?:codes?|numbers?|pins?|photos?|pictures?)\b|"
    r"\b(?:buy|purchase|get)\b[^.\n]{0,40}\b(?:gift ?cards?|itunes cards?|google play cards?|steam cards?)\b", re.I)
_INVESTMENT = re.compile(
    r"\bguaranteed (?:returns?|profits?|income)\b|\b\d{1,3}\s?% (?:daily|weekly|monthly|per (?:day|week|month))\b|"
    r"\b(?:double|triple) your (?:money|investment|capital)\b|\bpre-?ipo\b|\brisk[- ]free (?:investment|profit|returns?)\b|"
    r"أرباح مضمونة|ارباح مضمونة|عائد مضمون", re.I)


def _hits(rx: re.Pattern, text: str, n: int = 3) -> list[str]:
    out: list[str] = []
    for m in rx.finditer(text[:MAX_TEXT]):
        w = m.group(0).strip().lower()[:40]
        if w and w not in out:
            out.append(w)
        if len(out) >= n:
            break
    return out


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
STRONG_CODES = {
    "MSG_SCAM_LINK", "MSG_SUSPICIOUS_LINK", "MSG_LOOKALIKE_LINK", "MSG_CREDENTIAL_REQUEST",
    "SENDER_MOBILE_FOR_INSTITUTION", "SENDER_FOREIGN_FOR_INSTITUTION",
    "CALLBACK_MOBILE_FOR_INSTITUTION", "CALLBACK_FOREIGN_FOR_INSTITUTION", "MSG_PHONE_LINKED_TO_SCAM",
    "MSG_SHORTENER_FOR_INSTITUTION", "MSG_LOOKALIKE_LETTERS",
    "MSG_CALLBACK_PRESSURE", "MSG_JOB_LURE", "MSG_NEW_NUMBER_LURE", "MSG_GIFT_CARD_REQUEST",
    "MSG_INVESTMENT_LURE", "MSG_PRESSURE_UNOFFICIAL_LINK",
}
WEAK_CODES = {
    "MSG_URGENCY", "MSG_PAYMENT_DEMAND", "MSG_EMIRATES_ID_LURE", "MSG_PRIZE_LURE", "MSG_UNOFFICIAL_LINK",
    "MSG_UNOFFICIAL_CALLBACK",
}


@dataclass
class MessageFlag(RedFlag):
    strength: str = "info"
    evidence: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "severity": self.severity, "points": self.points, "strength": self.strength,
                "en": self.en, "ar": self.ar, "evidence": self.evidence}


@dataclass
class MessageRuleResult:
    score: int
    verdict: str
    entity: Entity | None              # the impersonated institution (only when a strong signal exists)
    claimed: Entity | None             # who the message claims to be from (any verdict)
    claimed_how: str | None
    flags: list[MessageFlag] = field(default_factory=list)
    credential_requests: list[str] = field(default_factory=list)
    verified_official: bool = False
    actionable: bool = False           # link / number / credential request / sender number: something to act on
    max_link_score: int = 0

    @property
    def strong_present(self) -> bool:
        return any(f.points > 0 and f.strength == "strong" for f in self.flags)

    def flags_dicts(self) -> list[dict[str, Any]]:
        return [f.to_dict() for f in self.flags]


def parse_sender(sender: str | None) -> dict[str, Any]:
    """{"type": "phone"|"alphanumeric"|"none", "info": PhoneInfo|None}. A sender with letters is an id."""
    s = (sender or "").strip()[:64]
    if not s:
        return {"type": "none", "info": None}
    digits = sum(ch.isdigit() for ch in s.translate(phone_intel._ARABIC_DIGITS))  # noqa: SLF001
    if re.fullmatch(r"[+\d\s().\-٠-٩]+", s) and digits >= 3:
        info = phone_intel.analyze(s)
        return {"type": "phone", "info": info if info.key else None}
    return {"type": "alphanumeric", "info": None}


def run_message_rules(text: str, *, sender: str | None, links: list[dict[str, Any]],
                      phones: list[dict[str, Any]], sender_check: dict[str, Any] | None) -> MessageRuleResult:
    """Score one message. `links` = extract_links() entries enriched with {verdict, risk_score, official,
    whitelisted}; `phones` = check results for the numbers written in the text ({status, e164, ...});
    `sender_check` = the check result of a phone-number sender (None for an id / no sender)."""
    text = (text or "")[:MAX_TEXT]
    flags: list[MessageFlag] = []

    def add(code: str, severity: str, points: int, en: str, ar: str, evidence: str | None = None) -> None:
        if any(f.code == code for f in flags):
            return
        strength = "strong" if code in STRONG_CODES else "weak" if code in WEAK_CODES else "info"
        flags.append(MessageFlag(code, severity, points if strength != "info" else 0, en, ar,
                                 strength=strength, evidence=(evidence or None) and evidence[:300]))

    claimed, how = claimed_entity(text, sender)
    plain = deconfuse(text)  # wording rules read the text as a person does
    # Words written with look-alike foreign letters (Latin-looking, Cyrillic / Greek inside): done to
    # slip past spam filters. Only words that MIX scripts count, so real Russian / Greek text is fine.
    mixed = [f for f in scan_text(text, "body") if f.get("kind") == "mixed_script"]
    if mixed:
        words = ", ".join(dict.fromkeys(f["skeleton"] for f in mixed[:4]))
        add("MSG_LOOKALIKE_LETTERS", "critical", 50,
            f"The message writes ordinary words ({words}) with look-alike foreign letters, a trick used to "
            "slip past spam filters. Real organisations do not write like this.",
            f"تكتب الرسالة كلمات عادية ({words}) بأحرف أجنبية شبيهة باللاتينية، وهي حيلة لتجاوز فلاتر الرسائل "
            "المزعجة. الجهات الحقيقية لا تكتب بهذه الطريقة.",
            ", ".join(unescape(f["sample_escaped"]) for f in mixed[:4]))
    name_en = claimed.name_en if claimed else ""
    name_ar = claimed.name_ar if claimed else ""

    # -- links ------------------------------------------------------------------------------------
    max_link = max([l["risk_score"] for l in links if isinstance(l.get("risk_score"), int)] or [0])
    hi = [l for l in links if l.get("verdict") == "HIGH-RISK SCAM"]
    sus = [l for l in links if l.get("verdict") == "SUSPICIOUS"]
    if hi:
        add("MSG_SCAM_LINK", "critical", 65,
            f"The link in this message ({hi[0]['domain']}) was scanned by Saqr and is a scam website.",
            f"تم فحص الرابط الموجود في هذه الرسالة ({hi[0]['domain']}) وتبيّن أنه موقع احتيالي.",
            ", ".join(f"{l['domain']} ({l.get('risk_score')})" for l in hi[:3]))
    elif sus:
        add("MSG_SUSPICIOUS_LINK", "medium", 30,
            f"The link in this message ({sus[0]['domain']}) was scanned and looks suspicious.",
            f"تم فحص الرابط الموجود في هذه الرسالة ({sus[0]['domain']}) ويبدو مشبوهاً.",
            ", ".join(f"{l['domain']} ({l.get('risk_score')})" for l in sus[:3]))
    for l in links:
        if l.get("whitelisted"):
            continue
        try:
            lex = page_signals.lexical(l["url"])
        except ValueError:
            continue
        hits = [f for f in lex.flags if f.code in STRONG_LEXICAL]
        if hits:
            add("MSG_LOOKALIKE_LINK", "critical", 50,
                f"The link {lex.unicode_host} imitates a real website: {hits[0].en}",
                f"الرابط {lex.unicode_host} يقلّد موقعاً حقيقياً: {hits[0].ar}",
                f"{lex.host}: {', '.join(f.code for f in hits)}")
            claimed = claimed or lex.impersonated
            break
    if claimed:
        unofficial = [l for l in links if not l.get("whitelisted") and l.get("verdict") in (None, "SAFE")]
        if unofficial:
            add("MSG_UNOFFICIAL_LINK", "low", 10,
                f"The message claims to be from {claimed.name_en} but links to {unofficial[0]['domain']}, "
                f"which is not one of its websites ({', '.join(claimed.domains[:2])}).",
                f"تدّعي الرسالة أنها من {claimed.name_ar} لكنها تحتوي على رابط إلى {unofficial[0]['domain']}، "
                f"وهو ليس من مواقعها ({'، '.join(claimed.domains[:2])}).", unofficial[0]["domain"])

        # A named company / government body does not hide its address behind a public link shortener
        # (bit.ly, tinyurl ...): the citizen cannot see where the link goes, and scammers rely on that.
        from urllib.parse import urlsplit

        from .url_features import SHORTENER_HOSTS

        short = [h for h in ((urlsplit(l["url"]).hostname or "").lower().removeprefix("www.")
                             for l in links if not l.get("whitelisted")) if h in SHORTENER_HOSTS]
        if short:
            add("MSG_SHORTENER_FOR_INSTITUTION", "high", 35,
                f"The message claims to be from {claimed.name_en} but hides its link behind a public link "
                f"shortener ({short[0]}). {claimed.name_en} uses its own website address "
                f"({', '.join(claimed.domains[:2])}).",
                f"تدّعي الرسالة أنها من {claimed.name_ar} لكنها تُخفي الرابط خلف خدمة اختصار روابط عامة "
                f"({short[0]}). تستخدم {claimed.name_ar} عنوان موقعها الرسمي ({'، '.join(claimed.domains[:2])}).",
                short[0])

    # -- the sender's number ------------------------------------------------------------------------
    st = (sender_check or {}).get("status")
    if claimed and st == "mobile_for_institution":
        add("SENDER_MOBILE_FOR_INSTITUTION", "high", 35,
            f"The message claims to be from {name_en}, but it was sent from a personal mobile number. "
            "Government bodies and banks never text from personal mobiles.",
            f"تدّعي الرسالة أنها من {name_ar}، لكنها أُرسلت من رقم هاتف متحرك شخصي. "
            "الجهات الحكومية والبنوك لا ترسل رسائل من أرقام شخصية.", sender_check.get("masked"))
    elif claimed and st == "foreign_for_institution":
        add("SENDER_FOREIGN_FOR_INSTITUTION", "high", 35,
            f"The message claims to be from {name_en}, a UAE institution, but it came from a foreign number "
            f"({sender_check.get('region') or 'abroad'}).",
            f"تدّعي الرسالة أنها من {name_ar}، وهي جهة إماراتية، لكنها جاءت من رقم أجنبي "
            f"({sender_check.get('region') or 'خارج الدولة'}).", sender_check.get("masked"))
    if st == "linked_to_scam":
        add("MSG_PHONE_LINKED_TO_SCAM", "critical", 40,
            "The sender's number is already linked to fake listings in Saqr's fraud intelligence.",
            "رقم المرسل مرتبط مسبقاً بإدراجات مزيفة في استخبارات صقر للاحتيال.", sender_check.get("masked"))

    # -- call-back numbers in the text -------------------------------------------------------------
    for p in phones:
        s = p.get("status")
        if claimed and s == "mobile_for_institution":
            add("CALLBACK_MOBILE_FOR_INSTITUTION", "high", 35,
                f"The message asks you to contact {name_en} on a personal mobile number. "
                f"{name_en}'s official numbers are {', '.join(claimed.phones[:3]) or 'on its website'}.",
                f"تطلب الرسالة التواصل مع {name_ar} على رقم هاتف متحرك شخصي. "
                f"الأرقام الرسمية: {'، '.join(claimed.phones[:3]) or 'على موقعها الرسمي'}.", p.get("masked"))
        elif claimed and s == "foreign_for_institution":
            add("CALLBACK_FOREIGN_FOR_INSTITUTION", "high", 35,
                f"The message asks you to call a foreign number ({p.get('region') or 'abroad'}) for {name_en}, "
                "a UAE institution that only uses UAE numbers.",
                f"تطلب الرسالة الاتصال برقم أجنبي ({p.get('region') or 'خارج الدولة'}) باسم {name_ar}، "
                "وهي جهة إماراتية تستخدم أرقاماً إماراتية فقط.", p.get("masked"))
        elif claimed and s == "unofficial":
            add("MSG_UNOFFICIAL_CALLBACK", "low", 10,
                f"The number in the message is not one of {name_en}'s official numbers.",
                f"الرقم الموجود في الرسالة ليس من الأرقام الرسمية لـ{name_ar}.", p.get("masked"))
        if s == "linked_to_scam":
            add("MSG_PHONE_LINKED_TO_SCAM", "critical", 40,
                "A number in this message is already linked to fake listings in Saqr's fraud intelligence.",
                "رقم في هذه الرسالة مرتبط مسبقاً بإدراجات مزيفة في استخبارات صقر للاحتيال.", p.get("masked"))

    # -- credential requests -------------------------------------------------------------------------
    # "Enter ..." counts only with a non-official link, and never in a message that itself delivers a code.
    enter_counts = any(not l.get("whitelisted") for l in links) and not delivers_code(text)
    asks = credential_requests(plain, enter_counts=enter_counts)
    if asks:
        add("MSG_CREDENTIAL_REQUEST", "critical", 40,
            "The message asks you to send or enter a one-time code (OTP), PIN, CVV, card number or UAE PASS "
            "code. No bank or government body ever asks for these by message.",
            "تطلب الرسالة إرسال أو إدخال رمز تحقق (OTP) أو رقم سري أو رمز CVV أو رقم بطاقة أو رمز UAE PASS. "
            "لا يطلب أي بنك أو جهة حكومية هذه البيانات عبر الرسائل أبداً.", "; ".join(asks))

    # -- weak wording ----------------------------------------------------------------------------------
    urg = _hits(URGENCY, plain) + _hits(_URGENCY_MORE, plain)
    if urg:
        add("MSG_URGENCY", "low", 10, "It pressures you to act fast (deadlines, threats to block, arrest or impound).",
            "تضغط عليك للتصرف بسرعة (مهل زمنية أو تهديد بالحظر أو القبض أو الحجز).", "; ".join(urg[:4]))
    pay = _hits(_PAYMENT, plain)
    if pay:
        add("MSG_PAYMENT_DEMAND", "low", 10, "It talks about a fine, fee or payment.",
            "تتحدث عن غرامة أو رسوم أو دفعة مالية.", "; ".join(pay))
    eid = _hits(_EMIRATES_ID, plain)
    if eid:
        add("MSG_EMIRATES_ID_LURE", "low", 10, "It says your Emirates ID must be updated or will be suspended.",
            "تقول إن هويتك الإماراتية يجب تحديثها أو سيتم إيقافها.", "; ".join(eid))
    prize = _hits(_PRIZE, plain)
    if prize:
        add("MSG_PRIZE_LURE", "low", 10, "It promises a prize, reward or refund.",
            "تعد بجائزة أو مكافأة أو مبلغ مسترد.", "; ".join(prize))
    # -- scripts that need no link ------------------------------------------------------------------
    threat = _hits(_ACCOUNT_THREAT, plain)
    call = _CALL_NUMBER.search(plain.translate(phone_intel._ARABIC_DIGITS))  # noqa: SLF001
    official_number = bool(phones) and all(p.get("status") in ("official", "verified_official") for p in phones)
    # "never call ..." / "do not call ..." is advice, not a request ("if you did not authorise this, call" is one)
    told_not_to = bool(call) and re.search(r"\b(?:never|do not|don'?t)\s+(?:\w+\s+){0,2}$",
                                           plain[max(0, call.start() - 30):call.start()], re.I)
    if call and not official_number and not told_not_to \
            and ((claimed and (threat or urg or pay or prize)) or (threat and (urg or pay)) or prize):
        add("MSG_CALLBACK_PRESSURE", "high", 35,
            "It pushes you to call or message a phone number about a problem with your account, card or case. "
            "Scammers do this so a person, not a website, takes your details. Use the number on the official website.",
            "تدفعك الرسالة إلى الاتصال أو مراسلة رقم هاتف بسبب مشكلة في حسابك أو بطاقتك أو قضية. يفعل المحتالون ذلك "
            "ليأخذ شخص بياناتك مباشرة. استخدم الرقم الموجود على الموقع الرسمي.", call.group(1).strip())
    if (_JOB_OFFER.search(plain) and _EASY_PAY.search(plain)) or _UNSOLICITED_JOB.search(plain):
        add("MSG_JOB_LURE", "high", 35,
            "An unexpected job offer with easy pay for little work (rating, liking, short tasks). These 'task jobs' "
            "end with a request to pay a deposit.",
            "عرض عمل غير متوقع بأجر سهل مقابل عمل بسيط (تقييم، إعجابات، مهام قصيرة). تنتهي هذه «الوظائف» بطلب دفع مبلغ مقدّم.",
            "; ".join(_hits(_JOB_OFFER, plain, 2) + _hits(_EASY_PAY, plain, 1)))
    if _NEW_NUMBER.search(plain) and (_FAMILY.search(plain) or _MONEY_ASK.search(plain)):
        add("MSG_NEW_NUMBER_LURE", "high", 35,
            "Someone says they are family or a friend on a 'new number' or a borrowed phone. Call the number you "
            "already have for them before you reply or send money.",
            "شخص يدّعي أنه من العائلة أو الأصدقاء ويراسلك من «رقم جديد» أو هاتف مستعار. اتصل برقمه الذي تعرفه قبل الرد أو "
            "إرسال أي مبلغ.", "; ".join(_hits(_NEW_NUMBER, plain, 2)))
    if _GIFT_CARDS.search(plain):
        add("MSG_GIFT_CARD_REQUEST", "critical", 50,
            "It asks you to buy gift cards and send the codes. No employer, bank or government body is ever paid this way.",
            "تطلب الرسالة شراء بطاقات هدايا وإرسال رموزها. لا تُدفع أي مبالغ لجهة عمل أو بنك أو جهة حكومية بهذه الطريقة.",
            "; ".join(_hits(_GIFT_CARDS, plain, 1)))
    if _INVESTMENT.search(plain):
        add("MSG_INVESTMENT_LURE", "high", 35,
            "It promises guaranteed or very high returns. No real investment can promise that.",
            "تعد الرسالة بأرباح مضمونة أو مرتفعة جداً. لا يوجد استثمار حقيقي يضمن ذلك.",
            "; ".join(_hits(_INVESTMENT, plain, 2)))
    # a named sender + a link that is not theirs + pressure: the classic text-message scam shape
    unofficial_link = any(not l.get("whitelisted") for l in links)
    if claimed and unofficial_link and (threat or sum(bool(x) for x in (urg, pay, eid, prize)) >= 2):
        add("MSG_PRESSURE_UNOFFICIAL_LINK", "high", 30,
            f"It uses {name_en}'s name, pressures you (deadline, payment or a blocked account) and sends you to a "
            f"website that is not {name_en}'s.",
            f"تستخدم الرسالة اسم {name_ar} وتضغط عليك (مهلة أو دفع أو حساب موقوف) وتوجّهك إلى موقع لا يتبع {name_ar}.",
            "; ".join((threat + urg + pay)[:3]))
    social = any(f.code in ("MSG_CALLBACK_PRESSURE", "MSG_JOB_LURE", "MSG_NEW_NUMBER_LURE", "MSG_GIFT_CARD_REQUEST",
                            "MSG_INVESTMENT_LURE") for f in flags)

    if claimed:
        add("MSG_CLAIMED_SENDER", "info", 0, f"The message presents itself as coming from {name_en}.",
            f"تقدّم الرسالة نفسها على أنها من {name_ar}.", how)
    if links and all(l.get("official") for l in links):
        add("MSG_OFFICIAL_LINKS", "info", 0, "Every link in the message goes to an official UAE website.",
            "جميع الروابط في الرسالة تؤدي إلى مواقع إماراتية رسمية.")

    # -- score ---------------------------------------------------------------------------------------
    strong = [f for f in flags if f.strength == "strong" and f.points > 0]
    if not strong:  # weak wording alone is normal in real messages: keep it as a note, 0 points
        flags = [MessageFlag(f.code, "info", 0, f.en, f.ar, strength=f.strength, evidence=f.evidence)
                 if f.strength == "weak" else f for f in flags]
    total = sum(f.points for f in flags if f.strength in ("strong", "weak"))
    score = min(100, max(total, max_link if strong else 0))
    codes = {f.code for f in flags if f.points > 0}
    if claimed and ("MSG_CREDENTIAL_REQUEST" in codes or max_link >= 30 or "MSG_LOOKALIKE_LINK" in codes):
        score = max(score, 70)
    actionable = bool(links or phones or asks or social or st in ("mobile_for_institution",
                                                                   "foreign_for_institution", "linked_to_scam"))
    if not actionable:
        score = 0
    verdict = verdict_for(score)
    contradicted = any(p.get("status") in ("unofficial", "mobile_for_institution", "foreign_for_institution",
                                           "linked_to_scam") for p in phones) or st in (
        "mobile_for_institution", "foreign_for_institution", "linked_to_scam")
    verified = (verdict == "SAFE" and bool(links) and all(l.get("official") for l in links)
                and not contradicted and not codes)
    return MessageRuleResult(score, verdict, claimed if strong else None, claimed, how, flags, asks,
                             verified_official=verified, actionable=actionable, max_link_score=max_link)


def link_is_official(url: str) -> tuple[bool, bool]:
    """(verified official UAE website, whitelisted/trusted site) for a link."""
    try:
        lex = page_signals.lexical(url)
    except ValueError:
        return False, False
    return is_official_uae(lex), lex.is_whitelisted


# ---------------------------------------------------------------------------
# Privacy helpers + explanations
# ---------------------------------------------------------------------------
_LONG_DIGITS = re.compile(r"(?<!\d)\d(?:[ \-]?\d){3,18}(?!\d)")


def excerpt(text: str, n: int = EXCERPT_CHARS) -> str:
    """The first n characters with codes, card / account numbers and phone numbers hidden (••••)."""
    t = (text or "").translate(phone_intel._ARABIC_DIGITS)  # noqa: SLF001
    return _LONG_DIGITS.sub("••••", t)[:n]


def explanations(rr: MessageRuleResult, score: int | None = None) -> tuple[str, str]:
    score = rr.score if score is None else score
    verdict = verdict_for(score)
    tail_en = ("Never share OTP codes, PINs or card details by message or phone. Report fraud to Abu Dhabi Police "
               "(Aman 8002626).")
    tail_ar = "لا تشارك أبداً رموز التحقق أو الأرقام السرية أو بيانات البطاقة عبر الرسائل أو الهاتف. أبلغ شرطة أبوظبي (أمان 8002626)."
    if verdict == "SAFE":
        if rr.verified_official:
            return ("Every link in this message goes to an official UAE website and nothing contradicts it. "
                    f"{tail_en}",
                    f"جميع الروابط في هذه الرسالة تؤدي إلى مواقع إماراتية رسمية ولا يوجد ما يناقض ذلك. {tail_ar}")
        return ("No signs of fraud were found in this message. A sender name can be faked, so if a message ever asks "
                f"for codes or money, contact the institution yourself. {tail_en}",
                "لم يتم العثور على علامات احتيال في هذه الرسالة. يمكن تزوير اسم المرسل، لذا إذا طلبت منك رسالة رموزاً أو "
                f"أموالاً فتواصل مع الجهة بنفسك. {tail_ar}")
    ent = rr.entity
    if verdict == "HIGH-RISK SCAM":
        head_en = ("DANGER — This message is very likely a scam"
                   + (f" pretending to be {ent.name_en}" if ent else "") + ". Do NOT open its link, call its number or reply.")
        head_ar = ("خطر — من المرجح جداً أن هذه الرسالة احتيالية" + (f" تنتحل صفة {ent.name_ar}" if ent else "")
                   + ". لا تفتح رابطها ولا تتصل برقمها ولا ترد عليها.")
    else:
        head_en = "CAUTION — This message shows warning signs of fraud. Do not open links, call numbers or send any codes."
        head_ar = "تنبيه — تُظهر هذه الرسالة علامات تحذيرية على الاحتيال. لا تفتح الروابط ولا تتصل بالأرقام ولا ترسل أي رموز."
        if ent:
            head_en += f" It may be pretending to be {ent.name_en}."
            head_ar += f" قد تكون منتحلة لصفة {ent.name_ar}."
    top = sorted((f for f in rr.flags if f.points > 0), key=lambda f: -f.points)[:4]
    bullets_en = "\n".join(f"• {f.en}" for f in top)
    bullets_ar = "\n".join(f"• {f.ar}" for f in top)
    if ent:
        tail_en = (f"If you are worried, contact {ent.name_en} yourself through its official website "
                   f"({', '.join(ent.domains[:2])}) — not through this message. " + tail_en)
        tail_ar = (f"إذا كنت قلقاً فتواصل مع {ent.name_ar} بنفسك عبر موقعها الرسمي ({'، '.join(ent.domains[:2])}) "
                   "وليس عبر هذه الرسالة. " + tail_ar)
    return (f"{head_en}\n\nRed flags:\n{bullets_en}\n\n{tail_en}", f"{head_ar}\n\nعلامات الخطر:\n{bullets_ar}\n\n{tail_ar}")


def blend(rr: MessageRuleResult, llm: dict[str, Any] | None) -> int:
    """Rules are the floor. A confident (>= 0.7) AI scam opinion next to a strong signal escalates
    (0.25 rules + 0.75 AI); without one it can reach SUSPICIOUS at most (64). Nothing to act on (no
    link, number or request) or only official links and nothing contradicting: the AI cannot raise it."""
    if not llm or not rr.actionable or rr.verified_official:
        return rr.score
    try:
        risk = max(0, min(100, int(float(llm.get("risk_score", 0)))))
        conf = float(llm.get("confidence", 0.5))
    except (TypeError, ValueError):
        return rr.score
    if llm.get("verdict") not in ("SUSPICIOUS", "HIGH-RISK SCAM") or conf < 0.7:
        return rr.score
    if rr.strong_present:
        return min(100, max(rr.score, round(0.25 * rr.score + 0.75 * risk)))
    return max(rr.score, min(64, round(0.5 * rr.score + 0.5 * risk)))
