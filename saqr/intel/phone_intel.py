"""Phone-number intelligence: parse a messy number and say what kind of line it is.

Uses ONLY the core of Google's libphonenumber port (`phonenumbers.parse`, `is_valid_number`,
`number_type`, `format_number`, `region_code_for_number` + its short-number check). Never import
`phonenumbers.carrier`, `.geocoder` or `.timezone`: they load tens of MB of data and the Render
host has 512 MB. Measured cost of what is used here: ~1.1 MB Python heap, ~3 MB RSS (metadata is
loaded lazily, one region at a time).

    analyze("+971 (0) 50 123 4567").to_dict()
    -> {"e164": "+971501234567", "national": "501234567", "country_code": 971, "region": "AE",
        "is_valid": True, "line_type": "mobile", "is_uae": True, "is_uae_mobile": True, ...}

`key` is the canonical form `registry.normalise_phone` returns (the registry / graph key):
UAE toll-free (800…) and shared-cost (600…) numbers and short codes keep their national digits
(800555, 600599999, 999), every other number is its E.164 digits without "+" (971501234567).
"""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass

import phonenumbers
from phonenumbers import PhoneNumberType as _T

UAE_CC = 971

# What the library returns -> our small vocabulary. VOIP / personal / pager / FIXED_LINE_OR_MOBILE are
# NOT claimed (the UAE metadata has no VoIP range); UAN = the UAE "600" unified numbers (shared cost).
_LINE_TYPES = {
    _T.MOBILE: "mobile",
    _T.FIXED_LINE: "fixed_line",
    _T.TOLL_FREE: "toll_free",
    _T.SHARED_COST: "shared_cost",
    _T.UAN: "shared_cost",
    _T.PREMIUM_RATE: "premium",
}

# UAE short codes the library's short-number metadata does not know (it only lists 999 for AE).
# Kept small and explicit; a short code alone never makes a number "official" (that is the registry's job).
UAE_SHORT_CODES = frozenset({
    "999",   # police emergency
    "998",   # ambulance
    "997",   # civil defence / fire
    "996",   # electricity emergency
    "901",   # police non-emergency (Dubai, Sharjah, Ras Al Khaimah)
    "2828",  # Abu Dhabi Police Aman service, SMS
    "101",   # e& customer care
    "155",   # du customer care
    "171",   # ICP
})

_ARABIC_DIGITS = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")
_TEL_PREFIX = re.compile(r"^\s*(tel|callto|sms)\s*:\s*/*", re.I)
_TRUNK_ZERO = re.compile(r"\(\s*0\s*\)")  # "+971 (0) 50 ..." — the (0) is the national trunk prefix


@dataclass(frozen=True)
class PhoneInfo:
    raw: str
    e164: str | None = None
    national: str = ""             # national significant digits (501234567, 800555) or the short code
    country_code: int | None = None
    region: str | None = None      # ISO 3166 region, e.g. "AE", "US"
    is_valid: bool = False         # a valid number for its region (short codes are not "valid numbers")
    line_type: str = "unknown"     # mobile | toll_free | fixed_line | shared_cost | premium | unknown
    is_uae: bool = False
    is_uae_mobile: bool = False    # +971 5x
    is_short_code: bool = False
    key: str = ""                  # canonical registry key (see module docstring); "" = not a number

    def to_dict(self) -> dict:
        return asdict(self)


def clean(raw: str | None) -> str:
    """tel: prefix, Arabic-Indic digits and the "(0)" trunk marker removed; nothing else changed."""
    s = _TEL_PREFIX.sub("", str(raw or "")).translate(_ARABIC_DIGITS)
    return _TRUNK_ZERO.sub(" ", s).strip()


def _digits(s: str) -> str:
    return "".join(ch for ch in s if "0" <= ch <= "9")


def _legacy_key(digits: str) -> str:
    """The pre-phonenumbers rule, kept for anything the library cannot validate (odd lengths, demo data)."""
    if digits.startswith("00971"):
        digits = "971" + digits[5:]
    if digits.startswith("971"):
        rest = digits[3:].lstrip("0")
        # 971800555 / 9710600599999 are the toll-free / shared-cost numbers written internationally
        return rest if rest.startswith(("800", "600")) else digits
    if digits.startswith(("800", "600")) or len(digits) <= 4:
        return digits
    if digits.startswith("0") and len(digits) in (9, 10):
        return "971" + digits[1:]
    return digits


def _short_code(digits: str, s: str, default_region: str) -> bool:
    if s.lstrip().startswith("+") or not 3 <= len(digits) <= 5:
        return False
    if default_region == "AE" and digits in UAE_SHORT_CODES:
        return True
    try:
        return phonenumbers.is_valid_short_number_for_region(phonenumbers.parse(digits, default_region),
                                                             default_region)
    except phonenumbers.NumberParseException:
        return False


def mask(info: PhoneInfo) -> str:
    """A number with its middle hidden ("+971 50 *** **67"): enough to recognise it, not to dial it."""
    if info.e164 and info.country_code:
        nat = info.national
        head = nat[:2] if info.is_uae else nat[:1]
        return f"+{info.country_code} {head} *** **{nat[-2:]}"
    d = _digits(clean(info.raw))
    return (d[:2] + "*" * max(0, len(d) - 4) + d[-2:]) if len(d) > 4 else "***"


# -- numbers inside free text (SMS / WhatsApp / email bodies) --------------------------------------------
# Strict on purpose: OTP codes, amounts, dates, reference / tracking / order numbers must never become
# "phone numbers". A candidate must look like a dialled number (+ / 00 international, or a 0-prefixed UAE
# number), parse as a VALID number, and must not follow a code / reference / currency word. UAE 800 / 600
# numbers are only taken right after a call word ("call 800 555"), never on their own.
_SEP = r"[ \t\-.() ]"
_CANDIDATE = re.compile(
    rf"(?<![\w+/.:#@-])((?:\+|00)\s?\d(?:{_SEP}{{0,3}}\d){{6,14}}|0\d(?:{_SEP}{{0,2}}\d){{6,10}}|\(0\d\)(?:{_SEP}{{0,2}}\d){{6,9}})(?![\w/@])")
_TEL_LINK = re.compile(r"\b(?:tel|callto)\s*:\s*/*(\+?[\d][\d \-.()]{4,20}\d)", re.I)
_CALL_WORD_TOLL = re.compile(
    r"(?:\b(?:call|tel|phone|contact|ring|dial|helpline|hotline)\b|اتصل|اتصلوا|اتصلي|هاتف|الهاتف|بالرقم|على الرقم)"
    r"[^\d\n]{0,14}((?:800|600)(?:[ \-]?\d){3,7})(?![\d\w])", re.I)
_NOT_PHONE_BEFORE = re.compile(
    r"(?:\b(?:otp|code|pin|passcode|ref|reference|tracking|track|order|booking|invoice|inv|transaction|txn|trx|"
    r"account|a/c|acc|card|policy|id|awb|shipment|parcel|consignment|receipt|case|ticket|serial|plate|amount|"
    r"total|balance|aed|dhs?|usd|eur|sar|gbp|inr)\b|[$€£]|رمز|الرمز|مرجع|المرجع|تتبع|التتبع|طلب|الطلب|فاتورة|"
    r"حساب|الحساب|بطاقة|البطاقة|معاملة|المعاملة|درهم|مبلغ|المبلغ|شحنة|الشحنة|إيصال)"
    r"\W{0,3}(?:no\.?|nr\.?|number|num|#|رقم)?\W{0,3}$", re.I)
_CURRENCY_AFTER = re.compile(r"^\s*(?:aed|dhs?|usd|eur|fils|درهم|فلس|د\.إ)\b", re.I)
_DATE_LIKE = re.compile(r"^\(?\d{1,4}\)?[./-]\d{1,2}[./-]\d{2,4}$")


def find_phones(text: str | None, limit: int = 5, default_region: str = "AE") -> list[PhoneInfo]:
    """Valid phone numbers written in a message (see the rules above), de-duplicated by key."""
    t = str(text or "")[:20_000].translate(_ARABIC_DIGITS)  # 1:1 character mapping: offsets are kept
    found: list[tuple[int, str]] = []
    for m in _TEL_LINK.finditer(t):
        found.append((m.start(1), m.group(1)))
    for m in _CALL_WORD_TOLL.finditer(t):
        found.append((m.start(1), m.group(1)))
    for m in _CANDIDATE.finditer(t):
        raw = m.group(1).strip()
        before, after = t[max(0, m.start(1) - 28):m.start(1)], t[m.end(1):m.end(1) + 8]
        if _NOT_PHONE_BEFORE.search(before) or _CURRENCY_AFTER.match(after) or _DATE_LIKE.match(raw):
            continue
        found.append((m.start(1), raw))
    out: dict[str, PhoneInfo] = {}
    for _, raw in sorted(found, key=lambda x: x[0]):
        info = analyze(raw, default_region)
        if not info.key or info.key in out:
            continue
        if info.is_valid and info.line_type in {"mobile", "fixed_line", "toll_free", "shared_cost", "unknown"}:
            out[info.key] = info
        if len(out) >= limit:
            break
    return list(out.values())


def analyze(raw: str | None, default_region: str = "AE") -> PhoneInfo:
    raw_s = "" if raw is None else str(raw)
    s = clean(raw_s)
    digits = _digits(s)
    if not digits:
        return PhoneInfo(raw=raw_s)

    if _short_code(digits, s, default_region):
        cc = phonenumbers.country_code_for_region(default_region) or None
        return PhoneInfo(raw=raw_s, national=digits, country_code=cc, region=default_region,
                         is_uae=cc == UAE_CC, is_short_code=True, key=digits)

    try:
        num = phonenumbers.parse(s, default_region)
    except phonenumbers.NumberParseException:
        return PhoneInfo(raw=raw_s, national=digits, key=_legacy_key(digits))

    valid = phonenumbers.is_valid_number(num)
    cc = num.country_code
    national = phonenumbers.national_significant_number(num)
    if valid:
        region = phonenumbers.region_code_for_number(num)
        line = _LINE_TYPES.get(phonenumbers.number_type(num), "unknown")
    else:
        region = phonenumbers.region_code_for_country_code(cc)
        line = "unknown"
    region = None if region in (None, "ZZ") else region
    is_uae = cc == UAE_CC
    if valid and is_uae and line in {"toll_free", "shared_cost"}:
        key = national                      # 800555, 600599999 (how the UAE writes and the registry stores them)
    elif valid:
        key = f"{cc}{national}"             # 971501234567, 18005551234
    else:
        key = _legacy_key(digits)
    return PhoneInfo(
        raw=raw_s,
        e164=phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164) if valid else None,
        national=national, country_code=cc, region=region, is_valid=valid, line_type=line,
        is_uae=is_uae, is_uae_mobile=valid and is_uae and line == "mobile" and national.startswith("5"),
        key=key,
    )
