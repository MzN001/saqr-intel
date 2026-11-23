"""Official UAE entity registry: whitelisted domains, brand keywords, phones, branches.

NOTE: Phone numbers and branch coordinates are demo reference data. Verify them
against the entities' official channels before any operational use.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import settings


@dataclass(frozen=True)
class Entity:
    id: str
    name_en: str
    name_ar: str
    category: str  # government | courier | telecom | bank | identity
    domains: tuple[str, ...]
    keywords: tuple[str, ...]  # brand tokens used for lookalike detection
    phones: tuple[str, ...]  # normalised digits only
    aliases: tuple[str, ...] = ()  # business-name aliases (EN + AR) for Maps matching
    lure_en: str = ""
    lure_ar: str = ""
    branches: tuple[tuple[str, float, float], ...] = field(default_factory=tuple)
    common_keywords: tuple[str, ...] = ()  # ordinary words: impersonation only next to a lure word


ENTITIES: tuple[Entity, ...] = (
    Entity(
        id="adpolice",
        name_en="Abu Dhabi Police",
        name_ar="شرطة أبوظبي",
        category="government",
        domains=("adpolice.gov.ae",),
        keywords=("adpolice", "ad-police", "abudhabipolice", "abudhabi-police", "adp-fines"),
        phones=("999", "8002626"),
        aliases=("abu dhabi police", "ad police", "adpolice", "traffic fines", "شرطة أبوظبي", "شرطة ابوظبي"),
        lure_en="unpaid traffic fines or a blocked vehicle file",
        lure_ar="مخالفات مرورية غير مدفوعة أو حظر ملف المركبة",
        branches=(
            ("Abu Dhabi Police GHQ", 24.4700, 54.3681),
            ("Traffic & Patrols – Al Saada", 24.4421, 54.3920),
        ),
    ),
    Entity(
        id="tamm",
        name_en="TAMM Abu Dhabi",
        name_ar="منصة تم - حكومة أبوظبي",
        category="government",
        domains=("tamm.abudhabi",),
        keywords=("tamm",),
        phones=("800555",),
        aliases=("tamm", "tamm abu dhabi", "tamm service center", "مركز تم", "منصة تم"),
        lure_en="government service fees, refunds or a payment that is 'about to expire'",
        lure_ar="رسوم خدمات حكومية أو استرداد مبالغ أو دفعة «على وشك الانتهاء»",
        branches=(("TAMM Centre – Khalifa City", 24.4198, 54.5776),),
    ),
    Entity(
        id="emiratespost",
        name_en="Emirates Post",
        name_ar="بريد الإمارات",
        category="courier",
        domains=("emiratespost.ae",),
        keywords=("emiratespost", "emirates-post", "emiratepost", "emirates-pst", "epost-uae"),
        phones=("600599999",),
        aliases=("emirates post", "emiratespost", "بريد الإمارات", "بريد الامارات"),
        lure_en="a parcel held for a small 'redelivery' or customs fee",
        lure_ar="شحنة محتجزة مقابل رسوم «إعادة توصيل» أو رسوم جمركية بسيطة",
        branches=(("Emirates Post – Abu Dhabi Central", 24.4889, 54.3615),),
    ),
    Entity(
        id="etisalat",
        name_en="e& (Etisalat)",
        name_ar="اتصالات من e&",
        category="telecom",
        domains=("etisalat.ae", "eand.com"),
        keywords=("etisalat", "etisalet", "etsalat", "eand"),
        phones=("101", "800101"),
        aliases=("etisalat", "e&", "etisalat by e&", "اتصالات"),
        lure_en="expiring reward points or a prize you supposedly won",
        lure_ar="نقاط مكافآت توشك على الانتهاء أو جائزة مزعومة",
        branches=(("e& Tower Abu Dhabi", 24.4886, 54.3647),),
    ),
    Entity(
        id="du",
        name_en="du",
        name_ar="دو",
        category="telecom",
        domains=("du.ae",),
        keywords=("du",),
        phones=("155", "800155"),
        aliases=("du telecom", "du store", "du shop", "دو"),
        lure_en="a prize draw or a line about to be suspended",
        lure_ar="سحب على جائزة أو خط على وشك الإيقاف",
        branches=(),
    ),
    Entity(
        id="uaepass",
        name_en="UAE PASS",
        name_ar="الهوية الرقمية UAE PASS",
        category="identity",
        domains=("uaepass.ae",),
        keywords=("uaepass", "uae-pass", "uaepas"),
        phones=("600561111",),
        aliases=("uae pass", "uaepass", "الهوية الرقمية"),
        lure_en="an account that must be 're-verified' to avoid suspension",
        lure_ar="حساب يجب «إعادة التحقق منه» لتجنب إيقافه",
        branches=(),
    ),
    Entity(
        id="fab",
        name_en="First Abu Dhabi Bank (FAB)",
        name_ar="بنك أبوظبي الأول",
        category="bank",
        domains=("bankfab.com",),
        keywords=("bankfab", "fab", "firstabudhabibank", "first-abudhabi-bank"),
        phones=("600525500",),
        aliases=("first abu dhabi bank", "bank fab", "fab bank", "fab atm", "بنك أبوظبي الأول"),
        lure_en="a blocked card or account that needs urgent 'updating'",
        lure_ar="بطاقة أو حساب محظور يحتاج إلى «تحديث» عاجل",
        branches=(("FAB HQ – Khalifa Business Park", 24.4560, 54.3240),),
    ),
    Entity(
        id="adcb",
        name_en="ADCB",
        name_ar="بنك أبوظبي التجاري",
        category="bank",
        domains=("adcb.com",),
        keywords=("adcb",),
        phones=("600502030",),
        aliases=("adcb", "abu dhabi commercial bank", "بنك أبوظبي التجاري"),
        lure_en="a card verification or a 'suspicious transaction' on your account",
        lure_ar="التحقق من البطاقة أو «معاملة مشبوهة» على حسابك",
        branches=(("ADCB HQ – Sheikh Zayed St", 24.4900, 54.3570),),
    ),
)

def _g(id_: str, en: str, ar: str, domains: str, keywords: str, common: str = "") -> Entity:
    """A global brand. `keywords` alone prove impersonation (paypal, icloud); `common` keywords are
    ordinary words (apple, chase, amazon) and only count next to a lure word (apple-id-verify)."""
    return Entity(id=id_, name_en=en, name_ar=ar, category="global", domains=tuple(domains.split()),
                  keywords=tuple(keywords.split()), phones=(), common_keywords=tuple(common.split()))


# The brands phishing kits copy most worldwide (APWG / OpenPhish top targets) plus big UAE brands
# outside the government list. Used for scam detection only (not Maps, CT simulation or awareness).
GLOBAL_BRANDS: tuple[Entity, ...] = (
    _g("paypal", "PayPal", "باي بال", "paypal.com paypal.me paypalobjects.com", "paypal"),
    _g("microsoft", "Microsoft", "مايكروسوفت",
       "microsoft.com microsoftonline.com live.com outlook.com office.com office365.com onedrive.com "
       "msn.com bing.com azure.com xbox.com skype.com windows.com microsoft365.com hotmail.com",
       "microsoft office365 microsoft365 onedrive hotmail msoffice outlook365 sharepoint", "outlook office"),
    _g("apple", "Apple", "آبل", "apple.com icloud.com me.com apple.co", "icloud appleid itunes applepay", "apple"),
    _g("amazon", "Amazon", "أمازون",
       "amazon.com amazon.ae amazon.sa amazon.co.uk amazon.de amazon.in amazon.fr amazon.eg amazonaws.com "
       "amazon.jobs primevideo.com", "amazonprime", "amazon prime"),
    _g("netflix", "Netflix", "نتفليكس", "netflix.com nflxext.com", "netflix"),
    _g("facebook", "Facebook", "فيسبوك", "facebook.com fb.com messenger.com meta.com", "facebook fbook", "meta"),
    _g("instagram", "Instagram", "إنستغرام", "instagram.com", "instagram instagr"),
    _g("whatsapp", "WhatsApp", "واتساب", "whatsapp.com whatsapp.net wa.me", "whatsapp"),
    _g("google", "Google", "جوجل", "google.com google.ae gmail.com youtube.com googleapis.com withgoogle.com",
       "gmail", "google"),
    _g("dhl", "DHL", "دي إتش إل", "dhl.com dhl.ae dhl.de", "dhl"),
    _g("fedex", "FedEx", "فيديكس", "fedex.com", "fedex"),
    _g("ups", "UPS", "يو بي إس", "ups.com", "", "ups"),
    _g("usps", "USPS", "البريد الأمريكي USPS", "usps.com", "usps"),
    _g("aramex", "Aramex", "أرامكس", "aramex.com", "aramex"),
    _g("binance", "Binance", "بينانس", "binance.com", "binance"),
    _g("coinbase", "Coinbase", "كوين بيس", "coinbase.com", "coinbase"),
    _g("metamask", "MetaMask", "ميتاماسك", "metamask.io", "metamask"),
    _g("trustwallet", "Trust Wallet", "محفظة ترست", "trustwallet.com", "trustwallet"),
    _g("ledger", "Ledger", "ليدجر", "ledger.com", "", "ledger"),
    _g("cryptocom", "Crypto.com", "كريبتو.كوم", "crypto.com", "", "crypto"),
    _g("steam", "Steam", "ستيم", "steampowered.com steamcommunity.com", "steamcommunity steampowered", "steam"),
    _g("roblox", "Roblox", "روبلوكس", "roblox.com", "roblox"),
    _g("chase", "Chase", "بنك تشيس", "chase.com", "", "chase"),
    _g("wellsfargo", "Wells Fargo", "ويلز فارغو", "wellsfargo.com", "wellsfargo"),
    _g("bofa", "Bank of America", "بنك أوف أمريكا", "bankofamerica.com", "bankofamerica"),
    _g("hsbc", "HSBC", "بنك إتش إس بي سي", "hsbc.com hsbc.ae hsbc.co.uk", "hsbc"),
    _g("citi", "Citibank", "سيتي بنك", "citi.com citibank.com", "citibank", "citi"),
    _g("emiratesnbd", "Emirates NBD", "بنك الإمارات دبي الوطني", "emiratesnbd.com", "emiratesnbd enbd"),
    _g("mashreq", "Mashreq", "بنك المشرق", "mashreq.com", "mashreq mashreqbank"),
    _g("adib", "Abu Dhabi Islamic Bank", "مصرف أبوظبي الإسلامي", "adib.ae", "adib"),
    _g("dubaipolice", "Dubai Police", "شرطة دبي", "dubaipolice.gov.ae", "dubaipolice"),
    _g("rta", "RTA Dubai", "هيئة الطرق والمواصلات", "rta.ae", "", "rta salik"),
    _g("emiratesair", "Emirates (airline)", "طيران الإمارات", "emirates.com", "", "emirates"),
    _g("noon", "noon", "نون", "noon.com", "", "noon"),
    _g("careem", "Careem", "كريم", "careem.com", "careem"),
    _g("docusign", "DocuSign", "دوكيوساين", "docusign.com docusign.net", "docusign"),
    _g("dropbox", "Dropbox", "دروب بوكس", "dropbox.com", "dropbox"),
    _g("adobe", "Adobe", "أدوبي", "adobe.com", "adobe"),
    _g("linkedin", "LinkedIn", "لينكدإن", "linkedin.com", "linkedin"),
    _g("telegram", "Telegram", "تيليجرام", "telegram.org t.me", "telegram"),
    _g("tiktok", "TikTok", "تيك توك", "tiktok.com", "tiktok"),
    _g("twitter", "X (Twitter)", "إكس (تويتر)", "x.com twitter.com", "twitter"),
    _g("att", "AT&T", "إيه تي آند تي", "att.com", "", "att"),
    _g("yahoo", "Yahoo", "ياهو", "yahoo.com", "yahoo"),
    _g("booking", "Booking.com", "بوكينج", "booking.com", "", "booking"),
    _g("airbnb", "Airbnb", "إير بي إن بي", "airbnb.com airbnb.ae", "airbnb"),
    _g("ebay", "eBay", "إيباي", "ebay.com", "ebay"),
    _g("wise", "Wise", "وايز", "wise.com transferwise.com", "transferwise", "wise"),
    _g("revolut", "Revolut", "ريفولوت", "revolut.com", "revolut"),
)
# Every brand scam detection knows: UAE entities first (they win ties), then global brands.
ALL_BRANDS: tuple[Entity, ...] = ENTITIES + GLOBAL_BRANDS

ENTITY_BY_ID = {e.id: e for e in ALL_BRANDS}

# Well-known legitimate UAE websites that are not in ENTITIES above. They are trusted (scanned as
# SAFE, subdomains included) but are not used as impersonation targets. Add more with the
# EXTRA_WHITELIST_DOMAINS setting in .env (comma-separated).
TRUSTED_UAE_DOMAINS: tuple[str, ...] = (
    "u.ae",                  # official UAE Government portal
    "abudhabi.ae",           # Abu Dhabi Government portal
    "rta.ae",                # Dubai Roads & Transport Authority
    "dubaipolice.gov.ae",
    "moi.gov.ae",            # Ministry of Interior
    "icp.gov.ae",            # Federal Authority for Identity & Citizenship
    "tdra.gov.ae",
    "mohre.gov.ae",
    "dewa.gov.ae",
    "emirates.com",          # Emirates airline (not Emirates Post)
    "etihad.com",
    "adnoc.ae",
    "emiratesnbd.com",
)

OFFICIAL_DOMAINS: dict[str, Entity | None] = {d: e for e in ALL_BRANDS for d in e.domains}
for _d in (*TRUSTED_UAE_DOMAINS, *settings.extra_whitelist, *settings.own_hosts):
    OFFICIAL_DOMAINS.setdefault(_d.lower(), None)

# Phone number -> entity
OFFICIAL_PHONES: dict[str, Entity] = {p: e for e in ENTITIES for p in e.phones}

SUSPICIOUS_TLDS = {
    "info", "xyz", "top", "online", "site", "club", "icu", "live", "shop", "vip", "buzz",
    "rest", "cfd", "sbs", "click", "link", "monster", "quest", "lol", "cyou", "support", "help",
}

LURE_KEYWORDS = (
    "fine", "fines", "pay", "payment", "verify", "verification", "secure", "update", "login",
    "signin", "track", "tracking", "parcel", "delivery", "redeliver", "refund", "reward",
    "rewards", "prize", "winner", "otp", "kyc", "account", "suspend", "customs", "wallet",
    "portal", "smart", "service", "claim", "unlock", "confirm", "billing", "gov",
)

# Abu Dhabi emirate approximate bounding box (lat_min, lat_max, lng_min, lng_max)
ABU_DHABI_BBOX = (22.6, 25.3, 51.5, 56.0)

# ASNs of large shared-infrastructure providers. IPs on these networks are recorded
# but NOT used to cluster domains into syndicates (to avoid false links via CDNs).
SHARED_INFRA_ASNS = {"13335", "16509", "14618", "15169", "8075", "54113", "20940", "16625", "396982"}


def normalise_phone(raw: str | None) -> str:
    """Return digits only, converting +971 / 00971 / leading 0 to a canonical 971 form
    for mobile/landline numbers; short codes (999, 800xxx, 600xxxxxx) are kept as-is."""
    if not raw:
        return ""
    digits = "".join(ch for ch in raw if ch.isdigit())
    if digits.startswith("00971"):
        digits = "971" + digits[5:]
    if digits.startswith("971"):
        return digits
    if digits.startswith(("800", "600")) or len(digits) <= 4:
        return digits
    if digits.startswith("0") and len(digits) in (9, 10):
        return "971" + digits[1:]
    return digits
