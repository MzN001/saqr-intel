"""Official UAE entity registry: whitelisted domains, brand keywords, phones, branches.

NOTE: Branch coordinates are demo reference data. Phone numbers listed in `VERIFIED_PHONES` were
checked on the entity's own website (source URL next to each); every other number is unverified
demo data. Verify those against the entities' official channels before any operational use.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..config import settings
from .phone_intel import analyze as _analyze_phone


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
        phones=("999", "8002626", "8003333", "2828"),
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
        phones=("101", "800101", "8005800"),
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
    # salik.ae: Salik toll accounts; rta.ae's own footer links "RTA Salik page" -> https://www.salik.ae/en (checked 2026-11-24)
    _g("rta", "RTA Dubai", "هيئة الطرق والمواصلات", "rta.ae salik.ae", "", "rta salik"),
    # "dewa" is also a Balinese title / Indonesian word, so it only counts next to a lure word (dewa-bill-pay)
    # or, in an email display name, next to a role word ("DEWA Customer Care").
    _g("dewa", "DEWA", "هيئة كهرباء ومياه دبي", "dewa.gov.ae", "", "dewa"),
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
    # rakbank.ae: "Contact Us - Rakbank" at https://www.rakbank.ae/en/contact-us (checked 2026-11-24)
    _g("rakbank", "RAKBANK", "بنك رأس الخيمة الوطني", "rakbank.ae", "rakbank"),
    # -- wider coverage (2026-11-25): brands that fill the public phishing feeds but were not listed.
    # Names that are also ordinary words or that fans build sites around (spotify-charts, fortnite-skins)
    # are `common` keywords: they only count next to a lure word. Every domain below is in the Tranco
    # top-1M list (tools/check_brand_domains.py).
    _g("shopee", "Shopee", "شوبي",
       "shopee.com shopee.co.id shopee.sg shopee.com.my shopee.ph shopee.vn shopee.co.th shopee.tw "
       "shopee.com.br shopee.com.mx shopee.cl shopee.com.co", "shopee"),
    _g("lazada", "Lazada", "لازادا",
       "lazada.com lazada.sg lazada.com.my lazada.co.id lazada.com.ph lazada.co.th lazada.vn", "lazada"),
    _g("tokopedia", "Tokopedia", "توكوبيديا", "tokopedia.com", "tokopedia"),
    _g("aliexpress", "AliExpress", "علي إكسبريس", "aliexpress.com aliexpress.us aliexpress.ru alibaba.com",
       "aliexpress alibaba"),
    _g("mercadolibre", "Mercado Libre", "ميركادو ليبري",
       "mercadolibre.com mercadolibre.com.ar mercadolibre.com.mx mercadolibre.cl mercadolibre.com.co "
       "mercadolivre.com.br mercadopago.com mercadopago.com.br mercadopago.com.ar mercadopago.com.mx",
       "mercadolibre mercadolivre mercadopago"),
    _g("allegro", "Allegro", "أليغرو", "allegro.pl allegrolokalnie.pl allegro.cz allegro.sk", "allegrolokalnie",
       "allegro"),
    _g("olx", "OLX", "أو إل إكس",
       "olx.com olx.pl olx.ua olx.com.br olx.pt olx.ro olx.bg olx.kz olx.uz olx.in olx.co.id olx.com.pk "
       "olx.com.eg olx.com.lb", "", "olx"),
    _g("cdiscount", "Cdiscount", "سي ديسكاونت", "cdiscount.com", "cdiscount"),
    _g("rakuten", "Rakuten", "راكوتن", "rakuten.co.jp rakuten.com rakuten.fr rakuten.de rakuten.com.tw "
       "rakuten-card.co.jp rakuten-bank.co.jp", "rakuten"),
    _g("xfinity", "Xfinity (Comcast)", "إكسفينيتي", "xfinity.com comcast.com comcast.net", "xfinity comcast"),
    _g("verizon", "Verizon", "فيرايزون", "verizon.com verizonwireless.com", "verizon"),
    _g("vodafone", "Vodafone", "فودافون",
       "vodafone.com vodafone.co.uk vodafone.de vodafone.it vodafone.es vodafone.com.au vodafone.in vodafone.pt "
       "vodafone.ie vodafone.com.tr vodafone.com.eg vodafone.qa vodafone.ro vodafone.gr vodafone.cz vodafone.hu "
       "vodafone.nl vodafone.al vodafone.com.gh", "vodafone"),
    _g("telstra", "Telstra", "تلسترا", "telstra.com.au telstra.com", "telstra"),
    _g("telus", "TELUS", "تيلوس", "telus.com", "telus"),
    _g("swisscom", "Swisscom", "سويسكوم", "swisscom.ch swisscom.com", "swisscom"),
    _g("anz", "ANZ Bank", "بنك ANZ", "anz.com anz.com.au anz.co.nz", "", "anz"),
    _g("commbank", "Commonwealth Bank", "بنك الكومنولث", "commbank.com.au", "commbank"),
    _g("westpac", "Westpac", "ويستباك", "westpac.com.au westpac.co.nz", "westpac"),
    _g("santander", "Santander", "بنك سانتاندير",
       "santander.com santander.co.uk santander.com.br bancosantander.es santander.com.mx santander.cl "
       "santander.com.ar santander.pt santander.de santander.pl santanderbank.com santander.us", "", "santander"),
    _g("bbva", "BBVA", "بنك BBVA", "bbva.com bbva.es bbva.mx bbva.com.ar bbva.pe bbva.com.co", "bbva"),
    _g("barclays", "Barclays", "باركليز", "barclays.co.uk barclays.com barclaycard.co.uk barclaysus.com",
       "barclays barclaycard"),
    _g("lloyds", "Lloyds Bank", "بنك لويدز", "lloydsbank.com lloydsbank.co.uk", "lloydsbank", "lloyds"),
    _g("natwest", "NatWest", "نات ويست", "natwest.com", "natwest"),
    _g("amex", "American Express", "أمريكان إكسبريس", "americanexpress.com aexp-static.com", "americanexpress",
       "amex"),
    _g("capitalone", "Capital One", "كابيتال وان", "capitalone.com", "capitalone"),
    _g("usaa", "USAA", "يو إس إيه إيه", "usaa.com", "usaa"),
    _g("navyfederal", "Navy Federal", "نيفي فيدرال", "navyfederal.org", "navyfederal"),
    _g("nubank", "Nubank", "نوبنك", "nubank.com.br nu.com.mx", "nubank"),
    _g("bradesco", "Bradesco", "براديسكو", "bradesco.com.br", "bradesco"),
    _g("itau", "Itaú", "إيتاو", "itau.com.br itau.cl itau.com.ar itau.com.uy itau.com.py", "", "itau"),
    _g("kraken", "Kraken", "كراكن", "kraken.com", "", "kraken"),
    _g("okx", "OKX", "أو كي إكس", "okx.com", "", "okx"),
    _g("bybit", "Bybit", "بايبت", "bybit.com", "bybit"),
    _g("kucoin", "KuCoin", "كوكوين", "kucoin.com", "kucoin"),
    _g("opensea", "OpenSea", "أوبن سي", "opensea.io", "opensea"),
    _g("uniswap", "Uniswap", "يونيسواب", "uniswap.org", "uniswap"),
    _g("trezor", "Trezor", "تريزور", "trezor.io", "trezor"),
    _g("phantom", "Phantom Wallet", "محفظة فانتوم", "phantom.app phantom.com", "", "phantom"),
    _g("exodus", "Exodus Wallet", "محفظة إكسودس", "exodus.com", "", "exodus"),
    _g("royalmail", "Royal Mail", "البريد الملكي البريطاني", "royalmail.com", "royalmail"),
    _g("evri", "Evri", "إيفري", "evri.com", "", "evri"),
    _g("dpd", "DPD", "دي بي دي", "dpd.com dpd.co.uk dpd.de dpd.fr dpd.ch dpd.com.pl dpd.ie dpd.nl", "", "dpd"),
    _g("laposte", "La Poste", "البريد الفرنسي", "laposte.fr laposte.net", "laposte"),
    _g("posteitaliane", "Poste Italiane", "البريد الإيطالي", "poste.it posteitaliane.it", "posteitaliane"),
    _g("auspost", "Australia Post", "بريد أستراليا", "auspost.com.au", "auspost"),
    _g("canadapost", "Canada Post", "بريد كندا", "canadapost-postescanada.ca canadapost.ca", "canadapost"),
    _g("spotify", "Spotify", "سبوتيفاي", "spotify.com", "", "spotify"),
    _g("disneyplus", "Disney+", "ديزني بلس", "disneyplus.com disney.com", "disneyplus", "disney"),
    _g("discord", "Discord", "ديسكورد", "discord.com discord.gg discordapp.com", "discordapp", "discord"),
    _g("twitch", "Twitch", "تويتش", "twitch.tv", "", "twitch"),
    _g("epicgames", "Epic Games", "إيبك غيمز", "epicgames.com fortnite.com", "epicgames", "fortnite"),
    _g("pubg", "PUBG", "ببجي", "pubg.com pubgmobile.com krafton.com", "pubgmobile", "pubg"),
    _g("garena", "Garena Free Fire", "غارينا فري فاير", "garena.com garena.sg garena.tw garena.co.id garena.vn", "garena", "freefire"),
    _g("playstation", "PlayStation", "بلايستيشن", "playstation.com sony.com", "", "playstation"),
    _g("snapchat", "Snapchat", "سناب شات", "snapchat.com", "snapchat"),
    _g("onlyfans", "OnlyFans", "أونلي فانز", "onlyfans.com", "onlyfans"),
    _g("temu", "Temu", "تيمو", "temu.com", "", "temu"),
    _g("wetransfer", "WeTransfer", "وي ترانسفير", "wetransfer.com", "wetransfer"),
    _g("zoom", "Zoom", "زووم", "zoom.us zoom.com", "", "zoom"),
    _g("intuit", "Intuit", "إنتويت", "intuit.com quickbooks.com turbotax.com", "quickbooks turbotax", "intuit"),
    _g("godaddy", "GoDaddy", "جو دادي", "godaddy.com", "godaddy"),
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
    "emirates.com",          # Emirates airline (not Emirates Post)
    "etihad.com",
    "adnoc.ae",
    "emiratesnbd.com",
    "emiratesrc.ae",         # Emirates Red Crescent (verified 2026-11-23: emiratesrc.ae/en, Wikidata Q7303955)
    # 3-letter labels: trusted, but never look-alike targets (would make "cbd-oil" / "dibs" typo noise).
    "dib.ae",                # Dubai Islamic Bank (checked 2026-11-24: https://www.dib.ae/ footer "Dubai Islamic Bank PJSC")
    "cbd.ae",                # Commercial Bank of Dubai (checked 2026-11-24: https://www.cbd.ae/general/customer-care,
                             # 600 575 556 / customercare@cbd.ae; direct fetch 403, read via the search index)
)

# Known legitimate sites that are NOT UAE institutions and NOT any entity's domain, but whose names collide
# with a brand (so the look-alike rules would flag them). Trusted (SAFE, unjudged, never published to the
# blocklist) like TRUSTED_UAE_DOMAINS, but not counted as UAE institutions (maps_sentinel).
TRUSTED_UNRELATED_DOMAINS: tuple[str, ...] = (
    # AdPolice GmbH-style ad-fraud company, unrelated to Abu Dhabi Police; verified on its website 2026-11-25
    "adpolice.com",
)

# Every registered domain under the gov.ae public suffix is a UAE government site: .aeDA (TDRA) .ae Domain
# Name Policy AEDA-POL-007 s.15 "Eligibility Requirements for gov.ae Restricted Zone" (registrant must be a
# UAE government entity, ministry letter required, UAE-accredited registrars only):
# https://tdra.gov.ae/-/media/aeda/Policies/ae-policies/English/Domain_Name_Policy-EN.ashx (checked 2026-11-24).
# Used by domain_intel.official_match on the REGISTERED domain only (gov.ae.evil.com is not official).
GOV_AE_SUFFIX = "gov.ae"

# Extra official domains of an entity that are NOT used for look-alike matching (a 3-letter label such as
# "epg" would make every 4-letter domain containing it a "typo"). Mail from them is that entity's own mail.
ENTITY_EXTRA_DOMAINS: dict[str, str] = {
    "epg.gov.ae": "emiratespost",  # Emirates Post Group (verified 2026-11-23: epg.gov.ae, custservice@epg.gov.ae)
    # e& UAE consumer site (verified 2026-11-25: https://www.etisalat.ae/en/index.html answers 302 ->
    # https://www.eand.ae/en/index.html, footer "etisalat. All Rights Reserved."; e&'s customer charter PDF
    # cited in VERIFIED_PHONES lives there too)
    "eand.ae": "etisalat",
}

OFFICIAL_DOMAINS: dict[str, Entity | None] = {d: e for e in ALL_BRANDS for d in e.domains}
for _d, _id in ENTITY_EXTRA_DOMAINS.items():
    OFFICIAL_DOMAINS.setdefault(_d, ENTITY_BY_ID[_id])
for _d in (*TRUSTED_UAE_DOMAINS, *TRUSTED_UNRELATED_DOMAINS, *settings.extra_whitelist, *settings.own_hosts):
    OFFICIAL_DOMAINS.setdefault(_d.lower(), None)

# Phone number -> entity
OFFICIAL_PHONES: dict[str, Entity] = {p: e for e in ENTITIES for p in e.phones}

# Numbers confirmed on the entity's own website (checked 2026-11-24). The rest of ENTITIES.phones is demo
# data: 800101 (e& charter lists 101 + 8005800 instead), 155 / 800155 (du.ae unreachable), 600561111 (UAE PASS:
# only third-party / icp.gov.ae search snippets), 600502030 (ADCB: adcb.com answers 403; its pages also list
# 600 50 2322).
VERIFIED_PHONES: dict[str, str] = {
    "999": "https://www.adpolice.gov.ae/en/contact-us",          # Emergency
    "8003333": "https://www.adpolice.gov.ae/en/contact-us",      # Abu Dhabi Police call center
    "8002626": "https://www.adpolice.gov.ae/en/contact-us",      # Aman service
    "2828": "https://www.adpolice.gov.ae/en/Media-Center/News/2021/06/28/ADP-Calls-on-the-Public-to-Communicate-with-Aman-Service",
    "800555": "https://www.tamm.abudhabi/en/contact-us",          # Abu Dhabi Contact Center
    "600599999": "https://www.emiratespost.ae/contact-us",       # "+971 600 599 999" (600599995 is not on the page)
    "101": "https://www.eand.ae/en/system/wst/assets/docs/consumer/general/customer-service-charter-en.pdf",
    "8005800": "https://www.eand.ae/en/system/wst/assets/docs/consumer/general/customer-service-charter-en.pdf",
    "600525500": "https://www.bankfab.com/en-ae/contact-us",     # FAB Service, personal banking
}

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
    """Canonical registry / graph key of a phone number (`phone_intel.PhoneInfo.key`): UAE toll-free and
    shared-cost numbers and short codes keep their national digits (800555, 600599999, 999), whatever way
    they were written (+971 800 555, 971800555, ٨٠٠٥٥٥); every other number is its E.164 digits without
    "+" (971501234567, 18005551234)."""
    if not raw:
        return ""
    return _analyze_phone(raw).key
