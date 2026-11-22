"""Pre-seeded Abu Dhabi cyber-fraud intelligence (synthetic demo data).

All infrastructure below is fictitious for the hackathon demo. ASNs are taken from
the private-use range (AS64512–AS65534) so no real network is defamed. Domains are
treated as hostile and are NEVER fetched live: the sandbox renders the replica HTML
stored here so the demo works fully offline.
"""
from __future__ import annotations

import re

SYNDICATES = [
    {
        "id": "SYN-SANDVIPER",
        "name": "Sand Viper Syndicate",
        "name_ar": "شبكة أفعى الرمال",
        "seed_node": "ip:185.220.101.44",
        "description": "Multi-brand government & courier impersonation ring sharing one bulletproof VPS, "
                       "one Let's Encrypt issuance pattern and a hijacked Google Maps pin in Mussafah.",
    },
    {
        "id": "SYN-DESERTMIRAGE",
        "name": "Desert Mirage Crew",
        "name_ar": "مجموعة سراب الصحراء",
        "seed_node": "ip:203.0.113.77",
        "description": "Banking OTP-harvesting kit targeting FAB and ADCB customers via WhatsApp lures.",
    },
]

# Hostile infrastructure — used both for the graph and as offline evidence.
DEMO_INTEL: dict[str, dict] = {
    "adpolice-fines-ae.info": {
        "ip": "185.220.101.44", "asn": "AS64512", "asn_org": "OFFSHORE-VPS-LTD (seed data)", "country": "SC",
        "registrar": "NameSilo-like Budget Registrar (seed)", "registered_hours_ago": 3,
        "abuse_emails": ["abuse@budget-registrar.example"], "name_servers": ["ns1.fastdns-park.example", "ns2.fastdns-park.example"],
        "ssl_issuer": "commonName=R11, organizationName=Let's Encrypt", "cert_age_hours": 2.5,
        "page_title": "شرطة أبوظبي | دفع المخالفات المرورية - Abu Dhabi Police Fines",
        "page_text": "Abu Dhabi Police — Traffic Fines Payment. You have 2 unpaid fines (AED 1,250). Pay within 24 hours "
                     "to avoid vehicle impoundment and a 50% discount loss. شرطة أبوظبي - لديك مخالفات غير مدفوعة. "
                     "ادفع خلال 24 ساعة لتجنب حجز المركبة. Enter Emirates ID, card number, expiry, CVV and the OTP sent to you.",
        "forms": [{"action": "https://185.220.101.44/gate/collect.php", "method": "post",
                   "fields": ["emirates_id", "full_name", "card_number", "exp_date", "cvv", "otp"]}],
        "entity": "adpolice", "cloaking": True, "accent": "#0b3d2e",
    },
    "emiratespost-track-uae.com": {
        "ip": "185.220.101.44", "asn": "AS64512", "asn_org": "OFFSHORE-VPS-LTD (seed data)", "country": "SC",
        "registrar": "NameSilo-like Budget Registrar (seed)", "registered_hours_ago": 30,
        "abuse_emails": ["abuse@budget-registrar.example"], "name_servers": ["ns1.fastdns-park.example", "ns2.fastdns-park.example"],
        "ssl_issuer": "commonName=R11, organizationName=Let's Encrypt", "cert_age_hours": 29,
        "page_title": "Emirates Post | Your parcel is on hold - بريد الإمارات",
        "page_text": "Emirates Post: Your parcel AE-77812 is on hold due to an incomplete address. Pay AED 7.50 redelivery fee "
                     "to release your shipment. بريد الإمارات: شحنتك محتجزة. ادفع 7.50 درهم رسوم إعادة التوصيل. "
                     "Card number, CVV, OTP verification required.",
        "forms": [{"action": "https://185.220.101.44/gate/collect.php", "method": "post",
                   "fields": ["full_name", "phone", "card_number", "exp_date", "cvv", "otp"]}],
        "entity": "emiratespost", "cloaking": True, "accent": "#c8102e",
    },
    "tamm-smart-pay.net": {
        "ip": "185.220.101.44", "asn": "AS64512", "asn_org": "OFFSHORE-VPS-LTD (seed data)", "country": "SC",
        "registrar": "NameSilo-like Budget Registrar (seed)", "registered_hours_ago": 5,
        "abuse_emails": ["abuse@budget-registrar.example"], "name_servers": ["ns1.fastdns-park.example", "ns2.fastdns-park.example"],
        "ssl_issuer": "commonName=R11, organizationName=Let's Encrypt", "cert_age_hours": 4,
        "page_title": "TAMM | Smart Payment Portal - منصة تم",
        "page_text": "TAMM Abu Dhabi Government Services — your service fee refund of AED 340 is waiting. Sign in with UAE PASS "
                     "to claim before it expires today. منصة تم: لديك مبلغ مسترد. سجل الدخول عبر UAE PASS. "
                     "UAE PASS username, password and OTP required.",
        "forms": [{"action": "https://185.220.101.44/gate/uaepass.php", "method": "post",
                   "fields": ["uaepass_username", "password", "otp", "card_number", "cvv"]}],
        "entity": "tamm", "cloaking": True, "accent": "#5b2c83",
    },
    "fab-secure-update.top": {
        "ip": "203.0.113.77", "asn": "AS64520", "asn_org": "NIGHTOWL-HOSTING (seed data)", "country": "NL",
        "registrar": "Anonymous-Reg Ltd (seed)", "registered_hours_ago": 52,
        "abuse_emails": ["abuse@anonymous-reg.example"], "name_servers": ["ns1.nightowl.example"],
        "ssl_issuer": "commonName=E5, organizationName=Let's Encrypt", "cert_age_hours": 50,
        "page_title": "FAB Online Banking - Card Update",
        "page_text": "First Abu Dhabi Bank: your debit card has been temporarily blocked. Update your card details and confirm the OTP "
                     "to reactivate. بنك أبوظبي الأول: تم حظر بطاقتك مؤقتاً.",
        "forms": [{"action": "/api/save", "method": "post", "fields": ["card_number", "exp_date", "cvv", "otp", "pin"]}],
        "entity": "fab", "accent": "#00205b",
    },
    "adcb-card-verify.xyz": {
        "ip": "203.0.113.77", "asn": "AS64520", "asn_org": "NIGHTOWL-HOSTING (seed data)", "country": "NL",
        "registrar": "Anonymous-Reg Ltd (seed)", "registered_hours_ago": 20,
        "abuse_emails": ["abuse@anonymous-reg.example"], "name_servers": ["ns1.nightowl.example"],
        "ssl_issuer": "commonName=E5, organizationName=Let's Encrypt", "cert_age_hours": 19,
        "page_title": "ADCB | Verify Suspicious Transaction",
        "page_text": "ADCB Security Alert: a transaction of AED 4,999 is pending. If this was not you, verify your card now "
                     "and enter the OTP. بنك أبوظبي التجاري: معاملة مشبوهة.",
        "forms": [{"action": "/api/save", "method": "post", "fields": ["card_number", "exp_date", "cvv", "otp"]}],
        "entity": "adcb", "accent": "#e30613",
    },
    "du-prize-winner.top": {
        "ip": "198.51.100.23", "asn": "AS64601", "asn_org": "CHEAPCLOUD-VPS (seed data)", "country": "US",
        "registrar": "Budget Domains Inc (seed)", "registered_hours_ago": 400,
        "abuse_emails": ["abuse@budget-domains.example"], "name_servers": ["ns1.cheapcloud.example"],
        "ssl_issuer": "commonName=R10, organizationName=Let's Encrypt", "cert_age_hours": 390,
        "page_title": "du 20th Anniversary Prize Draw",
        "page_text": "Congratulations! Your du number won AED 10,000. Pay AED 25 processing fee to claim your prize.",
        "forms": [{"action": "/claim", "method": "post", "fields": ["phone", "card_number", "cvv"]}],
        "entity": "du", "accent": "#00a9ce",
    },
}

# Hijacked / fake Google Maps listings
MAP_PINS = [
    {
        "id": "pin:mussafah-adp-fines",
        "name": "Abu Dhabi Police – Traffic Fines Payment Center",
        "lat": 24.3489, "lng": 54.5052, "area": "Mussafah M-37 (vacant plot)",
        "website": "adpolice-fines-ae.info", "phone": "+971 50 000 7781",
        "place_type": "vacant_lot", "verified": False, "reviews": 3,
        "syndicate": "SYN-SANDVIPER",
    },
    {
        "id": "pin:mussafah-emiratespost",
        "name": "Emirates Post Parcel Collection – Mussafah",
        "lat": 24.3501, "lng": 54.5068, "area": "Mussafah M-37 (residential villa)",
        "website": "emiratespost-track-uae.com", "phone": "+971 50 000 7781",
        "place_type": "residential", "verified": False, "reviews": 1,
        "syndicate": "SYN-SANDVIPER",
    },
    {
        "id": "pin:khalifa-tamm-kiosk",
        "name": "TAMM Smart Payment Kiosk",
        "lat": 24.4210, "lng": 54.5790, "area": "Khalifa City A (empty retail unit)",
        "website": "tamm-smart-pay.net", "phone": "+971 50 000 7781",
        "place_type": "vacant_lot", "verified": False, "reviews": 0,
        "syndicate": "SYN-SANDVIPER",
    },
]

CITIZEN_REPORTS = [
    {"id": "report:CR-1001", "target": "adpolice-fines-ae.info", "channel": "sms", "hours_ago": 2,
     "message": "AD Police: You have unpaid fines AED 1250. Pay now to avoid impound: adpolice-fines-ae.info"},
    {"id": "report:CR-1002", "target": "adpolice-fines-ae.info", "channel": "whatsapp", "hours_ago": 1,
     "message": "شرطة أبوظبي: لديك مخالفة مرورية، ادفع الآن adpolice-fines-ae.info"},
    {"id": "report:CR-1003", "target": "emiratespost-track-uae.com", "channel": "sms", "hours_ago": 20,
     "message": "Emirates Post: your parcel is on hold. Pay AED 7.50: emiratespost-track-uae.com"},
    {"id": "report:CR-1004", "target": "tamm-smart-pay.net", "channel": "sms", "hours_ago": 4,
     "message": "TAMM: Refund AED 340 pending. Claim via UAE PASS today: tamm-smart-pay.net"},
    {"id": "report:CR-1005", "target": "pin:mussafah-adp-fines", "channel": "maps", "hours_ago": 6,
     "message": "Google Maps listing for 'AD Police fines center' sent me to a payment site."},
    {"id": "report:CR-1006", "target": "fab-secure-update.top", "channel": "whatsapp", "hours_ago": 40,
     "message": "FAB: your card is blocked, update here fab-secure-update.top"},
    {"id": "report:CR-1007", "target": "adcb-card-verify.xyz", "channel": "email", "hours_ago": 12,
     "message": "ADCB Security: verify suspicious transaction adcb-card-verify.xyz"},
    {"id": "report:CR-1008", "target": "du-prize-winner.top", "channel": "sms", "hours_ago": 300,
     "message": "du: you won AED 10,000! du-prize-winner.top"},
]

CT_SEED = [
    ("adpolice-fines-ae.info", 3), ("tamm-smart-pay.net", 5), ("adcb-card-verify.xyz", 19),
    ("emiratespost-track-uae.com", 29), ("uaepass-verify-login.online", 1),
]


def replica_html(domain: str) -> str:
    """Self-contained replica of the phishing page for offline sandbox screenshots."""
    d = DEMO_INTEL[domain]
    fields = "".join(
        f'<label>{f.replace("_", " ").title()}</label><input name="{f}" placeholder="{f.replace("_", " ")}">'
        for f in d["forms"][0]["fields"]
    )
    return f"""<!doctype html><html lang="ar" dir="auto"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{d['page_title']}</title>
<style>body{{font-family:system-ui,Segoe UI,Tahoma,sans-serif;margin:0;background:#f4f4f4}}
header{{background:{d['accent']};color:#fff;padding:18px;font-weight:700;font-size:18px}}
main{{padding:16px}}.card{{background:#fff;border-radius:10px;padding:16px;box-shadow:0 2px 8px #0002}}
.warn{{background:#fff3cd;border:1px solid #f0c36d;padding:10px;border-radius:8px;margin-bottom:12px;font-size:14px}}
label{{display:block;font-size:12px;color:#555;margin-top:10px}}input{{width:100%;padding:10px;border:1px solid #ccc;border-radius:6px;box-sizing:border-box}}
button{{margin-top:16px;width:100%;padding:12px;background:{d['accent']};color:#fff;border:0;border-radius:6px;font-size:16px}}</style>
</head><body><header>{d['page_title']}</header><main><div class="card"><div class="warn">{d['page_text'][:260]}</div>
<form action="{d['forms'][0]['action']}" method="post">{fields}<button type="button">Pay / ادفع الآن</button></form></div></main></body></html>"""


# Local training replicas served by the backend at /mock-scam/<slug>. A link pointing at one of
# these on a loopback host is analysed as the seeded hostile domain it replicates.
MOCK_SCAM_SLUGS = {
    "tamm-fine": "tamm-smart-pay.net",
    "emiratespost": "emiratespost-track-uae.com",
    "adpolice-fines": "adpolice-fines-ae.info",
    "adcb": "adcb-card-verify.xyz",
    "fab": "fab-secure-update.top",
}
_LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def resolve_mock_scam(url: str) -> tuple[str, str | None]:
    """Map http://127.0.0.1:8000/mock-scam/<slug>/... to https://<seeded-domain>/... (else unchanged)."""
    from urllib.parse import urlsplit

    raw = url.strip()
    try:
        parts = urlsplit(raw if "://" in raw else "http://" + raw)
        host = (parts.hostname or "").lower()
    except ValueError:
        return url, None
    m = re.match(r"^/mock-scam/([a-z0-9-]+)(/.*)?$", parts.path or "")
    if host not in _LOCAL_HOSTS or not m or m.group(1) not in MOCK_SCAM_SLUGS:
        return url, None
    rest = (m.group(2) or "/") + (f"?{parts.query}" if parts.query else "")
    return f"https://{MOCK_SCAM_SLUGS[m.group(1)]}{rest}", m.group(1)
