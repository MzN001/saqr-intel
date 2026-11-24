"""HTML fixtures for the brand-fingerprint tests: legitimate pages that MENTION a UAE brand (or just look
like a log-in page) and must stay below the clone threshold. All hosts are invented (.example)."""

NEWS_TAMM = ("""<!doctype html><html lang="en"><head><title>TAMM fines: how to pay Abu Dhabi traffic fines online
 | Gulf Daily</title><meta property="og:site_name" content="Gulf Daily">
<style>header{background:#c4161c} a{color:#1a5fb4}</style></head><body><header><img src="/img/gulfdaily-logo.svg"
 alt="Gulf Daily logo"></header><h1>TAMM fines: how to pay Abu Dhabi traffic fines online</h1>
<p>Residents can now settle traffic fines through the TAMM platform (منصة تم) using UAE PASS. Abu Dhabi Police
 reminded motorists that only tamm.abudhabi is official.</p>
<img src="https://www.tamm.abudhabi/assets/images/hero-fines.jpg" alt="TAMM app screenshot">
<form action="/newsletter"><input name="email" placeholder="Your email"></form>
<footer>© 2026 Gulf Daily Media. All rights reserved.</footer></body></html>""", "https://gulfdaily.example/tamm-fines")

PARTNER_UAEPASS = ("""<!doctype html><html lang="en"><head><title>Acme Insurance | Customer log-in</title>
<meta property="og:site_name" content="Acme Insurance"><style>:root{--primary:#0b6e4f}.btn{background:#0b6e4f}</style>
</head><body><header><img src="/static/acme-logo.png" alt="Acme Insurance logo"></header>
<h1>Log in to your policy</h1><form action="/session" method="post"><label for="u">Username</label>
<input id="u" name="username"><label for="p">Password</label><input id="p" type="password" name="password">
<button>Log in</button></form><p>or</p><a href="/auth/uaepass"><img
 src="https://uaepass.ae/assets/UAEPASS_Login_Btn.svg" alt="Sign in with UAE PASS"></a>
<p>Sign in with UAE PASS, the UAE's digital identity (الهوية الرقمية).</p>
<footer>© 2026 Acme Insurance PJSC</footer></body></html>""", "https://portal.acme-insurance.example/login")

BANK_COMPARISON = ("""<!doctype html><html lang="en"><head><title>Best UAE credit cards 2026: ADCB vs FAB vs Emirates NBD
 compared</title><meta property="og:site_name" content="CardCompare UAE"><style>body{color:#222}.cta{background:#ff7a00}</style>
</head><body><h1>Compare credit cards from ADCB, FAB and Emirates NBD</h1>
<img src="https://www.adcb.com/en/Images/adcb-logo.png" alt="ADCB logo">
<img src="https://www.bankfab.com/-/media/fab-logo.svg" alt="FAB logo">
<p>First Abu Dhabi Bank and Abu Dhabi Commercial Bank both offer cashback cards.</p>
<form action="/search"><input name="q" placeholder="Search cards"></form>
<footer>© 2026 CardCompare UAE</footer></body></html>""", "https://cardcompare.example/credit-cards")

GENERIC_BLUE_LOGIN = ("""<!doctype html><html lang="en"><head><title>Member area | Desert Fitness Club</title>
<meta name="theme-color" content="#003da6"><style>:root{--brand-primary:#003da6;--accent:#00102b}
.btn{background:#003da6;color:#fff}</style></head><body><h1>Members sign in</h1>
<form action="/login" method="post"><input name="email" type="email"><input name="password" type="password">
<button>Sign in</button></form><footer>© 2026 Desert Fitness Club LLC</footer></body></html>""",
                      "https://desertfitness.example/members")

DENTAL = ("""<!doctype html><html lang="ar" dir="rtl"><head><title>عيادة الابتسامة - أبوظبي</title></head><body>
<h1>عيادة الابتسامة لطب الأسنان</h1><p>احجز موعدك الآن في أبوظبي.</p><form action="/book"><input name="name">
<input name="phone"></form></body></html>""", "https://smile-clinic.example/")

ARABIC_NEWS_DU = ("""<!doctype html><html lang="fr"><head><title>Le site du voyageur | Conseils</title></head><body>
<h1>Le guide du voyageur à Dubaï</h1><p>Les opérateurs e& et du proposent des cartes SIM touristes.</p>
<footer>© 2026 Le Voyageur</footer></body></html>""", "https://voyageur.example/dubai")

NEGATIVES = {
    "news_tamm_fines": NEWS_TAMM,
    "partner_uaepass_button": PARTNER_UAEPASS,
    "bank_comparison": BANK_COMPARISON,
    "generic_blue_login": GENERIC_BLUE_LOGIN,
    "dental_clinic_ar": DENTAL,
    "french_travel_du": ARABIC_NEWS_DU,
}
