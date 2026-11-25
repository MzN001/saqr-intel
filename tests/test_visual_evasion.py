"""Evasion resistance + visual brand-clone detection (all offline: httpx.MockTransport, no real request).

* JavaScript redirects on full pages (unconditional only), page evidence for every redirect hop
* phone vs desktop (MOBILE_CLOAKING_DETECTED) and its false-positive guards
* brand fingerprint extraction + similarity matrix (demo replica high, legit look-alikes low)
* scoring thresholds, score_breakdown reconciliation, payment-gateway hosts, screenshot path (mocked)
"""
import asyncio
import ipaddress
import os
import struct
import tempfile
import zlib
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr import pipeline  # noqa: E402
from saqr.config import settings  # noqa: E402
from saqr.intel import ai_inspector, brand_fingerprint as bf, page_signals, redirects  # noqa: E402
from saqr.intel import sandbox as sandbox_mod, visual_similarity as vs  # noqa: E402
from saqr.intel.ai_inspector import run_rules  # noqa: E402
from saqr.intel.domain_intel import RedFlag  # noqa: E402
from saqr.intel.threat_feeds import threat_feeds  # noqa: E402
from saqr.seed_data import DEMO_INTEL, replica_html  # noqa: E402

import sys  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from visual_fixtures import NEGATIVES  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
HTML = {"content-type": "text/html; charset=utf-8"}
OLD = {"domain_age_hours": 24 * 365 * 10}
FILLER = "<p>" + "Our clinic offers dental care in Abu Dhabi, open every day of the week. " * 20 + "</p>"
CARD_FORM = ('<form action="/p"><input name="cardnumber"><input name="cvv"><input name="otp"></form>')


async def fake_guard(host: str):
    try:
        return ipaddress.ip_address(host).is_global, [host]
    except ValueError:
        return host != "localhost", []


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def codes(flags) -> set[str]:
    return {f["code"] if isinstance(f, dict) else f.code for f in flags}


# ===========================================================================
# 1a. JavaScript redirects on full pages
# ===========================================================================
def _page(script: str, late: bool = False) -> str:
    if late:
        return f"<html><body>{FILLER * 12}<script>{script}</script></body></html>"
    return f"<html><head><title>Loading</title><script>{script}</script></head><body>{FILLER}</body></html>"


@pytest.mark.parametrize("script,target", [
    ('window.location = "https://evil.example/a";', "https://evil.example/a"),
    ("var t = 1;\ntop.location.href = 'https://evil.example/b'", "https://evil.example/b"),
    ('// moved\nlocation.replace("https://evil.example/c")', "https://evil.example/c"),
    ('window.location.assign("https://evil.example/d");', "https://evil.example/d"),
    ('setTimeout(function(){ window.location.href = "https://evil.example/e"; }, 50);', "https://evil.example/e"),
    ('var s = "{("; self.location = "https:\\/\\/evil.example\\/f";', "https://evil.example/f"),
])
def test_unconditional_js_redirect_on_a_long_page_is_followed(script, target):
    assert redirects.html_redirect(_page(script)) == (target, "js")


@pytest.mark.parametrize("script", [
    'if (isMobile()) { location.href = "https://evil.example/c"; }',
    'if (/iPhone/.test(navigator.userAgent))\n  location.href = "https://evil.example/c";',
    'btn.onclick = () => { location.href = "https://evil.example/h"; }',
    'document.addEventListener("click", function(){ location.assign("https://evil.example/l") })',
    'function go(){ location.href = "https://evil.example/f"; }',
    'loggedIn ? location.href = "https://evil.example/t" : 0',
    'ok && location.replace("https://evil.example/and")',
])
def test_conditional_or_handler_navigation_is_not_followed(script):
    assert redirects.html_redirect(_page(script)) == (None, None)


def test_redirect_far_down_a_long_page_is_not_followed():
    assert redirects.html_redirect(_page('location.href = "https://evil.example/late"', late=True)) == (None, None)


def test_json_ld_or_template_scripts_are_not_code():
    body = _page("").replace("<script></script>",
                             '<script type="application/ld+json">{"x": 1} location.href="https://evil.example/j"</script>')
    assert redirects.html_redirect(body) == (None, None)


# ===========================================================================
# 1b. Page evidence for every hop
# ===========================================================================
@pytest.fixture
def web(monkeypatch):
    routes: dict[str, tuple[int, dict, str]] = {}
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        key = request.url.host + request.url.path
        if key not in routes:
            return httpx.Response(404, headers=HTML, text="not found")
        status, headers, body = routes[key]
        return httpx.Response(status, headers=headers, text="" if request.method == "HEAD" else body)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(redirects, "TRANSPORT", transport)
    monkeypatch.setattr(sandbox_mod, "TRANSPORT", transport)
    monkeypatch.setattr(redirects, "host_is_safe_target", fake_guard)
    monkeypatch.setattr(sandbox_mod, "host_is_safe_target", fake_guard)
    return routes, calls


def scan(client, url: str, run_sandbox: bool = True) -> dict:
    r = client.post("/api/analyze-url", json={"url": url, "run_sandbox": run_sandbox, "use_llm": False})
    assert r.status_code == 200, r.text
    return r.json()


def test_every_html_hop_gets_page_evidence_and_the_worst_hop_is_judged(client, web):
    routes, calls = web
    # A harmless-looking hop whose page collects card + OTP, then forwards scanners to a famous site.
    routes["rb.gy/x"] = (301, {"location": "https://gift-portal.example/claim"}, "")
    routes["gift-portal.example/claim"] = (200, HTML, (
        "<html><head><title>Claim your gift</title><script>window.location.replace('https://www.google.com/');"
        "</script></head><body>" + FILLER + CARD_FORM + "</body></html>"))
    body = scan(client, "https://rb.gy/x")
    chain = body["technical_indicators"]["redirect_chain"]
    hop = next(h for h in chain if h["host"] == "gift-portal.example")
    assert hop["page_risk"] > 0 and "CREDENTIAL_HARVESTING" in hop["page_notes"]
    assert hop["page_title"] == "Claim your gift"
    assert [h["host"] for h in chain] == ["rb.gy", "gift-portal.example", "www.google.com"]
    assert body["domain"] == "gift-portal.example" and body["verdict"] != "SAFE"
    assert {"OTP", "CARD_NUMBER"} <= set(body["technical_indicators"]["harvested_fields"])
    # bodies were reused: every hop fetched at most once with GET, Google never fetched at all
    gets = [u for m, u in calls if m == "GET"]
    assert len(gets) == len(set(gets)) and not any("google" in u for _, u in calls)


def test_hop_records_never_carry_html(client, web):
    routes, _ = web
    routes["t.ly/h"] = (301, {"location": "https://plain-shop.example/"}, "")
    routes["plain-shop.example/"] = (200, HTML, "<html><head><title>Plain shop</title></head><body>" + FILLER + "</body></html>")
    body = scan(client, "https://t.ly/h")
    for h in body["technical_indicators"]["redirect_chain"]:
        assert "html" not in h and set(h) <= {"url", "host", "status", "via", "note", "risk", "page_risk",
                                              "page_notes", "page_title"}
    assert body["verdict"] == "SAFE"


# ===========================================================================
# 2. Phone vs desktop
# ===========================================================================
@pytest.fixture
def http_only():
    saved = {n: getattr(settings, n) for n in ("offline_mode", "sandbox_enabled")}
    object.__setattr__(settings, "offline_mode", False)
    object.__setattr__(settings, "sandbox_enabled", False)
    yield sandbox_mod.Sandbox()
    for name, value in saved.items():
        object.__setattr__(settings, name, value)


def personas(monkeypatch, phone, desktop, bot=None) -> None:
    """phone / desktop / bot: (status, html) or (status, html, redirect_to) per User-Agent; a redirect
    target maps to its own (status, html) in the same dict under the key 'url:<target>'."""
    pages: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        ua = request.headers["user-agent"]
        key = str(request.url)
        if key in pages:
            s, h = pages[key]
            return httpx.Response(s, headers=HTML, text=h)
        view = phone if "iPhone" in ua else desktop if "Windows NT" in ua else (bot or desktop)
        if len(view) == 3:
            pages[view[2]] = view[:2]
            return httpx.Response(302, headers={"location": view[2]})
        return httpx.Response(view[0], headers=HTML, text=view[1])

    monkeypatch.setattr(sandbox_mod, "TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(sandbox_mod, "host_is_safe_target", fake_guard)


def inspect(sb, url="https://pay-fines.example/"):
    return asyncio.run(sb.inspect(url, "pay-fines.example"))


PHONE_FORM = ("<html><head><title>Pay your fine</title></head><body><h1>Traffic fine</h1>"
              + CARD_FORM + "</body></html>")
DESKTOP_HOME = ("<html><head><title>Pay Fines Info</title></head><body>" + FILLER + "</body></html>")
NOT_FOUND = "<html><head><title>404 Not Found</title></head><body>Not Found</body></html>"


def test_phone_only_card_form_is_mobile_cloaking(http_only, monkeypatch):
    personas(monkeypatch, (200, PHONE_FORM), (404, NOT_FOUND))
    page = inspect(http_only)
    mc = page["mobile_cloaking"]
    assert mc["detected"] is True and {"CARD_NUMBER", "OTP"} <= set(mc["phone_only_fields"])
    rr = run_rules(page_signals.lexical("https://pay-fines.example/"), OLD, page, None)
    flag = next(f for f in rr.flags if f.code == "MOBILE_CLOAKING_DETECTED")
    assert flag.points == 25 and "phones" in flag.en and "الهواتف" in flag.ar


def test_phone_sent_to_another_website_is_mobile_cloaking(http_only, monkeypatch):
    personas(monkeypatch, (200, "<html><head><title>Verify</title></head><body>Continue</body></html>",
                           "https://collect-pay-ae.example/start"), (200, DESKTOP_HOME))
    mc = inspect(http_only)["mobile_cloaking"]
    assert mc["detected"] is True and mc["phone_redirected_to"] == "collect-pay-ae.example"


@pytest.mark.parametrize("case", ["responsive", "app_link", "m_subdomain", "amp", "consent", "challenge_403",
                                  "challenge_200", "rate_limited", "password_only_login"])
def test_mobile_cloaking_false_positive_guards(http_only, monkeypatch, case):
    otp_page = ("<html><head><title>Sign in</title></head><body><form><input name='otp'></form></body></html>")
    phone, desktop = {
        "responsive": ((200, PHONE_FORM), (200, PHONE_FORM)),
        "app_link": ((200, otp_page, "https://brand.onelink.me/abc"), (200, DESKTOP_HOME)),
        "m_subdomain": ((200, otp_page, "https://m.pay-fines.example/"), (200, DESKTOP_HOME)),
        "amp": ((200, otp_page, "https://news-site.example/amp/story-1"), (200, DESKTOP_HOME)),
        "consent": ((200, otp_page, "https://consent-gate.example/?continue=1"), (200, DESKTOP_HOME)),
        "challenge_403": ((200, PHONE_FORM), (403, "<html><title>Just a moment...</title>cf-chl</html>")),
        "challenge_200": ((200, PHONE_FORM), (200, "<html><head><title>Attention Required! | Cloudflare"
                                                   "</title></head><body>Please complete the security check"
                                                   "</body></html>")),
        "rate_limited": ((200, PHONE_FORM), (429, "Too many requests")),
        "password_only_login": ((200, "<html><head><title>Log in</title></head><body><form><input "
                                      "type='password' name='pw'></form></body></html>"), (200, DESKTOP_HOME)),
    }[case]
    personas(monkeypatch, phone, desktop)
    page = inspect(http_only)
    assert page["mobile_cloaking"]["detected"] is False, page["mobile_cloaking"]
    rr = run_rules(page_signals.lexical("https://pay-fines.example/"), OLD, page, None)
    assert "MOBILE_CLOAKING_DETECTED" not in codes(rr.flags)


def test_dual_persona_keeps_the_bot_cloaking_check(http_only, monkeypatch):
    decoy = (200, "<html><head><title>Under Construction</title></head><body>soon</body></html>")
    personas(monkeypatch, (200, PHONE_FORM), (200, PHONE_FORM), bot=decoy)
    page = inspect(http_only)
    assert page["cloaking"]["detected"] is True and page["mobile_cloaking"]["detected"] is False


def test_three_personas_are_fetched_concurrently(http_only, monkeypatch):
    seen = []

    def handler(request):
        seen.append(request.headers["user-agent"])
        return httpx.Response(200, headers=HTML, text=DESKTOP_HOME)

    monkeypatch.setattr(sandbox_mod, "TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(sandbox_mod, "host_is_safe_target", fake_guard)
    inspect(http_only)
    assert len(seen) == 3 and any("iPhone" in u for u in seen) and any("Windows NT" in u for u in seen)
    assert sandbox_mod.BOT_USER_AGENT in seen


# ===========================================================================
# 3. Brand fingerprint
# ===========================================================================
def test_baselines_cover_every_portal_with_capture_metadata():
    ids = {b["id"] for b in bf.baselines()}
    assert ids == {"tamm", "uaepass", "adpolice", "emiratespost", "salik", "icp", "adcb", "fab", "emiratesnbd",
                   "etisalat", "du"}
    for b in bf.baselines():
        assert b["status"] in {"full", "partial"} and b["captured_at"] and b["official_domains"] and b["brand_terms"]
        assert "html" not in b and "text" not in b  # derived fingerprints only, never page copies


def test_extract_reads_title_form_colours_and_hotlinked_assets():
    html = ('<html lang="ar" dir="rtl"><head><title>TAMM | Pay - منصة تم</title><meta name="theme-color" content="#5b2c83">'
            '<link rel="icon" href="https://www.tamm.abudhabi/favicon.ico"><link rel="stylesheet" href="/css/tamm-portal.css">'
            '<style>:root{--primary:#5b2c83} .b{color:#f0c36d}</style></head><body><header><img src="https://www.tamm.abudhabi/'
            'logo.svg" alt="TAMM logo"></header><form action="https://203.0.113.9/c.php"><input name="uaepass_username">'
            '<input type="password" name="pw"></form><footer>© 2026 TAMM</footer></body></html>')
    fp = bf.extract(html, "https://tamm-pay.example/")
    assert fp["title_segments"][0] == "tamm" and "منصه تم" in fp["title_segments"]
    assert {"UAE_PASS", "PASSWORD"} <= set(fp["form"]["kinds"]) and fp["form"]["action_hosts"] == ["203.0.113.9"]
    assert fp["colours"][0] == "#5b2c83" and fp["lang"] == "ar" and fp["dir"] == "rtl"
    hot = {(a["kind"], a["host"]) for a in fp["assets"]}
    assert ("favicon", "www.tamm.abudhabi") in hot and ("logo", "www.tamm.abudhabi") in hot
    assert fp["favicon"] == "https://www.tamm.abudhabi/favicon.ico" and "tamm" in fp["copyright"]
    tamm = next(b for b in bf.baselines() if b["id"] == "tamm")
    sim = bf.similarity(fp, tamm)
    assert sim["score"] >= 90 and sim["components"]["assets"] == 100


def test_demo_replica_matches_tamm_strongly():
    for html, url in ((replica_html("tamm-smart-pay.net"), "https://tamm-smart-pay.net/"),
                      ((REPO / "demo-scam-site" / "index.html").read_text(encoding="utf-8"),
                       "https://saqr-demo-scam.vercel.app/")):
        best = bf.best_match(bf.extract(html, url), host="tamm-smart-pay.net")
        assert best["id"] == "tamm" and best["score"] >= bf.CLONE_THRESHOLD, best
        assert len(best["agreeing"]) >= 2


def test_other_replicas_never_match_a_different_brand():
    expected = {"adpolice-fines-ae.info": "adpolice", "emiratespost-track-uae.com": "emiratespost",
                "fab-secure-update.top": "fab", "adcb-card-verify.xyz": "adcb", "du-prize-winner.top": "du"}
    for dom, want in expected.items():
        best = bf.best_match(bf.extract(replica_html(dom), f"https://{dom}/"))
        assert best["id"] == want, (dom, best)


@pytest.mark.parametrize("name", sorted(NEGATIVES))
def test_legitimate_pages_mentioning_a_brand_stay_below_the_clone_threshold(name):
    html, url = NEGATIVES[name]
    fp = bf.extract(html, url)
    scores = {b["id"]: bf.similarity(fp, b)["score"] for b in bf.baselines()}
    assert max(scores.values()) < bf.CLONE_THRESHOLD, scores
    assert max(scores.values()) < bf.WEAK_THRESHOLD, scores  # not even weak corroboration


def test_generic_evidence_alone_is_capped():
    """Same colours + same form shape, no brand name / asset: never above 40."""
    fab = next(b for b in bf.baselines() if b["id"] == "fab")
    fp = bf.extract(NEGATIVES["generic_blue_login"][0], NEGATIVES["generic_blue_login"][1])
    sim = bf.similarity(fp, fab)
    assert sim["components"]["colours"] >= 50 and sim["components"]["form"] >= 50 and sim["score"] <= 40


def test_short_brand_names_need_a_title_segment():
    fp = bf.extract(NEGATIVES["french_travel_du"][0], NEGATIVES["french_travel_du"][1])
    assert "du" not in bf.brands_named(fp)
    fp = bf.extract("<html><head><title>du | Mobile plans</title></head></html>", "https://x.example/")
    assert "du" in bf.brands_named(fp)


def test_official_portal_is_never_its_own_clone():
    fp = bf.extract(replica_html("tamm-smart-pay.net"), "https://www.tamm.abudhabi/")
    best = bf.best_match(fp, host="www.tamm.abudhabi")
    assert best["id"] != "tamm"


def test_official_domains_are_never_fetched_or_judged(client, monkeypatch):
    called = []
    monkeypatch.setattr(bf, "extract", lambda *a, **k: called.append(a) or {})
    for url in ("https://www.tamm.abudhabi/en/pay", "https://smartservices.icp.gov.ae/", "https://www.adcb.com/"):
        body = scan(client, url)
        assert body["verdict"] == "SAFE" and body["risk_score"] == 0 and body["visual_similarity"] is None
    assert not called


# ===========================================================================
# 5. Scoring
# ===========================================================================
def _vis(score, entity="TAMM", entity_id="tamm"):
    return {"score": score, "matched_entity": entity, "matched_entity_ar": "تم", "entity_id": entity_id,
            "matched_domain": "tamm.abudhabi", "components": {}, "screenshot_used": False, "official": False}


def _rules(host, vis, **page):
    return run_rules(page_signals.lexical(f"https://{host}/"), OLD,
                     {"page_title": "", "text": "", "harvested_fields": [], "visual_similarity": vis, **page}, None)


def test_clone_at_75_is_a_strong_flag_naming_the_portal():
    rr = _rules("refund-centre.example", _vis(87))
    flag = next(f for f in rr.flags if f.code == "VISUAL_BRAND_CLONE_DETECTED")
    assert flag.points == 35 and "87% like the real TAMM portal" in flag.en and "TAMM's" in flag.en
    assert "87" in flag.ar and "تم" in flag.ar
    assert rr.verdict == "SUSPICIOUS" and rr.entity is not None and rr.entity.id == "tamm"


def test_clone_with_a_card_form_is_high_risk():
    rr = _rules("refund-centre.example", _vis(87), harvested_fields=["PASSWORD", "UAE_PASS"])
    assert rr.verdict == "HIGH-RISK SCAM" and rr.score >= 70


@pytest.mark.parametrize("score", [50, 74])
def test_50_to_74_is_weak_corroboration_only(score):
    rr = _rules("dubai-dental.example", _vis(score))
    assert rr.score == _rules("dubai-dental.example", None).score and rr.verdict == "SAFE"
    assert next(f for f in rr.flags if f.code == "VISUAL_BRAND_SIMILARITY").points == 0
    # next to strong evidence it counts
    rr = _rules("dubai-dental.example", _vis(score), harvested_fields=["OTP"])
    assert next(f for f in rr.flags if f.code == "VISUAL_BRAND_SIMILARITY").points == 10


def test_weak_visual_similarity_never_tips_a_result_over_the_block_line():
    page = {"harvested_fields": ["OTP", "CARD_NUMBER", "CVV"], "text": "pay immediately"}
    base = _rules("dubai-dental.example", None, **page)
    assert base.score == 55 and base.verdict == "SUSPICIOUS"
    rr = _rules("dubai-dental.example", _vis(60), **page)
    assert rr.score == 64 and rr.verdict == "SUSPICIOUS"
    assert sum(f.points for f in rr.flags) == rr.score  # breakdown still reconciles
    assert next(f for f in rr.flags if f.code == "VISUAL_BRAND_SIMILARITY").points == 9
    # already over the line without it: the weak flag keeps its full points
    more = {**page, "external_form_actions": ["https://collect.example/x"]}
    assert _rules("dubai-dental.example", None, **more).score == 65
    rr = _rules("dubai-dental.example", _vis(60), **more)
    assert rr.score == 75 and next(f for f in rr.flags if f.code == "VISUAL_BRAND_SIMILARITY").points == 10
    # the strong clone flag (>= 75%) is unchanged and still blocks
    rr = _rules("dubai-dental.example", _vis(87), **page)
    assert rr.verdict == "HIGH-RISK SCAM" and "VISUAL_BRAND_CLONE_DETECTED" in codes(rr.flags)


def test_below_50_adds_nothing():
    assert not codes(_rules("refund-centre.example", _vis(49)).flags) & {
        "VISUAL_BRAND_SIMILARITY", "VISUAL_BRAND_CLONE_DETECTED"}


def test_clone_signal_is_weak_on_payment_gateways_and_popular_sites():
    for host in ("paypage.ngenius-payments.com", "secure.telr.com", "www.wikipedia.org"):
        rr = _rules(host, _vis(90))
        assert "VISUAL_BRAND_CLONE_DETECTED" not in codes(rr.flags), host
        assert rr.verdict == "SAFE", (host, rr.score)


# ===========================================================================
# Payment gateways: judged by content, never trusted, never published
# ===========================================================================
@pytest.mark.parametrize("host", ["paypage.ngenius-payments.com", "checkout.network.ae", "sbcheckout.payfort.com",
                                  "secure.telr.com", "pay.magnati.com", "pay.noonpayments.com", "secure.paytabs.com",
                                  "pay.checkout.com", "checkout.stripe.com"])
def test_merchant_checkout_on_a_gateway_is_safe(host):
    lex = page_signals.lexical(f"https://{host}/pay/ORD-123456?ref=abc")
    assert page_signals.payment_gateway(host) and not lex.is_whitelisted
    assert ai_inspector.url_model_result(lex) is None  # the gateway's address is not the merchant's
    page = {"page_title": "e& bill payment", "text": "Pay your Etisalat bill", "final_url": f"https://{host}/",
            "harvested_fields": ["CARD_NUMBER", "CVV", "CARD_EXPIRY"]}
    rr = run_rules(lex, OLD, page, None)
    assert rr.verdict == "SAFE", (rr.score, [(f.code, f.points) for f in rr.flags])


def test_otp_pin_on_a_gateway_is_still_judged():
    page = {"page_title": "Verify", "text": "", "harvested_fields": ["CARD_NUMBER", "CVV", "OTP", "ATM_PIN"],
            "final_url": "https://secure.telr.com/"}
    rr = run_rules(page_signals.lexical("https://secure.telr.com/x"), OLD, page, None)
    assert rr.verdict != "SAFE"


def test_same_card_page_off_a_gateway_is_still_flagged():
    page = {"page_title": "e& bill payment", "text": "Pay your Etisalat bill", "final_url": "https://x/",
            "harvested_fields": ["CARD_NUMBER", "CVV", "CARD_EXPIRY"]}
    rr = run_rules(page_signals.lexical("https://etisalat-bill-pay.example/"), OLD, page, None)
    assert rr.verdict == "HIGH-RISK SCAM"


def test_gateway_host_is_never_published(client, monkeypatch):
    monkeypatch.setattr(threat_feeds, "lookup", lambda host: "TestFeed" if host == "pay.telr.com" else None)
    body = scan(client, "https://pay.telr.com/evil", run_sandbox=False)
    assert body["verdict"] == "HIGH-RISK SCAM"
    published = {d["domain"] for d in client.get("/api/dns-blocklist?min_score=0").json()["domains"]}
    assert not {d for d in published if d.endswith("telr.com")}


# ===========================================================================
# Demo moment + score_breakdown
# ===========================================================================
def test_mock_scam_tamm_page_is_a_visual_clone_of_tamm(client):
    body = scan(client, "http://127.0.0.1:8000/mock-scam/tamm-fine")
    vis = body["visual_similarity"]
    assert vis["matched_entity"] == "TAMM" and vis["matched_domain"] == "tamm.abudhabi"
    assert vis["score"] >= 75 and vis["screenshot_used"] is False
    assert set(vis["components"]) == {"title", "assets", "colours", "form", "favicon"}
    flag = next(f for f in body["red_flags"] if f["code"] == "VISUAL_BRAND_CLONE_DETECTED")
    assert "TAMM" in flag["en"] and flag["points"] == 35
    assert body["verdict"] == "HIGH-RISK SCAM"


def _reconciles(body):
    parts = body["score_breakdown"]
    assert [p["layer"] for p in parts][:8] == ["url_model", "address", "redirects", "page", "cloaking", "visual",
                                               "threat_feeds", "domain_age_tls"]
    assert parts[-1]["layer"] == "ai_judge"
    assert sum(p["points"] for p in parts) == body["risk_score"], parts
    for p in parts:
        assert p["summary_en"] and p["summary_ar"] and p["name_ar"]


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000/mock-scam/tamm-fine", "https://adcb-card-verify.xyz/",
                                 "https://dubai-dental.example/", "https://www.tamm.abudhabi/",
                                 "https://tamm-refund-verify.xyz/login"])
def test_score_breakdown_reconciles_with_the_score(client, url):
    _reconciles(scan(client, url, run_sandbox=True))


def test_score_breakdown_represents_the_llm_blend_and_the_cap():
    flags = [RedFlag("BRAND_IMPERSONATION", "high", 40, "x", "y"), RedFlag("CREDENTIAL_HARVESTING", "critical", 45, "a", "b"),
             RedFlag("NEWLY_REGISTERED", "critical", 25, "c", "d"), RedFlag("URL_SHORTENER", "info", 0, "e", "f")]
    parts = pipeline.score_breakdown(flags, rules_score=100, final_score=96, engine="gemini:x")
    by = {p["layer"]: p["points"] for p in parts}
    assert by["address"] == 40 and by["page"] == 45 and by["domain_age_tls"] == 25 and by["redirects"] == 0
    assert by["combination"] == -10 and by["ai_judge"] == -4 and sum(by.values()) == 96
    floor = pipeline.score_breakdown([RedFlag("AI_PHISHING_URL", "high", 45, "a", "b"),
                                      RedFlag("YOUNG_DOMAIN", "medium", 15, "c", "d")], 70, 70, "rules")
    assert {p["layer"]: p["points"] for p in floor}["combination"] == 10


# ===========================================================================
# 4. Screenshot similarity (fully mocked)
# ===========================================================================
def make_png(w: int, h: int, fn) -> bytes:
    raw = b"".join(b"\x00" + bytes(c for x in range(w) for c in fn(x, y)) for y in range(h))

    def chunk(kind, data):
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


GRADIENT = make_png(40, 40, lambda x, y: ((x * 6) % 256, (y * 5) % 256, ((x + y) * 3) % 256))
BLANK = make_png(40, 40, lambda x, y: (250, 250, 250))


def test_dhash_basics():
    h = vs.dhash_bytes(GRADIENT)
    assert h is not None and vs.similarity(h, h) == 100 and vs.similarity(h, h ^ 0xFF) == 88
    assert vs.dhash_bytes(BLANK) is None  # a loading spinner / empty shell gives no hash
    assert vs.dhash_bytes(b"not an image") is None


@pytest.fixture
def shots(monkeypatch):
    calls = []
    state = {"mode": "ok"}

    def handler(request):
        calls.append(str(request.url))
        if state["mode"] == "timeout":
            raise httpx.ReadTimeout("slow", request=request)
        if state["mode"] == "blank":
            return httpx.Response(200, headers={"content-type": "image/png"}, content=BLANK)
        return httpx.Response(200, headers={"content-type": "image/png"}, content=GRADIENT)

    monkeypatch.setattr(vs, "TRANSPORT", httpx.MockTransport(handler))
    return calls, state


def test_thumio_screenshot_is_hashed(shots):
    calls, _ = shots
    res = asyncio.run(vs.capture_hash("https://refund-centre.example/pay"))
    assert res == {"hash": vs.to_hex(vs.dhash_bytes(GRADIENT)), "source": "thumio"}
    assert calls == ["https://image.thum.io/get/png/width/160/https://refund-centre.example/pay"]


def test_screenshot_timeout_and_blank_fail_silently(shots):
    _, state = shots
    state["mode"] = "timeout"
    assert asyncio.run(vs.capture_hash("https://refund-centre.example/", timeout=1)) is None
    state["mode"] = "blank"
    assert asyncio.run(vs.capture_hash("https://refund-centre.example/", timeout=1)) is None


@pytest.mark.parametrize("url", ["http://127.0.0.1:8000/mock-scam/tamm-fine", "http://10.0.0.5/admin",
                                 "https://www.tamm.abudhabi/", "https://smartservices.icp.gov.ae/",
                                 "http://localhost:3000/", "https://tamm-smart-pay.net/"])
def test_screenshots_are_never_taken_for_official_private_or_demo_hosts(shots, url):
    calls, _ = shots
    assert asyncio.run(vs.capture_hash(url)) is None and not calls


def test_offline_mode_takes_no_screenshot():
    assert settings.offline_mode and vs.TRANSPORT is None
    assert asyncio.run(vs.capture_hash("https://refund-centre.example/")) is None


def test_mshots_placeholder_is_detected():
    req = httpx.Request("GET", "https://s0.wp.com/mshots/v1/x?w=160")
    assert vs._is_mshots_placeholder(httpx.Response(307, headers={"location": "https://s0.wp.com/mshots/v1/default"},
                                                    request=req))
    assert vs._is_mshots_placeholder(httpx.Response(200, headers={"content-type": "image/gif"}, request=req))
    assert not vs._is_mshots_placeholder(httpx.Response(200, headers={"content-type": "image/jpeg"}, request=req))


def test_screenshot_switch_and_corroboration(monkeypatch):
    """The pipeline asks for a screenshot only when switched on, network allowed and the page is suspicious;
    a near-identical hash of the SAME portal raises the fingerprint score, a hash alone never makes a clone."""
    adp = next(b for b in bf.baselines() if b["id"] == "adpolice")
    calls = []

    async def fake_capture(url, page=None, timeout=6.0):
        calls.append(url)
        return {"hash": adp["dhash"]["thumio"], "source": "thumio"}

    async def no_favicon(url, timeout=3.0):
        return None

    monkeypatch.setattr(vs, "capture_hash", fake_capture)
    monkeypatch.setattr(bf, "fetch_favicon_hash", no_favicon)
    lex = page_signals.lexical("https://adp-fines-pay.example/")
    page = {"status": "ok", "final_url": "https://adp-fines-pay.example/",
            "html": replica_html("adpolice-fines-ae.info")}

    def run(enabled, allow=True):
        object.__setattr__(settings, "visual_screenshots", enabled)
        try:
            return asyncio.run(pipeline.visual_similarity_for(lex, page, deep=True, net=OLD, syndicate=None,
                                                              allow_network=allow))
        finally:
            object.__setattr__(settings, "visual_screenshots", True)

    off = run(False)
    assert not calls and off["screenshot_used"] is False
    assert run(True, allow=False)["screenshot_used"] is False and not calls
    on = run(True)
    assert calls and on["screenshot_used"] is True and on["screenshot_similarity"] == 100
    assert on["score"] > on["fingerprint_score"]
    # an unrelated page whose screenshot happens to match never becomes a clone through the hash alone
    page2 = {"status": "ok", "final_url": "https://x.example/", "html": NEGATIVES["dental_clinic_ar"][0]}
    object.__setattr__(settings, "visual_screenshots", True)
    res = asyncio.run(pipeline.visual_similarity_for(page_signals.lexical("https://x.example/"), page2, deep=True,
                                                     net=OLD, syndicate=None, allow_network=True))
    assert res["score"] < bf.CLONE_THRESHOLD


def test_png_path_never_needs_pillow(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_pil(name, *a, **k):
        if name == "PIL" or name.startswith("PIL."):
            raise ImportError("Pillow blocked in this test")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_pil)
    assert vs.dhash_bytes(GRADIENT) is not None and vs.png_gray(GRADIENT)[:2] == (40, 40)


@pytest.mark.parametrize("calibrated,shown", [(0.71, "71%"), (None, "99%")])
def test_url_model_text_shows_calibrated_probability_with_raw_fallback(monkeypatch, calibrated, shown):
    res = {"probability": 0.99, "calibrated_probability": calibrated, "reasons": []}
    monkeypatch.setattr(ai_inspector, "url_model_result", lambda lex: res)
    flag = next(f for f in ai_inspector.intel_flags(page_signals.lexical("https://odd-name-x1.example/"))
                if f.code == "AI_PHISHING_URL")
    assert f"rates this address {shown} likely" in flag.en
    assert flag.points == 65  # the decision still follows the RAW probability (0.99 >= certain)


def test_seeded_demo_domains_have_replica_fingerprints():
    for dom in DEMO_INTEL:
        assert bf.extract(replica_html(dom), f"https://{dom}/")["title"]
