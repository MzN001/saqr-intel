"""SMS / WhatsApp message forensics (POST /api/analyze-message, saqr/intel/message_intel.py) plus the
package-C additions to email (call-back numbers, MX) and websites (TLS weak signal, verified_official).

Near-zero false positives: weak wording ("fine", "OTP", "Emirates ID") never scores alone; a genuine bank
OTP SMS, TAMM receipt or Emirates Post notice is SAFE. Run: pytest -q tests/test_message_intel.py
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import asyncio  # noqa: E402
import json  # noqa: E402
import sqlite3  # noqa: E402
import time  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.intel import email_auth, message_intel, page_signals, phone_intel  # noqa: E402
from saqr.intel import email_rules as R  # noqa: E402
from saqr.intel.ai_inspector import run_rules  # noqa: E402
from saqr.intel.email_types import Address, AuthARC, AuthDKIM, AuthDMARC, AuthReport, AuthSPF, ParsedEmail  # noqa: E402
from saqr.ws_hub import hub, public_view  # noqa: E402

SCAM_LINK = "https://tamm-smart-pay.net/fine"  # seeded scam domain (offline intel)


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def scan(client, text, sender=None, **extra):
    body = {"text": text, "use_llm": False, **extra}
    if sender is not None:
        body["sender"] = sender
    r = client.post("/api/analyze-message", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def codes(res):
    return {f["code"] for f in res["red_flags"] if f["points"] > 0}


def row(scan_id):
    con = sqlite3.connect(os.environ["DATABASE_PATH"])
    try:
        return con.execute("SELECT kind, target, domain, result_json FROM scans WHERE id=?", (scan_id,)).fetchone()
    finally:
        con.close()


# ---------------------------------------------------------------------------------------------- scams
def test_fake_tamm_fine_with_lookalike_link_from_personal_mobile_is_high_risk(client):
    r = scan(client, f"TAMM: You have an unpaid traffic fine of AED 350. Pay within 24 hours to avoid impound: "
                     f"{SCAM_LINK}", "+971 50 123 4567")
    assert r["kind"] == "message" and r["verdict"] == "HIGH-RISK SCAM" and r["risk_score"] >= 65
    assert {"MSG_SCAM_LINK", "MSG_LOOKALIKE_LINK", "SENDER_MOBILE_FOR_INSTITUTION"} <= codes(r)
    assert r["impersonated_entity"] == "TAMM Abu Dhabi" and r["verified_official"] is False
    link = r["links"][0]
    assert link["domain"] == "tamm-smart-pay.net" and link["verdict"] == "HIGH-RISK SCAM" and link["scan_id"]
    # the link was saved as its own URL scan: that is how it reaches the DNS blocklist
    assert row(link["scan_id"])[0] == "url" and row(link["scan_id"])[2] == "tamm-smart-pay.net"


def test_police_from_uk_number_asking_to_call_back_is_flagged(client):
    r = scan(client, "Abu Dhabi Police: Your vehicle file has been blocked. Call us back urgently on "
                     "+44 20 7946 0958 to resolve it.", "+44 20 7946 0000")
    assert r["verdict"] != "SAFE" and r["risk_score"] >= 30
    assert "CALLBACK_FOREIGN_FOR_INSTITUTION" in codes(r)
    assert any(p["status"] == "foreign_for_institution" for p in r["phones"])


def test_bank_asking_to_reply_with_otp_is_flagged(client):
    r = scan(client, "ADCB: Your card has been temporarily blocked. Reply with the OTP you receive to reactivate it.",
             "ADCB")
    assert r["verdict"] == "HIGH-RISK SCAM" and "MSG_CREDENTIAL_REQUEST" in codes(r)
    assert r["impersonated_entity"] == "ADCB"


def test_police_fine_demand_from_personal_mobile_without_link_is_at_least_suspicious(client):
    r = scan(client, "Abu Dhabi Police: You have an unpaid traffic fine of AED 500. Pay today to avoid legal action.",
             "+971 50 999 8888")
    assert r["verdict"] in ("SUSPICIOUS", "HIGH-RISK SCAM") and "SENDER_MOBILE_FOR_INSTITUTION" in codes(r)


def test_arabic_fake_police_fine_with_scam_link(client):
    r = scan(client, f"شرطة أبوظبي: لديك مخالفة مرورية غير مدفوعة بقيمة 500 درهم. ادفع اليوم عبر {SCAM_LINK}",
             "+971501112233")
    assert r["verdict"] == "HIGH-RISK SCAM" and "MSG_SCAM_LINK" in codes(r)
    assert r["claimed_entity"] == "Abu Dhabi Police"


def test_arabic_bank_asking_to_send_the_otp(client):
    r = scan(client, "بنك أبوظبي التجاري: تم إيقاف بطاقتك مؤقتاً. أرسل لنا رمز التحقق الذي سيصلك لإعادة تفعيلها.",
             "ADCB")
    assert r["verdict"] == "HIGH-RISK SCAM" and "MSG_CREDENTIAL_REQUEST" in codes(r)


@pytest.mark.parametrize("text,asks", [
    ("يرجى إرسال رمز التحقق الذي وصلك إلى الموظف", True),          # polite request: verbal noun
    ("الرجاء مشاركة الرقم السري مع موظف البنك", True),
    ("قم بإرسال رمز التحقق لإكمال الطلب", True),
    ("تم إرسال رمز التحقق إلى رقم هاتفك المسجل", False),           # delivery notice, not a request
    ("سيتم إرسال رمز التحقق إلى هاتفك", False),
    ("يرجى عدم مشاركة رمز التحقق مع أي شخص", False),              # advice
])
def test_arabic_polite_credential_requests(text, asks):
    assert bool(message_intel.credential_requests(text, enter_counts=False)) is asks


def test_arabic_polite_otp_request_from_alphanumeric_sender_is_flagged(client):
    r = scan(client, "FAB: تم تعليق حسابك. يرجى إرسال رمز التحقق الذي وصلك لإعادة التفعيل.", "FAB")
    assert r["verdict"] != "SAFE" and "MSG_CREDENTIAL_REQUEST" in codes(r)


def test_whatsapp_code_takeover_without_brand_is_suspicious(client):
    r = scan(client, "Hi, I sent you a code by mistake, please send me the code you just received", channel="whatsapp")
    assert r["verdict"] == "SUSPICIOUS" and codes(r) == {"MSG_CREDENTIAL_REQUEST"}


# ------------------------------------------------------------------------------------- genuine messages
def test_genuine_bank_otp_is_safe(client):
    for sender in ("ADCB", None, "+971 50 123 4567"):
        r = scan(client, "Your OTP is 123456. Never share it with anyone, including bank staff.", sender)
        assert r["verdict"] == "SAFE" and r["risk_score"] == 0 and r["phones"] == [], sender


def test_genuine_otp_delivery_with_enter_wording_is_safe(client):
    r = scan(client, "Use 482913 as your one-time password to complete your payment of AED 120. Enter this code "
                     "only on the ADCB app. Do not share it.", "ADCB")
    assert r["verdict"] == "SAFE"


def test_genuine_tamm_receipt_is_safe_and_verified(client):
    r = scan(client, "TAMM: Payment of AED 300 received for your vehicle registration renewal. "
                     "Receipt: https://www.tamm.abudhabi/en/receipts?ref=88213", "TAMM")
    assert r["verdict"] == "SAFE" and r["risk_score"] == 0 and r["verified_official"] is True
    assert r["links"][0]["official"] is True and r["links"][0]["verdict"] == "SAFE"


def test_genuine_emirates_post_notice_is_safe(client):
    r = scan(client, "Emirates Post: your parcel EP123456789AE is out for delivery today. "
                     "Track it at https://www.emiratespost.ae/track", "EmiratesPost")
    assert r["verdict"] == "SAFE" and r["verified_official"] is True and r["phones"] == []


def test_friend_message_with_number_and_normal_link_is_safe(client):
    r = scan(client, "Hey! Dinner at 8? Here is the menu https://www.instagram.com/p/abc123 - call me on "
                     "050 765 4321 if you are late", "+971 55 111 2222")
    assert r["verdict"] == "SAFE" and r["risk_score"] == 0
    assert [p["status"] for p in r["phones"]] == ["unknown"]


def test_friend_mentioning_police_fine_is_not_a_police_claim(client):
    r = scan(client, "I paid my Abu Dhabi Police fine today, finally! Call me on 050 765 4321", "+971 55 111 2222")
    assert r["verdict"] == "SAFE" and r["claimed_entity"] is None


def test_scary_wording_without_anything_to_act_on_is_safe(client):
    r = scan(client, "Abu Dhabi Police: Your Emirates ID will be suspended today. Unpaid fine AED 1,000. "
                     "Congratulations, you won a refund!", "ADPolice")
    assert r["verdict"] == "SAFE" and r["risk_score"] == 0
    weak = {f["code"] for f in r["red_flags"] if f["strength"] == "weak"}
    assert {"MSG_URGENCY", "MSG_PAYMENT_DEMAND", "MSG_EMIRATES_ID_LURE", "MSG_PRIZE_LURE"} <= weak
    assert all(f["points"] == 0 for f in r["red_flags"])


def test_arabic_genuine_otp_is_safe(client):
    r = scan(client, "رمز التحقق الخاص بك هو 482913. لا تشارك هذا الرمز مع أي شخص.", "ADCB")
    assert r["verdict"] == "SAFE"


# ---------------------------------------------------------------------------------- phone extraction
@pytest.mark.parametrize("text", [
    "Your OTP is 123456.", "Your code: 048213", "Pay AED 1,250.00 now", "Tracking RR123456789AE",
    "Ref No. 0501234567", "order #05012345678", "Date 05/03/2026 or 2026-11-24", "card 4111 1111 1111 1111",
    "reference 00971501234567", "transaction 0212345678 AED", "IBAN AE07 0331 2345 6789 0123 456",
    "Booking 0123456789", "Amount 0501234567 AED",
])
def test_codes_amounts_and_references_are_not_phones(text):
    assert phone_intel.find_phones(text) == []


@pytest.mark.parametrize("text,e164", [
    ("call me on 050 123 4567", "+971501234567"),
    ("+971 (0) 50 123 4567", "+971501234567"),
    ("Call +44 20 7946 0958 now", "+442079460958"),
    ("tel:+971501234567", "+971501234567"),
    ("اتصل على ٠٥٠١٢٣٤٥٦٧", "+971501234567"),
    ("call 800 555 for help", "+971800555"),
])
def test_real_numbers_are_found(text, e164):
    assert [p.e164 for p in phone_intel.find_phones(text)] == [e164]


def test_toll_free_needs_a_call_word():
    assert phone_intel.find_phones("Invoice total 800555") == []


def test_links_are_refanged_and_sentence_joins_ignored():
    links = message_intel.extract_links("Pay at tamm-smart-pay.net/fine now.fine.Pay me hxxps://evil[.]com/x "
                                        "or write to info@tamm.abudhabi")
    assert [l["domain"] for l in links] == ["tamm-smart-pay.net", "evil.com"]


# ---------------------------------------------------------------------------------- privacy / storage
def test_storage_keeps_no_full_text_and_no_domain(client):
    tail = "UNIQUETAILTOKEN"
    text = (f"TAMM: You have an unpaid fine. Pay now at {SCAM_LINK} or call 050 123 4567. " + "x " * 200 + tail)
    r = scan(client, text, "+971 50 123 4567")
    kind, target, domain, raw = row(r["scan_id"])
    assert kind == "message" and domain is None and target.startswith("text message")
    stored = json.loads(raw)
    assert tail not in raw and len(stored["message"]["excerpt"]) <= 300
    assert "0501234567" not in stored["message"]["excerpt"]  # digit runs are hidden in the excerpt
    # the DNS blocklist never names a message scan (only its scam link, saved as a URL scan)
    feed = (client.get("/api/dns-blocklist")).text
    assert "tamm-smart-pay.net" in feed and "971501234567" not in feed


def test_safe_message_stores_no_excerpt_and_masked_numbers(client):
    r = scan(client, "Hey! call me on 050 765 4321 tonight", "+971 55 111 2222")
    assert r["verdict"] == "SAFE" and r["message"]["excerpt"]
    stored = json.loads(row(r["scan_id"])[3])
    assert stored["message"]["excerpt"] is None
    assert stored["phones"][0]["e164"] is None and "*" in stored["phones"][0]["masked"]
    assert "551112222" not in row(r["scan_id"])[3] and "7654321" not in row(r["scan_id"])[3]


def test_scans_listing_and_false_alarm_label(client):
    r = scan(client, "ADCB: Reply with the OTP you receive to keep your card active.", "ADCB")
    listed = client.get("/api/scans", params={"kind": "message"}).json()["scans"]
    assert any(s["scan_id"] == r["scan_id"] and s["domain"] is None for s in listed)
    fa = client.post("/api/feedback/false-alarm", json={"scan_id": r["scan_id"]})
    assert fa.status_code == 200
    items = client.get("/api/feedback/false-alarms").json()
    found = [i for i in items["items"] if i.get("scan_id") == r["scan_id"]]
    assert found and found[0]["label"] == "text message" and found[0]["kind"] == "message"


def test_public_ws_clients_never_get_message_events(client):
    hub.recent.clear()
    r = scan(client, "ADCB: Reply with the OTP you receive to keep your card active.", "ADCB")
    events = [m for m in hub.recent if m["event"] == "message_scan.completed"]
    assert events and events[-1]["data"]["scan_id"] == r["scan_id"]
    data = events[-1]["data"]
    assert "message" not in data and "excerpt" not in json.dumps(data) and "OTP you receive" not in json.dumps(data)
    assert public_view("message_scan.completed", data) is None
    assert all(not m["event"].startswith("message_scan") for m in hub.recent_for(None, public=True))
    received = [m for m in hub.recent if m["event"] == "citizen_report.received" and m["data"]["kind"] == "message"]
    assert received and received[-1]["data"]["target"] == "text message"


def test_text_cap_and_empty_text(client):
    assert client.post("/api/analyze-message", json={"text": "x" * 4001}).status_code == 422
    assert client.post("/api/analyze-message", json={"text": "   "}).status_code == 422


# ---------------------------------------------------------------------------------------- email
def _mail(from_name, from_addr, body, subject="Notice"):
    headers = [("Received", "from mail.example.com (mail.example.com [192.0.2.25]) by mx.example.net; "
                            "Mon, 23 Nov 2026 10:00:00 +0400")]
    return ParsedEmail(source="raw", has_headers=True, byte_exact=False, raw_bytes=None, headers=headers,
                       subject=subject, date="", from_=Address(from_name, from_addr, from_addr.rpartition("@")[2]),
                       reply_to=None, return_path=None, sender=None, to_count=1, list_id=None, text_body=body,
                       html_body="", links=[], attachments=[])


def _auth(dmarc="none", align=False):
    return AuthReport(trusted_authserv="mx.example.net", spf=AuthSPF("pass", "", "", "auth_results"),
                      dkim=[AuthDKIM("x", "s1", "pass" if align else "none", align, "auth_results")],
                      dmarc=AuthDMARC(dmarc, "reject", {"spf": align, "dkim": align}, "auth_results"),
                      arc=AuthARC("none", 0))


def _rules(p, a=None, **kw):
    return R.run_email_rules(p, a or _auth(), unicode_findings=[], link_results=[], campaign_matches=[],
                             user_model=None, **kw)


def test_email_foreign_callback_for_claimed_institution_is_strong():
    body = "Your parcel is held. Call our customs agent on +44 20 7946 0958 today."
    p = _mail("Emirates Post", "notice@ep-parcel-desk.test", body)
    rr = _rules(p, phone_numbers=phone_intel.find_phones(body))
    f = next(f for f in rr.flags if f.code == "CALLBACK_FOREIGN_FOR_INSTITUTION")
    assert f.strength == "strong" and f.points == 35 and rr.score >= 30


def test_email_mobile_callback_for_claimed_institution_is_strong():
    body = "Your vehicle file is blocked. Call the officer on 050 123 4567."
    rr = _rules(_mail("Abu Dhabi Police", "fines@adp-notice.test", body), phone_numbers=phone_intel.find_phones(body))
    assert "CALLBACK_MOBILE_FOR_INSTITUTION" in {f.code for f in rr.flags if f.points > 0}


def test_email_mobile_number_without_institution_claim_is_not_flagged():
    body = "Thanks for the order! Call me on 050 123 4567 if anything is missing."
    rr = _rules(_mail("Sara's Bakery", "sara@bakery-shop.test", body), phone_numbers=phone_intel.find_phones(body))
    assert not {f.code for f in rr.flags} & {"CALLBACK_MOBILE_FOR_INSTITUTION", "CALLBACK_FOREIGN_FOR_INSTITUTION"}
    assert rr.score < 30


def test_email_no_mx_is_weak():
    p = _mail("Sara", "sara@brand-new-shop.test", "Hello there")
    alone = _rules(p, sender_mx="none")
    f = next(f for f in alone.flags if f.code == "SENDER_NO_MX")
    assert f.points == 0 and alone.score == 0
    with_strong = _rules(p, sender_mx="none", sender_age_hours=48.0)
    assert next(f for f in with_strong.flags if f.code == "SENDER_NO_MX").points == 10
    assert not any(f.code == "SENDER_NO_MX" for f in _rules(p, sender_mx="found").flags)
    assert not any(f.code == "SENDER_NO_MX" for f in _rules(_mail("x", "a@gmail.com", "hi"), sender_mx="none").flags)


def test_lookup_mx_respects_offline_failures_and_deadline(monkeypatch):
    assert asyncio.run(email_auth.lookup_mx("example.test")) is None  # OFFLINE_MODE: no lookup
    assert asyncio.run(email_auth.lookup_mx("example.test", mxfunc=lambda d: "none")) == "none"
    assert asyncio.run(email_auth.lookup_mx("example.test", mxfunc=lambda d: "found")) == "found"

    def boom(d):
        raise OSError("dns down")

    assert asyncio.run(email_auth.lookup_mx("example.test", mxfunc=boom)) is None
    monkeypatch.setattr(email_auth, "spf_deadline_s", lambda: 0.2)
    t = time.perf_counter()
    assert asyncio.run(email_auth.lookup_mx("example.test", mxfunc=lambda d: time.sleep(2) or "none")) is None
    assert time.perf_counter() - t < 1.5


def test_email_verified_official_for_authenticated_official_sender():
    p = _mail("Abu Dhabi Police", "noreply@adpolice.gov.ae", "Your traffic fine receipt is attached in the app.")
    rr = _rules(p, _auth(dmarc="pass", align=True))
    assert rr.verified_official and rr.score < 30
    assert not _rules(p, _auth(dmarc="fail")).verified_official


def test_email_response_has_verified_official_and_phones(client):
    r = client.post("/api/analyze-email", json={"source": "text", "text": "Hello, call me on 050 123 4567.",
                                                "use_llm": False})
    assert r.status_code == 200, r.text
    j = r.json()
    assert j["verified_official"] is False and j["phones"][0]["masked"].startswith("+971 50")
    assert "mx" in j["authentication"]


# ---------------------------------------------------------------------------------------- websites
def test_invalid_tls_is_weak_alone_and_counts_next_to_a_lookalike():
    plain = run_rules(page_signals.lexical("https://familybakery.ae/"), {"ssl_valid": False}, None, None)
    f = next(f for f in plain.flags if f.code == "TLS_INVALID")
    assert f.points == 0 and plain.score == 0
    fake = run_rules(page_signals.lexical(SCAM_LINK), {"ssl_valid": False}, None, None)
    assert next(f for f in fake.flags if f.code == "TLS_INVALID").points == 10
    expired = run_rules(page_signals.lexical("https://familybakery.ae/"),
                        {"ssl_valid": False, "ssl_not_after": "2020-01-01T00:00:00+00:00"}, None, None)
    assert "expired" in next(f for f in expired.flags if f.code == "TLS_INVALID").en
    ok = run_rules(page_signals.lexical("https://familybakery.ae/"), {"ssl_valid": True}, None, None)
    assert not any(f.code == "TLS_INVALID" for f in ok.flags)


def test_analyze_url_has_verified_official_alias(client):
    for url, expect in (("https://www.tamm.abudhabi/", True), (SCAM_LINK, False)):
        r = client.post("/api/analyze-url", json={"url": url, "run_sandbox": False, "use_llm": False}).json()
        assert r["verified_official"] is expect and r["verified_official"] == r["is_official_domain"]


def test_ai_opinion_never_lifts_a_message_with_nothing_to_act_on():
    scam_llm = {"verdict": "HIGH-RISK SCAM", "risk_score": 95, "confidence": 0.95}
    calm = message_intel.run_message_rules("Abu Dhabi Police: your fine is unpaid, pay today.", sender="ADPolice",
                                           links=[], phones=[], sender_check=None)
    assert not calm.actionable and message_intel.blend(calm, scam_llm) == 0
    ask = message_intel.run_message_rules("Please send me the code you received", sender=None,
                                          links=[], phones=[], sender_check=None)
    assert ask.strong_present and message_intel.blend(ask, scam_llm) >= 65
    assert message_intel.blend(ask, {"verdict": "SAFE", "risk_score": 0, "confidence": 0.99}) == ask.score


def test_sms_guard_demo_message_is_quarantined(client):
    """The /citizen SMS Guard demo text (frontend SmsGuard.tsx) goes through this endpoint."""
    r = scan(client, "Emirates Post: Parcel held at Abu Dhabi customs. Pay AED 14.50 at "
                     "http://127.0.0.1:8000/mock-scam/emiratespost", "EmiratesPost", interception_channel="AUTO_SMS_GUARD")
    assert r["verdict"] == "HIGH-RISK SCAM" and r["links"][0]["domain"] == "emiratespost-track-uae.com"


# ---- 2026-11-25: a named sender hiding its link behind a public shortener ----
def _short_rules(text, url, whitelisted=False):
    from saqr.intel.message_intel import run_message_rules

    link = {"url": url, "domain": url.split("/")[2], "verdict": None, "risk_score": None,
            "official": whitelisted, "whitelisted": whitelisted}
    return run_message_rules(text, sender=None, links=[link], phones=[], sender_check=None)


def test_brand_sms_with_a_public_shortener_is_suspicious():
    rr = _short_rules("Aramex: Your Parcel is on hold because the house number was not included. Update your "
                      "details within 24 hours: https://bit.ly/40JzQ96", "https://bit.ly/40JzQ96")
    assert "MSG_SHORTENER_FOR_INSTITUTION" in {f.code for f in rr.flags if f.points > 0}
    assert rr.verdict != "SAFE"


def test_shortener_without_a_named_sender_stays_safe():
    rr = _short_rules("Hey, here are the photos from Friday https://bit.ly/40JzQ96", "https://bit.ly/40JzQ96")
    assert rr.verdict == "SAFE"


def test_brand_sms_with_its_own_link_is_not_a_shortener_case():
    rr = _short_rules("Aramex: your shipment is out for delivery. Track it: https://www.aramex.com/track/123",
                      "https://www.aramex.com/track/123", whitelisted=True)
    assert "MSG_SHORTENER_FOR_INSTITUTION" not in {f.code for f in rr.flags}
