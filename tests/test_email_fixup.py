"""Regression tests for the email-scanning fix-up round (E2E findings, 2026-11-23).

1. A self-made ARC seal never switches off DMARC_FAIL / OFFICIAL_SENDER_UNAUTHENTICATED.
2. SPF has a hard deadline; permerror / temperror are not shown as "SPF fail".
3. OFFICIAL_SENDER_UNAUTHENTICATED needs a delivered copy (a Received header): drafts / templates get a note.
4. Registry: Emirates Red Crescent, Emirates Post Group (epg.gov.ae) and DEWA.
5. Styled (math-bold / small-capital / full-width) letters that spell a brand are a strong flag.
6. A percent-encoded link host is scanned under its real (decoded) domain.
7. Common-word brands (Amazon, Apple ...) in a display name next to a role word; a subject that merely
   mentions a brand ("DHL vs Aramex prices?") is not a brand claim.
Fully offline. Run: pytest -q tests/test_email_fixup.py
"""
import asyncio
import base64
import os
import tempfile
import time

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import dkim  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr import email_pipeline  # noqa: E402
from saqr.intel import email_auth as ea  # noqa: E402
from saqr.intel import email_parse as ep  # noqa: E402
from saqr.intel import email_rules as R  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402
from saqr.intel.email_types import Address, AuthARC, AuthDKIM, AuthDMARC, AuthReport, AuthSPF, ParsedEmail  # noqa: E402
from saqr.intel.email_unicode import scan_text  # noqa: E402
from saqr.routers import email as email_router  # noqa: E402

if "/api/analyze-email" not in {getattr(r, "path", None) for r in app.routes}:
    app.include_router(email_router.router)

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "emails")
RECEIVED = ("Received: from mail.sender.test (mail.sender.test [192.0.2.9]) by mx.google.com with ESMTPS id a1;"
            " Mon, 23 Nov 2026 10:00:00 +0400\n")


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def raw(from_, subject="Notice", body="Hello.", top=RECEIVED):
    return (f"{top}From: {from_}\nTo: me@example.com\nSubject: {subject}\nDate: Mon, 23 Nov 2026 10:00:00 +0400\n"
            f"MIME-Version: 1.0\nContent-Type: text/plain; charset=utf-8\n\n{body}\n")


def scan(client, **body):
    body.setdefault("use_llm", False)
    r = client.post("/api/analyze-email", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def scan_raw(client, *a, **kw):
    return scan(client, source="raw", text=raw(*a, **kw))


def codes(res, scoring=True):
    flags = res["red_flags"] if isinstance(res, dict) else [f.to_dict() for f in res.flags]
    return {f["code"] for f in flags if f["points"] > 0 or not scoring}


def mail(from_name, from_addr, *, subject="Notice", body="Hello.", delivered=True, reply_to=None):
    headers = [("Received", "from a (a [192.0.2.9]) by mx.google.com; Mon")] if delivered else [("From", from_addr)]
    return ParsedEmail(source="raw", has_headers=True, byte_exact=False, raw_bytes=None, headers=headers,
                       subject=subject, date="", from_=Address(from_name, from_addr, from_addr.rpartition("@")[2]),
                       reply_to=Address("", reply_to, reply_to.rpartition("@")[2]) if reply_to else None,
                       return_path=None, sender=None, to_count=1, list_id=None, text_body=body, html_body="",
                       links=[], attachments=[])


def auth(*, spf="none", dmarc="none", policy=None, arc="none", arc_trusted=False, source="auth_results", dkim=()):
    return AuthReport(trusted_authserv="mx.google.com", spf=AuthSPF(spf, "", "", "auth_results"),
                      dkim=[AuthDKIM(d, "s1", r, False, "auth_results") for d, r in dkim],
                      dmarc=AuthDMARC(dmarc, policy, {"spf": False, "dkim": False}, source),
                      arc=AuthARC(arc, 1 if arc != "none" else 0, trusted=arc_trusted))


def rules(p, a=None, findings=None, age=None):
    return R.run_email_rules(p, a or auth(), unicode_findings=findings or [], link_results=[], campaign_matches=[],
                             user_model=None, sender_age_hours=age)


# ---------------------------------------------------------------------------------------------------
# 1. ARC
# ---------------------------------------------------------------------------------------------------
GMAIL_ARC_DMARC_FAIL = ("Authentication-Results: mx.google.com; arc=pass (i=1); spf=fail smtp.mailfrom=service@paypal.com;"
                        " dkim=none; dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com\n" + RECEIVED)


def test_arc_pass_does_not_hide_provider_dmarc_fail(client):
    """E2E: trusted Gmail said dmarc=fail (p=REJECT) + arc=pass (any sealer) -> scored SAFE 0."""
    res = scan_raw(client, "PayPal <service@paypal.com>", "Account limited", "Please review your account.",
                   top=GMAIL_ARC_DMARC_FAIL)
    assert res["verdict"] == "HIGH-RISK SCAM", (res["risk_score"], codes(res, False))
    assert {"DMARC_FAIL", "OFFICIAL_SENDER_UNAUTHENTICATED"} <= codes(res)
    assert res["authentication"]["arc"] == {"result": "pass", "chain_length": 0}  # response contract unchanged


@pytest.mark.parametrize("trusted", [False, True])
def test_untrusted_or_provider_failed_arc_never_suppresses_strong_flags(trusted):
    p = mail("PayPal", "service@paypal.com")
    rr = rules(p, auth(dmarc="fail", policy="reject", arc="pass", arc_trusted=trusted))
    assert {"DMARC_FAIL", "OFFICIAL_SENDER_UNAUTHENTICATED"} <= codes(rr) and rr.score >= 65


def test_untrusted_arc_does_not_suppress_weak_flags_or_vouch():
    p = mail("Shop", "news@shop.example", reply_to="other@elsewhere.example")
    rr = rules(p, auth(arc="pass", arc_trusted=False, dkim=[("shop.example", "fail")]))
    assert {"REPLY_TO_MISMATCH", "DKIM_FAIL"} <= codes(rr, False)
    assert "ARC_PASS" not in codes(rr, False) and not rr.is_list


def test_trusted_arc_still_excuses_forwarding_side_effects():
    p = mail("Shop", "news@shop.example", reply_to="other@elsewhere.example")
    rr = rules(p, auth(arc="pass", arc_trusted=True, dkim=[("shop.example", "fail")]))
    assert not {"REPLY_TO_MISMATCH", "DKIM_FAIL"} & codes(rr, False) and "ARC_PASS" in codes(rr, False)
    # a DMARC failure we computed ourselves (not the provider's verdict) is excused by a trusted ARC pass
    official = mail("Abu Dhabi Police", "news@adpolice.gov.ae")
    rr = rules(official, auth(dmarc="fail", policy="reject", arc="pass", arc_trusted=True, source="computed"))
    assert not {"DMARC_FAIL", "OFFICIAL_SENDER_UNAUTHENTICATED"} & codes(rr, False)


@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)


class StubDNS:
    def __init__(self, records):
        self.records = {k.lower(): v for k, v in records.items()}

    def __call__(self, name, timeout=5):
        return self.records.get((name.decode() if isinstance(name, bytes) else name).lower())


def _sealed(key, sealer: bytes, gmail_ar: bytes) -> bytes:
    pytest.importorskip("authres")  # dkimpy needs it to SIGN an ARC set
    base = (b"Authentication-Results: mx." + sealer + b"; spf=pass smtp.mailfrom=service@paypal.com;"
            b" dmarc=pass header.from=paypal.com\r\n"
            b"From: PayPal <service@paypal.com>\r\nTo: me@example.com\r\nSubject: Account limited\r\n"
            b"Date: Mon, 23 Nov 2026 10:00:00 +0400\r\nMessage-ID: <x1@paypal.com>\r\n\r\nReview your account.\r\n")
    sealed = b"".join(dkim.arc_sign(base, b"arc1", sealer, key[0], b"mx." + sealer)) + base
    return (gmail_ar + b"Received: from relay.evil-sealer.test (relay.evil-sealer.test [192.0.2.66]) by mx.google.com"
            b" with ESMTPS id q1; Mon, 23 Nov 2026 10:00:01 +0400\r\n" + sealed)


def _verify(data, dns):
    return asyncio.run(ea.verify(ep.parse(source="eml", file_bytes=data), offline=True, dnsfunc=dns))


def test_self_made_arc_seal_is_valid_but_not_trusted(key):
    gmail = (b"Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=service@paypal.com; dkim=none;"
             b" dmarc=fail (p=REJECT) header.from=paypal.com\r\n")
    data = _sealed(key, b"evil-sealer.test", gmail)
    a = _verify(data, StubDNS({"arc1._domainkey.evil-sealer.test.": key[1]}))
    assert a.arc.result == "pass" and a.arc.trusted is False
    rr = rules(ep.parse(source="eml", file_bytes=data), a)
    assert {"DMARC_FAIL", "OFFICIAL_SENDER_UNAUTHENTICATED"} <= codes(rr) and rr.verdict == "HIGH-RISK SCAM"


def test_arc_seal_by_trusted_provider_is_trusted(key):
    data = _sealed(key, b"google.com", b"")
    a = _verify(data, StubDNS({"arc1._domainkey.google.com.": key[1]}))
    assert a.arc.result == "pass" and a.arc.trusted is True
    assert a.arc.to_dict() == {"result": "pass", "chain_length": 1}


def test_provider_arc_pass_is_trusted():
    text = ("Authentication-Results: mx.google.com; arc=pass (i=1); dkim=pass header.d=lists.example.org\r\n"
            "Received: from lists.example.org (lists.example.org. [192.0.2.80]) by mx.google.com; Mon, 23 Nov 2026\r\n"
            "From: Someone <someone@example.com>\r\nSubject: list mail\r\n\r\nhi\r\n")
    a = asyncio.run(ea.verify(ep.parse(source="raw", text=text), offline=True))
    assert a.arc.result == "pass" and a.arc.trusted is True
    forged = text.replace("mx.google.com;", "mx.evil.test;", 1)
    a = asyncio.run(ea.verify(ep.parse(source="raw", text=forged), offline=True))
    assert not (a.arc.result == "pass" and a.arc.trusted)


# ---------------------------------------------------------------------------------------------------
# 2. SPF deadline + permerror / temperror wording
# ---------------------------------------------------------------------------------------------------
NO_AR = ("Received: by 2002:a05:6a10:1::1 with SMTP id z; Mon, 23 Nov 2026\r\n"
         "Return-Path: <bounce@shop.example>\r\n"
         "Received: from mail.shop.example (mail.shop.example. [192.0.2.30]) by mx.google.com; Mon, 23 Nov 2026\r\n"
         "From: Shop <news@shop.example>\r\nSubject: Sale\r\n\r\nhi\r\n")


def test_spf_hard_deadline(monkeypatch):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import spf

    def slow_check2(i, s, h, **kw):  # pyspf ignoring its own timeout
        time.sleep(3)
        return ("pass", "too late")

    monkeypatch.setattr(spf, "check2", slow_check2)
    monkeypatch.setattr(ea, "spf_deadline_s", lambda: 0.3)
    t0 = time.perf_counter()
    a = asyncio.run(ea.verify(ep.parse(source="raw", text=NO_AR), offline=False, dnsfunc=StubDNS({})))
    assert time.perf_counter() - t0 < 2.0
    assert a.spf.result == "temperror" and a.spf.source == "computed"


def test_spf_deadline_is_a_few_seconds():
    assert 1.0 <= ea.spf_deadline_s() <= 6.0


@pytest.mark.parametrize("result", ["permerror", "temperror"])
def test_spf_errors_are_not_shown_as_spf_fail(result):
    rr = rules(mail("Shop", "news@shop.example"), auth(spf=result), age=48.0)  # strong anchor: new domain
    assert "SPF_FAIL" not in codes(rr, False)
    assert "SPF_FAIL" in codes(rules(mail("Shop", "news@shop.example"), auth(spf="fail"), age=48.0))


# ---------------------------------------------------------------------------------------------------
# 3. Official sender without proof needs a delivered copy
# ---------------------------------------------------------------------------------------------------
def test_draft_or_template_from_official_sender_is_not_unauthenticated(client):
    res = scan_raw(client, "Abu Dhabi Police <noreply@adpolice.gov.ae>", "Road safety week",
                   "Join our road safety week events.", top="")
    assert res["verdict"] == "SAFE" and "OFFICIAL_SENDER_UNAUTHENTICATED" not in codes(res, False)
    note = next(f for f in res["red_flags"] if f["code"] == "HEADERS_NOT_AVAILABLE")
    assert note["points"] == 0 and "draft" in note["en"] and note["ar"]


def test_delivered_official_sender_without_proof_still_flags(client):
    res = scan_raw(client, "Abu Dhabi Police <noreply@adpolice.gov.ae>", "Road safety week", "Join us.")
    assert "OFFICIAL_SENDER_UNAUTHENTICATED" in codes(res)


@pytest.mark.parametrize("name,source", [("auth_spoofed_results.eml", "eml"), ("msg_outlook_spoof_tamm.msg", "msg")])
def test_spoof_fixtures_still_flag(client, name, source):
    with open(os.path.join(FIX, name), "rb") as fh:
        b64 = base64.b64encode(fh.read()).decode()
    res = scan(client, source=source, file_base64=b64, file_name=name, follow_links=False)
    assert res["verdict"] != "SAFE" and "OFFICIAL_SENDER_UNAUTHENTICATED" in codes(res), codes(res, False)


def test_paypal_reject_spoof_still_high_risk(client):
    top = ("Authentication-Results: mx.google.com; spf=softfail smtp.mailfrom=service@paypal.com; dkim=none;"
           " dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=paypal.com\n" + RECEIVED)
    res = scan_raw(client, "PayPal <service@paypal.com>", "Your account is limited",
                   "Confirm your identity within 24 hours.", top=top)
    assert res["verdict"] == "HIGH-RISK SCAM" and "DMARC_FAIL" in codes(res)


# ---------------------------------------------------------------------------------------------------
# 4. Registry
# ---------------------------------------------------------------------------------------------------
def test_emirates_red_crescent_is_official(client):
    lex = analyze_lexical("emiratesrc.ae")
    assert lex.is_whitelisted and not lex.flags
    res = scan_raw(client, "Emirates Red Crescent <donate@emiratesrc.ae>", "Ramadan campaign",
                   "Donate to the Ramadan campaign.", top="")
    assert res["verdict"] == "SAFE" and not {"SENDER_LOOKALIKE", "DISPLAY_NAME_BRAND_SPOOF"} & codes(res, False)
    assert res["email"]["from"]["is_official"]


def test_emirates_post_group_domain(client):
    lex = analyze_lexical("epg.gov.ae")
    assert lex.is_whitelisted and lex.impersonated and lex.impersonated.id == "emiratespost"
    res = scan_raw(client, "Emirates Post <noreply@epg.gov.ae>", "Your parcel", "Your parcel was delivered.", top="")
    assert res["verdict"] == "SAFE" and "DISPLAY_NAME_BRAND_SPOOF" not in codes(res, False)
    # the short "epg" label is not a look-alike target (no typo noise on other 3-4 letter domains)
    assert analyze_lexical("epgl.ae").impersonated is None and analyze_lexical("mepg.com").impersonated is None


def test_dewa_is_named(client):
    res = scan_raw(client, "DEWA <noreply@dewa.gov.ae>", "Unpaid bill", "Your DEWA bill of AED 230 is due today, pay now.")
    assert res["verdict"] == "HIGH-RISK SCAM" and res["impersonated_entity"] == "DEWA"
    assert analyze_lexical("dewa.gov.ae").is_whitelisted
    assert analyze_lexical("dewa-bill-pay.com").impersonated.id == "dewa"
    assert analyze_lexical("dewalt.com").impersonated is None


@pytest.mark.parametrize("display,address", [("Dewa Ayu", "dewa.ayu@gmail.com"), ("I Dewa Gede Putra", "dewa.gede@yahoo.com")])
def test_dewa_as_a_balinese_name_is_not_a_brand_claim(display, address):
    rr = rules(mail(display, address, subject="Photos from the trip"))
    assert not {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER"} & codes(rr, False)


def test_dewa_department_name_from_gmail_is_a_brand_claim():
    rr = rules(mail("DEWA Customer Care", "dewa.billing.uae@gmail.com", subject="Unpaid bill"))
    assert "FREEMAIL_BRAND_SENDER" in codes(rr) and rr.entity and rr.entity.id == "dewa"


# ---------------------------------------------------------------------------------------------------
# 5. Styled letters spelling a brand
# ---------------------------------------------------------------------------------------------------
STYLED = {
    "math_bold_subject": ("subject", "\U0001d40f\U0001d41a\U0001d432\U0001d40f\U0001d41a\U0001d425 account notice"),
    "small_caps_display": ("display_name", "ᴘᴀʏᴘᴀʟ"),
    "fullwidth_body": ("body", "Your ＰａｙＰａｌ account is on hold"),
    "two_word_brand": ("subject", "\U0001d404\U0001d426\U0001d422\U0001d42b\U0001d41a\U0001d42d\U0001d41e\U0001d42c "
                                  "\U0001d40f\U0001d428\U0001d42c\U0001d42d parcel"),
}


def _styled_mail(where, text, from_addr="info@shop-news.test"):
    return mail(text if where == "display_name" else "Info", from_addr,
                subject=text if where == "subject" else "Notice", body=text if where == "body" else "Hello.")


@pytest.mark.parametrize("case", sorted(STYLED))
def test_styled_brand_is_strong(case):
    where, text = STYLED[case]
    rr = rules(_styled_mail(where, text), findings=scan_text(text, where))
    f = next((f for f in rr.flags if f.code == "DISPLAY_NAME_CONFUSABLE"), None)
    assert f is not None and f.strength == "strong" and f.points == 65, [x.code for x in rr.flags]
    assert rr.verdict == "HIGH-RISK SCAM" and rr.entity is not None


@pytest.mark.parametrize("text", [
    "\U0001d416\U0001d41e\U0001d41e\U0001d424\U0001d425\U0001d432 \U0001d403\U0001d41e\U0001d41a\U0001d425\U0001d42c",  # Weekly Deals
    "\U0001d400\U0001d429\U0001d429\U0001d425\U0001d41e \U0001d40f\U0001d422\U0001d41e recipe",  # Apple Pie (common word)
    "\U0001d405\U0001d41a\U0001d41b\U0001d42e\U0001d425\U0001d428\U0001d42e\U0001d42c offers",  # Fabulous
])
def test_styled_text_that_is_not_a_brand_stays_weak(text):
    rr = rules(_styled_mail("subject", text), findings=scan_text(text, "subject"))
    assert "DISPLAY_NAME_CONFUSABLE" not in codes(rr, False) and rr.verdict == "SAFE"
    assert "FANCY_UNICODE" in codes(rr, False)


def test_styled_brand_from_the_authenticated_brand_is_not_flagged():
    text = STYLED["math_bold_subject"][1]
    p = _styled_mail("subject", text, from_addr="service@paypal.com")
    a = AuthReport(trusted_authserv="mx.google.com", spf=AuthSPF("pass", "paypal.com", "", "auth_results"),
                   dkim=[AuthDKIM("paypal.com", "s1", "pass", True, "auth_results")],
                   dmarc=AuthDMARC("pass", "reject", {"spf": True, "dkim": True}, "auth_results"))
    rr = rules(p, a, findings=scan_text(text, "subject"))
    assert "DISPLAY_NAME_CONFUSABLE" not in codes(rr, False)


# ---------------------------------------------------------------------------------------------------
# 6. Percent-encoded link host
# ---------------------------------------------------------------------------------------------------
def test_scan_target_decodes_percent_encoded_host():
    l = {"url": "https://p%D0%B0ypal.com:8443/login?x=1", "domain": "xn--pypal-4ve.com"}
    assert email_pipeline._scan_target(l) == "https://xn--pypal-4ve.com:8443/login?x=1"
    plain = {"url": "https://shop.example/a%20b", "domain": "shop.example"}
    assert email_pipeline._scan_target(plain) == plain["url"]  # a %-escape in the PATH is left alone


def test_percent_encoded_link_is_scanned_under_real_domain(client, monkeypatch):
    seen = []
    real = email_pipeline.analyze_url

    async def spy(url, **kw):
        seen.append(url)
        return await real(url, **kw)

    monkeypatch.setattr(email_pipeline, "analyze_url", spy)
    res = scan_raw(client, "Info <info@shop-news.test>", "notice", "Open https://p%D0%B0ypal.com/login now")
    assert seen == ["https://xn--pypal-4ve.com/login"]
    link = res["links"][0]
    assert link["domain"] == "xn--pypal-4ve.com" and link["verdict"] == "HIGH-RISK SCAM"


# ---------------------------------------------------------------------------------------------------
# 7. Common-word brands in a display name; subject mentions
# ---------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("display,address,brand", [
    ("Amazon Recruitment Team", "amazon.hr.jobs@gmail.com", "amazon"),
    ("Apple Support", "apple.help.desk@outlook.com", "apple"),
    ("Team Google", "security@g00gle-alerts.test", "google"),
    ("Chase Fraud Alerts", "alerts@chase-secure-mail.test", "chase"),
    ("Wise Account Verification", "wise.verify@gmail.com", "wise"),
    ("noon Customer Care", "noon.refunds@gmail.com", "noon"),
    ("فريق دعم أمازون", "amazon.ar@gmail.com", "amazon"),
])
def test_common_word_brand_with_role_word_is_a_claim(display, address, brand):
    rr = rules(mail(display, address))
    assert {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER"} & codes(rr), [f.code for f in rr.flags]
    assert rr.entity and rr.entity.id == brand


@pytest.mark.parametrize("display,address", [
    ("Chase Smith", "chase.smith@gmail.com"), ("Apple Martin", "apple.m@gmail.com"), ("Wise Guy", "wiseguy@gmail.com"),
    ("Amazon rainforest trip", "trip.club@gmail.com"), ("Noon Prayer Group", "prayer@gmail.com"),
    ("Apple Support", "noreply@email.apple.com"), ("Amazon.ae Customer Service", "order-update@amazon.ae"),
])
def test_common_word_brand_false_positives(display, address):
    rr = rules(mail(display, address, subject="Hello"))
    assert not {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER"} & codes(rr, False), [f.code for f in rr.flags]


@pytest.mark.parametrize("subject", ["DHL vs Aramex prices?", "Is FedEx or Aramex cheaper to Jordan", "Netflix tonight?"])
def test_subject_that_only_mentions_a_brand_is_not_a_claim(subject):
    rr = rules(mail("Omar", "omar.k@gmail.com", subject=subject, body="Which one do you think?"))
    assert "FREEMAIL_BRAND_SENDER" not in codes(rr, False) and rr.verdict == "SAFE"


@pytest.mark.parametrize("subject", ["Your Aramex parcel is waiting", "Aramex: action needed", "PayPal - please respond",
                                     "Netflix payment failed", "بريد الإمارات: رسوم شحنتك"])
def test_subject_that_reads_like_a_brand_notice_is_a_claim(subject):
    rr = rules(mail("Notice", "notice.center@gmail.com", subject=subject))
    assert "FREEMAIL_BRAND_SENDER" in codes(rr), subject
