"""Email rules engine (saqr/intel/email_rules.py): every flag code fires on its own evidence, weak flags
need a strong one, and the contract's floor / cap / mailing-list suppression hold. ParsedEmail and
AuthReport objects are built by hand, so these tests need neither the parser nor the network."""
import os
import tempfile

# Same offline test setup as tests/test_api.py (must run before any saqr import: settings are read once).
os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402

from saqr.intel import email_rules as R  # noqa: E402
from saqr.intel.email_types import (  # noqa: E402
    Address, Attachment, AuthARC, AuthDKIM, AuthDMARC, AuthReport, AuthSPF, Link, ParsedEmail,
)
from saqr.intel.email_unicode import scan_address, scan_text, scan_url  # noqa: E402
from saqr.intel.threat_feeds import threat_feeds  # noqa: E402


def addr(display="", address=""):
    return Address(display, address, address.rpartition("@")[2].lower() if "@" in address else "")


def mail(*, from_name="Sara", from_addr="sara@example.com", subject="Hello", body="See you soon.",
         reply_to=None, return_path=None, links=(), attachments=(), headers=None, has_headers=True,
         list_id=None, byte_exact=False, html=""):
    if headers is None and has_headers:  # a delivered copy (every receiving server adds a Received header)
        headers = [("Received", "from mail.example.com (mail.example.com [192.0.2.25]) by mx.example.net; "
                                "Mon, 23 Nov 2026 10:00:00 +0400")]
    return ParsedEmail(
        source="raw", has_headers=has_headers, byte_exact=byte_exact, raw_bytes=None,
        headers=list(headers or []), subject=subject, date="", from_=addr(from_name, from_addr),
        reply_to=addr(*reply_to) if reply_to else None, return_path=addr("", return_path) if return_path else None,
        sender=None, to_count=1, list_id=list_id, text_body=body, html_body=html,
        links=[Link(h, t) for h, t in links], attachments=[Attachment(n, 10) for n in attachments])


def auth(spf="pass", dkim=(), dmarc="none", policy=None, arc="none", align=False, arc_trusted=True, dmarc_source="auth_results"):
    return AuthReport(trusted_authserv="mx.example.net", spf=AuthSPF(spf, "", "", "auth_results"),
                      dkim=[AuthDKIM(d, "s1", r, align, src) for d, r, src in dkim],
                      dmarc=AuthDMARC(dmarc, policy, {"spf": align, "dkim": align}, dmarc_source),
                      arc=AuthARC(arc, 1 if arc != "none" else 0, trusted=arc_trusted))


def link(domain, verdict=None, score=None, text="", mismatch=False):
    return {"url": f"https://{domain}/x", "display_text": text, "domain": domain, "unwrapped_from": None,
            "text_mismatch": mismatch, "scan_id": None, "risk_score": score, "verdict": verdict}


def run(p, a=None, *, findings=None, links=None, campaigns=None, model=None, age=None):
    return R.run_email_rules(p, a or auth(), unicode_findings=findings or [], link_results=links or [],
                             campaign_matches=campaigns or [], user_model=model, sender_age_hours=age)


def codes(rr, scoring=True):
    return {f.code for f in rr.flags if (f.points > 0 or not scoring)}


# Strong anchor used to make weak flags count: a 2-day-old sender domain (SENDER_NEW_DOMAIN 30).
NEW = 48.0


# -- strong flags ----------------------------------------------------------------------------------
STRONG_CASES = {
    "IDN_MIXED_SCRIPT": lambda: run(mail(from_addr="alerts@xn--dcb-secure-yqi.test"),
                                    findings=scan_address("alerts@xn--dcb-secure-yqi.test", "from.address")),
    "DISPLAY_NAME_CONFUSABLE": lambda: run(mail(subject="Your PаyPal account"),
                                           findings=scan_text("Your PаyPal account", "subject")),
    "BIDI_OVERRIDE": lambda: run(mail(attachments=["Invoice_‮fdp.exe"]),
                                 findings=scan_text("Invoice_‮fdp.exe", "attachment")),
    "CAMPAIGN_IOC_MATCH": lambda: run(mail(), campaigns=[{"id": "cmp-1", "title_en": "Fake fines", "title_ar": "مخالفات",
                                                          "match": "ioc", "points": 65, "matched": ["evil.test"]}]),
    "LINK_HIGH_RISK": lambda: run(mail(), links=[link("tamm-smart-pay.net", "HIGH-RISK SCAM", 92)]),
    "KNOWN_PHISHING_LINK": lambda: run(mail(), links=[link("feed-listed-phish.test")]),
    "SENDER_LOOKALIKE": lambda: run(mail(from_name="Support", from_addr="no-reply@paypal-login-verify.com")),
    "DANGEROUS_ATTACHMENT": lambda: run(mail(attachments=["statement.pdf.html"])),
    "INVISIBLE_IN_TOKEN": lambda: run(mail(body="Your Pay​Pal"), findings=scan_text("Your Pay​Pal", "body")),
    "PUNYCODE_DOMAIN": lambda: run(mail(), findings=scan_url("https://xn--mgbh0fb.xn--mgbaam7a8h/")),
    "DISPLAY_NAME_ADDRESS_SPOOF": lambda: run(mail(from_name="service@paypal.com", from_addr="x@random-shop.test")),
    "DMARC_FAIL": lambda: run(mail(from_addr="info@bank.test"), auth(dmarc="fail", policy="reject")),
    "DISPLAY_NAME_BRAND_SPOOF": lambda: run(mail(from_name="PayPal Service", from_addr="noreply@random-shop.test")),
    "FREEMAIL_BRAND_SENDER": lambda: run(mail(from_name="Delivery", from_addr="aramex.uae.2026@gmail.com",
                                              subject="Your Aramex parcel is waiting")),
    "LINK_TEXT_MISMATCH": lambda: run(mail(), links=[link("evil.test", text="https://www.paypal.com/", mismatch=True)]),
    "SENDER_NEW_DOMAIN": lambda: run(mail(from_addr="hi@brand-new-shop.test"), age=NEW),
    "LINK_SUSPICIOUS": lambda: run(mail(), links=[link("odd-site.test", "SUSPICIOUS", 45)]),
    "REPLY_TO_FREEMAIL_BRAND": lambda: run(mail(from_name="ADCB Card Services", from_addr="cards@adcb-alerts.test",
                                                reply_to=("ADCB", "adcb.uae@outlook.com"))),
}


@pytest.fixture(autouse=True)
def _feed():
    saved = dict(threat_feeds.hosts)
    threat_feeds.load({"Test feed": ["feed-listed-phish.test"]})
    yield
    threat_feeds.hosts = saved


@pytest.mark.parametrize("code", sorted(STRONG_CASES))
def test_strong_flag_fires(code):
    rr = STRONG_CASES[code]()
    flag = next((f for f in rr.flags if f.code == code), None)
    assert flag is not None, (code, [f.code for f in rr.flags])
    assert flag.strength == "strong" and flag.points > 0 and flag.en and flag.ar
    assert rr.score >= 25 and rr.verdict != "SAFE" or code == "REPLY_TO_FREEMAIL_BRAND", (code, rr.score)


def test_strong_points_match_contract():
    expect = {"IDN_MIXED_SCRIPT": 65, "DISPLAY_NAME_CONFUSABLE": 65, "BIDI_OVERRIDE": 65, "CAMPAIGN_IOC_MATCH": 65,
              "LINK_HIGH_RISK": 65, "KNOWN_PHISHING_LINK": 70, "SENDER_LOOKALIKE": 50, "DANGEROUS_ATTACHMENT": 50,
              "INVISIBLE_IN_TOKEN": 45, "PUNYCODE_DOMAIN": 40, "DISPLAY_NAME_ADDRESS_SPOOF": 40, "DMARC_FAIL": 35,
              "DISPLAY_NAME_BRAND_SPOOF": 35, "FREEMAIL_BRAND_SENDER": 35, "LINK_TEXT_MISMATCH": 30,
              "SENDER_NEW_DOMAIN": 30, "LINK_SUSPICIOUS": 30, "REPLY_TO_FREEMAIL_BRAND": 25}
    expect_extra = {"OFFICIAL_SENDER_UNAUTHENTICATED": 40}
    assert set(expect_extra) <= R.STRONG_CODES and expect_extra.keys() & R.BRAND_CLAIM
    for code, pts in expect.items():
        rr = STRONG_CASES[code]()
        assert next(f for f in rr.flags if f.code == code).points == pts, code


def test_single_script_idn_alone_is_suspicious():
    rr = STRONG_CASES["PUNYCODE_DOMAIN"]()
    assert rr.score == 40 and rr.verdict == "SUSPICIOUS"


def test_punycode_not_double_counted_with_mixed_script():
    rr = STRONG_CASES["IDN_MIXED_SCRIPT"]()
    assert "IDN_MIXED_SCRIPT" in codes(rr) and "PUNYCODE_DOMAIN" not in codes(rr, False)
    assert rr.verdict == "HIGH-RISK SCAM"


def test_double_extension_and_rlo_exe():
    assert R.attachment_risk("Invoice_88412_‮fdp.exe")[0] == "dangerous"
    assert R.attachment_risk("photo.jpg.scr")[0] == "dangerous"
    assert R.attachment_risk("scan.pdf.zip")[0] == "dangerous"
    assert R.attachment_risk("report.pdf") == (None, None)
    assert R.attachment_risk("backup.tar.gz")[0] == "archive"


# -- weak flags ------------------------------------------------------------------------------------
WEAK_CASES = {
    "SPF_FAIL": dict(a=auth(spf="fail")),
    "SPF_SOFTFAIL": dict(a=auth(spf="softfail")),
    "DKIM_FAIL": dict(p=mail(from_addr="hi@brand-new-shop.test", byte_exact=True,
                             headers=[("DKIM-Signature", "v=1; d=brand-new-shop.test")]),
                      a=auth(dkim=[("brand-new-shop.test", "fail", "verified")])),
    "CREDENTIAL_REQUEST": dict(p=mail(from_addr="hi@brand-new-shop.test", body="Please confirm your identity and enter your password.")),
    "USER_MODEL_SCAM": dict(model={"available": True, "p_scam": 0.97, "labels": 30, "spec": "email-v1"}),
    "CAMPAIGN_LURE_MATCH": dict(campaigns=[{"id": "cmp-2", "title_en": "Parcel fee", "title_ar": "رسوم شحنة",
                                            "match": "lure", "points": 20, "matched": ["redelivery", "customs fee"]}]),
    "DMARC_FAIL_P_NONE": dict(a=auth(dmarc="fail", policy="none")),
    "NO_AUTHENTICATION": dict(a=auth(spf="none")),
    "REPLY_TO_MISMATCH": dict(p=mail(from_addr="hi@brand-new-shop.test", reply_to=("", "other@another-place.test"))),
    "URGENCY_LANGUAGE": dict(p=mail(from_addr="hi@brand-new-shop.test", body="Your account will be suspended within 24 hours.")),
    "PAYMENT_REQUEST": dict(p=mail(from_addr="hi@brand-new-shop.test", body="A customs fee of AED 12.50 is due before redelivery.")),
    "FANCY_UNICODE": dict(findings=scan_text("\U0001d401\U0001d40e\U0001d40b\U0001d403 offer", "subject")),
    "BRAND_MENTION": dict(p=mail(from_addr="hi@brand-new-shop.test", body="Track your Aramex shipment.")),
    "RETURN_PATH_MISMATCH": dict(p=mail(from_addr="hi@brand-new-shop.test", return_path="bounce@elsewhere-mailer.test")),
    "ATTACHMENT_ARCHIVE": dict(p=mail(from_addr="hi@brand-new-shop.test", attachments=["documents.zip"])),
}


def _weak(code, with_strong):
    kw = dict(WEAK_CASES[code])
    p = kw.pop("p", mail(from_addr="hi@brand-new-shop.test"))
    a = kw.pop("a", None)
    return run(p, a, age=NEW if with_strong else None, findings=kw.get("findings"),
               campaigns=kw.get("campaigns"), model=kw.get("model"))


@pytest.mark.parametrize("code", sorted(WEAK_CASES))
def test_weak_flag_counts_only_next_to_strong(code):
    rr = _weak(code, with_strong=True)
    f = next((f for f in rr.flags if f.code == code), None)
    assert f is not None and f.strength == "weak" and f.points > 0, (code, [x.code for x in rr.flags])
    alone = _weak(code, with_strong=False)
    fa = next(f for f in alone.flags if f.code == code)
    assert fa.points == 0 and alone.score == 0 and alone.verdict == "SAFE", code


def test_advice_is_not_a_credential_request():
    rr = run(mail(body="We will never ask for your password or OTP by email."), age=NEW)
    assert "CREDENTIAL_REQUEST" not in codes(rr, False)


# -- info flags ------------------------------------------------------------------------------------
# -- official address without proof --------------------------------------------------------------
def test_official_sender_unauthenticated():
    p = mail(from_name="Abu Dhabi Police", from_addr="fines@adpolice.gov.ae", body="Pay your fine now: AED 500 is due today.")
    rr = run(p, auth(spf="none"))
    f = next(f for f in rr.flags if f.code == "OFFICIAL_SENDER_UNAUTHENTICATED")
    assert f.strength == "strong" and f.points == 40 and f.en and f.ar
    assert rr.score >= 70 and rr.entity and rr.entity.name_en == "Abu Dhabi Police"  # brand claim + payment floor
    assert "OFFICIAL_SENDER_UNAUTHENTICATED" in codes(run(p, auth(spf="softfail", dmarc="fail", policy="reject")))


@pytest.mark.parametrize("kw,a", [
    (dict(), auth(spf="pass", dmarc="pass", align=True)),                                   # DMARC pass
    (dict(), auth(spf="none", dkim=[("adpolice.gov.ae", "pass", "auth_results")], align=True)),  # aligned DKIM
    (dict(), auth(spf="pass", align=True)),                                                 # aligned SPF
    (dict(has_headers=False), AuthReport.not_checked()),                                     # pasted visible text
    (dict(), auth(spf="none", arc="pass")),                                                  # ARC-vouched forward
])
def test_official_sender_unauthenticated_false_positives(kw, a):
    rr = run(mail(from_name="Abu Dhabi Police", from_addr="fines@adpolice.gov.ae", **kw), a)
    assert "OFFICIAL_SENDER_UNAUTHENTICATED" not in codes(rr, False)


def test_forged_list_id_does_not_hide_unauthenticated_official_sender():
    """E2E regression: "List-Id:" is a plain header anyone can type; it hid a spoofed adpolice.gov.ae (score 60 -> 0)."""
    rr = run(mail(from_name="Abu Dhabi Police", from_addr="fines@adpolice.gov.ae", list_id="news.adpolice.gov.ae"),
             auth(spf="none"))
    assert "OFFICIAL_SENDER_UNAUTHENTICATED" in codes(rr)


def test_unauthenticated_freemail_or_ordinary_sender_not_flagged():
    for address in ("someone@gmail.com", "sara@example.com"):
        assert "OFFICIAL_SENDER_UNAUTHENTICATED" not in codes(run(mail(from_addr=address), auth(spf="none")), False)


def test_info_flags():
    p = mail(from_name="FAB", from_addr="notifications@bankfab.com", list_id="news.bankfab.com",
             headers=[("List-Unsubscribe", "<mailto:u@bankfab.com>")])
    rr = run(p, auth(spf="pass", dmarc="pass", policy="reject", arc="pass", align=True),
             model={"available": True, "p_scam": 0.02, "labels": 40, "spec": "email-v1"})
    assert {"DMARC_PASS", "ARC_PASS", "BULK_SENDER", "OFFICIAL_SENDER", "USER_MODEL_TRUSTED"} <= codes(rr, False)
    assert all(f.points == 0 for f in rr.flags) and rr.verdict == "SAFE"
    rr = run(mail(has_headers=False), AuthReport.not_checked())
    assert "HEADERS_NOT_AVAILABLE" in codes(rr, False) and rr.score == 0


def test_freemail_dmarc_pass_explains_free_account():
    rr = run(mail(from_addr="someone@gmail.com"), auth(dmarc="pass", align=True))
    f = next(f for f in rr.flags if f.code == "DMARC_PASS")
    assert "anyone" in f.en


# -- floors, caps, suppression ------------------------------------------------------------------------
def test_brand_claim_plus_credential_request_floor_70():
    rr = run(mail(from_name="PayPal Service", from_addr="noreply@random-shop.test",
                  body="Log in here to confirm your identity."))
    assert {"DISPLAY_NAME_BRAND_SPOOF", "CREDENTIAL_REQUEST"} <= codes(rr) and rr.score >= 70


def test_brand_claim_plus_suspicious_link_floor_70():
    rr = run(mail(from_name="PayPal Service", from_addr="noreply@random-shop.test"),
             links=[link("odd-site.test", "SAFE", 30)])
    assert rr.score >= 70


def test_score_is_at_least_highest_link_score():
    rr = run(mail(), links=[link("a-site.test", "SAFE", 25)])
    assert rr.score == 25 and rr.max_link_score == 25


def test_score_is_capped_at_100():
    rr = run(mail(from_name="PayPal", from_addr="x@gmail.com", subject="PayPal limited",
                  attachments=["a.exe"], body="confirm your identity within 24 hours"),
             links=[link("tamm-smart-pay.net", "HIGH-RISK SCAM", 95)])
    assert rr.score == 100


def test_authenticated_official_sender_cap_20():
    p = mail(from_name="Emirates Post partner notice", from_addr="notifications@bankfab.com")
    rr = run(p, auth(spf="pass", dmarc="pass", policy="reject", align=True))
    assert "DISPLAY_NAME_BRAND_SPOOF" in codes(rr) and rr.score == 20 and rr.capped and rr.verdict == "SAFE"
    rr = run(p, auth(dmarc="pass", align=True), links=[link("tamm-smart-pay.net", "HIGH-RISK SCAM", 92)])
    assert rr.score >= 65 and not rr.capped  # a scam link is never vouched away


def test_freemail_sender_is_never_capped():
    rr = STRONG_CASES["FREEMAIL_BRAND_SENDER"]()
    rr2 = run(mail(from_name="Delivery", from_addr="aramex.uae.2026@gmail.com", subject="Your Aramex parcel is waiting"),
              auth(dmarc="pass", align=True))
    assert rr2.score == rr.score > 20


def test_mailing_list_suppresses_dkim_reply_to_return_path():
    p = mail(from_addr="hi@brand-new-shop.test", list_id="group.example.org", byte_exact=True,
             reply_to=("", "other@another-place.test"), return_path="bounce@elsewhere-mailer.test",
             headers=[("DKIM-Signature", "v=1; d=brand-new-shop.test")])
    rr = run(p, auth(dkim=[("brand-new-shop.test", "fail", "verified")]), age=NEW)
    assert not {"DKIM_FAIL", "REPLY_TO_MISMATCH", "RETURN_PATH_MISMATCH"} & codes(rr, False)


def test_dkim_fail_needs_byte_exact_source():
    p = mail(from_addr="hi@brand-new-shop.test", byte_exact=False, headers=[("DKIM-Signature", "v=1")])
    rr = run(p, auth(dkim=[("brand-new-shop.test", "fail", "verified")]), age=NEW)
    assert "DKIM_FAIL" not in codes(rr, False)
    rr = run(p, auth(dkim=[("brand-new-shop.test", "fail", "verified"), ("esp.test", "pass", "auth_results")]), age=NEW)
    assert "DKIM_FAIL" not in codes(rr, False)


def test_via_display_name_is_not_a_spoof():
    rr = run(mail(from_name="'service@paypal.com' via PayPal Fans", from_addr="fans@googlegroups.com"))
    assert not {"DISPLAY_NAME_BRAND_SPOOF", "DISPLAY_NAME_ADDRESS_SPOOF"} & codes(rr, False)


def test_brand_own_domains_are_not_spoofs():
    for name, address in [("PayPal", "service@intl.paypal.com"), ("Facebook", "notification@facebookmail.com"),
                          ("Amazon.ae", "order-update@amazon.com"), ("TAMM", "noreply@tamm.abudhabi")]:
        rr = run(mail(from_name=name, from_addr=address))
        assert not {"DISPLAY_NAME_BRAND_SPOOF", "DISPLAY_NAME_ADDRESS_SPOOF", "BRAND_MENTION"} & codes(rr, False), name


def test_entity_only_with_strong_evidence():
    rr = run(mail(body="I bought it on PayPal yesterday."))
    assert rr.entity is None
    rr = STRONG_CASES["DISPLAY_NAME_BRAND_SPOOF"]()
    assert rr.entity and rr.entity.name_en == "PayPal"


# -- links helpers ------------------------------------------------------------------------------------
def test_unwrap_known_wrappers():
    g = "https://www.google.com/url?q=https%3A%2F%2Fevil.test%2Fa%3Fb%3D1&sa=D"
    assert R.unwrap_url(g) == ("https://evil.test/a?b=1", g)
    s = "https://nam12.safelinks.protection.outlook.com/?url=https%3A%2F%2Fevil.test%2Flogin&data=05%7C01"
    assert R.unwrap_url(s)[0] == "https://evil.test/login"
    fb = "https://l.facebook.com/l.php?u=https%3A%2F%2Fevil.test%2F&h=AT0"
    assert R.unwrap_url(fb)[0] == "https://evil.test/"
    pp = "https://urldefense.proofpoint.com/v2/url?u=https-3A__evil.test_login&d=DwMF"
    assert R.unwrap_url(pp)[0] == "https://evil.test/login"
    nested = "https://www.google.com/url?q=" + "https%3A%2F%2Fnam1.safelinks.protection.outlook.com%2F%3Furl%3Dhttps%253A%252F%252Fevil.test%252F"
    assert R.unwrap_url(nested)[0] == "https://evil.test/"
    assert R.unwrap_url("https://example.com/page") == ("https://example.com/page", None)


def test_link_text_mismatch_rules():
    assert R.link_text_mismatch("https://www.paypal.com/signin", "paypal-account-review.test") == (True, "www.paypal.com")
    assert R.link_text_mismatch("www.example.com", "u8812.ct.sendgrid.net")[0] is False   # ESP click tracker
    assert R.link_text_mismatch("Verify my card", "evil.test")[0] is False              # not an address
    assert R.link_text_mismatch("www.bankfab.com", "www.bankfab.com")[0] is False
    assert R.link_text_mismatch("amazon.ae", "www.amazon.com")[0] is False              # same brand
    assert R.link_text_mismatch("PаyPal.com", "evil.test")[0] is True              # deconfused text


# -- LLM blend -----------------------------------------------------------------------------------------
def test_blend_email():
    strong = STRONG_CASES["LINK_TEXT_MISMATCH"]()          # score 30, strong evidence
    assert R.blend_email(strong, None) == 30
    assert R.blend_email(strong, {"verdict": "HIGH-RISK SCAM", "risk_score": 90, "confidence": 0.9}) == round(0.25 * 30 + 0.75 * 90)
    assert R.blend_email(strong, {"verdict": "SAFE", "risk_score": 0, "confidence": 0.99}) == 30     # never lowered
    assert R.blend_email(strong, {"verdict": "HIGH-RISK SCAM", "risk_score": 90, "confidence": 0.4}) == 30  # not confident
    weak = run(mail(body="Prince needs your help"))                     # no strong flag
    assert R.blend_email(weak, {"verdict": "HIGH-RISK SCAM", "risk_score": 95, "confidence": 0.9}) == 48   # SUSPICIOUS at most
    capped = run(mail(from_name="Emirates Post partner", from_addr="n@bankfab.com"), auth(dmarc="pass", align=True))
    assert capped.capped and R.blend_email(capped, {"verdict": "HIGH-RISK SCAM", "risk_score": 99, "confidence": 0.99}) == 20


def test_template_explanations_bilingual():
    rr = STRONG_CASES["DISPLAY_NAME_BRAND_SPOOF"]()
    en, ar = R.template_explanations(rr)
    assert "PayPal" in en and "paypal.com" in en and ar and "8002626" in ar
    en, ar = R.template_explanations(run(mail()))
    assert "No major red flags" in en and ar


# -- personal model as a weak signal (USER_MODEL_SCAM) ------------------------------------------------------
def _model(p):
    return {"available": True, "p_scam": p, "labels": 80, "spec": "email-v1"}


PAY_BODY = "Please send the wire transfer today to our new account."


def test_personal_model_plus_scam_request_is_suspicious_at_most():
    rr = run(mail(from_addr="accounts.dept77@outlook.com", body=PAY_BODY), model=_model(0.999))
    assert rr.verdict == "SUSPICIOUS" and 30 <= rr.score <= 64, (rr.score, codes(rr, False))
    assert {"USER_MODEL_SCAM", "PAYMENT_REQUEST"} <= codes(rr) and not rr.strong_present and rr.entity is None
    # every corroborating weak flag at once still never reaches HIGH-RISK on the model's word
    rr = run(mail(from_addr="accounts.dept77@outlook.com", reply_to=("", "pay@another-place.test"),
                  body=PAY_BODY + " Confirm your identity and enter your password. Your account will be suspended."),
             auth(spf="fail", dmarc="fail", policy="none"), model=_model(1.0),
             campaigns=WEAK_CASES["CAMPAIGN_LURE_MATCH"]["campaigns"])
    assert rr.verdict == "SUSPICIOUS" and rr.score == 64


@pytest.mark.parametrize("kw", [
    dict(p=mail(from_addr="friend.person@outlook.com", body="See you on Friday."), model=_model(0.999)),  # model alone
    dict(p=mail(from_addr="friend.person@outlook.com", body=PAY_BODY), model=_model(0.95)),  # below MODEL_FLOOR_P
    dict(p=mail(from_addr="friend.person@outlook.com", body=PAY_BODY), model=None),  # no model
    dict(p=mail(from_addr="friend.person@outlook.com", body="Urgent: reply within 24 hours."), model=_model(0.999)),
    dict(p=mail(from_addr="noreply@github.com", body="Use the link to reset your password. Sign in to confirm your account."),
         model=_model(0.999)),  # top-10k sender: authentication rules judge it, not the personal model
])
def test_personal_model_never_lifts_without_corroboration(kw):
    rr = run(kw["p"], model=kw["model"])
    assert rr.verdict == "SAFE" and rr.score == 0, (rr.score, codes(rr, False))


def test_regression_plain_text_punycode_in_body_is_high_risk_once():
    """'Go to xn--pypal-4ve.com' as plain text: look-alike domain in the body (HIGH-RISK), not also
    counted a second time as PUNYCODE_DOMAIN."""
    body = "Your account is limited. Go to xn--pypal-4ve.com and log in."
    rr = run(mail(body=body), findings=scan_text(body, "body"))
    assert "DISPLAY_NAME_CONFUSABLE" in codes(rr) and "PUNYCODE_DOMAIN" not in codes(rr), codes(rr)
    assert rr.verdict == "HIGH-RISK SCAM"


def test_regression_percent_encoded_link_host():
    assert R.host_of("https://p%D0%B0ypal.com/signin") == "xn--pypal-4ve.com"
    assert R.host_of("https://example.com/%D0%B0") == "example.com"
    assert R.host_of("https://a%2Fb.example/") == "a%2fb.example"
