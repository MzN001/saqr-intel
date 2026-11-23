"""Short courier brands (DHL, UPS) as an EMAIL brand claim, and subjects that warn ABOUT a scam.

ai_inspector._entity_in_text skips global brand names under 4 letters, so "DHL Express <x@gmail.com>"
used to pass as an ordinary sender. email_rules.short_brand_claim recognises them in the display name /
subject only (website scanning keeps using _entity_in_text unchanged), as a whole word next to courier
wording; "ups" in normal English never counts. A friend's "Be careful: fake DHL emails" warning is not a
brand claim either. Offline: ParsedEmail / AuthReport are built by hand."""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402

from saqr.intel import email_rules as R  # noqa: E402
from saqr.intel.ai_inspector import _entity_in_text  # noqa: E402
from saqr.intel.email_types import (  # noqa: E402
    Address, AuthARC, AuthDMARC, AuthReport, AuthSPF, ParsedEmail,
)

CUSTOMS_LURE = [{"id": "cmp-f9622df3", "title_en": 'Courier "customs duties due" emails', "title_ar": "رسوم جمركية",
                 "match": "lure", "points": 20, "matched": ["customs duties", "could not be delivered"]}]
DHL_BODY = ("Your parcel could not be delivered because the customs duties have not been paid. "
            "Pay the customs fee of AED 18 within 24 hours.")


def mail(from_name, from_addr, subject="Hello", body="See you soon."):
    dom = from_addr.rpartition("@")[2].lower()
    return ParsedEmail(source="raw", has_headers=True, byte_exact=False, raw_bytes=None, headers=[], subject=subject,
                       date="", from_=Address(from_name, from_addr, dom), reply_to=None, return_path=None, sender=None,
                       to_count=1, list_id=None, text_body=body, html_body="", links=[], attachments=[])


def auth(dmarc="none", policy=None, align=False):
    return AuthReport(trusted_authserv="mx.google.com", spf=AuthSPF("pass" if align else "none", "", "", "auth_results"),
                      dkim=[], dmarc=AuthDMARC(dmarc, policy, {"spf": align, "dkim": align}, "auth_results"),
                      arc=AuthARC("none", 0))


def run(p, a=None, campaigns=None):
    return R.run_email_rules(p, a or auth(), unicode_findings=[], link_results=[], campaign_matches=campaigns or [],
                             user_model=None)


def codes(rr):
    return {f.code for f in rr.flags if f.points > 0}


@pytest.mark.parametrize("from_name,subject", [
    ("DHL Express", "Your shipment is waiting clearance fees"),
    ("DHL", "Notification"),                       # the whole display name is the brand
    ("dhl express delivery", "Pending"),           # DHL is no English word: any case
    ("DHL-Express Customer Service", "Hello"),
    ("UPS", "Hello"),
    ("UPS Delivery Notification", "Action needed"),
    ("UPS Customer Care", "Your package is on hold"),  # courier wording in the subject
    ("Customer Care", "UPS: your package could not be delivered"),  # subject claim + free mail
])
def test_short_courier_brand_from_freemail_is_a_brand_claim(from_name, subject):
    rr = run(mail(from_name, "parcel.desk.2026@gmail.com", subject))
    assert "FREEMAIL_BRAND_SENDER" in codes(rr), (from_name, subject, codes(rr))
    assert rr.entity and rr.entity.id in ("dhl", "ups")


def test_dhl_display_name_with_customs_lure_is_high_risk_and_names_the_campaign():
    rr = run(mail("DHL Express", "dhl.express.clearance@gmail.com", "Your parcel: customs duties unpaid", DHL_BODY),
             campaigns=CUSTOMS_LURE)
    assert {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER", "CAMPAIGN_LURE_MATCH"} <= codes(rr)
    assert rr.verdict == "HIGH-RISK SCAM" and rr.score >= 70 and rr.entity.id == "dhl"
    # same mail from a non-free look-alike shop domain: display-name spoof still counts
    rr = run(mail("DHL Express", "notice@parcel-centre-mail.com", "Customs duties unpaid", DHL_BODY))
    assert "DISPLAY_NAME_BRAND_SPOOF" in codes(rr)


@pytest.mark.parametrize("from_name,from_addr,a", [
    ("DHL Express", "noreply@dhl.com", auth("pass", "reject", True)),
    ("DHL Paket", "noreply@dhl.de", auth("pass", "reject", True)),
    ("DHL Parcel UK", "noreply@dhlparcel.co.uk", auth("pass", "reject", True)),
    ("UPS My Choice", "mcinfo@ups.com", auth("pass", "reject", True)),
])
def test_real_courier_senders_are_not_brand_spoofs(from_name, from_addr, a):
    rr = run(mail(from_name, from_addr, "Duties and taxes due for your shipment", DHL_BODY), a, campaigns=CUSTOMS_LURE)
    assert not codes(rr) & {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER", "SENDER_LOOKALIKE"}, codes(rr)
    assert rr.verdict == "SAFE"


@pytest.mark.parametrize("from_name,subject,body", [
    ("Ups and Downs Fitness", "Class schedule", "New classes next week."),
    ("Maya", "Follow-UPS for the delivery meeting", "Notes from the delivery meeting attached."),
    ("Maya", "ups, sorry about the parcel", "I sent the parcel to the wrong flat."),
    ("Maya", "Thumbs ups and pop-ups for the shipping page", "See the shipping page mock-up."),
    ("Tech Deals", "UPS battery backup sale - free shipping", "1500VA UPS, free delivery this week."),
    ("UPS Battery Store", "New stock", "Uninterruptible power supply units, free shipping."),
    ("Omar", "DHL or the post office?", "Which one is cheaper to send to Jordan?"),  # no courier wording
    ("Adhl Group", "Shipment update", "Your shipment is ready."),  # DHL inside another word
])
def test_ordinary_words_and_names_are_not_courier_claims(from_name, subject, body):
    rr = run(mail(from_name, "someone.person@gmail.com", subject, body))
    assert not codes(rr) & {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER"}, (subject, codes(rr))
    assert rr.verdict == "SAFE"


@pytest.mark.parametrize("subject,body,campaigns", [
    ("Be careful: fake DHL customs fee emails",
     "The email said her DHL parcel could not be delivered because customs duties have not been paid, and "
     "asked her to pay customs fees by card. It is a scam.", CUSTOMS_LURE),
    ('Watch out for the PayPal "pending charge" scam',
     "You get a PayPal email about a pending charge of USD 987.90 and it says call us immediately to cancel "
     "this transaction. Do not call the number!",
     [{"id": "cmp-772733ae", "title_en": "PayPal call-us", "title_ar": "باي بال", "match": "lure", "points": 20,
       "matched": ["pending charge", "call us immediately"]}]),
    ("احذروا من رسائل احتيال باسم أرامكس", "رسالة تطلب دفع رسوم جمركية لشحنة غير مسلمة.", CUSTOMS_LURE),
])
def test_a_friend_warning_about_a_scam_is_not_a_scam(subject, body, campaigns):
    rr = run(mail("Sara Ahmed", "sara.ahmed.family@gmail.com", subject, body), campaigns=campaigns)
    assert not rr.strong_present and rr.verdict == "SAFE", (rr.score, codes(rr))


def test_display_name_brand_still_counts_when_the_subject_mentions_scams():
    rr = run(mail("PayPal Security", "paypal.security.team@gmail.com", "Scam alert: confirm your account",
                  "Sign in and confirm your password to keep your account."))
    assert {"DISPLAY_NAME_BRAND_SPOOF", "FREEMAIL_BRAND_SENDER"} <= codes(rr) and rr.verdict == "HIGH-RISK SCAM"


def test_website_brand_matching_is_unchanged():
    # the website / SMS path still ignores short names; only the email display-name / subject path uses them
    assert _entity_in_text("DHL Express customs fee") is None
    assert _entity_in_text("UPS package on hold") is None
    assert [e.id for e in R.SHORT_BRANDS] == ["dhl", "ups"]
