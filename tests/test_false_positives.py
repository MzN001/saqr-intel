"""Regression tests for false alarms found when scanning real, legitimate websites.

Run: pytest -q
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")

import pytest  # noqa: E402

from saqr.intel.ai_inspector import run_rules  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402
from saqr.intel.sandbox import Sandbox, classify_fields  # noqa: E402

OLD_DOMAIN = {"domain_age_hours": 24 * 365 * 20}


def _page(fields, *, text="", cloaking=False, ext=()):
    return {"page_title": "", "text": text, "harvested_fields": classify_fields([{"fields": fields}]),
            "cloaking": {"detected": cloaking}, "external_form_actions": list(ext), "final_url": "https://x"}


# --- field classification -------------------------------------------------------------
@pytest.mark.parametrize("field", [
    {"name": "monthly", "type": "radio", "label": "One time"},                       # Wikipedia donation
    {"name": "plateCode", "type": "select-one", "label": "الرمز"},                    # RTA plate code
    {"name": "departing", "type": "text", "placeholder": "DD/MM/YYYY HH:MM"},         # RTA journey planner
    {"name": "q", "type": "text", "placeholder": "Explore services"},
    {"name": "treatment", "type": "text", "label": "Treatment"},
])
def test_ordinary_fields_are_not_sensitive(field):
    found = set(classify_fields([{"fields": [field]}]))
    assert not {"OTP", "CARD_EXPIRY", "ATM_PIN", "CARD_NUMBER", "CVV"} & found, found


@pytest.mark.parametrize("field,expected", [
    ({"name": "otp", "type": "text"}, "OTP"),
    ({"name": "code", "type": "text", "label": "رمز التحقق"}, "OTP"),
    ({"name": "cc", "type": "text", "autocomplete": "cc-number"}, "CARD_NUMBER"),
    ({"name": "cardNumber", "type": "tel"}, "CARD_NUMBER"),
    ({"name": "cvv", "type": "tel"}, "CVV"),
    ({"name": "exp", "type": "text", "placeholder": "MM/YY"}, "CARD_EXPIRY"),
    ({"name": "pin", "type": "password", "label": "ATM PIN"}, "PASSWORD"),
])
def test_scam_fields_still_detected(field, expected):
    assert expected in classify_fields([{"fields": [field]}])


# --- cloaking --------------------------------------------------------------------------
def test_bot_blocking_without_sensitive_form_is_not_cloaking():
    naive = {"status": 403, "title": "", "text": "", "html": ""}
    rendered = {"page_title": "Wikipedia", "text": "The free encyclopedia", "http_status": 200,
                "harvested_fields": [], "forms": [{}]}
    assert Sandbox._cloak_verdict(naive, rendered)["detected"] is False


def test_hidden_payment_form_is_cloaking():
    naive = {"status": 404, "title": "Under Construction", "text": "coming soon", "html": ""}
    rendered = {"page_title": "TAMM Pay", "text": "Pay your fine now", "http_status": 200,
                "harvested_fields": ["CARD_NUMBER", "CVV"], "forms": [{}]}
    assert Sandbox._cloak_verdict(naive, rendered)["detected"] is True


# --- scoring -------------------------------------------------------------------------------
def test_legit_site_with_login_and_uae_pass_button_is_safe():
    # e.g. a government portal: "Sign in with UAE PASS", a password box, JS-rendered page
    page = _page([{"name": "password", "type": "password"}], text="Sign in with UAE PASS", cloaking=True,
                 ext=["https://auth.example.org/login"])
    rr = run_rules(analyze_lexical("portal.example.org"), OLD_DOMAIN, page, None)
    assert rr.verdict == "SAFE", (rr.score, [(f.code, f.points) for f in rr.flags])
    assert rr.entity is None


def test_lookalike_with_uae_pass_login_is_still_flagged():
    page = _page([{"name": "password", "type": "password"}], text="UAE PASS login", cloaking=True)
    rr = run_rules(analyze_lexical("uaepass-verify-login.xyz"), {}, page, None)
    assert rr.verdict == "HIGH-RISK SCAM", (rr.score, [(f.code, f.points) for f in rr.flags])


def test_old_domain_harvesting_cards_with_brand_is_still_a_scam():
    # compromised old website hosting a TAMM payment kit
    page = _page([{"name": "cardNumber"}, {"name": "cvv"}, {"name": "otp"}], text="TAMM Abu Dhabi payment")
    rr = run_rules(analyze_lexical("old-bakery-site.com"), OLD_DOMAIN, page, None)
    assert rr.verdict == "HIGH-RISK SCAM", (rr.score, [(f.code, f.points) for f in rr.flags])


@pytest.mark.parametrize("domain", ["u.ae", "www.rta.ae", "www.emirates.com", "smartservices.icp.gov.ae"])
def test_trusted_uae_sites_are_whitelisted(domain):
    lex = analyze_lexical(domain)
    assert lex.is_whitelisted and lex.score == 0
