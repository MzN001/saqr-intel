"""Phone intelligence (saqr/intel/phone_intel.py) + the registry facts built on it: normalise_phone keys,
VERIFIED_PHONES, new official domains, the gov.ae rule. Offline.

Run: pytest -q tests/test_phone_intel.py
"""
import os
import subprocess
import sys
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")

import pytest  # noqa: E402

from saqr.intel import page_signals, phone_intel  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical, gov_ae_domain, official_match  # noqa: E402
from saqr.intel.registry import (ENTITY_BY_ID, OFFICIAL_PHONES, VERIFIED_PHONES,  # noqa: E402
                                 normalise_phone)


# --- parsing matrix -------------------------------------------------------------------------
@pytest.mark.parametrize("raw", ["800555", "800 555", "+971 800 555", "971800555", "00971800555", "800-555",
                                 "+971 (0) 800 555", "tel:800555", "٨٠٠٥٥٥"])
def test_uae_toll_free_all_spellings(raw):
    info = phone_intel.analyze(raw)
    assert (info.e164, info.national, info.key) == ("+971800555", "800555", "800555")
    assert info.is_valid and info.is_uae and info.line_type == "toll_free"
    assert (info.country_code, info.region) == (971, "AE")
    assert not info.is_uae_mobile and not info.is_short_code


@pytest.mark.parametrize("raw", ["600599999", "600 59 9999", "+971 600 599999", "971600599999", "00971 600 599 999"])
def test_uae_shared_cost_600_numbers(raw):
    info = phone_intel.analyze(raw)
    assert (info.e164, info.key, info.line_type) == ("+971600599999", "600599999", "shared_cost")


@pytest.mark.parametrize("raw", ["+971 50 123 4567", "+971 (0) 50 123 4567", "00971501234567", "0501234567",
                                 "050-123-4567", "tel:+971501234567", "tel://+971-50-123-4567", "٠٥٠١٢٣٤٥٦٧",
                                 "۰۵۰۱۲۳۴۵۶۷", "971501234567"])
def test_uae_mobile_all_spellings(raw):
    info = phone_intel.analyze(raw)
    assert (info.e164, info.key, info.line_type) == ("+971501234567", "971501234567", "mobile")
    assert info.is_uae_mobile and info.is_valid


@pytest.mark.parametrize("raw,line,key", [
    ("02 444 4444", "fixed_line", "97124444444"),
    ("+971 4 555 1234", "fixed_line", "97145551234"),
    ("8002626", "toll_free", "8002626"),
    ("600525500", "shared_cost", "600525500"),
])
def test_uae_line_types(raw, line, key):
    info = phone_intel.analyze(raw)
    assert (info.line_type, info.key, info.is_uae, info.is_uae_mobile) == (line, key, True, False)


def test_foreign_numbers():
    gb = phone_intel.analyze("+44 20 7946 0958")
    assert (gb.is_valid, gb.is_uae, gb.region, gb.country_code, gb.line_type) == (True, False, "GB", 44, "fixed_line")
    assert gb.key == "442079460958" and gb.e164 == "+442079460958"
    # not a real NANP number: never valid, region from the calling code (not the library's DO guess)
    us = phone_intel.analyze("+1 800 123 4567")
    assert (us.is_valid, us.e164, us.region, us.line_type, us.key) == (False, None, "US", "unknown", "18001234567")


@pytest.mark.parametrize("raw", ["999", "901", "2828", "101", "155", "998", "tel:999", "٩٩٩"])
def test_uae_short_codes(raw):
    info = phone_intel.analyze(raw)
    assert info.is_short_code and info.is_uae and info.e164 is None and not info.is_valid
    assert info.key == info.national and len(info.key) in (3, 4)


@pytest.mark.parametrize("raw", [None, "", "abcd", "+", "call us", "--"])
def test_invalid_input(raw):
    info = phone_intel.analyze(raw)
    assert (info.key, info.e164, info.is_valid, info.line_type, info.is_short_code) == ("", None, False, "unknown", False)


def test_odd_digits_fall_back_without_crashing():
    assert phone_intel.analyze("12").key == "12"
    assert phone_intel.analyze("12345").key == "12345"
    assert not phone_intel.analyze("+971 12").is_valid
    assert phone_intel.analyze("+971 800 555").to_dict()["line_type"] == "toll_free"


def test_no_heavy_phonenumbers_modules():
    code = ("import sys; import saqr.intel.phone_intel as p; p.analyze('+971501234567'); p.analyze('999');"
            "bad=[m for m in sys.modules if m.startswith(('phonenumbers.carrier','phonenumbers.geocoder',"
            "'phonenumbers.timezone','phonenumbers.geodata','phonenumbers.carrierdata','phonenumbers.tzdata'))];"
            "print(bad); sys.exit(1 if bad else 0)")
    r = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                       cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    assert r.returncode == 0, r.stdout + r.stderr


# --- registry keys --------------------------------------------------------------------------
@pytest.mark.parametrize("raw,key", [
    ("+971 800 555", "800555"), ("971800555", "800555"), ("800 555", "800555"),          # was 971800555 != 800555
    ("+971 600 599999", "600599999"), ("999", "999"), ("+971 50 000 7781", "971500007781"),
    ("024444444", "97124444444"), (None, ""), ("", ""),
])
def test_normalise_phone_keys(raw, key):
    assert normalise_phone(raw) == key


def test_international_toll_free_matches_the_official_registry():
    assert OFFICIAL_PHONES[normalise_phone("+971 800 555")].id == "tamm"
    assert OFFICIAL_PHONES[normalise_phone("+971 600 599999")].id == "emiratespost"
    assert OFFICIAL_PHONES[normalise_phone("+971 800 2626")].id == "adpolice"


def test_registry_phone_keys_are_already_canonical():
    for key, ent in OFFICIAL_PHONES.items():
        assert normalise_phone(key) == key, (key, ent.id)


def test_verified_phones():
    assert {"999", "8002626", "2828", "8003333", "800555", "600599999", "600525500", "101"} <= set(VERIFIED_PHONES)
    for num, src in VERIFIED_PHONES.items():
        assert num in OFFICIAL_PHONES, num                       # only numbers the registry actually uses
        assert src.startswith("https://"), num
    assert "600599995" not in OFFICIAL_PHONES                    # not on emiratespost.ae
    assert "901" not in ENTITY_BY_ID["adpolice"].phones          # 901 is Dubai/Sharjah/RAK, not Abu Dhabi Police


# --- new official domains -------------------------------------------------------------------
@pytest.mark.parametrize("host,match", [
    ("salik.ae", "salik.ae"), ("www.salik.ae", "salik.ae"), ("dib.ae", "dib.ae"), ("www.cbd.ae", "cbd.ae"),
    ("rakbank.ae", "rakbank.ae"), ("online.rakbank.ae", "rakbank.ae"),
])
def test_new_official_domains(host, match):
    lex = analyze_lexical(host)
    assert lex.is_whitelisted and lex.official_match == match and lex.score == 0


@pytest.mark.parametrize("domain", ["cbd-oil-shop.com", "dibs.com", "cbdx.com", "dibcafe.com", "my-cbd.store",
                                    "dib.com", "cbd.com"])
def test_three_letter_trusted_labels_are_not_lookalike_targets(domain):
    lex = analyze_lexical(domain)
    assert not lex.is_whitelisted
    assert not {f.code for f in lex.flags} & {"TYPOSQUAT", "BRAND_IMPERSONATION", "TLD_SWAP", "HOMOGLYPH_SPOOF"}, \
        [(f.code, f.en) for f in lex.flags]


def test_salik_and_rakbank_impersonation_still_caught():
    assert analyze_lexical("salik-fine-pay.com").impersonated.id == "rta"
    assert analyze_lexical("rakbank-verify-login.com").impersonated.id == "rakbank"


# --- gov.ae ---------------------------------------------------------------------------------
@pytest.mark.parametrize("host,match", [
    ("adpolice.gov.ae", "adpolice.gov.ae"), ("www.itc.gov.ae", "itc.gov.ae"),
    ("darb.itc.gov.ae", "itc.gov.ae"), ("admobility.gov.ae", "admobility.gov.ae"),
    ("a.b.c.mohap.gov.ae", "mohap.gov.ae"), ("WWW.SOMEAUTHORITY.GOV.AE.", "someauthority.gov.ae"),
])
def test_any_registered_gov_ae_domain_is_official(host, match):
    assert gov_ae_domain(host) == match
    lex = analyze_lexical(host)
    assert lex.is_whitelisted and lex.score == 0
    assert page_signals.lexical(host).is_whitelisted


@pytest.mark.parametrize("host", [
    "gov.ae", "adpolice-gov.ae.evil.com", "gov.ae.example.com", "adpolice.gov.ae.evil.com", "evilgov.ae",
    "gov-ae.com", "adpolicegov.ae", "www.gov.ae.secure-pay.xyz", "adpolice.gov.ae-verify.com",
])
def test_gov_ae_lookalikes_are_not_official(host):
    assert gov_ae_domain(host) is None
    assert official_match(host) is None
    assert not analyze_lexical(host).is_whitelisted


def test_gov_ae_lookalike_still_flagged():
    lex = analyze_lexical("adpolice.gov.ae.fines-pay.xyz")
    assert not lex.is_whitelisted and lex.score >= 40, [(f.code, f.points) for f in lex.flags]
