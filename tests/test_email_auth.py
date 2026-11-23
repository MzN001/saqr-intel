"""Tests for saqr.intel.email_auth (workstream A). Fully offline: DKIM / ARC signatures are made at test
time with a fresh RSA key and DNS is a stub. Run: pytest -q tests/test_email_auth.py"""
import asyncio
import base64
import os
import tempfile
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import dkim  # noqa: E402
import pytest  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402

from saqr.intel import email_auth as ea  # noqa: E402
from saqr.intel import email_parse as ep  # noqa: E402
from saqr.intel.email_types import AuthReport  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "emails"


def run(coro):
    return asyncio.run(coro)


# ---------------------------------------------------------------------------
# Test keys + stub DNS
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                           serialization.NoEncryption())
    pub = k.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return priv, b"v=DKIM1; k=rsa; p=" + base64.b64encode(pub)


class StubDNS:
    """dkimpy-style dnsfunc: name (bytes, trailing dot) -> TXT bytes or None; records every query."""

    def __init__(self, records=None, fail=()):
        self.records = {k.lower(): v for k, v in (records or {}).items()}
        self.fail = {f.lower() for f in fail}
        self.queries = []

    def __call__(self, name, timeout=5):
        n = (name.decode() if isinstance(name, bytes) else name).lower()
        self.queries.append(n)
        if n in self.fail:
            raise TimeoutError("stub DNS timeout")
        return self.records.get(n)


BODY = b"Hello,\r\n\r\nYour order 1234 has shipped.\r\n"


def message(from_addr=b"shop@example.com", extra_top=b"", body=BODY):
    return (extra_top
            + b"From: Example Shop <" + from_addr + b">\r\n"
            b"To: customer@example.net\r\n"
            b"Subject: Your order has shipped\r\n"
            b"Date: Mon, 23 Nov 2026 10:00:00 +0400\r\n"
            b"Message-ID: <order1234@example.com>\r\n"
            b"MIME-Version: 1.0\r\n"
            b"Content-Type: text/plain; charset=utf-8\r\n"
            b"\r\n" + body)


def signed(key, domain=b"example.com", selector=b"s1", **kw):
    msg = message(**kw)
    sig = dkim.sign(msg, selector, domain, key[0], include_headers=[b"from", b"to", b"subject", b"date"])
    return sig + msg


def verify_eml(data, **kw):
    return run(ea.verify(ep.parse(source="eml", file_bytes=data), **kw))


# ---------------------------------------------------------------------------
# Shared fixtures (header-only, offline)
# ---------------------------------------------------------------------------
EXPECTED = {
    "legit_arabic_bank.eml": dict(authserv="mx.google.com", spf=("pass", "bankfab.com", "192.0.2.45"),
                                  dkim=[("bankfab.com", "selector1", "pass", True)],
                                  dmarc=("pass", "reject", {"spf": True, "dkim": True})),
    "legit_newsletter_list.eml": dict(authserv="mx.google.com", spf=("pass", "sendgrid.net", "198.51.100.20"),
                                      dkim=[("example.com", "s1", "pass", True), ("sendgrid.info", "smtpapi", "pass", False)],
                                      dmarc=("pass", "reject", {"spf": False, "dkim": True})),
    "phish_paypal_cyrillic.eml": dict(authserv="mx.google.com", spf=("pass", "gmail.com", "209.85.220.41"),
                                      dkim=[("gmail.com", "20230601", "pass", True)],
                                      dmarc=("pass", "none", {"spf": True, "dkim": True})),
    # Received by an unknown provider: its own Authentication-Results are not believed.
    "phish_bidi_attachment.eml": dict(authserv=None, spf=("not_checked", "", ""), dkim=[],
                                      dmarc=("not_checked", None, {"spf": False, "dkim": False})),
    "phish_punycode_sender.eml": dict(authserv=None, spf=("not_checked", "", ""), dkim=[],
                                      dmarc=("not_checked", None, {"spf": False, "dkim": False})),
    "legit_plain.eml": dict(authserv=None, spf=("not_checked", "", ""), dkim=[],
                            dmarc=("not_checked", None, {"spf": False, "dkim": False})),
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_shared_fixtures_offline(name):
    exp = EXPECTED[name]
    r = verify_eml((FIXTURES / name).read_bytes(), offline=True)
    assert r.trusted_authserv == exp["authserv"]
    assert (r.spf.result, r.spf.domain, r.spf.client_ip) == exp["spf"]
    assert [(d.domain, d.selector, d.result, d.aligned) for d in r.dkim] == exp["dkim"]
    assert (r.dmarc.result, r.dmarc.policy, r.dmarc.alignment) == exp["dmarc"]
    assert r.arc.result == "none" and r.arc.chain_length == 0
    if exp["authserv"]:
        assert r.spf.source == r.dmarc.source == "auth_results"
        assert all(d.source == "auth_results" for d in r.dkim)


def test_contract_sample_matches():
    import json

    sample = json.loads((Path(__file__).parent / "fixtures" / "contract" / "analyze_email_response.json").read_text())
    r = verify_eml((FIXTURES / "phish_paypal_cyrillic.eml").read_bytes(), offline=True)
    assert r.to_dict() == sample["authentication"]


def test_fake_dkim_signatures_fail_when_verified(key):
    """The shared fixtures carry fake signatures: real crypto (stub DNS with an unrelated key) says fail,
    but the trusted provider's verdict for those signatures still wins (it saw the original message)."""
    dns = StubDNS({"selector1._domainkey.bankfab.com.": key[1]})
    r = verify_eml((FIXTURES / "legit_arabic_bank.eml").read_bytes(), offline=True, dnsfunc=dns)
    assert [(d.result, d.source) for d in r.dkim] == [("pass", "auth_results")]
    # The same bytes without the provider's Authentication-Results: our own check decides.
    raw = (FIXTURES / "legit_arabic_bank.eml").read_bytes()
    start = raw.index(b"Authentication-Results:")
    end = raw.index(b"Return-Path:")
    r = verify_eml(raw[:start] + raw[end:], offline=True, dnsfunc=dns)
    assert r.trusted_authserv is None
    assert [(d.domain, d.result, d.source) for d in r.dkim] == [("bankfab.com", "fail", "verified")]


# ---------------------------------------------------------------------------
# DKIM crypto
# ---------------------------------------------------------------------------
def test_dkim_pass_and_dmarc_computed(key):
    dns = StubDNS({"s1._domainkey.example.com.": key[1], "_dmarc.example.com.": b"v=DMARC1; p=reject; adkim=r"})
    r = verify_eml(signed(key), offline=True, dnsfunc=dns)
    assert [(d.domain, d.selector, d.result, d.aligned, d.source) for d in r.dkim] == [
        ("example.com", "s1", "pass", True, "verified")]
    assert r.dmarc.to_dict() == {"result": "pass", "policy": "reject", "alignment": {"spf": False, "dkim": True},
                                 "source": "computed"}
    assert r.spf.result == "not_checked"  # offline and no trusted provider recorded the client IP


def test_dkim_tampered_body_fails(key):
    data = signed(key).replace(b"order 1234", b"order 9999")
    dns = StubDNS({"s1._domainkey.example.com.": key[1], "_dmarc.example.com.": b"v=DMARC1; p=reject"})
    r = verify_eml(data, offline=True, dnsfunc=dns)
    assert [(d.result, d.source) for d in r.dkim] == [("fail", "verified")]
    # SPF could not be checked, so DMARC has no verdict (it needs SPF or DKIM to pass).
    assert r.dmarc.result == "not_checked" and r.dmarc.policy == "reject"


def test_dkim_tampered_header_fails(key):
    data = signed(key).replace(b"Subject: Your order has shipped", b"Subject: Pay now")
    r = verify_eml(data, offline=True, dnsfunc=StubDNS({"s1._domainkey.example.com.": key[1]}))
    assert r.dkim[0].result == "fail"


def test_dkim_missing_key_is_fail_but_dns_timeout_is_not_checked(key):
    r = verify_eml(signed(key), offline=True, dnsfunc=StubDNS({}))
    assert r.dkim[0].result == "fail"
    r = verify_eml(signed(key), offline=True, dnsfunc=StubDNS(fail=["s1._domainkey.example.com."]))
    assert r.dkim[0].result == "not_checked"


def test_dkim_unaligned_signer(key):
    dns = StubDNS({"s1._domainkey.mailer.test.": key[1], "_dmarc.example.com.": b"v=DMARC1; p=quarantine"})
    r = verify_eml(signed(key, domain=b"mailer.test"), offline=True, dnsfunc=dns)
    assert (r.dkim[0].domain, r.dkim[0].result, r.dkim[0].aligned) == ("mailer.test", "pass", False)
    assert r.dmarc.alignment == {"spf": False, "dkim": False}


def test_dkim_not_checked_for_pasted_source(key):
    """A paste is not byte-exact: the signature is listed but not judged."""
    data = signed(key).decode()
    dns = StubDNS({"s1._domainkey.example.com.": key[1]})
    r = run(ea.verify(ep.parse(source="raw", text=data), offline=True, dnsfunc=dns))
    assert [(d.domain, d.result) for d in r.dkim] == [("example.com", "not_checked")]
    assert not any("_domainkey" in q for q in dns.queries)


def test_dkim_offline_without_dnsfunc_is_not_checked(key):
    r = verify_eml(signed(key), offline=True)
    assert [d.result for d in r.dkim] == ["not_checked"]
    assert r.dmarc.result == "not_checked"


def test_strict_dkim_alignment(key):
    dns = StubDNS({"s1._domainkey.example.com.": key[1], "_dmarc.news.example.com.": b"v=DMARC1; p=reject; adkim=s"})
    r = verify_eml(signed(key, from_addr=b"shop@news.example.com"), offline=True, dnsfunc=dns)
    assert r.dkim[0].result == "pass" and r.dkim[0].aligned is False  # strict: example.com != news.example.com
    dns.records["_dmarc.news.example.com."] = b"v=DMARC1; p=reject"
    r = verify_eml(signed(key, from_addr=b"shop@news.example.com"), offline=True, dnsfunc=dns)
    assert r.dkim[0].aligned is True and r.dmarc.result == "pass"


# ---------------------------------------------------------------------------
# ARC
# ---------------------------------------------------------------------------
GMAIL_TOP = (b"Authentication-Results: mx.google.com; dkim=pass header.i=@example.com header.s=s1;"
             b" spf=pass smtp.mailfrom=shop@example.com; dmarc=pass (p=REJECT) header.from=example.com\r\n"
             b"Received: from mail.example.com (mail.example.com. [192.0.2.25]) by mx.google.com with ESMTPS id x1;"
             b" Mon, 23 Nov 2026 10:00:01 +0400\r\n")


def arc_signed(key):
    pytest.importorskip("authres")  # dkimpy needs it to SIGN an ARC set (verifying works without it)
    base = signed(key, extra_top=GMAIL_TOP)
    arc_headers = dkim.arc_sign(base, b"arc1", b"google.com", key[0], b"mx.google.com")
    return b"".join(arc_headers) + base


def test_arc_chain_pass(key):
    dns = StubDNS({"arc1._domainkey.google.com.": key[1], "s1._domainkey.example.com.": key[1]})
    data = arc_signed(key)
    r = verify_eml(data, offline=True, dnsfunc=dns)
    assert r.arc.to_dict() == {"result": "pass", "chain_length": 1}
    assert r.trusted_authserv == "mx.google.com"
    assert r.dmarc.result == "pass" and r.dmarc.source == "auth_results"


def test_arc_chain_tampered_fails(key):
    dns = StubDNS({"arc1._domainkey.google.com.": key[1], "s1._domainkey.example.com.": key[1]})
    data = arc_signed(key).replace(b"order 1234", b"order 6666")
    r = verify_eml(data, offline=True, dnsfunc=dns)
    assert r.arc.result == "fail" and r.arc.chain_length == 1


def test_arc_not_verifiable_offline_is_none(key):
    r = verify_eml(arc_signed(key), offline=True)
    assert r.arc.to_dict() == {"result": "none", "chain_length": 1}


def test_arc_result_from_trusted_authentication_results():
    raw = (b"Authentication-Results: mx.google.com; arc=pass (i=1 spf=pass); dkim=pass header.d=lists.example.org\r\n"
           b"ARC-Seal: i=1; a=rsa-sha256; d=lists.example.org; s=a1; cv=none; b=xx\r\n"
           b"Received: from lists.example.org (lists.example.org. [192.0.2.80]) by mx.google.com; Mon, 23 Nov 2026\r\n"
           b"From: Someone <someone@example.com>\r\nSubject: list mail\r\n\r\nhi\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw.decode()), offline=True))
    assert r.arc.to_dict() == {"result": "pass", "chain_length": 1}


# ---------------------------------------------------------------------------
# Authentication-Results parsing and the trust boundary
# ---------------------------------------------------------------------------
def test_parse_authentication_results_gmail():
    ar = ea.parse_authentication_results(
        'mx.google.com; dkim=pass header.i=@bankfab.com header.s=selector1 header.b=Rk2bQxLp; '
        'spf=pass (google.com: domain of "a;b"@x.com designates 192.0.2.45 as permitted sender) '
        'smtp.mailfrom="bounces+1=gmail.com@sendgrid.net"; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=bankfab.com')
    assert ar.authserv_id == "mx.google.com"
    assert [(m.method, m.result) for m in ar.methods] == [("dkim", "pass"), ("spf", "pass"), ("dmarc", "pass")]
    assert ar.methods[0].props == {"header.i": "@bankfab.com", "header.s": "selector1", "header.b": "Rk2bQxLp"}
    assert ar.methods[1].props["smtp.mailfrom"] == "bounces+1=gmail.com@sendgrid.net"
    assert "designates 192.0.2.45" in ar.methods[1].comment
    assert "p=REJECT" in ar.methods[2].comment


def test_parse_authentication_results_variants():
    ms = ea.parse_authentication_results(
        "spf=pass (sender IP is 209.85.1.2) smtp.mailfrom=gmail.com; dkim=pass (signature was verified) "
        "header.d=gmail.com;dmarc=pass action=none header.from=gmail.com;compauth=pass reason=100")
    assert ms.authserv_id is None
    assert [m.method for m in ms.methods] == ["spf", "dkim", "dmarc", "compauth"]
    yahoo = ea.parse_authentication_results("atlas-production.v2.mail.bf1.yahoo.com; dkim=pass header.i=@x.com; "
                                            "dmarc=pass(p=REJECT) header.from=x.com")
    assert yahoo.authserv_id.endswith("yahoo.com") and yahoo.methods[1].result == "pass"
    assert "p=REJECT" in yahoo.methods[1].comment
    none = ea.parse_authentication_results("mx.example.com 1; none")
    assert none.authserv_id == "mx.example.com" and none.methods == []
    aar = ea.parse_authentication_results("i=2; mx.microsoft.com 1; spf=pass smtp.mailfrom=a.com", arc=True)
    assert (aar.instance, aar.authserv_id, aar.methods[0].method) == (2, "mx.microsoft.com", "spf")
    nested = ea.parse_authentication_results("mx.google.com; spf=pass (a (nested; comment) here) smtp.mailfrom=a@b.com")
    assert nested.methods[0].props["smtp.mailfrom"] == "a@b.com"


def test_parse_received():
    rec = ea.parse_received("from mta1.bankfab.com (mta1.bankfab.com. [192.0.2.45]) by mx.google.com with ESMTPS id 4"
                            " for <a@b.com> (version=TLS1_3); Mon, 23 Nov 2026 01:30:04 -0800 (PST)")
    assert rec == {"from": "mta1.bankfab.com", "helo": "mta1.bankfab.com", "ip": "192.0.2.45", "by": "mx.google.com"}
    ms = ea.parse_received("from mail.dewa-billing.test (203.0.113.50) by BN8NAM11FT045.mail.protection.outlook.com"
                           " (10.13.177.47) with Microsoft SMTP Server; Mon, 23 Nov 2026")
    assert ms["ip"] == "203.0.113.50" and ms["by"] == "bn8nam11ft045.mail.protection.outlook.com"
    v6 = ea.parse_received("from h.example ([IPv6:2001:db8::1]) by mx.example.org; date")
    assert v6["ip"] == "2001:db8::1"
    internal = ea.parse_received("by 2002:a05:6a20:9e31:b0:2c1:77ab:91fe with SMTP id k49csp311802pzb; Mon")
    assert internal["by"].startswith("2002:") and internal["from"] == ""


@pytest.mark.parametrize("host,trusted", [
    ("mx.google.com", True), ("BN8NAM11FT045.mail.protection.outlook.com", True), ("dm6pr12mb4321.namprd12.prod.outlook.com", True),
    ("atlas-production.v2.mail.bf1.yahoo.com", True), ("dkim-verifier.icloud.com", True), ("mx.zohomail.com", True),
    ("mail.protonmail.ch", True), ("mx1.mail.example.com", False), ("google.com.evil.test", False),
    ("notgoogle.com", False), ("", False), (None, False),
])
def test_is_trusted_host(host, trusted):
    assert ea.is_trusted_host(host) is trusted


def test_trusted_authserv_can_be_extended(monkeypatch):
    monkeypatch.setenv("EMAIL_TRUSTED_AUTHSERV", "mx1.mail.example.com, .isp.example")
    assert ea.is_trusted_host("mx1.mail.example.com") and ea.is_trusted_host("in.isp.example")
    r = verify_eml((FIXTURES / "phish_bidi_attachment.eml").read_bytes(), offline=True)
    assert r.trusted_authserv == "mx1.mail.example.com"
    assert (r.spf.result, r.spf.domain, r.spf.client_ip) == ("softfail", "ep-invoices.test", "203.0.113.77")
    assert [(d.domain, d.result) for d in r.dkim] == [("", "none")]
    assert r.dmarc.result == "none"


def test_spoofed_results_below_untrusted_receiver_are_ignored():
    """auth_spoofed_results.eml: a forged "mx.google.com; dkim=pass; dmarc=pass" written by the sender,
    under the citizen's (unknown) provider's own Received header."""
    r = verify_eml((FIXTURES / "auth_spoofed_results.eml").read_bytes(), offline=True)
    assert r.trusted_authserv is None
    assert r.dkim == [] and r.spf.result == "not_checked"
    assert r.dmarc.result == "not_checked" and r.dmarc.source == "none"


def test_topmost_trusted_results_win_over_forged_lower_ones():
    raw = ("Received: by 2002:a05:6a10:1::1 with SMTP id z; Mon, 23 Nov 2026\r\n"
           "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=x@adpolice.gov.ae;"
           " dkim=none; dmarc=fail (p=REJECT) header.from=adpolice.gov.ae\r\n"
           "Received: from evil.test (evil.test. [198.51.100.9]) by mx.google.com; Mon, 23 Nov 2026\r\n"
           "Authentication-Results: mx.google.com; dkim=pass header.d=adpolice.gov.ae; spf=pass"
           " smtp.mailfrom=x@adpolice.gov.ae; dmarc=pass header.from=adpolice.gov.ae\r\n"
           "From: Police <x@adpolice.gov.ae>\r\nSubject: fine\r\n\r\npay\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.trusted_authserv == "mx.google.com"
    assert (r.spf.result, r.dmarc.result, r.dmarc.policy) == ("fail", "fail", "reject")
    assert [(d.result, d.domain) for d in r.dkim] == [("none", "")]
    assert r.spf.client_ip == "198.51.100.9"  # from the provider's own entry Received


@pytest.mark.parametrize("below_entry", [
    # another provider's name, directly under Gmail's entry hop
    "Authentication-Results: mx.microsoft.com; dkim=pass header.d=adpolice.gov.ae; dmarc=pass header.from=adpolice.gov.ae\r\n",
    # Gmail's name, but further down among the sender's own headers
    "X-Mailer: bulk 1.0\r\nAuthentication-Results: mx.google.com; dkim=pass header.d=adpolice.gov.ae;"
    " dmarc=pass header.from=adpolice.gov.ae\r\n",
    # a sender-written hop pretending to be Gmail, below the real entry hop
    "Received: from x (x [192.0.2.1]) by mx.google.com; Mon\r\nAuthentication-Results: mx.google.com; dmarc=pass"
    " header.from=adpolice.gov.ae\r\n",
])
def test_forged_results_below_the_entry_hop_are_ignored(below_entry):
    raw = ("Received: from evil.test (evil.test. [198.51.100.9]) by mx.google.com; Mon, 23 Nov 2026\r\n"
           + below_entry + "From: Police <x@adpolice.gov.ae>\r\nSubject: fine\r\n\r\npay\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.trusted_authserv is None and r.dkim == [] and r.dmarc.result == "not_checked"


def test_postfix_style_results_just_below_the_entry_hop():
    """Postfix milters add Authentication-Results right under the provider's own Received header."""
    raw = ("Received: from mail.shop.example (mail.shop.example [192.0.2.30]) by mailin.protonmail.ch (Postfix); Mon\r\n"
           "Authentication-Results: mailin.protonmail.ch; dmarc=pass (p=quarantine) header.from=shop.example;"
           " spf=pass smtp.mailfrom=shop.example; dkim=pass header.d=shop.example header.s=k1\r\n"
           "From: Shop <news@shop.example>\r\n\r\nhi\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.trusted_authserv == "mailin.protonmail.ch"
    assert (r.dmarc.result, r.dmarc.policy, r.dmarc.alignment) == ("pass", "quarantine", {"spf": True, "dkim": True})


def test_results_without_any_received_header_are_ignored():
    raw = ("Authentication-Results: mx.google.com; dkim=pass header.d=bank.example; dmarc=pass header.from=bank.example\r\n"
           "From: Bank <a@bank.example>\r\nSubject: hi\r\n\r\nbody\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.trusted_authserv is None and r.dmarc.result == "not_checked"


def test_untrusted_authserv_on_top_is_skipped():
    raw = ("Authentication-Results: spamfilter.corp.example; dmarc=pass header.from=x.com\r\n"
           "Received: by 2002:a05::1 with SMTP id q; Mon, 23 Nov 2026\r\n"
           "Authentication-Results: mx.google.com; spf=softfail smtp.mailfrom=a@x.com; dmarc=fail (p=NONE) header.from=x.com\r\n"
           "Received: from h.x.com (h.x.com. [192.0.2.7]) by mx.google.com; Mon, 23 Nov 2026\r\n"
           "From: <a@x.com>\r\n\r\nbody\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.trusted_authserv == "mx.google.com"
    assert (r.spf.result, r.dmarc.result, r.dmarc.policy) == ("softfail", "fail", "none")


def test_microsoft365_without_authserv_id():
    r = verify_eml((FIXTURES / "auth_microsoft365_dmarc_fail.eml").read_bytes(), offline=True)
    assert r.trusted_authserv == "bn8nam11ft045.mail.protection.outlook.com"
    assert (r.spf.result, r.spf.domain, r.spf.client_ip) == ("fail", "dewa-billing.test", "203.0.113.50")
    assert [(d.domain, d.result) for d in r.dkim] == [("", "none")]
    assert r.dmarc.to_dict() == {"result": "fail", "policy": "quarantine", "alignment": {"spf": False, "dkim": False},
                                 "source": "auth_results"}


def test_received_spf_used_when_no_spf_in_results():
    raw = ("Received-SPF: Pass (protection.outlook.com: domain of shop.example designates 192.0.2.30 as permitted"
           " sender) receiver=protection.outlook.com; client-ip=192.0.2.30; helo=mail.shop.example;"
           " envelope-from=\"bounce@shop.example\"\r\n"
           "Received: from mail.shop.example (192.0.2.30) by X1.mail.protection.outlook.com (10.0.0.1); Mon\r\n"
           "From: Shop <news@shop.example>\r\n\r\nhi\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.spf.to_dict() == {"result": "pass", "domain": "shop.example", "client_ip": "192.0.2.30",
                               "source": "auth_results"}


def test_icloud_split_results_are_merged():
    raw = ("Received: from p00-icloudmta-asmtp-us-west-1a-60-percent-0 by p00-icloudmta-asmtp; Mon\r\n"
           "Authentication-Results: dmarc.icloud.com; dmarc=pass header.from=example.com\r\n"
           "Authentication-Results: dkim-verifier.icloud.com; dkim=pass (2048-bit key) header.d=example.com header.s=k1\r\n"
           "Authentication-Results: spf.icloud.com; spf=pass (spf.icloud.com: domain of a@example.com designates"
           " 192.0.2.44 as permitted sender) smtp.mailfrom=a@example.com\r\n"
           "Authentication-Results: bimi.icloud.com; bimi=skipped\r\n"
           "Received: from mail.example.com (mail.example.com [192.0.2.44]) by mx.icloud.com; Mon\r\n"
           "From: A <a@example.com>\r\n\r\nhi\r\n")
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True))
    assert r.trusted_authserv == "dmarc.icloud.com"
    assert (r.spf.result, r.dkim[0].result, r.dmarc.result) == ("pass", "pass", "pass")
    assert r.dmarc.alignment == {"spf": True, "dkim": True}


# ---------------------------------------------------------------------------
# DMARC logic
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("domain,from_domain,mode,expect", [
    ("example.com", "example.com", "r", True),
    ("mail.example.com", "example.com", "r", True),
    ("example.com", "news.example.com", "r", True),
    ("example.com", "news.example.com", "s", False),
    ("bank.co.uk", "other.co.uk", "r", False),  # public suffix aware
    ("sendgrid.net", "example.com", "r", False),
    ("", "example.com", "r", False),
])
def test_alignment(domain, from_domain, mode, expect):
    assert ea.aligned(domain, from_domain, mode) is expect


def test_lookup_dmarc_falls_back_to_org_domain_and_uses_sp():
    dns = StubDNS({"_dmarc.example.com.": b"v=DMARC1; p=reject; sp=quarantine; aspf=s"})
    rec, ok = run(ea.lookup_dmarc("mail.example.com", ea._TxtLookup(True, dns)))
    assert ok and rec["effective_p"] == "quarantine" and rec["aspf"] == "s"
    assert dns.queries == ["_dmarc.mail.example.com.", "_dmarc.example.com."]
    rec, ok = run(ea.lookup_dmarc("example.com", ea._TxtLookup(True, dns)))
    assert rec["effective_p"] == "reject"
    rec, ok = run(ea.lookup_dmarc("nodmarc.example", ea._TxtLookup(True, StubDNS({}))))
    assert ok and rec is None
    rec, ok = run(ea.lookup_dmarc("x.example", ea._TxtLookup(True, StubDNS(fail=["_dmarc.x.example."]))))
    assert not ok and rec is None
    assert ea.parse_dmarc_record("v=spf1 -all") is None


def test_dmarc_policy_filled_from_dns_when_results_omit_it():
    raw = ("Received: from h.shop.example (h.shop.example. [192.0.2.7]) by mx.google.com; Mon\r\n"
           "From: <a@shop.example>\r\n\r\nx\r\n")
    raw = "Authentication-Results: mx.google.com; spf=fail smtp.mailfrom=a@shop.example; dmarc=fail header.from=shop.example\r\n" + raw
    dns = StubDNS({"_dmarc.shop.example.": b"v=DMARC1; p=quarantine"})
    r = run(ea.verify(ep.parse(source="raw", text=raw), offline=True, dnsfunc=dns))
    assert (r.dmarc.result, r.dmarc.policy, r.dmarc.source) == ("fail", "quarantine", "auth_results")


# ---------------------------------------------------------------------------
# SPF (pyspf mocked)
# ---------------------------------------------------------------------------
NO_AR = ("Received: by 2002:a05:6a10:1::1 with SMTP id z; Mon, 23 Nov 2026\r\n"
         "Return-Path: <bounce@shop.example>\r\n"
         "Received: from mail.shop.example (mail.shop.example. [192.0.2.30]) by mx.google.com; Mon, 23 Nov 2026\r\n"
         "From: Shop <news@shop.example>\r\nSubject: Sale\r\n\r\nhi\r\n")


@pytest.fixture
def mock_spf(monkeypatch):
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        import spf
    calls = []

    def fake_check2(i, s, h, **kw):
        calls.append((i, s, h))
        return ("fail", "mock: not permitted")

    monkeypatch.setattr(spf, "check2", fake_check2)
    return calls


def test_spf_computed_from_trusted_entry_hop(mock_spf):
    dns = StubDNS({"_dmarc.shop.example.": b"v=DMARC1; p=reject"})
    r = run(ea.verify(ep.parse(source="raw", text=NO_AR), offline=False, dnsfunc=dns))
    assert mock_spf == [("192.0.2.30", "bounce@shop.example", "mail.shop.example")]
    assert r.spf.to_dict() == {"result": "fail", "domain": "shop.example", "client_ip": "192.0.2.30", "source": "computed"}
    # SPF fail + no DKIM signature at all -> DMARC fails, with the record's policy.
    assert r.dmarc.to_dict() == {"result": "fail", "policy": "reject", "alignment": {"spf": False, "dkim": False},
                                 "source": "computed"}


def test_spf_pass_aligned_gives_dmarc_pass(monkeypatch, mock_spf):
    import spf

    monkeypatch.setattr(spf, "check2", lambda i, s, h, **kw: ("pass", "ok"))
    dns = StubDNS({"_dmarc.shop.example.": b"v=DMARC1; p=none"})
    r = run(ea.verify(ep.parse(source="raw", text=NO_AR), offline=False, dnsfunc=dns))
    assert (r.spf.result, r.dmarc.result, r.dmarc.policy, r.dmarc.alignment["spf"]) == ("pass", "pass", "none", True)


def test_spf_not_computed_offline_or_without_trusted_hop(mock_spf):
    r = run(ea.verify(ep.parse(source="raw", text=NO_AR), offline=True))
    assert r.spf.result == "not_checked"
    untrusted = NO_AR.replace("by mx.google.com", "by mx1.mail.example.com")
    r = run(ea.verify(ep.parse(source="raw", text=untrusted), offline=False, dnsfunc=StubDNS({})))
    assert r.spf.result == "not_checked"
    assert mock_spf == []


def test_spf_from_results_is_not_recomputed(mock_spf):
    r = verify_eml((FIXTURES / "legit_arabic_bank.eml").read_bytes(), offline=False, dnsfunc=StubDNS({}))
    assert r.spf.source == "auth_results" and mock_spf == []


def test_spf_crash_degrades(monkeypatch):
    import spf

    def boom(*a, **kw):
        raise RuntimeError("dns exploded")

    monkeypatch.setattr(spf, "check2", boom)
    r = run(ea.verify(ep.parse(source="raw", text=NO_AR), offline=False, dnsfunc=StubDNS({})))
    assert r.spf.result == "not_checked" and r.spf.source == "none"


# ---------------------------------------------------------------------------
# Never raises
# ---------------------------------------------------------------------------
def test_no_headers_is_not_checked():
    p = ep.parse(source="text", text="From: a@b.com\nSubject: hi\n\nhello")
    assert run(ea.verify(p, offline=False)).to_dict() == AuthReport.not_checked().to_dict()


def test_verify_never_raises(monkeypatch):
    p = ep.parse(source="eml", file_bytes=(FIXTURES / "legit_arabic_bank.eml").read_bytes())

    def boom(*a, **kw):
        raise RuntimeError("unexpected")

    monkeypatch.setattr(ea, "analyse_chain", boom)
    assert run(ea.verify(p, offline=True)).to_dict() == AuthReport.not_checked().to_dict()


def test_garbage_headers_do_not_crash():
    raw = ("Authentication-Results: ;;;===;(((\r\nReceived: from\r\nReceived: by\r\nDKIM-Signature: garbage\r\n"
           "ARC-Seal: i=x\r\nFrom: <>\r\n\r\nx\r\n")
    r = run(ea.verify(ep.parse(source="eml", file_bytes=raw.encode()), offline=True, dnsfunc=StubDNS({})))
    assert r.dkim[0].result in ("fail", "not_checked")
    assert r.dmarc.result == "not_checked"


def test_msg_fixture_authentication():
    data = (FIXTURES / "msg_outlook_spoof_tamm.msg").read_bytes()
    r = run(ea.verify(ep.parse(source="msg", file_bytes=data), offline=True))
    assert r.trusted_authserv == "mx.google.com"
    assert (r.spf.result, r.spf.domain) == ("pass", "fines-portal.test")
    assert r.dmarc.to_dict() == {"result": "fail", "policy": "reject", "alignment": {"spf": False, "dkim": False},
                                 "source": "auth_results"}


def test_ed25519_signature_without_pynacl_is_not_checked(monkeypatch):
    """E2E regression (real suse.de list mail): dkimpy raises NaClNotFoundError for ed25519 signatures when
    PyNaCl is missing; that was reported as DKIM "fail" on a genuine message."""
    def no_nacl(self, *a, **k):
        raise dkim.NaClNotFoundError("PyNaCl not installed")

    monkeypatch.setattr(dkim.DKIM, "verify", no_nacl)
    assert ea._verify_dkim_sync(b"From: a@example.com\r\n\r\nhi\r\n", 1, lambda name, timeout=5: None) == ["not_checked"]
