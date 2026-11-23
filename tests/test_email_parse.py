"""Tests for saqr.intel.email_parse (workstream A). Fully offline. Run: pytest -q tests/test_email_parse.py"""
import os
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402

from saqr.intel import email_parse as ep  # noqa: E402

FIXTURES = Path(__file__).parent / "fixtures" / "emails"
MSG_FIXTURE = FIXTURES / "msg_outlook_spoof_tamm.msg"


def load(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


# ---------------------------------------------------------------------------
# Minimal compound-file (CFB v3) writer, so the .msg tests need no Outlook and no GPL library.
# Layout: [mini stream][big streams][mini FAT][directory][FAT]; one FAT sector chain, no DIFAT.
# ---------------------------------------------------------------------------
_ENDOFCHAIN, _FREESECT, _FATSECT, _NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


class _Node:
    def __init__(self, name, kind, data=b""):
        self.name, self.kind, self.data = name, kind, data  # kind: 1 storage, 2 stream, 5 root
        self.children, self.start, self.size = [], _ENDOFCHAIN, 0
        self.left = self.right = self.child = _NOSTREAM
        self.id = 0


def build_cfb(streams: dict) -> bytes:
    """streams = {"storage/sub/stream_name": bytes}; storages are created from the paths."""
    root = _Node("Root Entry", 5)
    for path, data in streams.items():
        node = root
        parts = path.split("/")
        for part in parts[:-1]:
            nxt = next((c for c in node.children if c.name == part), None)
            if nxt is None:
                nxt = _Node(part, 1)
                node.children.append(nxt)
            node = nxt
        node.children.append(_Node(parts[-1], 2, data))
    entries = [root]
    for node in entries:  # breadth-first; the list grows while we walk it
        node.children.sort(key=lambda c: (len(c.name), c.name.upper()))
        entries.extend(node.children)
    for i, node in enumerate(entries):
        node.id = i

    def tree(children):  # balanced binary search tree of siblings (all black)
        if not children:
            return _NOSTREAM
        mid = len(children) // 2
        children[mid].left = tree(children[:mid])
        children[mid].right = tree(children[mid + 1:])
        return children[mid].id

    for node in entries:
        if node.kind in (1, 5):
            node.child = tree(node.children)

    sectors, fat = [], []

    def alloc(data: bytes) -> int:
        n = (len(data) + 511) // 512
        if n == 0:
            return _ENDOFCHAIN
        start = len(sectors)
        for i in range(n):
            sectors.append(data[i * 512:(i + 1) * 512].ljust(512, b"\0"))
            fat.append(start + i + 1 if i < n - 1 else _ENDOFCHAIN)
        return start

    mini, minifat = bytearray(), []
    for node in entries:
        if node.kind != 2:
            continue
        node.size = len(node.data)
        if node.size < 4096:
            n = (node.size + 63) // 64
            if n:
                node.start = len(mini) // 64
                for i in range(n):
                    minifat.append(node.start + i + 1 if i < n - 1 else _ENDOFCHAIN)
                mini += node.data.ljust(n * 64, b"\0")
    root.start, root.size = alloc(bytes(mini)), len(mini)
    for node in entries:
        if node.kind == 2 and node.size >= 4096:
            node.start = alloc(node.data)
    minifat += [_FREESECT] * (-len(minifat) % 128)
    minifat_start = alloc(struct.pack(f"<{len(minifat)}I", *minifat)) if minifat else _ENDOFCHAIN
    n_minifat = len(minifat) // 128

    dir_bytes = bytearray()
    for node in entries:
        name = (node.name + "\0").encode("utf-16-le")
        dir_bytes += struct.pack("<64sHBBIII16sIQQIQ", name.ljust(64, b"\0"), len(name), node.kind, 1,
                                 node.left, node.right, node.child, b"\0" * 16, 0, 0, 0,
                                 node.start if node.kind != 1 else 0, node.size if node.kind != 1 else 0)
    while len(dir_bytes) % 512:
        dir_bytes += struct.pack("<64sHBBIII16sIQQIQ", b"\0" * 64, 0, 0, 0, _NOSTREAM, _NOSTREAM, _NOSTREAM,
                                 b"\0" * 16, 0, 0, 0, 0, 0)
    dir_start = alloc(bytes(dir_bytes))

    n_fat = 1
    while len(sectors) + n_fat > n_fat * 128:
        n_fat += 1
    assert n_fat <= 109
    fat_start = len(sectors)
    fat += [_FATSECT] * n_fat
    fat += [_FREESECT] * (n_fat * 128 - len(fat))
    fat_bytes = struct.pack(f"<{len(fat)}I", *fat)
    difat = [fat_start + i for i in range(n_fat)] + [_FREESECT] * (109 - n_fat)
    header = struct.pack("<8s16sHHHHH6sIIIIIIIII", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", b"\0" * 16, 0x3E, 3,
                         0xFFFE, 9, 6, b"\0" * 6, 0, n_fat, dir_start, 0, 4096, minifat_start, n_minifat,
                         _ENDOFCHAIN, 0) + struct.pack("<109I", *difat)
    return header + b"".join(sectors) + fat_bytes


# 2025-11-23 10:30 UTC as a Windows FILETIME (100 ns steps since 1601-01-01).
FT_2025_11_23_1030 = int((datetime(2025, 11, 23, 10, 30, tzinfo=timezone.utc)
                          - datetime(1601, 1, 1, tzinfo=timezone.utc)).total_seconds()) * 10_000_000


def u16(s: str) -> bytes:
    return s.encode("utf-16-le")


def props_stream(filetime: int) -> bytes:
    """__properties_version1.0 of a top-level message: 32-byte header + one PidTagClientSubmitTime entry."""
    return b"\0" * 32 + struct.pack("<IIQ", 0x00390040, 0x6, filetime)


SPOOF_TAMM_HEADERS = (
    "Delivered-To: resident.example@gmail.com\r\n"
    "Received: by 2002:a05:6a10:1234:b0:5f1:aa01:2c4e with SMTP id x1csp1;\r\n"
    "        Mon, 23 Nov 2026 02:10:05 -0800 (PST)\r\n"
    "Authentication-Results: mx.google.com;\r\n"
    "       spf=pass (google.com: domain of bounce@fines-portal.test designates 203.0.113.9 as permitted sender)"
    " smtp.mailfrom=bounce@fines-portal.test;\r\n"
    "       dkim=none;\r\n"
    "       dmarc=fail (p=REJECT sp=REJECT dis=QUARANTINE) header.from=tamm.abudhabi\r\n"
    "Return-Path: <bounce@fines-portal.test>\r\n"
    "Received: from mail.fines-portal.test (mail.fines-portal.test. [203.0.113.9])\r\n"
    "        by mx.google.com with ESMTPS id abc123; Mon, 23 Nov 2026 02:10:04 -0800 (PST)\r\n"
    "From: \"TAMM Abu Dhabi\" <noreply@tamm.abudhabi>\r\n"
    "To: resident.example@gmail.com\r\n"
    "Subject: Unpaid traffic fine - pay within 24 hours\r\n"
    "Date: Mon, 23 Nov 2026 14:10:02 +0400\r\n"
    "Message-ID: <fine.20261123141002@fines-portal.test>\r\n"
    "MIME-Version: 1.0\r\n"
    "Content-Type: multipart/mixed; boundary=\"tammfine\"\r\n\r\n"
)
SPOOF_TAMM_HTML = (
    "<html><head><meta charset=\"utf-8\"></head><body><p>You have an unpaid traffic fine of AED 300.</p>"
    "<p><a href=\"https://tamm-fine-pay.test/pay?ref=77\">https://www.tamm.abudhabi/fines</a></p>"
    "<p>دفع المخالفة</p></body></html>"
)


def build_spoof_tamm_msg() -> bytes:
    """An Outlook .msg of a TAMM fine scam, received by Gmail (real internet headers, dmarc=fail)."""
    att = "__attach_version1.0_#00000000/"
    return build_cfb({
        "__substg1.0_0037001F": u16("Unpaid traffic fine - pay within 24 hours"),
        "__substg1.0_0C1A001F": u16("TAMM Abu Dhabi"),
        "__substg1.0_0C1F001F": u16("noreply@tamm.abudhabi"),
        "__substg1.0_007D001F": u16(SPOOF_TAMM_HEADERS),
        "__substg1.0_1000001F": u16("You have an unpaid traffic fine of AED 300.\r\n"
                                    "Pay now: https://tamm-fine-pay.test/pay?ref=77\r\n"),
        "__substg1.0_10130102": SPOOF_TAMM_HTML.encode("utf-8"),
        "__properties_version1.0": props_stream(0),
        att + "__substg1.0_3707001F": u16("Fine_Notice.pdf.exe"),
        att + "__substg1.0_3704001F": u16("FINE_N~1.EXE"),
        att + "__substg1.0_370E001F": u16("application/octet-stream"),
        att + "__substg1.0_37010102": b"MZ" + b"\0" * 5000,  # > 4096 bytes: stored in the big FAT
        "__recip_version1.0_#00000000/__substg1.0_3001001F": u16("Resident"),
    })


def build_headerless_msg(rtf_only: bool = False) -> bytes:
    """A .msg with no internet headers (e.g. a sent item): sender from MAPI properties, 8-bit strings."""
    streams = {
        "__substg1.0_0037001E": "Café invoice".encode("cp1252"),
        "__substg1.0_0C1A001E": b"Billing Team",
        "__substg1.0_0C1F001E": b"/O=EXCHANGELABS/OU=EXCHANGE ADMINISTRATIVE GROUP/CN=RECIPIENTS/CN=BILLING",
        "__substg1.0_5D01001E": b"billing@example.org",
        "__properties_version1.0": props_stream(FT_2025_11_23_1030),
        "__recip_version1.0_#00000000/__substg1.0_3001001F": u16("A"),
        "__recip_version1.0_#00000001/__substg1.0_3001001F": u16("B"),
    }
    if rtf_only:
        streams["__substg1.0_10090102"] = b"LZFu-compressed-rtf-placeholder"
    else:
        streams["__substg1.0_1000001E"] = b"Please see http://billing.example.org/invoice/7"
    return build_cfb(streams)


# ---------------------------------------------------------------------------
# Shared .eml fixtures
# ---------------------------------------------------------------------------
EXPECTED = {
    "legit_arabic_bank.eml": dict(
        from_address="notifications@bankfab.com", from_domain="bankfab.com",
        display_name="بنك أبوظبي الأول",
        subject_contains="راتبك", reply_to=None, return_path="notifications@bankfab.com",
        list_id=None, links=[("https://www.bankfab.com/ar-ae/personal", "www.bankfab.com")], attachments=[]),
    "legit_newsletter_list.eml": dict(
        from_address="news@example.com", from_domain="example.com", display_name="Example Weekly",
        subject_contains="five recipes", reply_to=None,
        return_path="bounces+4821913-ab12-reader.example=gmail.com@sendgrid.net",
        list_id="Example Weekly <weekly.news.example.com>",
        links=[("https://u8812.ct.sendgrid.net/ls/click?upn=fixture-read-online", "Read online"),
               ("https://u8812.ct.sendgrid.net/ls/click?upn=fixture-site", "www.example.com")],
        attachments=[]),
    "legit_plain.eml": dict(
        from_address="sara@example.com", from_domain="example.com", display_name="Sara Example",
        subject_contains="Lunch on Thursday", reply_to=None, return_path=None, list_id=None, links=[],
        attachments=[]),
    "phish_bidi_attachment.eml": dict(
        from_address="billing@ep-invoices.test", from_domain="ep-invoices.test",
        display_name="Emirates Post Billing", subject_contains="customs fee", reply_to=None,
        return_path="billing@ep-invoices.test", list_id=None, links=[],
        attachments=[("Invoice_88412_‮fdp.exe", 30)]),
    "phish_paypal_cyrillic.eml": dict(
        from_address="paypal.support.team2026@gmail.com", from_domain="gmail.com", display_name="PayPal Support",
        subject_contains="PаyPal", reply_to=None, return_path="paypal.support.team2026@gmail.com",
        list_id=None,
        links=[("https://www.google.com/url?q=https%3A%2F%2Fpaypal-account-review.test%2Fsignin%3Fcase%3DPP-48213"
                "&sa=D&usg=AOvVaw0fake", "https://www.paypal.com/signin"),
               ("https://www.paypal.com/signin", "")],
        attachments=[("PayPal_Case_PP-48213.pdf", 15)]),
    "phish_punycode_sender.eml": dict(
        from_address="alerts@xn--dcb-secure-yqi.test", from_domain="xn--dcb-secure-yqi.test",
        display_name="ADCB Card Services", subject_contains="temporarily blocked",
        reply_to="adcb.cards.uae@outlook.com", return_path="bounce@xn--dcb-secure-yqi.test", list_id=None,
        links=[("https://xn--dcb-secure-yqi.test/verify?ref=ADCB-77310", "Verify my card")], attachments=[]),
}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_shared_fixtures_parse(name):
    exp = EXPECTED[name]
    p = ep.parse(source="eml", file_bytes=load(name), file_name=name)
    assert p.source == "eml" and p.has_headers and p.byte_exact
    assert p.raw_bytes == load(name)
    assert p.from_.address == exp["from_address"]
    assert p.from_.domain == exp["from_domain"]
    assert p.from_.display_name == exp["display_name"]
    assert exp["subject_contains"] in p.subject
    assert (p.reply_to.address if p.reply_to else None) == exp["reply_to"]
    assert (p.return_path.address if p.return_path else None) == exp["return_path"]
    assert p.list_id == exp["list_id"]
    got_links = [(link.href, link.text) for link in p.links]
    for link in exp["links"]:
        assert link in got_links
    if not exp["links"]:
        assert got_links == []
    assert [(a.name, a.size) for a in p.attachments] == exp["attachments"]
    assert p.to_count == 1
    assert p.date.startswith("Mon, 23 Nov 2026")
    assert p.message_id.startswith("<") and p.text_body.strip()
    assert p.header("authentication-results") == (p.headers_all("Authentication-Results") or [None])[0]


def test_fixture_details():
    bank = ep.parse(source="eml", file_bytes=load("legit_arabic_bank.eml"))
    assert "عزيزي" in bank.text_body  # Arabic body decoded from base64 UTF-8
    assert bank.html_body.startswith("<html")
    assert len(bank.links) == 1  # the bare "www.bankfab.com" in the text part is the same site
    news = ep.parse(source="eml", file_bytes=load("legit_newsletter_list.eml"))
    assert [h for h in news.headers if h[0] == "DKIM-Signature"][0][1].startswith("v=1; a=rsa-sha256")
    assert "\n" not in news.header("Authentication-Results")  # unfolded
    puny = ep.parse(source="eml", file_bytes=load("phish_punycode_sender.eml"))
    assert ep.unicode_domain(puny.from_) == "аdcb-secure.test"  # Cyrillic а kept for the Unicode rules


# ---------------------------------------------------------------------------
# Pasted raw source
# ---------------------------------------------------------------------------
def test_pasted_raw_is_crlf_and_not_byte_exact():
    text = load("phish_paypal_cyrillic.eml").decode("utf-8")
    p = ep.parse(source="raw", text="\n\n" + text)
    assert p.has_headers and not p.byte_exact
    assert b"\r\n" in p.raw_bytes and b"\n" not in p.raw_bytes.replace(b"\r\n", b"")
    assert p.from_.address == "paypal.support.team2026@gmail.com"
    assert p.attachments[0].name == "PayPal_Case_PP-48213.pdf"


def test_raw_unicode_domains_are_never_lost():
    raw = ("From: PayPal <service@pаypal.com>\n"
           "Reply-To: help@pay​pal.com\n"
           "Subject: Café\n\n"
           "Visit https://pаypal.com/login now\n")
    p = ep.parse(source="raw", text=raw)
    assert p.from_.address == "service@pаypal.com"  # original spelling kept
    assert p.from_.domain == "xn--pypal-4ve.com"
    assert p.reply_to.address == "help@pay​pal.com"
    assert p.reply_to.domain.startswith("xn--") and p.reply_to.domain != "paypal.com"
    assert ep.unicode_domain(p.reply_to) == "pay​pal.com"
    assert p.links[0].href == "https://pаypal.com/login"
    assert ep.link_host(p.links[0].href) == ("xn--pypal-4ve.com", "pаypal.com")
    assert p.subject == "Café"


@pytest.mark.parametrize("host,expect", [
    ("PayPal.COM.", "paypal.com"),
    ("pаypal.com", "xn--pypal-4ve.com"),
    ("münchen.de", "xn--mnchen-3ya.de"),
    ("pay​pal.com", "xn--paypal-df0c.com"),  # IDNA would silently drop the invisible character
    ("ｐａｙpal.com", "xn--pal-n76secrc.com"),  # fullwidth letters are not folded into "pay"
])
def test_ascii_host(host, expect):
    assert ep.ascii_host(host) == expect


def test_ascii_host_bidi_label_stays_ascii():
    out = ep.ascii_host("evil‮com.test")
    assert out.isascii() and out.startswith("xn--") and out.endswith(".test")


def test_text_marked_as_text_but_really_raw_source():
    text = load("legit_plain.eml").decode("utf-8").replace("From: Sara", "Received: from a by b; x\nFrom: Sara", 1)
    p = ep.parse(source="text", text=text)
    assert p.has_headers and not p.byte_exact
    assert p.from_.address == "sara@example.com"
    assert any("full email source" in n for n in p.notes)


def test_raw_without_headers_falls_back_to_visible_text():
    p = ep.parse(source="raw", text="Your parcel is waiting, pay at hxxps://parcel-fee[.]test/pay")
    assert not p.has_headers
    assert p.links[0].href == "https://parcel-fee.test/pay"
    assert p.notes


# ---------------------------------------------------------------------------
# Pasted visible text
# ---------------------------------------------------------------------------
def test_visible_text_outlook_block():
    text = ("From: PayPal Service <service@paypa1-support.test>\n"
            "Sent: Monday, November 23, 2026 9:14 AM\n"
            "To: Omar; Sara\n"
            "Subject: Account limited\n"
            "\n"
            "Dear customer, log in at https://paypa1-support.test/login.\n")
    p = ep.parse(source="text", text=text)
    assert not p.has_headers and not p.byte_exact and p.headers == []
    assert p.from_.display_name == "PayPal Service"
    assert p.from_.address == "service@paypa1-support.test"
    assert p.subject == "Account limited"
    assert p.date.startswith("Monday")
    assert p.to_count == 2
    assert p.text_body.startswith("Dear customer")
    assert [link.href for link in p.links] == ["https://paypa1-support.test/login"]


def test_visible_text_outlook_mailto_and_reply_to():
    text = ("From: ADCB [mailto:alerts@adcb-alerts.test]\n"
            "Reply-To: adcb.help@gmail.com\n"
            "Subject: Card blocked\n\nVerify now.")
    p = ep.parse(source="text", text=text)
    assert p.from_.address == "alerts@adcb-alerts.test" and p.from_.display_name == "ADCB"
    assert p.reply_to.address == "adcb.help@gmail.com" and p.reply_to.domain == "gmail.com"


def test_visible_text_arabic_labels():
    text = ("من: هيئة الطرق <info@rta-pay.test>\n"
            "الموضوع: مخالفة غير مدفوعة\n"
            "التاريخ: 23/11/2026\n"
            "\n"
            "ادفع الآن: rta-pay.info/fine")
    p = ep.parse(source="text", text=text)
    assert p.from_.address == "info@rta-pay.test"
    assert p.subject.startswith("مخالفة")
    assert p.date == "23/11/2026"
    assert [link.href for link in p.links] == ["rta-pay.info/fine"]


def test_visible_text_gmail_opened_view():
    text = ("Your account has been limited\n"
            "Inbox\n"
            "\n"
            "PayPal Support <paypal.support.team2026@gmail.com>\n"
            "9:14 AM (2 hours ago)\n"
            "to me\n"
            "\n"
            "Dear Customer, please confirm your identity.\n")
    p = ep.parse(source="text", text=text)
    assert p.from_.address == "paypal.support.team2026@gmail.com"
    assert p.from_.display_name == "PayPal Support"
    assert p.subject == "Your account has been limited"
    assert p.text_body.startswith("Dear Customer")


def test_visible_text_forwarded_message():
    text = ("FYI is this real?\n\n"
            "---------- Forwarded message ---------\n"
            "From: Etisalat <billing@etisalat-refund.test>\n"
            "Date: Mon, Nov 23, 2026 at 9:00 AM\n"
            "Subject: Refund AED 250\n"
            "To: <me@example.com>\n"
            "\n"
            "Claim your refund: https://etisalat-refund.test/claim\n")
    p = ep.parse(source="text", text=text)
    assert p.from_.address == "billing@etisalat-refund.test"
    assert p.subject == "Refund AED 250"
    assert p.to_count == 1
    assert p.text_body.startswith("Claim your refund")


def test_visible_text_body_only():
    p = ep.parse(source="text", text="Hello, your package is waiting.\nCall us.")
    assert not p.has_headers and p.from_.address == "" and p.subject == ""
    assert p.text_body.startswith("Hello")


def test_text_links_skip_emails_files_and_dedupe():
    body = ("Write to help@bank.example.com or open invoice.pdf. Visit www.good-site.com and "
            "https://x.test/a, https://x.test/a again, <https://y.test/b>, hxxp://evil[.]test/c and Mr.Smith")
    p = ep.parse(source="text", text=body)
    assert [link.href for link in p.links] == ["www.good-site.com", "https://x.test/a", "https://y.test/b",
                                              "http://evil.test/c"]


def test_links_are_capped():
    body = " ".join(f"https://site{i}.test/x" for i in range(150))
    assert len(ep.parse(source="text", text=body).links) == ep.MAX_LINKS


def test_html_links_skip_mailto_and_use_alt_text():
    html = ('<a href="mailto:x@y.z">mail</a><a href="tel:+971">call</a><a href="#top">top</a>'
            '<a href=" https://a.test/1 ">One</a><a href="//b.test/2"><img alt="Pay now" src="cid:1"></a>')
    links = ep.links_from_html(html)
    assert [(link.href, link.text) for link in links] == [("https://a.test/1", "One"), ("https://b.test/2", "Pay now")]


# ---------------------------------------------------------------------------
# Extension DOM capture (meta) and extra HTML
# ---------------------------------------------------------------------------
META = {
    "provider": "gmail", "message_key": "k" * 64, "from_name": "DHL Express", "from_address": "dhl@dhl-redelivery.test",
    "reply_to": "DHL <support@gmail.com>", "subject": "Your parcel is on hold", "date": "Mon, 23 Nov 2026",
    "body_text": "Pay the customs fee at https://dhl-redelivery.test/pay",
    "links": [{"href": "https://dhl-redelivery.test/pay?id=1", "text": "Track parcel"}],
    "attachments": [{"name": "label.html", "size": 1200}],
}


def test_meta_only():
    p = ep.parse(source="text", meta=META)
    assert not p.has_headers and not p.byte_exact
    assert p.from_.address == "dhl@dhl-redelivery.test" and p.from_.display_name == "DHL Express"
    assert p.reply_to.address == "support@gmail.com"
    assert p.subject == "Your parcel is on hold"
    assert [link.href for link in p.links] == ["https://dhl-redelivery.test/pay?id=1", "https://dhl-redelivery.test/pay"]
    assert p.links[0].text == "Track parcel"
    assert [(a.name, a.size) for a in p.attachments] == [("label.html", 1200)]


def test_meta_with_raw_headers_win():
    raw = load("phish_punycode_sender.eml").decode("utf-8")
    p = ep.parse(source="raw", text=raw, meta={**META, "attachments": []})
    assert p.has_headers
    assert p.from_.address == "alerts@xn--dcb-secure-yqi.test"  # headers beat the page
    assert p.subject.startswith("ADCB")
    assert any(link.href == "https://dhl-redelivery.test/pay?id=1" for link in p.links)  # page links added


def test_meta_overrides_guess_from_visible_text():
    p = ep.parse(source="text", text="From: someone\n\nhello", meta={"from_address": "real@sender.test"})
    assert p.from_.address == "real@sender.test"


def test_extra_html_param():
    p = ep.parse(source="text", text="Body", html='<p><a href="https://html-link.test/x">Open</a></p>')
    assert ("https://html-link.test/x", "Open") in [(link.href, link.text) for link in p.links]
    assert p.html_body.startswith("<p>")


# ---------------------------------------------------------------------------
# Errors and limits
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("kwargs", [
    dict(source="text"),
    dict(source="text", text="   \n "),
    dict(source="raw", text=""),
    dict(source="eml"),
    dict(source="msg"),
    dict(source="pdf", text="x"),
])
def test_unusable_input_raises(kwargs):
    with pytest.raises(ValueError):
        ep.parse(**kwargs)


def test_size_limit():
    with pytest.raises(ValueError, match="4 MB"):
        ep.parse(source="eml", file_bytes=b"From: a@b.c\r\n\r\n" + b"x" * (4 * 1024 * 1024))
    with pytest.raises(ValueError, match="4 MB"):
        ep.parse(source="text", text="y" * (4 * 1024 * 1024 + 1))


def test_msg_that_is_not_ole_raises():
    with pytest.raises(ValueError, match="not an Outlook"):
        ep.parse(source="msg", file_bytes=b"From: a@b.c\r\n\r\nhi")


def test_eml_without_header_block_is_read_as_text():
    p = ep.parse(source="eml", file_bytes="Just some text with https://a.test/x".encode())
    assert not p.has_headers and not p.byte_exact and p.links[0].href == "https://a.test/x"


def test_undeclared_8bit_body_is_utf8():
    raw = "From: a@b.test\r\nSubject: x\r\n\r\nمرحبا https://مثال.test/\r\n".encode()
    p = ep.parse(source="eml", file_bytes=raw)
    assert p.text_body.startswith("مرحبا")
    assert p.links[0].href == "https://مثال.test/"


# ---------------------------------------------------------------------------
# Outlook .msg
# ---------------------------------------------------------------------------
def test_msg_stream_decoders():
    assert ep.decode_msg_string(u16("Hello مرحبا\0\0"), "001F") == "Hello مرحبا"
    assert ep.decode_msg_string("Café".encode("cp1252") + b"\0", "001E") == "Café"
    assert ep.decode_msg_string("Café".encode("utf-8"), "001E") == "Café"
    assert ep.decode_msg_html(b'<meta charset="windows-1256"><p>\xe3</p>').endswith("<p>م</p>")
    assert ep.decode_msg_html("<p>é</p>".encode("utf-8")) == "<p>é</p>"
    assert ep.filetime_to_iso(FT_2025_11_23_1030).startswith("2025-11-23T10:30")
    assert ep.filetime_to_iso(0) == ""


def test_msg_with_transport_headers():
    data = build_spoof_tamm_msg()
    import olefile

    assert olefile.isOleFile(data)
    p = ep.parse(source="msg", file_bytes=data, file_name="fine.msg")
    assert p.source == "msg" and p.has_headers and not p.byte_exact and p.raw_bytes is None
    assert p.from_.address == "noreply@tamm.abudhabi" and p.from_.display_name == "TAMM Abu Dhabi"
    assert p.subject == "Unpaid traffic fine - pay within 24 hours"
    assert p.date == "Mon, 23 Nov 2026 14:10:02 +0400"
    assert p.return_path.address == "bounce@fines-portal.test"
    assert p.header("Authentication-Results").startswith("mx.google.com;")
    assert p.message_id == "<fine.20261123141002@fines-portal.test>"
    assert p.to_count == 1
    assert "unpaid traffic fine" in p.text_body
    assert "دفع" in p.html_body  # binary HTML decoded with its <meta charset>
    assert ("https://tamm-fine-pay.test/pay?ref=77", "https://www.tamm.abudhabi/fines") in [
        (link.href, link.text) for link in p.links]
    assert [(a.name, a.size, a.content_type) for a in p.attachments] == [
        ("Fine_Notice.pdf.exe", 5002, "application/octet-stream")]


def test_msg_without_transport_headers():
    p = ep.parse(source="msg", file_bytes=build_headerless_msg())
    assert not p.has_headers and p.headers == []
    assert p.from_.address == "billing@example.org"  # SMTP address, not the Exchange X.500 name
    assert p.from_.display_name == "Billing Team"
    assert p.subject == "Café invoice"  # 8-bit string property in Windows-1252
    assert p.date.startswith("2025-11-23T10:30")
    assert p.to_count == 2
    assert p.links[0].href == "http://billing.example.org/invoice/7"
    assert any("internet headers" in n for n in p.notes)


def test_msg_rtf_only_body_is_skipped_with_note():
    p = ep.parse(source="msg", file_bytes=build_headerless_msg(rtf_only=True))
    assert p.text_body == "" and any("RTF" in n for n in p.notes)


def test_ole_file_uploaded_as_eml_is_read_as_msg():
    p = ep.parse(source="eml", file_bytes=build_spoof_tamm_msg(), file_name="renamed.eml")
    assert p.source == "msg" and p.from_.address == "noreply@tamm.abudhabi"


def test_msg_fixture_file_matches_builder():
    """tests/fixtures/emails/msg_outlook_spoof_tamm.msg is the builder's output (shared with other tests)."""
    assert MSG_FIXTURE.read_bytes() == build_spoof_tamm_msg()
    p = ep.parse(source="msg", file_bytes=MSG_FIXTURE.read_bytes(), file_name=MSG_FIXTURE.name)
    assert p.from_.domain == "tamm.abudhabi" and p.attachments[0].name == "Fine_Notice.pdf.exe"
