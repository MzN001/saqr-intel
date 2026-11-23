"""False-positive regression cases for email scanning: real, harmless mail must stay SAFE.

The three legitimate fixtures plus inline messages for the traps real mail is full of: a Google
Groups list that breaks DKIM, a bulk-mail (ESP) bounce address, Arabic / Persian text with ZWNJ,
emoji ZWJ sequences, preheader padding, and a real bank notice with aligned DMARC.
Run: pytest -q tests/test_email_false_positives.py
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"  # no WHOIS/DNS/LLM calls in CI
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import base64  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

pytest.importorskip("saqr.intel.email_parse")  # the parser (email workstream A) is required end to end

from main import app  # noqa: E402
from saqr.routers import email as email_router  # noqa: E402

if "/api/analyze-email" not in {getattr(r, "path", None) for r in app.routes}:
    app.include_router(email_router.router)

FIX = Path(__file__).parent / "fixtures"
EMAILS = FIX / "emails"


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def b64(name: str) -> str:
    return base64.b64encode((EMAILS / name).read_bytes()).decode()


def scan(client, **body):
    body.setdefault("use_llm", False)
    r = client.post("/api/analyze-email", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def codes(res, scoring=True):
    return {f["code"] for f in res["red_flags"] if f["points"] > 0 or not scoring}


@pytest.mark.parametrize("name", ["legit_plain.eml", "legit_newsletter_list.eml", "legit_arabic_bank.eml"])
def test_legit_fixtures_safe(client, name):
    res = scan(client, source="eml", file_base64=b64(name), file_name=name)
    assert res["verdict"] == "SAFE" and res["risk_score"] < 30, (name, res["risk_score"], codes(res))
    assert not any(f["strength"] == "strong" and f["points"] > 0 for f in res["red_flags"]), codes(res)
    assert res["unicode"]["findings"] == []


def test_arabic_bank_is_recognised_as_official(client):
    res = scan(client, source="eml", file_base64=b64("legit_arabic_bank.eml"))
    assert {"DMARC_PASS", "OFFICIAL_SENDER"} <= codes(res, False)
    assert res["email"]["from"]["is_official"] and res["citizen_explanation_en"] and res["citizen_explanation_ar"]


GOOGLE_GROUP = """Delivered-To: omar.example@gmail.com
Received: by 2002:a05:6a20:1111:b0:2c1:77ab:91fe with SMTP id k49csp1pzb;
        Mon, 23 Nov 2026 02:00:05 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=fail header.i=@example.com header.s=s1 header.b=AbCdEf12;
       arc=pass (i=1 spf=pass spfdomain=example.com dkim=pass dkdomain=example.com dmarc=pass fromdomain=example.com);
       spf=pass (google.com: domain of lunch-club+bncBAABB@googlegroups.com designates 209.85.220.69 as permitted sender) smtp.mailfrom=lunch-club+bncBAABB@googlegroups.com;
       dmarc=fail (p=NONE sp=NONE dis=NONE arc=pass) header.from=example.com
Return-Path: <lunch-club+bncBAABB@googlegroups.com>
ARC-Seal: i=1; a=rsa-sha256; t=1795255205; cv=none; d=google.com; s=arc-20240605; b=FAKEarcSealForFixtureOnly==
ARC-Authentication-Results: i=1; mx.google.com; dkim=pass header.i=@example.com; spf=pass smtp.mailfrom=sara@example.com; dmarc=pass header.from=example.com
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=s1; h=from:to:subject:date; bh=FAKEbh=; b=FAKEb=
From: Sara Example <sara@example.com>
Reply-To: lunch-club@googlegroups.com
To: Lunch Club <lunch-club@googlegroups.com>
Subject: [lunch-club] Thursday lunch at 1 pm
Date: Mon, 23 Nov 2026 14:00:01 +0400
Message-ID: <abc123.lunch@example.com>
List-Id: <lunch-club.googlegroups.com>
List-Unsubscribe: <mailto:lunch-club+unsubscribe@googlegroups.com>
Precedence: list
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Hi all, lunch on Thursday at 1 pm at the usual place?

--
You received this message because you are subscribed to the Google Groups "Lunch Club" group.
To unsubscribe from this group, visit https://groups.google.com/d/optout
"""

ESP_BOUNCE = """Received: from a8-30.smtp-out.amazonses.com (a8-30.smtp-out.amazonses.com [54.240.8.30])
        by mx1.mail.example.com (Postfix) with ESMTPS id 4R1
        for <reader@example.com>; Mon, 23 Nov 2026 08:00:00 +0400 (+04)
Authentication-Results: mx1.mail.example.com;
       spf=pass smtp.mailfrom=0100018c1a2b3c4d-aaaa@amazonses.com;
       dkim=pass header.d=amazonses.com;
       dmarc=none header.from=small-bakery.example
Return-Path: <0100018c1a2b3c4d-aaaa@amazonses.com>
DKIM-Signature: v=1; a=rsa-sha256; d=amazonses.com; s=ug7nbtf4; h=from:to:subject; bh=FAKE=; b=FAKE=
From: Small Bakery <hello@small-bakery.example>
Reply-To: orders@small-bakery-shop.example
To: reader@example.com
Subject: This week's bread menu
Date: Mon, 23 Nov 2026 08:00:00 +0400
Message-ID: <menu.47@small-bakery.example>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Fresh sourdough and za'atar manakish this week. Order online:
https://small-bakery.example/menu
"""

BANK_NOTICE = """Delivered-To: customer.example@gmail.com
Received: by 2002:a05:6a20:2222:b0:2c1:77ab:91fe with SMTP id k49csp2pzb;
        Mon, 23 Nov 2026 03:00:05 -0800 (PST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@adcb.com header.s=sel1 header.b=Zz9;
       spf=pass (google.com: domain of alerts@adcb.com designates 192.0.2.80 as permitted sender) smtp.mailfrom=alerts@adcb.com;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=adcb.com
Return-Path: <alerts@adcb.com>
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=adcb.com; s=sel1; h=from:to:subject:date; bh=FAKE=; b=FAKE=
From: ADCB <alerts@adcb.com>
To: customer.example@gmail.com
Subject: ADCB: Important - your card will expire soon, update your details
Date: Mon, 23 Nov 2026 15:00:01 +0400
Message-ID: <card.renewal.88@adcb.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear customer,

Your ADCB debit card ending 4821 expires on 30/11/2026. Your new card will be delivered to your
registered address. To update your delivery details, log in to the ADCB app or https://www.adcb.com.

ADCB will never ask for your PIN, OTP or password by email or phone.
"""


def test_google_groups_list_breaking_dkim_is_safe(client):
    res = scan(client, source="raw", text=GOOGLE_GROUP)
    assert res["verdict"] == "SAFE", (res["risk_score"], codes(res, False))
    assert not {"DKIM_FAIL", "REPLY_TO_MISMATCH", "RETURN_PATH_MISMATCH", "DMARC_FAIL"} & codes(res, False)
    assert res["email"]["is_bulk"]


def test_esp_return_path_is_safe(client):
    res = scan(client, source="raw", text=ESP_BOUNCE)
    assert res["verdict"] == "SAFE", (res["risk_score"], codes(res, False))
    assert "RETURN_PATH_MISMATCH" not in codes(res, False)


def test_real_bank_notice_with_aligned_dmarc_is_safe(client):
    res = scan(client, source="raw", text=BANK_NOTICE)
    assert res["verdict"] == "SAFE" and res["risk_score"] <= 20, (res["risk_score"], codes(res, False))
    assert "OFFICIAL_SENDER" in codes(res, False)
    assert not {"DISPLAY_NAME_BRAND_SPOOF", "OFFICIAL_SENDER_UNAUTHENTICATED", "SENDER_LOOKALIKE"} & codes(res, False)


@pytest.mark.parametrize("text", [
    # Persian with ZWNJ inside words
    "From: Maryam <maryam@example.ir>\nSubject: جلسهٔ هفتهٔ بعد\n\n"
    "سلام، می‌خواستم بگویم "
    "که جلسه به‌روز شد.",
    # Arabic with RLM / ZWNJ and an Arabic signature
    "From: أحمد <ahmed@example.ae>\nSubject: موعد الغداء\n\n"
    "مرحباً‏ هل أنت متاح يوم "
    "الخميس؟‌\nمع تحياتي",
    # emoji ZWJ sequences
    "From: Lina <lina@example.com>\nSubject: Family picnic \U0001f468‍\U0001f469‍\U0001f467\n\n"
    "See you all on Friday! \U0001f3f3️‍\U0001f308 \U0001f9d1‍\U0001f373 bring snacks \U0001f44d\U0001f3fd",
])
def test_international_text_is_safe(client, text):
    res = scan(client, source="text", text=text)
    assert res["verdict"] == "SAFE" and res["unicode"]["findings"] == [], (codes(res, False), res["unicode"])


def test_preheader_padding_is_safe(client):
    html = ("<html><body><div style=\"display:none\">Our autumn menu is here" + "‌ ͏" * 60 + "</div>"
            "<p>Hello! Our autumn menu is here.</p><p>​</p><p><a href=\"https://small-bakery.example/menu\">"
            "See the menu</a></p></body></html>")
    meta = {"provider": "gmail", "from_name": "Small Bakery", "from_address": "hello@small-bakery.example",
            "subject": "Autumn menu ‌‌‌", "body_text": "Our autumn menu is here" + "‌ ͏" * 60
            + "\nHello! Our autumn menu is here.\n​\n",
            "links": [{"href": "https://small-bakery.example/menu", "text": "See the menu"}]}
    res = scan(client, source="text", html=html, meta=meta)
    assert res["verdict"] == "SAFE" and res["unicode"]["findings"] == [], (codes(res, False), res["unicode"])


def test_pasted_official_text_without_headers_is_not_unauthenticated(client):
    res = scan(client, source="text", text="From: TAMM <noreply@tamm.abudhabi>\nSubject: Your request was received\n\n"
                                            "Thank you. Your request 4821 is being processed.")
    assert res["verdict"] == "SAFE"
    assert "HEADERS_NOT_AVAILABLE" in codes(res, False) and "OFFICIAL_SENDER_UNAUTHENTICATED" not in codes(res, False)
