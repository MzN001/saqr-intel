"""Unicode-trick detector (saqr/intel/email_unicode.py): every kind is found, and ordinary
international text is never flagged. Pure functions: no app, no network."""
import os
import tempfile

# Same offline test setup as tests/test_api.py (must run before any saqr import: settings are read once).
os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402

from saqr.intel.email_unicode import (
    deconfuse,
    escape,
    scan_address,
    scan_domain,
    scan_text,
    scan_url,
    script_of,
)


def kinds(findings):
    return {f["kind"] for f in findings}


# -- found ----------------------------------------------------------------------------------------
def test_cyrillic_letter_in_subject_is_mixed_script():
    f = scan_text("Your PаyPal account has been limited", "subject")
    assert f == [{"where": "subject", "kind": "mixed_script", "sample_escaped": "P\\u0430yPal", "skeleton": "paypal"}]


def test_greek_and_uppercase_cyrillic_lookalikes():
    assert kinds(scan_text("Dear Μicrosoft user", "body")) == {"mixed_script"}      # Greek capital Mu
    assert kinds(scan_text("РАУРАL", "display_name")) == {"mixed_script"}


def test_whole_word_of_lookalikes_spelling_a_brand():
    f = scan_text("аррӏе ID", "subject")  # "аррӏе" all Cyrillic
    assert any(x["kind"] == "whole_script_confusable" and x["skeleton"] == "apple" for x in f)


def test_punycode_sender_domain_mixed_script():
    f = scan_address("alerts@xn--dcb-secure-yqi.test", "from.address")
    assert {(x["where"], x["kind"]) for x in f} == {("from.domain", "mixed_script"), ("from.domain", "punycode")}
    assert f[0]["skeleton"] == "adcb-secure.test"
    assert f[0]["sample_escaped"] == "\\u0430dcb-secure.test"


def test_unicode_domain_written_directly_and_whole_script():
    f = scan_domain("аррӏе.com", "link")
    assert kinds(f) == {"whole_script_confusable", "punycode"}


def test_single_script_idn_is_only_punycode():
    assert kinds(scan_domain("موقع.امارات", "link")) == {"punycode"}
    assert kinds(scan_domain("例え.jp", "link")) == {"punycode"}  # Han + Hiragana is normal Japanese


def test_latin_plus_arabic_label_is_mixed():
    assert "mixed_script" in kinds(scan_domain("payبal.com", "link"))


def test_reply_to_keeps_its_where():
    f = scan_address("help@xn--pypal-4ve.com", "reply_to")  # pаypal.com
    assert f and all(x["where"] == "reply_to" for x in f)


def test_lookalike_in_address_local_part():
    f = scan_address("pаypal@gmail.com", "from.address")
    assert ("from.address", "mixed_script") in {(x["where"], x["kind"]) for x in f}


@pytest.mark.parametrize("text", ["Pay​Pal", "Pay‍Pal", "Pay⁠Pal", "Pay﻿Pal", "Pay͏Pal",
                                  "secure‌1234", "Pay­Pal"])
def test_invisible_inside_latin_word(text):
    assert kinds(scan_text(f"Hello {text} team", "body")) == {"invisible"}


def test_invisible_inside_url_or_address():
    assert "invisible" in kinds(scan_url("https://pay​pal.com/login"))
    assert "invisible" in kinds(scan_url("https://paypal.com/​/login"))
    assert "invisible" in kinds(scan_address("service​@paypal.com", "from.address"))
    assert "invisible" in kinds(scan_text("open https://example.​com/x now", "body"))


def test_bidi_override_in_attachment_name():
    f = scan_text("Invoice_88412_‮fdp.exe", "attachment")
    assert f[0]["kind"] == "bidi" and f[0]["skeleton"] == "invoice_88412_fdp.exe"
    assert kinds(scan_text("report⁦.pdf", "attachment")) == {"bidi"}  # any bidi control in a file name


def test_rlo_next_to_latin_text_in_body():
    assert kinds(scan_text("Download invoice‮gpj.exe today", "body")) == {"bidi"}


def test_bidi_in_link_or_address():
    assert "bidi" in kinds(scan_url("https://example.com/‮fdp.exe"))
    assert "bidi" in kinds(scan_address("billing‫@example.com", "from.address"))


def test_fancy_letters():
    f = scan_text("\U0001d40f\U0001d41a\U0001d432\U0001d40f\U0001d41a\U0001d425 Support", "display_name")
    assert kinds(f) == {"fancy"} and f[0]["skeleton"] == "paypal"
    assert kinds(scan_text("ＰａｙＰａｌ", "subject")) == {"fancy"}  # full-width


# -- never flagged ------------------------------------------------------------------------------------
@pytest.mark.parametrize("text", [
    "عزيزي العميل، تم إيداع راتبك",  # Arabic
    "می‌خواهم به‌روز",   # Persian with ZWNJ
    "क्‍ष संपर्क",                           # Devanagari with ZWJ
    "Family: \U0001f468‍\U0001f469‍\U0001f467 and \U0001f3f3️‍\U0001f308",  # emoji ZWJ sequences
    "Big sale today ‌ ͏‌ ͏‌ ͏",                    # preheader padding
    "​​​See you soon​\n‌‌",                                       # padding at line ends
    "Привет, Москва! сорок",  # Russian
    "Ελληνικά και αβγ",   # Greek text
    "Straße, café, naïve, µg, ™, ℹ info",                          # accented Latin
    "مرحبا‏ ‎(ID 4821)‎ and ‫نص‬",   # LRM/RLM, RLE/PDF
    "Wonder­ful hyphen­ation of long words",                                           # soft hyphens
    "﻿Hello, this starts with a byte-order mark",
    "日本語のメール iPhone用",                                  # Japanese + Latin
])
def test_ordinary_text_is_never_flagged(text):
    assert scan_text(text, "body") == [], text


@pytest.mark.parametrize("host", ["gmail.com", "mail.bankfab.com", "u8812.ct.sendgrid.net", "", None])
def test_ascii_domains_are_clean(host):
    assert scan_domain(host, "from.domain") == []


def test_persian_file_name_with_zwnj_is_clean():
    assert scan_text("گزارش‌مالی.pdf", "attachment") == []


# -- helpers -------------------------------------------------------------------------------------------
def test_helpers():
    assert escape("pаy\U0001d40f") == "p\\u0430y\\U0001d40f"
    assert deconfuse("Pаy​Pal") == "PayPal"
    assert script_of("а") == "Cyrillic" and script_of("a") == "Latin" and script_of("1") is None
    assert script_of("\U0001d40f") == "Latin"  # styled letters look Latin


def test_findings_are_capped():
    text = " ".join(f"PаyPal{i}" for i in range(500))
    assert len(scan_text(text, "body")) <= 40


# -- regressions from the end-to-end adversarial run (2026-11-23) -----------------------------------
@pytest.mark.parametrize("hidden", ["⁢", "᠎", "ㅤ", "\U000e0041", "️", "‎"])
def test_other_invisible_characters_inside_a_word(hidden):
    # invisible operators, Mongolian vowel separator, Hangul filler, tag characters, variation
    # selectors and LRM between two Latin letters hide a brand from filters just like U+200B
    f = scan_text(f"Your Pay{hidden}Pal account is limited", "body")
    assert kinds(f) == {"invisible"} and f[0]["skeleton"] == "paypal", f
    if hidden != "\u200e":  # LRM next to an address is normal copy-paste from right-to-left mail
        assert kinds(scan_address(f"service@pay{hidden}pal.com", "from.address")) >= {"invisible"}
        assert "invisible" in kinds(scan_url(f"https://pay{hidden}pal.com/login"))


@pytest.mark.parametrize("word,skel", [("PɑyPal", "paypal"), ("LınkedIn", "linkedin"),
                                       ("Netflıx", "netflix")])
def test_latin_only_lookalike_letters_spelling_a_brand(word, skel):
    f = scan_text(f"Your {word} account", "body")
    assert [(x["kind"], x["skeleton"]) for x in f] == [("whole_script_confusable", skel)]


def test_latin_only_lookalike_domain_spelling_a_brand():
    assert kinds(scan_domain("pɑypal.com", "link")) == {"whole_script_confusable", "punycode"}
    assert kinds(scan_domain("pɑypal-secure.net", "link")) == {"whole_script_confusable", "punycode"}
    assert kinds(scan_domain("kayıt.com.tr", "link")) == {"punycode"}  # Turkish word, not a brand


def test_lisu_and_small_cherokee_lookalikes():
    assert kinds(scan_text("ꓑayPal Billing", "display_name")) == {"mixed_script"}
    assert "mixed_script" in kinds(scan_domain("ꮒaypal.com", "from.domain"))


def test_percent_encoded_link_host_is_decoded():
    f = scan_url("https://p%D0%B0ypal.com/signin")
    assert kinds(f) == {"mixed_script", "punycode"} and f[0]["skeleton"] == "paypal.com"
    assert scan_url("https://example.com/%D0%B0") == []


def test_plain_text_punycode_domain_in_body():
    f = scan_text("Go to xn--pypal-4ve.com and log in.", "body")
    assert ("mixed_script", "paypal.com") in {(x["kind"], x["skeleton"]) for x in f}
    assert scan_text("see https://example.com/xn--path and 3.14", "body") == []


def test_small_capitals_are_fancy():
    assert kinds(scan_text("Your ᴘᴀʏᴘᴀʟ account", "body")) == {"fancy"}
    assert deconfuse("ᴘᴀʏᴘᴀʟ") == "paypal"


@pytest.mark.parametrize("host", ["рус.рф", "рос.рф",
                                  "xn--p1acf.xn--p1ai", "ехо.москва"])
def test_cyrillic_name_under_cyrillic_tld_is_only_punycode(host):
    # every letter happens to look Latin, but under .рф / .москва it is an ordinary Russian name
    assert kinds(scan_domain(host, "link")) == {"punycode"}


def test_lookalike_spelling_brand_under_cyrillic_tld_still_flagged():
    assert "whole_script_confusable" in kinds(scan_domain("аррӏе.рф", "link"))
    assert "whole_script_confusable" in kinds(scan_domain("сосо.com", "link"))


@pytest.mark.parametrize("text", [
    "Bсе хорошо",       # Russian "Все" typed with a Latin B
    "Kayıt işlemi, ılık su, Iğdır",  # Turkish dotless i
    "\U0001f3f4\U000e0067\U000e0062\U000e0065\U000e006e\U000e0067\U000e007f flag, 1️⃣, ❤️",
    "فاطمة‏ Fatima‎ (ID)",
])
def test_regression_ordinary_text_still_clean(text):
    assert scan_text(text, "body") == [], text


def test_fullwidth_or_math_domain_spelling_a_brand():
    assert "whole_script_confusable" in kinds(scan_domain("ｐａｙｐａｌ.com", "from.domain"))
    assert "whole_script_confusable" in kinds(scan_domain("\U0001d429\U0001d41a\U0001d432\U0001d429\U0001d41a\U0001d425.com", "link"))


def test_punycode_url_written_as_link_text():
    f = scan_text("https://xn--pypal-4ve.com/signin", "body")
    assert ("mixed_script", "paypal.com") in {(x["kind"], x["skeleton"]) for x in f}
