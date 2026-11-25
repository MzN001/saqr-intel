"""A SAFE result that could not actually be checked is "not verified", never a clean bill of health.

Run: pytest -q tests/test_verification_note.py   (offline)
"""
from saqr import message_pipeline
from saqr.intel import page_signals
from saqr.pipeline import verification_note


def _lex(url):
    return page_signals.lexical(url)


def test_unresolved_short_link_is_not_verified():
    note = verification_note("SAFE", _lex("https://bit.ly/zz-nonexistent"), None)
    assert note and note["status"] == "unverified" and note["code"] == "SHORTLINK_UNRESOLVED"
    assert note["en"] and note["ar"]


def test_site_that_did_not_answer_is_not_verified():
    lex = _lex("https://some-small-unknown-shop.example/pay")
    for page in ({"status": "unreachable", "http_status": None}, {"status": "ok", "http_status": 404},
                 {"status": "ok", "http_status": 503}):
        note = verification_note("SAFE", lex, page)
        assert note and note["code"] == "SITE_UNREACHABLE", page


def test_a_page_that_was_read_is_verified():
    assert verification_note("SAFE", _lex("https://some-small-unknown-shop.example/"),
                             {"status": "ok", "http_status": 200}) is None


def test_fast_scans_without_a_page_are_not_marked():
    # extension / SMS link sub-scans do not fetch the page: only an unresolved shortener is "not verified"
    assert verification_note("SAFE", _lex("https://some-small-unknown-shop.example/"), None) is None


def test_never_on_scams_official_or_popular_sites():
    dead = {"status": "unreachable", "http_status": None}
    assert verification_note("HIGH-RISK SCAM", _lex("https://bit.ly/x"), None) is None
    assert verification_note("SUSPICIOUS", _lex("https://some-small-unknown-shop.example/"), dead) is None
    assert verification_note("SAFE", _lex("https://www.adpolice.gov.ae/"), dead) is None   # official
    assert verification_note("SAFE", _lex("https://www.wikipedia.org/"), {"status": "ok", "http_status": 403}) is None


def _link(url, **extra):
    host = url.split("/")[2]
    return {"url": url, "domain": host, "whitelisted": False, "official": False, "mock_scam_replica": None, **extra}


def test_short_links_in_a_message_are_scanned_not_skipped_as_popular():
    picked = message_pipeline._candidates([_link("https://bit.ly/abc"), _link("https://www.youtube.com/watch?v=1")])  # noqa: SLF001
    assert [l["domain"] for l in picked] == ["bit.ly"]


def test_message_with_an_unchecked_link_is_not_verified():
    note = message_pipeline._unverified_links([_link("https://bit.ly/abc", unverified=True)])  # noqa: SLF001
    assert note and note["code"] == "MSG_LINK_UNVERIFIED" and "bit.ly" in note["en"]
    assert message_pipeline._unverified_links([_link("https://example.org/x", unverified=False)]) is None  # noqa: SLF001
