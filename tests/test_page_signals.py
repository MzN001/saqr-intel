"""Page-content evidence for platform-hosted / hacked-site phishing (saqr/intel/page_signals.py)."""
import time

import pytest

from saqr.intel import ai_inspector, page_signals
from saqr.intel.ai_inspector import STRONG_SIGNALS, run_rules
from saqr.intel.domain_intel import analyze_lexical
from saqr.intel.sandbox import classify_fields, sandbox


def _page(html: str, url: str, title: str = "", text: str = "") -> dict:
    return sandbox._from_http_only({"status": 200, "final_url": url, "title": title, "text": text, "html": html},  # noqa: SLF001
                                   url, time.perf_counter())


def _codes(rr) -> set[str]:
    return {f.code for f in rr.flags if f.points > 0}


def test_new_page_flags_are_strong_signals():
    assert {"PROVIDER_PHISHING_WARNING", "FORM_SERVICE_CREDENTIALS", "BRAND_LOGIN_PAGE",
            "SHORTLINK_DISABLED"} <= STRONG_SIGNALS


def test_cloudflare_phishing_interstitial_blocks():
    url = "https://pj-suporte-net.com/"
    page = _page("<html></html>", url, "Suspected Phishing | Cloudflare",
                 "Suspected Phishing | Cloudflare Please enable cookies. Warning Suspected Phishing This website has "
                 "been reported for potential phishing.")
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert "PROVIDER_PHISHING_WARNING" in _codes(rr)
    assert rr.verdict == "HIGH-RISK SCAM"


def test_ordinary_cloudflare_block_page_is_not_a_phishing_warning():
    url = "https://some-shop.com/"
    page = _page("<html></html>", url, "Attention Required! | Cloudflare",
                 "Please enable cookies. Sorry, you have been blocked")
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert "PROVIDER_PHISHING_WARNING" not in _codes(rr)
    assert rr.verdict == "SAFE"


def test_weebly_form_asking_for_password_is_caught():
    url = "https://treemanaging.weebly.com/"
    html = ('<form action="//www.weebly.com/weebly/apps/formSubmit.php" method="POST">'
            '<label class="wsite-form-label" for="input-1">Email <span>*</span></label><input id="input-1" name="_u1" type="text">'
            '<label class="wsite-form-label" for="input-2">Passvvord <span>*</span></label><input id="input-2" name="_u2" type="text">'
            '</form>')
    page = _page(html, url, "Home", "Home * Indicates required field Email * Passvvord * Let's go")
    assert "PASSWORD" in page["harvested_fields"]
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert "FORM_SERVICE_CREDENTIALS" in _codes(rr)
    assert rr.score >= 45


def test_weebly_contact_form_without_secrets_is_safe():
    url = "https://bakery-family.weebly.com/"
    html = ('<form action="//www.weebly.com/weebly/apps/formSubmit.php"><label for="a">Name</label><input id="a" name="_u1">'
            '<label for="b">Email</label><input id="b" name="_u2"><label for="c">Message</label><textarea id="c" name="_u3">'
            '</textarea></form>')
    page = _page(html, url, "Contact us", "Contact us Name Email Message")
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert not _codes(rr) & {"FORM_SERVICE_CREDENTIALS", "BRAND_LOGIN_PAGE"}
    assert rr.verdict == "SAFE"


def test_brand_login_page_on_free_hosting_is_high_risk():
    url = "https://my-docs-page.github.io/"
    html = '<form action="next.php" method="post"><input name="email"><input name="pass" type="password"></form>'
    page = _page(html, url, "PayPal Login | Log in to your account", "Log in to your PayPal account")
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert "BRAND_LOGIN_PAGE" in _codes(rr)
    assert rr.verdict == "HIGH-RISK SCAM"
    assert rr.entity is not None and rr.entity.name_en == "PayPal"


def test_accented_brand_title_still_names_the_brand():
    assert page_signals.fold("Róbinhood Login") == "Robinhood Login"


@pytest.mark.parametrize("url,title,html", [
    # documentation about a brand on a free-hosting platform: no log-in wording, no secrets
    ("https://sdk-notes.github.io/", "PayPal SDK documentation", "<p>REST examples</p>"),
    # a blog review mentioning a brand, newsletter e-mail only
    ("https://old-tech-blog.com/review", "Microsoft Teams review",
     '<form><input name="email" placeholder="Your e-mail"></form>'),
])
def test_brand_mentions_without_a_login_form_stay_safe(url, title, html):
    rr = run_rules(page_signals.lexical(url), {}, _page(html, url, title, title), None)
    assert "BRAND_LOGIN_PAGE" not in _codes(rr)
    assert rr.verdict == "SAFE"


def test_static_html_labels_are_read():
    url = "https://example-shop.com/"
    page = _page('<form><label>Card number <input name="f1"></label><span>CVV</span><input name="f2"></form>', url)
    assert {"CARD_NUMBER", "CVV"} <= set(page["harvested_fields"])
    assert classify_fields(page["forms"]) == page["harvested_fields"]


def test_cloud_bucket_on_an_official_domain_is_not_whitelisted():
    lex = page_signals.lexical("https://glucopril.storage.googleapis.com/40ad1baf13b34c.html")
    assert not lex.is_whitelisted
    assert analyze_lexical("https://glucopril.storage.googleapis.com/x.html").is_whitelisted
    assert page_signals.lexical("https://www.google.com/").is_whitelisted
    assert page_signals.lexical("https://u.ae/en/information-and-services").is_whitelisted


def test_shortener_that_terminated_the_link_warns():
    url = "https://tinyurl.com/ClickIcl"
    page = _page("<html></html>", url, "URL Shortener, Branded Short Links & Analytics | TinyURL",
                 "TinyURL Visit TinyURL.com URL Terminated This TinyURL has been terminated")
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert "SHORTLINK_DISABLED" in _codes(rr)
    assert rr.score >= 30


def test_user_content_hosts():
    assert page_signals.user_content("att-10page.weeblysite.com")
    assert page_signals.user_content("abc.gitbook.io")
    assert page_signals.user_content("x.github.io")
    assert not page_signals.user_content("gitbook.io.example.com")
    assert not page_signals.user_content("adcb.com")


def _model_says(monkeypatch, p):
    monkeypatch.setattr(ai_inspector, "url_model_result", lambda lex: {"probability": p, "reasons": []})


def test_new_domain_and_leaning_model_together_warn(monkeypatch):
    _model_says(monkeypatch, 0.6)
    rr = run_rules(page_signals.lexical("https://interactlve-brokers.com/"), {"domain_age_hours": 48}, None, None)
    assert {"YOUNG_DOMAIN", "AI_NEW_DOMAIN"} <= _codes(rr)
    assert rr.verdict == "SUSPICIOUS"
    old = run_rules(page_signals.lexical("https://interactlve-brokers.com/"), {"domain_age_hours": 24 * 400}, None, None)
    assert "AI_NEW_DOMAIN" not in _codes(old)


def test_taken_down_domain_with_phishy_address_warns(monkeypatch):
    _model_says(monkeypatch, 0.9)
    url = "https://atualiza-pj.com/"
    gone = run_rules(page_signals.lexical(url), {"dns_status": "nxdomain", "ip_addresses": []}, None, None)
    assert "SITE_TAKEN_DOWN" in _codes(gone) and gone.verdict == "SUSPICIOUS"
    alive = run_rules(page_signals.lexical(url), {"dns_status": "ok", "ip_addresses": ["203.0.113.9"]}, None, None)
    assert "SITE_TAKEN_DOWN" not in _codes(alive)


def test_model_and_page_branding_agree(monkeypatch):
    url = "https://www-movies-app.netlify.app/"
    page = _page("<html></html>", url, "Netflix", "Netflix")
    _model_says(monkeypatch, 0.9)
    rr = run_rules(page_signals.lexical(url), {}, page, None)
    assert "BRAND_CONTENT" in _codes(rr) and rr.score >= 30
    _model_says(monkeypatch, 0.1)
    assert run_rules(page_signals.lexical(url), {}, page, None).verdict == "SAFE"


def test_brand_named_only_by_its_own_platform_is_not_impersonation():
    rr = run_rules(page_signals.lexical("https://tinworth.sharepoint.com/sites/manila/shared%20documents/forms/allitems.aspx"),
                   {}, None, None)
    assert "BRAND_IMPERSONATION" not in _codes(rr)
    fake = page_signals.lexical("https://microsoft-office365-login.sharepoint.com/")
    assert not page_signals.platform_named_only(fake)
    assert "BRAND_IMPERSONATION" in _codes(run_rules(fake, {}, None, None))


def test_renewed_certificate_on_an_old_domain_is_not_zero_hour():
    url = "http://www.britishbottleforum.co.uk/"
    old = run_rules(page_signals.lexical(url), {"cert_age_hours": 5, "domain_age_hours": 24 * 3000}, None, None)
    assert "FRESH_CERTIFICATE" not in {f.code for f in old.flags}
    new = run_rules(page_signals.lexical(url), {"cert_age_hours": 5, "domain_age_hours": 24 * 3}, None, None)
    assert "FRESH_CERTIFICATE" in _codes(new)
