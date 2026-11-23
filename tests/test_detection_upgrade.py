"""Global-brand impersonation, trained URL classifier, threat feeds, LLM blending. Run: pytest -q"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402

from saqr.intel import url_model  # noqa: E402
from saqr.intel.ai_inspector import LLMVerdict, blend, run_rules, url_model_probability  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402
from saqr.intel.threat_feeds import ThreatFeeds, threat_feeds  # noqa: E402


def rules(host):
    return run_rules(analyze_lexical(host), {}, None, None)


@pytest.mark.parametrize("host", [
    "paypal-secure-login.com", "secure.paypa1.com", "appleid-verify-account.com",
    "microsoft-office365-signin.web.app", "wise-login-verify.com",
])
def test_global_brand_phishing_is_high_risk(host):
    assert rules(host).verdict == "HIGH-RISK SCAM"


@pytest.mark.parametrize("host", [
    # real brand domains, ordinary words that contain a brand, popular sites, other ccTLDs
    "outlook.live.com", "appleid.apple.com", "accounts.google.com", "google.fr", "amazon.eg", "paypal.com",
    "pineapple.com", "apple-pie-recipes.com", "chaser.com", "wise-living.com", "noonday.org", "adac.de",
    "github.com", "dubai-mall.com", "emirates.com", "du.ae", "steampowered.com",
])
def test_real_or_harmless_sites_stay_safe(host):
    r = rules(host)
    assert r.verdict == "SAFE", (host, r.score, [f.code for f in r.flags if f.points])


def test_url_model_is_installed_and_sane():
    assert url_model.available()
    assert url_model.phishing_probability("microsoft-office365-signin-verify.web.app") > 0.95
    assert url_model.phishing_probability("wikipedia.org") < 0.5
    # popular sites are never judged by the model alone
    assert url_model_probability(analyze_lexical("https://www.bbc.co.uk/news")) is None


def test_random_free_hosting_name_needs_more_than_the_model():
    r = rules("adorable-dodol-caf89a.netlify.app")
    assert r.verdict == "SUSPICIOUS"  # model alone: warn, but not a scam verdict


def test_threat_feed_matches_exact_hosts_and_never_platforms():
    f = ThreatFeeds()
    f.load({"test": ["https://evil-login.pages.dev/x", "verifcv.com", "pages.dev", "vercel.app", "google.com",
                     "paypal.com", "www.Bad-Shop.top"]})
    assert f.lookup("evil-login.pages.dev") == "test"
    assert f.lookup("bnpp.verifcv.com") == "test"  # sub-domain of a listed domain
    assert f.lookup("bad-shop.top") == "test"
    for safe in ("other.pages.dev", "x.vercel.app", "google.com", "paypal.com", "mail.google.com"):
        assert f.lookup(safe) is None, safe


def test_feed_hit_is_high_risk(monkeypatch):
    monkeypatch.setattr(threat_feeds, "hosts", {"totally-normal-shop.com": "OpenPhish"})
    r = rules("totally-normal-shop.com")
    assert r.verdict == "HIGH-RISK SCAM" and any(f.code == "KNOWN_PHISHING_FEED" for f in r.flags)


def test_confident_llm_scam_verdict_lifts_corroborated_case():
    rr = rules("adorable-dodol-caf89a.netlify.app")  # model-only SUSPICIOUS
    lv = LLMVerdict(risk_score=92, verdict="HIGH-RISK SCAM", confidence=0.9)
    assert blend(rr, lv) >= 65


def test_confident_llm_safe_verdict_softens_model_only_warning():
    rr = rules("adorable-dodol-caf89a.netlify.app")
    lv = LLMVerdict(risk_score=5, verdict="SAFE", confidence=0.9)
    assert blend(rr, lv) < 30


def test_llm_cannot_lower_hard_evidence():
    rr = rules("secure.paypa1.com")  # homoglyph spoof
    lv = LLMVerdict(risk_score=0, verdict="SAFE", confidence=1.0)
    assert blend(rr, lv) == rr.score


@pytest.mark.parametrize("url", ["https://saqr-intel.vercel.app/citizen", "https://saqr-intel-api.onrender.com/docs"])
def test_saqr_own_website_is_always_safe(url):
    """The SAQR site lives on vercel.app next to the demo scam pages: it must never be flagged."""
    r = rules(url)
    assert r.verdict == "SAFE" and r.score == 0


def test_own_hosts_never_published():
    from saqr import self_hosts
    assert {"saqr-intel.vercel.app", "saqr-intel-api.onrender.com"} <= self_hosts.known_hosts()
    assert "saqr-demo-scam.vercel.app" not in self_hosts.known_hosts()  # the demo scam page still is
