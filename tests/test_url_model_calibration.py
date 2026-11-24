"""URL model calibration, model loading and address-level regressions. Run: pytest -q"""
import json
import os
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402

from saqr.intel import url_model  # noqa: E402
from saqr.intel.ai_inspector import run_rules, url_model_result  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import calibration as cal  # noqa: E402

GRID = [i / 1000 for i in range(1001)]


def rules(url):
    return run_rules(analyze_lexical(url), {}, None, None)


def test_model_loads_with_trees_and_metrics():
    assert url_model.available()
    assert url_model._trees() is not None  # noqa: SLF001 - the ensemble, not the linear fallback
    stored = json.loads(url_model.METRICS_PATH.read_text(encoding="utf-8"))
    assert set(stored["thresholds"]) >= {"suspect", "strong", "certain"}
    size = url_model.MODEL_PATH.stat().st_size + url_model.TREES_PATH.stat().st_size
    assert size < 6_000_000


def test_shipped_calibration_matches_the_installed_model():
    stored = json.loads(url_model.METRICS_PATH.read_text(encoding="utf-8"))
    assert stored["calibration"]["model_sha256"] == url_model.model_fingerprint()
    assert url_model.calibrate(0.5) is not None


def test_calibration_is_monotone_and_bounded():
    vals = [url_model.calibrate(p) for p in GRID]
    assert all(v is not None and 0.0 <= v <= 1.0 for v in vals)
    assert all(b >= a - 1e-12 for a, b in zip(vals, vals[1:]))
    assert vals[-1] > vals[0]


@pytest.mark.parametrize("url", ["https://tamm-fines-pay.top/ae/pay", "https://www.wikipedia.org/wiki/UAE",
                                 "https://salik-toll-pay.vercel.app/pay"])
def test_raw_score_is_unchanged_and_calibrated_is_extra(url):
    res = url_model.score_url(url)
    raw = url_model._score(url)[0]  # noqa: SLF001
    assert res["probability"] == raw
    assert res["calibrated_probability"] == url_model.calibrate(raw)


def test_calibration_refused_for_other_model_files(tmp_path, monkeypatch):
    stored = json.loads(url_model.METRICS_PATH.read_text(encoding="utf-8"))
    stored["calibration"]["model_sha256"] = "0" * 64
    fake = tmp_path / "model_metrics.json"
    fake.write_text(json.dumps(stored), encoding="utf-8")
    monkeypatch.setattr(url_model, "METRICS_PATH", fake)
    url_model._calibration.cache_clear()  # noqa: SLF001
    try:
        assert url_model.calibrate(0.9) is None
        assert url_model.score_url("https://example-shop.com/cart")["calibrated_probability"] is None
    finally:
        monkeypatch.undo()
        url_model._calibration.cache_clear()  # noqa: SLF001


def test_runtime_and_training_side_tables_agree():
    table = json.loads(url_model.METRICS_PATH.read_text(encoding="utf-8"))["calibration"]
    for p in GRID[::7]:
        assert url_model.calibrate(p) == pytest.approx(cal.apply(table, p), abs=1e-12)


def test_isotonic_and_platt_fits_are_monotone():
    p = [i / 200 for i in range(200)] * 3
    y = [int((i % 200) / 200 > 0.6) if i % 5 else int((i % 200) / 200 > 0.3) for i in range(600)]
    for tab in (cal.fit_isotonic(p, y), cal.fit_platt(p, y)):
        out = [cal.apply(tab, v) for v in GRID]
        assert all(b >= a - 1e-12 for a, b in zip(out, out[1:]))
        assert all(0.0 <= v <= 1.0 for v in out)
    assert cal.ece([0.0, 1.0], [0, 1]) == 0.0 and cal.brier([1.0], [0]) == 1.0


@pytest.mark.parametrize("url", ["https://www.adcb.com/en/personal/accounts/", "https://u.ae/en/information-and-services",
                                 "https://www.tamm.abudhabi/en/life-events/individual/traffic-fines",
                                 "https://uaepass.ae/faq", "https://www.adpolice.gov.ae/en/Pages/home.aspx"])
def test_official_sites_stay_unjudged(url):
    assert url_model_result(analyze_lexical(url)) is None
    assert rules(url).verdict == "SAFE"


@pytest.mark.parametrize("url", ["https://tamm-traffic-fines-pay.top/ae/pay/card.php",
                                 "https://adcb-secure-login.xyz/verify/index.php?email=victim@mail.com"])
def test_obvious_lookalikes_are_still_flagged(url):
    assert rules(url).verdict != "SAFE"


@pytest.mark.parametrize("url", [
    "https://www.khaleejtimes.com/uae/beware-of-fake-salik-sms-asking-you-to-pay-toll-fines",
    "https://gulfnews.com/uae/crime/abu-dhabi-police-warn-of-fake-tamm-traffic-fine-payment-links-1.500123",
    "https://www.thenationalnews.com/news/uae/2026/10/02/how-to-spot-a-fake-adcb-login-page/",
    "https://www.bbc.com/news/articles/paypal-account-verify-scam-warning",
])
def test_news_about_scams_on_real_news_hosts_is_not_flagged_by_address_rules(url):
    r = rules(url)
    assert r.score < 30, (url, r.score, [(f.code, f.points) for f in r.flags if f.points])
