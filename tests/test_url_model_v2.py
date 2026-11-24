"""Phishing URL model v2: pure-Python inference, explanations, false-positive regressions, tools. Run: pytest -q"""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402

from saqr.intel import ai_inspector, url_features, url_model  # noqa: E402
from saqr.intel.ai_inspector import intel_flags, run_rules, url_model_result  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
VECTORS = json.loads((ROOT / "tests" / "fixtures" / "url_model_vectors.json").read_text(encoding="utf-8"))


def rules(url):
    return run_rules(analyze_lexical(url), {}, None, None)


@pytest.mark.parametrize("vec", VECTORS, ids=[v["url"][:40] for v in VECTORS])
def test_pure_python_inference_matches_training_side(vec):
    assert url_model.stage1_logit(vec["url"]) == pytest.approx(vec["stage1"], abs=1e-4)
    assert url_model.score_url(vec["url"])["probability"] == pytest.approx(vec["probability"], abs=1e-4)


def test_model_files_are_small_and_v1_api_still_works():
    size = url_model.MODEL_PATH.stat().st_size + (url_model.TREES_PATH.stat().st_size if url_model.TREES_PATH.exists() else 0)
    assert size < 5_000_000
    assert url_model.available()
    p = url_model.phishing_probability("microsoft-office365-signin-verify.web.app")
    assert 0.0 <= p <= 1.0 and p == url_model.phishing_probability("www.microsoft-office365-signin-verify.web.app")


def test_canonical_form_drops_collection_artefacts():
    a = url_model.score_url("https://www.example-shop.com/cart")["probability"]
    for v in ("http://example-shop.com/cart", "HTTPS://WWW.EXAMPLE-SHOP.COM:443/cart", "example-shop.com/cart#top"):
        assert url_model.score_url(v)["probability"] == pytest.approx(a, abs=1e-9), v


def test_scoring_is_fast():
    import time
    urls = [f"https://shop{i}-deals.example{i % 7}.com/p/{i}?ref=x" for i in range(300)]
    t = time.perf_counter()
    for u in urls:
        url_model.score_url(u)
    assert (time.perf_counter() - t) / len(urls) < 0.005


@pytest.mark.parametrize("url", [
    "https://www.adcb.com/en/personal/accounts/", "https://www.bankfab.com/en-ae/personal/cards/credit-cards",
    "https://www.tamm.abudhabi/en/life-events/individual/traffic-fines", "https://uaepass.ae/faq",
    "https://es.adpolice.gov.ae/TrafficServices/FinesPublic/Inquiry.aspx", "https://www.du.ae/self-care/login",
    "https://www.etisalat.ae/b2c/eshop/viewbill?locale=EN", "https://www.emiratesnbd.com/en/personal-banking",
    "https://smartservices.icp.gov.ae/echannels/web/client/default.html#/login",
    "https://www.paypal.com/signin", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b",
    "https://secure.chase.com/web/auth/dashboard", "https://www.hsbc.ae/online/", "https://www.amazon.ae/ap/signin",
    "https://www.dhl.com/ae-en/home/tracking.html", "https://www.aramex.com/ae/en/track/shipments",
    "https://www.dewa.gov.ae/en/consumer/billing/easy-pay", "https://www.wikipedia.org/wiki/Abu_Dhabi",
])
def test_uae_and_bank_deep_links_stay_safe(url):
    r = rules(url)
    assert r.verdict == "SAFE" and r.score < 30, (url, r.score, [(f.code, f.points) for f in r.flags if f.points])


@pytest.mark.parametrize("url", [
    "https://adcb-secure-login.xyz/verify/index.php?email=victim@mail.com",
    "https://paypal.com.secure-update-account.info/webscr?cmd=_login-submit",
    "http://tamm-traffic-fines-pay.top/ae/pay/card.php",
    "https://emiratespost-redelivery-fee.com/track/confirm",
    "https://appleid.apple.com.verify-session-locked.cfd/signin",
])
def test_obvious_phishing_is_high_risk(url):
    r = rules(url)
    assert r.verdict == "HIGH-RISK SCAM", (url, r.score, [(f.code, f.points) for f in r.flags if f.points])


@pytest.mark.parametrize("url", [
    "https://sites-7f3a2.web.app/microsoft/office365/login/verify.php?email=user@company.ae",
    "https://pub-3e8c1d2a9b.r2.dev/adcb/online-banking/secure/login.html",
])
def test_path_only_evidence_on_free_hosting_is_caught(url):
    res = url_model_result(analyze_lexical(url))
    assert res is not None and res["probability"] >= ai_inspector.ML_SUSPECT, res
    assert rules(url).verdict != "SAFE"


def test_ai_flag_names_human_readable_reasons():
    lex = analyze_lexical("https://adcb-secure-login.xyz/verify/index.php?email=victim@mail.com")
    flag = next(f for f in intel_flags(lex) if f.code in ("AI_PHISHING_URL", "AI_SUSPICIOUS_URL"))
    assert "Main reasons:" in flag.en and "أهم الأسباب" in flag.ar
    res = url_model.score_url(lex.normalized_url)
    assert 1 <= len(res["reasons"]) <= 3 and all(r["en"] and r["ar"] for r in res["reasons"])
    assert any("adcb" in r["en"].lower() or ".xyz" in r["en"] or "login" in r["en"] for r in res["reasons"])


def test_popular_and_official_sites_are_never_judged():
    for url in ("https://www.bbc.co.uk/news/world", "https://www.adcb.com/en/", "https://u.ae/en"):
        assert url_model_result(analyze_lexical(url)) is None, url


def test_features_brand_on_unrelated_domain():
    x, ctx = url_features.extract("https://paypal.com.secure-update.info/webscr")
    assert x[url_features.INDEX["brand_in_sub"]] == 1 and ctx["brand"] == "PayPal"
    x, ctx = url_features.extract("https://www.paypal.com/signin")
    assert x[url_features.INDEX["brand_official"]] == 1 and not x[url_features.INDEX["brand_in_sub"]]
    x, ctx = url_features.extract("https://xn--pypal-4ve.com/")
    assert x[url_features.INDEX["brand_sim"]] >= 0.99 and ctx["brand_near"] == "paypal"


def test_thresholds_come_from_measured_metrics():
    stored = json.loads(url_model.METRICS_PATH.read_text(encoding="utf-8"))
    assert ai_inspector.ML_STRONG == pytest.approx(stored["thresholds"]["strong"])
    assert ai_inspector.ML_SUSPECT < ai_inspector.ML_STRONG < ai_inspector.ML_CERTAIN < 1


def _run(script, *args, cwd=ROOT):
    return subprocess.run([sys.executable, str(ROOT / "tools" / script), *args], cwd=cwd, capture_output=True,
                          text=True, timeout=120)


def test_evaluate_and_predict_smoke(tmp_path):
    data = tmp_path / "tiny.csv"
    data.write_text("url,label\nhttps://www.adcb.com/en/personal/,0\nhttps://www.wikipedia.org/wiki/UAE,0\n"
                    "https://adcb-secure-login.xyz/verify/index.php,1\nhttp://tamm-traffic-fines-pay.top/ae/pay,1\n",
                    encoding="utf-8")
    out = tmp_path / "report.json"
    for mode in ("model", "system"):
        r = _run("evaluate.py", str(data), "--mode", mode, "--out", str(out))
        assert r.returncode == 0, r.stderr
        rep = json.loads(out.read_text(encoding="utf-8"))
        assert rep["rows"] == 4 and rep["phishing"] == 2 and "precision" in rep and "pr_points" in rep
        assert "confusion" in r.stdout and "worst false negatives" in r.stdout
    assert rep["fp"] == 0 and rep["tp"] == 2
    urls = tmp_path / "urls.txt"
    urls.write_text("https://www.adcb.com/en/\nadcb-secure-login.xyz/verify\n", encoding="utf-8")
    pred = tmp_path / "pred.csv"
    r = _run("predict.py", str(urls), "-o", str(pred))
    assert r.returncode == 0, r.stderr
    lines = pred.read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("url,label,score,verdict") and len(lines) == 3
    assert lines[1].split(",")[1] == "0" and lines[2].split(",")[1] == "1"


def test_model_metrics_endpoint():
    from fastapi.testclient import TestClient
    import main
    with TestClient(main.app) as c:
        r = c.get("/api/model/metrics")
    assert r.status_code == 200
    body = r.json()
    assert body["model"]["name"] and body["model"]["training_rows"] > 100_000
    assert body["holdout"]["rows"] > 1000 and body["fp_suite"]["rows"] > 1000 and body["datasets"]
