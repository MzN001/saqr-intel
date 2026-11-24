"""tools/evaluate.py live harness: resumable records, evidence capture, rescoring and the summary."""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import evaluate  # noqa: E402
from saqr import pipeline  # noqa: E402
from saqr.db import db  # noqa: E402


def _rec(url, score, *, feed=None, verdict=None, **kw):
    return {"url": url, "score": score, "verdict": verdict or ("HIGH-RISK SCAM" if score >= 65 else "SAFE"),
            "feed": feed, "feeds_in_scan": False, "ms": 1000, "reasons": [], **kw}


def test_summary_reports_both_feed_views_and_miss_categories():
    rows = [("https://a.test/", 1, "openphish_live"), ("https://b.test/", 1, "phishtank_2026-11-24"),
            ("https://c.test/", 0, "tranco_longtail"), ("https://d.test/", 1, "openphish_live")]
    recs = {
        "https://a.test/": _rec("https://a.test/", 70),
        "https://b.test/": _rec("https://b.test/", 0, feed="OpenPhish", dns_status="nxdomain",
                                evidence={"net": {"ip_addresses": []}}),
        "https://c.test/": _rec("https://c.test/", 10),
        "https://d.test/": _rec("https://d.test/", 0, verdict="TIMEOUT"),
    }
    s = evaluate.live_summary(rows, recs)
    assert s["no_feeds"]["block_65"]["recall"] == pytest.approx(1 / 3, abs=1e-3)
    assert s["with_feeds"]["block_65"]["recall"] == pytest.approx(2 / 3, abs=1e-3)
    assert s["no_feeds"]["warn_30"]["fpr"] == 0
    assert s["phishing_missed_at_warn_by_category"] == {"dead: no DNS": 1, "scan timeout / error": 1}
    assert s["feed_hits"] == {"phishing": 1, "legit": 0}
    assert s["errors"] == 1
    assert s["by_source"]["phishtank"]["rows"] == 1


def test_records_survive_unicode_line_separators(tmp_path):
    path = tmp_path / "r.jsonl"
    path.write_text(json.dumps(_rec("https://a.test/", 5, page_title="x\u2028y"), ensure_ascii=False) + "\n",
                    encoding="utf-8")
    assert evaluate.read_records(path)["https://a.test/"]["page_title"] == "x\u2028y"


def test_rescore_rejudges_saved_evidence_with_current_rules():
    page = {"evidence_source": "http_fallback", "http_status": 200, "final_url": "https://x-docs.github.io/",
            "page_title": "PayPal Login | Log in", "text": "Log in to your PayPal account",
            "html": '<form action="p.php"><input name="e"><input name="p" type="password"></form>',
            "cloaking": {"detected": False}}
    rec = _rec("https://x-docs.github.io/", 0, judged_url="https://x-docs.github.io/",
               evidence={"net": {}, "page": page})
    score, reasons = evaluate.rescore_record(rec)
    assert score >= 65
    assert any(r.startswith("BRAND_LOGIN_PAGE") for r in reasons)


def test_run_live_is_resumable_and_isolated(tmp_path, monkeypatch):
    calls = []

    async def fake_analyze(url, **kw):
        calls.append((url, kw))
        return {"risk_score": 80, "verdict": "HIGH-RISK SCAM", "normalized_url": url, "input_domain": "a.test",
                "domain": "a.test", "is_official_domain": False,
                "red_flags": [{"code": "AI_PHISHING_URL", "points": 45, "en": "x"}],
                "technical_indicators": {"redirect_chain": [], "sandbox_status": "ok", "http_status": 200,
                                         "page_title": "t", "harvested_fields": [], "dns_status": "ok"},
                "timings": {"total_ms": 5}, "analyzer": {"engine": "rules"}}

    async def nothing():
        return None

    monkeypatch.setenv("SAQR_EVAL_NO_FEED_SNAPSHOT", "1")
    monkeypatch.setattr(pipeline, "analyze_url", fake_analyze)
    monkeypatch.setattr(pipeline, "gather_network", pipeline.gather_network)
    monkeypatch.setattr(pipeline.sandbox, "inspect", pipeline.sandbox.inspect)
    monkeypatch.setattr(pipeline, "_eval_capture", False, raising=False)
    monkeypatch.setattr(db, "connect", nothing)
    monkeypatch.setattr(db, "close", nothing)
    out = tmp_path / "live.jsonl"
    first = evaluate.run_live(["https://a.test/", "https://b.test/"], records=str(out), progress=False)
    assert len(first) == 2 and len(calls) == 2
    assert all(kw["ingest"] is False and kw["run_sandbox"] is True and kw["use_llm"] is False for _, kw in calls)
    again = evaluate.run_live(["https://a.test/", "https://b.test/", "https://c.test/"], records=str(out),
                              progress=False)
    assert len(calls) == 3 and calls[-1][0] == "https://c.test/"
    assert again["https://a.test/"]["flags"] == ["AI_PHISHING_URL"]
    assert len(out.read_text(encoding="utf-8").strip().split("\n")) == 3


def test_live_timeout_is_recorded_not_raised(monkeypatch):
    import asyncio

    async def slow(url, **kw):
        await asyncio.sleep(5)

    monkeypatch.setattr(pipeline, "analyze_url", slow)
    rec = asyncio.run(evaluate.live_record("https://slow.test/", use_llm=False, timeout=0.05))
    assert rec["verdict"] == "TIMEOUT" and rec["score"] == 0.0
    assert evaluate.miss_category(rec) == "scan timeout / error"
