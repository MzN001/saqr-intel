"""POST /api/analyze-email end to end (TestClient, offline): verdicts, contract shape, WebSocket events,
privacy (no sender domain in the DNS blocklist, no API key or raw reporter id stored), limits and
graceful degradation. Run: pytest -q tests/test_email_api.py
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"  # no WHOIS/DNS/LLM calls in CI
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import base64  # noqa: E402
import json  # noqa: E402
import sqlite3  # noqa: E402
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

import sys  # noqa: E402

from saqr.intel import user_llm  # noqa: E402
from saqr.security import RateLimiter  # noqa: E402

CONTRACT_REQ = json.loads((FIX / "contract" / "analyze_email_request.json").read_text(encoding="utf-8"))
CONTRACT_RES = json.loads((FIX / "contract" / "analyze_email_response.json").read_text(encoding="utf-8"))
SECRET = CONTRACT_REQ["llm"]["api_key"]


def db_dump() -> str:
    """Every row of the scans table as text (the raw SQLite file, as an analyst would see it)."""
    con = sqlite3.connect(os.environ["DATABASE_PATH"])
    try:
        return json.dumps(con.execute("SELECT * FROM scans").fetchall(), ensure_ascii=False, default=str)
    finally:
        con.close()


@pytest.mark.parametrize("name,expect", [
    ("phish_paypal_cyrillic.eml", "HIGH-RISK SCAM"),
    ("phish_punycode_sender.eml", "HIGH-RISK SCAM"),
    ("phish_bidi_attachment.eml", "HIGH-RISK SCAM"),
])
def test_phishing_fixtures(client, name, expect):
    res = scan(client, source="eml", file_base64=b64(name), file_name=name)
    assert res["verdict"] == expect, (res["risk_score"], codes(res))
    assert res["kind"] == "email" and res["domain"] is None and res["scan_id"].startswith("EML-")
    assert res["citizen_explanation_en"] and res["citizen_explanation_ar"]


def test_fixture_flags(client):
    pp = scan(client, source="eml", file_base64=b64("phish_paypal_cyrillic.eml"))
    assert {"DISPLAY_NAME_CONFUSABLE", "FREEMAIL_BRAND_SENDER", "LINK_TEXT_MISMATCH"} <= codes(pp)
    assert pp["impersonated_entity"] == "PayPal" and "paypal.com" in pp["official_domains"]
    link = next(l for l in pp["links"] if l["domain"] == "paypal-account-review.test")
    assert link["unwrapped_from"].startswith("https://www.google.com/url") and link["text_mismatch"] and link["scan_id"]
    pu = scan(client, source="eml", file_base64=b64("phish_punycode_sender.eml"))
    assert {"IDN_MIXED_SCRIPT", "SENDER_LOOKALIKE", "REPLY_TO_FREEMAIL_BRAND"} <= codes(pu)
    assert pu["email"]["from"]["unicode_domain"] == "аdcb-secure.test"
    bi = scan(client, source="eml", file_base64=b64("phish_bidi_attachment.eml"))
    assert {"BIDI_OVERRIDE", "DANGEROUS_ATTACHMENT"} <= codes(bi) and bi["attachments"][0]["risky"]


def test_forged_auth_results_from_official_domain_is_not_safe(client):
    if not (EMAILS / "auth_spoofed_results.eml").exists():
        pytest.skip("fixture not present")
    res = scan(client, source="eml", file_base64=b64("auth_spoofed_results.eml"), follow_links=False)
    assert res["verdict"] != "SAFE", (res["risk_score"], codes(res, False))
    assert "OFFICIAL_SENDER_UNAUTHENTICATED" in codes(res)


def test_outlook_msg_file(client):
    name = "msg_outlook_spoof_tamm.msg"
    if not (EMAILS / name).exists():
        pytest.skip("fixture not present")
    res = scan(client, source="msg", file_base64=b64(name), file_name=name)
    assert res["source"] == "msg" and res["verdict"] != "SAFE", (res["risk_score"], codes(res, False))


def test_websocket_events(client):
    with client.websocket_connect("/ws/live") as ws:
        assert ws.receive_json()["event"] == "hello"
        res = scan(client, source="eml", file_base64=b64("phish_bidi_attachment.eml"))
        first = ws.receive_json()
        assert first["event"] == "citizen_report.received" and first["data"]["kind"] == "email"
        assert first["data"]["scan_id"] == res["scan_id"]
        done = ws.receive_json()
        assert done["event"] == "email_scan.completed"
        d = done["data"]
        assert set(d) == {"scan_id", "kind", "target", "risk_score", "verdict", "channel", "interception_channel",
                          "impersonated_entity", "created_at", "top_flags"}
        assert d["verdict"] == "HIGH-RISK SCAM" and "BIDI_OVERRIDE" in d["top_flags"]


def test_contract_shape(client):
    req = {k: v for k, v in CONTRACT_REQ.items() if k != "llm"}
    res = scan(client, **req)
    assert set(CONTRACT_RES) <= set(res), set(CONTRACT_RES) - set(res)
    for block in ("email", "authentication", "analyzer", "user_model"):
        assert set(CONTRACT_RES[block]) <= set(res[block]), block
    assert set(CONTRACT_RES["email"]["from"]) <= set(res["email"]["from"])
    assert set(CONTRACT_RES["red_flags"][0]) <= set(res["red_flags"][0])
    assert set(CONTRACT_RES["links"][0]) <= set(res["links"][0])
    assert res["interception_channel"] == "PC_BROWSER_EXTENSION" and res["source"] == "raw"
    assert res["model_features"] == sorted(set(res["model_features"])) and res["model_features"]
    assert res["user_model"]["spec"] == "email-v1"
    assert len(res["email"]["body_excerpt"]) <= 500


def test_sender_domain_never_in_dns_blocklist(client):
    pp = scan(client, source="eml", file_base64=b64("phish_paypal_cyrillic.eml"))
    bi = scan(client, source="eml", file_base64=b64("phish_bidi_attachment.eml"))
    assert pp["verdict"] == bi["verdict"] == "HIGH-RISK SCAM"
    published = {e["domain"] for e in client.get("/api/dns-blocklist?min_score=0").json()["domains"]}
    assert "gmail.com" not in published and "ep-invoices.test" not in published
    assert "paypal-account-review.test" in published  # the scam LINK is published (its own URL scan)
    con = sqlite3.connect(os.environ["DATABASE_PATH"])
    try:
        rows = con.execute("SELECT domain FROM scans WHERE kind='email'").fetchall()
    finally:
        con.close()
    assert rows and all(r[0] is None for r in rows)


def test_api_key_never_returned_or_stored(client, monkeypatch):
    seen = {}

    async def fake_judge(cfg, evidence):
        seen["cfg_key"] = cfg["api_key"]
        seen["evidence"] = json.dumps(evidence, ensure_ascii=False)
        return ({"risk_score": 95, "verdict": "HIGH-RISK SCAM", "impersonated_entity": "PayPal",
                 "citizen_explanation_en": "Scam.", "citizen_explanation_ar": "احتيال.",
                 "key_red_flags": ["fake PayPal"], "confidence": 0.95}, "user:example-mini", None)

    monkeypatch.setattr(user_llm, "judge", fake_judge)
    r = client.post("/api/analyze-email", json=CONTRACT_REQ)
    assert r.status_code == 200, r.text
    body = r.json()
    assert seen["cfg_key"] == SECRET                      # it did reach the user's model ...
    assert SECRET not in seen["evidence"]                 # ... but never as evidence
    assert "untrusted_email" in seen["evidence"]
    assert SECRET not in r.text and SECRET not in db_dump()
    assert body["analyzer"]["engine"] == "user:example-mini" and body["analyzer"]["user_llm_host"] == "llm.example.com"
    assert body["analyzer"]["confidence"] == 0.95 and body["llm_red_flags"] == ["fake PayPal"]
    assert body["risk_score"] >= 65


def test_invalid_request_errors_never_echo_the_key(client):
    long_key = "sk-" + "Z" * 700
    r = client.post("/api/analyze-email", json={"source": "text", "text": "hi", "llm": {"api_key": long_key}})
    assert r.status_code == 422 and "ZZZZ" not in r.text
    r = client.post("/api/analyze-email", json={"source": "bogus", "text": "x", "llm": {"api_key": SECRET}})
    assert r.status_code == 422 and SECRET not in r.text


def test_user_llm_error_reported_offline(client):
    res = scan(client, **{**CONTRACT_REQ, "use_llm": True, "follow_links": False})
    assert res["analyzer"]["engine"] == "rules" and res["analyzer"]["user_llm_error"]
    assert SECRET not in json.dumps(res)


def test_reporter_id_is_stored_only_as_key(client):
    rid = "r-test-reporter-0123456789abcdef"
    res = scan(client, source="eml", file_base64=b64("phish_paypal_cyrillic.eml"), reporter_id=rid)
    dump = db_dump()
    assert rid not in dump and rid not in json.dumps(res)
    from saqr.intel.user_model import reporter_key
    con = sqlite3.connect(os.environ["DATABASE_PATH"])
    try:
        row = con.execute("SELECT reporter FROM scans WHERE id=?", (res["scan_id"],)).fetchone()
    finally:
        con.close()
    assert row[0] == reporter_key(rid)


def test_saved_scan_keeps_only_body_excerpt(client):
    marker = "UNIQUE-TAIL-MARKER-7731"
    body = "Hello,\n" + ("filler text. " * 200) + marker
    res = scan(client, source="text", text=f"From: a@example.com\nSubject: long\n\n{body}")
    stored = client.get(f"/api/scans/{res['scan_id']}").json()
    assert marker not in json.dumps(stored) and len(stored["email"]["body_excerpt"]) <= 500
    assert stored["model_features"] == res["model_features"] and stored["email"]["from"]["address"] == "a@example.com"
    assert "llm" not in stored
    listed = client.get("/api/scans?kind=email").json()["scans"]
    assert any(s["scan_id"] == res["scan_id"] for s in listed)


def test_follow_links_false_scans_nothing(client):
    res = scan(client, source="eml", file_base64=b64("phish_paypal_cyrillic.eml"), follow_links=False)
    assert res["links"] and all(l["scan_id"] is None for l in res["links"])
    assert "LINK_TEXT_MISMATCH" in codes(res)


def test_meta_only_capture(client):
    meta = {k: v for k, v in CONTRACT_REQ["meta"].items()}
    res = scan(client, source="text", meta=meta, follow_links=False)
    assert res["verdict"] == "HIGH-RISK SCAM" and not res["email"]["has_headers"]
    assert "HEADERS_NOT_AVAILABLE" in codes(res, False)


def test_limits_and_bad_input(client):
    assert client.post("/api/analyze-email", json={"source": "text"}).status_code == 422
    big = b'{"source":"text","text":"' + b"a" * (4 * 1024 * 1024 + 10) + b'"}'
    r = client.post("/api/analyze-email", content=big, headers={"content-type": "application/json"})
    assert r.status_code == 413
    r = client.post("/api/analyze-email", json={"source": "eml", "file_base64": base64.b64encode(b"just words").decode()})
    assert r.status_code in (200, 422)
    r = client.post("/api/analyze-email", json={"source": "eml", "meta": None, "text": None, "file_base64": None})
    assert r.status_code == 422


def test_own_rate_limit_bucket():
    import asyncio

    from fastapi import HTTPException
    from starlette.requests import Request

    dep = email_router.rate_limit_bucket(RateLimiter(1))
    req = Request({"type": "http", "client": ("10.0.0.9", 1), "headers": []})
    asyncio.run(dep(req))
    with pytest.raises(HTTPException) as e:
        asyncio.run(dep(req))
    assert e.value.status_code == 429
    assert email_router.email_limiter is not __import__("saqr.security", fromlist=["_limiter"])._limiter


def test_degrades_when_a_sibling_fails(client, monkeypatch):
    from saqr.intel import campaigns

    def boom(_input):
        raise RuntimeError("feed down")

    monkeypatch.setattr(campaigns.campaign_feed, "match", boom)
    res = scan(client, source="eml", file_base64=b64("phish_bidi_attachment.eml"))
    assert res["verdict"] == "HIGH-RISK SCAM" and "campaigns_error" in res["analyzer"]["notes"]


def test_parser_missing_gives_503(client, monkeypatch):
    monkeypatch.setitem(sys.modules, "saqr.intel.email_parse", None)
    import saqr.intel as pkg
    monkeypatch.delattr(pkg, "email_parse", raising=False)
    r = client.post("/api/analyze-email", json={"source": "text", "text": "hello", "use_llm": False})
    assert r.status_code == 503
