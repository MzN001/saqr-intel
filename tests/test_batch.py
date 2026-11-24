"""Pre-click shield API: POST /api/batch-verdict and POST /api/check-phone (offline)."""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.db import db, iso  # noqa: E402
from saqr.intel import maps_sentinel, redirects  # noqa: E402
from saqr.intel.registry import ENTITY_BY_ID  # noqa: E402
from saqr.routers import batch  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def verdicts(client, urls, **extra):
    r = client.post("/api/batch-verdict", json={"urls": urls, **extra})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["count"] == len(urls)
    return body["results"]


def counts(client):
    async def q():
        rows = []
        for table in ("scans", "graph_nodes", "graph_edges", "hunter_detections"):
            rows.append((await db.fetchone(f"SELECT COUNT(*) AS n FROM {table}"))["n"])
        return rows
    return client.portal.call(q)


def test_scam_official_and_unknown_sites(client):
    tamm, official, unknown, paypal, phish = verdicts(client, [
        "https://tamm-smart-pay.net/refund", "https://www.tamm.abudhabi/services", "https://www.wikipedia.org/",
        "https://www.paypal.com/signin", "https://paypal-login-verify.com/account"])
    assert tamm["verdict"] == "HIGH-RISK SCAM" and tamm["score"] >= 65
    assert tamm["entity"]["id"] == "tamm" and tamm["entity"]["official_phones_display"] == ["800 555"]
    assert tamm["official"] is False
    codes = [r["code"] for r in tamm["reasons"]]
    assert "BRAND_IMPERSONATION" in codes and "NEWLY_REGISTERED" in codes  # seeded intel, no network
    assert all(r["en"] and r["ar"] for r in tamm["reasons"])

    assert official["verdict"] == "SAFE" and official["official"] is True
    assert official["entity"]["id"] == "tamm" and official["reasons"][0]["code"] == "OFFICIAL_DOMAIN"

    # unknown-safe and foreign brands: no tick, no entity, no reasons (no noise next to results)
    for r in (unknown, paypal):
        assert r["verdict"] == "SAFE" and r["official"] is False and r["entity"] is None and r["reasons"] == []

    assert phish["verdict"] == "HIGH-RISK SCAM" and phish["entity"]["id"] == "paypal"


def test_redirect_wrappers_are_unwrapped_without_network(client, monkeypatch):
    calls = []
    monkeypatch.setattr(redirects, "TRANSPORT", httpx.MockTransport(lambda req: calls.append(req) or httpx.Response(500)))
    ad, wrapped_official, open_redirect, short = verdicts(client, [
        "https://www.google.com/url?q=https://tamm-smart-pay.net/pay&sa=U",
        "https://www.google.ae/url?q=https%3A%2F%2Fwww.adpolice.gov.ae%2Fen",
        "https://unknown-tracker.example/out?url=https://www.adpolice.gov.ae/",
        "https://bit.ly/3xYzAbC",
    ])
    assert ad["domain"] == "tamm-smart-pay.net" and ad["input_domain"] == "www.google.com"
    assert ad["redirected"] is True and ad["verdict"] == "HIGH-RISK SCAM"
    assert ad["reasons"][0]["code"] == "REDIRECTS_TO_FLAGGED"
    assert wrapped_official["domain"] == "www.adpolice.gov.ae" and wrapped_official["official"] is True
    # an unknown site in front of an official one never earns the green tick
    assert open_redirect["official"] is False
    assert short["unresolved_shortener"] is True and short["verdict"] == "SAFE"
    assert calls == []  # expand=false: never touches the network


def test_expand_follows_shorteners_on_a_budget(client, monkeypatch):
    async def guard(host):
        return True, []

    def handler(request):
        if request.url.host == "bit.ly":
            return httpx.Response(301, headers={"location": "https://tamm-refund-verify.xyz/pay"})
        return httpx.Response(200, headers={"content-type": "text/html"}, text="<html>hi</html>")

    monkeypatch.setattr(redirects, "TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(redirects, "host_is_safe_target", guard)
    [r] = verdicts(client, ["https://bit.ly/tamm-refund"], expand=True)
    assert r["domain"] == "tamm-refund-verify.xyz" and r["input_domain"] == "bit.ly"
    assert r["verdict"] != "SAFE" and r["redirected"] is True and r["unresolved_shortener"] is False
    assert r["entity"]["id"] == "tamm"


def test_mock_scam_demo_link_order_duplicates_and_bad_input(client):
    urls = ["http://127.0.0.1:8000/mock-scam/tamm-fine", "not a url at all ::", "javascript:alert(1)",
            "http://127.0.0.1:8000/mock-scam/tamm-fine"]
    first, bad, js, again = verdicts(client, urls)
    assert first["url"] == urls[0] and first["domain"] == "tamm-smart-pay.net"
    assert first["verdict"] == "HIGH-RISK SCAM" and again == first
    for r in (bad, js):
        assert r["verdict"] is None and r["error"] and r["reasons"] == []


def test_request_limits(client):
    assert client.post("/api/batch-verdict", json={"urls": []}).status_code == 422
    assert client.post("/api/batch-verdict", json={"urls": ["a.com"] * 201}).status_code == 422
    assert client.post("/api/batch-verdict", json={"urls": ["https://x.com/" + "a" * 2100]}).status_code == 422
    assert client.post("/api/batch-verdict", json={"urls": ["a.com"] * 200}).status_code == 200


def test_no_db_writes_or_graph_ingest(client):
    before = counts(client)
    verdicts(client, ["https://adcb-card-verify.xyz/", "https://fab-secure-update.top/x", "https://example.org/"])
    client.post("/api/check-phone", json={"phone": "+971 50 000 7781", "claimed_entity": "Emirates Post"})
    assert counts(client) == before


def test_known_verdicts_are_reused(client):
    """A site SAQR already rated in full (page content, sandbox) keeps that verdict on a search page,
    and a hunter detection is shown before any victim reports it."""
    async def seed():
        await db.save_scan({"scan_id": "SCN-20261124-BATCH1", "kind": "url", "target": "https://quiet-refund.example/",
                            "domain": "quiet-refund.example", "created_at": iso(), "risk_score": 80,
                            "verdict": "HIGH-RISK SCAM", "impersonated_entity": "TAMM Abu Dhabi"})
        await db.execute(
            "INSERT OR IGNORE INTO hunter_detections (domain, source, first_seen, score, verdict, entity, status) "
            "VALUES (?,?,?,?,?,?,?)", ("calm-portal.example", "crtsh", iso(), 72, "HIGH-RISK SCAM", "adpolice", "confirmed"))
        await db.save_scan({"scan_id": "SCN-20261124-BATCH2", "kind": "url", "target": "https://www.tamm.abudhabi/",
                            "domain": "www.tamm.abudhabi", "created_at": iso(), "risk_score": 40,
                            "verdict": "SUSPICIOUS"})
    async def cleanup():
        await db.execute("DELETE FROM scans WHERE id IN ('SCN-20261124-BATCH1', 'SCN-20261124-BATCH2')")
        await db.execute("DELETE FROM hunter_detections WHERE domain = 'calm-portal.example'")

    client.portal.call(seed)
    try:
        prior, hunted, demo, official = verdicts(client, [
            "https://quiet-refund.example/claim", "https://calm-portal.example/", "https://saqr-demo-scam.vercel.app/",
            "https://www.tamm.abudhabi/"])
    finally:  # the database is shared with the other test modules (blocklist, hunter)
        client.portal.call(cleanup)
        batch._cache.clear()
    assert prior["verdict"] == "HIGH-RISK SCAM" and prior["score"] == 80
    assert prior["reasons"][0]["code"] == "SAQR_PRIOR_SCAN" and prior["entity"]["id"] == "tamm"
    assert hunted["reasons"][0]["code"] == "PROACTIVE_DETECTION" and hunted["entity"]["id"] == "adpolice"
    assert demo["verdict"] == "HIGH-RISK SCAM" and demo["reasons"][0]["code"] == "CONFIRMED_SCAM_PAGE"
    assert official["verdict"] == "SAFE" and official["official"] is True  # official sites are never overridden


def test_fifty_urls_are_fast(client):
    urls = [f"https://shop-{i}-dealz{i % 7}.com/item/{i}" for i in range(45)] + [
        "https://tamm-smart-pay.net/", "https://www.google.com/url?q=https://adcb-card-verify.xyz/",
        "https://www.bankfab.com/", "https://emiratespost-track-uae.com/", "https://www.google.com/"]
    batch._cache.clear()  # cold: every host is analysed
    r = client.post("/api/batch-verdict", json={"urls": urls})
    assert r.status_code == 200 and r.json()["count"] == 50
    assert r.json()["elapsed_ms"] < 500, r.json()["elapsed_ms"]  # target 150 ms; generous for slow CI machines


def test_own_rate_bucket(client, monkeypatch):
    monkeypatch.setattr(batch.batch_limiter, "per_minute", 2)
    batch.batch_limiter.hits.clear()
    codes = [client.post("/api/batch-verdict", json={"urls": ["a.com"]}).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    # the citizen's URL-scan bucket is untouched
    assert client.post("/api/analyze-url", json={"url": "https://www.tamm.abudhabi/"}).status_code == 200
    batch.batch_limiter.hits.clear()


@pytest.mark.parametrize("phone,claim,context,status,level", [
    ("800555", "TAMM Service Center", None, "official", "official"),
    ("800 555", "مركز تم", "ad", "official", "official"),
    ("+971 50 123 4567", "TAMM Abu Dhabi", "maps", "mobile_for_institution", "danger"),
    ("02 444 4444", "TAMM Abu Dhabi", "ad", "unofficial", "danger"),
    ("02 444 4444", "TAMM Abu Dhabi", "maps", "unofficial", "caution"),
    ("+971 50 000 7781", "Emirates Post Parcel Collection", "maps", "mobile_for_institution", "danger"),
    ("+971 50 000 7781", None, None, "linked_to_scam", "danger"),
    ("8002626", None, None, "official", "official"),
    ("+971 4 555 1234", None, "panel", "unknown", "none"),
    ("+1 800 123 4567", "PayPal", "ad", "unknown", "none"),
])
def test_check_phone(client, phone, claim, context, status, level):
    r = client.post("/api/check-phone", json={"phone": phone, "claimed_entity": claim, "context": context})
    assert r.status_code == 200, r.text
    body = r.json()
    assert (body["status"], body["level"]) == (status, level), body
    if level == "danger":
        assert body["reasons"] and all(x["en"] and x["ar"] for x in body["reasons"])
    if status == "official":
        assert body["entity"]["id"] in {"tamm", "adpolice"}


def test_check_phone_explains_the_official_number(client):
    body = client.post("/api/check-phone", json={"phone": "+971 55 765 4321", "claimed_entity": "TAMM",
                                                 "context": "ad"}).json()
    assert body["entity"]["official_phones_display"] == ["800 555"]
    assert {"UNOFFICIAL_PHONE", "MOBILE_FOR_INSTITUTION"} <= {x["code"] for x in body["reasons"]}
    assert client.post("/api/check-phone", json={"phone": "ab"}).status_code == 422
    assert client.post("/api/check-phone", json={"phone": "abcd"}).status_code == 422


def test_phone_flags_shared_with_maps_sentinel():
    tamm = ENTITY_BY_ID["tamm"]
    assert maps_sentinel.phone_flags(tamm, "800 555") == []
    assert maps_sentinel.phone_flags(None, "0501234567") == []
    assert [f.code for f in maps_sentinel.phone_flags(tamm, "0501234567")] == ["UNOFFICIAL_PHONE", "MOBILE_FOR_INSTITUTION"]
    assert [f.code for f in maps_sentinel.phone_flags(ENTITY_BY_ID["etisalat"], "0501234567")] == ["UNOFFICIAL_PHONE"]


@pytest.mark.parametrize("raw,shown", [("800555", "800 555"), ("8002626", "800 2626"), ("600599999", "600 599 999"),
                                       ("999", "999"), ("+971500007781", "+971 50 000 7781"),
                                       ("024444444", "+971 2 444 4444")])
def test_format_phone(raw, shown):
    assert batch.format_phone(raw) == shown
