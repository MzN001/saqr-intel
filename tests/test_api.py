"""End-to-end smoke tests. Run: pytest -q"""
import os
import tempfile

os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(), "test.db")
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"  # no WHOIS/DNS/LLM calls in CI
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_health(client):
    assert client.get("/health").json()["status"] == "ok"


@pytest.mark.parametrize("domain,expect_scam", [
    ("adpolice-fines-ae.info", True), ("tamm-smart-pay.net", True), ("xn--tmm-6cd.abudhabi", True),
    ("tamm.abudhabi", False), ("www.adpolice.gov.ae", False), ("dubai-dental.com", False), ("tammy-salon.com", False),
])
def test_lexical(domain, expect_scam):
    r = analyze_lexical(domain)
    assert (r.score >= 30) == expect_scam, (domain, r.score, [f.code for f in r.flags])


def test_analyze_seeded_scam_broadcasts(client):
    with client.websocket_connect("/ws/live") as ws:
        assert ws.receive_json()["event"] == "hello"
        r = client.post("/api/analyze-url", json={
            "message_text": "TAMM: Refund AED 340 pending. Claim: hxxps://tamm-smart-pay[.]net/refund", "channel": "sms"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["verdict"] == "HIGH-RISK SCAM"
        assert body["impersonated_entity"] == "TAMM Abu Dhabi"
        assert body["citizen_explanation_ar"] and body["citizen_explanation_en"]
        assert "OTP" in body["technical_indicators"]["harvested_fields"]
        assert body["technical_indicators"]["ip_addresses"] == ["185.220.101.44"]
        assert body["syndicate"]["id"] == "SYN-SANDVIPER"
        events = [ws.receive_json()["event"] for _ in range(3)]
        assert events[0] == "citizen_report.received"
        assert "url_scan.completed" in events


def test_official_domain_safe(client):
    body = client.post("/api/analyze-url", json={"url": "https://www.tamm.abudhabi/"}).json()
    assert body["verdict"] == "SAFE" and body["is_official_domain"]


def test_maps_geospoof(client):
    r = client.post("/api/scan-maps", json={
        "maps_url": "https://www.google.com/maps/place/Abu+Dhabi+Police+Traffic+Fines+Payment+Center/@24.3489,54.5052,17z"})
    assert r.status_code == 200, r.text
    body = r.json()
    codes = {f["code"] for f in body["red_flags"]}
    assert body["verdict"] == "HIGH-RISK SCAM"
    assert {"UNOFFICIAL_DOMAIN_ON_LISTING", "PHONE_REUSED_ACROSS_PINS"} <= codes


def test_maps_new_pin_joins_syndicate(client):
    body = client.post("/api/scan-maps", json={
        "business_name": "Emirates Post Express Counter", "website": "emiratespost-delivery-fee.online",
        "phone": "+971 50 000 7781", "lat": 24.36, "lng": 54.51}).json()
    assert body["verdict"] == "HIGH-RISK SCAM"
    assert body["syndicate"]["id"] == "SYN-SANDVIPER"


def test_graph(client):
    g = client.get("/api/syndicate-graph").json()
    types = {n["type"] for n in g["nodes"]}
    assert {"domain", "map_pin", "ip_address", "phone_number", "citizen_report"} <= types
    names = {s["name"] for s in g["syndicates"]}
    assert "Sand Viper Syndicate" in names and "Desert Mirage Crew" in names
    sv = next(s for s in g["syndicates"] if s["id"] == "SYN-SANDVIPER")
    assert {"adpolice-fines-ae.info", "emiratespost-track-uae.com", "tamm-smart-pay.net"} <= set(sv["domains"])


def test_takedown_and_awareness(client):
    scans = client.get("/api/scans?kind=url").json()["scans"]
    scam = next(s for s in scans if s["verdict"] == "HIGH-RISK SCAM")
    d = client.post(f"/api/generate-takedown/{scam['scan_id']}").json()
    assert d["case_reference"].startswith("ADP-CYB-") and d["notices"]["registrar_abuse"]
    md = client.post(f"/api/generate-takedown/{scam['scan_id']}?format=markdown")
    assert md.text.startswith("# TAKEDOWN DOSSIER")
    a = client.get("/api/awareness-alert").json()
    assert a["status"] == "active_wave" and a["post_ar"] and a["post_en"]


def test_ssrf_guard(client):
    body = client.post("/api/analyze-url", json={"url": "http://127.0.0.1:8000/health"}).json()
    assert body["technical_indicators"]["sandbox_status"] in {"blocked", "skipped_offline"}


def test_ct_stream(client):
    j = client.get("/api/ct-stream").json()
    assert j["detections"]
