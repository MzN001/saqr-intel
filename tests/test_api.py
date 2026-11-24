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
        assert body["technical_indicators"]["ip_addresses"] == ["203.0.113.44"]
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


# --- Maps pin-hijack: messaging / link-in-bio "websites", personal and foreign numbers --------------
def scan_maps(client, **body):
    r = client.post("/api/scan-maps", json=body)
    assert r.status_code == 200, r.text
    out = r.json()
    out["codes"] = {f["code"] for f in out["red_flags"]}
    return out


@pytest.mark.parametrize("website", ["https://wa.me/971501112233", "api.whatsapp.com/send?phone=971501112233",
                                     "chat.whatsapp.com/AbCd", "t.me/emiratespost_help",
                                     "https://www.instagram.com/emiratespost.help", "bit.ly/ep-parcel",
                                     "forms.gle/xyz", "https://sites.google.com/view/emirates-post"])
def test_maps_institution_on_messaging_link_is_not_official(client, website):
    body = scan_maps(client, business_name="Emirates Post Customer Center", website=website)
    assert "INSTITUTION_MESSAGING_LINK" in body["codes"]
    assert "OFFICIAL_DOMAIN" not in body["codes"] and "UNOFFICIAL_DOMAIN_ON_LISTING" not in body["codes"]
    assert body["verdict"] == "SUSPICIOUS" and body["risk_score"] == 55
    assert body["verified_official"] is False
    assert "is official" not in body["citizen_explanation_en"]
    # the platform is never the scam site: no graph / blocklist / takedown target
    assert body["listing"]["website_domain"] is None and body["domain"] is None
    assert body["listing"]["website_host"]


def test_maps_tamm_centre_on_linktree(client):
    body = scan_maps(client, business_name="TAMM Service Centre", website="https://linktr.ee/tamm.services")
    assert "INSTITUTION_MESSAGING_LINK" in body["codes"] and body["verdict"] == "SUSPICIOUS"
    flag = next(f for f in body["red_flags"] if f["code"] == "INSTITUTION_MESSAGING_LINK")
    assert "linktr.ee" in flag["en"] and "tamm.abudhabi" in flag["en"] and flag["ar"]


def test_maps_messaging_link_plus_personal_mobile_is_high_risk(client):
    body = scan_maps(client, business_name="Emirates Post Parcel Desk", website="wa.me/971502223344",
                     phone="+971 50 222 3344")
    assert {"INSTITUTION_MESSAGING_LINK", "MOBILE_FOR_INSTITUTION"} <= body["codes"]
    assert body["verdict"] == "HIGH-RISK SCAM"


def test_maps_bank_branch_with_personal_mobile_only_is_suspicious(client):
    body = scan_maps(client, business_name="ADCB Branch Al Wahda", phone="+971 55 333 4455")
    assert {"UNOFFICIAL_PHONE", "MOBILE_FOR_INSTITUTION"} <= body["codes"]
    assert body["risk_score"] == 30 and body["verdict"] == "SUSPICIOUS"


@pytest.mark.parametrize("phone", ["+44 20 7946 0101", "+91 98765 40101"])
def test_maps_institution_with_foreign_number(client, phone):
    body = scan_maps(client, business_name="Abu Dhabi Police Service Desk", phone=phone)
    assert "FOREIGN_NUMBER_FOR_INSTITUTION" in body["codes"] and body["verdict"] != "SAFE"


def test_maps_bank_with_foreign_number_is_not_foreign_flagged(client):
    # same scoping as /api/check-phone: a UAE bank can have real numbers abroad
    body = scan_maps(client, business_name="ADCB Head Office", phone="+44 20 7946 0202")
    assert "FOREIGN_NUMBER_FOR_INSTITUTION" not in body["codes"] and body["verdict"] == "SAFE"


@pytest.mark.parametrize("phone", ["+971 800 555", "800555", "00971 800 555"])
def test_maps_official_tamm_listing_is_verified(client, phone):
    body = scan_maps(client, business_name="TAMM Service Center", website="https://www.tamm.abudhabi/", phone=phone)
    assert body["verdict"] == "SAFE" and body["verified_official"] is True
    assert not body["codes"] - {"OFFICIAL_DOMAIN"}


def test_maps_official_site_with_contradicting_mobile_is_not_verified(client):
    body = scan_maps(client, business_name="TAMM Service Center", website="tamm.abudhabi", phone="+971 50 444 5566")
    assert body["verified_official"] is False and body["verdict"] != "SAFE"


@pytest.mark.parametrize("name,website,phone", [
    ("Al Fanar Restaurant & Cafe", "https://wa.me/971505556677", "+971 50 555 6677"),
    ("Bella Ladies Salon", "https://www.instagram.com/bella.salon.ad", "+971 56 555 7788"),
    ("Karak House Cafeteria", "linktr.ee/karakhouse", "055 555 8899"),
    ("Desert Rose Flowers", "https://api.whatsapp.com/send?phone=971585559900", "+971 58 555 9900"),
])
def test_maps_ordinary_business_with_whatsapp_and_mobile_is_safe(client, name, website, phone):
    body = scan_maps(client, business_name=name, website=website, phone=phone)
    assert body["verdict"] == "SAFE" and body["risk_score"] == 0 and body["red_flags"] == []
    assert body["impersonated_entity"] is None and body["verified_official"] is False


def test_maps_real_gov_ae_listing_is_safe(client):
    body = scan_maps(client, business_name="Department of Municipalities and Transport",
                     website="https://www.dmt.gov.ae/")
    assert body["verdict"] == "SAFE" and body["red_flags"] == [] and body["verified_official"] is True


def test_maps_seeded_pins_unchanged(client):
    for pin in ("Abu Dhabi Police Traffic Fines Payment Center", "Emirates Post Parcel Collection Mussafah",
                "TAMM Smart Payment Kiosk"):
        body = scan_maps(client, business_name=pin)
        assert body["verdict"] == "HIGH-RISK SCAM" and body["verified_official"] is False
        assert "UNOFFICIAL_DOMAIN_ON_LISTING" in body["codes"] and body["listing"]["website_domain"]


def test_platform_kind():
    from saqr.intel.maps_sentinel import platform_kind
    assert platform_kind("wa.me") == platform_kind("api.whatsapp.com") == "messaging"
    assert platform_kind("www.linktr.ee") == platform_kind("m.facebook.com") == "social"
    assert platform_kind("bit.ly") == "shortener"
    assert platform_kind("docs.google.com", "/forms/d/e/x") == platform_kind("sites.google.com") == "builder"
    assert platform_kind("docs.google.com", "/document/d/x") is None
    for host in ("tamm.abudhabi", "adcb.com", "dmt.gov.ae", "alfanar-restaurant.ae"):
        assert platform_kind(host) is None
