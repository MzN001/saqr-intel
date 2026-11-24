"""/police Command Center API + two-way sync with /citizen. Run: pytest -q"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.police_state import campaign_id_for  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_state_is_populated_on_cold_boot(client):
    s = client.get("/api/police/state").json()
    assert set(s["kpis"]) == {"citizens_protected", "active_entities", "hijacked_pins", "x_alerts_dispatched",
                              "pre_victim_detections"}
    assert s["kpis"]["citizens_protected"] > 0 and s["kpis"]["hijacked_pins"] >= 1
    # Honest numbers: the demo baseline and the live part are reported separately and add up.
    assert s["demo_baseline"] == {"citizens_protected": 1284, "x_alerts_dispatched": 37}
    for k in ("citizens_protected", "x_alerts_dispatched"):
        assert s["live_counts"][k] >= 0
        assert s["kpis"][k] == s["demo_baseline"][k] + s["live_counts"][k]
    assert 1 <= len(s["recent_events"]) <= 25
    domains = {c["domain"] for c in s["campaigns"]}
    assert "tamm-smart-pay.net" in domains
    c = next(c for c in s["campaigns"] if c["domain"] == "tamm-smart-pay.net")
    assert c["defanged_domain"] == "tamm-smart-pay[.]net" and c["status"] == "ACTIVE" and c["hit_count"] >= 1
    pins = {p["title"]: p for p in s["map_pins"]}
    m37 = pins["Emirates Post Customer Center - Mussafah M-37"]
    assert (m37["lat"], m37["lng"], m37["type"]) == (24.3712, 54.5115, "SPOOFED")
    assert {p["type"] for p in s["map_pins"]} == {"SPOOFED", "VERIFIED"}


def test_citizen_scan_updates_kpis_stream_and_ws(client):
    before = client.get("/api/police/state").json()["kpis"]["citizens_protected"]
    with client.websocket_connect("/ws/live?topics=police") as ws:
        ws.receive_json()  # hello
        r = client.post("/api/analyze-url", json={"url": "http://127.0.0.1:8000/mock-scam/tamm-fine", "run_sandbox": False,
                                                  "interception_channel": "PC_BROWSER_EXTENSION"})
        assert r.json()["verdict"] != "SAFE"
        msg = ws.receive_json()
        assert msg["event"] == "police.event" and msg["data"]["channel"] == "PC_BROWSER_EXTENSION"
    s = client.get("/api/police/state").json()
    assert s["kpis"]["citizens_protected"] == before + 1
    assert s["live_counts"]["citizens_protected"] == s["kpis"]["citizens_protected"] - 1284 >= 1
    assert s["recent_events"][0]["channel"] == "PC_BROWSER_EXTENSION"


def test_safe_scan_does_not_count(client):
    before = client.get("/api/police/state").json()["kpis"]["citizens_protected"]
    client.post("/api/analyze-url", json={"url": "https://www.adpolice.gov.ae/", "run_sandbox": False})
    assert client.get("/api/police/state").json()["kpis"]["citizens_protected"] == before


def test_x_alert_from_citizen_flags_campaign(client):
    before = client.get("/api/police/state").json()["kpis"]["x_alerts_dispatched"]
    with client.websocket_connect("/ws/live?topics=police") as ws:
        ws.receive_json()
        r = client.post("/api/police/log-x-alert", json={"domain": "emiratespost-track-uae[.]com",
                                                         "impersonated_entity": "Emirates Post"})
        assert r.status_code == 200
        assert ws.receive_json()["event"] == "police.x_alert"
    s = client.get("/api/police/state").json()
    assert s["kpis"]["x_alerts_dispatched"] == before + 1
    assert s["live_counts"]["x_alerts_dispatched"] >= 1
    c = next(c for c in s["campaigns"] if c["domain"] == "emiratespost-track-uae.com")
    assert c["status"] == "COMMUNITY_FLAGGED_X" and "X_COMMUNITY_ALERT" in c["channels"]
    assert s["recent_events"][0]["channel"] == "X_COMMUNITY_ALERT"


def test_sync_telecom_publishes_rpz_and_outranks_x_flag(client):
    cid = campaign_id_for("emiratespost-track-uae.com")
    r = client.post("/api/police/sync-telecom", json={"campaign_id": cid, "domain": "emiratespost-track-uae.com"})
    assert r.json()["status"] == "SYNCED_TO_TELECOM_DNS"
    client.post("/api/police/log-x-alert", json={"domain": "emiratespost-track-uae.com"})
    c = next(c for c in client.get("/api/police/state").json()["campaigns"] if c["campaign_id"] == cid)
    assert c["status"] == "SYNCED_TO_TELECOM_DNS"
    rpz = client.get("/api/dns-blocklist?format=rpz").text
    assert "emiratespost-track-uae.com CNAME ." in rpz


def test_sync_telecom_refuses_official_and_own_sites(client):
    for d in ("adpolice.gov.ae", "saqr-intel.vercel.app", "127.0.0.1"):
        assert client.post("/api/police/sync-telecom", json={"domain": d}).status_code == 422


def test_official_warning_reaches_citizen(client):
    w = {"title_en": "Fake TAMM refund SMS", "title_ar": "رسائل استرداد مزيفة من تم",
         "message_en": "Do not open tamm-smart-pay.net.", "message_ar": "لا تفتح الرابط.", "domain": "tamm-smart-pay.net"}
    with client.websocket_connect("/ws/live?topics=police.warning") as ws:
        ws.receive_json()
        assert client.post("/api/police/broadcast-warning", json=w).status_code == 200
        msg = ws.receive_json()
        assert msg["event"] == "police.warning" and msg["data"]["verified"] is True
    latest = client.get("/api/police/warning/latest").json()["warning"]
    assert latest["title_en"] == w["title_en"] and latest["defanged_domain"] == "tamm-smart-pay[.]net"
    alert = client.get("/api/awareness-alert?use_llm=false").json()
    assert alert["official_police_warning"]["id"] == latest["id"]


def test_takedown_dossier_fields(client):
    cid = campaign_id_for("tamm-smart-pay.net")
    d = client.get(f"/api/police/takedown/{cid}").json()
    for k in ("aman_ref_id", "target_domain", "defanged_domain", "impersonated_entity", "ip_address", "asn",
              "registrar_abuse_email", "red_flags", "citizen_reports_count", "generated_at"):
        assert k in d, k
    assert d["target_domain"] == "tamm-smart-pay.net" and d["aman_ref_id"].startswith("AMAN-")
    assert d["red_flags"] and d["citizen_reports_count"] >= 1
    assert client.get("/api/police/takedown/CMP-NOPE0000").status_code == 404


def test_maps_scan_adds_live_pin(client):
    r = client.post("/api/scan-maps", json={"business_name": "Abu Dhabi Police – Traffic Fines Payment Center",
                                            "website": "adpolice-fines-ae.info", "phone": "+971500007781",
                                            "lat": 24.3489, "lng": 54.5052})
    assert r.json()["verdict"] != "SAFE"
    pins = client.get("/api/police/state").json()["map_pins"]
    assert any(p["type"] == "SPOOFED" and abs(p["lat"] - 24.3489) < 1e-6 for p in pins)


def test_event_ids_are_unique(client):
    ids = [e["id"] for e in client.get("/api/police/state").json()["recent_events"]]
    assert len(ids) == len(set(ids))
