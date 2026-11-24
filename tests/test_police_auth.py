"""POLICE_API_KEY lock: police APIs refuse keyless callers, citizen features keep working. Run: pytest -q"""
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
from saqr.config import settings  # noqa: E402
from saqr.ws_hub import hub, public_view  # noqa: E402

KEY = "k"
GUARDED = ("/api/police/state", "/api/scans", "/api/hunter/status", "/api/awareness-alert?use_llm=false")
HDR = {"X-API-Key": KEY}

URL_SCAN = {"scan_id": "URL-AUTHTEST1", "kind": "url", "domain": "tamm-smart-pay.net", "verdict": "HIGH-RISK SCAM",
            "risk_score": 90, "impersonated_entity": "TAMM", "channel": "web", "created_at": "2026-11-24T00:00:00Z",
            "ip_addresses": ["203.0.113.9"], "harvested_fields": ["card_number"], "syndicate": {"name": "Sand Viper"},
            "interception_channel": "PC_BROWSER_EXTENSION"}
EMAIL_SCAN = {"scan_id": "EML-AUTHTEST1", "kind": "email", "target": "victim@example.com | Your refund",
              "risk_score": 80, "verdict": "HIGH-RISK SCAM", "top_flags": ["SCAM_LINK"], "created_at": "2026-11-24T00:00:00Z"}
MAPS_SCAN = {"scan_id": "MAP-AUTHTEST1", "kind": "maps", "verdict": "SUSPICIOUS", "risk_score": 60,
             "listing": {"website_domain": "adpolice-fines-ae.info"}, "syndicate": {"name": "Desert Mirage"}}


def _set_key(value: str) -> None:
    object.__setattr__(settings, "police_api_key", value)  # Settings is a frozen dataclass


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def key_set():
    old = settings.police_api_key
    _set_key(KEY)
    yield
    _set_key(old)


def _bcast(client, event, data):
    client.portal.call(hub.broadcast, event, data)


# ---------------------------------------------------------------------------- HTTP
@pytest.mark.parametrize("path", GUARDED)
def test_police_endpoints_need_key(client, key_set, path):
    assert client.get(path).status_code == 401
    assert client.get(path, headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get(path, headers=HDR).status_code == 200


def test_evidence_pack_needs_key(client, key_set):
    assert client.get("/api/dossiers/DOS-NOPE/evidence-pack").status_code == 401
    assert client.get("/api/dossiers/DOS-NOPE/evidence-pack", headers=HDR).status_code == 404


def test_citizen_endpoints_stay_open(client, key_set):
    assert client.get("/api/police/warning/latest").status_code == 200
    r = client.get("/api/public/awareness?hours=72")
    assert r.status_code == 200
    body = r.json()
    assert "status" in body and "official_police_warning" in body
    # same shape as the guarded alert
    guarded = client.get("/api/awareness-alert?use_llm=false&hours=72", headers=HDR).json()
    assert body["status"] == guarded["status"]


def test_key_unset_everything_open(client):
    assert not settings.police_api_key
    for path in GUARDED:
        assert client.get(path).status_code == 200, path
    with client.websocket_connect("/ws/live?topics=police,hunter") as ws:
        ws.receive_json()  # hello
        _bcast(client, "hunter.detection", {"domain": "x-unset.example"})
        assert ws.receive_json()["event"] == "hunter.detection"


# ---------------------------------------------------------------------------- WebSocket
def test_public_view_strips_police_fields():
    u = public_view("url_scan.completed", URL_SCAN)
    assert "ip_addresses" not in u and "syndicate" not in u
    assert u["harvested_fields"] == ["card_number"] and u["domain"] == "tamm-smart-pay.net"
    assert URL_SCAN["ip_addresses"]  # original untouched
    e = public_view("email_scan.completed", EMAIL_SCAN)
    assert e["target"] is None and e["top_flags"] == ["SCAM_LINK"]
    m = public_view("maps_scan.completed", MAPS_SCAN)
    assert "syndicate" not in m and m["listing"]["website_domain"] == "adpolice-fines-ae.info"
    assert public_view("police.warning", {"id": "W1"}) == {"id": "W1"}
    for ev in ("police.event", "hunter.detection", "citizen_report.received", "graph.updated", "police"):
        assert public_view(ev, {}) is None


def test_keyless_ws_gets_only_public_events(client, key_set):
    hub.recent.clear()
    _bcast(client, "hunter.detection", {"domain": "hunted.example"})
    _bcast(client, "police.event", {"id": "EV-1"})
    _bcast(client, "url_scan.completed", URL_SCAN)
    _bcast(client, "police.warning", {"id": "W-OLD"})
    with client.websocket_connect("/ws/live?topics=police,hunter") as ws:
        hello = ws.receive_json()
        assert hello["event"] == "hello"
        recent = hello["data"]["recent"]
        events = [m["event"] for m in recent]
        assert "police.event" not in events and not any(e.startswith("hunter.") for e in events)
        assert "police.warning" in events
        url = next(m for m in recent if m["event"] == "url_scan.completed")
        assert "ip_addresses" not in url["data"] and "syndicate" not in url["data"]

        _bcast(client, "hunter.detection", {"domain": "hunted2.example"})
        _bcast(client, "police.event", {"id": "EV-2"})
        _bcast(client, "police.proactive_detection", {"id": "EV-3"})
        _bcast(client, "police.warning", {"id": "W-NEW"})
        msg = ws.receive_json()
        assert msg["event"] == "police.warning" and msg["data"]["id"] == "W-NEW"

        _bcast(client, "url_scan.completed", URL_SCAN)
        msg = ws.receive_json()
        assert msg["event"] == "url_scan.completed"
        assert "ip_addresses" not in msg["data"] and msg["data"]["harvested_fields"] == ["card_number"]

        _bcast(client, "email_scan.completed", EMAIL_SCAN)
        msg = ws.receive_json()
        assert msg["event"] == "email_scan.completed" and msg["data"]["target"] is None

        # subscribe cannot widen to police topics either
        ws.send_json({"action": "subscribe", "topics": ["police", "hunter", "url_scan.completed"]})
        assert ws.receive_json()["data"]["topics"] == ["url_scan.completed"]
        _bcast(client, "police.warning", {"id": "W-3"})
        _bcast(client, "url_scan.completed", URL_SCAN)
        assert ws.receive_json()["event"] == "url_scan.completed"


def test_keyless_ws_hello_recent_is_topic_filtered(client, key_set):
    hub.recent.clear()
    _bcast(client, "police.warning", {"id": "W-1"})
    _bcast(client, "maps_scan.completed", MAPS_SCAN)
    with client.websocket_connect("/ws/live?topics=maps_scan") as ws:
        recent = ws.receive_json()["data"]["recent"]
        assert [m["event"] for m in recent] == ["maps_scan.completed"]
        assert "syndicate" not in recent[0]["data"]


@pytest.mark.parametrize("how", ["token", "header"])
def test_ws_with_key_gets_everything(client, key_set, how):
    hub.recent.clear()
    _bcast(client, "police.event", {"id": "EV-OLD"})
    url = "/ws/live?topics=police,hunter,url_scan" + ("&token=k" if how == "token" else "")
    kwargs = {} if how == "token" else {"headers": HDR}
    with client.websocket_connect(url, **kwargs) as ws:
        assert "police.event" in [m["event"] for m in ws.receive_json()["data"]["recent"]]
        _bcast(client, "hunter.detection", {"domain": "hunted3.example"})
        assert ws.receive_json()["event"] == "hunter.detection"
        _bcast(client, "url_scan.completed", URL_SCAN)
        msg = ws.receive_json()
        assert msg["data"]["ip_addresses"] == ["203.0.113.9"] and msg["data"]["syndicate"]["name"] == "Sand Viper"
