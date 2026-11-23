"""Telecom RPZ feed + DIRECT_API default channel. Run: pytest -q"""
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
from saqr.routers.blocklist import _publishable  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_mock_scam_pages_have_card_and_otp_fields(client):
    for slug in ("tamm-fine", "emiratespost"):
        html = client.get(f"/mock-scam/{slug}").text
        assert 'name="otp"' in html and 'name="card_number"' in html and "data-original-action" in html


def test_default_channel_is_direct_api(client):
    with client.websocket_connect("/ws/live?topics=url_scan") as ws:
        ws.receive_json()  # hello
        client.post("/api/analyze-url", json={"url": "http://127.0.0.1:8000/mock-scam/tamm-fine", "run_sandbox": False})
        msg = ws.receive_json()
        assert msg["event"] == "url_scan.completed"
        assert msg["data"]["interception_channel"] == "DIRECT_API"


def test_blocklist_json_and_rpz(client):
    j = client.get("/api/dns-blocklist").json()
    names = {d["domain"] for d in j["domains"]}
    assert {"tamm-smart-pay.net", "emiratespost-track-uae.com"} <= names
    assert j["count"] == len(j["domains"]) and "CNAME ." in j["rpz"]
    r = client.get("/api/dns-blocklist?format=rpz")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    assert "tamm-smart-pay.net CNAME ." in r.text and "*.tamm-smart-pay.net CNAME ." in r.text
    assert "$TTL" in r.text and " SOA " in r.text


@pytest.mark.parametrize("domain", [
    "adpolice.gov.ae", "www.tamm.abudhabi", "u.ae", "emirates.com",   # official / trusted
    "vercel.app", "onrender.com", "127.0.0.1", "localhost", "printer.local", "bad domain.com", "x.com\nevil CNAME .", None,
])
def test_never_published(domain):
    assert _publishable(domain) is None


def test_published_domain_normalised():
    assert _publishable("WWW.Tamm-Smart-Pay.NET.") == "tamm-smart-pay.net"
    assert _publishable("saqr-demo-scam.vercel.app") == "saqr-demo-scam.vercel.app"


def test_keepalive_only_on_render(monkeypatch):
    from saqr import keepalive

    monkeypatch.delenv("RENDER_EXTERNAL_URL", raising=False)
    monkeypatch.delenv("KEEP_AWAKE_URL", raising=False)
    assert keepalive.public_url() is None
    monkeypatch.setenv("RENDER_EXTERNAL_URL", "https://saqr-intel-api.onrender.com/")
    assert keepalive.public_url() == "https://saqr-intel-api.onrender.com"
    monkeypatch.setenv("KEEP_AWAKE", "false")
    assert keepalive.public_url() is None


def test_demo_scam_page_always_flagged(client):
    names = {d["domain"]: d for d in client.get("/api/dns-blocklist").json()["domains"]}
    assert names["saqr-demo-scam.vercel.app"]["impersonated_entity"] == "TAMM Abu Dhabi"
    assert "vercel.app" not in names
