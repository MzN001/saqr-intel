"""Phone DNS shield endpoints + CORS for the Vercel deployment. Run: pytest -q"""
import os
import plistlib
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _profile(client, query=""):
    r = client.get(f"/api/ios-dns-profile{query}")
    assert r.status_code == 200, r.text
    assert r.headers["content-type"].startswith("application/x-apple-aspen-config")
    assert 'filename="SAQR-INTEL-Shield.mobileconfig"' in r.headers["content-disposition"]
    return plistlib.loads(r.content)


def test_ios_profile_default_is_valid_plist(client):
    p = _profile(client)
    dns = p["PayloadContent"][0]
    assert p["PayloadType"] == "Configuration" and p["PayloadVersion"] == 1
    assert dns["PayloadType"] == "com.apple.dnsSettings.managed"
    assert dns["DNSSettings"] == {"DNSProtocol": "HTTPS", "ServerURL": "https://security.cloudflare-dns.com/dns-query"}
    for d in (p, dns):
        assert len(d["PayloadUUID"]) == 36 and d["PayloadIdentifier"]


def test_ios_profile_nextdns(client):
    p = _profile(client, "?nextdns_id=abc123")
    assert p["PayloadContent"][0]["DNSSettings"]["ServerURL"] == "https://dns.nextdns.io/abc123"


def test_ios_profile_is_stable(client):
    assert _profile(client)["PayloadUUID"] == _profile(client)["PayloadUUID"]


@pytest.mark.parametrize("query", [
    "?doh_url=https://evil.example/dns-query",
    "?doh_url=http://security.cloudflare-dns.com/dns-query",
    "?nextdns_id=abc<script>",
    "?nextdns_id=../../x",
])
def test_ios_profile_rejects_untrusted_dns(client, query):
    assert client.get(f"/api/ios-dns-profile{query}").status_code == 422


def test_android_config(client):
    assert client.get("/api/android-dns-config").json()["dot_hostname"] == "security.cloudflare-dns.com"
    assert client.get("/api/android-dns-config?nextdns_id=abc123").json()["dot_hostname"] == "abc123.dns.nextdns.io"
    assert client.get("/api/android-dns-config?nextdns_id=bad id").status_code == 422


@pytest.mark.parametrize("origin,allowed", [
    ("https://saqr-intel.vercel.app", True),
    ("https://saqr-intel-k39vj82aj-zubairnk22-4225.vercel.app", True),
    ("http://localhost:3000", True),
    ("https://someone-else.vercel.app", False),
])
def test_cors(client, origin, allowed):
    r = client.options("/api/analyze-url", headers={"Origin": origin, "Access-Control-Request-Method": "POST"})
    assert (r.headers.get("access-control-allow-origin") == origin) == allowed
