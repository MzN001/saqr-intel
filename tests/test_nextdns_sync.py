"""SAQR -> NextDNS denylist sync, against a fake NextDNS API. Run: pytest -q"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import json  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.config import settings  # noqa: E402
from saqr.db import db, iso  # noqa: E402
from saqr.intel import nextdns_sync as mod  # noqa: E402


class FakeNextDNS:
    def __init__(self, key="good-key", profile="abc123", existing=("owner-entry.com",)):
        self.key, self.profile = key, profile
        self.denylist = [{"id": d, "active": True} for d in existing]
        self.posts = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        if request.headers.get("X-Api-Key") != self.key:
            return httpx.Response(403, json={"errors": [{"code": "forbidden"}]})
        if request.url.path != f"/profiles/{self.profile}/denylist":
            return httpx.Response(404, json={"errors": [{"code": "notFound"}]})
        if request.method == "GET":
            return httpx.Response(200, json={"data": self.denylist})
        body = json.loads(request.content)
        self.posts.append(body["id"])
        self.denylist.append(body)
        return httpx.Response(200, json={})


@pytest.fixture
def fake(monkeypatch):
    server = FakeNextDNS()
    real_client = httpx.AsyncClient
    monkeypatch.setattr(mod.httpx, "AsyncClient",
                        lambda **kw: real_client(transport=httpx.MockTransport(server.handler), **kw))
    for k, v in {"nextdns_api_key": "good-key", "nextdns_profile_id": "abc123",
                 "nextdns_api_base": "https://api.nextdns.test"}.items():
        object.__setattr__(settings, k, v)  # settings is a frozen dataclass
    yield server
    for k in ("nextdns_api_key", "nextdns_profile_id"):
        object.__setattr__(settings, k, "")
    object.__setattr__(settings, "nextdns_api_base", "https://api.nextdns.io")


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def test_status_without_config(client):
    s = client.get("/api/nextdns-status").json()
    assert s["configured"] is False and "api_key" not in json.dumps(s).lower().replace("nextdns_api_key", "")


def test_sync_pushes_seeded_scams_not_ct_only_and_keeps_owner_entries(client, fake):
    async def go():
        await db.execute("INSERT INTO ct_events (domain, seen_at, score, entity, source) VALUES (?,?,?,?,?)",
                         ("tamm-ct-only-lookalike.xyz", iso(), 95, "TAMM Abu Dhabi", "simulated"))
        sync = mod.NextDNSSync()
        first = await sync.sync_once()
        second = await sync.sync_once()
        return sync, first, second

    sync, first, second = client.portal.call(go)
    assert {"tamm-smart-pay.net", "emiratespost-track-uae.com"} <= set(first)
    assert "tamm-ct-only-lookalike.xyz" not in fake.posts          # CT-only names need review first
    assert "adpolice.gov.ae" not in fake.posts                      # official sites never pushed
    assert second == []                                             # idempotent
    assert {"id": "owner-entry.com", "active": True} in fake.denylist  # owner's own entries untouched
    st = sync.status()
    assert st["configured"] and st["synced_domains"] >= 2 and st["android_dot_hostname"] == "abc123.dns.nextdns.io"
    assert "good-key" not in json.dumps(st)


def test_bad_key_reports_clear_error(client, fake):
    fake.key = "something-else"

    async def go():
        await mod.NextDNSSync().sync_once()

    with pytest.raises(RuntimeError, match="API key"):
        client.portal.call(go)
