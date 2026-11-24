"""Scam-alert push notifications + NextDNS block watcher. Run: pytest -q"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import base64  # noqa: E402
import json  # noqa: E402

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr import push  # noqa: E402
from saqr.intel.nextdns_sync import BlockWatcher  # noqa: E402

SUB = {"endpoint": "https://web.push.apple.com/QK-test-endpoint", "keys": {"p256dh": "BPkey", "auth": "authkey"}}


class FakeResponse:
    def __init__(self, status):
        self.status_code = status


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture
def sent(monkeypatch):
    calls = []

    def fake_send(sub, payload, *_):
        calls.append((sub["endpoint"], payload))
        return 201

    monkeypatch.setattr(push, "_send_sync", fake_send)
    return calls


def test_vapid_public_key_is_p256_point(client):
    key = client.get("/api/push/vapid-public-key").json()["publicKey"]
    raw = base64.urlsafe_b64decode(key + "=" * (-len(key) % 4))
    assert len(raw) == 65 and raw[0] == 4


def test_subscribe_test_unsubscribe(client, sent):
    assert client.post("/api/push/subscribe", json={"subscription": SUB, "lang": "ar"}).json()["ok"]
    r = client.post("/api/push/test", json={"endpoint": SUB["endpoint"]})
    assert r.status_code == 200
    endpoint, payload = sent[-1]
    assert endpoint == SUB["endpoint"] and payload["lang"] == "ar" and "[.]" in payload["body"]
    assert payload["url"] == "/citizen?alert=tamm-smart-pay.net"
    assert client.post("/api/push/unsubscribe", json={"endpoint": SUB["endpoint"]}).json()["ok"]
    assert client.post("/api/push/test", json={"endpoint": SUB["endpoint"]}).status_code == 404


def test_subscribe_rejects_non_https_endpoint(client):
    bad = {**SUB, "endpoint": "http://evil.example/push"}
    assert client.post("/api/push/subscribe", json={"subscription": bad}).status_code == 422


def test_expired_subscription_is_removed(client, monkeypatch):
    from pywebpush import WebPushException

    def gone(sub, payload, *_):
        raise WebPushException("gone", response=FakeResponse(410))

    monkeypatch.setattr(push, "_send_sync", gone)
    client.post("/api/push/subscribe", json={"subscription": SUB})
    assert client.post("/api/push/test", json={"endpoint": SUB["endpoint"]}).status_code == 502
    assert client.post("/api/push/test", json={"endpoint": SUB["endpoint"]}).status_code == 404  # deleted


def test_stale_connection_is_retried_fresh(client, monkeypatch):
    import requests

    attempts = []

    def flaky(sub, payload, session):
        attempts.append(session)
        if len(attempts) == 1:
            raise requests.exceptions.ReadTimeout("stale connection")
        return 201

    monkeypatch.setattr(push, "_send_sync", flaky)
    client.post("/api/push/subscribe", json={"subscription": SUB})
    assert client.post("/api/push/test", json={"endpoint": SUB["endpoint"]}).status_code == 200
    assert len(attempts) == 2 and attempts[0] is not attempts[1]  # second try used a new session


def test_alert_verdict_for_flagged_domain(client):
    client.post("/api/analyze-url", json={"url": "http://127.0.0.1:8000/mock-scam/tamm-fine", "run_sandbox": False})
    v = client.get("/api/alerts/verdict?domain=tamm-smart-pay.net").json()
    assert v["verdict"] == "HIGH-RISK SCAM" and "screenshot_base64" not in v
    assert client.get("/api/alerts/verdict?domain=example.org").status_code == 404


def test_live_stream_alerts_instantly(client, sent):
    client.post("/api/push/subscribe", json={"subscription": SUB, "lang": "en"})
    body = (
        'data: {"timestamp":"2026-11-22T11:00:00Z","domain":"ads.example","status":"blocked"}\n\n'
        'data: {"timestamp":"2026-11-22T11:00:01Z","domain":"emiratespost-track-uae.com","status":"default"}\n\n'
        'id: abc\ndata: {"timestamp":"2026-11-22T11:00:02Z","domain":"emiratespost-track-uae.com","status":"blocked"}\n\n'
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/logs/stream")
        return httpx.Response(200, text=body, headers={"content-type": "text/event-stream"})

    async def go():
        watcher = BlockWatcher()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            await watcher.stream(c)
        return watcher

    before = len(sent)
    watcher = client.portal.call(go)
    new = sent[before:]
    assert watcher.alerts_sent == 1 and len(new) == 1  # only the blocked, SAQR-flagged entry
    assert "emiratespost-track-uae[.]com" in new[0][1]["body"]


def test_block_watcher_alerts_only_for_saqr_flagged_domains(client, sent):
    client.post("/api/push/subscribe", json={"subscription": SUB, "lang": "en"})
    logs = {"data": [{"timestamp": "2026-11-22T10:00:00.000Z", "domain": "old.example", "status": "blocked"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=logs)

    async def go():
        watcher = BlockWatcher()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            first = await watcher.poll_once(c)  # baseline: old history never alerts
            logs["data"] = [
                {"timestamp": "2026-11-22T10:00:05.000Z", "domain": "ads.tracker.example", "status": "blocked"},
                {"timestamp": "2026-11-22T10:00:06.000Z", "domain": "www.tamm-smart-pay.net", "root": "tamm-smart-pay.net"},
                {"timestamp": "2026-11-22T10:00:07.000Z", "domain": "tamm-smart-pay.net"},
            ]
            second = await watcher.poll_once(c)
            third = await watcher.poll_once(c)  # nothing new
            return first, second, third

    before = len(sent)
    first, second, third = client.portal.call(go)
    assert first == [] and third == []
    assert second == ["tamm-smart-pay.net"]  # once, despite two log lines; ad block ignored
    new = sent[before:]
    assert len(new) == 1 and "TAMM" in new[0][1]["body"] and json.dumps(new[0][1])


def test_late_written_block_is_not_skipped(client, sent):
    """The 15:01:10 miss: a blocked line that shows up after newer lines were already seen."""
    client.post("/api/push/subscribe", json={"subscription": SUB, "lang": "en"})
    logs = {"data": [{"timestamp": "2026-11-23T15:00:00.000Z", "domain": "old.example", "status": "blocked"}]}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=logs)

    async def go():
        watcher = BlockWatcher()
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            await watcher.poll_once(c)  # baseline
            logs["data"] = [{"timestamp": "2026-11-23T15:01:20.000Z", "domain": "ads.example", "status": "blocked"}]
            await watcher.poll_once(c)
            # NextDNS writes the phone's 15:01:10 block a moment late, behind a newer line:
            logs["data"] = [{"timestamp": "2026-11-23T15:01:20.000Z", "domain": "ads.example", "status": "blocked"},
                            {"timestamp": "2026-11-23T15:01:10.000Z", "domain": "saqr-demo-scam.vercel.app",
                             "status": "blocked"}]
            return await watcher.poll_once(c), await watcher.poll_once(c)

    before = len(sent)
    late, again = client.portal.call(go)
    assert late == ["saqr-demo-scam.vercel.app"] and again == []
    assert len(sent[before:]) == 1


def test_failed_alert_is_retried(client, monkeypatch):
    client.post("/api/push/subscribe", json={"subscription": SUB, "lang": "en"})
    calls = []

    def flaky(sub, payload, *_):
        calls.append(payload["body"])
        if len(calls) <= 2:  # first alert and its fresh-connection retry both fail
            raise push.requests.ConnectionError("apple hiccup")
        return 201

    monkeypatch.setattr(push, "_send_sync", flaky)

    async def go():
        import asyncio
        watcher = BlockWatcher()
        watcher.RETRY_DELAYS = (0.05,)
        first = await watcher.handle([{"timestamp": "t", "domain": "aed-refund-claim.vercel.app", "status": "blocked"}])
        await asyncio.sleep(0.5)
        return first, watcher

    first, watcher = client.portal.call(go)
    assert first == [] and watcher.alerts_failed == 1 and watcher.alerts_sent == 1
    assert len(calls) == 3 and push.last_error and "ConnectionError" in push.last_error
    assert client.get("/api/nextdns-status").json()["alerts"]["last_push_error"]


IPHONE = {"endpoint": "https://web.push.apple.com/QK-iphone", "keys": {"p256dh": "BPkey", "auth": "authkey"}}
ANDROID = {"endpoint": "https://fcm.googleapis.com/fcm/send/android-1", "keys": {"p256dh": "BPkey", "auth": "authkey"}}


def test_block_alert_goes_only_to_the_phone_that_tried(client, sent):
    """Two friends on the same SAQR shield: only the phone that opened the scam gets the alert."""
    client.post("/api/push/subscribe", json={"subscription": IPHONE, "lang": "en", "device": "saqriphone1"})
    client.post("/api/push/subscribe", json={"subscription": ANDROID, "lang": "en", "device": "saqrandroid2"})

    async def go():
        watcher = BlockWatcher()
        a = await watcher.handle([{"timestamp": "t1", "domain": "tamm-smart-pay.net", "status": "blocked",
                                   "device": {"id": "X1", "name": "saqriphone1"}}])
        b = await watcher.handle([{"timestamp": "t2", "domain": "tamm-smart-pay.net", "status": "blocked",
                                   "device": {"id": "X2", "name": "saqrandroid2"}}])
        c = await watcher.handle([{"timestamp": "t3", "domain": "tamm-smart-pay.net", "status": "blocked",
                                   "device": {"id": "X1", "name": "saqriphone1"}}])  # repeat within 2 min
        return a, b, c

    before = len(sent)
    a, b, c = client.portal.call(go)
    targets = [e for e, _ in sent[before:]]
    assert a == ["tamm-smart-pay.net"] and b == ["tamm-smart-pay.net"] and c == []
    assert targets == [IPHONE["endpoint"], ANDROID["endpoint"]]  # each phone once, never the other's
    client.post("/api/push/unsubscribe", json={"endpoint": IPHONE["endpoint"]})
    client.post("/api/push/unsubscribe", json={"endpoint": ANDROID["endpoint"]})


def test_unnamed_block_never_reaches_tagged_phones(client, sent):
    client.post("/api/push/subscribe", json={"subscription": IPHONE, "lang": "en", "device": "saqriphone1"})

    async def go():
        return await BlockWatcher().handle([{"timestamp": "t9", "domain": "aed-refund-claim.vercel.app",
                                             "status": "blocked", "device": {"id": "__UNIDENTIFIED__"}}])

    before = len(sent)
    client.portal.call(go)
    assert IPHONE["endpoint"] not in [e for e, _ in sent[before:]]
    client.post("/api/push/unsubscribe", json={"endpoint": IPHONE["endpoint"]})


def test_device_tag_goes_into_the_dns_settings(client):
    host = client.get("/api/android-dns-config", params={"nextdns_id": "abc123", "device": "saqrandroid2"}).json()
    assert "saqrandroid2-abc123.dns.nextdns.io" in json.dumps(host)
    prof = client.get("/api/ios-dns-profile", params={"nextdns_id": "abc123", "device": "saqriphone1"}).text
    assert "https://dns.nextdns.io/abc123/saqriphone1" in prof
    assert client.get("/api/android-dns-config", params={"device": "Bad Tag!"}).status_code == 422


def test_open_tab_retries_do_not_repeat_the_alert(client, sent):
    """Safari retries a blocked scam tab every few minutes: one alert, until the phone leaves it alone."""
    client.post("/api/push/subscribe", json={"subscription": IPHONE, "lang": "en", "device": "saqriphone1"})
    line = {"domain": "saqr-demo-scam.vercel.app", "status": "blocked", "device": {"name": "saqriphone1"}}
    key = "saqr-demo-scam.vercel.app|saqriphone1"

    async def go():
        import time as t
        w = BlockWatcher()
        first = await w.handle([{**line, "timestamp": "a"}])
        # 3 minutes later the open tab retries (the 2-minute repeat window has passed):
        w._recent[key] -= 180
        w._last_attempt[key] -= 180
        retry = await w.handle([{**line, "timestamp": "b"}])
        # 15 minutes of quiet, then a fresh test on the same phone:
        w._recent[key] = t.monotonic() - 1000
        w._last_attempt[key] = t.monotonic() - 900
        fresh = await w.handle([{**line, "timestamp": "c"}])
        return first, retry, fresh

    before = len(sent)
    first, retry, fresh = client.portal.call(go)
    assert first == ["saqr-demo-scam.vercel.app"] and retry == [] and fresh == ["saqr-demo-scam.vercel.app"]
    assert len(sent[before:]) == 2
    client.post("/api/push/unsubscribe", json={"endpoint": IPHONE["endpoint"]})
