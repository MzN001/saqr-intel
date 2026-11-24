"""Report a false alarm + officer queue + privacy retention. Run: pytest -q tests/test_feedback.py"""
import json
import os
import tempfile
from datetime import timedelta

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.config import settings  # noqa: E402
from saqr.db import db, iso, utcnow  # noqa: E402
from saqr.routers.feedback import feedback_limiter  # noqa: E402

KEY = "k"
HDR = {"X-API-Key": KEY}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _fresh_bucket():
    feedback_limiter.hits.clear()
    yield
    feedback_limiter.hits.clear()


@pytest.fixture
def key_set():
    old = settings.police_api_key
    object.__setattr__(settings, "police_api_key", KEY)
    yield
    object.__setattr__(settings, "police_api_key", old)


def _save(client, scan_id, *, kind="url", domain="example-shop.ae", verdict="SUSPICIOUS", score=55,
          target=None, created_at=None, reporter=None, message_text=None):
    scan = {"scan_id": scan_id, "kind": kind, "domain": domain, "verdict": verdict, "risk_score": score,
            "target": target or f"https://{domain}/login?token=SECRET123", "created_at": created_at or iso(),
            "reporter": reporter, "message_text": message_text}
    client.portal.call(db.save_scan, scan)
    return scan


def _report(client, scan_id, note=None):
    body = {"scan_id": scan_id}
    if note is not None:
        body["note"] = note
    return client.post("/api/feedback/false-alarm", json=body)


def _item(client, scan_id):
    items = client.get("/api/feedback/false-alarms").json()["items"]
    return next((i for i in items if i["scan_id"] == scan_id), None)


def test_submit_appears_in_list(client):
    _save(client, "URL-FA-0001")
    r = _report(client, "URL-FA-0001", "This is my bank's real site")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "open" and r.json()["deduplicated"] is False
    body = client.get("/api/feedback/false-alarms").json()
    assert body["counts"]["open"] >= 1 and body["counts"]["total"] >= 1
    it = _item(client, "URL-FA-0001")
    assert it["label"] == "example-shop.ae" and it["verdict"] == "SUSPICIOUS" and it["score"] == 55
    assert it["note"] == "This is my bank's real site" and it["status"] == "open"
    assert body["items"][0]["last_reported_at"] >= body["items"][-1]["last_reported_at"]  # newest first


def test_repeat_from_same_client_is_deduplicated(client):
    _save(client, "URL-FA-0002")
    assert _report(client, "URL-FA-0002").json()["deduplicated"] is False
    r = _report(client, "URL-FA-0002", "late note")
    assert r.json()["deduplicated"] is True
    it = _item(client, "URL-FA-0002")
    assert it["reports"] == 1 and it["note"] == "late note"


def test_note_length_cap(client):
    _save(client, "URL-FA-0003")
    assert _report(client, "URL-FA-0003", "x" * 281).status_code == 422
    assert _report(client, "URL-FA-0003", "x" * 280).status_code == 200


def test_unknown_scan_404(client):
    assert _report(client, "URL-DOES-NOT-EXIST").status_code == 404


def test_own_rate_limit(client):
    for i in range(4):
        _save(client, f"URL-FA-RL{i}")
    codes = [_report(client, f"URL-FA-RL{i}").status_code for i in range(4)]
    assert codes[:3] == [200, 200, 200] and codes[3] == 429


def test_police_key_guards_queue(client, key_set):
    _save(client, "URL-FA-0004")
    assert _report(client, "URL-FA-0004").status_code == 200  # citizens stay keyless
    assert client.get("/api/feedback/false-alarms").status_code == 401
    rid = client.get("/api/feedback/false-alarms", headers=HDR).json()["items"][0]["id"]
    assert client.post(f"/api/feedback/false-alarms/{rid}", json={"status": "dismissed"}).status_code == 401
    r = client.post(f"/api/feedback/false-alarms/{rid}", json={"status": "dismissed"}, headers=HDR)
    assert r.status_code == 200 and r.json()["status"] == "dismissed"


def test_resolve_updates_status(client):
    _save(client, "URL-FA-0005")
    rid = _report(client, "URL-FA-0005").json()["id"]
    r = client.post(f"/api/feedback/false-alarms/{rid}", json={"status": "confirmed"})
    assert r.status_code == 200 and r.json()["status"] == "confirmed" and r.json()["resolved_at"]
    assert _item(client, "URL-FA-0005")["status"] == "confirmed"
    assert client.post(f"/api/feedback/false-alarms/{rid}", json={"status": "whitelisted"}).status_code == 422
    assert client.post("/api/feedback/false-alarms/FA-NOPE", json={"status": "confirmed"}).status_code == 404


def test_stored_record_has_no_full_url(client):
    _save(client, "URL-FA-0006", domain="secret-path.example")
    _report(client, "URL-FA-0006")
    row = client.portal.call(db.fetchone, "SELECT * FROM false_alarms WHERE scan_id=?", ("URL-FA-0006",))
    dumped = json.dumps(row)
    assert "SECRET123" not in dumped and "https://" not in dumped and "/login" not in dumped
    assert row["label"] == "secret-path.example"


def test_email_scan_gets_neutral_label(client):
    _save(client, "EML-FA-0001", kind="email", domain=None, target="boss@corp.example | Wire the money now")
    assert _report(client, "EML-FA-0001").status_code == 200
    row = client.portal.call(db.fetchone, "SELECT * FROM false_alarms WHERE scan_id=?", ("EML-FA-0001",))
    assert row["label"] == "email message"
    assert "boss@" not in json.dumps(row) and "Wire" not in json.dumps(row)


def test_retention_prunes_old_and_keeps_recent_and_seeded(client):
    old = iso(utcnow() - timedelta(days=45))
    _save(client, "URL-OLD-SAFE", verdict="SAFE", score=0, created_at=old)
    _save(client, "URL-OLD-SCAM", verdict="HIGH-RISK SCAM", score=90, created_at=old, message_text="Pay now 0501234567")
    _save(client, "EML-OLD-0001", kind="email", domain=None, verdict="SUSPICIOUS", created_at=old)
    _save(client, "URL-OLD-SEED", verdict="SAFE", score=0, created_at=old, reporter="seed")
    _save(client, "URL-NEW-SAFE", verdict="SAFE", score=0)
    deleted = client.portal.call(db.prune_scans, 30)
    assert deleted >= 2

    def exists(sid):
        return client.portal.call(db.fetchone, "SELECT 1 FROM scans WHERE id=?", (sid,)) is not None
    assert not exists("URL-OLD-SAFE") and not exists("EML-OLD-0001")
    assert exists("URL-NEW-SAFE") and exists("URL-OLD-SEED")
    assert exists("URL-OLD-SCAM")  # blocklist evidence stays ...
    assert client.portal.call(db.get_scan, "URL-OLD-SCAM")["message_text"] is None  # ... without the SMS text
    assert client.portal.call(db.prune_scans, 0) == 0  # 0 = keep forever


def test_safe_scan_stored_without_query(client):
    _save(client, "URL-SAFE-Q", verdict="SAFE", score=0, target="https://shop.example/p?id=42&email=a@b.c#x")
    row = client.portal.call(db.fetchone, "SELECT target, result_json FROM scans WHERE id=?", ("URL-SAFE-Q",))
    assert row["target"] == "https://shop.example/p"
    assert "email=a@b.c" not in row["result_json"]
    _save(client, "URL-SCAM-Q", verdict="HIGH-RISK SCAM", score=90, target="https://bad.example/p?id=42")
    row = client.portal.call(db.fetchone, "SELECT target FROM scans WHERE id=?", ("URL-SCAM-Q",))
    assert row["target"] == "https://bad.example/p?id=42"  # scam evidence unchanged


def test_safe_response_to_citizen_keeps_query(client):
    r = client.post("/api/analyze-url", json={"url": "https://www.google.com/search?q=hello", "run_sandbox": False,
                                              "use_llm": False})
    assert r.status_code == 200, r.text
    body = r.json()
    if body["verdict"] == "SAFE":
        assert "q=hello" in body["target"]
        stored = client.portal.call(db.fetchone, "SELECT target FROM scans WHERE id=?", (body["scan_id"],))
        assert "q=hello" not in stored["target"]
