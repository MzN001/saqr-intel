"""/police evidence: rich dossiers for campaigns and Proactive Hunter detections, evidence pack zip,
/health hunter block. Run: pytest -q"""
import base64
import hashlib
import io
import json
import os
import tempfile
import zipfile
from datetime import timedelta

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.db import db, iso, utcnow  # noqa: E402
from saqr.intel import takedown  # noqa: E402
from saqr.intel.domain_intel import sha256_text  # noqa: E402
from saqr.police_state import campaign_id_for  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def _scan(client, url, **extra):
    r = client.post("/api/analyze-url", json={"url": url, "run_sandbox": False, **extra})
    assert r.status_code == 200
    return r.json()


def _zip(content: bytes) -> dict[str, bytes]:
    with zipfile.ZipFile(io.BytesIO(content)) as z:
        return {n: z.read(n) for n in z.namelist()}


def test_campaign_takedown_carries_the_full_evidence_dossier(client):
    scan = _scan(client, "https://tamm-fine-payment-ae.xyz/")
    assert scan["verdict"] == "HIGH-RISK SCAM"
    d = client.get(f"/api/police/takedown/{campaign_id_for(scan['domain'])}").json()
    assert d["scan_id"] == scan["scan_id"]
    ev = d["evidence"]
    for key in ("whois", "dns", "network", "tls", "sandbox_evidence", "red_flags", "evidence_integrity", "timeline",
                "notices", "timestamps"):
        assert key in ev, key
    assert all(f["en"] and f["ar"] for f in ev["red_flags"])
    hops = ev["sandbox_evidence"]["redirect_chain"]
    assert hops and set(hops[0]) == {"url", "host", "status", "via", "risk", "note"}
    ts = ev["timestamps"]
    assert ts["first_seen"] <= ts["scanned_at"] <= ts["generated_at"] and ts["timezone"] == "UTC"
    assert ev["sandbox_evidence"]["screenshot_available"] is False
    assert "fast scan" in ev["sandbox_evidence"]["screenshot_note"]
    assert "tamm-fine-payment-ae.xyz" in ev["notices"]["registrar_abuse"]
    assert ev["evidence_integrity"]["hash_algorithm"] == "SHA-256"


def test_evidence_pack_zip_has_every_file_and_a_correct_manifest(client):
    scan = _scan(client, "https://uaepass-login-verify-account.top/")
    ev = client.get(f"/api/police/takedown/{campaign_id_for(scan['domain'])}").json()["evidence"]
    r = client.get(f"/api/dossiers/{ev['dossier_id']}/evidence-pack")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    assert f"{ev['case_reference']}-evidence-pack.zip" in r.headers["content-disposition"]
    files = _zip(r.content)
    assert set(files) == {"dossier.json", "dossier.md", "takedown_notice.txt", "manifest.json"}
    manifest = json.loads(files["manifest.json"])
    assert {f["name"] for f in manifest["files"]} == set(files) - {"manifest.json"}
    for f in manifest["files"]:
        assert f["sha256"] == hashlib.sha256(files[f["name"]]).hexdigest()
        assert f["bytes"] == len(files[f["name"]])
    assert json.loads(files["dossier.json"])["dossier_id"] == ev["dossier_id"]
    assert "## Redirect chain" in files["dossier.md"].decode()
    assert "REGISTRAR ABUSE NOTICE" in files["takedown_notice.txt"].decode()
    assert manifest["screenshot_note"] and manifest["screenshot_matches_capture_hash"] is None
    assert client.get("/api/dossiers/DOS-NOPE/evidence-pack").status_code == 404


def test_evidence_pack_includes_the_screenshot_and_checks_its_capture_hash():
    shot = base64.b64encode(b"\xff\xd8\xff\xe0 fake jpeg bytes").decode()
    d = {"dossier_id": "DOS-T", "case_reference": "ADP-CYB-T", "classification": "RESTRICTED", "scan_id": "SCN-T",
         "generated_at": "2026-11-24T08:00:00+00:00", "generated_by": "test",
         "summary": {"target_defanged": "x[.]top", "verdict": "HIGH-RISK SCAM", "risk_score": 90,
                     "impersonated_entity": "TAMM", "official_domains": [], "harvested_data_types": [],
                     "citizen_reports": 0},
         "whois": {}, "network": {}, "tls": {}, "red_flags": [], "timeline": [],
         "sandbox_evidence": {"redirect_chain": [], "screenshot_available": True},
         "evidence_integrity": {"screenshot_sha256": sha256_text(shot)},
         "recommended_actions": [], "legal_basis": [], "notices": {"registrar_abuse": "R", "hosting_abuse": "H"}}
    files = _zip(takedown.evidence_pack(d, shot))
    assert files["screenshot.jpg"] == base64.b64decode(shot)
    manifest = json.loads(files["manifest.json"])
    assert manifest["screenshot_matches_capture_hash"] is True
    assert "screenshot.jpg" in {f["name"] for f in manifest["files"]}


def test_redirect_hops_accepts_hop_objects_and_old_url_strings():
    hops = takedown.redirect_hops({"redirect_chain": [
        "https://bit.ly/abc", {"url": "https://x-scam.top/", "host": "x-scam.top", "status": 200, "via": "http"}, {}]})
    assert [h["host"] for h in hops] == ["bit.ly", "x-scam.top"]
    assert hops[1]["status"] == 200 and hops[0]["via"] is None


def test_hunter_detection_dossier_measures_lead_time_and_blocked_visits(client):
    domain = "adcb-card-refund-portal.top"
    first_seen = iso(utcnow() - timedelta(hours=3))
    client.portal.call(db.execute, (
        "INSERT INTO hunter_detections (domain, source, first_seen, scanned_at, triage_score, score, verdict, entity, "
        "flags_json, status, simulated) VALUES (?, 'lookalike_sweep', ?, ?, 70, 70, 'HIGH-RISK SCAM', 'ADCB', "
        "'[\"BRAND_IMPERSONATION\"]', 'confirmed', 0)"), (domain, first_seen, first_seen))
    det_id = client.portal.call(db.fetchone, "SELECT id FROM hunter_detections WHERE domain=?", (domain,))["id"]
    try:
        _check_detection_dossier(client, domain, det_id, first_seen)
    finally:  # other test files expect only the simulated rows of a cold boot
        client.portal.call(db.execute, "DELETE FROM hunter_detections WHERE id=?", (det_id,))


def _check_detection_dossier(client, domain, det_id, first_seen):
    d = client.get(f"/api/police/detections/{det_id}/dossier").json()
    assert d["detection"]["citizen_visits"] == 0 and d["detection"]["lead_time_hours"] is None
    assert d["evidence"] is None and "no flagged full scan" in d["note"]
    assert any(r["code"] == "BRAND_IMPERSONATION" and r["ar"] for r in d["triage_reasons"])

    scan = _scan(client, f"https://{domain}/", interception_channel="PC_BROWSER_EXTENSION")
    assert scan["verdict"] != "SAFE"
    client.portal.call(db.execute, "UPDATE hunter_detections SET scan_id=? WHERE id=?", (scan["scan_id"], det_id))

    d = client.get(f"/api/police/detections/{det_id}/dossier").json()
    det = d["detection"]
    assert det["citizen_visits"] == 1 and det["citizen_visits_blocked"] == 1
    assert 2.9 <= det["lead_time_hours"] <= 3.1 and det["source_label"].startswith("Look-alike")
    ev = d["evidence"]
    assert ev["detection"]["detection_id"] == det_id and ev["timestamps"]["first_seen"] == first_seen
    assert any("Proactive Hunter" in t["event"] for t in ev["timeline"])
    assert "## Proactive detection" in takedown.dossier_markdown(ev)

    state = client.get("/api/police/state").json()
    row = next(x for x in state["proactive_detections"] if x["id"] == det_id)
    assert row["citizen_visits"] == 1 and row["citizen_visits_blocked"] == 1


def test_simulated_detection_dossier_is_labelled_and_has_triage_reasons(client):
    sims = [x for x in client.get("/api/police/state").json()["proactive_detections"] if x["simulated"]]
    assert sims, "simulated mode seeds detections on boot"
    d = client.get(f"/api/police/detections/{sims[0]['id']}/dossier").json()
    assert d["detection"]["simulated"] is True and d["evidence"] is None
    assert d["note"].startswith("Simulated lead")
    assert d["triage_reasons"] and all(r["en"] and r["ar"] for r in d["triage_reasons"])
    assert client.get("/api/police/detections/999999/dossier").status_code == 404


def test_health_reports_the_hunter(client):
    h = client.get("/health").json()["hunter"]
    assert h["mode"] == "simulated" and h["data"] == "simulated"
    assert {"background_loop", "cycle_running", "cycles", "last_cycle_finished_at", "backlog",
            "pre_victim_detections"} <= set(h)
    assert isinstance(h["pre_victim_detections"], int)
