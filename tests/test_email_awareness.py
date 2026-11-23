"""Regression (web-app E2E): after an email scan that impersonates a brand, the Crowd-Shield radar's
GET /api/awareness-alert crashed with 500 (sorted() on {None, "domain"}): email scans have domain NULL.
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

pytest.importorskip("saqr.intel.email_parse")

from main import app  # noqa: E402

SAMPLE = """From: TAMM Abu Dhabi <tamm.refunds.uae@gmail.com>
Subject: Traffic fine refund of AED 1,250 - claim within 24 hours

Dear Resident, confirm your card details and the OTP code within 24 hours: https://tamm-smart-pay.net/refund
"""


def test_awareness_alert_survives_email_scans():
    with TestClient(app) as c:
        r = c.post("/api/analyze-email", json={"source": "text", "text": SAMPLE, "use_llm": False})
        assert r.status_code == 200 and r.json()["impersonated_entity"] and r.json()["domain"] is None
        a = c.get("/api/awareness-alert", params={"hours": 168})
        assert a.status_code == 200, a.text[:300]
