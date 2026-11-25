"""Stage test set: 151 real-style SMS (tests/stage_set/messages.json) through the SMS checker, offline, rules only.

92 scam messages (toll, parcel, bank, OTP hand-over, job, "new number", call-back, prize, investment; with
look-alike letters, shorteners, look-alike domains, Arabic and other languages) and 59 legitimate ones chosen to be
close to scams. 39 scam texts use wording quoted on a cited page; the rest are written in the style of a named
campaign (see each entry's "source"). It is a regression guard for the demo, NOT a real-world accuracy figure.

Rules:
* no legitimate message may be flagged (0 false alarms);
* a scam must not get a green "safe": it is flagged, or shown as "not verified" (its link could not be checked).
  A few are undetectable from the text alone ("are we still on for dinner on Friday?"): the floor below is the
  honest count on 2026-11-25, and the listed ids are the known misses.

Full table: python tools/eval_stage.py --misses.   Run: pytest -q tests/test_stage_set.py
"""
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
import eval_stage  # noqa: E402

MAX_FALSE_ALARMS = 0
MIN_SCAMS_NOT_SAFE = 85  # of 92: flagged or "not verified"
# Texts that carry no checkable sign on their own (reply-only lures, a real-looking bank check, chat openers).
KNOWN_SAFE = {"scam-toll-001", "scam-toll-005", "scam-parcel-002", "scam-bank-008", "scam-crypto-002", "scam-crypto-003"}

CASES = eval_stage.load()


@pytest.fixture(scope="module")
def rows():
    with TestClient(app) as client:
        return eval_stage.run(client, CASES)


def test_file_shape():
    ids = [c["id"] for c in CASES]
    assert len(ids) == len(set(ids))
    assert Counter(c["label"] for c in CASES) == {"scam": 92, "legit": 59}
    assert all(c["text"].strip() and c["source"] for c in CASES)


def test_no_legitimate_message_is_flagged(rows):
    bad = [(r["id"], r["sms_verdict"], r["sms_flags"]) for r in rows if r["label"] == "legit" and r["sms"] == "flagged"]
    assert len(bad) <= MAX_FALSE_ALARMS, bad


def test_scams_do_not_get_a_green_safe(rows):
    scams = [r for r in rows if r["label"] == "scam"]
    safe = sorted(r["id"] for r in scams if r["sms"] == "safe")
    assert len(scams) - len(safe) >= MIN_SCAMS_NOT_SAFE, safe
    assert set(safe) <= KNOWN_SAFE, sorted(set(safe) - KNOWN_SAFE)


def test_sms_never_says_safe_when_email_says_scam(rows):
    # the same text must not be "safe" in one checker and a scam in the other
    split = [r["id"] for r in rows if r["label"] == "scam" and r["sms"] == "safe" and r["email"] == "flagged"]
    assert not split, split
