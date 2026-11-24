"""UAE regression suite: 50 hand-written cases (tests/uae_suite/cases.json) through the real endpoints, offline,
rules only. Thresholds: 0 false positives on the 25 legitimate cases and at least 24 / 25 scams detected.

A synthetic set written by the team: it guards against regressions on common UAE cases; it is NOT a measure of
accuracy on real-world scams. Detected / false positive are defined once in tests/uae_suite/suite.py.
Full table: python tools/eval_uae.py. Run: pytest -q tests/test_uae_suite.py
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"  # no WHOIS / DNS / TLS / page fetch / LLM
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

from collections import Counter  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from tests.uae_suite import suite  # noqa: E402

MAX_FALSE_POSITIVES = 0
MIN_SCAMS_DETECTED = 24

CASES = suite.load_cases()


@pytest.fixture(scope="module")
def results():
    with TestClient(app) as client:
        return suite.run_all(client, CASES)


def test_case_file_shape():
    ids = [c["id"] for c in CASES]
    assert len(CASES) == 50 and len(set(ids)) == 50
    assert Counter(c["label"] for c in CASES) == {"malicious": 25, "legitimate": 25}
    for c in CASES:
        assert c["modality"] in suite.MODALITIES and c["label"] in ("malicious", "legitimate"), c["id"]
        assert c["description"] and isinstance(c["input"], dict), c["id"]
    for m in suite.MODALITIES:  # every input type has both labels
        assert {c["label"] for c in CASES if c["modality"] == m} == {"malicious", "legitimate"}, m


def test_every_case_answers(results):
    assert not [r.summary() for r in results if r.error]


def test_thresholds(results):
    m = suite.metrics(results)
    fps = [r.summary() for r in results if r.outcome == "FP"]
    fns = [r.summary() for r in results if r.outcome == "FN"]
    assert m.fp <= MAX_FALSE_POSITIVES, "legitimate cases flagged:\n" + "\n".join(fps)
    assert m.tp >= MIN_SCAMS_DETECTED, f"only {m.tp}/25 scams detected; missed:\n" + "\n".join(fns)


def test_official_legitimate_cases_are_verified(results):
    assert not suite.verified_official_misses(results)


def test_scams_are_never_verified_official(results):
    assert not [r.id for r in results if r.malicious and r.response.get("verified_official")]


def test_detection_rule():
    assert suite.is_detected("url", {"verdict": "SUSPICIOUS"}) and not suite.is_detected("url", {"verdict": "SAFE"})
    assert suite.is_detected("phone", {"level": "caution"}) and suite.is_detected("phone", {"level": "danger"})
    assert not suite.is_detected("phone", {"level": "official"}) and not suite.is_detected("phone", {"level": "none"})
