"""Personal email model "email-v1": parity vectors, maths, strict import validation and the API.

Run: pytest -q tests/test_user_model.py
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"  # no WHOIS/DNS/LLM calls in CI
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import copy  # noqa: E402
import json  # noqa: E402
import math  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.db import db, iso  # noqa: E402
from saqr.intel import user_model as um  # noqa: E402
from saqr.routers import user_model as um_router  # noqa: E402

# The integration step mounts the router in main.py; until then, mount it here.
if "/api/email-model/label" not in {getattr(r, "path", None) for r in app.routes}:
    app.include_router(um_router.router)

FIX = Path(__file__).parent / "fixtures"
VECTORS = json.loads((FIX / "model_vectors.json").read_text(encoding="utf-8"))
REPORTER = "r-test-0123456789abcdef"
OTHER = "r-other-fedcba9876543210"


def _strip_time(m):
    m = copy.deepcopy(m)
    m.pop("updated_at", None)
    return m


# ---------------------------------------------------------------------------
# Parity vectors (shared with the JS twin)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("vec", VECTORS["features"], ids=lambda v: v["note"][:60])
def test_feature_vectors(vec):
    assert set(um.feature_strings(vec["input"])) == set(vec["strings"])
    assert um.features(vec["input"]) == vec["buckets"]
    assert vec["buckets"] == sorted({um.bucket(s) for s in vec["strings"]})


@pytest.mark.parametrize("vec", VECTORS["predict"], ids=lambda v: v["note"][:60])
def test_predict_vectors(vec):
    feats = um.features(vec["input"])
    assert feats == vec["features"]
    r = um.predict(vec["model"], feats, vec["input"].get("from_address"))
    assert r["available"] == vec["available"] and r["labels"] == vec["labels"] and r["spec"] == "email-v1"
    if vec["p_scam"] is None:
        assert r["p_scam"] is None
    else:
        assert abs(r["p_scam"] - vec["p_scam"]) <= 1e-9


def test_train_and_merge_vectors():
    for vec in VECTORS["train"]:
        m = copy.deepcopy(vec["start"])
        for s in vec["steps"]:
            um.train(m, s["features"], s["label"], s["from_address"])
        assert _strip_time(m) == _strip_time(vec["expect"])
    for vec in VECTORS["merge"]:
        assert _strip_time(um.merge(vec["a"], vec["b"])) == _strip_time(vec["expect"])


def test_vectors_are_rich_enough():
    feats, preds = VECTORS["features"], VECTORS["predict"]
    assert len(feats) >= 30 and len(preds) >= 10
    text = json.dumps([v["input"] for v in feats], ensure_ascii=False)
    assert any("\u0600" <= ch <= "\u06ff" for ch in text)  # Arabic
    assert any(ord(ch) > 0xFFFF for ch in text)  # non-BMP (emoji, Gothic, math letters)
    assert "\u200b" in text and "\u202e" in text  # invisible + bidi
    assert sum(p["p_scam"] is None for p in preds) >= 3  # not available (< 10 docs)
    assert any(abs(p["p_scam"] - 1 / (1 + math.exp(-30))) < 1e-15 for p in preds if p["p_scam"])  # clamp
    # a token of 30 astral code points is kept although its UTF-16 length is 60
    assert any(len(s) == 32 and ord(s[2]) > 0xFFFF for v in feats for s in v["strings"] if s.startswith("b:"))


# ---------------------------------------------------------------------------
# Contract fixtures cross-check
# ---------------------------------------------------------------------------
def test_contract_example_features_match_response_fixture():
    req = json.loads((FIX / "contract/analyze_email_request.json").read_text(encoding="utf-8"))
    resp = json.loads((FIX / "contract/analyze_email_response.json").read_text(encoding="utf-8"))
    m = req["meta"]
    inp = {"from_address": m["from_address"], "from_name": m["from_name"], "reply_to": m["reply_to"],
           "subject": m["subject"], "body_text": m["body_text"],
           "link_domains": [lk["domain"] for lk in resp["links"]],  # the UNWRAPPED link hosts
           "auth": {"spf": "pass", "dkim": "pass", "dmarc": "pass"},
           "flags": [f["code"] for f in resp["red_flags"]]}  # every flag, info ones included
    assert um.features(inp) == resp["model_features"]


def test_contract_user_model_fixture_is_valid():
    raw = json.loads((FIX / "contract/user_model.json").read_text(encoding="utf-8"))
    clean = um.validate_model(raw)
    assert _strip_time(clean) == _strip_time(raw)
    assert um.predict(clean, [], "")["available"] is True


# ---------------------------------------------------------------------------
# Maths details
# ---------------------------------------------------------------------------
def test_tokens_and_regdom_basics():
    assert um.tokens("Pay\u200bPal \uff36\uff25\uff32\uff29\uff26\uff39 a ab") == ["paypal", "verify", "ab"]
    assert um.tokens("\U00010330 \U00010330\U00010331") == ["\U00010330\U00010331"]
    assert um.regdom("WWW.Bank.CO.AE.") == "bank.co.ae"
    assert um.regdom("co.uk") == "co.uk" and um.regdom("") == ""
    assert um.sender_key("A@B.com") == um.sender_key("a@b.com") and len(um.sender_key("x")) == 8
    assert um.fnv1a32("") == 0x811C9DC5 and um.fnv1a32("a") == 0xE40C292C  # published FNV-1a test values


def test_untrain_restores_the_model():
    m = um.new_model()
    um.train(m, [1, 2, 3], "scam", "a@b.c")
    before = _strip_time(m)
    um.train(m, [2, 3, 4], "ham", "x@y.z")
    um.untrain(m, [2, 3, 4], "ham", "x@y.z")
    assert _strip_time(m) == before
    um.untrain(m, [1, 2, 3], "scam", "a@b.c")
    assert _strip_time(m) == _strip_time(um.new_model())
    um.untrain(m, [1], "scam", "a@b.c")  # nothing to undo: stays at zero
    assert m["classes"]["scam"]["docs"] == 0


def test_flag_thresholds():
    assert um.flag_for(None) is None and um.flag_for(0.5) is None
    assert um.flag_for(0.9) == "USER_MODEL_SCAM" and um.flag_for(0.1) == "USER_MODEL_TRUSTED"


@pytest.mark.parametrize("mutate,why", [
    (lambda m: m.update(format="other"), "format"),
    (lambda m: m.update(version=2), "version"),
    (lambda m: m.update(spec="email-v2"), "spec"),
    (lambda m: m.update(buckets=1024), "buckets"),
    (lambda m: m.update(extra=1), "unknown key"),
    (lambda m: m["classes"].update(spam={"docs": 0, "total": 0, "counts": {}}), "extra class"),
    (lambda m: m["classes"]["scam"].update(docs=-1), "negative"),
    (lambda m: m["classes"]["scam"].update(docs=True), "bool"),
    (lambda m: m["classes"]["scam"].update(docs=1.5), "float"),
    (lambda m: m["classes"]["scam"]["counts"].update({"65536": 1}), "bucket out of range"),
    (lambda m: m["classes"]["scam"]["counts"].update({"007": 1}), "leading zero"),
    (lambda m: m["classes"]["scam"]["counts"].update({"12": 99}), "count above docs"),
    (lambda m: m["senders"].update({"XYZ": {"scam": 0, "ham": 1}}), "bad sender key"),
    (lambda m: m["senders"].update({"0000000a": {"scam": 0, "ham": 99}}), "sender above docs"),
    (lambda m: m["senders"].update({"0000000a": {"scam": 0}}), "sender missing ham"),
    (lambda m: m["classes"]["scam"]["counts"].update({"5\n": 1}), "bucket key with trailing newline"),
    (lambda m: m["senders"].update({"0000000a\n": {"scam": 0, "ham": 1}}), "sender key with trailing newline"),
])
def test_validate_model_is_strict(mutate, why):
    m = um.new_model()
    um.train(m, [12, 13], "scam", "a@b.c")
    um.train(m, [13], "ham", "d@e.f")
    um.validate_model(copy.deepcopy(m))  # the untouched model is fine
    mutate(m)
    with pytest.raises(ValueError):
        um.validate_model(m)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


_counter = iter(range(1, 10_000))


def _save_email_scan(client, reporter=REPORTER, kind="email", feats=(10, 20, 30), sender="Boss@Company.ae",
                     with_features=True):
    """Store a scan the way the email pipeline does (only the fields the label endpoint reads)."""
    sid = f"EML-20261123-T{next(_counter):05d}"
    scan = {"scan_id": sid, "kind": kind, "target": f"{sender} | Secret subject words", "domain": None,
            "created_at": iso(), "risk_score": 10, "verdict": "SAFE", "channel": "email", "reporter": reporter,
            "email": {"from": {"address": sender}, "subject": "Secret subject words"}}
    if with_features:
        scan["model_features"] = list(feats)
    client.portal.call(db.save_scan, scan)
    return sid


def _label(client, sid, label, reporter=REPORTER):
    return client.post("/api/email-model/label", json={"reporter_id": reporter, "scan_id": sid, "label": label})


def test_label_relabel_download_import_delete(client):
    client.delete(f"/api/email-model/{REPORTER}")
    assert client.get(f"/api/email-model/{REPORTER}").status_code == 404

    sid = _save_email_scan(client)
    r = _label(client, sid, "scam")
    assert r.status_code == 200, r.text
    assert {"ok": True, "changed": True, "previous": None, "labels": 1, "scam": 1, "ham": 0}.items() <= r.json().items()

    again = _label(client, sid, "scam").json()  # same label again: nothing changes
    assert again["changed"] is False and again["labels"] == 1

    flip = _label(client, sid, "ham").json()  # relabel REPLACES the earlier label
    assert flip["previous"] == "scam" and flip["scam"] == 0 and flip["ham"] == 1 and flip["labels"] == 1

    dl = client.get(f"/api/email-model/{REPORTER}")
    assert dl.status_code == 200
    assert 'filename="saqr-my-model.json"' in dl.headers["content-disposition"]
    model = dl.json()
    assert model["classes"]["scam"] == {"docs": 0, "total": 0, "counts": {}}
    assert model["classes"]["ham"]["counts"] == {"10": 1, "20": 1, "30": 1}
    assert model["senders"] == {um.sender_key("boss@company.ae"): {"scam": 0, "ham": 1}}

    # counts only: no mail text and no raw reporter id in the stored row
    row = client.portal.call(db.fetchone, "SELECT * FROM user_models WHERE reporter_hash=?",
                             (um.reporter_key(REPORTER),))
    stored = json.dumps(row)
    assert "secret" not in stored.lower() and "company" not in stored.lower() and REPORTER not in stored

    merged = client.put(f"/api/email-model/{REPORTER}", content=json.dumps(model))
    assert merged.status_code == 200 and merged.json()["ham"] == 2
    assert client.get(f"/api/email-model/{REPORTER}").json()["classes"]["ham"]["counts"]["10"] == 2

    replaced = client.put(f"/api/email-model/{REPORTER}?mode=replace", content=json.dumps(model))
    assert replaced.json()["ham"] == 1

    gone = client.delete(f"/api/email-model/{REPORTER}")
    assert gone.json() == {"ok": True, "deleted": True}
    assert client.get(f"/api/email-model/{REPORTER}").status_code == 404
    assert client.delete(f"/api/email-model/{REPORTER}").json()["deleted"] is False


def test_label_ownership_and_kind_checks(client):
    sid = _save_email_scan(client, reporter=OTHER)
    assert _label(client, sid, "scam").status_code == 403  # someone else's scan
    assert _label(client, _save_email_scan(client, reporter=None), "scam").status_code == 403  # no reporter saved
    assert _label(client, _save_email_scan(client, kind="url"), "scam").status_code == 422
    assert _label(client, _save_email_scan(client, with_features=False), "scam").status_code == 422
    assert _label(client, "EML-20261123-NOPE00", "scam").status_code == 404
    hashed = _save_email_scan(client, reporter=um.reporter_key(REPORTER))  # pipeline may store the hash instead
    assert _label(client, hashed, "ham").status_code == 200
    client.delete(f"/api/email-model/{REPORTER}")
    assert _label(client, sid, "spam").status_code == 422
    assert _label(client, sid, "scam", reporter="short").status_code == 422
    r = _label(client, sid, "scam")
    assert "—" in r.json()["detail"]  # English — Arabic


def test_model_becomes_available_after_ten_of_each(client):
    rid = "r-avail-0123456789abcd"
    client.delete(f"/api/email-model/{rid}")
    for i in range(10):
        assert _label(client, _save_email_scan(client, rid, feats=(1, 2, 100 + i), sender=f"p{i}@prize.top"),
                      "scam", reporter=rid).status_code == 200
    last = None
    for i in range(10):
        last = _label(client, _save_email_scan(client, rid, feats=(1, 3, 200 + i), sender="hr@company.ae"), "ham", reporter=rid)
    assert last.json()["available"] is True
    scam_like = client.portal.call(um.predict_for, rid, [1, 2], "new@prize.top")
    ham_like = client.portal.call(um.predict_for, rid, [1, 3], "hr@company.ae")
    assert scam_like["available"] and scam_like["p_scam"] > 0.9 and um.flag_for(scam_like["p_scam"]) == "USER_MODEL_SCAM"
    assert ham_like["p_scam"] < 0.1 and ham_like["labels"] == 20
    none = client.portal.call(um.predict_for, None, [1, 2], "")
    assert none == {"available": False, "p_scam": None, "labels": 0, "spec": "email-v1"}
    client.delete(f"/api/email-model/{rid}")


def test_import_rejects_bad_files(client):
    rid = "r-import-0123456789abc"
    assert client.put(f"/api/email-model/{rid}", content=b"not json").status_code == 422
    assert client.put(f"/api/email-model/{rid}", content=json.dumps({"format": "x"})).status_code == 422
    bad = um.new_model()
    bad["classes"]["scam"]["counts"]["5"] = 3  # more than docs (0)
    assert client.put(f"/api/email-model/{rid}", content=json.dumps(bad)).status_code == 422
    huge = b" " * (um_router.MAX_IMPORT_BYTES + 1)
    assert client.put(f"/api/email-model/{rid}", content=huge).status_code == 413
    assert client.get("/api/email-model/too-short").status_code == 422
    bomb = '{"format":"saqr-user-model","classes":' + "[" * 100_000 + "]" * 100_000 + "}"
    assert client.put(f"/api/email-model/{rid}", content=bomb).status_code == 422  # RecursionError, not 500
    assert client.get(f"/api/email-model/{rid}").status_code == 404  # nothing was stored


def test_merge_that_would_overflow_the_limits_is_refused(client):
    """Merging must keep a model the server (and the extension) can import again."""
    rid = "r-overflow-0123456789a"
    client.delete(f"/api/email-model/{rid}")
    big = um.new_model()
    big["classes"]["scam"].update(docs=600_000_000, total=600_000_000, counts={"7": 600_000_000})
    assert client.put(f"/api/email-model/{rid}", content=json.dumps(big)).status_code == 200
    r = client.put(f"/api/email-model/{rid}", content=json.dumps(big))
    assert r.status_code == 422 and "—" in r.json()["detail"]
    stored = client.get(f"/api/email-model/{rid}").json()
    assert stored["classes"]["scam"]["docs"] == 600_000_000  # unchanged
    assert client.put(f"/api/email-model/{rid}?mode=replace", content=json.dumps(stored)).status_code == 200
    client.delete(f"/api/email-model/{rid}")
