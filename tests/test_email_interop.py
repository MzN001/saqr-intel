"""Cross-workstream guards for email scanning (Python backend <-> extension <-> web app).

* Every flag code the email rules engine can emit has citizen reason text in the extension's result
  page (extension/blocked.js REASONS) and in the web app (frontend/src/lib/share.ts), so a new code
  can never show up as the generic "it fails official verification".
* A personal model exported by either side (server GET / extension options page) imports on the other
  (server PUT is strict, the extension's validate() is looser). Needs Node.js; skipped without it.

Run: pytest -q tests/test_email_interop.py
"""
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import copy  # noqa: E402
import json  # noqa: E402
import re  # noqa: E402
import shutil  # noqa: E402
import subprocess  # noqa: E402
from pathlib import Path  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.intel import email_rules  # noqa: E402
from saqr.intel import user_model as um  # noqa: E402

REPO = Path(__file__).resolve().parent.parent
FIX = Path(__file__).parent / "fixtures"
VECTORS = json.loads((FIX / "model_vectors.json").read_text(encoding="utf-8"))
NODE = shutil.which("node")


# ---------------------------------------------------------------------------
# Flag codes -> reason text
# ---------------------------------------------------------------------------
def emitted_codes() -> set[str]:
    """Every code email_rules.run_email_rules can add (read from its source + its code sets)."""
    src = Path(email_rules.__file__).read_text(encoding="utf-8")
    codes = set(re.findall(r'\badd\(\s*"([A-Z][A-Z0-9_]+)"', src))
    # _unicode_flags builds its flags from a (code, severity, ...) table
    codes |= set(re.findall(r'\(\s*"([A-Z][A-Z0-9_]+)",\s*"(?:critical|high|medium|low|info)"', src))
    return codes | email_rules.STRONG_CODES | email_rules.WEAK_CODES


def _keys(text: str, start: str) -> set[str]:
    block = text[text.index(start):]
    block = block[:block.index("\n};")]
    return set(re.findall(r"^\s*([A-Z][A-Z0-9_]+):", block, re.M))


def test_every_email_flag_code_is_found():
    codes = emitted_codes()
    assert len(codes) >= 35, sorted(codes)
    for c in ("OFFICIAL_SENDER_UNAUTHENTICATED", "IDN_MIXED_SCRIPT", "DMARC_PASS", "USER_MODEL_TRUSTED"):
        assert c in codes


def test_extension_result_page_explains_every_email_flag():
    reasons = _keys((REPO / "extension" / "blocked.js").read_text(encoding="utf-8"), "const REASONS = {")
    missing = sorted(emitted_codes() - reasons)
    assert not missing, f"add these codes to REASONS in extension/blocked.js: {missing}"


def test_web_app_explains_every_email_flag():
    reasons = _keys((REPO / "frontend" / "src" / "lib" / "share.ts").read_text(encoding="utf-8"),
                    "const REASON_BY_FLAG")
    missing = sorted(emitted_codes() - reasons)
    assert not missing, f"add these codes to REASON_BY_FLAG in frontend/src/lib/share.ts: {missing}"


def test_reason_texts_have_english_and_arabic():
    src = (REPO / "extension" / "blocked.js").read_text(encoding="utf-8")
    for code in emitted_codes():
        m = re.search(rf'^\s*{code}: \["([^"]+)", "([^"]+)"\],$', src, re.M)
        assert m, code
        assert re.search("[\u0600-\u06ff]", m.group(2)), code


# ---------------------------------------------------------------------------
# Personal model: export on one side, import on the other
# ---------------------------------------------------------------------------
def _node(script: str, payload) -> dict:
    out = subprocess.run([NODE, "-e", script], input=json.dumps(payload), capture_output=True, text=True,
                         cwd=REPO, timeout=60, check=True)
    return json.loads(out.stdout)


JS_PRELUDE = 'const M = require("./extension/lib/user_model.js"); const fs = require("fs");' \
             'const input = JSON.parse(fs.readFileSync(0, "utf8"));'


def _training_set():
    """(features, label, from_address) for every feature vector, alternating labels, a few repeat senders."""
    out = []
    for i, vec in enumerate(VECTORS["features"]):
        sender = vec["input"].get("from_address") or ("" if i % 7 == 0 else f"user{i % 5}@example.com")
        out.append((vec["buckets"], "scam" if i % 2 else "ham", sender))
    return out


def _without_time(m):
    m = copy.deepcopy(m)
    m.pop("updated_at", None)
    for c in m["classes"].values():
        c["counts"] = {k: v for k, v in c["counts"].items() if v}
    m["senders"] = {k: v for k, v in m["senders"].items() if v["scam"] or v["ham"]}
    return m


@pytest.mark.skipif(not NODE, reason="Node.js not installed")
def test_extension_export_imports_on_server():
    steps = _training_set()
    js_model = _node(JS_PRELUDE + """
      let m = M.newModel();
      for (const [f, label, from] of input) M.train(m, f, label, from);
      // the user changed their mind once: untrain + train the other label
      const [f0, l0, s0] = input[1];
      M.untrain(m, f0, l0, s0); M.train(m, f0, l0 === "scam" ? "ham" : "scam", s0);
      m = M.validate(JSON.parse(JSON.stringify(m)));   // what the options page downloads
      process.stdout.write(JSON.stringify(m));
    """, steps)
    with TestClient(app) as client:
        rid = "r-interop-js-to-server-0001"
        r = client.put(f"/api/email-model/{rid}?mode=replace", content=json.dumps(js_model))
        assert r.status_code == 200, r.text
        back = client.get(f"/api/email-model/{rid}").json()
        assert _without_time(back) == _without_time(js_model)
        # same opinion on every email on both sides
        for f, _, sender in steps[:10]:
            p = um.predict(back, f, sender)
            assert p["available"]
        client.delete(f"/api/email-model/{rid}")


@pytest.mark.skipif(not NODE, reason="Node.js not installed")
def test_server_export_imports_in_extension():
    steps = _training_set()
    model = um.new_model()
    for f, label, sender in steps:
        um.train(model, f, label, sender)
    f0, l0, s0 = steps[1]
    um.untrain(model, f0, l0, s0)
    um.train(model, f0, "ham" if l0 == "scam" else "scam", s0)
    contract = json.loads((FIX / "contract" / "user_model.json").read_text(encoding="utf-8"))
    with TestClient(app) as client:
        rid = "r-interop-server-to-js-0001"
        assert client.put(f"/api/email-model/{rid}?mode=replace", content=json.dumps(model)).status_code == 200
        server_export = client.get(f"/api/email-model/{rid}").json()
        client.delete(f"/api/email-model/{rid}")
    probes = [[f, s] for f, _, s in steps[:12]]
    res = _node(JS_PRELUDE + """
      const out = {};
      for (const [name, m] of Object.entries(input.models)) {
        const v = M.validate(m);
        out[name] = { model: v, p: input.probes.map(([f, s]) => M.predict(v, f, s).p_scam) };
      }
      process.stdout.write(JSON.stringify(out));
    """, {"models": {"server": server_export, "contract": contract}, "probes": probes})
    assert _without_time(res["server"]["model"]) == _without_time(server_export)
    assert _without_time(res["contract"]["model"]) == _without_time(um.validate_model(contract))
    for (f, s), p_js in zip(probes, res["server"]["p"]):
        p_py = um.predict(server_export, f, s)["p_scam"]
        assert (p_js is None and p_py is None) or abs(p_js - p_py) <= 1e-9
