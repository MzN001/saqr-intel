"""Stage test set: real-style scam and legitimate messages through the SMS and Email checkers.

    .venv/Scripts/python tools/eval_stage.py              # offline, rules only (what the tests run)
    .venv/Scripts/python tools/eval_stage.py --misses     # also print every miss and false alarm
    .venv/Scripts/python tools/eval_stage.py --json out.json

Reads tests/stage_set/messages.json ({id, label: scam|legit, category, text, sender, source, notes}).
Offline = no network, no AI: links are judged from their address only, so this is the FLOOR of what the
live site does (there, links are also opened and the AI judge reads the message).

A scam counts as caught when the verdict is not SAFE, or when the result says "not verified" (the citizen
is told Saqr could not check the link: amber, never a green "safe"). A legitimate message counts as a false
alarm only when the verdict is not SAFE.
"""
from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SET_PATH = ROOT / "tests" / "stage_set" / "messages.json"


def isolate() -> None:
    os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(prefix="saqr-stage-"), "stage.db")
    for key in ("NEXTDNS_API_KEY", "NEXTDNS_PROFILE_ID", "VAPID_PRIVATE_KEY", "POLICE_API_KEY", "GOOGLE_MAPS_API_KEY",
                "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        os.environ[key] = ""
    os.environ.update(CT_MODE="off", OFFLINE_MODE="true", LLM_PROVIDER="rules", RATE_LIMIT_PER_MINUTE="0",
                      EMAIL_RATE_LIMIT_PER_MINUTE="0", THREAT_FEEDS="false", HUNTER_MODE="off", KEEP_AWAKE="false")


def load(path: Path = SET_PATH) -> list[dict]:
    return json.loads(path.read_text(encoding="utf-8"))


def outcome(resp: dict) -> str:
    """'flagged' (not SAFE), 'unverified' (SAFE but Saqr says it could not check the link) or 'safe'."""
    if resp.get("verdict") != "SAFE":
        return "flagged"
    return "unverified" if resp.get("verification") else "safe"


def run(client, cases: list[dict]) -> list[dict]:
    rows = []
    for c in cases:
        body = {"text": c["text"][:4000], "channel": "sms", "use_llm": False}
        if c.get("sender"):
            body["sender"] = str(c["sender"])[:64]
        r = client.post("/api/analyze-message", json=body)
        sms = r.json() if r.status_code == 200 else {"verdict": "ERROR", "risk_score": -1, "detail": r.text[:200]}
        r = client.post("/api/analyze-email", json={"source": "text", "text": c["text"], "use_llm": False,
                                                    "use_user_model": False})
        em = r.json() if r.status_code == 200 else {"verdict": "ERROR", "risk_score": -1, "detail": r.text[:200]}
        rows.append({"id": c["id"], "label": c["label"], "category": c.get("category"),
                     "sms": outcome(sms), "sms_score": sms.get("risk_score"), "sms_verdict": sms.get("verdict"),
                     "sms_flags": [f["code"] for f in sms.get("red_flags", []) if f.get("points", 0) > 0],
                     "email": outcome(em), "email_score": em.get("risk_score"), "email_verdict": em.get("verdict"),
                     "text": c["text"]})
    return rows


def summary(rows: list[dict]) -> dict:
    scams = [r for r in rows if r["label"] == "scam"]
    legit = [r for r in rows if r["label"] == "legit"]
    out = {"scam": len(scams), "legit": len(legit)}
    for ch in ("sms", "email"):
        out[ch] = {"scams_flagged": sum(r[ch] == "flagged" for r in scams),
                   "scams_unverified": sum(r[ch] == "unverified" for r in scams),
                   "scams_called_safe": sum(r[ch] == "safe" for r in scams),
                   "legit_false_alarms": sum(r[ch] == "flagged" for r in legit),
                   "legit_unverified": sum(r[ch] == "unverified" for r in legit)}
    out["scams_safe_in_sms_but_flagged_in_email"] = sum(r["sms"] == "safe" and r["email"] == "flagged" for r in scams)
    out["sms_safe_by_category"] = dict(Counter(r["category"] for r in scams if r["sms"] == "safe"))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--misses", action="store_true")
    ap.add_argument("--json")
    args = ap.parse_args()
    isolate()
    sys.path.insert(0, str(ROOT))
    from fastapi.testclient import TestClient

    from main import app

    cases = load()
    with TestClient(app) as client:
        rows = run(client, cases)
    s = summary(rows)
    out = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    print(json.dumps(s, indent=1), file=out)
    if args.misses:
        print("\n--- scams the SMS check calls SAFE:", file=out)
        for r in rows:
            if r["label"] == "scam" and r["sms"] == "safe":
                print(f"  {r['id']:28s} sms {r['sms_score']} | email {r['email_verdict']} {r['email_score']} | "
                      f"{r['text'][:150]!r}", file=out)
        print("\n--- legitimate messages the SMS check flags:", file=out)
        for r in rows:
            if r["label"] == "legit" and r["sms"] == "flagged":
                print(f"  {r['id']:28s} sms {r['sms_verdict']} {r['sms_score']} {r['sms_flags']} | {r['text'][:150]!r}",
                      file=out)
    out.flush()
    if args.json:
        Path(args.json).write_text(json.dumps({"summary": s, "rows": rows}, ensure_ascii=False, indent=1),
                                   encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
