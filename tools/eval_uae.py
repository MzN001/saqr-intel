"""Run the 50-case UAE regression suite (tests/uae_suite/cases.json) and print the results.

    python tools/eval_uae.py                 # offline, rules only, deterministic (the default)
    python tools/eval_uae.py --json out.json # also save every case result + the metrics
    python tools/eval_uae.py --live          # REAL network + the configured LLM (see below)

What it measures: 25 malicious + 25 legitimate cases written by the SAQR team, across five input types
(website link, email, Google Maps listing, phone number, SMS / WhatsApp text). Every scam domain is
invented. It shows that common legitimate UAE cases are not flagged and that common scam patterns are
caught. It is NOT a measure of accuracy on real-world scams (see docs/MODEL_CARD.md for those numbers).

Detected = the verdict is not SAFE (phone: level "caution" or "danger"); defined once in
tests/uae_suite/suite.py.

Offline (default): OFFLINE_MODE=true, LLM_PROVIDER=rules, no WHOIS / DNS / TLS / page fetch / threat feeds /
Places, throw-away database, NextDNS / push / police / Maps keys blanked. Same setup as `pytest`.

--live: allows the network and the LLM. It uses the API keys in your environment / .env (GEMINI_API_KEY or
OPENAI_API_KEY), makes real requests (WHOIS, DNS, TLS, page fetches over HTTP, Gemini / OpenAI calls that use
your quota) and its numbers can change from run to run. Still a throw-away database with NextDNS, push,
police and Maps keys blanked, threat feeds and the hunter off.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))


def isolate(live: bool) -> None:
    """Set the environment before anything imports saqr (python-dotenv never overrides a set variable)."""
    from evaluate import _isolate  # same isolation as tools/evaluate.py

    _isolate(live, use_llm=live)
    os.environ["RATE_LIMIT_PER_MINUTE"] = "0"
    os.environ["HUNTER_MODE"] = "off"
    if not live:
        os.environ["ENABLE_PLAYWRIGHT"] = "false"  # rules only: no browser for the start-up demo scans either
    for key in ("EMAIL_TRUSTED_AUTHSERV", "USER_LLM_ALLOW_PRIVATE", "EMAIL_RATE_LIMIT_PER_MINUTE"):
        os.environ[key] = ""


def fmt(v) -> str:
    return "n/a" if v is None else f"{v:.3f}"


def run(live: bool, verbose: bool = False):
    import logging

    from fastapi.testclient import TestClient

    from main import app
    from tests.uae_suite import suite

    if not verbose:  # server request logs and start-up demo scans would bury the table
        logging.disable(logging.CRITICAL)

    cases = suite.load_cases()
    with TestClient(app) as client:
        t = time.perf_counter()
        results = suite.run_all(client, cases, live=live)
        elapsed = time.perf_counter() - t
    return suite, cases, results, elapsed


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", dest="json_out", help="save the per-case results and metrics to this file")
    ap.add_argument("--live", action="store_true",
                    help="allow network + the configured LLM (uses your keys, makes real requests)")
    ap.add_argument("--verbose", action="store_true", help="show the server logs")
    args = ap.parse_args()
    try:  # a miss line can contain Arabic: never crash on a Windows (cp1252) console
        sys.stdout.reconfigure(errors="replace")
    except AttributeError:
        pass
    isolate(args.live)
    suite, cases, results, elapsed = run(args.live, args.verbose)

    mode = "LIVE (network + LLM)" if args.live else "offline, rules only"
    print(f"SAQR UAE regression suite: {len(cases)} cases, mode: {mode}, {elapsed:.1f} s")
    print("Synthetic set written by the team; not a measure of accuracy on real-world scams.\n")
    print(f"{'modality':10s} {'cases':>5s} {'TP':>3s} {'FN':>3s} {'FP':>3s} {'TN':>3s} "
          f"{'recall':>7s} {'FPR':>6s}")
    per_mod = {}
    for m in suite.MODALITIES:
        mm = suite.metrics([r for r in results if r.case["modality"] == m])
        per_mod[m] = mm.to_dict()
        print(f"{m:10s} {mm.tp + mm.fn + mm.fp + mm.tn:5d} {mm.tp:3d} {mm.fn:3d} {mm.fp:3d} {mm.tn:3d} "
              f"{fmt(mm.recall):>7s} {fmt(mm.fpr):>6s}")
    total = suite.metrics(results)
    print(f"{'all':10s} {len(results):5d} {total.tp:3d} {total.fn:3d} {total.fp:3d} {total.tn:3d} "
          f"{fmt(total.recall):>7s} {fmt(total.fpr):>6s}\n")
    print(f"Precision {fmt(total.precision)}  Recall {fmt(total.recall)}  "
          f"False positive rate {fmt(total.fpr)}  F1 {fmt(total.f1)}")
    misses = [r for r in results if not r.correct]
    print(f"\nMisses ({len(misses)}):" if misses else "\nMisses: none")
    for r in misses:
        print(f"  {r.summary()}")
    vo = suite.verified_official_misses(results)
    print(f"verified_official missing on official legitimate cases: {vo if vo else 'none'}")
    if total.errors:
        print(f"request errors: {total.errors}")

    if args.json_out:
        out = {"mode": "live" if args.live else "offline", "date": time.strftime("%Y-%m-%d"),
               "cases": len(cases), "metrics": total.to_dict(), "by_modality": per_mod,
               "verified_official_misses": vo,
               "results": [{"id": r.id, "modality": r.case["modality"], "label": r.case["label"],
                            "outcome": r.outcome, "verdict": r.response.get("verdict"),
                            "risk_score": r.response.get("risk_score"), "level": r.response.get("level"),
                            "verified_official": r.response.get("verified_official"), "error": r.error}
                           for r in results]}
        Path(args.json_out).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"saved {args.json_out}")


if __name__ == "__main__":
    main()
