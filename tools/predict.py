"""Predict an unlabelled list of URLs (e.g. a hidden test set) -> CSV of url, label, score, verdict, reasons.

    python tools/predict.py urls.txt -o predictions.csv
    python tools/predict.py urls.csv --url-col link -o predictions.csv --label-at warn
    python tools/predict.py urls.txt -o predictions.csv --mode live --records live.jsonl   # full pipeline

label = 1 (phishing) when the offline engine's verdict reaches --label-at: "warn" = SUSPICIOUS or worse
(score >= 30, the default: best F1 on the source-disjoint holdout, see docs/MODEL_CARD.md) or "block" =
HIGH-RISK SCAM only (score >= 65: fewer false alarms, lower recall). score = risk score 0..100,
model_probability = the URL model's own probability (empty when the model must not judge the site,
e.g. official or top-100k sites).

--mode offline (default): the address-only engine, no network, fast (what a scan decides before any
page is fetched). --mode live: the full pipeline per URL (redirects / shorteners, WHOIS / DNS / TLS, the
page fetched as a UAE phone and as a bot, threat feeds with --feeds, the AI judge with --llm), through
tools/evaluate.run_live: throw-away database, NextDNS / push keys blanked, bounded concurrency,
per-URL timeout, and --records makes a long run resumable. Columns are the same in both modes.
"""
from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import evaluate  # noqa: E402
from url_datasets import SAMPLE, _records, detect_columns, normalise_url  # noqa: E402

CUTS = {"block": 65, "warn": 30}


def read_urls(path: Path, url_col: str | None) -> list[str]:
    sample = []
    for rec in _records(path):
        sample.append(rec)
        if len(sample) >= SAMPLE:
            break
    if not sample:
        return []
    key, _ = detect_columns(sample, url_col, None, want_label=False)
    out = []
    for rec in _records(path, [key]):
        raw = rec.get(key)
        if raw not in (None, ""):
            out.append(normalise_url(raw) or str(raw).strip())
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("-o", "--output", default="predictions.csv")
    ap.add_argument("--url-col")
    ap.add_argument("--label-at", choices=tuple(CUTS), default="warn")
    ap.add_argument("--mode", choices=("offline", "live"), default="offline")
    ap.add_argument("--concurrency", type=int, default=20, help="live: scans at the same time")
    ap.add_argument("--timeout", type=float, default=45.0, help="live: seconds per URL")
    ap.add_argument("--feeds", action="store_true", help="live: the scan uses the live threat feeds")
    ap.add_argument("--llm", action="store_true", help="live: allow the AI judge")
    ap.add_argument("--records", help="live: JSONL of per-URL results (resumable)")
    args = ap.parse_args()
    live = args.mode == "live"
    evaluate._isolate(live, args.llm)  # noqa: SLF001
    from saqr.intel.ai_inspector import url_model_probability, verdict_for
    from saqr.intel.page_signals import lexical

    urls = read_urls(Path(args.input), args.url_col)
    cut = CUTS[args.label_at]
    recs = evaluate.run_live(urls, concurrency=args.concurrency, use_llm=args.llm, timeout=args.timeout,
                             feeds=args.feeds, records=args.records) if live else {}
    counts = {"SAFE": 0, "SUSPICIOUS": 0, "HIGH-RISK SCAM": 0, "TIMEOUT": 0, "ERROR": 0}
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "score", "verdict", "model_probability", "reasons"])
        for u in urls:
            if live:
                rec = recs[u]
                score, reasons = float(rec["score"]), rec.get("reasons") or [rec.get("error", "")]
                verdict = rec["verdict"] if rec["verdict"] in ("TIMEOUT", "ERROR") else verdict_for(int(score))
                target = rec.get("judged_url") or u
            else:
                score, reasons, verdict = evaluate.system_result(u)
                target = u
            try:
                p = url_model_probability(lexical(target))
            except ValueError:
                p = None
            counts[verdict] += 1
            w.writerow([u, int(score >= cut), int(score), verdict, "" if p is None else round(p, 4),
                        " | ".join(reasons)])
    print(f"{len(urls)} URLs -> {args.output}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))


if __name__ == "__main__":
    main()
