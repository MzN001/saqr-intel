"""Predict an unlabelled list of URLs (e.g. a hidden test set) -> CSV of url, label, score, verdict, reasons.

    python tools/predict.py urls.txt -o predictions.csv
    python tools/predict.py urls.csv --url-col link -o predictions.csv --label-at warn

label = 1 (phishing) when the offline engine's verdict reaches --label-at: "warn" = SUSPICIOUS or worse
(score >= 30, the default: best F1 on the source-disjoint holdout, see docs/MODEL_CARD.md) or "block" =
HIGH-RISK SCAM only (score >= 65: fewer false alarms, lower recall). score = risk score 0..100,
model_probability = the URL model's own probability (empty when the model must not judge the site,
e.g. official or top-100k sites). Runs offline in the runtime venv; nothing is saved anywhere else.
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
    args = ap.parse_args()
    evaluate._isolate(False)  # noqa: SLF001
    from saqr.intel.ai_inspector import url_model_probability
    from saqr.intel.domain_intel import analyze_lexical

    urls = read_urls(Path(args.input), args.url_col)
    cut = CUTS[args.label_at]
    counts = {"SAFE": 0, "SUSPICIOUS": 0, "HIGH-RISK SCAM": 0}
    with open(args.output, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "score", "verdict", "model_probability", "reasons"])
        for u in urls:
            score, reasons, verdict = evaluate.system_result(u)
            try:
                p = url_model_probability(analyze_lexical(u))
            except ValueError:
                p = None
            counts[verdict] += 1
            w.writerow([u, int(score >= cut), int(score), verdict, "" if p is None else round(p, 4),
                        " | ".join(reasons)])
    print(f"{len(urls)} URLs -> {args.output}: " + ", ".join(f"{k} {v}" for k, v in counts.items()))


if __name__ == "__main__":
    main()
