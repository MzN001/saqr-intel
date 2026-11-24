"""Evaluate SAQR on ANY labelled URL dataset (runs in the normal runtime venv, standard library only).

    python tools/evaluate.py datasets/hannousse/dataset_B_05_2020.csv
    python tools/evaluate.py my.csv --url-col link --label-col verdict --positive bad,phish --mode system
    python tools/evaluate.py feed.txt --label 1 --mode live --concurrency 8 --out report.json

Modes:
  model   the trained URL model alone (url_model.score_url probability; --threshold 0..1)
  system  the offline engine a scan runs first: analyze_lexical + rules + model (score 0..100;
          --threshold in points, default 65 = HIGH-RISK; the 30-point SUSPICIOUS cut is reported too)
  live    the full pipeline.analyze_url (DNS / WHOIS / TLS / redirects; --llm to allow the AI judge)
          against a throw-away database, without graph ingestion and with NextDNS / push disabled.
Prints precision, recall, F1, FPR, accuracy, the confusion matrix, PR points and the 20 worst
false positives / negatives with their reasons.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

from url_datasets import load_labelled  # noqa: E402


def _isolate(live: bool) -> None:
    """Never touch live accounts or the real database from an evaluation run."""
    os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(prefix="saqr-eval-"), "eval.db")
    for key in ("NEXTDNS_API_KEY", "NEXTDNS_PROFILE_ID", "VAPID_PRIVATE_KEY"):
        os.environ[key] = ""
    os.environ["CT_MODE"] = "off"
    os.environ["THREAT_FEEDS"] = "false"
    if not live:
        os.environ["OFFLINE_MODE"] = "true"
        os.environ["LLM_PROVIDER"] = "rules"


def score_model(urls: list[str]) -> list[tuple[float, list[str]]]:
    from saqr.intel import url_model
    out = []
    for u in urls:
        res = url_model.score_url(u)
        out.append((res["probability"], [r["en"] for r in res["reasons"]]) if res else (0.0, ["no model"]))
    return out


def system_result(url: str) -> tuple[float, list[str], str]:
    from saqr.intel.ai_inspector import run_rules
    from saqr.intel.domain_intel import analyze_lexical
    try:
        rr = run_rules(analyze_lexical(url), {}, None, None)
    except ValueError as exc:
        return 0.0, [f"not a URL: {exc}"], "SAFE"
    reasons = [f"{f.code}+{f.points}: {f.en}" for f in rr.flags if f.points > 0]
    return float(rr.score), reasons, rr.verdict


def score_system(urls: list[str]) -> list[tuple[float, list[str]]]:
    return [system_result(u)[:2] for u in urls]


def score_live(urls: list[str], concurrency: int, use_llm: bool) -> list[tuple[float, list[str]]]:
    from saqr import pipeline
    from saqr.db import db

    async def run() -> list[tuple[float, list[str]]]:
        await db.connect()
        sem = asyncio.Semaphore(concurrency)

        async def one(u: str) -> tuple[float, list[str]]:
            async with sem:
                try:
                    r = await asyncio.wait_for(pipeline.analyze_url(u, use_llm=use_llm, ingest=False,
                                                                     run_sandbox=False), 60)
                except Exception as exc:  # noqa: BLE001 - one bad URL must not end the run
                    return 0.0, [f"error: {type(exc).__name__}: {exc}"[:200]]
                return float(r["risk_score"]), [f"{f['code']}+{f['points']}: {f['en']}"
                                                for f in r["red_flags"] if f["points"] > 0]
        try:
            return await asyncio.gather(*(one(u) for u in urls))
        finally:
            await db.close()

    return asyncio.run(run())


def confusion(scores: list[float], labels: list[int], th: float) -> dict:
    tp = sum(1 for s, y in zip(scores, labels) if s >= th and y == 1)
    fp = sum(1 for s, y in zip(scores, labels) if s >= th and y == 0)
    fn = sum(1 for s, y in zip(scores, labels) if s < th and y == 1)
    tn = sum(1 for s, y in zip(scores, labels) if s < th and y == 0)
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    r4 = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"threshold": th, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": r4(prec), "recall": r4(rec),
            "f1": r4(f1), "fpr": r4(fp / (fp + tn)) if fp + tn else None,
            "accuracy": r4((tp + tn) / len(labels)) if labels else None}


def evaluate(rows: list[tuple[str, int, str]], mode: str = "model", threshold: float | None = None,
             concurrency: int = 8, use_llm: bool = False, worst: int = 20) -> dict:
    urls = [r[0] for r in rows]
    labels = [r[1] for r in rows]
    t = time.perf_counter()
    if mode == "model":
        scored = score_model(urls)
    elif mode == "system":
        scored = score_system(urls)
    else:
        scored = score_live(urls, concurrency, use_llm)
    ms = (time.perf_counter() - t) * 1000 / max(1, len(urls))
    scores = [s for s, _ in scored]
    if mode == "model":
        if threshold is None:
            from saqr.intel import ai_inspector
            threshold = ai_inspector.ML_STRONG
        points = [0.5, 0.7, 0.8, 0.9, 0.95, 0.98, 0.99]
    else:
        threshold = 65.0 if threshold is None else threshold
        points = [20, 30, 45, 65, 70, 85]
    main = confusion(scores, labels, threshold)
    order = sorted(range(len(rows)), key=lambda i: -scores[i])
    fps = [i for i in order if labels[i] == 0 and scores[i] >= threshold][:worst]
    fns = [i for i in reversed(order) if labels[i] == 1 and scores[i] < threshold][:worst]
    item = lambda i: {"url": urls[i], "label": labels[i], "source": rows[i][2], "score": round(scores[i], 4),  # noqa: E731
                      "reasons": scored[i][1]}
    report = {"mode": mode, "rows": len(rows), "phishing": sum(labels), "legit": len(labels) - sum(labels),
              "ms_per_url": round(ms, 3), **main,
              "pr_points": [confusion(scores, labels, p) for p in points],
              "worst_false_positives": [item(i) for i in fps], "worst_false_negatives": [item(i) for i in fns]}
    if mode != "model":
        report["at_suspicious_30"] = confusion(scores, labels, 30.0)
    return report


def print_report(rep: dict) -> None:
    print(f"mode {rep['mode']}  rows {rep['rows']} (phishing {rep['phishing']}, legit {rep['legit']})  "
          f"{rep['ms_per_url']} ms/URL")
    print(f"threshold {rep['threshold']}: precision {rep['precision']}  recall {rep['recall']}  F1 {rep['f1']}  "
          f"FPR {rep['fpr']}  accuracy {rep['accuracy']}")
    print(f"confusion: TP {rep['tp']}  FP {rep['fp']}  FN {rep['fn']}  TN {rep['tn']}")
    if "at_suspicious_30" in rep:
        s = rep["at_suspicious_30"]
        print(f"at SUSPICIOUS (30): precision {s['precision']}  recall {s['recall']}  F1 {s['f1']}  FPR {s['fpr']}")
    print("PR points:")
    for p in rep["pr_points"]:
        print(f"  >= {p['threshold']}: P {p['precision']}  R {p['recall']}  F1 {p['f1']}  FPR {p['fpr']}")
    for key, title in (("worst_false_positives", "worst false positives"), ("worst_false_negatives", "worst false negatives")):
        print(f"{title} ({len(rep[key])}):")
        for it in rep[key]:
            print(f"  {it['score']:>7}  {it['url'][:110]}  [{it['source']}]")
            for r in it["reasons"][:3]:
                print(f"           - {r[:140]}")


HOLDOUT_DIR = ROOT / "datasets" / "holdout"
METRICS_PATH = ROOT / "saqr" / "intel" / "data" / "model_metrics.json"


def _brief(c: dict) -> dict:
    return {k: c[k] for k in ("threshold", "precision", "recall", "f1", "fpr", "tp", "fp", "fn", "tn")}


def suite(baseline: str | None) -> dict:
    """Model + end-to-end offline system on the fixed holdout sets -> summary in model_metrics.json."""
    from saqr.intel import ai_inspector
    sets = {p.stem: load_labelled(p, url_col="url", label_col="label", positive={"1"}, quiet=True)
            for p in sorted(HOLDOUT_DIR.glob("*.csv"))}
    if not sets:
        raise SystemExit("no holdout sets: run tools/train_url_model.py --build-holdout first")
    system: dict = {}
    model: dict = {}
    for name, rows in sets.items():
        sysrep = evaluate(rows, "system", 65.0)
        system[name] = {"rows": len(rows), "phishing": sysrep["phishing"], "block_65": _brief(sysrep),
                        "warn_30": _brief(sysrep["at_suspicious_30"])}
        modrep = evaluate(rows, "model", ai_inspector.ML_STRONG)
        model[name] = {"rows": len(rows), "phishing": modrep["phishing"], **_brief(modrep)}
        if name == "fp_suite":
            by: dict = {}
            for (u, y, src), rec in zip(rows, [system_result(u) for u, _, _ in rows]):
                b = by.setdefault(src, {"rows": 0, "warn_30": 0, "block_65": 0})
                b["rows"] += 1
                b["warn_30"] += rec[0] >= 30
                b["block_65"] += rec[0] >= 65
            system[name]["by_source"] = by
        print(f"{name:16s} rows {len(rows):6d}  model@{round(ai_inspector.ML_STRONG, 3)} P {model[name]['precision']} "
              f"R {model[name]['recall']} FPR {model[name]['fpr']} | system block P {system[name]['block_65']['precision']} "
              f"R {system[name]['block_65']['recall']} FPR {system[name]['block_65']['fpr']} | warn "
              f"P {system[name]['warn_30']['precision']} R {system[name]['warn_30']['recall']} "
              f"FPR {system[name]['warn_30']['fpr']}", flush=True)
    stored = json.loads(METRICS_PATH.read_text(encoding="utf-8")) if METRICS_PATH.exists() else {}
    before = None
    if baseline:
        before = json.loads(Path(baseline).read_text(encoding="utf-8")).get("system", {}).get("after")
    h = model.get("hannousse", {})
    stored["holdout"] = {"name": "hannousse (Hannousse & Yahiouche 2021, never trained on)", "rows": h.get("rows"),
                         "precision": h.get("precision"), "recall": h.get("recall"), "f1": h.get("f1"),
                         "fpr": h.get("fpr"), "threshold": h.get("threshold")}
    fr = model.get("fresh_phishing", {})
    stored["fresh_phishing"] = {"rows": fr.get("rows"), "recall_model": fr.get("recall"),
                                "recall_system_block": system.get("fresh_phishing", {}).get("block_65", {}).get("recall"),
                                "recall_system_warn": system.get("fresh_phishing", {}).get("warn_30", {}).get("recall")}
    fp = sets.get("fp_suite", [])
    stored["fp_suite"] = {"rows": len(fp), "false_positives": model.get("fp_suite", {}).get("fp"),
                          "false_positives_system_warn": system.get("fp_suite", {}).get("warn_30", {}).get("fp"),
                          "false_positives_system_block": system.get("fp_suite", {}).get("block_65", {}).get("fp"),
                          "by_source": system.get("fp_suite", {}).get("by_source")}
    stored["system"] = {"engine": "analyze_lexical + run_rules(lex, {}, None, None), offline, no LLM / feeds",
                        "after": system, "before": before, "model_at_strong": model}
    METRICS_PATH.parent.mkdir(parents=True, exist_ok=True)
    METRICS_PATH.write_text(json.dumps(stored, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    return stored


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dataset", nargs="?")
    ap.add_argument("--suite", action="store_true", help="run the fixed holdout sets, update model_metrics.json")
    ap.add_argument("--baseline", help="--suite: an older model_metrics.json whose system numbers are 'before'")
    ap.add_argument("--url-col")
    ap.add_argument("--label-col")
    ap.add_argument("--positive", help="comma-separated raw label values meaning phishing")
    ap.add_argument("--label", type=int, choices=(0, 1), help="every row has this label (plain lists)")
    ap.add_argument("--mode", choices=("model", "system", "live"), default="model")
    ap.add_argument("--threshold", type=float)
    ap.add_argument("--limit", type=int)
    ap.add_argument("--concurrency", type=int, default=8)
    ap.add_argument("--llm", action="store_true", help="live mode: allow the LLM judge")
    ap.add_argument("--out")
    args = ap.parse_args()
    _isolate(args.mode == "live")
    if args.suite:
        suite(args.baseline)
        return
    if not args.dataset:
        ap.error("dataset is required (or --suite)")
    rows = load_labelled(args.dataset, url_col=args.url_col, label_col=args.label_col,
                         positive=set(args.positive.split(",")) if args.positive else None, label=args.label,
                         limit=args.limit)
    rep = evaluate(rows, args.mode, args.threshold, args.concurrency, args.llm)
    rep["dataset"] = str(args.dataset)
    print_report(rep)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
