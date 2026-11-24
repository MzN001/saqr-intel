"""Old vs new URL model on the SAME validation split and holdout sets, plus the pre-agreed decision rule.

  .venv/Scripts/python -I tools/compare_models.py --old <dir> --new datasets/candidate --out cmp.json [--apply]

Each model directory holds url_model.bin, url_model_trees.json (optional) and model_metrics.json (its
thresholds). Scoring is the shipped pure-Python runtime (saqr.intel.url_model, ai_inspector.run_rules on
analyze_lexical: offline, no network, no LLM, no feeds), one process pool per model.

Per model: thresholds re-picked on the VALIDATION split (legitimate rows the server would judge, at 0.1% /
0.5% / 2% reach = certain / strong / suspect, the rates the shipped thresholds were chosen at), model
precision / recall / FPR at each of them on every set, the offline system's block (>= 65) / warn (>= 30)
numbers at the model's own shipped thresholds, false alarms per FP-suite source, and a calibration table
fitted on validation (isotonic vs Platt by cross-fitting) with ECE / Brier before and after.
Holdout sets are also reported on the "sealed_v1" subset: sites sealed in round 1, which neither model
can have trained on.

Decision rule (fixed before the comparison was run):
  new replaces old only if, on VALIDATION, recall at the strong threshold improves at an equal-or-lower FPR,
  AND the false-positive suite does not get worse (system warn and block false alarms, full suite and the
  sealed_v1 subset), AND the UAE official / bank subsets keep 0 false alarms (warn and block).
--apply installs the winner's files into saqr/intel/ and writes the calibration of the shipped model into
saqr/intel/data/model_metrics.json (a kept old model keeps its thresholds).
"""
from __future__ import annotations

import argparse
import gzip
import json
import os
import shutil
import sys
import time
from multiprocessing import Pool
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))

import calibration as cal  # noqa: E402

DATA = ROOT / "datasets"
HOLDOUT_DIR = DATA / "holdout"
VALIDATION = DATA / "splits" / "validation.csv"
SEALED_V1 = ROOT / "tools" / "holdout_sites_v1.txt.gz"
INTEL = ROOT / "saqr" / "intel"
RATES = {"certain": 0.001, "strong": 0.005, "suspect": 0.02}
UAE_BANK_SOURCES = ("harvest_uae_official", "harvest_brand_official", "fp_extra_bank_gov")


def _init(model_dir: str) -> None:
    import evaluate
    evaluate._isolate(False)  # noqa: SLF001 - offline, keys blanked, temp DB
    evaluate.use_model_dir(model_dir)
    from saqr.intel import ai_inspector  # noqa: F401 - reads the thresholds of THIS model at import


def _score(url: str) -> tuple[float, float, bool, str]:
    from saqr.intel import url_model as um
    from train_url_model import judged, site_of
    from evaluate import system_result
    res = um.score_url(url)
    sysscore = system_result(url)[0]
    return (res["probability"] if res else 0.0), sysscore, judged(url), site_of(url)


def score_all(model_dir: Path, urls: list[str], workers: int) -> list[tuple[float, float, bool, str]]:
    with Pool(workers, initializer=_init, initargs=(str(model_dir),)) as pool:
        return pool.map(_score, urls, chunksize=500)


def load_rows(path: Path) -> list[tuple[str, int, str]]:
    import csv
    with open(path, encoding="utf-8", newline="") as f:
        return [(r["url"], int(r["label"]), r["source"]) for r in csv.DictReader(f)]


def threshold_for_rate(legit_scores: list[float], rate: float) -> float:
    s = sorted(legit_scores, reverse=True)
    k = int(rate * len(s))
    return float(min(0.999, max(0.5, s[k] + 1e-6 if k < len(s) else 0.5)))


def conf(scores, labels, th) -> dict:
    tp = sum(1 for s, y in zip(scores, labels) if s >= th and y == 1)
    fp = sum(1 for s, y in zip(scores, labels) if s >= th and y == 0)
    fn = sum(1 for s, y in zip(scores, labels) if s < th and y == 1)
    tn = sum(1 for s, y in zip(scores, labels) if s < th and y == 0)
    r = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"threshold": round(th, 6), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": r(tp / (tp + fp)) if tp + fp else None, "recall": r(tp / (tp + fn)) if tp + fn else None,
            "fpr": r(fp / (fp + tn)) if fp + tn else None}


def report_model(name: str, model_dir: Path, sets: dict, workers: int) -> dict:
    t = time.time()
    shipped = json.loads((model_dir / "model_metrics.json").read_text(encoding="utf-8"))["thresholds"]
    urls = list(dict.fromkeys(u for rows in sets.values() for u, _, _ in rows))
    scored = dict(zip(urls, score_all(model_dir, urls, workers)))
    print(f"[{name}] scored {len(urls):,} URLs in {time.time() - t:.0f}s", flush=True)
    val = sets["validation"]
    legit = [scored[u][0] for u, y, _ in val if y == 0 and scored[u][2]]
    th = {k: threshold_for_rate(legit, r) for k, r in RATES.items()}
    out: dict = {"dir": str(model_dir), "thresholds_shipped": shipped, "thresholds_validation": th,
                 "validation_threshold_pool_rows": len(legit), "sets": {}}
    for sname, rows in sets.items():
        p = [scored[u][0] for u, _, _ in rows]
        sy = [scored[u][1] for u, _, _ in rows]
        y = [lab for _, lab, _ in rows]
        rep = {"rows": len(rows), "phishing": sum(y),
               "model_at_validation_thresholds": {k: conf(p, y, v) for k, v in th.items()},
               "model_at_shipped_thresholds": {k: conf(p, y, float(shipped[k])) for k in RATES},
               "system_block_65": conf(sy, y, 65.0), "system_warn_30": conf(sy, y, 30.0)}
        if sname.startswith("fp_suite") or sname.startswith("validation_news"):
            by: dict = {}
            for (u, lab, src), pp, ss in zip(rows, p, sy):
                b = by.setdefault(src, {"rows": 0, "model_fp_strong": 0, "model_fp_suspect": 0, "warn_30": 0,
                                        "block_65": 0})
                b["rows"] += 1
                b["model_fp_strong"] += lab == 0 and pp >= th["strong"] and scored[u][2]
                b["model_fp_suspect"] += lab == 0 and pp >= th["suspect"] and scored[u][2]
                b["warn_30"] += lab == 0 and ss >= 30
                b["block_65"] += lab == 0 and ss >= 65
            rep["by_source"] = by
        out["sets"][sname] = rep
    # Calibration fitted on validation (rows the server would judge), cross-fitted method choice.
    jv = [(scored[u][0], y, scored[u][3]) for u, y, _ in val if scored[u][2]]
    table, crep = cal.choose([a for a, _, _ in jv], [b for _, b, _ in jv], [c for _, _, c in jv])
    for sname, rows in sets.items():
        if sname == "validation":
            continue
        p = [scored[u][0] for u, _, _ in rows]
        y = [lab for _, lab, _ in rows]
        crep[sname] = {"raw": cal.reliability(p, y), "calibrated": cal.reliability([cal.apply(table, v) for v in p], y)}
    out["calibration"] = {"table": table, "report": crep}
    return out


def decide(old: dict, new: dict) -> dict:
    ov, nv = (m["sets"]["validation"]["model_at_validation_thresholds"]["strong"] for m in (old, new))
    checks = {"validation_recall_strong_improves": (nv["recall"] or 0) > (ov["recall"] or 0),
              "validation_fpr_strong_not_higher": (nv["fpr"] or 0) <= (ov["fpr"] or 0)}
    for s in ("fp_suite", "fp_suite@sealed_v1"):
        if s in new["sets"]:
            for cut in ("system_warn_30", "system_block_65"):
                checks[f"{s}_{cut}_fp_not_worse"] = new["sets"][s][cut]["fp"] <= old["sets"][s][cut]["fp"]
    by = new["sets"]["fp_suite"].get("by_source", {})
    checks["uae_official_bank_false_alarms_zero"] = all(
        by.get(src, {}).get("warn_30", 0) == 0 and by.get(src, {}).get("block_65", 0) == 0 for src in UAE_BANK_SOURCES)
    return {"checks": checks, "replace": all(checks.values()),
            "old_validation_strong": ov, "new_validation_strong": nv}


def table_rows(old: dict, new: dict) -> list[str]:
    lines = ["| set | model | P@strong | R@strong | FPR@strong | R@suspect | FPR@suspect | R@certain | FPR@certain | "
             "sys warn FP | sys block FP | sys warn R |", "|" + "---|" * 12]
    for sname in new["sets"]:
        for tag, m in (("old", old), ("new", new)):
            s = m["sets"][sname]
            v = s["model_at_validation_thresholds"]
            f = lambda x: "-" if x is None else f"{x:.4f}"  # noqa: E731
            lines.append(f"| {sname} | {tag} | {f(v['strong']['precision'])} | {f(v['strong']['recall'])} | "
                         f"{f(v['strong']['fpr'])} | {f(v['suspect']['recall'])} | {f(v['suspect']['fpr'])} | "
                         f"{f(v['certain']['recall'])} | {f(v['certain']['fpr'])} | {s['system_warn_30']['fp']} | "
                         f"{s['system_block_65']['fp']} | {f(s['system_warn_30']['recall'])} |")
    return lines


def install(winner: str, old_dir: Path, new_dir: Path, result: dict) -> None:
    metrics_path = INTEL / "data" / "model_metrics.json"
    stored = json.loads(metrics_path.read_text(encoding="utf-8"))
    src = new_dir if winner == "new" else old_dir
    rep = result["new" if winner == "new" else "old"]
    if winner == "new":
        for fname in ("url_model.bin", "url_model_trees.json"):
            if (src / fname).exists():
                shutil.copyfile(src / fname, INTEL / fname)
            elif (INTEL / fname).exists():
                (INTEL / fname).unlink()
        shutil.copyfile(src / "url_model_vectors.json", ROOT / "tests" / "fixtures" / "url_model_vectors.json")
        cand = json.loads((src / "model_metrics.json").read_text(encoding="utf-8"))
        prev = {k: stored[k] for k in ("live", "round2") if k in stored}
        stored = {**cand, "training_cutoff": stored.get("training_cutoff"),
                  "previous_model_measurements": {"note": "measured with model 2.0 (2026-11-24); not re-run",
                                                  **prev}}
    from saqr.intel import url_model as um
    um.MODEL_PATH, um.TREES_PATH = INTEL / "url_model.bin", INTEL / "url_model_trees.json"
    stored["calibration"] = {**rep["calibration"]["table"], "fitted_on": "validation split (datasets/splits/"
                             "validation.csv), rows the server would judge", "model_sha256": um.model_fingerprint(),
                             "report": rep["calibration"]["report"],
                             "note": "calibrated_probability = validation frequency of phishing at that raw score "
                                     "(validation is ~half phishing: real-world prevalence is far lower). "
                                     "Thresholds apply to the RAW score."}
    stored["retrain_comparison"] = {"date": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "winner": winner,
                                    "decision": result["decision"],
                                    "old": {k: result["old"][k] for k in ("thresholds_shipped", "thresholds_validation")},
                                    "new": {k: result["new"][k] for k in ("thresholds_shipped", "thresholds_validation")},
                                    "sets": {s: {"old": result["old"]["sets"][s], "new": result["new"]["sets"][s]}
                                             for s in result["new"]["sets"]}}
    metrics_path.write_text(json.dumps(stored, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--old", required=True)
    ap.add_argument("--new", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 2))
    ap.add_argument("--apply", action="store_true")
    args = ap.parse_args()
    sets = {"validation": load_rows(VALIDATION)}
    sets["validation_news_hardneg"] = [r for r in sets["validation"] if r[2].startswith("hardneg_")]
    with gzip.open(SEALED_V1, "rt", encoding="utf-8") as f:
        sealed = {line.strip() for line in f if line.strip()}
    from train_url_model import site_of
    for p in sorted(HOLDOUT_DIR.glob("*.csv")):
        rows = load_rows(p)
        sets[p.stem] = rows
        sets[f"{p.stem}@sealed_v1"] = [r for r in rows if site_of(r[0]) in sealed]
    print({k: len(v) for k, v in sets.items()}, flush=True)
    result = {"old": report_model("old", Path(args.old), sets, args.workers),
              "new": report_model("new", Path(args.new), sets, args.workers)}
    result["decision"] = decide(result["old"], result["new"])
    Path(args.out).write_text(json.dumps(result, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print("\n".join(table_rows(result["old"], result["new"])))
    print(json.dumps(result["decision"], indent=1))
    for tag in ("old", "new"):
        c = result[tag]["calibration"]["report"]
        print(tag, "calibration", json.dumps({k: c[k] for k in ("raw", "isotonic", "platt", "chosen")}))
    if args.apply:
        install("new" if result["decision"]["replace"] else "old", Path(args.old), Path(args.new), result)
        print("installed:", "new" if result["decision"]["replace"] else "old (kept)")


if __name__ == "__main__":
    main()
