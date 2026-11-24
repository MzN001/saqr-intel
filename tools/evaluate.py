"""Evaluate SAQR on ANY labelled URL dataset (runs in the normal runtime venv, standard library only).

    python tools/evaluate.py datasets/hannousse/dataset_B_05_2020.csv
    python tools/evaluate.py my.csv --url-col link --label-col verdict --positive bad,phish --mode system
    python tools/evaluate.py feed.txt --label 1 --mode live --concurrency 20 --out report.json \
        --records live.jsonl                     # resumable: finished URLs are skipped on a re-run
    python tools/evaluate.py --rescore live.jsonl  # re-judge saved live evidence with the current rules

Modes:
  model   the trained URL model alone (url_model.score_url probability; --threshold 0..1)
  system  the offline engine a scan runs first: analyze_lexical + rules + model (score 0..100;
          --threshold in points, default 65 = HIGH-RISK; the 30-point SUSPICIOUS cut is reported too)
  live    the full pipeline.analyze_url: redirects / shorteners, WHOIS / DNS / TLS, the page fetched as a
          UAE phone and as a bot (cloaking), --feeds to load the live threat feeds into the scan, --llm to
          allow the AI judge. Throw-away database, no graph ingestion, NextDNS / push keys blanked,
          bounded concurrency and a per-URL timeout. Whatever --feeds says, the feeds are downloaded once
          and every host on a link's path is looked up, so the report gives both numbers: without feeds
          (the honest one when the URLs came from those feeds) and with them (a hit = score >= 70).
Prints precision, recall, F1, FPR, accuracy, the confusion matrix, PR points and the 20 worst
false positives / negatives with their reasons.
"""
from __future__ import annotations

import argparse
import asyncio
import contextvars
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


def _isolate(live: bool, use_llm: bool = False, browser: bool = False) -> None:
    """Never touch live accounts or the real database from an evaluation run (call before importing saqr:
    python-dotenv does not override variables that are already set)."""
    os.environ["DATABASE_PATH"] = os.path.join(tempfile.mkdtemp(prefix="saqr-eval-"), "eval.db")
    for key in ("NEXTDNS_API_KEY", "NEXTDNS_PROFILE_ID", "VAPID_PRIVATE_KEY", "POLICE_API_KEY", "GOOGLE_MAPS_API_KEY"):
        os.environ[key] = ""
    os.environ["CT_MODE"] = "off"
    os.environ["THREAT_FEEDS"] = "false"
    if not live:
        os.environ["OFFLINE_MODE"] = "true"
    if not use_llm:
        os.environ["LLM_PROVIDER"] = "rules"
        for key in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY"):
            os.environ[key] = ""
    if live and not browser:
        os.environ["ENABLE_PLAYWRIGHT"] = "false"  # the Render path: pages fetched over HTTP, no Chromium


def score_model(urls: list[str]) -> list[tuple[float, list[str]]]:
    from saqr.intel import url_model
    out = []
    for u in urls:
        res = url_model.score_url(u)
        out.append((res["probability"], [r["en"] for r in res["reasons"]]) if res else (0.0, ["no model"]))
    return out


def system_result(url: str) -> tuple[float, list[str], str]:
    from saqr.intel.ai_inspector import run_rules
    from saqr.intel.page_signals import lexical
    try:
        rr = run_rules(lexical(url), {}, None, None)
    except ValueError as exc:
        return 0.0, [f"not a URL: {exc}"], "SAFE"
    reasons = [f"{f.code}+{f.points}: {f.en}" for f in rr.flags if f.points > 0]
    return float(rr.score), reasons, rr.verdict


def score_system(urls: list[str]) -> list[tuple[float, list[str]]]:
    return [system_result(u)[:2] for u in urls]


FEED_POINTS = 70  # KNOWN_PHISHING_FEED alone: HIGH-RISK at both cuts
_evidence: contextvars.ContextVar[dict | None] = contextvars.ContextVar("saqr_eval_evidence", default=None)


def _capture_evidence() -> None:
    """Keep each scan's network + page evidence so --rescore can re-judge it later (sites die fast)."""
    from saqr import pipeline

    if getattr(pipeline, "_eval_capture", False):
        return
    gather, inspect = pipeline.gather_network, pipeline.sandbox.inspect

    async def gather_network(lex):
        net = await gather(lex)
        box = _evidence.get()
        if box is not None:
            box["net"] = net
        return net

    async def sandbox_inspect(url, domain, profile="mobile"):
        page = await inspect(url, domain, profile)
        box = _evidence.get()
        if box is not None:
            box["page"] = {k: v for k, v in page.items() if k != "screenshot_b64"}
            if isinstance(box["page"].get("html"), str):
                box["page"]["html"] = box["page"]["html"][:100_000]
        return page

    pipeline.gather_network = gather_network
    pipeline.sandbox.inspect = sandbox_inspect
    pipeline._eval_capture = True  # noqa: SLF001


async def load_feed_snapshot():
    """The live threat feeds, downloaded once, in a private instance (the scan only sees them with --feeds)."""
    from saqr.intel.threat_feeds import ThreatFeeds

    snap = ThreatFeeds()
    await snap.refresh()
    return snap


async def live_record(url: str, *, use_llm: bool, timeout: float, snap=None) -> dict:
    from saqr import pipeline

    box: dict = {}
    _evidence.set(box)
    t = time.perf_counter()
    rec: dict = {"url": url}
    try:
        r = await asyncio.wait_for(pipeline.analyze_url(url, use_llm=use_llm, ingest=False, run_sandbox=True,
                                                         channel="eval"), timeout)
    except Exception as exc:  # noqa: BLE001 - one bad URL must not end the run
        kind = "timeout" if isinstance(exc, asyncio.TimeoutError) else "error"
        rec.update(score=0.0, verdict=kind.upper(), error=f"{type(exc).__name__}: {exc}"[:200],
                   ms=int((time.perf_counter() - t) * 1000), flags=[], reasons=[])
        return rec
    ti = r["technical_indicators"]
    hosts = [r["input_domain"], r["domain"], *[h.get("host") for h in ti.get("redirect_chain") or []]]
    feed = next((f for h in dict.fromkeys(hosts) if h and (f := snap.lookup(h))), None) if snap else None
    rec.update(
        score=float(r["risk_score"]), verdict=r["verdict"], judged_url=r["normalized_url"],
        input_domain=r["input_domain"], domain=r["domain"], is_official=r["is_official_domain"],
        flags=[f["code"] for f in r["red_flags"] if f["points"] > 0],
        info_flags=[f["code"] for f in r["red_flags"] if f["points"] == 0],
        reasons=[f"{f['code']}+{f['points']}: {f['en']}" for f in r["red_flags"] if f["points"] > 0],
        sandbox_status=ti.get("sandbox_status"), http_status=ti.get("http_status"),
        page_title=(ti.get("page_title") or "")[:160], harvested=ti.get("harvested_fields") or [],
        dns_status=ti.get("dns_status"), domain_age_hours=ti.get("domain_age_hours"),
        hops=len(ti.get("redirect_chain") or []), feed=feed, ms=r["timings"].get("total_ms"),
        timings=r["timings"], engine=r["analyzer"]["engine"], evidence=box)
    return rec


def read_records(path: str | Path) -> dict[str, dict]:
    out: dict[str, dict] = {}
    p = Path(path)
    if p.exists():
        for line in p.read_text(encoding="utf-8").split("\n"):  # not splitlines(): pages contain U+2028
            if line.strip():
                rec = json.loads(line)
                out[rec["url"]] = rec
    return out


def run_live(urls: list[str], *, concurrency: int = 20, use_llm: bool = False, timeout: float = 45.0,
             feeds: bool = False, records: str | None = None, progress: bool = True) -> dict[str, dict]:
    """Scan every URL with the full pipeline; returns {url: record}. With records=path each finished
    URL is appended to that JSONL file at once and URLs already in it are not scanned again."""
    from saqr.db import db
    from saqr.intel import threat_feeds as tf

    done = read_records(records) if records else {}
    todo = [u for u in dict.fromkeys(urls) if u not in done]

    async def run() -> None:
        _capture_evidence()
        # SAQR_EVAL_NO_FEED_SNAPSHOT=1 (tests, offline runs): no feed download, no with-feeds view
        snap = await load_feed_snapshot() if not os.environ.get("SAQR_EVAL_NO_FEED_SNAPSHOT") else None
        if feeds and snap:
            tf.threat_feeds.hosts, tf.threat_feeds.counts = dict(snap.hosts), dict(snap.counts)
        await db.connect()
        sem = asyncio.Semaphore(concurrency)
        out = open(records, "a", encoding="utf-8") if records else None
        n = 0

        async def one(u: str) -> None:
            nonlocal n
            async with sem:
                rec = await live_record(u, use_llm=use_llm, timeout=timeout, snap=snap)
            rec["feeds_in_scan"] = feeds
            done[u] = rec
            if out:
                out.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
                out.flush()
            n += 1
            if progress and n % 25 == 0:
                print(f"  {n}/{len(todo)} scanned", flush=True)
        try:
            await asyncio.gather(*(one(u) for u in todo))
        finally:
            if out:
                out.close()
            await db.close()

    if todo:
        asyncio.run(run())
    return done


def rescore_record(rec: dict) -> tuple[float, list[str]]:
    """Re-judge a saved live scan with the current rules + model (same inputs, no network)."""
    from saqr.intel.ai_inspector import run_rules
    from saqr.intel.page_signals import lexical

    ev = rec.get("evidence") or {}
    if not rec.get("judged_url"):
        return float(rec.get("score") or 0.0), list(rec.get("reasons") or [])
    page = ev.get("page")
    if page and page.get("evidence_source") == "http_fallback" and page.get("html"):
        from saqr.intel.sandbox import sandbox
        # re-parse the saved HTML so form / field changes in the sandbox are measured too
        cloak = page.get("cloaking")
        page = sandbox._from_http_only({"status": page.get("http_status"), "final_url": page.get("final_url"),  # noqa: SLF001
                                        "title": page.get("page_title", ""), "text": page.get("text", ""),
                                        "html": page["html"]}, rec["judged_url"], time.perf_counter())
        page["cloaking"] = cloak
    rr = run_rules(lexical(rec["judged_url"]), ev.get("net") or {}, page, None)
    return float(rr.score), [f"{f.code}+{f.points}: {f.en}" for f in rr.flags if f.points > 0]


def with_feed(score: float, rec: dict) -> float:
    return max(score, FEED_POINTS) if rec.get("feed") else score


def score_live(urls: list[str], concurrency: int, use_llm: bool, timeout: float = 45.0, feeds: bool = False,
               records: str | None = None) -> list[tuple[float, list[str]]]:
    recs = run_live(urls, concurrency=concurrency, use_llm=use_llm, timeout=timeout, feeds=feeds, records=records)
    return [(float(recs[u]["score"]), recs[u].get("reasons") or [recs[u].get("error", "")]) for u in urls]


def miss_category(rec: dict) -> str:
    """Why a live scan missed (or why a legit site was flagged): a coarse bucket for the report."""
    from saqr.intel.threat_feeds import on_free_hosting

    if rec.get("verdict") in ("TIMEOUT", "ERROR"):
        return "scan timeout / error"
    if rec.get("dns_status") not in (None, "ok") and not (rec.get("evidence") or {}).get("net", {}).get("ip_addresses"):
        return "dead: no DNS"
    st = rec.get("sandbox_status")
    code = rec.get("http_status")
    if st != "ok" or code is None:
        return "dead: unreachable"
    if code >= 400:
        return f"dead / blocked: HTTP {code // 100}xx"
    host = rec.get("domain") or ""
    if on_free_hosting(host):
        return "platform-hosted page"
    if rec.get("harvested"):
        return "own domain, has a form (" + ",".join(rec["harvested"][:3]) + ")"
    return "own domain, benign-looking page"


def live_summary(rows: list[tuple[str, int, str]], recs: dict[str, dict], rescore: bool = False) -> dict:
    """Precision / recall / FPR at block and warn, with and without feeds, misses by category, timing."""
    labels = [y for _, y, _ in rows]
    base = []
    for u, _, _ in rows:
        rec = recs[u]
        base.append(rescore_record(rec)[0] if rescore else float(rec["score"]))
    if any(recs[u].get("feeds_in_scan") for u, _, _ in rows):
        nofeed = None  # the scan itself used the feeds: the no-feeds number needs a run without --feeds
    else:
        nofeed = base
    fed = [with_feed(s, recs[u]) for s, (u, _, _) in zip(base, rows)]
    out: dict = {"rows": len(rows), "phishing": sum(labels), "legit": len(labels) - sum(labels)}
    for name, scores in (("no_feeds", nofeed), ("with_feeds", fed)):
        if scores is not None:
            out[name] = {"block_65": _brief(confusion(scores, labels, 65.0)),
                         "warn_30": _brief(confusion(scores, labels, 30.0))}
    scores = nofeed if nofeed is not None else fed
    miss: dict[str, int] = {}
    false_alarm: dict[str, list[str]] = {}
    for (u, y, src), s in zip(rows, scores):
        if y == 1 and s < 30:
            c = miss_category(recs[u])
            miss[c] = miss.get(c, 0) + 1
        if y == 0 and s >= 30:
            false_alarm.setdefault(src, []).append(f"{s:.0f} {u}")
    out["phishing_missed_at_warn_by_category"] = dict(sorted(miss.items(), key=lambda kv: -kv[1]))
    out["false_alarms_at_warn_by_source"] = false_alarm
    by_src: dict[str, dict] = {}
    for (u, y, src), s in zip(rows, scores):
        b = by_src.setdefault(src.split("_20")[0], {"rows": 0, "label": y, "warn_30": 0, "block_65": 0})
        b["rows"] += 1
        b["warn_30"] += s >= 30
        b["block_65"] += s >= 65
    out["by_source"] = by_src
    ms = sorted(int(recs[u].get("ms") or 0) for u, _, _ in rows)
    if ms:
        out["scan_ms"] = {"median": ms[len(ms) // 2], "p95": ms[min(len(ms) - 1, int(len(ms) * 0.95))],
                          "max": ms[-1]}
    out["errors"] = sum(1 for u, _, _ in rows if recs[u].get("verdict") in ("TIMEOUT", "ERROR"))
    out["feed_hits"] = {"phishing": sum(1 for u, y, _ in rows if y == 1 and recs[u].get("feed")),
                        "legit": sum(1 for u, y, _ in rows if y == 0 and recs[u].get("feed"))}
    return out


def print_live(summary: dict) -> None:
    print(f"live rows {summary['rows']} (phishing {summary['phishing']}, legit {summary['legit']}), "
          f"errors {summary['errors']}, feed hits {summary['feed_hits']}, scan ms {summary.get('scan_ms')}")
    for name in ("no_feeds", "with_feeds"):
        if name in summary:
            for cut in ("block_65", "warn_30"):
                c = summary[name][cut]
                print(f"  {name:10s} {cut:8s} P {c['precision']}  R {c['recall']}  FPR {c['fpr']}  "
                      f"(TP {c['tp']} FP {c['fp']} FN {c['fn']} TN {c['tn']})")
    print("  missed phishing (warn) by category:", json.dumps(summary["phishing_missed_at_warn_by_category"]))
    for src, items in summary["false_alarms_at_warn_by_source"].items():
        print(f"  false alarms [{src}]: {len(items)}")
        for it in items[:8]:
            print(f"     {it[:130]}")


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
             concurrency: int = 20, use_llm: bool = False, worst: int = 20, timeout: float = 45.0,
             feeds: bool = False, records: str | None = None) -> dict:
    urls = [r[0] for r in rows]
    labels = [r[1] for r in rows]
    t = time.perf_counter()
    if mode == "model":
        scored = score_model(urls)
    elif mode == "system":
        scored = score_system(urls)
    else:
        scored = score_live(urls, concurrency, use_llm, timeout, feeds, records)
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


def store_live(summary: dict, dataset: str, use_llm: bool) -> None:
    stored = json.loads(METRICS_PATH.read_text(encoding="utf-8")) if METRICS_PATH.exists() else {}
    keep = ("rows", "phishing", "legit", "no_feeds", "with_feeds", "phishing_missed_at_warn_by_category",
            "scan_ms", "errors", "feed_hits", "by_source")
    stored["live"] = {"date": time.strftime("%Y-%m-%d", time.gmtime()), "sample": Path(dataset).name,
                      "engine": "pipeline.analyze_url (redirects, WHOIS/DNS/TLS, HTTP page fetch + two-view cloaking, "
                                + ("LLM" if use_llm else "no LLM") + "); ENABLE_PLAYWRIGHT=false",
                      **{k: summary[k] for k in keep if k in summary}}
    METRICS_PATH.write_text(json.dumps(stored, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


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
    ap.add_argument("--concurrency", type=int, default=20)
    ap.add_argument("--llm", action="store_true", help="live mode: allow the LLM judge")
    ap.add_argument("--feeds", action="store_true", help="live mode: the scan itself uses the live threat feeds")
    ap.add_argument("--browser", action="store_true", help="live mode: use Chromium if installed (default: HTTP only)")
    ap.add_argument("--timeout", type=float, default=45.0, help="live mode: seconds per URL")
    ap.add_argument("--records", help="live mode: JSONL of per-URL results + evidence (resumable)")
    ap.add_argument("--rescore", help="re-judge a --records file with the current rules (labels from DATASET)")
    ap.add_argument("--live-metrics", action="store_true", help="live mode: store the summary in model_metrics.json")
    ap.add_argument("--out")
    args = ap.parse_args()
    _isolate(args.mode == "live" and not args.rescore, args.llm, args.browser)
    if args.suite:
        suite(args.baseline)
        return
    if not args.dataset:
        ap.error("dataset is required (or --suite)")
    rows = load_labelled(args.dataset, url_col=args.url_col, label_col=args.label_col,
                         positive=set(args.positive.split(",")) if args.positive else None, label=args.label,
                         limit=args.limit)
    if args.rescore:
        recs = read_records(args.rescore)
        rows = [r for r in rows if r[0] in recs]
        summary = live_summary(rows, recs, rescore=True)
        print_live(summary)
        if args.out:
            Path(args.out).write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    if args.mode == "live":
        recs = run_live([r[0] for r in rows], concurrency=args.concurrency, use_llm=args.llm, timeout=args.timeout,
                        feeds=args.feeds, records=args.records)
        summary = live_summary(rows, recs)
        print_live(summary)
        if args.live_metrics:
            store_live(summary, str(args.dataset), args.llm)
        if args.out:
            Path(args.out).write_text(json.dumps(summary, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
        return
    rep = evaluate(rows, args.mode, args.threshold, args.concurrency, args.llm)
    rep["dataset"] = str(args.dataset)
    print_report(rep)
    if args.out:
        Path(args.out).write_text(json.dumps(rep, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
