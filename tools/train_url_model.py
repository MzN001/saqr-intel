"""Train SAQR's phishing URL model v2 -> saqr/intel/url_model.bin (+ url_model_trees.json, model_metrics.json)

Train on any set of labelled datasets (any format tools/url_datasets.py reads) plus the built-in recipe:

    .venv-train/Scripts/python -I tools/train_url_model.py              # Windows: candidate -> datasets/candidate/
    .venv/Scripts/python -I tools/compare_models.py --old <backup> --new datasets/candidate --out c.json --apply
    .venv-train/bin/py -I tools/train_url_model.py                      # built-in recipe (datasets/)
    .venv-train/bin/py -I tools/train_url_model.py --data extra.csv --data feed.txt:1 --no-recipe
    .venv/bin/python tools/train_url_model.py --build-holdout            # (re)write the fixed holdout sets

--data PATH[:LABEL] adds a file (LABEL 0/1 for plain lists without a label column).
Needs numpy, scipy, scikit-learn, lightgbm (developer machine only; the server runs pure Python).

Honest evaluation: the holdout sets (a whole dataset never trained on, the newest phishing feeds, a
false-positive suite of real UAE / bank / long-tail sites, evasion variants of holdout URLs) are
written to datasets/holdout/ and every site in them (registered domain, or full host on a free-hosting
platform) is listed in tools/holdout_sites.txt.gz and dropped from training. Validation is split by
site, never by URL, so the same domain is never on both sides.

Known data biases this recipe neutralises: in PhiUSIIL every legit URL is a bare homepage, and the
host-only feeds (Tranco, Phishing Army, Phishing.Database domains) have no paths, so those sources are
trained as bare hosts: path / query evidence is learnt only from sources where both classes have paths.
Scheme, "www." and default ports are dropped (collection artefacts). Synthetic rows get a capped weight.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import random
import struct
import sys
import time
import zlib
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tools"))
def _runtime_site_packages() -> list[Path]:
    """site-packages of the runtime venv, for saqr imports (tldextract, dotenv, phonenumbers) when they are
    not installed in the training venv. Linux layout .venv/lib/pythonX.Y/site-packages, Windows layout
    .venv/Lib/site-packages; only used when the runtime venv runs the SAME Python minor version (compiled
    packages from another version would not load)."""
    ver = f"python{sys.version_info.major}.{sys.version_info.minor}"
    out = [ROOT / ".venv" / "lib" / ver / "site-packages"]
    cfg = ROOT / ".venv" / "pyvenv.cfg"
    if os.name == "nt" and cfg.exists():
        text = cfg.read_text(encoding="utf-8", errors="replace")
        if f"version = {sys.version_info.major}.{sys.version_info.minor}." in text \
                or f"version_info = {sys.version_info.major}.{sys.version_info.minor}." in text:
            out.append(ROOT / ".venv" / "Lib" / "site-packages")
    return [p for p in out if p.is_dir()]


for _site in _runtime_site_packages():
    sys.path.append(str(_site))  # appended: the training venv's own packages win

from url_datasets import load_labelled  # noqa: E402
from saqr.intel import url_features as uf  # noqa: E402
from saqr.intel import url_model as um  # noqa: E402

DATA = ROOT / "datasets"
HOLDOUT_DIR = DATA / "holdout"
EXCLUDE_PATH = ROOT / "tools" / "holdout_sites.txt.gz"
EXCLUDE_V1_PATH = ROOT / "tools" / "holdout_sites_v1.txt.gz"  # sites sealed in round 1 (2026-11-24 model)
CANDIDATE_DIR = DATA / "candidate"
SPLITS_DIR = DATA / "splits"
CUTOFF_UTC = "2026-11-24T21:10:00Z"  # training cut-off, also in model_metrics.json "training_cutoff"
METRICS_PATH = ROOT / "saqr" / "intel" / "data" / "model_metrics.json"
VECTORS_PATH = ROOT / "tests" / "fixtures" / "url_model_vectors.json"
SEED = 20261124

# Real login / service pages of banks, payment and government sites (checked by hand, 2026-11-24).
FP_EXTRA = (
    "https://www.adcb.com/en/personal/", "https://www.adcb.com/en/personal/accounts/", "https://www.bankfab.com/en-ae/personal",
    "https://www.bankfab.com/en-ae/personal/cards/credit-cards", "https://www.emiratesnbd.com/en/personal-banking",
    "https://www.mashreq.com/en/uae/neo/", "https://www.adib.ae/en/personal", "https://www.adib.ae/en/pages/online-banking.aspx",
    "https://www.tamm.abudhabi/en/life-events/individual/traffic-fines", "https://www.tamm.abudhabi/en/aspects-of-life/housing",
    "https://uaepass.ae/", "https://uaepass.ae/faq", "https://www.adpolice.gov.ae/en/Pages/home.aspx",
    "https://es.adpolice.gov.ae/TrafficServices/FinesPublic/Inquiry.aspx", "https://www.emiratespost.ae/en/track-shipment",
    "https://www.etisalat.ae/en/c/mobile/postpaid.html", "https://www.etisalat.ae/b2c/eshop/viewbill?locale=EN",
    "https://www.du.ae/personal/mobile", "https://www.du.ae/self-care/login", "https://u.ae/en/information-and-services",
    "https://www.dubaipolice.gov.ae/wps/portal/home/services/individualservices/trafficfinespayment",
    "https://www.rta.ae/wps/portal/rta/ae/home/rta-services", "https://icp.gov.ae/en/", "https://smartservices.icp.gov.ae/echannels/web/client/default.html#/login",
    "https://mohre.gov.ae/en/home.aspx", "https://www.dewa.gov.ae/en/consumer/billing/easy-pay",
    "https://www.paypal.com/signin", "https://www.paypal.com/myaccount/summary", "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id=4765445b",
    "https://outlook.live.com/mail/0/", "https://accounts.google.com/signin/v2/identifier?service=mail",
    "https://appleid.apple.com/sign-in", "https://www.icloud.com/mail", "https://secure.chase.com/web/auth/dashboard",
    "https://connect.secure.wellsfargo.com/auth/login/present", "https://www.bankofamerica.com/online-banking/sign-in/",
    "https://www.hsbc.ae/online/", "https://online.citi.com/US/login.do", "https://www.amazon.ae/ap/signin?openid.pape.max_auth_age=0",
    "https://www.netflix.com/login", "https://www.facebook.com/login/", "https://www.instagram.com/accounts/login/",
    "https://www.linkedin.com/login", "https://www.dhl.com/ae-en/home/tracking.html", "https://www.aramex.com/ae/en/track/shipments",
    "https://www.fedex.com/fedextrack/?trknbr=123456789012", "https://www.binance.com/en/login", "https://www.coinbase.com/signin",
    "https://wise.com/login/", "https://www.revolut.com/app/", "https://www.noon.com/uae-en/account_mobile/",
    "https://www.careem.com/en-ae/", "https://www.emirates.com/ae/english/manage-booking/", "https://www.etihad.com/en-ae/manage",
)
HOLDOUT_EVASION = {"hannousse+evasion", "hannousse_free_hosting+evasion", "hannousse_lure_host+evasion",
                   "hf_pirocheto+evasion", "jpcert+evasion", "phishtank+evasion", "openphish+evasion"}
FRESH_JPCERT = ("202608.csv", "202609.csv")
# Per-source caps (rows) and how the source is used. "host": train as a bare host (no path evidence).
RECIPE = (
    ("hf_phreshphish/urls.csv", 180_000, "full"),
    ("phiusiil/PhiUSIIL_Phishing_URL_Dataset.csv", 90_000, "host"),
    ("phishing_army/phishing_army_blocklist.txt", 40_000, "host"),
    ("phishing_database/phishing-links-ACTIVE.txt", 70_000, "full"),
    ("phishing_database/phishing-domains-ACTIVE.txt", 25_000, "host"),
    ("hf_kmack/urls.csv", 50_000, "full"),
    ("hf_ealvaradob/urls.json", 30_000, "full"),
    ("augmented/legit_lure_hosts.csv", None, "full"),
    ("augmented/synthetic_phishing.csv", None, "full"),
    ("augmented/legit_hard_negatives.csv", None, "full"),  # tools/collect_hard_negatives.py (round 2)
)
HARDNEG_VAL_SHARE = 25  # percent of hard-negative SITES held out as the news / advisory validation slice
TRANCO_TRAIN = 100_000
SYNTHETIC_WEIGHT = 0.3
EVASION_WEIGHT = 0.5
EVASION_TRAIN = 30_000
VAL_SHARE = 10  # percent of sites (by hash) in the grouped validation split


def site_of(url: str) -> str:
    return uf.parse(url).site


def bucket(key: str, mod: int = 100) -> int:
    return zlib.crc32(key.encode("utf-8", "ignore")) % mod


def host_only(url: str) -> str:
    p = uf.parse(url)
    return "http://" + p.host + "/"


def _tranco() -> list[tuple[int, str]]:
    with open(DATA / "tranco" / "top-1m.csv", encoding="utf-8") as f:
        return [(int(r), d.strip().lower()) for r, d in csv.reader(f) if d]


def _write(rows, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "label", "source"])
        w.writerows(rows)


def _read(path: Path) -> list[tuple[str, int, str]]:
    with open(path, encoding="utf-8", newline="") as f:
        return [(r["url"], int(r["label"]), r["source"]) for r in csv.DictReader(f)]


# ---------------------------------------------------------------------------------------------------------
# Holdout sets
# ---------------------------------------------------------------------------------------------------------
def build_holdout() -> dict[str, int]:
    rng = random.Random(SEED)
    sets: dict[str, list] = {}
    sets["hannousse"] = load_labelled(DATA / "hannousse" / "dataset_B_05_2020.csv", quiet=True)
    fresh = []
    for name in FRESH_JPCERT:
        fresh += [(u, 1, f"jpcert_{name[:6]}") for u, _, _ in load_labelled(DATA / "jpcert" / name, quiet=True)]
    fresh += load_labelled(DATA / "openphish" / "feed.txt", quiet=True)
    fresh += load_labelled(DATA / "phishtank" / "online-valid.csv", quiet=True)
    sets["fresh_phishing"] = fresh

    fp = []
    deep = load_labelled(DATA / "augmented" / "legit_deep_links.csv", quiet=True)
    for u, lab, src in deep:
        if lab == 0 and (src in ("harvest_uae_official", "harvest_brand_official") or bucket(site_of(u)) < 20):
            fp.append((u, 0, src))
    for u, lab, src in load_labelled(DATA / "augmented" / "legit_free_hosting.csv", quiet=True):
        if lab == 0 and not src.startswith("hannousse") and bucket(site_of(u)) < 20:
            fp.append((u, 0, src))
    sets["robustness"] = [r for r in load_labelled(DATA / "augmented" / "evasion_variants.csv", quiet=True)
                          if r[2] in HOLDOUT_EVASION]
    bad_sites = {site_of(u) for name in ("hannousse", "fresh_phishing", "robustness") for u, y, _ in sets[name] if y}
    tail = [d for r, d in _tranco() if r > 100_000 and d not in bad_sites]
    sealed_v1 = _read_sites(EXCLUDE_V1_PATH)
    if sealed_v1:
        # Round 2+: the Tranco list changes daily, so re-sampling would pick sites earlier models may have
        # trained on. Take the long-tail sites that were already sealed in round 1 (never trained on by any
        # model), so the FP suite stays comparable and fair to the old model.
        tail = [d for d in tail if d in sealed_v1]
    fp += [(f"https://{d}/", 0, "tranco_longtail") for d in rng.sample(sorted(tail), min(6000, len(tail)))]
    fp += [(u, 0, "fp_extra_bank_gov") for u in FP_EXTRA]
    sets["fp_suite"] = fp

    sites = set(sealed_v1)  # once sealed, a site stays sealed
    for name, rows in sets.items():
        _write(rows, HOLDOUT_DIR / f"{name}.csv")
        sites.update(site_of(u) for u, _, _ in rows)
    with gzip.open(EXCLUDE_PATH, "wt", encoding="utf-8") as f:
        f.write("\n".join(sorted(s for s in sites if s)) + "\n")
    out = {k: len(v) for k, v in sets.items()}
    out["excluded_sites"] = len(sites)
    out["sealed_v1_sites"] = len(sealed_v1)
    print(json.dumps(out))
    return out


def _read_sites(path: Path) -> set[str]:
    if not path.exists():
        return set()
    with gzip.open(path, "rt", encoding="utf-8") as f:
        return {line.strip() for line in f if line.strip()}


def holdout_sets() -> dict[str, list[tuple[str, int, str]]]:
    return {p.stem: _read(p) for p in sorted(HOLDOUT_DIR.glob("*.csv"))}


# ---------------------------------------------------------------------------------------------------------
# Training data
# ---------------------------------------------------------------------------------------------------------
def training_rows(extra: list[tuple[str, int | None]], recipe: bool) -> tuple[list[str], list[int], list[float], list[str], dict]:
    rng = random.Random(SEED)
    with gzip.open(EXCLUDE_PATH, "rt", encoding="utf-8") as f:
        excluded = {line.strip() for line in f if line.strip()}
    rows: list[tuple[str, int, float, str]] = []
    counts: Counter = Counter()

    def add(items, cap, mode, weight=1.0):
        items = [it for it in items if site_of(it[0]) not in excluded]
        if cap and len(items) > cap:
            items = rng.sample(items, cap)
        for u, lab, src in items:
            u = host_only(u) if mode == "host" else u
            w = SYNTHETIC_WEIGHT if src == "synthetic" or src.endswith("_synthetic") else weight
            rows.append((u, lab, w, src))
            counts[src] += 1

    if recipe:
        for rel, cap, mode in RECIPE:
            t = time.time()
            src = rel.split("/")[0] if rel.startswith(("hf_kmack", "hf_ealvaradob")) else None  # both files: urls.*
            if not (DATA / rel).exists():
                print(f"  {rel}: MISSING, skipped", flush=True)
                continue
            add(load_labelled(DATA / rel, source=src, quiet=True), cap, mode)
            print(f"  {rel}: total {sum(counts.values()):,} ({time.time() - t:.0f}s)", flush=True)
        jp = []
        for p in sorted((DATA / "jpcert").glob("*.csv")):
            if p.name not in FRESH_JPCERT and p.stem[:6] <= CUTOFF_UTC[:7].replace("-", ""):  # cut-off month
                jp += [(u, 1, "jpcert") for u, _, _ in load_labelled(p, quiet=True)]
        add(jp, None, "full")
        deep = [r for r in load_labelled(DATA / "augmented" / "legit_deep_links.csv", quiet=True)
                if r[2] == "harvest_tranco" and bucket(site_of(r[0])) >= 20]
        add(deep, None, "full")
        free = [r for r in load_labelled(DATA / "augmented" / "legit_free_hosting.csv", quiet=True)
                if not r[2].startswith("hannousse") and bucket(site_of(r[0])) >= 20]
        add(free, None, "full")
        ev = [r for r in load_labelled(DATA / "augmented" / "evasion_variants.csv", quiet=True)
              if r[2] not in HOLDOUT_EVASION and not r[2].startswith("harvest_uae") and not r[2].startswith("harvest_brand")]
        add(ev, EVASION_TRAIN, "full", EVASION_WEIGHT)
        tr = [(f"http://{d}/", 0, "tranco") for _, d in _tranco()]
        add(tr, TRANCO_TRAIN, "host")
    for path, label in extra:
        add(load_labelled(path, label=label, quiet=True), None, "full")

    # canonical dedupe; a URL with both labels is dropped
    by_url: dict[str, list] = {}
    for u, lab, w, src in rows:
        by_url.setdefault(uf.canonical(u), []).append((u, lab, w, src))
    urls, labels, weights, sources = [], [], [], []
    conflicts = 0
    for group in by_url.values():
        if len({g[1] for g in group}) > 1:
            conflicts += 1
            continue
        u, lab, w, src = group[0]
        urls.append(u), labels.append(lab), weights.append(w), sources.append(src)
    info = {"rows": len(urls), "conflicts_dropped": conflicts, "per_source": dict(counts.most_common())}
    print(f"training rows {len(urls):,} (phishing {sum(labels):,}), conflicts dropped {conflicts:,}", flush=True)
    return urls, labels, weights, sources, info


def _featurise(chunk: list[str]):
    import numpy as np
    lens, idx, val, named = [], [], [], []
    for u in chunk:
        h = um.hashed(u)
        lens.append(len(h))
        idx.extend(h.keys())
        val.extend(h.values())
        named.append(uf.extract(u)[0])
        uf.parse.cache_clear()
    return (np.array(lens, dtype=np.int64), np.array(idx, dtype=np.int32), np.array(val, dtype=np.float32),
            np.array(named, dtype=np.float32))


def featurise(urls: list[str]):
    import numpy as np
    from multiprocessing import Pool
    from scipy.sparse import csr_matrix
    chunks = [urls[i:i + 5000] for i in range(0, len(urls), 5000)]
    with Pool(max(1, (os.cpu_count() or 2) - 2)) as pool:
        parts = pool.map(_featurise, chunks)
    lens = np.concatenate([p[0] for p in parts])
    indptr = np.concatenate([[0], np.cumsum(lens)])
    X = csr_matrix((np.concatenate([p[2] for p in parts]), np.concatenate([p[1] for p in parts]), indptr),
                   shape=(len(urls), um.N_FEATURES))
    return X, np.concatenate([p[3] for p in parts])


# ---------------------------------------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------------------------------------
def fit_linear(X, y, w):
    from sklearn.linear_model import LogisticRegression
    clf = LogisticRegression(C=4.0, solver="liblinear", max_iter=300, random_state=SEED)
    clf.fit(X, y, sample_weight=w)
    return clf


def quantise(clf):
    import numpy as np
    coef = clf.coef_[0].astype(np.float64)
    scale = max(1e-9, float(np.abs(coef).max()) / 32767.0)
    q = np.clip(np.round(coef / scale), -32767, 32767).astype("<i2")
    return q, scale, float(clf.intercept_[0])


def linear_logit(q, scale, bias, X):
    import numpy as np
    return bias + scale * (X @ q.astype(np.float64))


def fit_trees(Z, y, w, Zv, yv, wv):
    import lightgbm as lgb
    params = dict(objective="binary", learning_rate=0.06, num_leaves=48, min_data_in_leaf=200,
                  feature_fraction=0.85, bagging_fraction=0.8, bagging_freq=1, lambda_l2=2.0,
                  seed=SEED, deterministic=True, force_row_wise=True, verbose=-1, num_threads=12)
    dtr = lgb.Dataset(Z, y, weight=w, feature_name=[*uf.FEATURES, um.STAGE1], free_raw_data=False)
    dva = lgb.Dataset(Zv, yv, weight=wv, reference=dtr)
    return lgb.train(params, dtr, num_boost_round=500, valid_sets=[dva],
                     callbacks=[lgb.early_stopping(40, verbose=False)])


def export_trees(booster) -> dict:
    dump = booster.dump_model()
    trees = []
    for t in dump["tree_info"]:
        feat, thr, left, right, value = [], [], [], [], []

        def visit(node) -> int:
            i = len(feat)
            feat.append(-1), thr.append(0.0), left.append(-1), right.append(-1), value.append(0.0)
            if "leaf_index" in node or "split_index" not in node:
                value[i] = round(float(node.get("leaf_value", 0.0)), 7)
                return i
            assert node["decision_type"] == "<=", node["decision_type"]
            feat[i] = node["split_feature"]
            thr[i] = float(node["threshold"])
            value[i] = round(float(node["internal_value"]), 7)
            left[i] = visit(node["left_child"])
            right[i] = visit(node["right_child"])
            return i

        visit(t["tree_structure"])
        trees.append([feat, thr, left, right, value])
    return {"features": [*uf.FEATURES, um.STAGE1], "trees": trees, "objective": "binary"}


def metrics_at(p, y, th) -> dict:
    import numpy as np
    pred = p >= th
    tp = int((pred & (y == 1)).sum()); fp = int((pred & (y == 0)).sum())
    fn = int((~pred & (y == 1)).sum()); tn = int((~pred & (y == 0)).sum())
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / (tp + fn) if tp + fn else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else None
    r = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"threshold": th, "tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": r(prec), "recall": r(rec),
            "f1": r(f1), "fpr": r(fp / (fp + tn)) if fp + tn else None}


def judged(url: str) -> bool:
    """Would the server let the model judge this URL? (ai_inspector.url_model_result: official / trusted
    sites and Tranco top-100k sites off free hosting are never judged, so they cannot be false alarms.)"""
    from saqr.intel.registry import OFFICIAL_DOMAINS
    p = uf.parse(url)
    if any(p.host == d or p.host.endswith("." + d) for d in OFFICIAL_DOMAINS):
        return False
    return bool(p.platform) or p.reg_domain not in uf.popular_ranks()


def threshold_for_fpr(p_legit, target: float) -> float:
    import numpy as np
    s = np.sort(p_legit)[::-1]
    k = int(np.floor(target * len(s)))
    return float(min(0.999, max(0.5, s[k] + 1e-6 if k < len(s) else 0.5)))


def write_vectors(urls: list[str]) -> None:
    out = []
    for u in urls:
        res = um.score_url(u)
        out.append({"url": u, "probability": round(res["probability"], 6), "stage1": round(um.stage1_logit(u), 6)})
    VECTORS_PATH.parent.mkdir(parents=True, exist_ok=True)
    VECTORS_PATH.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")


VECTOR_URLS = (
    "https://www.adcb.com/en/personal/accounts/", "http://adcb-secure-login.xyz/verify/index.php?email=a@b.com",
    "https://paypal.com.secure-update.info/webscr?cmd=login", "https://microsoft-office365-signin.web.app/",
    "http://192.168.1.1:8080/a", "https://xn--pypal-4ve.com/", "https://bit.ly/3abc", "https://wikipedia.org/",
    "https://tamm-fines-pay.top/ae/pay", "https://my-portfolio.netlify.app/projects/2024",
)


def is_hardneg(src: str) -> bool:
    return src.startswith("hardneg_")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", action="append", default=[], help="extra dataset PATH[:LABEL]")
    ap.add_argument("--no-recipe", action="store_true", help="train only on --data files")
    ap.add_argument("--build-holdout", action="store_true", help="rewrite datasets/holdout/ and exit")
    ap.add_argument("--linear-only", action="store_true", help="ship stage 1 only")
    ap.add_argument("--out-dir", default=str(CANDIDATE_DIR),
                    help="where the CANDIDATE is written; tools/compare_models.py decides whether it replaces "
                         "the shipped model in saqr/intel/")
    args = ap.parse_args()
    if args.build_holdout:
        build_holdout()
        return
    import numpy as np
    import calibration as cal

    if not EXCLUDE_PATH.exists():
        build_holdout()
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    um.MODEL_PATH = out_dir / "url_model.bin"
    um.TREES_PATH = out_dir / "url_model_trees.json"
    um.METRICS_PATH = out_dir / "model_metrics.json"
    extra = []
    for d in args.data:
        path, _, lab = d.rpartition(":") if d.rsplit(":", 1)[-1] in ("0", "1") else (d, "", "")
        extra.append((path, int(lab) if lab else None))
    t0 = time.time()
    urls, labels, weights, sources, info = training_rows(extra, not args.no_recipe)
    y = np.array(labels, dtype=np.int8)
    w = np.array(weights, dtype=np.float64)
    for c in (0, 1):  # balance the classes
        w[y == c] *= len(y) / (2 * w[y == c].sum())
    t = time.time()
    X, N = featurise(urls)
    print(f"features {X.shape}, nnz {X.nnz:,} in {time.time() - t:.0f}s", flush=True)
    sites = [site_of(u) for u in urls]
    site_b = np.array([bucket(s) for s in sites])
    hn = np.array([is_hardneg(s) for s in sources])
    # Grouped validation: 10% of sites; hard-negative sites 25% (a meaningful news / advisory slice).
    val = (site_b < VAL_SHARE) | (hn & (site_b < HARDNEG_VAL_SHARE))
    tr = ~val
    # Trees early-stop on a site-disjoint slice of TRAINING sites: validation stays untouched until
    # thresholds and calibration are picked on it.
    es = tr & (site_b >= VAL_SHARE) & (site_b < VAL_SHARE + 4)
    fold = site_b % 2
    val_idx = np.where(val)[0]
    _write([(urls[i], int(y[i]), sources[i]) for i in val_idx], SPLITS_DIR / "validation.csv")

    t = time.time()
    oof = np.zeros(len(urls))
    for k in (0, 1):  # out-of-fold stage-1 scores, so the trees learn from honest stage-1 inputs
        m = tr & (fold == k)
        clf = fit_linear(X[tr & (fold != k)], y[tr & (fold != k)], w[tr & (fold != k)])
        oof[m] = linear_logit(*quantise(clf), X[m])
    clf = fit_linear(X[tr], y[tr], w[tr])
    q, scale, bias = quantise(clf)
    oof[val] = linear_logit(q, scale, bias, X[val])
    print(f"stage 1 trained in {time.time() - t:.0f}s", flush=True)
    um.MODEL_PATH.write_bytes(um.MAGIC + struct.pack("<iff", um.N_BITS, scale, bias) + q.tobytes())
    um._linear.cache_clear()

    Z = np.column_stack([N, oof]).astype(np.float32)
    booster = None
    if not args.linear_only:
        t = time.time()
        fit = tr & ~es
        booster = fit_trees(Z[fit], y[fit], w[fit], Z[es], y[es], w[es])
        print(f"stage 2: {booster.num_trees()} trees in {time.time() - t:.0f}s", flush=True)

    def sig(z):
        return 1 / (1 + np.exp(-np.clip(z, -30, 30)))

    def predict(rows):
        Xh, Nh = featurise([u for u, _, _ in rows])
        s1 = linear_logit(q, scale, bias, Xh)
        lin = sig(s1)
        ens = booster.predict(np.column_stack([Nh, s1]).astype(np.float32)) if booster else None
        return lin, ens

    sets = holdout_sets()
    vsrc = [sources[i] for i in val_idx]
    preds = {"validation": (sig(oof[val]), booster.predict(Z[val]) if booster else None,
                            y[val].astype(int), vsrc)}
    judged_mask = {"validation": np.array([judged(urls[i]) for i in val_idx])}
    hn_val = np.array([is_hardneg(s) for s in vsrc])
    if hn_val.any():
        lin, ens, yy, _ = preds["validation"]
        preds["validation_news_hardneg"] = (lin[hn_val], None if ens is None else ens[hn_val], yy[hn_val],
                                            [s for s, m in zip(vsrc, hn_val) if m])
        judged_mask["validation_news_hardneg"] = judged_mask["validation"][hn_val]
    for name, rows in sets.items():
        lin, ens = predict(rows)
        preds[name] = (lin, ens, np.array([r[1] for r in rows]), [r[2] for r in rows])
        judged_mask[name] = np.array([judged(r[0]) for r in rows])

    def legit_pool(kind: int):
        """Legitimate VALIDATION URLs the server would actually let the model judge (never a holdout set)."""
        m = (preds["validation"][2] == 0) & judged_mask["validation"]
        return preds["validation"][kind][m]

    choose = {}
    for kind, nm in ((0, "linear"), (1, "ensemble")):
        if kind == 1 and not booster:
            continue
        pool = legit_pool(kind)
        th = {"certain": threshold_for_fpr(pool, 0.001), "strong": threshold_for_fpr(pool, 0.005),
              "suspect": threshold_for_fpr(pool, 0.02)}
        rep = {"thresholds": th, "threshold_pool": "validation legit rows the server would judge",
               "threshold_pool_rows": int(len(pool)), "sets": {}}
        for sname, (lin, ens, yy, srcs) in preds.items():
            p = lin if kind == 0 else ens
            rep["sets"][sname] = {"rows": int(len(yy)), "phishing": int(yy.sum()),
                                  **{k: metrics_at(p, yy, v) for k, v in th.items()}}
            if sname == "fp_suite":
                by = {}
                for s in sorted(set(srcs)):
                    m = np.array([x == s for x in srcs])
                    by[s] = {"rows": int(m.sum()), "fp_at_strong": int((p[m] >= th["strong"]).sum()),
                             "fp_at_suspect": int((p[m] >= th["suspect"]).sum())}
                rep["sets"][sname]["by_source"] = by
        choose[nm] = rep
    for nm, rep in choose.items():
        print(f"\n== {nm}  thresholds {json.dumps({k: round(v, 4) for k, v in rep['thresholds'].items()})}")
        for sname, s in rep["sets"].items():
            m = s["strong"]
            print(f"  {sname:24s} rows {s['rows']:7d}  @strong P {m['precision']} R {m['recall']} F1 {m['f1']} "
                  f"FPR {m['fpr']}  | @suspect R {s['suspect']['recall']} FPR {s['suspect']['fpr']}")

    def val_recall(nm):  # stage choice on VALIDATION (equal FPR by construction), never on a holdout set
        return choose[nm]["sets"]["validation"]["strong"]["recall"] or 0
    ship = "ensemble" if booster and val_recall("ensemble") > val_recall("linear") else "linear"
    if ship == "ensemble":
        um.TREES_PATH.write_text(json.dumps(export_trees(booster), separators=(",", ":")), encoding="utf-8")
    elif um.TREES_PATH.exists():
        um.TREES_PATH.unlink()
    um._trees.cache_clear()
    um._score.cache_clear()
    print(f"\ncandidate stage: {ship}")

    # Calibration on validation (judged rows, both classes); isotonic vs Platt chosen by cross-fitting.
    kind = 1 if ship == "ensemble" else 0
    jm = judged_mask["validation"]
    pv = [float(v) for v in preds["validation"][kind][jm]]
    yv = [int(v) for v in preds["validation"][2][jm]]
    gv = [sites[i] for i, keep in zip(val_idx, jm) if keep]
    table, cal_rep = cal.choose(pv, yv, gv)
    for sname in sets:
        p = [float(v) for v in preds[sname][kind]]
        yy = [int(v) for v in preds[sname][2]]
        cal_rep[f"holdout_{sname}"] = {"raw": cal.reliability(p, yy),
                                       "calibrated": cal.reliability([cal.apply(table, v) for v in p], yy)}
    print("calibration:", json.dumps({k: v for k, v in cal_rep.items() if not k.startswith("holdout")}), flush=True)

    chk = [u for u, _, _ in sets["hannousse"][:300]] if "hannousse" in sets else urls[:300]
    Xc, Nc = featurise(chk)
    s1c = linear_logit(q, scale, bias, Xc)
    ref = booster.predict(np.column_stack([Nc, s1c]).astype(np.float32)) if ship == "ensemble" else sig(s1c)
    diff = max(abs(um.score_url(u)["probability"] - r) for u, r in zip(chk, ref))
    print(f"pure-Python vs training-side max |diff| on {len(chk)} URLs: {diff:.2e}")
    size = um.MODEL_PATH.stat().st_size + (um.TREES_PATH.stat().st_size if um.TREES_PATH.exists() else 0)
    vec = [{"url": u, "probability": round(um.score_url(u)["probability"], 6), "stage1": round(um.stage1_logit(u), 6)}
           for u in VECTOR_URLS]
    (out_dir / "url_model_vectors.json").write_text(json.dumps(vec, indent=1) + "\n", encoding="utf-8")
    syn = sum(v for k, v in info["per_source"].items() if k.split("+")[0] == "synthetic" or k.endswith("_synthetic"))
    metrics = {
        "model": {"name": "saqr-url-v2", "version": f"2.1-{ship}", "stage": ship,
                  "trained_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                  "training_rows": info["rows"], "training_phishing": int(y.sum()), "seed": SEED,
                  "files_bytes": size, "trees": booster.num_trees() if booster and ship == "ensemble" else 0,
                  "pure_python_max_abs_diff": diff},
        "datasets": [{"name": k, "rows": v} for k, v in info["per_source"].items()],
        "synthetic_share_of_training_rows": round(syn / max(1, sum(info["per_source"].values())), 4),
        "split": {"validation_rows": int(val.sum()), "validation_hardneg_rows": int((val & hn).sum()),
                  "rule": f"{VAL_SHARE}% of sites by hash ({HARDNEG_VAL_SHARE}% of hard-negative sites)",
                  "early_stopping_rows": int(es.sum()),
                  "early_stopping": "site-disjoint slice of the training sites (validation untouched)"},
        "holdout_sets": {k: len(v) for k, v in sets.items()},
        "thresholds": choose[ship]["thresholds"],
        "calibration": {**table, "fitted_on": "validation split, rows the server would judge",
                        "model_sha256": um.model_fingerprint(), "report": cal_rep},
        "model_eval": choose,
        "minutes": round((time.time() - t0) / 60, 1),
    }
    (out_dir / "model_metrics.json").write_text(json.dumps(metrics, indent=1) + "\n", encoding="utf-8")
    print(f"candidate in {out_dir}: {size / 1e6:.2f} MB ({ship}); {metrics['minutes']} min")


if __name__ == "__main__":
    main()
