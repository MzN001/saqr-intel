"""Train SAQR's phishing-hostname classifier -> saqr/intel/url_model.bin

Developer tool (needs: pip install scikit-learn numpy pandas). Data (download first):
  PhiUSIIL_Phishing_URL_Dataset.csv  https://archive.ics.uci.edu/dataset/967  (label 0 = phishing, 1 = legit)
  phishing_army_blocklist.txt        https://phishing.army/download/phishing_army_blocklist.txt
  top-1m.csv                         https://tranco-list.eu/top-1m.csv.zip
usage: python tools/train_url_model.py <data_dir> [--exclude evalset.json]

Only the hostname is used. In PhiUSIIL every legitimate URL is a bare homepage and every URL with
a path is phishing, so a model that saw paths would flag any real deep link (paypal.com/signin).
"""
from __future__ import annotations

import csv
import json
import random
import sys
import time
from array import array
from pathlib import Path
from urllib.parse import urlsplit

import numpy as np
import pandas as pd
from scipy.sparse import csr_matrix
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from saqr.intel.url_model import MODEL_PATH, N_FEATURES, features, normalise_host  # noqa: E402

LEGIT_SUBDOMAINS = ("mail", "login", "accounts", "account", "app", "my", "m", "shop", "store", "support",
                    "help", "portal", "secure", "online", "auth", "id", "pay", "web", "en", "blog", "docs",
                    "api", "cdn", "static", "news", "careers", "investor", "signin", "billing", "status")


def host_of(url: str) -> str:
    try:
        return normalise_host(urlsplit(url if "://" in url else "http://" + url).hostname or "")
    except ValueError:
        return ""


def load(data: Path, exclude: set[str]) -> tuple[list[str], list[int]]:
    random.seed(11)
    phish: set[str] = set()
    legit: set[str] = set()

    df = pd.read_csv(data / "PhiUSIIL_Phishing_URL_Dataset.csv", usecols=["URL", "label"])
    for url, label in zip(df.URL, df.label):
        h = host_of(url)
        if h:
            (legit if label == 1 else phish).add(h)

    for line in (data / "phishing_army_blocklist.txt").read_text(encoding="utf-8", errors="ignore").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            phish.add(normalise_host(line))

    ranks: dict[str, int] = {}
    with open(data / "top-1m.csv", encoding="utf-8") as f:
        for r, dom in csv.reader(f):
            ranks[dom] = int(r)
    top = [d for d, r in ranks.items() if r <= 400_000]
    legit.update(normalise_host(d) for d in top)
    for d in [d for d, r in ranks.items() if r <= 30_000]:
        legit.add(f"{random.choice(LEGIT_SUBDOMAINS)}.{d}")

    very_popular = {d for d, r in ranks.items() if r <= 10_000}
    phish = {h for h in phish if h and h not in very_popular}  # feed noise on huge sites
    both = phish & legit
    phish -= both
    legit -= both
    phish -= exclude
    legit -= exclude
    hosts = sorted(phish) + sorted(legit)
    labels = [1] * len(phish) + [0] * len(legit)
    print(f"phishing hosts {len(phish):,}  legit hosts {len(legit):,}  (dropped {len(both):,} conflicts)")
    return hosts, labels


def matrix(hosts: list[str]) -> csr_matrix:
    indptr, idx, vals = [0], [], []
    for h in hosts:
        f = features(h)
        idx.extend(f.keys())
        vals.extend(f.values())
        indptr.append(len(idx))
    return csr_matrix((np.array(vals, dtype=np.float32), np.array(idx, dtype=np.int32), np.array(indptr)),
                      shape=(len(hosts), N_FEATURES))


def main() -> None:
    data = Path(sys.argv[1])
    exclude: set[str] = set()
    if "--exclude" in sys.argv:
        for it in json.load(open(sys.argv[sys.argv.index("--exclude") + 1], encoding="utf-8")):
            exclude.add(host_of(it["url"]))
    hosts, labels = load(data, exclude)
    y = np.array(labels)
    t = time.time()
    X = matrix(hosts)
    print(f"features built in {time.time() - t:.0f}s: {X.shape}, nnz {X.nnz:,}")

    rng = np.random.default_rng(5)
    test = rng.random(len(hosts)) < 0.1
    clf = LogisticRegression(C=8.0, solver="liblinear", class_weight="balanced", max_iter=200)
    t = time.time()
    clf.fit(X[~test], y[~test])
    p = clf.predict_proba(X[test])[:, 1]
    print(f"trained in {time.time() - t:.0f}s; held-out AUC {roc_auc_score(y[test], p):.4f}")
    for th in (0.5, 0.8, 0.9, 0.95, 0.98):
        tp = ((p >= th) & (y[test] == 1)).sum() / max(1, (y[test] == 1).sum())
        fp = ((p >= th) & (y[test] == 0)).sum() / max(1, (y[test] == 0).sum())
        print(f"  threshold {th}: catches {tp:.1%} of phishing, false alarms on {fp:.2%} of legit")

    clf.fit(X, y)  # final model on everything (still excluding the evaluation set)
    w = array("f", clf.coef_[0].astype(np.float32).tolist())
    b = array("f", [float(clf.intercept_[0])])
    MODEL_PATH.write_bytes(w.tobytes() + b.tobytes())
    print(f"saved {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1e6:.1f} MB)")


if __name__ == "__main__":
    main()
