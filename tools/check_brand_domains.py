"""Sanity checks for saqr/intel/registry.py GLOBAL_BRANDS (offline, standard library + the runtime venv).

    python -I tools/check_brand_domains.py            # needs datasets/tranco/top-1m.csv (tools/fetch_datasets.py)

1. Every official domain of a global brand should be a well-known site: it is looked up in the Tranco
   top-1M list. A domain that is missing is printed (a typo, or a domain to verify by hand).
2. Every Tranco top-100k registered domain is run through the look-alike rules. A popular site that gets
   BRAND_IMPERSONATION / TYPOSQUAT is printed: it is either an official domain missing from the registry
   or a legitimate third party the rules would wrongly flag.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("THREAT_FEEDS", "false")
sys.path.insert(0, str(ROOT))

from saqr.intel.domain_intel import analyze_lexical  # noqa: E402
from saqr.intel.registry import GLOBAL_BRANDS  # noqa: E402


def main() -> int:
    path = ROOT / "datasets" / "tranco" / "top-1m.csv"
    if not path.exists():
        print("datasets/tranco/top-1m.csv is missing: run tools/fetch_datasets.py first")
        return 2
    rank: dict[str, int] = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            r, _, d = line.strip().partition(",")
            if d:
                rank[d] = int(r)
    missing = [(e.id, d) for e in GLOBAL_BRANDS for d in e.domains if d not in rank]
    print(f"official domains not in Tranco top-1M: {len(missing)}")
    for ent, d in missing:
        print(f"  {ent:14s} {d}")
    limit = int(sys.argv[1]) if len(sys.argv) > 1 else 100_000
    hits = []
    for d, r in rank.items():
        if r > limit:
            continue
        rep = analyze_lexical(d)
        codes = [f.code for f in rep.flags if f.code in ("BRAND_IMPERSONATION", "TYPOSQUAT", "HOMOGLYPH_SPOOF")]
        if codes and rep.impersonated:
            hits.append((r, d, rep.impersonated.id, codes[0]))
    print(f"top-{limit} sites flagged by the look-alike rules: {len(hits)}")
    for r, d, ent, code in sorted(hits):
        print(f"  {r:7d} {d:40s} {ent:14s} {code}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
