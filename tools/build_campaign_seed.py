"""Re-generate saqr/intel/data/campaigns_seed.json (the phishing-campaign seed).

The seed has two kinds of campaigns:

* researched ones (references with source_id "saqr-research"): written by hand from public
  advisories, every fact traceable to a cited page. They are kept as they are (re-validated).
* live ones: rebuilt from today's RSS / Atom headlines of the sources in campaigns.SOURCES,
  mapped onto the fixed brand x lure taxonomy (fetched text never becomes matching wording).

Usage (from the repo root, inside the venv):
    python tools/build_campaign_seed.py                  # refresh live part, keep research, write
    python tools/build_campaign_seed.py --offline        # only re-validate + rewrite (no network)
    python tools/build_campaign_seed.py --check          # validate the file, write nothing
    python tools/build_campaign_seed.py --import-curated research.json
          # add / replace researched campaigns from a JSON list of
          # {"slug": "...", title_en, title_ar, summary_en, summary_ar, brands, terms, min_terms,
          #  channels, regions, severity, first_seen, last_seen, references: [{url, title}],
          #  "urls": [indicator domains], "senders": [indicator sender domains]}
          # (ids are derived from the slug, so re-importing the same slug updates it in place)

Every indicator goes through campaigns.ioc_allowed(): platforms, free-mail providers, official /
trusted / top-10k domains are dropped (and reported).
"""
from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("CT_MODE", "off")

from saqr.intel import campaigns as cm  # noqa: E402

RESEARCH = cm.CURATED_SOURCE["id"]


def _day(s: str) -> str:
    s = (s or "").strip()
    return f"{s}T00:00:00Z" if len(s) == 10 else s


def from_curated(entry: dict) -> tuple[dict | None, list[str]]:
    """A research entry (with "slug") -> contract campaign; also the indicators that were dropped."""
    urls, senders = entry.get("urls") or [], entry.get("senders") or []
    c = {
        "id": cm.campaign_id("seed:" + entry["slug"]),
        **{k: entry.get(k) for k in ("title_en", "title_ar", "summary_en", "summary_ar", "brands", "terms",
                                      "min_terms", "channels", "regions", "severity")},
        "first_seen": _day(entry.get("first_seen", "")), "last_seen": _day(entry.get("last_seen", "")),
        "references": [{"source_id": RESEARCH, "url": r["url"], "title": r.get("title", "")}
                       for r in entry.get("references") or []],
        "indicators": {"sender_domains": senders, "url_domains": urls},
    }
    clean = cm.clean_campaign(c)
    kept = set(clean["indicators"]["url_domains"] + clean["indicators"]["sender_domains"]) if clean else set()
    dropped = [d for d in [*urls, *senders] if cm.regdom(cm.refang_host(d)) not in kept]
    return clean, dropped


def is_research(c: dict) -> bool:
    return bool(c.get("references")) and all(r.get("source_id") == RESEARCH for r in c["references"])


def validate(feed: dict) -> list[str]:
    """Problems that would make the seed unusable or unsafe (empty list = fine)."""
    problems = []
    if feed.get("format") != cm.FORMAT:
        problems.append("format is not saqr-campaigns")
    ids = set()
    for c in feed.get("campaigns") or []:
        clean = cm.clean_campaign(c)
        if not clean:
            problems.append(f"invalid campaign {c.get('id')}")
            continue
        if clean != c:
            problems.append(f"{c['id']}: not in normalised form (run without --check to rewrite)")
        if c["id"] in ids:
            problems.append(f"duplicate id {c['id']}")
        ids.add(c["id"])
        if not c["references"]:
            problems.append(f"{c['id']}: no references")
    return problems


async def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--offline", action="store_true", help="do not fetch live feeds")
    ap.add_argument("--check", action="store_true", help="validate only, write nothing")
    ap.add_argument("--import-curated", type=Path, help="JSON list of researched campaigns to add / replace")
    ap.add_argument("--out", type=Path, default=cm.SEED_PATH)
    args = ap.parse_args()

    current = cm.load_seed(args.out)
    if args.check:
        problems = validate(current)
        for p in problems:
            print("PROBLEM:", p)
        print(f"{len(current.get('campaigns') or [])} campaigns, {len(problems)} problems")
        return 1 if problems else 0

    research = {c["id"]: c for c in (cm.clean_campaign(x) for x in current.get("campaigns") or []) if c and is_research(c)}
    if args.import_curated:
        for entry in json.loads(args.import_curated.read_text(encoding="utf-8")):
            c, dropped = from_curated(entry)
            if not c:
                print("SKIPPED (invalid):", entry.get("slug"))
                continue
            if dropped:
                print(f"{entry['slug']}: indicators dropped by the safety rules: {dropped}")
            research[c["id"]] = c

    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sources = [{**cm.CURATED_SOURCE, "ok": True, "fetched_at": now, "items": len(research)}]
    live: list[dict] = []
    if not args.offline:
        feed = cm.CampaignFeed(seed_path=None)  # empty: we only want the live part
        items, status = await feed.fetch_sources()
        seed_urls = {r["url"] for c in research.values() for r in c["references"]}
        live = [c for c in (cm.clean_campaign(x) for x in cm.campaigns_from_items(items, skip_urls=seed_urls)) if c]
        for st in status.values():
            print(f"  source {st['id']:<18} ok={st['ok']} items={st['items']} {st.get('error') or ''}")
            sources.append({k: st[k] for k in ("id", "name", "url", "license", "ok", "fetched_at", "items")})
    else:  # keep the previous live part untouched
        live = [c for c in (cm.clean_campaign(x) for x in current.get("campaigns") or []) if c and not is_research(c)]
        sources += [s for s in current.get("sources") or [] if s.get("id") != RESEARCH]

    ordered = sorted(research.values(), key=lambda c: c["last_seen"], reverse=True)
    ids = {c["id"] for c in ordered}
    ordered += [c for c in live if c["id"] not in ids]
    out = {"format": cm.FORMAT, "version": cm.VERSION, "generated_at": now, "ttl_hours": cm.TTL_HOURS,
           "sources": sources, "campaigns": ordered}
    problems = validate(out)
    if problems:
        for p in problems:
            print("PROBLEM:", p)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    n_ioc = sum(1 for c in ordered if c["indicators"]["url_domains"] or c["indicators"]["sender_domains"])
    print(f"Wrote {args.out.relative_to(ROOT)}: {len(ordered)} campaigns ({len(research)} researched, "
          f"{len(ordered) - len(research)} from live feeds, {n_ioc} with indicators)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
