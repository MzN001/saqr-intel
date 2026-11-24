"""Capture brand-fingerprint baselines of the real UAE portals -> saqr/intel/data/brand_fingerprints.json.

Run: .venv\\Scripts\\python tools\\build_brand_fingerprints.py [--no-screenshots]

Polite: one request per second, a clear User-Agent, robots.txt respected, only the official home /
log-in pages (+ up to 2 first-party CSS files for colours and the favicon). Only DERIVED fingerprints
are stored (tokens, asset names, colours, field kinds, hashes), never page copies. A portal that blocks
automated fetches (403 / JS-only shell) gets a `partial` baseline built from what was reachable plus
the registry's names and domains.

Screenshot dHashes come from image.thum.io (and mshots when Pillow is installed): the same services the
runtime uses, so like is compared with like.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit
from urllib.robotparser import RobotFileParser

import httpx

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from saqr.intel import brand_fingerprint as bf  # noqa: E402
from saqr.intel import visual_similarity as vs  # noqa: E402

USER_AGENT = "Mozilla/5.0 (compatible; BrandBaselineCapture/1.0; anti-phishing reference fingerprint)"
OUT = ROOT / "saqr" / "intel" / "data" / "brand_fingerprints.json"

# Registry data: names, official domains, brand terms (EN + AR), registry entity id, pages to capture,
# and the sign-in method the official portal uses (fallback form kinds when its log-in page is not reachable).
PORTALS = [
    dict(id="tamm", entity_id="tamm", name_en="TAMM", name_ar="تم", official_domains=["tamm.abudhabi"],
         brand_terms=["tamm", "tamm abu dhabi", "تم", "منصة تم", "تم أبوظبي"], login_kinds=["UAE_PASS"],
         pages=["https://www.tamm.abudhabi/", "https://www.tamm.abudhabi/en"]),
    dict(id="uaepass", entity_id="uaepass", name_en="UAE PASS", name_ar="الهوية الرقمية UAE PASS",
         official_domains=["uaepass.ae"], brand_terms=["uae pass", "uaepass", "الهوية الرقمية"],
         login_kinds=["EMIRATES_ID"], pages=["https://uaepass.ae/", "https://www.uaepass.ae/"]),
    dict(id="adpolice", entity_id="adpolice", name_en="Abu Dhabi Police", name_ar="شرطة أبوظبي",
         official_domains=["adpolice.gov.ae"], brand_terms=["abu dhabi police", "adpolice", "شرطة أبوظبي", "شرطة ابوظبي"],
         login_kinds=["UAE_PASS"], pages=["https://www.adpolice.gov.ae/", "https://www.adpolice.gov.ae/en"]),
    dict(id="emiratespost", entity_id="emiratespost", name_en="Emirates Post", name_ar="بريد الإمارات",
         official_domains=["emiratespost.ae", "epg.gov.ae"], brand_terms=["emirates post", "emiratespost", "بريد الإمارات"],
         login_kinds=["PASSWORD"], pages=["https://www.emiratespost.ae/", "https://www.emiratespost.ae/en"]),
    dict(id="salik", entity_id="rta", name_en="Salik", name_ar="سالك", official_domains=["salik.ae", "rta.ae"],
         brand_terms=["salik", "سالك"], login_kinds=["PASSWORD"],
         pages=["https://www.salik.ae/", "https://www.salik.ae/en"]),
    dict(id="icp", entity_id=None, name_en="ICP", name_ar="الهيئة الاتحادية للهوية والجنسية",
         official_domains=["icp.gov.ae"], brand_terms=["icp", "federal authority for identity", "الهيئة الاتحادية للهوية"],
         login_kinds=["UAE_PASS"], pages=["https://icp.gov.ae/", "https://smartservices.icp.gov.ae/"]),
    dict(id="adcb", entity_id="adcb", name_en="ADCB", name_ar="بنك أبوظبي التجاري", official_domains=["adcb.com"],
         brand_terms=["adcb", "abu dhabi commercial bank", "بنك أبوظبي التجاري"], login_kinds=["PASSWORD"],
         pages=["https://www.adcb.com/", "https://www.adcb.com/en/personal/"]),
    dict(id="fab", entity_id="fab", name_en="FAB", name_ar="بنك أبوظبي الأول", official_domains=["bankfab.com"],
         brand_terms=["fab", "first abu dhabi bank", "bank fab", "بنك أبوظبي الأول"], login_kinds=["PASSWORD"],
         pages=["https://www.bankfab.com/", "https://www.bankfab.com/en-ae/personal"]),
    dict(id="emiratesnbd", entity_id="emiratesnbd", name_en="Emirates NBD", name_ar="بنك الإمارات دبي الوطني",
         official_domains=["emiratesnbd.com"], brand_terms=["emirates nbd", "emiratesnbd", "enbd", "بنك الإمارات دبي الوطني"],
         login_kinds=["PASSWORD"], pages=["https://www.emiratesnbd.com/", "https://www.emiratesnbd.com/en"]),
    dict(id="etisalat", entity_id="etisalat", name_en="e&", name_ar="اتصالات من e&",
         official_domains=["etisalat.ae", "eand.com", "eand.ae"], brand_terms=["e&", "etisalat", "etisalat by e&", "اتصالات"],
         login_kinds=["PASSWORD"], pages=["https://www.etisalat.ae/", "https://www.eand.com/"]),
    dict(id="du", entity_id="du", name_en="du", name_ar="دو", official_domains=["du.ae"],
         brand_terms=["du", "دو", "du telecom"], login_kinds=["PASSWORD"],
         pages=["https://www.du.ae/", "https://www.du.ae/personal"]),
]

_robots: dict[str, RobotFileParser | None] = {}


def owned(host: str, domains: list[str]) -> bool:
    h = (host or "").lower()
    return any(h == d or h.endswith("." + d) for d in domains)


def polite_get(client: httpx.Client, url: str, limit: int = 600_000) -> httpx.Response | None:
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    if origin not in _robots:
        rp = RobotFileParser()
        try:
            r = client.get(origin + "/robots.txt")
            rp.parse(r.text.splitlines() if r.status_code == 200 else [])
            _robots[origin] = rp
        except httpx.HTTPError:
            _robots[origin] = None
        time.sleep(1)
    rp = _robots.get(origin)
    if rp is not None and not rp.can_fetch(USER_AGENT, url):
        print(f"   robots.txt disallows {url}")
        return None
    try:
        r = client.get(url)
    except httpx.HTTPError as exc:
        print(f"   {url}: {type(exc).__name__}")
        return None
    finally:
        time.sleep(1)
    if len(r.content) > limit:
        return None
    return r


def capture(portal: dict, client: httpx.Client, screenshots: bool) -> dict:
    print(f"== {portal['name_en']}")
    fps, sources, notes = [], [], []
    colour_css = ""
    favicon_hash = favicon_url = None
    for url in portal["pages"]:
        r = polite_get(client, url)
        if r is None:
            notes.append(f"{url}: no answer")
            continue
        final_host = r.url.host or ""
        if not owned(final_host, portal["official_domains"]):
            notes.append(f"{url}: redirected off the official domain ({final_host})")
            continue
        ctype = r.headers.get("content-type", "")
        print(f"   {url} -> {r.status_code} {ctype[:30]} {len(r.content)} B")
        if r.status_code != 200 or "html" not in ctype:
            notes.append(f"{url}: HTTP {r.status_code}")
            continue
        fp = bf.extract(r.text, str(r.url))
        fps.append(fp)
        sources.append(str(r.url))
        # first-party CSS (full URLs re-read from the page) for the colour palette
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(r.text, "html.parser")
        css_links = [urljoin(str(r.url), l["href"]) for l in soup.find_all("link", href=True)
                     if "stylesheet" in " ".join(l.get("rel") or []).lower()]
        for css in [c for c in css_links if owned(urlsplit(c).hostname or "", portal["official_domains"])][:2]:
            cr = polite_get(client, css, limit=400_000)
            if cr is not None and cr.status_code == 200:
                colour_css += " " + cr.text
        if not favicon_hash and fp.get("favicon"):
            fav = fp["favicon"]
            fr = polite_get(client, fav, limit=bf.FAVICON_LIMIT)
            if fr is not None and fr.status_code == 200 and fr.content:
                favicon_hash, favicon_url = hashlib.sha256(fr.content).hexdigest(), fav

    title_tokens, phrases, asset_names, asset_hosts, kinds = Counter(), [], set(), set(), set()
    inline_colours: Counter = Counter()
    langs = Counter()
    has_brand = False
    for fp in fps:
        title_tokens.update(fp["title_tokens"])
        phrases += fp["phrases"][:10]
        for a in fp["assets"]:
            if a["kind"] in {"logo", "favicon", "css", "js"} and bf.distinctive_asset(a["name"]):
                asset_names.add(a["name"])
            if a["host"] and not bf.generic_host(a["host"]) and not owned(a["host"], portal["official_domains"]) \
                    and a["kind"] in {"logo", "favicon", "css", "js"}:
                asset_hosts.add(a["host"])  # the brand's own CDN hosts (e.g. a dedicated asset domain)
        # sign-in fields only: newsletter / search / contact boxes (EMAIL, PHONE) say nothing about the brand
        kinds |= set(fp["form"]["kinds"]) & {"PASSWORD", "EMIRATES_ID", "UAE_PASS", "OTP"}
        if fp["form"]["uaepass_button"]:
            kinds.add("UAE_PASS")
        inline_colours.update({c: 3 - i * 0.3 for i, c in enumerate(fp["colours"])})
        langs[fp["lang"][:2]] += 1
        fp_named = bf.brands_named(fp, ({"id": portal["id"], "brand_terms": [bf.norm(t) for t in portal["brand_terms"]],
                                         "official_domains": portal["official_domains"]},))
        has_brand = has_brand or bool(fp_named)
    colours = bf.dominant_colours(colour_css + " " + " ".join(c for c, _ in inline_colours.most_common(8)))
    if not kinds:
        kinds = set(portal["login_kinds"])
        notes.append("form kinds from registry data (log-in page not reachable)")
    status = "full" if fps and has_brand and (colours or asset_names) else "partial"
    if not fps:
        notes.append("no page reachable: baseline from registry data only")
    dhash: dict[str, str] = {}
    if screenshots:
        for name, tmpl in (("thumio", vs.THUMIO_URL),):
            try:
                r = httpx.get(tmpl.format(url=portal["pages"][0]), timeout=40, headers={"User-Agent": USER_AGENT})
                h = vs.dhash_bytes(r.content) if r.status_code == 200 else None
            except httpx.HTTPError:
                h = None
            if h is not None:
                dhash[name] = vs.to_hex(h)
            else:
                notes.append(f"{name} screenshot blank or unavailable (no dHash)")
            time.sleep(1)
    return {
        "id": portal["id"], "entity_id": portal["entity_id"], "name_en": portal["name_en"], "name_ar": portal["name_ar"],
        "official_domains": portal["official_domains"], "brand_terms": portal["brand_terms"],
        "status": status, "captured_at": datetime.now(timezone.utc).date().isoformat(), "sources": sources,
        "title_tokens": [t for t, _ in title_tokens.most_common(20)], "phrases": phrases[:12],
        "asset_names": sorted(asset_names)[:40], "asset_hosts": sorted(asset_hosts)[:10],
        "colours": colours[:5], "form_kinds": sorted(kinds), "lang": langs.most_common(1)[0][0] if langs else "",
        "favicon_url": favicon_url, "favicon_sha256": favicon_hash, "dhash": dhash,
        "dhash_captured_at": datetime.now(timezone.utc).date().isoformat() if dhash else None, "notes": notes,
    }


def drop_shared_hashes(baselines: list[dict]) -> None:
    """Two different portals with the SAME screenshot hash = the service returned an error / placeholder
    frame, not the portal: such hashes are removed (they would match each other at 100%)."""
    seen: Counter = Counter(h for b in baselines for h in (b.get("dhash") or {}).values())
    for b in baselines:
        for src, h in list((b.get("dhash") or {}).items()):
            if seen[h] > 1:
                del b["dhash"][src]
                b.setdefault("notes", []).append(f"{src} screenshot identical to another portal's (placeholder): dropped")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-screenshots", action="store_true")
    ap.add_argument("--only", help="comma list of portal ids")
    ap.add_argument("--dedupe-only", action="store_true", help="only drop shared screenshot hashes in the JSON")
    args = ap.parse_args()
    if args.dedupe_only:
        data = json.loads(OUT.read_text(encoding="utf-8"))
        drop_shared_hashes(data["baselines"])
        OUT.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
        return
    only = set(args.only.split(",")) if args.only else None
    old = {}
    if OUT.exists():
        old = {b["id"]: b for b in json.loads(OUT.read_text(encoding="utf-8")).get("baselines", [])}
    out = []
    with httpx.Client(headers={"User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.8",
                               "Accept-Language": "en-US,en;q=0.8,ar;q=0.6"},
                      follow_redirects=True, timeout=15) as client:
        for p in PORTALS:
            if only and p["id"] not in only and p["id"] in old:
                out.append(old[p["id"]])
                continue
            out.append(capture(p, client, not args.no_screenshots))
            if args.no_screenshots and p["id"] in old:  # keep the previous screenshot hash
                out[-1]["dhash"] = old[p["id"]].get("dhash") or {}
                out[-1]["dhash_captured_at"] = old[p["id"]].get("dhash_captured_at")
            print(f"   -> {out[-1]['status']}  colours={out[-1]['colours']} kinds={out[-1]['form_kinds']} "
                  f"assets={len(out[-1]['asset_names'])} dhash={out[-1]['dhash']}")
    drop_shared_hashes(out)
    OUT.write_text(json.dumps({
        "version": 1, "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "user_agent": USER_AGENT, "tool": "tools/build_brand_fingerprints.py",
        "note": "Derived fingerprints only (no page copies). status=partial: portal blocked or JS-only; "
                "built from what was reachable plus registry data.",
        "baselines": out}, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
