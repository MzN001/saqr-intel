"""Pre-click shield: verdicts for many links at once, and official-number checks for phones.

POST /api/batch-verdict  {urls: [...<=200], expand: false}
    The browser extension (Google / Bing results, sponsored ads, Maps cards) and the /citizen demo
    badge every link BEFORE it is clicked. Offline evidence only, so 50 links take a few
    milliseconds: look-alike / brand rules, the trained URL model, global threat feeds, seeded
    syndicate intelligence, and what SAQR already knows (earlier full scans, proactive-hunter
    detections, confirmed demo scam pages). Redirect wrappers (google.com/url?q=, ?url=...) are
    unwrapped without the network; with expand=true URL shorteners are expanded on a tight budget.
    Nothing is saved, nothing enters the syndicate graph.

POST /api/check-phone  {phone, claimed_entity?, context?}
    Is a number shown in an ad / Maps card / knowledge panel one of the claimed institution's
    official numbers? Same rules as the Maps sentinel (maps_sentinel.phone_flags).

Own rate-limit bucket: one search page sends a few batches, which must not use up the citizen's
URL-scan allowance (4 x RATE_LIMIT_PER_MINUTE, at least 120; 0 = off).
"""
from __future__ import annotations

import asyncio
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from ..config import settings
from ..db import db
from ..intel import graph_engine, page_signals, redirects
from ..intel.ai_inspector import run_rules, verdict_for
from ..intel.domain_intel import RedFlag, normalize_url
from ..intel.email_rules import host_of, unwrap_url
from ..intel.maps_sentinel import match_entity, phone_flags, pins_sharing_phone
from ..intel.registry import (ENTITIES, ENTITY_BY_ID, ENTITY_EXTRA_DOMAINS, OFFICIAL_PHONES, TRUSTED_UAE_DOMAINS,
                              Entity, normalise_phone)
from ..pipeline import gather_network
from ..schemas import BatchVerdictRequest, CheckPhoneRequest
from ..security import RateLimiter
from ..seed_data import DEMO_INTEL, resolve_mock_scam
from .email import rate_limit_bucket

router = APIRouter(prefix="/api", tags=["Pre-click shield (search, ads, Maps)"])


def _per_minute() -> int:
    base = settings.rate_limit_per_minute
    return 0 if base <= 0 else max(120, base * 4)


batch_limiter = RateLimiter(_per_minute())
batch_rate_limit = rate_limit_bucket(batch_limiter)

CACHE_TTL_S = 600
CACHE_MAX = 5000
MAX_HOPS = 4
EXPAND_MAX = 10          # shorteners expanded per request
EXPAND_HOP_TIMEOUT_S = 1.5
EXPAND_BUDGET_S = 3.0    # the whole request never waits longer than this for the network
MAX_REASONS = 4
# Big UAE banks / authorities that the registry lists with the global brands.
UAE_BRAND_IDS = {"emiratesnbd", "mashreq", "adib", "dubaipolice", "rta", "dewa", "emiratesair"}


@dataclass
class HostVerdict:
    host: str
    score: int
    entity: Entity | None
    flags: list[RedFlag] = field(default_factory=list)
    official: bool = False        # a verified official UAE website: the only case that gets a green tick
    passthrough: bool = False     # shortener / official / very popular: never the site to blame
    whitelisted: bool = False     # any official / trusted domain: earlier verdicts never override it

    @property
    def verdict(self) -> str:
        return verdict_for(self.score)


_cache: OrderedDict[str, tuple[float, HostVerdict]] = OrderedDict()


def is_official_uae(lex) -> bool:
    if not lex.is_whitelisted or lex.official_match in settings.own_hosts:
        return False
    match = lex.official_match or ""
    ent = lex.impersonated
    return (match.endswith((".ae", ".abudhabi")) or match in TRUSTED_UAE_DOMAINS or match in ENTITY_EXTRA_DOMAINS
            or match in settings.extra_whitelist or ent in ENTITIES or (ent is not None and ent.id in UAE_BRAND_IDS))


async def assess_host(url: str) -> HostVerdict:
    """Offline verdict for the website a URL is on (cached per host)."""
    _, host = normalize_url(url)
    hit = _cache.get(host)
    if hit and hit[0] > time.monotonic():
        _cache.move_to_end(host)
        return hit[1]
    lex = page_signals.lexical(url)
    net: dict[str, Any] = {}
    syndicate = None
    if not lex.is_whitelisted and (lex.registered_domain in DEMO_INTEL or lex.host in DEMO_INTEL):
        net = await gather_network(lex)  # seeded intelligence: answered from memory, no network
        syndicate = await graph_engine.syndicate_for([f"domain:{lex.host}", f"domain:{lex.registered_domain}"])
    rr = run_rules(lex, net, None, syndicate)
    hv = HostVerdict(host=lex.host, score=rr.score, entity=rr.entity, flags=rr.flags,
                     official=is_official_uae(lex),
                     passthrough=redirects.is_trusted_passthrough(lex.host, lex.registered_domain),
                     whitelisted=lex.is_whitelisted)
    _cache[host] = (time.monotonic() + CACHE_TTL_S, hv)
    while len(_cache) > CACHE_MAX:
        _cache.popitem(last=False)
    return hv


def static_chain(url: str) -> list[dict[str, Any]]:
    """Redirect-parameter hops (google.com/url?q=..., ?url=..., Safe Links), no network."""
    hops = [{"url": url, "host": host_of(url), "via": "input"}]
    cur = url
    for _ in range(MAX_HOPS):
        nxt = unwrap_url(cur, depth=1)[0]
        if nxt == cur or not host_of(nxt) or any(h["url"] == nxt for h in hops):
            break
        cur = nxt
        hops.append({"url": cur, "host": host_of(cur), "via": "param"})
    return hops


async def expand_chains(chains: dict[str, list[dict[str, Any]]]) -> None:
    """Replace the chains that end in a URL shortener by the walked chain (HEAD requests only)."""
    todo = [u for u, hops in chains.items() if redirects.is_shortener(hops[-1]["host"])][:EXPAND_MAX]
    if not todo:
        return

    async def walk(u: str) -> None:
        try:
            chains[u] = await redirects.resolve_chain(u, max_hops=MAX_HOPS, timeout=EXPAND_HOP_TIMEOUT_S, fast=True)
        except Exception:  # noqa: BLE001 - keep the static chain
            pass

    tasks = [asyncio.create_task(walk(u)) for u in todo]
    _, pending = await asyncio.wait(tasks, timeout=EXPAND_BUDGET_S)
    for t in pending:
        t.cancel()


def judge(chain: list[HostVerdict]) -> HostVerdict:
    """The host the verdict is about: the worst one; with no risk anywhere the destination, unless
    that is a famous / official site behind an unknown one (same rule as pipeline.follow_redirects)."""
    worst = max(h.score for h in chain)
    if worst > 0:
        return next(h for h in reversed(chain) if h.score == worst)
    final = chain[-1]
    if final.passthrough:
        unknown = [h for h in chain if not h.passthrough]
        if unknown:
            return unknown[0]
    return final


def _entity_for(name_or_id: str | None) -> Entity | None:
    if not name_or_id:
        return None
    return ENTITY_BY_ID.get(name_or_id) or next((e for e in ENTITY_BY_ID.values() if e.name_en == name_or_id), None)


async def known_evidence(hosts: list[str]) -> dict[str, list[tuple[RedFlag, Entity | None]]]:
    """What SAQR already decided about these hosts: earlier full scans, the proactive hunter,
    and the confirmed demo scam pages (the same sources the DNS blocklist publishes)."""
    out: dict[str, list[tuple[RedFlag, Entity | None]]] = {}
    if not hosts:
        return out
    marks = ",".join("?" * len(hosts))
    scans = await db.fetchall(
        f"SELECT domain, MAX(risk_score) AS score, MAX(impersonated_entity) AS entity FROM scans "
        f"WHERE domain IN ({marks}) AND kind = 'url' AND verdict != 'SAFE' GROUP BY domain", tuple(hosts))
    for r in scans:
        out.setdefault(r["domain"], []).append((RedFlag(
            "SAQR_PRIOR_SCAN", "critical" if r["score"] >= 65 else "high", int(r["score"]),
            f"SAQR already inspected this website in full and rated it {verdict_for(r['score'])} ({r['score']}/100).",
            f"سبق أن فحص صقر هذا الموقع بالكامل وصنّفه {'احتيالاً عالي الخطورة' if r['score'] >= 65 else 'مشبوهاً'} "
            f"({r['score']}/100)."), _entity_for(r["entity"])))
    hunted = await db.fetchall(
        f"SELECT domain, source, score, entity FROM hunter_detections "
        f"WHERE domain IN ({marks}) AND status != 'cleared'", tuple(hosts))
    for r in hunted:
        out.setdefault(r["domain"], []).append((RedFlag(
            "PROACTIVE_DETECTION", "critical" if r["score"] >= 65 else "high", int(r["score"]),
            f"SAQR's proactive hunter found this new look-alike domain ({r['source']}) before any victim reported it.",
            f"عثر صائد صقر الاستباقي على هذا النطاق المقلِّد الجديد ({r['source']}) قبل أن يبلّغ عنه أي ضحية."),
            _entity_for(r["entity"])))
    demo = set(settings.demo_scam_domains)
    for h in hosts:
        if h in demo:
            out.setdefault(h, []).append((RedFlag(
                "CONFIRMED_SCAM_PAGE", "critical", 70,
                "Confirmed by SAQR analysts: a fake TAMM payment page.",
                "مؤكَّد من محللي صقر: صفحة دفع مزيفة تنتحل صفة منصة تم."), ENTITY_BY_ID.get("tamm")))
    return out


def _apply_known(hv: HostVerdict, known: list[tuple[RedFlag, Entity | None]]) -> HostVerdict:
    if not known or hv.whitelisted:
        return hv
    score = max([hv.score] + [f.points for f, _ in known])
    entity = hv.entity or next((e for _, e in known if e), None)
    return HostVerdict(hv.host, min(100, score), entity, [f for f, _ in known] + hv.flags,
                       passthrough=hv.passthrough)


def _entity_json(e: Entity | None) -> dict[str, Any] | None:
    if not e:
        return None
    return {"id": e.id, "name_en": e.name_en, "name_ar": e.name_ar, "official_domains": list(e.domains),
            "official_phones": list(e.phones), "official_phones_display": [format_phone(p) for p in e.phones]}


def _reasons(flags: list[RedFlag], verdict: str, official: bool) -> list[dict[str, str]]:
    if verdict == "SAFE":
        return [{"code": f.code, "en": f.en, "ar": f.ar} for f in flags if official and f.code == "OFFICIAL_DOMAIN"][:1]
    lead = [f for f in flags if f.code == "REDIRECTS_TO_FLAGGED"]
    top = sorted((f for f in flags if f.points > 0), key=lambda f: -f.points)[:MAX_REASONS]
    return [{"code": f.code, "en": f.en, "ar": f.ar} for f in lead + top]


async def batch_verdicts(urls: list[str], expand: bool = False) -> list[dict[str, Any]]:
    unique = list(dict.fromkeys(u.strip() for u in urls))
    targets: dict[str, str] = {}
    chains: dict[str, list[dict[str, Any]]] = {}
    for u in unique:
        target = resolve_mock_scam(u)[0]
        try:
            normalize_url(target)
        except ValueError:
            continue
        targets[u] = target
        chains[target] = static_chain(target)
    if expand:
        await expand_chains(chains)

    per_host: dict[str, HostVerdict] = {}
    host_of_url: dict[str, str] = {}
    for hops in chains.values():
        for hop in hops:
            if hop.get("note") == "blocked_private" and hop.get("via") != "input":
                continue
            if hop["url"] in host_of_url:
                continue
            try:
                hv = await assess_host(hop["url"])
            except ValueError:
                continue
            host_of_url[hop["url"]] = hv.host
            per_host.setdefault(hv.host, hv)
    known = await known_evidence(sorted(per_host))
    per_host = {h: _apply_known(hv, known.get(h, [])) for h, hv in per_host.items()}

    results: dict[str, dict[str, Any]] = {}
    for u in unique:
        target = targets.get(u)
        hops = chains.get(target or "", [])
        chain = list({host_of_url[h["url"]]: per_host[host_of_url[h["url"]]]
                      for h in hops if h["url"] in host_of_url}.values())
        if not chain:
            results[u] = {"url": u, "domain": None, "input_domain": host_of(u) or None, "score": 0, "verdict": None,
                          "entity": None, "official": False, "reasons": [], "redirected": False,
                          "unresolved_shortener": False, "error": "Not a website address"}
            continue
        judged = judge(chain)
        input_host = chain[0].host
        flags = redirects.flags_for(hops, input_host, judged.host, judged.verdict) + judged.flags
        official = judged.official and judged.verdict == "SAFE" and all(h.passthrough for h in chain)
        results[u] = {
            "url": u, "domain": judged.host, "input_domain": host_of(u) or input_host,
            "score": judged.score, "verdict": judged.verdict,
            "entity": _entity_json(judged.entity) if (judged.verdict != "SAFE" or official) else None,
            "official": official,
            "reasons": _reasons(flags, judged.verdict, official),
            "redirected": judged.host != input_host,
            "unresolved_shortener": redirects.is_shortener(chain[-1].host),
        }
    return [results[u.strip()] for u in urls]


@router.post("/batch-verdict", dependencies=[Depends(batch_rate_limit)])
async def batch_verdict(req: BatchVerdictRequest):
    t0 = time.perf_counter()
    results = await batch_verdicts(req.urls, expand=req.expand)
    return {"results": results, "count": len(results), "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1)}


# ---------------------------------------------------------------------------------------------
# Phones
# ---------------------------------------------------------------------------------------------
def format_phone(digits: str) -> str:
    """800555 -> '800 555', 600599999 -> '600 599 999', 971500007781 -> '+971 50 000 7781'."""
    d = normalise_phone(digits)
    if d.startswith(("800", "600")) and len(d) > 3:
        rest = d[3:]
        groups = [rest] if len(rest) <= 4 else [rest[i:i + 3] for i in range(0, len(rest), 3)]
        return " ".join([d[:3], *groups])
    if d.startswith("971") and len(d) >= 11:
        local = d[3:]
        return f"+971 {local[:-7]} {local[-7:-4]} {local[-4:]}"
    return d


async def check_phone(phone: str, claimed_entity: str | None = None, context: str | None = None) -> dict[str, Any]:
    norm = normalise_phone(phone)
    if len(norm) < 3:
        raise ValueError("Not a phone number")
    claimed = match_entity(claimed_entity)[0] if claimed_entity else None
    owner = OFFICIAL_PHONES.get(norm)
    flags = phone_flags(claimed, phone) if claimed and claimed.phones else []
    codes = {f.code for f in flags}
    if claimed and claimed.phones:
        status = ("mobile_for_institution" if "MOBILE_FOR_INSTITUTION" in codes
                  else "unofficial" if "UNOFFICIAL_PHONE" in codes else "official")
    else:
        status = "official" if owner and not claimed else "unknown"
    linked = [] if status == "official" else await pins_sharing_phone(norm)
    if linked:
        names = "; ".join(r["label"] for r in linked[:3])
        flags.insert(0, RedFlag(
            "PHONE_LINKED_TO_SCAM", "critical", 25,
            f"This number is attached to {len(linked)} fake map listing(s) SAQR linked to fraud: {names}.",
            f"هذا الرقم مرتبط بـ{len(linked)} إدراج(ات) مزيفة على الخريطة ربطها صقر بالاحتيال."))
        status = "linked_to_scam" if status == "unknown" else status
    if status in {"mobile_for_institution", "linked_to_scam"} or (linked and status == "unofficial"):
        level = "danger"
    elif status == "unofficial":
        level = "danger" if context == "ad" else "caution"
    elif status == "official":
        level = "official"
    else:
        level = "none"
    entity = claimed or owner
    flags.sort(key=lambda f: -f.points)
    return {"phone": phone, "normalized": norm, "status": status, "level": level,
            "claimed_entity": claimed_entity, "entity": _entity_json(entity),
            "reasons": [{"code": f.code, "en": f.en, "ar": f.ar} for f in flags][:MAX_REASONS]}


@router.post("/check-phone", dependencies=[Depends(batch_rate_limit)])
async def check_phone_endpoint(req: CheckPhoneRequest):
    try:
        return await check_phone(req.phone, req.claimed_entity, req.context)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
