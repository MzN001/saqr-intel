"""URL analysis orchestration: lexical -> network intel -> sandbox -> AI verdict -> graph."""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from datetime import timedelta
from typing import Any

from urllib.parse import urlsplit

from .config import settings
from .db import db, iso, utcnow
from .intel import ai_inspector, brand_fingerprint, graph_engine, page_signals, redirects, visual_similarity
from .intel.domain_intel import (
    LexicalReport,
    age_hours,
    analyze_lexical,
    asn_lookup,
    dns_lookup,
    sha256_text,
    tls_lookup,
    whois_lookup,
)
from .intel.sandbox import page_from_html, sandbox
from .intel.threat_feeds import on_free_hosting
from .seed_data import DEMO_INTEL, replica_html, resolve_mock_scam

log = logging.getLogger("saqr.pipeline")
URL_IN_TEXT = re.compile(r"(?:hxxps?|https?)://\S+|(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,24}(?:/\S*)?", re.I)


def new_scan_id(prefix: str = "SCN") -> str:
    return f"{prefix}-{utcnow():%Y%m%d}-{secrets.token_hex(3).upper()}"


def extract_url(text: str) -> str | None:
    m = URL_IN_TEXT.search(text or "")
    return m.group(0).rstrip(".,;:!?)\"'") if m else None


async def gather_network(lex: LexicalReport) -> dict[str, Any]:
    seeded = DEMO_INTEL.get(lex.registered_domain) or DEMO_INTEL.get(lex.host)
    if seeded:
        created = utcnow() - timedelta(hours=seeded["registered_hours_ago"])
        return {
            "evidence_source": "seeded_intel", "ip_addresses": [seeded["ip"]], "asn": seeded["asn"],
            "asn_org": seeded["asn_org"], "ip_country": seeded["country"], "shared_infrastructure": False,
            "ssl_issuer": seeded["ssl_issuer"], "ssl_valid": True, "cert_age_hours": seeded["cert_age_hours"],
            "ssl_not_before": iso(utcnow() - timedelta(hours=seeded["cert_age_hours"])),
            "registrar": seeded["registrar"], "creation_date": iso(created),
            "domain_age_hours": float(seeded["registered_hours_ago"]), "abuse_emails": seeded["abuse_emails"],
            "name_servers": seeded["name_servers"], "mx": [], "dns_status": "ok",
        }

    who, dns_res, tls = await asyncio.gather(
        whois_lookup(lex.registered_domain), dns_lookup(lex.host), tls_lookup(lex.host))
    ips = dns_res.get("a", [])
    asn = await asn_lookup(ips[0]) if ips else {"status": "no_ip"}
    return {
        "evidence_source": "live",
        "ip_addresses": ips, "ipv6_addresses": dns_res.get("aaaa", []),
        "asn": asn.get("asn"), "asn_org": asn.get("org"), "ip_country": asn.get("country"),
        "ip_prefix": asn.get("prefix"), "shared_infrastructure": asn.get("shared_infrastructure", False),
        "ssl_issuer": tls.get("issuer"), "ssl_valid": tls.get("valid"), "ssl_subject": tls.get("subject"),
        "ssl_not_before": tls.get("not_before"), "ssl_not_after": tls.get("not_after"),
        "cert_age_hours": tls.get("cert_age_hours"), "ssl_sha256": tls.get("sha256"),
        "registrar": who.get("registrar"), "creation_date": who.get("creation_date"),
        "domain_age_hours": age_hours(who.get("creation_date")), "abuse_emails": who.get("abuse_emails", []),
        "registrant_country": who.get("registrant_country"),
        "name_servers": who.get("name_servers") or dns_res.get("ns", []), "mx": dns_res.get("mx", []),
        "dns_status": dns_res.get("status"),
        "lookup_status": {"whois": who.get("status"), "dns": dns_res.get("status"), "tls": tls.get("status"),
                          "asn": asn.get("status")},
    }


def _hop_risk(lex: LexicalReport) -> int:
    """Cheap risk of one hop's address: look-alike rules + threat feeds + the URL classifier."""
    if lex.is_whitelisted:
        return 0
    return min(100, lex.score + sum(f.points for f in ai_inspector.intel_flags(lex)))


def _hop_pages(hops: list[dict[str, Any]], bodies: dict[int, dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Page evidence for every hop whose HTML was already read while walking the chain (no extra
    request): page_signals + form fields, judged with the hop's own address. Adds page_risk /
    page_notes / page_title to the hop record. Returns host -> {page, score}."""
    out: dict[str, dict[str, Any]] = {}
    for i, body in sorted(bodies.items()):
        hop = hops[i]
        try:
            hop_lex = page_signals.lexical(hop["url"])
        except ValueError:
            continue
        if hop_lex.is_whitelisted:
            continue
        page = page_from_html(body.get("html") or "", hop["url"], body.get("status"))
        rr = ai_inspector.run_rules(hop_lex, {}, page, None)
        address = _hop_risk(hop_lex)
        lex_codes = {f.code for f in hop_lex.flags} | {"KNOWN_PHISHING_FEED", "AI_PHISHING_URL", "AI_SUSPICIOUS_URL"}
        hop["page_risk"] = max(0, rr.score - address)
        hop["page_notes"] = [f.code for f in rr.flags if f.points > 0 and f.code not in lex_codes][:6]
        hop["page_title"] = (page.get("page_title") or "")[:120]
        if hop_lex.host not in out or rr.score >= out[hop_lex.host]["score"]:
            out[hop_lex.host] = {"page": page, "score": rr.score}
    return out


async def follow_redirects(lex: LexicalReport, *, fast: bool,
                           pages: dict[str, dict[str, Any]] | None = None) -> tuple[LexicalReport, list[dict[str, Any]]]:
    """Walk the link's redirect chain and pick the host the verdict must be about.

    Every distinct host on the way is checked: its address and, when its HTML was read on the way,
    its page (combined evidence). The worst one is judged; when none stands out it is the final
    destination, unless that is a famous or official site and an unknown site sits in front of it
    (a scam page that bounces scanners to google.com must not be judged as Google).
    pages (out-parameter): host -> {page, score} of the hops whose HTML was read."""
    bodies: dict[int, dict[str, Any]] = {}
    hops = await redirects.resolve_chain(lex.normalized_url, max_hops=5 if fast else 8,
                                         timeout=2.5 if fast else 5.0, fast=fast, pages=bodies)
    hop_pages = _hop_pages(hops, bodies)
    if pages is not None:
        pages.update(hop_pages)
    by_host: dict[str, LexicalReport] = {lex.host: lex}
    for hop in hops[1:]:
        if hop.get("note") == "blocked_private":
            continue
        try:
            hop_lex = page_signals.lexical(hop["url"])
        except ValueError:
            continue
        by_host[hop_lex.host] = hop_lex  # the last address seen on a host is where its page lives
    if len(by_host) < 2:
        return lex, hops
    risks = {host: max(_hop_risk(hl), (hop_pages.get(host) or {}).get("score", 0)) for host, hl in by_host.items()}
    for hop in hops:
        if hop["host"] in risks:
            hop["risk"] = risks[hop["host"]]
    candidates = list(by_host.values())
    worst = max(risks.values())
    if worst > 0:
        return next(hl for hl in reversed(candidates) if risks[hl.host] == worst), hops
    final = candidates[-1]
    if redirects.is_trusted_passthrough(final.host, final.registered_domain):
        unknown = [hl for hl in candidates if not redirects.is_trusted_passthrough(hl.host, hl.registered_domain)]
        if unknown:
            return unknown[0], hops
    return final, hops


# ---------------------------------------------------------------------------
# Visual similarity: brand fingerprint (+ optional screenshot hash)
# ---------------------------------------------------------------------------
async def visual_similarity_for(lex: LexicalReport, page: dict[str, Any], *, deep: bool, net: dict[str, Any],
                                syndicate: dict[str, Any] | None, allow_network: bool) -> dict[str, Any] | None:
    """{score, matched_entity, matched_domain, components, screenshot_used} for the page, or None."""
    html = page.get("html") or ""
    if not html and page.get("evidence_source") == "seeded_replica":
        dom = lex.registered_domain if lex.registered_domain in DEMO_INTEL else lex.host
        html = replica_html(dom) if dom in DEMO_INTEL else ""
    if not html:
        return None
    base_url = page.get("final_url") or lex.normalized_url
    fp = brand_fingerprint.extract(html, base_url)
    host = (urlsplit(base_url).hostname or lex.host).lower()
    match = brand_fingerprint.best_match(fp, host=host)
    if match is None:
        return None
    # One optional request: the page's own favicon, only when the page already resembles a portal.
    if deep and allow_network and match["score"] >= 40:
        fav = brand_fingerprint.favicon_candidate(fp)
        if fav:
            fp["favicon_hash"] = await brand_fingerprint.fetch_favicon_hash(fav)
            if fp["favicon_hash"]:
                match = brand_fingerprint.best_match(fp, host=host) or match
    fp_score = match["score"]
    shot = None
    shot_used = False
    if deep and allow_network and settings.visual_screenshots:
        prelim = ai_inspector.run_rules(lex, net, {**page, "visual_similarity": _visual_view(match, fp_score, False)},
                                        syndicate).score
        if prelim >= 30 or fp_score >= 50 or lex.impersonated is not None:
            probe = await visual_similarity.capture_hash(base_url, page, settings.visual_screenshot_timeout_s)
            shot = visual_similarity.best_screenshot_match(probe, brand_fingerprint.baselines(), host)
    score = fp_score
    # Unrelated portals' thumbnails already reach 70-75% (white layouts): only a near-identical hash
    # (>= 88%, at most 7 of 64 bits differ) of the SAME portal the fingerprint picked raises the score.
    if shot and shot["id"] == match["id"] and shot["score"] >= visual_similarity.CORROBORATE_AT:
        bonus = min(15, round((shot["score"] - visual_similarity.CORROBORATE_AT) * 1.25))
        score = min(100, fp_score + bonus)
        if fp_score < brand_fingerprint.WEAK_THRESHOLD:
            score = min(score, brand_fingerprint.CLONE_THRESHOLD - 1)  # a hash alone never makes a clone
        shot_used = True
    view = _visual_view(match, score, shot_used)
    view["fingerprint_score"] = fp_score
    if shot:
        view["screenshot_similarity"] = shot["score"]
    return view


def _visual_view(match: dict[str, Any], score: int, shot_used: bool) -> dict[str, Any]:
    return {"score": int(score), "matched_entity": match.get("name_en"), "matched_entity_ar": match.get("name_ar"),
            "entity_id": match.get("entity_id"), "matched_domain": match.get("matched_domain"),
            "components": match.get("components"), "screenshot_used": shot_used,
            "baseline_status": match.get("status"), "official": False}


# ---------------------------------------------------------------------------
# Score breakdown (additive response field)
# ---------------------------------------------------------------------------
LAYERS: list[tuple[str, str, str, str, str]] = [
    # id, EN name, AR name, EN "nothing found", AR "nothing found"
    ("url_model", "AI address model", "نموذج العناوين الذكي",
     "The AI model does not find the address phishing-like.", "لا يرى النموذج الذكي أن العنوان يشبه عناوين التصيّد."),
    ("address", "Address rules (look-alike, brand, ending)", "قواعد العنوان (تشابه، علامة تجارية، امتداد)",
     "No look-alike, brand or address warning signs.", "لا توجد علامات تشابه أو انتحال في العنوان."),
    ("redirects", "Redirects", "التحويلات", "The link does not hide its destination.", "لا يخفي الرابط وجهته."),
    ("page", "Page evidence", "محتوى الصفحة", "Nothing dangerous found on the page.", "لم يُعثر على محتوى خطير في الصفحة."),
    ("cloaking", "Cloaking", "التخفّي", "Every visitor sees the same page.", "يرى جميع الزوار الصفحة نفسها."),
    ("visual", "Visual similarity", "التشابه البصري", "It does not imitate an official portal.", "لا تقلّد بوابة رسمية."),
    ("threat_feeds", "Threat feeds & scam networks", "قوائم التهديدات وشبكات الاحتيال",
     "Not listed by threat intelligence.", "غير مدرج في قوائم استخبارات التهديدات."),
    ("domain_age_tls", "Domain age & certificate", "عمر النطاق والشهادة",
     "No domain-age or certificate warning signs.", "لا توجد علامات تحذير في عمر النطاق أو الشهادة."),
]
_LAYER_OF = {
    **dict.fromkeys(("AI_PHISHING_URL", "AI_SUSPICIOUS_URL", "AI_NEW_DOMAIN", "SITE_TAKEN_DOWN"), "url_model"),
    **dict.fromkeys(("REDIRECTS_TO_FLAGGED", "URL_SHORTENER", "REDIRECT_CHAIN"), "redirects"),
    **dict.fromkeys(("CLOAKING", "MOBILE_CLOAKING_DETECTED"), "cloaking"),
    **dict.fromkeys(("VISUAL_BRAND_CLONE_DETECTED", "VISUAL_BRAND_SIMILARITY"), "visual"),
    **dict.fromkeys(("KNOWN_PHISHING_FEED", "KNOWN_SYNDICATE_INFRA"), "threat_feeds"),
    **dict.fromkeys(("NEWLY_REGISTERED", "YOUNG_DOMAIN", "FRESH_CERTIFICATE", "CERT_RENEWED", "TLS_INVALID"),
                    "domain_age_tls"),
    **dict.fromkeys(("CREDENTIAL_HARVESTING", "BRAND_CONTENT", "URGENCY_PRESSURE", "EXFIL_FORM", "NO_HTTPS",
                     "PROVIDER_PHISHING_WARNING", "SHORTLINK_DISABLED", "FORM_SERVICE_CREDENTIALS",
                     "BRAND_LOGIN_PAGE"), "page"),
}


def score_breakdown(flags: list[Any], rules_score: int, final_score: int, engine: str) -> list[dict[str, Any]]:
    """Ordered layers with their point contribution, built ONLY from the red flags (each flag in exactly
    one layer: nothing is double-counted), so the parts add up to the final risk_score:

        sum(layer points) + combination rules + AI judge == risk_score

    * "combination": the rules engine's adjustments to the plain flag sum (the 100 cap, and the floors
      that make brand + card form / confident AI model + independent clue = 70).
    * "ai_judge": what the LLM blend changed (blend(): rules are a floor; a confident, corroborated scam
      verdict weighs 0.75; a confident SAFE can halve a classifier-only warning, so it may be negative).
      0 when no LLM ran."""
    totals: dict[str, int] = {lid: 0 for lid, *_ in LAYERS}
    top: dict[str, Any] = {}
    for f in flags:
        layer = _LAYER_OF.get(f.code, "address")  # look-alike / lexical / official-domain flags
        totals[layer] += int(f.points)
        if f.points > 0 and (layer not in top or f.points > top[layer].points):
            top[layer] = f
        elif layer not in top and f.points == 0 and f.severity != "info":
            top[layer] = f
    out = []
    for lid, name_en, name_ar, none_en, none_ar in LAYERS:
        f = top.get(lid)
        out.append({"layer": lid, "name_en": name_en, "name_ar": name_ar, "points": totals[lid],
                    "summary_en": (f.en if f and f.points > 0 else none_en)[:160],
                    "summary_ar": (f.ar if f and f.points > 0 else none_ar)[:160]})
    flag_sum = sum(totals.values())
    if rules_score != flag_sum:
        delta = rules_score - flag_sum
        out.append({"layer": "combination", "name_en": "Combination rules", "name_ar": "قواعد الجمع",
                    "points": delta,
                    "summary_en": ("Capped at 100." if delta < 0 else
                                   "Independent warning signs agree, so the rules raise the score to a scam level."),
                    "summary_ar": ("الحد الأقصى 100." if delta < 0 else
                                   "تتوافق علامات خطر مستقلة، فترفع القواعد الدرجة إلى مستوى الاحتيال.")})
    used = engine != "rules"
    out.append({"layer": "ai_judge", "name_en": "AI judge", "name_ar": "المحكّم الذكي",
                "points": final_score - rules_score if used else 0,
                "summary_en": ("The AI judge's verdict was blended with the rules (rules are a floor)." if used else
                               "AI judge not used: rules-engine verdict."),
                "summary_ar": ("دُمج حكم المحكّم الذكي مع القواعد (القواعد حدّ أدنى)." if used else
                               "لم يُستخدم المحكّم الذكي: حكم محرك القواعد.")})
    return out


async def analyze_url(url: str, *, scan_id: str | None = None, channel: str | None = None,
                      reporter: str | None = None, message_text: str | None = None,
                      run_sandbox: bool = True, profile: str = "mobile", use_llm: bool = True,
                      ingest: bool = True, created_at: str | None = None,
                      interception_channel: str | None = None) -> dict[str, Any]:
    t0 = time.perf_counter()
    timings: dict[str, int] = {}
    scan_id = scan_id or new_scan_id()

    intercepted_url = url
    url, mock_slug = resolve_mock_scam(url)
    input_lex = lex = page_signals.lexical(url)
    timings["lexical_ms"] = int((time.perf_counter() - t0) * 1000)

    # Shorteners, open redirects, 30x / meta / JavaScript hops: judge where the link really goes.
    hops: list[dict[str, Any]] = []
    hop_pages: dict[str, dict[str, Any]] = {}
    if not mock_slug and lex.registered_domain not in DEMO_INTEL and lex.host not in DEMO_INTEL:
        t = time.perf_counter()
        try:
            lex, hops = await follow_redirects(lex, fast=not run_sandbox, pages=hop_pages)
        except Exception as exc:  # noqa: BLE001 - evidence gathering must never fail the scan
            log.warning("redirect chain for %s failed: %s", input_lex.host, exc)
        timings["redirect_ms"] = int((time.perf_counter() - t) * 1000)

    t = time.perf_counter()
    net = {"evidence_source": "skipped", "ip_addresses": []} if lex.is_whitelisted else await gather_network(lex)
    if on_free_hosting(lex.host):
        # Thousands of unrelated sites share a hosting platform's servers: never link them by IP
        # (SAQR's own website shares Vercel IPs with the demo scam pages).
        net["shared_infrastructure"] = True
    timings["network_ms"] = int((time.perf_counter() - t) * 1000)

    # Known-syndicate infrastructure check (before graph ingestion)
    probe = [f"domain:{lex.host}", f"domain:{lex.registered_domain}"]
    if not net.get("shared_infrastructure"):
        probe += [f"ip:{ip}" for ip in net.get("ip_addresses", [])]
    syndicate = None if lex.is_whitelisted else await graph_engine.syndicate_for(probe)

    page: dict[str, Any] | None = None
    if run_sandbox and not lex.is_whitelisted:
        t = time.perf_counter()
        page = await sandbox.inspect(lex.normalized_url, lex.registered_domain if lex.registered_domain in DEMO_INTEL
                                     else lex.host, profile)
        timings["sandbox_ms"] = int((time.perf_counter() - t) * 1000)

    # The judged hop's own page, read while walking the chain: it is the evidence when there is no
    # sandbox page, or when the sandbox was bounced elsewhere (a scam hop that forwards scanners on).
    hop_page = (hop_pages.get(lex.host) or {}).get("page")
    if hop_page and not lex.is_whitelisted:
        sandbox_host = (urlsplit((page or {}).get("final_url") or "").hostname or "").lower()
        if page is None or page.get("status") != "ok" or (sandbox_host and sandbox_host != lex.host):
            page = {**hop_page, "evidence_source": "redirect_hop",
                    "cloaking": (page or {}).get("cloaking"), "mobile_cloaking": (page or {}).get("mobile_cloaking")}

    visual: dict[str, Any] | None = None
    if page and page.get("status") == "ok" and not lex.is_whitelisted:
        t = time.perf_counter()
        try:
            visual = await visual_similarity_for(
                lex, page, deep=run_sandbox, net=net, syndicate=syndicate,
                allow_network=not settings.offline_mode and not mock_slug and lex.registered_domain not in DEMO_INTEL)
        except Exception as exc:  # noqa: BLE001 - optional evidence, never fails the scan
            log.warning("visual similarity for %s failed: %s", lex.host, exc)
        if visual:
            page["visual_similarity"] = visual
        timings["visual_ms"] = int((time.perf_counter() - t) * 1000)

    t = time.perf_counter()
    # Known training replicas are fully explained by the rules engine; skipping the LLM keeps the
    # stage demo deterministic and fast (well under 100 ms) even on a small cloud instance.
    fv = await ai_inspector.inspect(lex, net, page, syndicate, use_llm=use_llm and not mock_slug)
    timings["ai_ms"] = int((time.perf_counter() - t) * 1000)
    fv.flags = redirects.flags_for(hops, input_lex.host, lex.host, fv.verdict) + fv.flags
    if lex.host != input_lex.host:
        fv.explanation_en = f"This link ({input_lex.host}) really leads to {lex.host}.\n\n{fv.explanation_en}"
        fv.explanation_ar = f"هذا الرابط ({input_lex.host}) يقود فعلياً إلى {lex.host}.\n\n{fv.explanation_ar}"

    screenshot = (page or {}).pop("screenshot_b64", None)
    page_text = (page or {}).get("text") or ""
    ent = fv.impersonated
    result: dict[str, Any] = {
        "scan_id": scan_id, "kind": "url", "created_at": created_at or iso(),
        "target": intercepted_url, "input_url": intercepted_url, "normalized_url": lex.normalized_url,
        "mock_scam_replica": mock_slug, "interception_channel": interception_channel,
        "domain": lex.host, "registered_domain": lex.registered_domain, "unicode_domain": lex.unicode_host,
        "input_domain": input_lex.host,
        "channel": channel, "reporter": reporter, "message_text": message_text,
        "risk_score": fv.risk_score, "verdict": fv.verdict,
        "impersonated_entity": fv.impersonated_name,
        "impersonated_entity_ar": ent.name_ar if ent else None,
        "official_domains": list(ent.domains) if ent else [],
        "is_official_domain": lex.is_whitelisted,
        "verified_official": lex.is_whitelisted,  # alias of is_official_domain (same name as maps / message scans)
        "citizen_explanation_en": fv.explanation_en, "citizen_explanation_ar": fv.explanation_ar,
        "red_flags": [{"code": f.code, "severity": f.severity, "points": f.points, "en": f.en, "ar": f.ar}
                      for f in fv.flags],
        "llm_red_flags": fv.llm_flags,
        "lexical": {"similarity_to_official": lex.similarity, "is_punycode": lex.is_punycode, "tld": lex.tld,
                    "lexical_score": lex.score},
        "technical_indicators": {
            **{k: v for k, v in net.items()},
            "harvested_fields": fv.harvested,
            "forms": (page or {}).get("forms", []),
            "external_form_actions": (page or {}).get("external_form_actions", []),
            "final_url": (page or {}).get("final_url"),
            "http_status": (page or {}).get("http_status"),
            "redirect_chain": hops,
            "browser_redirects": (page or {}).get("redirect_chain", []),
            "page_title": (page or {}).get("page_title"),
            "page_text_excerpt": page_text[:1500],
            "cloaking": (page or {}).get("cloaking"),
            "mobile_cloaking": (page or {}).get("mobile_cloaking"),
            "sandbox_status": (page or {}).get("status", "skipped"),
            "sandbox_evidence_source": (page or {}).get("evidence_source"),
            "blocked_requests": (page or {}).get("blocked_requests", []),
        },
        "evidence_hashes": {
            "screenshot_sha256": sha256_text(screenshot) if screenshot else None,
            "dom_text_sha256": sha256_text(page_text) if page_text else None,
        },
        "syndicate": graph_engine._syn_brief(syndicate),  # noqa: SLF001
        "analyzer": {"engine": fv.engine, "confidence": fv.confidence, **fv.llm_extra},
        "visual_similarity": ({k: visual.get(k) for k in ("score", "matched_entity", "matched_domain", "components",
                                                          "screenshot_used")} if visual else None),
        "score_breakdown": score_breakdown(fv.flags, fv.rules_score, fv.risk_score, fv.engine),
        "timings": timings,
    }
    # scans.domain feeds the DNS blocklist / NextDNS: a shortener whose destination could not be
    # resolved must never be published or linked into the syndicate graph, nor a payment gateway's
    # shared checkout host (that would block every merchant's payments).
    unresolved_shortener = redirects.is_shortener(lex.host) or page_signals.payment_gateway(lex.host)
    stored = {**result, "domain": None} if unresolved_shortener else result
    await db.save_scan(stored, screenshot)
    if ingest and fv.verdict != "SAFE" and not unresolved_shortener:
        delta = await graph_engine.ingest_url_scan(result)
        result["graph_delta"] = delta
        if delta.get("syndicate"):
            result["syndicate"] = delta["syndicate"]
        await db.save_scan(result, screenshot)
    result["timings"]["total_ms"] = int((time.perf_counter() - t0) * 1000)
    result["screenshot_base64"] = screenshot
    return result


async def scan_demo_pages() -> None:
    """The phone-demo scam page lives on the real internet: scan it once per start (Render wipes the
    disk) so tapping its scam alert opens a full verdict. Skipped offline (tests)."""
    if settings.offline_mode:
        return
    for i, domain in enumerate(settings.demo_scam_domains, start=1):
        sid = f"SCN-DEMO-{i:04d}"
        if await db.fetchone("SELECT 1 FROM scans WHERE id=?", (sid,)):
            continue
        try:
            await analyze_url(f"https://{domain}/", scan_id=sid, channel="web", reporter="demo-seed",
                              use_llm=False, ingest=False, interception_channel="AUTO_TELECOM_DNS")
        except Exception as exc:  # noqa: BLE001
            log.warning("demo page scan %s failed: %s", domain, exc)


async def seed_historical_scans() -> None:
    """Run the real pipeline over seeded domains (no LLM, no live network) so dossiers work instantly."""
    await scan_demo_pages()  # first: the live phone demo must not wait behind the seeded domains
    for i, domain in enumerate(DEMO_INTEL, start=1):
        sid = f"SCN-SEED-{i:04d}"
        if await db.fetchone("SELECT 1 FROM scans WHERE id=?", (sid,)):
            continue
        try:
            hrs = max(0, DEMO_INTEL[domain]["registered_hours_ago"] - 1)
            await analyze_url(f"https://{domain}/", scan_id=sid, channel="sms", reporter="seed",
                              use_llm=False, ingest=False, created_at=iso(utcnow() - timedelta(hours=hrs)))
        except Exception as exc:  # noqa: BLE001
            log.warning("seed scan %s failed: %s", domain, exc)

