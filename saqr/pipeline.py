"""URL analysis orchestration: lexical -> network intel -> sandbox -> AI verdict -> graph."""
from __future__ import annotations

import asyncio
import logging
import re
import secrets
import time
from datetime import timedelta
from typing import Any

from .db import db, iso, utcnow
from .intel import ai_inspector, graph_engine
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
from .intel.sandbox import sandbox
from .seed_data import DEMO_INTEL, resolve_mock_scam

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
    lex = analyze_lexical(url)
    timings["lexical_ms"] = int((time.perf_counter() - t0) * 1000)

    t = time.perf_counter()
    net = {"evidence_source": "skipped", "ip_addresses": []} if lex.is_whitelisted else await gather_network(lex)
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

    t = time.perf_counter()
    fv = await ai_inspector.inspect(lex, net, page, syndicate, use_llm=use_llm)
    timings["ai_ms"] = int((time.perf_counter() - t) * 1000)

    screenshot = (page or {}).pop("screenshot_b64", None)
    page_text = (page or {}).get("text") or ""
    ent = fv.impersonated
    result: dict[str, Any] = {
        "scan_id": scan_id, "kind": "url", "created_at": created_at or iso(),
        "target": intercepted_url, "input_url": intercepted_url, "normalized_url": lex.normalized_url,
        "mock_scam_replica": mock_slug, "interception_channel": interception_channel,
        "domain": lex.host, "registered_domain": lex.registered_domain, "unicode_domain": lex.unicode_host,
        "channel": channel, "reporter": reporter, "message_text": message_text,
        "risk_score": fv.risk_score, "verdict": fv.verdict,
        "impersonated_entity": fv.impersonated_name,
        "impersonated_entity_ar": ent.name_ar if ent else None,
        "official_domains": list(ent.domains) if ent else [],
        "is_official_domain": lex.is_whitelisted,
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
            "redirect_chain": (page or {}).get("redirect_chain", []),
            "page_title": (page or {}).get("page_title"),
            "page_text_excerpt": page_text[:1500],
            "cloaking": (page or {}).get("cloaking"),
            "sandbox_status": (page or {}).get("status", "skipped"),
            "sandbox_evidence_source": (page or {}).get("evidence_source"),
            "blocked_requests": (page or {}).get("blocked_requests", []),
        },
        "evidence_hashes": {
            "screenshot_sha256": sha256_text(screenshot) if screenshot else None,
            "dom_text_sha256": sha256_text(page_text) if page_text else None,
        },
        "syndicate": graph_engine._syn_brief(syndicate),  # noqa: SLF001
        "analyzer": {"engine": fv.engine, "confidence": fv.confidence},
        "timings": timings,
    }
    await db.save_scan(result, screenshot)
    if ingest and fv.verdict != "SAFE":
        delta = await graph_engine.ingest_url_scan(result)
        result["graph_delta"] = delta
        if delta.get("syndicate"):
            result["syndicate"] = delta["syndicate"]
        await db.save_scan(result, screenshot)
    result["timings"]["total_ms"] = int((time.perf_counter() - t0) * 1000)
    result["screenshot_base64"] = screenshot
    return result


async def seed_historical_scans() -> None:
    """Run the real pipeline over seeded domains (no LLM, no live network) so dossiers work instantly."""
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
