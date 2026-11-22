"""Module 5a — 1-click law-enforcement takedown dossier."""
from __future__ import annotations

import json
import secrets
from typing import Any
from urllib.parse import quote

from ..db import db, iso, utcnow
from .domain_intel import sha256_text


def defang(s: str | None) -> str:
    if not s:
        return ""
    return s.replace("http", "hxxp").replace(".", "[.]")


async def _syndicate_context(scan: dict[str, Any]) -> dict[str, Any] | None:
    from .graph_engine import compute_clusters

    node_syn, *_ = await compute_clusters()
    keys = []
    if scan["kind"] == "url":
        keys = [f"domain:{scan['domain']}"]
    elif scan.get("listing"):
        keys = [scan["listing"]["pin_id"]]
    for k in keys:
        if k in node_syn:
            s = node_syn[k]
            return {k2: s[k2] for k2 in ("id", "name", "name_ar", "description", "domains", "ip_addresses",
                                         "map_pins", "phone_numbers", "citizen_reports", "impersonated_entities",
                                         "first_seen", "last_activity")}
    return None


async def build_dossier(scan: dict[str, Any], officer: str | None = None) -> dict[str, Any]:
    now = utcnow()
    case_ref = f"ADP-CYB-{now:%Y}-{secrets.token_hex(3).upper()}"
    ti = scan.get("technical_indicators", {})
    listing = scan.get("listing") or {}
    target_domain = scan.get("domain") or listing.get("website_domain")
    syndicate = await _syndicate_context(scan)

    reports = await db.fetchall(
        "SELECT n.id, n.first_seen, n.data_json FROM graph_edges e JOIN graph_nodes n ON n.id=e.target "
        "WHERE e.type='reported_by_citizen' AND e.source IN (?, ?) ORDER BY n.first_seen",
        (f"domain:{target_domain}", listing.get("pin_id") or "-"))

    timeline = []
    if ti.get("creation_date"):
        timeline.append({"ts": ti["creation_date"], "event": "Domain registered", "source": "WHOIS"})
    if ti.get("ssl_not_before"):
        timeline.append({"ts": ti["ssl_not_before"], "event": f"TLS certificate issued ({ti.get('ssl_issuer')})",
                         "source": "Certificate Transparency / TLS handshake"})
    for r in reports:
        data = json.loads(r["data_json"] or "{}")
        timeline.append({"ts": r["first_seen"], "event": f"Citizen report {r['id'].split(':', 1)[1]} "
                                                          f"via {data.get('channel') or 'portal'}",
                         "source": "SAQR-INTEL citizen portal"})
    timeline.append({"ts": scan["created_at"], "event": f"SAQR-INTEL analysis {scan['scan_id']}: {scan['verdict']} "
                                                         f"({scan['risk_score']}/100)", "source": "SAQR-INTEL"})
    timeline.append({"ts": iso(now), "event": f"Takedown dossier {case_ref} generated", "source": "SAQR-INTEL"})
    timeline.sort(key=lambda x: x["ts"] or "")

    abuse = ti.get("abuse_emails") or []
    registrar = ti.get("registrar") or "Unknown registrar"
    entity = scan.get("impersonated_entity") or "a UAE government/financial entity"
    harvested = ", ".join(ti.get("harvested_fields") or []) or "n/a"
    evidence_url = ti.get("final_url") or scan.get("normalized_url") or ""
    ips = ti.get("ip_addresses") or []

    registrar_notice = (
        f"Subject: URGENT abuse report — phishing domain {target_domain} (Ref {case_ref})\n\n"
        f"To: {', '.join(abuse) if abuse else f'Abuse desk of {registrar}'}\n\n"
        f"Abu Dhabi Police Cybercrime unit reports that the domain {target_domain}, sponsored by {registrar}, "
        f"is being used for phishing / fraud that impersonates {entity}. The site collects: {harvested}.\n\n"
        f"Evidence (captured {scan['created_at']} UTC):\n"
        f"  - URL (defanged): {defang(evidence_url)}\n"
        f"  - Hosting IP(s): {', '.join(ips) or 'n/a'} ({ti.get('asn') or 'ASN n/a'} {ti.get('asn_org') or ''})\n"
        f"  - Screenshot SHA-256: {scan.get('evidence_hashes', {}).get('screenshot_sha256') or 'n/a'}\n"
        f"  - DOM text SHA-256: {scan.get('evidence_hashes', {}).get('dom_text_sha256') or 'n/a'}\n\n"
        f"Under your registrar accreditation abuse obligations (e.g. ICANN RAA §3.18) we request that you suspend "
        f"the domain (clientHold), preserve registrant and payment records, and confirm action to this office.\n\n"
        f"Abu Dhabi Police — Cybercrime Investigations"
    )
    hosting_notice = (
        f"Subject: Abuse report — phishing content hosted on {', '.join(ips) or 'your network'} (Ref {case_ref})\n\n"
        f"Please disable the fraudulent content at {defang(evidence_url)} impersonating {entity}, and preserve "
        f"server logs, account and payment records pending a lawful request.\n\nAbu Dhabi Police — Cybercrime Investigations"
    )

    dossier = {
        "dossier_id": f"DOS-{secrets.token_hex(4).upper()}",
        "case_reference": case_ref,
        "classification": "RESTRICTED — LAW ENFORCEMENT SENSITIVE",
        "generated_at": iso(now), "generated_by": officer or "SAQR-INTEL automated",
        "scan_id": scan["scan_id"], "scan_kind": scan["kind"],
        "summary": {
            "target": target_domain or listing.get("name"), "target_defanged": defang(target_domain),
            "verdict": scan["verdict"], "risk_score": scan["risk_score"],
            "impersonated_entity": scan.get("impersonated_entity"),
            "official_domains": scan.get("official_domains", []),
            "harvested_data_types": ti.get("harvested_fields", []),
            "citizen_reports": len(reports),
            "narrative_en": scan.get("citizen_explanation_en"),
        },
        "whois": {
            "registrar": ti.get("registrar"), "creation_date": ti.get("creation_date"),
            "domain_age_hours": ti.get("domain_age_hours"), "registrant_country": ti.get("registrant_country"),
            "abuse_contacts": abuse, "name_servers": ti.get("name_servers", []),
        },
        "dns": {"a": ips, "aaaa": ti.get("ipv6_addresses", []), "mx": ti.get("mx", []),
                "ns": ti.get("name_servers", []), "status": ti.get("dns_status")},
        "network": {"ip_addresses": ips, "asn": ti.get("asn"), "asn_org": ti.get("asn_org"),
                    "country": ti.get("ip_country"), "prefix": ti.get("ip_prefix"),
                    "shared_infrastructure": ti.get("shared_infrastructure")},
        "tls": {"issuer": ti.get("ssl_issuer"), "not_before": ti.get("ssl_not_before"),
                "cert_age_hours": ti.get("cert_age_hours"), "sha256": ti.get("ssl_sha256"),
                "valid": ti.get("ssl_valid")},
        "sandbox_evidence": {
            "final_url": ti.get("final_url"), "redirect_chain": ti.get("redirect_chain", []),
            "page_title": ti.get("page_title"), "cloaking": ti.get("cloaking"),
            "forms": ti.get("forms", []), "external_form_actions": ti.get("external_form_actions", []),
            "evidence_source": ti.get("sandbox_evidence_source"),
        },
        "maps_evidence": listing or None,
        "red_flags": scan.get("red_flags", []),
        "evidence_integrity": {
            **scan.get("evidence_hashes", {}),
            "scan_record_sha256": sha256_text(json.dumps(
                {k: v for k, v in scan.items() if k != "screenshot_base64"}, sort_keys=True, default=str)),
            "hash_algorithm": "SHA-256",
            "note": "Hashes computed at capture time; retain the original scan record for chain of custody.",
        },
        "syndicate": syndicate,
        "timeline": timeline,
        "legal_basis": [
            "UAE Federal Decree-Law No. 34 of 2021 on Combatting Rumours and Cybercrimes (subject to legal review)",
            "UAE Federal Decree-Law No. 31 of 2021 (Penal Code) — fraud provisions (subject to legal review)",
        ],
        "recommended_actions": [
            {"priority": 1, "action": "Registrar suspension (clientHold)", "addressee": registrar},
            {"priority": 1, "action": "Hosting provider content removal & log preservation",
             "addressee": ti.get("asn_org") or "Hosting provider"},
            {"priority": 1, "action": "National ISP-level block request", "addressee": "TDRA (UAE)"},
            {"priority": 2, "action": "Browser blocklist submission",
             "addressee": "Google Safe Browsing / Microsoft SmartScreen",
             "links": [f"https://safebrowsing.google.com/safebrowsing/report_phish/?url={quote(evidence_url)}",
                       "https://www.microsoft.com/en-us/wdsi/support/report-unsafe-site"]},
            {"priority": 2, "action": "Notify impersonated entity security team", "addressee": entity},
            {"priority": 3, "action": "Publish public awareness alert", "addressee": "AD Police Media"},
        ] + ([{"priority": 1, "action": "Google Maps listing removal (impersonation / fake business)",
               "addressee": "Google Business Profile — legal removal request"}] if listing else []),
        "notices": {"registrar_abuse": registrar_notice, "hosting_abuse": hosting_notice},
    }
    await db.execute("INSERT INTO dossiers (id, scan_id, created_at, dossier_json) VALUES (?,?,?,?)",
                     (dossier["dossier_id"], scan["scan_id"], dossier["generated_at"],
                      json.dumps(dossier, ensure_ascii=False, default=str)))
    return dossier


def dossier_markdown(d: dict[str, Any]) -> str:
    s = d["summary"]
    lines = [
        f"# TAKEDOWN DOSSIER — {d['case_reference']}",
        f"**{d['classification']}**  ",
        f"Generated: {d['generated_at']} by {d['generated_by']} · Scan `{d['scan_id']}`",
        "", "## Summary",
        f"- **Target:** `{s['target_defanged']}`",
        f"- **Verdict:** {s['verdict']} ({s['risk_score']}/100)",
        f"- **Impersonates:** {s['impersonated_entity']} (official: {', '.join(s['official_domains']) or 'n/a'})",
        f"- **Harvests:** {', '.join(s['harvested_data_types']) or 'n/a'}",
        f"- **Citizen reports:** {s['citizen_reports']}",
        "", "## WHOIS",
        *[f"- {k}: {v}" for k, v in d["whois"].items()],
        "", "## Network / DNS / TLS",
        *[f"- {k}: {v}" for k, v in {**d["network"], **{f"tls_{k}": v for k, v in d["tls"].items()}}.items()],
        "", "## Red flags",
        *[f"- [{f['severity'].upper()}] {f['en']}" for f in d["red_flags"]],
        "", "## Timeline (UTC)",
        *[f"- {t['ts']} — {t['event']} _({t['source']})_" for t in d["timeline"]],
        "", "## Evidence integrity",
        *[f"- {k}: `{v}`" for k, v in d["evidence_integrity"].items()],
    ]
    if d.get("syndicate"):
        sy = d["syndicate"]
        lines += ["", f"## Linked syndicate — {sy['name']} ({sy['id']})",
                  f"- Domains: {', '.join(defang(x) for x in sy['domains'])}",
                  f"- IPs: {', '.join(sy['ip_addresses'])}", f"- Map pins: {'; '.join(sy['map_pins'])}",
                  f"- Phones: {', '.join(sy['phone_numbers'])}"]
    lines += ["", "## Recommended actions",
              *[f"{a['priority']}. {a['action']} → {a['addressee']}" for a in d["recommended_actions"]],
              "", "## Registrar abuse notice", "```", d["notices"]["registrar_abuse"], "```",
              "", "## Hosting abuse notice", "```", d["notices"]["hosting_abuse"], "```",
              "", "## Legal basis", *[f"- {x}" for x in d["legal_basis"]]]
    return "\n".join(lines)
