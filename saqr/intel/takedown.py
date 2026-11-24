"""Module 5a — 1-click law-enforcement takedown dossier."""
from __future__ import annotations

import base64
import hashlib
import io
import json
import secrets
import zipfile
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote, urlsplit

from ..config import settings
from ..db import db, iso, utcnow
from .domain_intel import sha256_text
from .sandbox import sandbox

SOURCE_LABELS = {"lookalike_sweep": "Look-alike domain sweep (DNS)", "nrd": "Newly registered domains feed",
                 "ct": "Certificate Transparency log monitor", "crtsh": "crt.sh certificate search"}
# Scans SAQR made itself (hunter, seed data): never counted as a citizen meeting the domain.
_NON_CITIZEN = ("hunter", "seed", "demo-seed")
_NON_CITIZEN_SQL = ",".join(f"'{r}'" for r in _NON_CITIZEN)


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


def _hours(start: str | None, end: str | None) -> float | None:
    def parse(v: str | None) -> datetime | None:
        try:
            dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            return None
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)

    a, b = parse(start), parse(end)
    return round((b - a).total_seconds() / 3600, 2) if a and b else None


def _no_screenshot_reason(ti: dict[str, Any]) -> str:
    if not settings.sandbox_enabled:
        return "No screenshot in cloud mode: the page was fetched over HTTP only (no browser sandbox)."
    if (ti.get("sandbox_status") or "skipped") == "skipped":
        return "No screenshot: this was a fast scan without the browser sandbox."
    if not sandbox.available:
        return "No screenshot: the browser sandbox is not available on this server."
    return "No screenshot was captured: the page did not render in the browser sandbox."


def redirect_hops(ti: dict[str, Any]) -> list[dict[str, Any]]:
    """The redirect chain as hop objects {url, host, status, via, risk, note}. Older scans (and the
    browser sandbox) store plain URL strings: those become hops with only url + host."""
    hops = []
    for h in ti.get("redirect_chain") or []:
        if isinstance(h, str):
            h = {"url": h, "host": urlsplit(h).hostname, "status": None, "via": None, "risk": None, "note": None}
        if isinstance(h, dict) and h.get("url"):
            hops.append({k: h.get(k) for k in ("url", "host", "status", "via", "risk", "note")})
    return hops


async def detection_context(domain: str | None = None, scan_id: str | None = None,
                            detection_id: int | None = None) -> dict[str, Any] | None:
    """The Proactive Hunter's record of this domain, with its lead time: when SAQR found it, and how
    many citizens met it afterwards (and how many of those were blocked)."""
    if detection_id is not None:
        row = await db.fetchone("SELECT * FROM hunter_detections WHERE id=?", (detection_id,))
    elif scan_id or domain:
        row = await db.fetchone("SELECT * FROM hunter_detections WHERE scan_id=? OR domain=? ORDER BY id LIMIT 1",
                                (scan_id or "-", domain or "-"))
    else:
        row = None
    if not row:
        return None
    seen = await db.fetchone(
        "SELECT COUNT(*) n, COALESCE(SUM(verdict != 'SAFE'), 0) blocked, MIN(created_at) first_at FROM scans "
        "WHERE (domain = ? OR domain LIKE '%.' || ?) AND created_at >= ? "
        f"AND COALESCE(reporter,'') NOT IN ({_NON_CITIZEN_SQL})", (row["domain"], row["domain"], row["first_seen"]))
    visits = int(seen["n"]) if seen else 0
    now = iso()
    return {
        "detection_id": row["id"], "domain": row["domain"], "defanged_domain": defang(row["domain"]),
        "source": row["source"], "source_label": SOURCE_LABELS.get(row["source"], row["source"]),
        "first_seen": row["first_seen"], "scanned_at": row["scanned_at"], "status": row["status"],
        "triage_score": row["triage_score"], "score": row["score"], "verdict": row["verdict"],
        "entity": row["entity"], "flags": json.loads(row["flags_json"] or "[]"),
        "domain_age_hours": row["domain_age_hours"], "registrar": row["registrar"], "ip": row["ip"],
        "asn": row["asn"], "scan_id": row["scan_id"], "simulated": bool(row["simulated"]),
        "detail": json.loads(row["detail_json"] or "{}"),
        "citizen_visits": visits, "citizen_visits_blocked": int(seen["blocked"]) if seen else 0,
        "first_citizen_at": seen["first_at"] if visits else None,
        "lead_time_hours": _hours(row["first_seen"], seen["first_at"]) if visits else None,
        "hours_since_detection": _hours(row["first_seen"], now),
        "caught_before_any_citizen": True,
    }


async def build_dossier(scan: dict[str, Any], officer: str | None = None,
                        detection: dict[str, Any] | None = None) -> dict[str, Any]:
    now = utcnow()
    case_ref = f"ADP-CYB-{now:%Y}-{secrets.token_hex(3).upper()}"
    ti = scan.get("technical_indicators", {})
    listing = scan.get("listing") or {}
    target_domain = scan.get("domain") or listing.get("website_domain")
    syndicate = await _syndicate_context(scan)
    if detection is None and scan["kind"] == "url":
        detection = await detection_context(domain=target_domain, scan_id=scan["scan_id"])
    first = await db.fetchone("SELECT MIN(created_at) ts FROM scans WHERE domain=?", (target_domain or "-",))
    first_seen = min(x for x in (first["ts"] if first else None, (detection or {}).get("first_seen"),
                                 scan["created_at"]) if x)
    shot = await db.fetchone("SELECT screenshot_b64 IS NOT NULL AND screenshot_b64 != '' has FROM scans WHERE id=?",
                             (scan["scan_id"],))
    has_screenshot = bool(shot and shot["has"])
    hops = redirect_hops(ti)

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
    if detection:
        timeline.append({"ts": detection["first_seen"], "source": "SAQR-INTEL Proactive Hunter",
                         "event": f"Found by the Proactive Hunter ({detection['source_label']}) before any citizen "
                                  f"visited or reported it" + (" [SIMULATED]" if detection["simulated"] else "")})
        if detection["first_citizen_at"]:
            timeline.append({"ts": detection["first_citizen_at"], "source": "SAQR-INTEL citizen shield",
                             "event": f"First citizen met it, {detection['lead_time_hours']} h after detection "
                                      f"({detection['citizen_visits_blocked']}/{detection['citizen_visits']} "
                                      f"visits blocked)"})
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
        + (f"  - Redirect chain: {' -> '.join(defang(h['host'] or h['url']) for h in hops)}\n" if len(hops) > 1 else "")
        + f"  - First seen by SAQR-INTEL: {first_seen} UTC\n"
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
            "input_domain": scan.get("input_domain"), "final_url": ti.get("final_url"), "redirect_chain": hops,
            "browser_redirects": ti.get("browser_redirects", []), "http_status": ti.get("http_status"),
            "page_title": ti.get("page_title"), "cloaking": ti.get("cloaking"),
            "forms": ti.get("forms", []), "external_form_actions": ti.get("external_form_actions", []),
            "evidence_source": ti.get("sandbox_evidence_source"),
            "screenshot_available": has_screenshot,
            "screenshot_note": None if has_screenshot else _no_screenshot_reason(ti),
        },
        "detection": detection,
        "timestamps": {"first_seen": first_seen, "scanned_at": scan["created_at"], "generated_at": iso(now),
                       "timezone": "UTC"},
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
        "", "## Redirect chain",
        *([f"{i}. `{defang(h['url'])}` ({h.get('via') or 'start'}, HTTP {h.get('status') or 'n/a'})"
           + (f" — {h['note']}" if h.get("note") else "")
           for i, h in enumerate(d.get("sandbox_evidence", {}).get("redirect_chain") or [], start=1)] or ["- none"]),
        f"- Screenshot: {'captured' if d.get('sandbox_evidence', {}).get('screenshot_available') else d.get('sandbox_evidence', {}).get('screenshot_note') or 'n/a'}",
        "", "## Red flags",
        *[f"- [{f['severity'].upper()}] (+{f.get('points', 0)}) {f['en']}" for f in d["red_flags"]],
        "", "## Timeline (UTC)",
        *[f"- {t['ts']} — {t['event']} _({t['source']})_" for t in d["timeline"]],
        "", "## Evidence integrity",
        *[f"- {k}: `{v}`" for k, v in d["evidence_integrity"].items()],
    ]
    if d.get("timestamps"):
        lines += ["", "## Timestamps (UTC)", *[f"- {k}: {v}" for k, v in d["timestamps"].items()]]
    if d.get("detection"):
        det = d["detection"]
        lines += ["", "## Proactive detection" + (" — SIMULATED" if det["simulated"] else ""),
                  f"- Source: {det['source_label']}", f"- First seen: {det['first_seen']}",
                  f"- Citizens who met it since: {det['citizen_visits']} ({det['citizen_visits_blocked']} blocked)",
                  f"- Lead time before the first citizen: "
                  f"{det['lead_time_hours'] if det['lead_time_hours'] is not None else 'no citizen has met it yet'}"]
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


def takedown_notice(d: dict[str, Any]) -> str:
    n = d["notices"]
    return (f"{d['classification']}\nCase {d['case_reference']} · dossier {d['dossier_id']} · generated "
            f"{d['generated_at']} UTC\n\n=== REGISTRAR ABUSE NOTICE ===\n\n{n['registrar_abuse']}\n\n"
            f"=== HOSTING ABUSE NOTICE ===\n\n{n['hosting_abuse']}\n")


def evidence_pack(d: dict[str, Any], screenshot_b64: str | None = None) -> bytes:
    """A zip for the prosecutor: dossier.json, dossier.md, takedown_notice.txt, screenshot.jpg (when
    one was captured) and manifest.json with the SHA-256 of every file in the pack."""
    files: dict[str, bytes] = {
        "dossier.json": json.dumps(d, indent=2, ensure_ascii=False, default=str).encode(),
        "dossier.md": dossier_markdown(d).encode(),
        "takedown_notice.txt": takedown_notice(d).encode(),
    }
    if screenshot_b64:
        files["screenshot.jpg"] = base64.b64decode(screenshot_b64)
    captured = (d.get("evidence_integrity") or {}).get("screenshot_sha256")
    manifest = {
        "case_reference": d["case_reference"], "dossier_id": d["dossier_id"], "scan_id": d["scan_id"],
        "generated_at": d["generated_at"], "packed_at": iso(), "hash_algorithm": "SHA-256",
        "files": [{"name": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in files.items()],
        "screenshot_matches_capture_hash": (sha256_text(screenshot_b64) == captured) if screenshot_b64 and captured
        else None,
        "screenshot_note": None if screenshot_b64 else (d.get("sandbox_evidence") or {}).get("screenshot_note"),
        "note": "screenshot_sha256 in the dossier is the hash of the base64 text stored at capture time; "
                "the file hashes above are of the bytes in this pack.",
    }
    files["manifest.json"] = json.dumps(manifest, indent=2, ensure_ascii=False).encode()
    try:
        stamp = datetime.fromisoformat(d["generated_at"].replace("Z", "+00:00")).timetuple()[:6]
    except (TypeError, ValueError):
        stamp = (1980, 1, 1, 0, 0, 0)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in files.items():
            z.writestr(zipfile.ZipInfo(name, date_time=stamp), data, compress_type=zipfile.ZIP_DEFLATED)
    return buf.getvalue()
