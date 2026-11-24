"""Module 2 — Search engine & Maps "Geo-Spoof" Sentinel.

Resolves a Google Maps URL / business name / coordinates into a listing (Google Places
API if a key is configured, else the seeded intel store, else caller-supplied fields),
then cross-verifies it against the official UAE registry:

* government / courier / bank name attached to an unofficial website
* phone number not on the entity's official list, or a mobile number for an institution
* the same phone number reused across multiple unrelated pins
* coordinates on a residential plot / empty lot / far from any official branch
"""
from __future__ import annotations

import hashlib
import logging
import math
import re
from typing import Any
from urllib.parse import parse_qs, unquote_plus, urlsplit

import httpx
from rapidfuzz import fuzz

from ..config import settings
from ..db import db
from ..security import host_is_safe_target
from ..seed_data import MAP_PINS, resolve_mock_scam
from .ai_inspector import intel_flags, verdict_for
from .domain_intel import RedFlag, analyze_lexical
from .registry import ABU_DHABI_BBOX, ALL_BRANDS, Entity, normalise_phone

log = logging.getLogger("saqr.maps")

SUSPICIOUS_PLACE_TYPES = {
    "residential", "house", "villa", "apartments", "construction", "brownfield", "greenfield",
    "vacant", "vacant_lot", "grass", "farmland", "sand", "scrub", "parking", "road", "track",
}
STRONG_FLAGS = {"UNOFFICIAL_DOMAIN_ON_LISTING", "PHISHING_WEBSITE_ON_LISTING", "LOOKALIKE_WEBSITE", "PHONE_REUSED_ACROSS_PINS",
                "KNOWN_SYNDICATE_INFRA", "MOBILE_FOR_INSTITUTION", "UNVERIFIED_LOCATION"}
MAPS_HOSTS = ("google.", "goo.gl", "maps.app.goo.gl", "g.co")


def haversine_km(lat1: float, lng1: float, lat2: float, lng2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2 - lat1), math.radians(lng2 - lng1)
    a = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(a))


def parse_maps_url(url: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    parts = urlsplit(url)
    path = unquote_plus(parts.path)
    m = re.search(r"!3d(-?\d+\.\d+)!4d(-?\d+\.\d+)", url) or re.search(r"@(-?\d+\.\d+),(-?\d+\.\d+)", url)
    if m:
        out["lat"], out["lng"] = float(m.group(1)), float(m.group(2))
    q = parse_qs(parts.query)
    for key in ("q", "query", "ll", "destination"):
        if key in q:
            val = q[key][0]
            cm = re.match(r"\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)\s*$", val)
            if cm and "lat" not in out:
                out["lat"], out["lng"] = float(cm.group(1)), float(cm.group(2))
            elif not cm:
                out.setdefault("name", val)
    pm = re.search(r"/place/([^/@]+)", path)
    if pm:
        out["name"] = pm.group(1).replace("+", " ").strip()
    return out


async def _expand_short_link(url: str) -> str:
    if settings.offline_mode:
        return url
    host = urlsplit(url).hostname or ""
    if not any(h in host for h in ("goo.gl", "g.co")):
        return url
    ok, _ = await host_is_safe_target(host)
    if not ok:
        return url
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=6) as c:
            r = await c.get(url)
            return str(r.url)
    except Exception:  # noqa: BLE001
        return url


async def places_lookup(name: str | None, lat: float | None, lng: float | None) -> dict[str, Any] | None:
    if not settings.google_maps_api_key or settings.offline_mode or not name:
        return None
    body: dict[str, Any] = {"textQuery": name, "languageCode": "en", "regionCode": "AE"}
    if lat is not None and lng is not None:
        body["locationBias"] = {"circle": {"center": {"latitude": lat, "longitude": lng}, "radius": 2000.0}}
    headers = {
        "X-Goog-Api-Key": settings.google_maps_api_key,
        "X-Goog-FieldMask": ("places.id,places.displayName,places.formattedAddress,places.location,"
                             "places.websiteUri,places.internationalPhoneNumber,places.types,"
                             "places.businessStatus,places.userRatingCount"),
    }
    try:
        async with httpx.AsyncClient(timeout=8) as c:
            r = await c.post("https://places.googleapis.com/v1/places:searchText", json=body, headers=headers)
            r.raise_for_status()
            places = r.json().get("places") or []
    except Exception as exc:  # noqa: BLE001
        log.warning("Places lookup failed: %s", exc)
        return None
    if not places:
        return None
    p = places[0]
    site = p.get("websiteUri") or ""
    return {
        "pin_id": f"pin:{p.get('id')}", "name": (p.get("displayName") or {}).get("text"),
        "address": p.get("formattedAddress"), "lat": (p.get("location") or {}).get("latitude"),
        "lng": (p.get("location") or {}).get("longitude"), "website": site,
        "phone": p.get("internationalPhoneNumber"), "place_types": p.get("types", []),
        "reviews": p.get("userRatingCount", 0), "source": "google_places",
    }


async def osm_reverse(lat: float, lng: float) -> dict[str, Any] | None:
    if not settings.osm_reverse_enabled or settings.offline_mode:
        return None
    try:
        async with httpx.AsyncClient(timeout=5, headers={"User-Agent": "SAQR-INTEL/1.0 (public-safety demo)"}) as c:
            r = await c.get("https://nominatim.openstreetmap.org/reverse",
                            params={"format": "jsonv2", "lat": lat, "lon": lng, "zoom": 18})
            r.raise_for_status()
            j = r.json()
            return {"category": j.get("category"), "type": j.get("type"), "addresstype": j.get("addresstype"),
                    "display_name": j.get("display_name")}
    except Exception as exc:  # noqa: BLE001
        log.info("OSM reverse failed: %s", exc)
        return None


def seeded_lookup(name: str | None, lat: float | None, lng: float | None, phone: str | None) -> dict[str, Any] | None:
    best, best_score = None, 0.0
    for pin in MAP_PINS:
        score = 0.0
        if lat is not None and lng is not None and haversine_km(lat, lng, pin["lat"], pin["lng"]) < 0.15:
            score += 60
        if name:
            score += fuzz.token_set_ratio(name.lower(), pin["name"].lower()) * 0.5
        if phone and normalise_phone(phone) == normalise_phone(pin["phone"]):
            score += 30
        if score > best_score:
            best, best_score = pin, score
    if not best or best_score < 45:
        return None
    return {"pin_id": best["id"], "name": best["name"], "address": best["area"], "lat": best["lat"],
            "lng": best["lng"], "website": best["website"], "phone": best["phone"],
            "place_types": [best["place_type"]], "reviews": best["reviews"], "source": "seeded_intel"}


def match_entity(name: str | None) -> tuple[Entity | None, float]:
    if not name:
        return None, 0.0
    n = name.lower()
    best: tuple[Entity | None, float] = (None, 0.0)
    for ent in ALL_BRANDS:
        if ent.category == "global":
            # Global brands by name only, and never ordinary words ("Noon Bakery" is not noon.com).
            names = [] if ent.name_en.lower() in ent.common_keywords else [ent.name_en]
        else:
            names = ([ent.name_en] if len(ent.name_en) > 3 else []) + [ent.name_ar, *ent.aliases]
        for alias in names:
            a = alias.lower()
            if len(a) <= 4:  # short brands must be whole words ("Tammy's" != TAMM)
                s = 100.0 if re.search(rf"(^|\W){re.escape(a)}(\W|$)", n) else 0.0
            else:
                s = 100.0 if a in n else fuzz.token_set_ratio(a, n) if len(n) > 3 else 0.0
            if s > best[1]:
                best = (ent, s)
    return best if best[1] >= 85 else (None, best[1])


INSTITUTION_CATEGORIES = {"government", "bank", "courier", "identity"}


def phone_flags(entity: Entity | None, phone: str | None) -> list[RedFlag]:
    """Is the phone shown next to an institution's name (Maps card, search ad) one of its official
    numbers? A personal mobile number for a bank or government office is a strong scam sign."""
    norm_phone = normalise_phone(phone)
    if not entity or not norm_phone:
        return []
    if norm_phone in {normalise_phone(p) for p in entity.phones}:
        return []
    flags = [RedFlag(
        "UNOFFICIAL_PHONE", "medium", 10,
        f"Phone {phone} is not an official {entity.name_en} number (official: {', '.join(entity.phones)}).",
        f"الرقم {phone} ليس رقماً رسمياً لـ{entity.name_ar} (الرسمي: {'، '.join(entity.phones)}).",
    )]
    if norm_phone.startswith("9715") and entity.category in INSTITUTION_CATEGORIES:
        flags.append(RedFlag("MOBILE_FOR_INSTITUTION", "high", 15,
                             "Institutions don't use personal mobile numbers on official listings.",
                             "المؤسسات الرسمية لا تستخدم أرقام هواتف متحركة شخصية في إدراجاتها."))
    return flags


async def pins_sharing_phone(norm_phone: str, exclude_pin: str = "") -> list[dict[str, Any]]:
    """Map listings in the intelligence graph that use this (normalised) phone number."""
    return await db.fetchall(
        "SELECT e.source, n.label FROM graph_edges e JOIN graph_nodes n ON n.id = e.source "
        "WHERE e.type='shares_phone' AND e.target=? AND e.source != ?",
        (f"phone:{norm_phone}", exclude_pin))


async def scan_listing(*, maps_url: str | None, business_name: str | None, query: str | None,
                       website: str | None, phone: str | None, lat: float | None, lng: float | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {}
    if maps_url:
        host = urlsplit(maps_url if "://" in maps_url else "https://" + maps_url).hostname or ""
        if not any(h in host for h in MAPS_HOSTS):
            raise ValueError("maps_url must be a Google Maps link")
        parsed = parse_maps_url(await _expand_short_link(maps_url))
    q_coords = re.match(r"\s*(-?\d+\.\d+)\s*,\s*(-?\d+\.\d+)\s*$", query or "")
    if q_coords:
        lat = lat if lat is not None else float(q_coords.group(1))
        lng = lng if lng is not None else float(q_coords.group(2))
        query = None
    name = business_name or parsed.get("name") or query
    lat = lat if lat is not None else parsed.get("lat")
    lng = lng if lng is not None else parsed.get("lng")

    found = await places_lookup(name, lat, lng) or seeded_lookup(name, lat, lng, phone)
    listing = {
        "pin_id": None, "name": name, "address": None, "lat": lat, "lng": lng, "website": website,
        "phone": phone, "place_types": [], "reviews": None, "source": "user_supplied",
    }
    if found:
        for k, v in found.items():
            if listing.get(k) in (None, "", []) or k in {"pin_id", "source", "place_types", "reviews", "address"}:
                listing[k] = v
    if not listing["name"] and not listing["lat"]:
        raise ValueError("Provide a maps_url, business_name, query, or coordinates")
    if not listing["pin_id"]:
        key = f"{(listing['name'] or '').lower()}|{round(listing['lat'] or 0, 4)}|{round(listing['lng'] or 0, 4)}"
        listing["pin_id"] = "pin:" + hashlib.sha1(key.encode()).hexdigest()[:12]

    flags: list[RedFlag] = []
    entity, name_conf = match_entity(listing["name"])
    website_domain = None
    website_risk = 0
    site_lex = None
    if listing.get("website"):
        try:
            site_lex = analyze_lexical(resolve_mock_scam(listing["website"])[0])
            website_domain = site_lex.host
            website_risk = site_lex.score
        except ValueError:
            pass
    listing["website_domain"] = website_domain
    if site_lex and site_lex.impersonated and not entity:
        entity = site_lex.impersonated

    # 0) The linked website is a known (threat feeds) or AI-detected phishing site
    site_intel = intel_flags(site_lex) if site_lex and not site_lex.is_whitelisted else []
    strong_intel = [f for f in site_intel if f.code in {"KNOWN_PHISHING_FEED", "AI_PHISHING_URL"}]
    if strong_intel:
        f0 = strong_intel[0]
        flags.append(RedFlag(
            "PHISHING_WEBSITE_ON_LISTING", "critical", 60 if f0.code == "KNOWN_PHISHING_FEED" else 40,
            f"The listing's website {website_domain} is a phishing site: {f0.en}",
            f"موقع الإدراج {website_domain} موقع تصيّد احتيالي: {f0.ar}",
        ))

    # 1) Official name + unofficial domain
    if entity and site_lex and not site_lex.is_whitelisted:
        flags.append(RedFlag(
            "UNOFFICIAL_DOMAIN_ON_LISTING", "critical", 30 if entity.category == "global" else 40,
            f"The listing uses the name '{entity.name_en}' but links to {website_domain}, which is NOT an official "
            f"{entity.name_en} website ({', '.join(entity.domains)}).",
            f"الإدراج يستخدم اسم «{entity.name_ar}» لكنه يربط بالموقع {website_domain} وهو ليس موقعاً رسمياً "
            f"(الرسمي: {'، '.join(entity.domains)}).",
        ))
        if site_lex.score >= 30:
            flags.append(RedFlag("LOOKALIKE_WEBSITE", "high", min(20, site_lex.score // 3),
                                 f"The linked website itself looks like a scam domain ({', '.join(f.code for f in site_lex.flags[:3])}).",
                                 "الموقع المرتبط نفسه يبدو نطاقاً احتيالياً."))
    elif entity and site_lex and site_lex.is_whitelisted:
        flags.append(RedFlag("OFFICIAL_DOMAIN", "info", 0, f"Website {website_domain} is official.",
                             f"الموقع {website_domain} رسمي."))
    elif not entity and site_lex and site_lex.score >= 30:
        flags.append(RedFlag("LOOKALIKE_WEBSITE", "high", min(30, site_lex.score // 2),
                             f"The linked website {website_domain} shows scam indicators.",
                             f"الموقع المرتبط {website_domain} يُظهر مؤشرات احتيال."))

    # 2) Phone checks
    norm_phone = normalise_phone(listing.get("phone"))
    flags += phone_flags(entity, listing.get("phone"))
    if norm_phone:
        rows = await pins_sharing_phone(norm_phone, exclude_pin=listing["pin_id"])
        if rows:
            names = [r["label"] for r in rows][:5]
            flags.append(RedFlag(
                "PHONE_REUSED_ACROSS_PINS", "critical", 25,
                f"The same phone number is attached to {len(rows)} other map listing(s): {'; '.join(names)}.",
                f"نفس رقم الهاتف مرتبط بـ{len(rows)} إدراج(ات) أخرى على الخريطة.",
            ))
            listing["phone_linked_pins"] = [r["source"] for r in rows]

    # 3) Location checks
    osm = None
    if listing.get("lat") is not None and listing.get("lng") is not None:
        la, ln = float(listing["lat"]), float(listing["lng"])
        lat_min, lat_max, lng_min, lng_max = ABU_DHABI_BBOX
        listing["inside_abu_dhabi"] = lat_min <= la <= lat_max and lng_min <= ln <= lng_max
        if entity and entity.branches:
            dists = sorted((haversine_km(la, ln, b[1], b[2]), b[0]) for b in entity.branches)
            listing["nearest_official_branch"] = {"name": dists[0][1], "distance_km": round(dists[0][0], 2)}
            if dists[0][0] > 1.5:
                flags.append(RedFlag(
                    "NOT_AT_OFFICIAL_BRANCH", "medium", 15,
                    f"The pin is {dists[0][0]:.1f} km from the nearest official {entity.name_en} site ({dists[0][1]}).",
                    f"الدبوس يبعد {dists[0][0]:.1f} كم عن أقرب موقع رسمي لـ{entity.name_ar}.",
                ))
        osm = await osm_reverse(la, ln) if listing["source"] != "seeded_intel" else None
        types = {t.lower() for t in listing.get("place_types") or []}
        if osm:
            listing["osm"] = osm
            types |= {str(osm.get("type") or "").lower(), str(osm.get("addresstype") or "").lower()}
            if osm.get("category") == "highway":
                types.add("road")
        bad = types & SUSPICIOUS_PLACE_TYPES
        if bad and (entity or flags):
            flags.append(RedFlag(
                "UNVERIFIED_LOCATION", "high", 20,
                f"The pin points to a {', '.join(sorted(bad)).replace('_', ' ')} — not a real service centre.",
                "الدبوس يشير إلى أرض فضاء أو منزل سكني — وليس مركز خدمة حقيقياً.",
            ))
    if listing.get("reviews") is not None and listing["reviews"] < 5 and entity:
        flags.append(RedFlag("LOW_REVIEW_HISTORY", "low", 5, "The listing has almost no review history.",
                             "الإدراج لا يملك تقريباً أي سجل تقييمات."))

    # 4) Syndicate link
    from .graph_engine import syndicate_for

    probe = [listing["pin_id"]] + ([f"domain:{website_domain}"] if website_domain else []) + \
        ([f"phone:{norm_phone}"] if norm_phone else [])
    syn = await syndicate_for(probe)
    if syn:
        flags.append(RedFlag("KNOWN_SYNDICATE_INFRA", "critical", 25,
                             f"Linked to known criminal network: {syn['name']}.",
                             f"مرتبط بشبكة إجرامية معروفة: {syn.get('name_ar') or syn['name']}."))

    score = min(100, sum(f.points for f in flags))
    # Weak signals alone (unlisted landline, distance from HQ, few reviews) never exceed SAFE:
    # real police stations / branches are often missing from the demo registry.
    if not any(f.code in STRONG_FLAGS for f in flags):
        score = min(score, 29)
    verdict = verdict_for(score)
    ent_en = entity.name_en if entity else "an institution"
    ent_ar = entity.name_ar if entity else "جهة رسمية"
    top = sorted((f for f in flags if f.points), key=lambda f: -f.points)[:4]
    if verdict == "SAFE":
        en = "No geo-spoofing indicators found for this listing."
        ar = "لم يتم العثور على مؤشرات تزييف جغرافي لهذا الإدراج."
    else:
        en = (f"{'DANGER' if verdict == 'HIGH-RISK SCAM' else 'CAUTION'} — This map listing pretends to be "
              f"{ent_en} but fails official verification:\n" + "\n".join(f"• {f.en}" for f in top) +
              ("\n\nUse only official websites/numbers: " + ", ".join(entity.domains + entity.phones) if entity else ""))
        ar = (f"{'خطر' if verdict == 'HIGH-RISK SCAM' else 'تنبيه'} — هذا الإدراج على الخريطة ينتحل صفة {ent_ar} "
              f"ولم يجتز التحقق الرسمي:\n" + "\n".join(f"• {f.ar}" for f in top) +
              ("\n\nاستخدم فقط المواقع والأرقام الرسمية: " + "، ".join(entity.domains + entity.phones) if entity else ""))
    return {
        "listing": listing, "risk_score": score, "verdict": verdict,
        "impersonated_entity": entity.name_en if entity else None,
        "impersonated_entity_ar": entity.name_ar if entity else None, "entity_match_confidence": round(name_conf, 1),
        "official_domains": list(entity.domains) if entity else [],
        "official_phones": list(entity.phones) if entity else [],
        "website_risk": website_risk,
        "red_flags": [{"code": f.code, "severity": f.severity, "points": f.points, "en": f.en, "ar": f.ar} for f in flags],
        "citizen_explanation_en": en, "citizen_explanation_ar": ar,
        "syndicate_hint": syn["id"] if syn else None,
    }
