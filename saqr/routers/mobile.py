"""System-wide DNS protection setup for phones (no app install).

GET /api/ios-dns-profile     -> Apple configuration profile (.mobileconfig) with encrypted DNS (DoH)
GET /api/android-dns-config  -> hostname for Android "Private DNS" (DNS-over-TLS)

Security: the DNS server inside a downloadable profile decides where ALL of a phone's lookups go.
To stop anyone crafting a link to this official endpoint that installs an attacker's DNS server,
`doh_url` is limited to known protective resolvers and `nextdns_id` must be a plain NextDNS ID.
"""
from __future__ import annotations

import re
import uuid
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import Response

router = APIRouter(prefix="/api", tags=["Mobile DNS shield"])

DEFAULT_DOH = "https://security.cloudflare-dns.com/dns-query"
DEFAULT_DOT = "security.cloudflare-dns.com"
ALLOWED_DOH_HOSTS = {
    "security.cloudflare-dns.com",  # Cloudflare 1.1.1.2: blocks malware & phishing
    "family.cloudflare-dns.com",
    "dns.nextdns.io",
    "dns.quad9.net",
}
NEXTDNS_ID = re.compile(r"^[a-z0-9]{4,16}$")
PROFILE_NAMESPACE = uuid.UUID("6f1c2a8e-5b7d-4a3e-9c1f-0d2e4b6a8c10")  # stable: reinstalling replaces, not duplicates


def _nextdns_id(raw: str | None) -> str | None:
    if raw is None or not raw.strip():
        return None
    value = raw.strip().lower()
    if not NEXTDNS_ID.match(value):
        raise HTTPException(422, "nextdns_id must be the 4-16 letter/digit ID from your NextDNS dashboard (e.g. abc123).")
    return value


def _checked_doh(url: str) -> str:
    parts = urlsplit(url.strip())
    if parts.scheme != "https" or (parts.hostname or "").lower() not in ALLOWED_DOH_HOSTS:
        raise HTTPException(422, f"doh_url must be an https URL on one of: {', '.join(sorted(ALLOWED_DOH_HOSTS))}")
    return url.strip()


def build_mobileconfig(doh_url: str, label: str) -> str:
    profile_uuid = str(uuid.uuid5(PROFILE_NAMESPACE, f"profile:{doh_url}")).upper()
    payload_uuid = str(uuid.uuid5(PROFILE_NAMESPACE, f"dns:{doh_url}")).upper()
    url = escape(doh_url)
    name = "SAQR-INTEL Citizen DNS Shield"
    desc = escape(f"Encrypted DNS ({label}) that blocks known phishing and scam websites in every app. "
                  "Abu Dhabi Police SAQR-INTEL citizen shield. Remove any time in Settings.")
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>DNSSettings</key>
      <dict>
        <key>DNSProtocol</key>
        <string>HTTPS</string>
        <key>ServerURL</key>
        <string>{url}</string>
      </dict>
      <key>PayloadDescription</key>
      <string>{desc}</string>
      <key>PayloadDisplayName</key>
      <string>{name}</string>
      <key>PayloadIdentifier</key>
      <string>ae.saqr-intel.dns.settings.{payload_uuid}</string>
      <key>PayloadType</key>
      <string>com.apple.dnsSettings.managed</string>
      <key>PayloadUUID</key>
      <string>{payload_uuid}</string>
      <key>PayloadVersion</key>
      <integer>1</integer>
      <key>ProhibitDisablement</key>
      <false/>
    </dict>
  </array>
  <key>PayloadDescription</key>
  <string>{desc}</string>
  <key>PayloadDisplayName</key>
  <string>{name}</string>
  <key>PayloadIdentifier</key>
  <string>ae.saqr-intel.dns.profile</string>
  <key>PayloadOrganization</key>
  <string>SAQR-INTEL</string>
  <key>PayloadRemovalDisallowed</key>
  <false/>
  <key>PayloadType</key>
  <string>Configuration</string>
  <key>PayloadUUID</key>
  <string>{profile_uuid}</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
</dict>
</plist>
"""


@router.get("/ios-dns-profile", response_class=Response,
            responses={200: {"content": {"application/x-apple-aspen-config": {}}}})
async def ios_dns_profile(
    doh_url: str = Query(DEFAULT_DOH, description="DNS-over-HTTPS URL (Cloudflare, NextDNS or Quad9 only)."),
    nextdns_id: str | None = Query(None, description="Optional NextDNS configuration ID; overrides doh_url."),
):
    nid = _nextdns_id(nextdns_id)
    if nid:
        doh, label = f"https://dns.nextdns.io/{nid}", f"NextDNS {nid}"
    else:
        doh = _checked_doh(doh_url)
        label = urlsplit(doh).hostname or "DoH"
    return Response(
        content=build_mobileconfig(doh, label),
        media_type="application/x-apple-aspen-config",
        headers={"Content-Disposition": 'attachment; filename="SAQR-INTEL-Shield.mobileconfig"', "Cache-Control": "no-store"},
    )


@router.get("/android-dns-config")
async def android_dns_config(nextdns_id: str | None = Query(None, description="Optional NextDNS configuration ID.")):
    nid = _nextdns_id(nextdns_id)
    host = f"{nid}.dns.nextdns.io" if nid else DEFAULT_DOT
    return {
        "dot_hostname": host,
        "provider": "NextDNS" if nid else "Cloudflare 1.1.1.2 (malware & phishing blocking)",
        "setting": "Android Settings → Network & Internet → Private DNS → Private DNS provider hostname",
    }
