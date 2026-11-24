"""Central configuration for SAQR-INTEL, loaded from environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
load_dotenv(BASE_DIR / ".env")


def _bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _float(name: str, default: float) -> float:
    try:
        return float(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


def _list(name: str, default: str = "") -> list[str]:
    return [x.strip() for x in os.getenv(name, default).split(",") if x.strip()]


@dataclass(frozen=True)
class Settings:
    app_name: str = "SAQR-INTEL"
    env: str = os.getenv("APP_ENV", "development")
    database_path: str = os.getenv("DATABASE_PATH", str(BASE_DIR / "data" / "saqr_intel.db"))
    cors_origins: list[str] = field(
        default_factory=lambda: _list(
            "CORS_ORIGINS", "https://saqr-intel.vercel.app,http://localhost:3000,http://127.0.0.1:3000")
    )
    # Vercel production + preview deployments of this project (saqr-intel-<hash>-<team>.vercel.app).
    cors_origin_regex: str = os.getenv("CORS_ORIGIN_REGEX", r"https://saqr-intel(-[a-z0-9-]+)?\.vercel\.app")

    # --- LLM -----------------------------------------------------------------
    # auto -> Gemini if key present, else OpenAI if key present, else rules engine
    llm_provider: str = os.getenv("LLM_PROVIDER", "auto").lower()
    gemini_api_key: str = os.getenv("GEMINI_API_KEY", "") or os.getenv("GOOGLE_API_KEY", "")
    # Tried in order; a model that is busy (503), retired (404) or over quota (429) is skipped in
    # about a second. Google retires model names regularly (2.5-flash went in 2026), hence a chain.
    gemini_models: list[str] = field(default_factory=lambda: _list(
        "GEMINI_MODEL", "gemini-3.8-flash,gemini-3.6-flash,gemini-3.5-flash,gemini-3.5-flash-lite,gemini-3.1-flash-lite"))

    @property
    def gemini_model(self) -> str:
        return self.gemini_models[0] if self.gemini_models else "gemini-3.8-flash"
    openai_api_key: str = os.getenv("OPENAI_API_KEY", "")
    openai_model: str = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
    llm_timeout_s: float = _float("LLM_TIMEOUT_SECONDS", 20.0)

    # --- Network intelligence ------------------------------------------------
    offline_mode: bool = _bool("OFFLINE_MODE", False)  # skip every outbound lookup
    whois_timeout_s: float = _float("WHOIS_TIMEOUT_SECONDS", 8.0)
    dns_timeout_s: float = _float("DNS_TIMEOUT_SECONDS", 3.0)
    tls_timeout_s: float = _float("TLS_TIMEOUT_SECONDS", 5.0)
    extra_whitelist: list[str] = field(default_factory=lambda: _list("EXTRA_WHITELIST_DOMAINS"))

    # --- Sandbox -------------------------------------------------------------
    # ENABLE_PLAYWRIGHT=false (cloud / Render free tier): never launch Chromium (keeps RAM low); pages
    # are fetched with httpx instead and screenshots are None. Falls back to SANDBOX_ENABLED (default on).
    sandbox_enabled: bool = _bool("ENABLE_PLAYWRIGHT", _bool("SANDBOX_ENABLED", True))
    sandbox_timeout_ms: int = _int("SANDBOX_TIMEOUT_MS", 15000)
    sandbox_max_concurrency: int = _int("SANDBOX_MAX_CONCURRENCY", 3)
    chromium_path: str = os.getenv("PLAYWRIGHT_CHROMIUM_PATH", "")
    allow_private_targets: bool = _bool("ALLOW_PRIVATE_TARGETS", False)  # SSRF guard
    # Optional UAE residential/mobile egress proxy to defeat datacenter-IP cloaking
    sandbox_proxy_server: str = os.getenv("SANDBOX_PROXY_SERVER", "")
    sandbox_proxy_username: str = os.getenv("SANDBOX_PROXY_USERNAME", "")
    sandbox_proxy_password: str = os.getenv("SANDBOX_PROXY_PASSWORD", "")

    # --- Maps ----------------------------------------------------------------
    google_maps_api_key: str = os.getenv("GOOGLE_MAPS_API_KEY", "")
    osm_reverse_enabled: bool = _bool("OSM_REVERSE_GEOCODE", True)

    # --- CT monitor ----------------------------------------------------------
    # simulated | certstream | off
    ct_mode: str = os.getenv("CT_MODE", "simulated").lower()
    certstream_url: str = os.getenv("CERTSTREAM_URL", "wss://certstream.calidog.io/")
    ct_sim_interval_s: float = _float("CT_SIM_INTERVAL_SECONDS", 12.0)
    ct_alert_threshold: int = _int("CT_ALERT_THRESHOLD", 45)

    # --- Proactive hunter -------------------------------------------------------
    # live | simulated | off. Finds scam domains before any citizen sees them (saqr/intel/hunter.py).
    # OFFLINE_MODE turns live into simulated (synthetic, labelled leads; no network).
    hunter_mode: str = os.getenv("HUNTER_MODE", "live").strip().lower()
    hunter_sources: list[str] = field(default_factory=lambda: _list("HUNTER_SOURCES", "lookalike_sweep,crtsh,ct,nrd"))
    hunter_interval_s: float = _float("HUNTER_INTERVAL_SECONDS", 900.0)
    hunter_start_delay_s: float = _float("HUNTER_START_DELAY_SECONDS", 45.0)
    hunter_sim_interval_s: float = _float("HUNTER_SIM_INTERVAL_SECONDS", 120.0)
    # Limits that keep a 512 MB single-worker host alive.
    hunter_max_scans_per_cycle: int = _int("HUNTER_MAX_SCANS_PER_CYCLE", 12)
    hunter_scan_concurrency: int = _int("HUNTER_SCAN_CONCURRENCY", 2)
    hunter_scan_timeout_s: float = _float("HUNTER_SCAN_TIMEOUT_SECONDS", 75.0)
    hunter_lookalikes_per_brand: int = _int("HUNTER_LOOKALIKES_PER_BRAND", 300)
    hunter_sweep_batch: int = _int("HUNTER_SWEEP_BATCH", 600)  # look-alike names resolved per cycle
    hunter_dns_concurrency: int = _int("HUNTER_DNS_CONCURRENCY", 25)
    hunter_triage_threshold: int = _int("HUNTER_TRIAGE_THRESHOLD", 35)  # lexical + URL-model score to earn a full scan
    hunter_use_llm: bool = _bool("HUNTER_USE_LLM", False)  # off: the hunt must not spend the citizens' LLM quota
    hunter_crtsh_queries: int = _int("HUNTER_CRTSH_QUERIES", 3)  # crt.sh keyword searches per cycle
    hunter_crtsh_timeout_s: float = _float("HUNTER_CRTSH_TIMEOUT_SECONDS", 60.0)
    hunter_crtsh_max_age_hours: float = _float("HUNTER_CRTSH_MAX_AGE_HOURS", 168.0)
    # A mild warning on a domain older than this is treated as an unrelated established site.
    hunter_established_days: int = _int("HUNTER_ESTABLISHED_DAYS", 730)

    # --- NextDNS phone shield sync --------------------------------------------
    # SAQR's high-risk domains are pushed to this NextDNS profile's denylist, so phones using it
    # (iPhone profile / Android Private DNS) block them in every app.
    nextdns_api_key: str = os.getenv("NEXTDNS_API_KEY", "")
    nextdns_profile_id: str = os.getenv("NEXTDNS_PROFILE_ID", "").strip().lower()
    nextdns_api_base: str = os.getenv("NEXTDNS_API_BASE", "https://api.nextdns.io")
    nextdns_sync_interval_s: float = _float("NEXTDNS_SYNC_INTERVAL_SECONDS", 60.0)
    nextdns_min_score: int = _int("NEXTDNS_MIN_SCORE", 65)
    # SAQR's own public addresses: always SAFE, never published to DNS blocklists / NextDNS, never
    # linked to a scam network (the website shares Vercel servers with the demo scam pages).
    own_hosts: list[str] = field(default_factory=lambda: _list(
        "OWN_HOSTS", "saqr-intel.vercel.app,saqr-intel-api.onrender.com"))
    # Global phishing feeds (Phishing Army + OpenPhish), refreshed every 6 h. THREAT_FEEDS=false to disable.
    threat_feeds_enabled: bool = _bool("THREAT_FEEDS", True)
    # Fake scam pages built for the phone demo (demo-scam-site/). Always flagged, so a Render restart
    # (which wipes the scan history) never stops the phone alert for them.
    demo_scam_domains: list[str] = field(default_factory=lambda: _list("DEMO_SCAM_DOMAINS") or ["saqr-demo-scam.vercel.app", "aed-refund-claim.vercel.app", "uae-fines-refund-portal.onrender.com"])
    # Domains seen ONLY by the certificate-transparency feed are not auto-pushed unless enabled.
    nextdns_include_ct: bool = _bool("NEXTDNS_INCLUDE_CT", False)

    # --- Email scanning --------------------------------------------------------
    # Live phishing-campaign feeds (CERT / vendor RSS) merged with the built-in seed list.
    campaign_feeds_enabled: bool = _bool("CAMPAIGN_FEEDS", True)
    campaign_refresh_hours: float = _float("CAMPAIGN_REFRESH_HOURS", 6.0)
    # Own bucket for POST /api/analyze-email (0 = off); defaults to RATE_LIMIT_PER_MINUTE.
    email_rate_limit_per_minute: int = _int("EMAIL_RATE_LIMIT_PER_MINUTE", _int("RATE_LIMIT_PER_MINUTE", 30))
    # Extra mail servers whose Authentication-Results headers are believed (Gmail, Outlook, Yahoo,
    # iCloud, Zoho and Proton are built in), e.g. "mx.myisp.ae".
    email_trusted_authserv: list[str] = field(default_factory=lambda: _list("EMAIL_TRUSTED_AUTHSERV"))
    # Laptop only: let a citizen's own AI endpoint be a local address (e.g. Ollama on 127.0.0.1).
    user_llm_allow_private: bool = _bool("USER_LLM_ALLOW_PRIVATE", False)

    # --- Security ------------------------------------------------------------
    police_api_key: str = os.getenv("POLICE_API_KEY", "")  # empty = open demo mode
    rate_limit_per_minute: int = _int("RATE_LIMIT_PER_MINUTE", 30)

    @property
    def active_llm(self) -> str:
        p = self.llm_provider
        if p == "gemini" and self.gemini_api_key:
            return "gemini"
        if p == "openai" and self.openai_api_key:
            return "openai"
        if p == "auto":
            if self.gemini_api_key:
                return "gemini"
            if self.openai_api_key:
                return "openai"
        return "rules"


settings = Settings()
