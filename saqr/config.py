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
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
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
    sandbox_enabled: bool = _bool("SANDBOX_ENABLED", True)
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
