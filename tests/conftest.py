"""Shared test setup: never let tests use the developer's real .env secrets or accounts.

python-dotenv does not override variables that already exist, so blanking them here (before any
`saqr` import) keeps the real NextDNS / LLM keys from .env out of the test process.
"""
import os

for _name in ("NEXTDNS_API_KEY", "NEXTDNS_PROFILE_ID", "GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
              "POLICE_API_KEY", "GOOGLE_MAPS_API_KEY", "VAPID_PRIVATE_KEY",
              # Email scanning: a developer's .env must not change what the tests expect.
              "EMAIL_TRUSTED_AUTHSERV", "USER_LLM_ALLOW_PRIVATE", "EMAIL_RATE_LIMIT_PER_MINUTE"):
    os.environ[_name] = ""
