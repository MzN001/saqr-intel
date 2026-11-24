"""Module 1b — Zero-hour Certificate Transparency monitor.

Modes (CT_MODE):
* ``certstream`` — consume a live CertStream websocket (public calidog or a self-hosted
  certstream-server-go). Every SAN is run through the fast lexical analyser; lookalikes
  of official UAE domains are stored and pushed to the command centre. Falls back to
  ``simulated`` automatically if the feed is unreachable.
* ``simulated`` — realistic synthetic issuance stream for offline demos.
* ``off``.
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
from typing import Any, Callable

from ..config import settings
from ..db import db, iso
from ..ws_hub import hub
from .domain_intel import analyze_lexical
from .registry import ENTITIES

log = logging.getLogger("saqr.ct")

_PATTERNS = [
    "{kw}-pay-{n}.{tld}", "{kw}-fines-{n}.{tld}", "secure-{kw}-update.{tld}", "{kw}-verify-login.{tld}",
    "{kw}-uae-track.{tld}", "{kw}-refund-portal.{tld}", "my-{kw}-{n}.{tld}", "{kw}.ae-services.{tld}",
]
_TLDS = ["info", "xyz", "top", "online", "com", "net", "site", "live"]
_BENIGN = ["coffee-house-{n}.com", "dubai-dental-{n}.ae", "my-portfolio-{n}.dev", "shop-{n}.store",
           "abudhabi-yoga-{n}.com", "cloud-{n}.app"]
_ISSUERS = ["Let's Encrypt R11", "Let's Encrypt E5", "ZeroSSL ECC DV", "Google Trust Services WE1", "Sectigo DV"]


class CTMonitor:
    def __init__(self) -> None:
        self.task: asyncio.Task | None = None
        self.mode = settings.ct_mode
        self.processed = 0
        self.detections = 0
        self.connected = False
        self._recent: set[str] = set()
        self.listeners: list[Callable[[dict[str, Any]], None]] = []  # called with every detection (hunter)

    def start(self) -> None:
        if self.mode == "off" or self.task:
            return
        self.task = asyncio.create_task(self._run(), name="ct-monitor")

    async def stop(self) -> None:
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass

    def status(self) -> dict[str, Any]:
        return {"mode": self.mode, "connected": self.connected, "processed": self.processed,
                "detections": self.detections, "threshold": settings.ct_alert_threshold}

    async def _run(self) -> None:
        if self.mode == "certstream" and not settings.offline_mode:
            try:
                await self._certstream()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("CertStream unavailable (%s) — falling back to simulated feed", exc)
            self.mode = "simulated"
        await self._simulate()

    async def evaluate(self, domain: str, issuer: str, source: str) -> dict[str, Any] | None:
        domain = domain.lstrip("*.").lower()
        self.processed += 1
        if domain in self._recent:
            return None
        try:
            lex = analyze_lexical(domain)
        except ValueError:
            return None
        if lex.is_whitelisted or lex.score < settings.ct_alert_threshold or not lex.impersonated:
            return None
        self._recent.add(domain)
        if len(self._recent) > 5000:
            self._recent.clear()
        self.detections += 1
        event = {"domain": domain, "issuer": issuer, "seen_at": iso(), "score": lex.score,
                 "impersonated_entity": lex.impersonated.name_en, "flags": [f.code for f in lex.flags],
                 "source": source}
        await db.execute(
            "INSERT INTO ct_events (domain, seen_at, score, entity, source, data_json) VALUES (?,?,?,?,?,?)",
            (domain, event["seen_at"], lex.score, lex.impersonated.name_en, source,
             json.dumps({"issuer": issuer, "flags": event["flags"]})))
        await hub.broadcast("ct.detection", event)
        for listener in self.listeners:
            listener(event)
        if self.detections % 200 == 0:  # keep the table (and every blocklist build that reads it) small
            await db.execute("DELETE FROM ct_events WHERE id NOT IN (SELECT id FROM ct_events ORDER BY id DESC LIMIT 1500)")
        return event

    async def _certstream(self) -> None:
        import websockets

        backoff, failures = 2, 0
        while True:
            try:
                async with websockets.connect(settings.certstream_url, open_timeout=10, ping_interval=20,
                                              max_size=2 ** 22) as ws:
                    self.connected, failures, backoff = True, 0, 2
                    log.info("Connected to CertStream %s", settings.certstream_url)
                    async for raw in ws:
                        msg = json.loads(raw)
                        if msg.get("message_type") != "certificate_update":
                            continue
                        leaf = msg["data"]["leaf_cert"]
                        issuer = (leaf.get("issuer") or {}).get("O") or (leaf.get("issuer") or {}).get("CN") or "?"
                        for d in leaf.get("all_domains", [])[:50]:
                            await self.evaluate(d, issuer, "certstream")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self.connected = False
                failures += 1
                if failures >= 3:
                    raise RuntimeError(f"certstream failed {failures}x: {exc}") from exc
                await asyncio.sleep(backoff)
                backoff = min(backoff * 2, 60)

    async def _simulate(self) -> None:
        rng = random.Random()
        self.connected = True
        while True:
            await asyncio.sleep(max(2.0, rng.gauss(settings.ct_sim_interval_s, 2)))
            # Each tick = a batch of benign certs + occasionally a lookalike
            for _ in range(rng.randint(8, 20)):
                await self.evaluate(rng.choice(_BENIGN).format(n=rng.randint(10, 9999)), rng.choice(_ISSUERS),
                                    "simulated")
                await asyncio.sleep(0)  # never hold the event loop for a whole batch (Render: 0.1 CPU)
            if rng.random() < 0.7:
                ent = rng.choice(ENTITIES)
                kw = rng.choice([k for k in ent.keywords if len(k) > 3] or [ent.keywords[0]])
                d = rng.choice(_PATTERNS).format(kw=kw, n=rng.randint(1, 99), tld=rng.choice(_TLDS))
                await self.evaluate(d, rng.choice(_ISSUERS[:3]), "simulated")


ct_monitor = CTMonitor()
