"""Proactive Hunter: finds scam domains BEFORE any citizen visits or reports them.

Four lead sources, each lead tagged with where it came from:

* ``lookalike_sweep`` - look-alike names of the official UAE domains (lookalike_gen) are resolved in
  DNS; the ones somebody has actually registered are leads.
* ``crtsh`` - new TLS certificates whose names contain a UAE brand keyword (crt.sh, slow and often
  down: long timeout, back-off, de-duplicated by certificate id).
* ``ct`` - detections of the existing certificate-transparency monitor (ct_monitor).
* ``nrd`` - the free daily newly-registered-domains list (whoisds.com, 70,000 names a day).

Every lead gets a cheap triage first (lexical rules + URL model, no network). Leads above the
threshold get the full scan (pipeline.analyze_url: WHOIS, DNS, TLS, page) on the channel
PROACTIVE_HUNTER, so a confirmed scam reaches the graph, the telecom blocklist and NextDNS through
the same path as a citizen report. Work is capped per cycle so a 512 MB single-worker host survives.

HUNTER_MODE: ``live`` (real sources), ``simulated`` (synthetic, clearly labelled leads: no network,
no pipeline scan, never published to a blocklist) or ``off``. OFFLINE_MODE turns live into simulated.
"""
from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import random
import re
import secrets
import zipfile
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable

import httpx

from .. import pipeline
from ..config import settings
from ..db import db, iso, utcnow
from ..ws_hub import hub
from . import ai_inspector, lookalike_gen
from .ct_monitor import ct_monitor
from .domain_intel import analyze_lexical
from .nextdns_sync import nextdns_sync
from .registry import ALL_BRANDS, ENTITIES, ENTITY_BY_ID
from .threat_feeds import NEVER_LIST, on_free_hosting, popularity_rank

log = logging.getLogger("saqr.hunter")

CHANNEL = "PROACTIVE_HUNTER"
REPORTER = "hunter"
SOURCES = ("lookalike_sweep", "crtsh", "ct", "nrd")
# Scans made by SAQR itself (not by a citizen): never counted as a citizen seeing the domain.
NON_CITIZEN_REPORTERS = (REPORTER, "seed", "demo-seed")
HOSTNAME = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:xn--[a-z0-9-]{1,59}|[a-z]{2,63})$")
UAE_ENTITY_IDS = frozenset(e.id for e in ENTITIES)
BRAND_FLAGS = frozenset({"BRAND_IMPERSONATION", "TYPOSQUAT", "HOMOGLYPH_SPOOF", "TLD_SWAP"})
# Brands whose only keyword is a two-letter word ("du" is also French for "of the"): in a feed of
# every new domain in the world they need a lure word next to them (du-prize, du-recharge).
AMBIGUOUS_BRANDS = frozenset(e.id for e in ALL_BRANDS
                             if max(len(k) for k in (*e.keywords, *e.common_keywords)) <= 2)
CRTSH_URL = "https://crt.sh/"
NRD_URL = "https://www.whoisds.com//whois-database/newly-registered-domains/{token}/nrd"
MAX_DOWNLOAD_BYTES = 6_000_000
BACKLOG_SIZE = 300

Resolver = Callable[[str], Awaitable[str]]  # domain -> "registered" | "nxdomain" | "unknown"


def clean_domain(raw: str | None) -> str | None:
    d = (raw or "").strip().lower().rstrip(".")
    while d.startswith("*."):
        d = d[2:]
    if d.startswith("www."):
        d = d[4:]
    return d if HOSTNAME.match(d) else None


# ---------------------------------------------------------------------------------------------
# Leads and triage
# ---------------------------------------------------------------------------------------------
@dataclass
class Lead:
    domain: str
    source: str
    first_seen: str = field(default_factory=iso)
    entity_id: str | None = None  # the brand a generated look-alike imitates
    detail: dict[str, Any] = field(default_factory=dict)
    simulated: bool = False


@dataclass(frozen=True)
class Triage:
    domain: str
    score: int
    lexical_score: int
    ml_probability: float | None
    entity: str | None
    entity_id: str | None
    flags: tuple[str, ...]
    drop_reason: str | None = None  # official | invalid | shared_platform | own_host | popular_site

    @property
    def uae(self) -> bool:
        return self.entity_id in UAE_ENTITY_IDS

    @property
    def names_a_brand(self) -> bool:
        """The address itself imitates a known brand (not only a classifier guess)."""
        if not self.entity_id or not BRAND_FLAGS.intersection(self.flags):
            return False
        return self.entity_id not in AMBIGUOUS_BRANDS or "LURE_KEYWORDS" in self.flags


def triage(domain: str) -> Triage:
    """Cheap, offline first look at a lead: lexical rules plus the trained URL model."""
    def dropped(reason: str) -> Triage:
        return Triage(domain, 0, 0, None, None, None, (), reason)

    d = clean_domain(domain)
    if not d:
        return dropped("invalid")
    if d in NEVER_LIST:
        return dropped("shared_platform")
    if d in settings.demo_scam_domains or d in settings.own_hosts:
        return dropped("own_host")
    try:
        lex = analyze_lexical(d)
    except ValueError:
        return dropped("invalid")
    if lex.is_whitelisted:
        return dropped("official")
    if popularity_rank(lex.registered_domain) and not on_free_hosting(lex.host):
        return dropped("popular_site")
    intel = ai_inspector.intel_flags(lex)
    ent = lex.impersonated
    return Triage(d, min(100, lex.score + sum(f.points for f in intel)), lex.score,
                  ai_inspector.url_model_probability(lex), ent.name_en if ent else None, ent.id if ent else None,
                  tuple(f.code for f in [*lex.flags, *intel]))


# ---------------------------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------------------------
class Source:
    name = ""
    real = True  # False = synthetic data

    def __init__(self) -> None:
        self.last_run: str | None = None
        self.last_ok: str | None = None
        self.last_error: str | None = None
        self.leads_found = 0
        self.note: str | None = None

    async def collect(self) -> list[Lead]:
        raise NotImplementedError

    async def run(self) -> list[Lead]:
        self.last_run = iso()
        try:
            leads = await self.collect()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - one broken source must not stop the others
            self.last_error = f"{type(exc).__name__}: {exc}".splitlines()[0][:200]
            log.warning("hunter source %s failed: %s", self.name, self.last_error)
            return []
        self.last_ok, self.last_error = iso(), None
        self.leads_found += len(leads)
        return leads

    def status(self) -> dict[str, Any]:
        return {"name": self.name, "data": "real" if self.real else "simulated", "last_run": self.last_run,
                "last_ok": self.last_ok, "last_error": self.last_error, "leads_found": self.leads_found,
                "note": self.note}


async def dns_registered(domain: str) -> str:
    """Is this name registered? NXDOMAIN = no. An answer, or a name that exists without an address
    (parked, or not switched on yet) = yes. Timeouts and server errors = unknown."""
    import dns.asyncresolver
    import dns.exception
    import dns.resolver

    res = dns.asyncresolver.Resolver()
    res.lifetime = settings.dns_timeout_s
    try:
        await res.resolve(domain, "A")
        return "registered"
    except dns.resolver.NXDOMAIN:
        return "nxdomain"
    except dns.resolver.NoAnswer:
        try:
            await res.resolve(domain, "NS")
            return "registered"
        except (dns.exception.DNSException, OSError):
            return "unknown"
    except (dns.exception.DNSException, OSError):
        return "unknown"


class LookalikeSweep(Source):
    """Resolves one slice of the generated look-alike list per cycle and keeps a cursor, so the
    whole list is covered every few cycles without a burst of DNS traffic."""
    name = "lookalike_sweep"

    def __init__(self, resolver: Resolver = dns_registered, candidates: list[lookalike_gen.Candidate] | None = None,
                 batch: int | None = None) -> None:
        super().__init__()
        self.resolver = resolver
        self.candidates = (candidates if candidates is not None
                           else lookalike_gen.generate_all(settings.hunter_lookalikes_per_brand))
        self.batch = batch or settings.hunter_sweep_batch
        self.cursor = 0
        self.resolved = 0
        self.unanswered = 0
        self.wildcard_tlds: dict[str, bool] = {}

    async def _probe_wildcards(self, tlds: set[str]) -> None:
        """Some endings answer for every name; a name that cannot exist tells us which."""
        new = sorted(tlds - set(self.wildcard_tlds))
        states = await asyncio.gather(*(self.resolver(f"saqr-probe-{secrets.token_hex(6)}.{tld}") for tld in new))
        self.wildcard_tlds.update({tld: state == "registered" for tld, state in zip(new, states)})

    async def collect(self) -> list[Lead]:
        if not self.candidates:
            return []
        n = min(self.batch, len(self.candidates))
        chunk = [self.candidates[(self.cursor + i) % len(self.candidates)] for i in range(n)]
        self.cursor = (self.cursor + n) % len(self.candidates)
        await self._probe_wildcards({c.domain.rsplit(".", 1)[-1] for c in chunk})
        sem = asyncio.Semaphore(max(1, settings.hunter_dns_concurrency))
        leads: list[Lead] = []

        async def check(cand: lookalike_gen.Candidate) -> None:
            if self.wildcard_tlds[cand.domain.rsplit(".", 1)[-1]]:
                return
            async with sem:
                state = await self.resolver(cand.domain)
            self.resolved += 1
            self.unanswered += state == "unknown"
            if state == "registered":
                leads.append(Lead(cand.domain, self.name, entity_id=cand.entity_id,
                                  detail={"technique": cand.technique, "imitates": cand.base}))

        await asyncio.gather(*(check(c) for c in chunk))
        self.note = (f"{self.resolved} names checked ({self.unanswered} got no DNS answer), cursor {self.cursor}/{len(self.candidates)}; "
                     f"wildcard endings skipped: {sorted(t for t, w in self.wildcard_tlds.items() if w) or 'none'}")
        return sorted(leads, key=lambda lead: lead.domain)


def crtsh_patterns() -> list[str]:
    """SQL-LIKE patterns for crt.sh: long keywords anywhere, short ones (tamm, adcb) only before a
    hyphen, where combosquats put them. Two- and three-letter brands are far too noisy."""
    out = []
    for ent in ENTITIES:
        for name in lookalike_gen.brand_names(ent):
            if len(name.replace("-", "")) >= 6:
                out.append(f"%{name}%")
            elif len(name) == 4:
                out.append(f"%{name}-%")
    out = list(dict.fromkeys(out))
    # "%uaepas%" already finds everything "%uaepass%" does: keep the wider pattern only
    return [p for p in out if not any(q != p and q.strip("%") in p.strip("%") for q in out)]


async def fetch_limited(url: str, *, params: dict[str, str] | None = None, timeout: float = 60.0) -> bytes:
    """GET with a size cap (a huge answer must not eat the memory of a small host)."""
    async with httpx.AsyncClient(timeout=timeout, follow_redirects=True,
                                 headers={"User-Agent": "SAQR-INTEL proactive hunter"}) as client:
        async with client.stream("GET", url, params=params) as resp:
            resp.raise_for_status()
            body = bytearray()
            async for part in resp.aiter_bytes():
                body += part
                if len(body) > MAX_DOWNLOAD_BYTES:
                    raise ValueError(f"answer larger than {MAX_DOWNLOAD_BYTES} bytes")
            return bytes(body)


def _parse_ts(value: Any) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


class CrtSh(Source):
    """Polls crt.sh for certificates naming a UAE brand. A few patterns per cycle, one request at a
    time; after a failure the source rests (2 min, doubling up to 1 h) instead of hammering it."""
    name = "crtsh"

    def __init__(self, fetch: Callable[[str], Awaitable[bytes]] | None = None, patterns: list[str] | None = None,
                 pause_s: float = 3.0) -> None:
        super().__init__()
        self.fetch = fetch or self._fetch
        self.patterns = patterns if patterns is not None else crtsh_patterns()
        self.pause_s = pause_s
        self.cursor = 0
        self.failures = 0
        self.rest_until: datetime | None = None
        self.seen_ids: set[int] = set()

    @staticmethod
    async def _fetch(pattern: str) -> bytes:
        return await fetch_limited(CRTSH_URL, params={"q": pattern, "output": "json", "exclude": "expired"},
                                   timeout=settings.hunter_crtsh_timeout_s)

    def parse(self, raw: bytes, pattern: str) -> list[Lead]:
        cutoff = utcnow() - timedelta(hours=settings.hunter_crtsh_max_age_hours)
        leads: dict[str, Lead] = {}
        for row in json.loads(raw):
            cert_id = row.get("id")
            if not isinstance(cert_id, int) or cert_id in self.seen_ids:
                continue
            self.seen_ids.add(cert_id)
            logged = _parse_ts(row.get("entry_timestamp") or row.get("not_before"))
            if not logged or logged < cutoff:
                continue
            for name in str(row.get("name_value") or "").split():
                d = clean_domain(name)
                if d and d not in leads:
                    leads[d] = Lead(d, self.name, detail={
                        "cert_id": cert_id, "cert_logged_at": iso(logged), "pattern": pattern,
                        "issuer": str(row.get("issuer_name") or "")[:120]})
        if len(self.seen_ids) > 100_000:
            self.seen_ids.clear()
        return list(leads.values())

    async def collect(self) -> list[Lead]:
        if self.rest_until and utcnow() < self.rest_until:
            self.note = f"resting until {iso(self.rest_until)} after {self.failures} failed request(s)"
            return []
        leads: list[Lead] = []
        answered = 0
        for i in range(min(settings.hunter_crtsh_queries, len(self.patterns))):
            pattern = self.patterns[self.cursor % len(self.patterns)]
            self.cursor += 1
            if i:
                await asyncio.sleep(self.pause_s)
            try:
                leads += self.parse(await self.fetch(pattern), pattern)
                answered += 1
                self.failures = 0
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - crt.sh answers 502 / times out several times a day
                self.failures += 1
                self.rest_until = utcnow() + timedelta(seconds=min(3600, 120 * 2 ** (self.failures - 1)))
                self.note = f"{answered} pattern(s) answered, then {pattern}: {type(exc).__name__}"
                if not answered:
                    raise
                return leads
        self.note = f"{answered} pattern(s) answered; {len(self.seen_ids)} certificates seen"
        return leads


class CTQueue(Source):
    """Takes the detections of the certificate-transparency monitor (ct_monitor calls ``push``).
    A live hunt ignores the monitor's synthetic stream: made-up names must not be scanned as real."""
    name = "ct"

    def __init__(self, accept_simulated: bool = False) -> None:
        super().__init__()
        self.accept_simulated = accept_simulated
        self.queue: deque[Lead] = deque(maxlen=200)
        self.ignored_simulated = 0

    def push(self, event: dict[str, Any]) -> None:
        synthetic = event.get("source") != "certstream"
        if synthetic and not self.accept_simulated:
            self.ignored_simulated += 1
            return
        d = clean_domain(event.get("domain"))
        if d:
            self.queue.append(Lead(d, self.name, simulated=synthetic,
                                   detail={"issuer": event.get("issuer"), "ct_source": event.get("source")}))

    async def collect(self) -> list[Lead]:
        leads = list(self.queue)
        self.queue.clear()
        self.note = (f"CT monitor mode: {ct_monitor.mode}; "
                     f"{self.ignored_simulated} synthetic CT detection(s) ignored")
        return leads


def nrd_keyword_filter() -> re.Pattern[str]:
    """One regular expression of every brand keyword: the cheap first cut over 70,000 names."""
    words = {k.replace("-", "") for ent in ALL_BRANDS for k in (*ent.keywords, *ent.common_keywords)}
    words |= {label for ent in ENTITIES for label, _ in lookalike_gen.official_labels(ent)}
    return re.compile("|".join(sorted((re.escape(w) for w in words if len(w) >= 2), key=len, reverse=True)))


class NewlyRegistered(Source):
    """whoisds.com publishes yesterday's newly registered domains as a free zip (no key). Read once
    per day; only names containing a brand keyword go on to triage."""
    name = "nrd"

    def __init__(self, fetch: Callable[[str], Awaitable[bytes]] | None = None) -> None:
        super().__init__()
        self.fetch = fetch or (lambda url: fetch_limited(url, timeout=90.0))
        self.done_day: str | None = None
        self.keywords = nrd_keyword_filter()

    @staticmethod
    def url_for(day: str) -> str:
        return NRD_URL.format(token=base64.b64encode(f"{day}.zip".encode()).decode())

    @staticmethod
    def names(raw: bytes) -> list[str]:
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            info = z.infolist()[0]
            if info.file_size > 4 * MAX_DOWNLOAD_BYTES:
                raise ValueError("newly-registered list is larger than expected")
            return z.read(info).decode("utf-8", "ignore").split()

    async def collect(self) -> list[Lead]:
        today = utcnow().date()
        for back in (1, 2):  # yesterday's list appears during the day; fall back to the day before
            day = (today - timedelta(days=back)).isoformat()
            if self.done_day and self.done_day >= day:
                self.note = f"list of {self.done_day} already processed"
                return []
            raw = await self.fetch(self.url_for(day))
            if not raw:
                continue
            names = self.names(raw)
            leads = []
            for i, name in enumerate(names):
                if i % 2000 == 0:
                    await asyncio.sleep(0)  # keep the web server responsive
                if self.keywords.search(name):
                    d = clean_domain(name)
                    if d:
                        leads.append(Lead(d, self.name, detail={"registered_on": day}))
            self.done_day = day
            self.note = f"list of {day}: {len(names)} new domains, {len(leads)} contain a brand keyword"
            return leads
        self.note = "no list published yet for the last two days"
        return []


SIM_REGISTRARS = ("NameSilo, LLC", "Hostinger Operations, UAB", "NameCheap, Inc.", "Gname.com Pte. Ltd.")


class Simulated(Source):
    """Synthetic leads for offline demos and tests: names from the look-alike generator, tagged
    with the four real source names in turn. Deterministic for a given seed."""
    name = "simulated"
    real = False

    def __init__(self, seed: int = 2026) -> None:
        super().__init__()
        self.rng = random.Random(seed)
        self.pool = [c for c in lookalike_gen.generate_all(120) if c.technique == "brand_lure"]
        self.rng.shuffle(self.pool)
        self.cursor = 0

    def take(self, n: int, first_seen: str | None = None) -> list[Lead]:
        leads = []
        for _ in range(min(n, len(self.pool))):
            cand = self.pool[self.cursor % len(self.pool)]
            source = SOURCES[self.cursor % len(SOURCES)]
            self.cursor += 1
            leads.append(Lead(cand.domain, source, first_seen or iso(), cand.entity_id, simulated=True, detail={
                "technique": cand.technique, "imitates": cand.base,
                "domain_age_hours": round(self.rng.uniform(1, 36), 1), "registrar": self.rng.choice(SIM_REGISTRARS),
                # documentation address space (RFC 5737) and a documentation AS number (RFC 5398)
                "ip": f"203.0.113.{self.rng.randint(2, 250)}", "asn": "AS64500"}))
        return leads

    async def collect(self) -> list[Lead]:
        return self.take(self.rng.randint(1, 3))


# ---------------------------------------------------------------------------------------------
# The service
# ---------------------------------------------------------------------------------------------
def effective_mode() -> str:
    mode = settings.hunter_mode if settings.hunter_mode in {"live", "simulated", "off"} else "off"
    return "simulated" if mode == "live" and settings.offline_mode else mode


def default_sources(mode: str) -> list[Source]:
    if mode == "simulated":
        return [Simulated()]
    if mode != "live":
        return []
    makers: dict[str, Callable[[], Source]] = {"lookalike_sweep": LookalikeSweep, "crtsh": CrtSh, "ct": CTQueue,
                                               "nrd": NewlyRegistered}
    return [makers[name]() for name in settings.hunter_sources if name in makers]


class Hunter:
    def __init__(self, mode: str | None = None, sources: list[Source] | None = None) -> None:
        self.mode = mode or effective_mode()
        self.sources = sources if sources is not None else default_sources(self.mode)
        self.task: asyncio.Task | None = None
        self.backlog: deque[tuple[Lead, Triage]] = deque(maxlen=BACKLOG_SIZE)
        self.cycles = 0
        self.max_scans = settings.hunter_max_scans_per_cycle
        self.last_cycle: dict[str, Any] | None = None
        self._lock = asyncio.Lock()
        self._kick = asyncio.Event()
        self._scan_sem = asyncio.Semaphore(max(1, settings.hunter_scan_concurrency))

    # -- lifecycle ---------------------------------------------------------------------------
    async def start(self) -> None:
        if self.mode == "off" or self.task:
            return
        self._lock, self._kick = asyncio.Lock(), asyncio.Event()  # bound to the loop that is running now
        if self.mode == "simulated":
            await self.seed_simulated()
        for src in self.sources:
            if isinstance(src, CTQueue) and src.push not in ct_monitor.listeners:
                ct_monitor.listeners.append(src.push)
        self.task = asyncio.create_task(self._loop(), name="proactive-hunter")

    async def stop(self) -> None:
        for src in self.sources:
            if isinstance(src, CTQueue) and src.push in ct_monitor.listeners:
                ct_monitor.listeners.remove(src.push)
        if self.task:
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):  # noqa: BLE001
                pass
            self.task = None

    def kick(self) -> bool:
        """Ask the background loop for a cycle now. False if the hunter is not running."""
        if not self.task or self.task.done():
            return False
        self._kick.set()
        return True

    @property
    def running(self) -> bool:
        return self._lock.locked()

    async def _loop(self) -> None:
        delay = settings.hunter_start_delay_s
        while True:
            try:
                await asyncio.wait_for(self._kick.wait(), timeout=delay)
            except asyncio.TimeoutError:
                pass
            self._kick.clear()
            try:
                await self.run_cycle()
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - the hunt must survive one bad cycle
                log.exception("hunter cycle failed")
            delay = settings.hunter_sim_interval_s if self.mode == "simulated" else settings.hunter_interval_s

    # -- one cycle ---------------------------------------------------------------------------
    async def run_cycle(self) -> dict[str, Any]:
        if self.mode == "off":
            return {"skipped": "hunter is off"}
        if self._lock.locked():
            return {"skipped": "a cycle is already running"}
        async with self._lock:
            started = iso()
            summary: dict[str, Any] = {"started_at": started, "mode": self.mode, "leads": 0, "by_source": {},
                                       "dropped": {}, "below_threshold": 0, "no_brand_evidence": 0, "already_known": 0, "scanned": 0,
                                       "confirmed": 0, "suspicious": 0, "cleared": 0, "failed": 0}
            batches = await asyncio.gather(*(src.run() for src in self.sources))
            queue = list(self.backlog)
            self.backlog.clear()
            queued = {lead.domain for lead, _ in queue}
            for lead in (lead for batch in batches for lead in batch):
                summary["leads"] += 1
                summary["by_source"][lead.source] = summary["by_source"].get(lead.source, 0) + 1
                tri = triage(lead.domain)
                if tri.drop_reason:
                    summary["dropped"][tri.drop_reason] = summary["dropped"].get(tri.drop_reason, 0) + 1
                    continue
                # A registered name the generator derived from a brand is evidence even when the
                # lexical rules miss the typo. Leads from the world-wide feeds must reach the
                # threshold AND imitate a brand by name: the hunt is for impersonation, and a
                # classifier-only guess is not enough to publish a block nobody asked for.
                if not (lead.source == "lookalike_sweep" and lead.entity_id):
                    if tri.score < settings.hunter_triage_threshold:
                        summary["below_threshold"] += 1
                        continue
                    if not tri.names_a_brand:
                        summary["no_brand_evidence"] += 1
                        continue
                if tri.domain in queued or await self._known(tri.domain):
                    summary["already_known"] += 1
                    continue
                queued.add(tri.domain)
                queue.append((lead, tri))
                if len(queue) % 50 == 0:
                    await asyncio.sleep(0)
            queue.sort(key=lambda item: (not (item[1].uae or item[0].entity_id in UAE_ENTITY_IDS), -item[1].score,
                                         item[0].domain))
            cap = max(0, self.max_scans)
            now, later = queue[:cap], queue[cap:]
            self.backlog.extend(later[:BACKLOG_SIZE])
            rows = await asyncio.gather(*(self._process(lead, tri) for lead, tri in now))
            for row in rows:
                summary["scanned"] += 1
                summary[row["status"] if row else "failed"] += 1
            if any(row and row["score"] >= settings.nextdns_min_score and not row["simulated"] for row in rows):
                nextdns_sync.kick()
            summary["backlog"] = len(self.backlog)
            summary["finished_at"] = iso()
            self.cycles += 1
            self.last_cycle = summary
            log.info("hunter cycle: %s", {k: v for k, v in summary.items() if k not in {"started_at", "finished_at"}})
            await hub.broadcast("hunter.cycle", summary)
            return summary

    async def _known(self, domain: str) -> bool:
        """Already hunted, or already seen by a citizen (then it is not a pre-victim catch)."""
        if await db.fetchone("SELECT 1 FROM hunter_detections WHERE domain=?", (domain,)):
            return True
        return bool(await db.fetchone(
            f"SELECT 1 FROM scans WHERE domain=? AND COALESCE(reporter,'') NOT IN ({_NON_CITIZEN_SQL}) LIMIT 1",
            (domain,)))

    async def _process(self, lead: Lead, tri: Triage, announce: bool = True) -> dict[str, Any] | None:
        entity = tri.entity or (ENTITY_BY_ID[lead.entity_id].name_en if lead.entity_id in ENTITY_BY_ID else None)
        row: dict[str, Any] = {
            "domain": tri.domain, "source": lead.source, "first_seen": lead.first_seen, "scanned_at": iso(),
            "triage_score": tri.score, "score": tri.score, "verdict": ai_inspector.verdict_for(tri.score),
            "entity": entity, "flags": list(tri.flags), "domain_age_hours": lead.detail.get("domain_age_hours"),
            "registrar": lead.detail.get("registrar"), "ip": lead.detail.get("ip"), "asn": lead.detail.get("asn"),
            "scan_id": None, "simulated": lead.simulated,
            "detail": {k: v for k, v in lead.detail.items() if k not in {"domain_age_hours", "registrar", "ip", "asn"}},
        }
        if not lead.simulated and self.mode == "live":
            try:
                async with self._scan_sem:
                    scan = await asyncio.wait_for(pipeline.analyze_url(
                        f"https://{tri.domain}/", reporter=REPORTER, run_sandbox=True,
                        use_llm=settings.hunter_use_llm, ingest=True, interception_channel=CHANNEL),
                        timeout=settings.hunter_scan_timeout_s)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001 - a dead or hostile site must not stop the cycle
                log.warning("hunter scan of %s failed: %s", tri.domain, type(exc).__name__)
                return None
            ti = scan.get("technical_indicators") or {}
            row.update(score=scan["risk_score"], verdict=scan["verdict"], scan_id=scan["scan_id"],
                       entity=scan.get("impersonated_entity") or entity,
                       flags=[f["code"] for f in scan.get("red_flags", [])],
                       domain_age_hours=ti.get("domain_age_hours"), registrar=ti.get("registrar"),
                       ip=(ti.get("ip_addresses") or [None])[0], asn=ti.get("asn"))
        row["status"] = status_for(row["score"], row["verdict"], row["domain_age_hours"])
        await db.execute(
            "INSERT OR IGNORE INTO hunter_detections (domain, source, first_seen, scanned_at, triage_score, score, "
            "verdict, entity, flags_json, domain_age_hours, registrar, ip, asn, scan_id, simulated, status, "
            "detail_json) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (row["domain"], row["source"], row["first_seen"], row["scanned_at"], row["triage_score"], row["score"],
             row["verdict"], row["entity"], json.dumps(row["flags"]), row["domain_age_hours"], row["registrar"],
             row["ip"], row["asn"], row["scan_id"], int(row["simulated"]), row["status"],
             json.dumps(row["detail"], ensure_ascii=False)))
        if announce and row["status"] != "cleared":
            event = {**row, "defanged_domain": row["domain"].replace(".", "[.]"), "citizen_visits": 0,
                     "data": "simulated" if row["simulated"] else "real"}
            await hub.broadcast("hunter.detection", event)
            await hub.broadcast("police.proactive_detection", event)  # the /police page refreshes on police.*
        return row

    async def seed_simulated(self) -> int:
        """Simulated mode only: a few back-dated synthetic detections so the dashboard is not empty
        on a cold boot. Silent (no live events) and idempotent."""
        sim = next((s for s in self.sources if isinstance(s, Simulated)), None)
        if not sim or await db.fetchone("SELECT 1 FROM hunter_detections LIMIT 1"):
            return 0
        now = utcnow()
        leads = [lead for hours in (41, 33, 26, 19, 11, 6, 3, 1)
                 for lead in sim.take(1, iso(now - timedelta(hours=hours, minutes=sim.rng.randint(0, 59))))]
        for lead in leads:
            await self._process(lead, triage(lead.domain), announce=False)
        return len(leads)

    # -- views -------------------------------------------------------------------------------
    async def status(self) -> dict[str, Any]:
        rows = await db.fetchall(
            "SELECT source, simulated, status, COUNT(*) n FROM hunter_detections GROUP BY source, simulated, status")
        by_source: dict[str, dict[str, Any]] = {}
        for r in rows:
            s = by_source.setdefault(r["source"], {"real": {}, "simulated": {}})
            s["simulated" if r["simulated"] else "real"][r["status"]] = r["n"]
        totals = {k: sum(r["n"] for r in rows if r["status"] == k) for k in ("confirmed", "suspicious", "cleared")}
        return {
            "mode": self.mode, "configured_mode": settings.hunter_mode,
            "data": {"live": "real", "simulated": "simulated"}.get(self.mode, "none"),
            "background_loop": bool(self.task and not self.task.done()), "cycle_running": self.running,
            "cycles": self.cycles, "last_cycle": self.last_cycle, "backlog": len(self.backlog),
            "sources": [s.status() for s in self.sources], "detections_by_source": by_source, "totals": totals,
            "limits": {"interval_s": settings.hunter_interval_s, "max_scans_per_cycle": self.max_scans,
                       "scan_concurrency": settings.hunter_scan_concurrency, "sweep_batch": settings.hunter_sweep_batch,
                       "dns_concurrency": settings.hunter_dns_concurrency,
                       "triage_threshold": settings.hunter_triage_threshold, "use_llm": settings.hunter_use_llm},
            "generated_at": iso(),
        }


_NON_CITIZEN_SQL = ",".join(f"'{r}'" for r in NON_CITIZEN_REPORTERS)
_CITIZEN_SCANS = (
    "FROM scans s WHERE (s.domain = h.domain OR s.domain LIKE '%.' || h.domain) AND s.created_at >= h.first_seen "
    f"AND COALESCE(s.reporter,'') NOT IN ({_NON_CITIZEN_SQL})")


def status_for(score: int, verdict: str, domain_age_hours: float | None) -> str:
    """confirmed = HIGH-RISK. suspicious = a warning on a domain that is not long established.
    cleared = SAFE, or only a mild warning on a domain older than HUNTER_ESTABLISHED_DAYS (the
    hunter looks for NEW threats; an old address with a similar name is usually an unrelated firm)."""
    if score >= 65:
        return "confirmed"
    if verdict == "SAFE":
        return "cleared"
    if domain_age_hours is not None and domain_age_hours > settings.hunter_established_days * 24:
        return "cleared"
    return "suspicious"


def _hours_between(start: str, end: str) -> float | None:
    a, b = _parse_ts(start), _parse_ts(end)
    return round((b - a).total_seconds() / 3600, 2) if a and b else None


async def latest_detections(limit: int = 50, include_cleared: bool = False) -> list[dict[str, Any]]:
    """Newest detections with the lead-time fields, computed from the scans table at read time:
    citizen_visits = scans of the same domain (or a sub-domain) by anyone but SAQR itself AFTER the
    hunter first saw it; lead_time_hours = how long before the first of them the hunter had it."""
    rows = await db.fetchall(
        f"SELECT h.*, (SELECT COUNT(*) {_CITIZEN_SCANS}) AS citizen_visits, "
        f"(SELECT MIN(s.created_at) {_CITIZEN_SCANS}) AS first_citizen_at "
        "FROM hunter_detections h " + ("" if include_cleared else "WHERE h.status != 'cleared' ")
        + "ORDER BY h.first_seen DESC, h.id DESC LIMIT ?", (limit,))
    now = iso()
    out = []
    for r in rows:
        r["flags"] = json.loads(r.pop("flags_json") or "[]")
        r["detail"] = json.loads(r.pop("detail_json") or "{}")
        r["simulated"] = bool(r["simulated"])
        r["data"] = "simulated" if r["simulated"] else "real"
        r["defanged_domain"] = r["domain"].replace(".", "[.]")
        r["hours_since_detection"] = _hours_between(r["first_seen"], now)
        r["lead_time_hours"] = _hours_between(r["first_seen"], r["first_citizen_at"]) if r["first_citizen_at"] else None
        r["published_to_blocklist"] = r["status"] == "confirmed" and not r["simulated"]
        out.append(r)
    return out


async def pre_victim_count() -> int:
    row = await db.fetchone("SELECT COUNT(*) n FROM hunter_detections WHERE status = 'confirmed'")
    return int(row["n"]) if row else 0


hunter = Hunter()
