"""SQLite persistence (aiosqlite) + idempotent seeding."""
from __future__ import annotations

import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

import aiosqlite

from .config import settings

SCHEMA = """
PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    kind TEXT NOT NULL,                -- url | maps
    target TEXT NOT NULL,
    domain TEXT,
    created_at TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    verdict TEXT NOT NULL,
    impersonated_entity TEXT,
    channel TEXT,
    reporter TEXT,
    result_json TEXT NOT NULL,
    screenshot_b64 TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_created ON scans(created_at);
CREATE INDEX IF NOT EXISTS idx_scans_domain ON scans(domain);

CREATE TABLE IF NOT EXISTS graph_nodes (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,                -- domain | map_pin | ip_address | phone_number | citizen_report
    label TEXT NOT NULL,
    risk INTEGER DEFAULT 0,
    data_json TEXT DEFAULT '{}',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_edges (
    source TEXT NOT NULL,
    target TEXT NOT NULL,
    type TEXT NOT NULL,                -- hosted_on | linked_to_pin | shares_phone | reported_by_citizen
    data_json TEXT DEFAULT '{}',
    created_at TEXT NOT NULL,
    PRIMARY KEY (source, target, type)
);
CREATE TABLE IF NOT EXISTS syndicates (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    name_ar TEXT,
    seed_node TEXT NOT NULL,
    description TEXT,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ct_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL,
    seen_at TEXT NOT NULL,
    score INTEGER NOT NULL,
    entity TEXT,
    source TEXT NOT NULL,
    data_json TEXT DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_ct_seen ON ct_events(seen_at);
CREATE TABLE IF NOT EXISTS hunter_detections (  -- proactive hunter: scam domains found before any citizen saw them
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,              -- lookalike_sweep | crtsh | ct | nrd
    first_seen TEXT NOT NULL,          -- when the hunter found it (lead time is measured from here)
    scanned_at TEXT,
    triage_score INTEGER NOT NULL DEFAULT 0,
    score INTEGER NOT NULL DEFAULT 0,
    verdict TEXT,
    entity TEXT,
    flags_json TEXT NOT NULL DEFAULT '[]',
    domain_age_hours REAL,
    registrar TEXT,
    ip TEXT,
    asn TEXT,
    scan_id TEXT,                      -- full scan in the scans table (NULL for simulated leads)
    simulated INTEGER NOT NULL DEFAULT 0,
    status TEXT NOT NULL,              -- confirmed | suspicious | cleared
    detail_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_hunter_first_seen ON hunter_detections(first_seen);
CREATE TABLE IF NOT EXISTS push_subscriptions (  -- phones that enabled SAQR scam alerts (Web Push)
    endpoint TEXT PRIMARY KEY,
    sub_json TEXT NOT NULL,
    lang TEXT NOT NULL DEFAULT 'en',
    created_at TEXT NOT NULL,
    device TEXT                              -- the phone's SAQR device tag (also in its DNS setting)
);
CREATE TABLE IF NOT EXISTS self_hosts (       -- public hostnames this backend is served from (never blocked)
    host TEXT PRIMARY KEY,
    seen_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS dossiers (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    dossier_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS user_models (      -- personal email model per citizen: bucket COUNTS only, never mail text
    reporter_hash TEXT PRIMARY KEY,            -- SHA-256 of the browser's random reporter_id (raw id is not stored here)
    model_json TEXT NOT NULL,                  -- saqr-user-model JSON (contract section 4)
    labelled_json TEXT NOT NULL DEFAULT '{}',  -- {scan_id: "scam"|"ham"} so relabelling a scan replaces its label
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS false_alarms (     -- citizen "Report a false alarm": domain + result only, never the full URL
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL UNIQUE,              -- one row per scan; repeat reports raise `reports`
    kind TEXT NOT NULL,                        -- url | maps | email
    label TEXT NOT NULL,                       -- the scan's domain, or a neutral label ("email message")
    verdict TEXT NOT NULL,
    score INTEGER NOT NULL,
    note TEXT NOT NULL DEFAULT '',
    reports INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',       -- open | confirmed | dismissed (a decision record only)
    created_at TEXT NOT NULL,
    last_reported_at TEXT NOT NULL,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_false_alarms_created ON false_alarms(created_at);
"""

# Scans made by SAQR itself (seeded demo history, the phone-demo pages, the proactive hunter): never
# pruned, they are demo data / police evidence rather than a citizen's check.
NON_CITIZEN_REPORTERS = ("seed", "demo-seed", "hunter")


def strip_query(url: str | None) -> str | None:
    """`url` without its ?query and #fragment (they can carry personal tokens)."""
    if not isinstance(url, str):
        return url
    return url.split("#", 1)[0].split("?", 1)[0]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).isoformat(timespec="seconds")


class Database:
    def __init__(self, path: str):
        self.path = path
        self.conn: aiosqlite.Connection | None = None

    async def connect(self) -> None:
        if self.path != ":memory:":
            os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        self.conn = await aiosqlite.connect(self.path)
        self.conn.row_factory = aiosqlite.Row
        await self.conn.executescript(SCHEMA)
        await self._migrate()
        await self.conn.commit()

    async def _migrate(self) -> None:
        """Add columns that older databases don't have yet."""
        async with self.conn.execute("PRAGMA table_info(push_subscriptions)") as cur:
            cols = {row[1] for row in await cur.fetchall()}
        if "device" not in cols:
            await self.conn.execute("ALTER TABLE push_subscriptions ADD COLUMN device TEXT")

    async def close(self) -> None:
        if self.conn:
            await self.conn.close()

    # -- generic helpers --------------------------------------------------
    async def fetchall(self, sql: str, params: tuple = ()) -> list[dict[str, Any]]:
        async with self.conn.execute(sql, params) as cur:
            return [dict(r) for r in await cur.fetchall()]

    async def fetchone(self, sql: str, params: tuple = ()) -> dict[str, Any] | None:
        async with self.conn.execute(sql, params) as cur:
            row = await cur.fetchone()
            return dict(row) if row else None

    async def execute(self, sql: str, params: tuple = ()) -> None:
        await self.conn.execute(sql, params)
        await self.conn.commit()

    # -- scans ------------------------------------------------------------
    async def save_scan(self, scan: dict[str, Any], screenshot_b64: str | None = None) -> None:
        if scan.get("kind") == "url" and scan.get("verdict") == "SAFE":
            # Privacy: a safe link's query string is not needed by anything (blocklist, graph and
            # dossiers only use non-SAFE scans), so it is never written to disk.
            scan = {**scan, **{k: strip_query(scan.get(k)) for k in ("target", "input_url", "normalized_url")
                               if scan.get(k)}}
        await self.conn.execute(
            """INSERT OR REPLACE INTO scans (id, kind, target, domain, created_at, risk_score, verdict,
               impersonated_entity, channel, reporter, result_json, screenshot_b64)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (scan["scan_id"], scan["kind"], scan["target"], scan.get("domain"), scan["created_at"],
             scan["risk_score"], scan["verdict"], scan.get("impersonated_entity"), scan.get("channel"),
             scan.get("reporter"), json.dumps(scan, ensure_ascii=False, default=str), screenshot_b64),
        )
        await self.conn.commit()

    async def get_scan(self, scan_id: str, with_screenshot: bool = True) -> dict[str, Any] | None:
        row = await self.fetchone("SELECT * FROM scans WHERE id=?", (scan_id,))
        if not row:
            return None
        scan = json.loads(row["result_json"])
        if with_screenshot:
            scan["screenshot_base64"] = row["screenshot_b64"]
        return scan

    async def list_scans(self, limit: int = 50, kind: str | None = None) -> list[dict[str, Any]]:
        sql = ("SELECT id AS scan_id, kind, target, domain, created_at, risk_score, verdict, impersonated_entity, channel "
               "FROM scans")
        params: tuple = ()
        if kind:
            sql += " WHERE kind=?"
            params = (kind,)
        sql += " ORDER BY created_at DESC LIMIT ?"
        return await self.fetchall(sql, params + (limit,))

    async def prune_scans(self, days: int | None = None) -> int:
        """Privacy retention. Scans older than `days` (default SCAN_RETENTION_DAYS; 0 = keep forever):
        safe results, email checks and scans without a domain are deleted; non-SAFE link / Maps scans
        stay (they back the DNS blocklist, police map and dossiers) but lose the citizen's pasted
        message text. SAQR's own scans (seed, demo-seed, hunter) are never touched. Returns rows deleted."""
        days = settings.scan_retention_days if days is None else days
        if days <= 0:
            return 0
        cutoff = iso(utcnow() - timedelta(days=days))
        own = ",".join("?" for _ in NON_CITIZEN_REPORTERS)
        base = (f"created_at < ? AND COALESCE(reporter,'') NOT IN ({own}) "
                "AND id NOT LIKE 'SCN-SEED-%' AND id NOT LIKE 'SCN-DEMO-%'")
        params = (cutoff, *NON_CITIZEN_REPORTERS)
        cur = await self.conn.execute(
            f"DELETE FROM scans WHERE {base} AND (verdict = 'SAFE' OR kind = 'email' OR domain IS NULL OR domain = '')",
            params)
        deleted = cur.rowcount or 0
        rows = await self.fetchall(
            f"SELECT id, result_json FROM scans WHERE {base} AND result_json LIKE '%\"message_text\": \"%'", params)
        for row in rows:
            try:
                data = json.loads(row["result_json"])
            except (TypeError, ValueError):
                continue
            if data.get("message_text"):
                data["message_text"] = None
                await self.conn.execute("UPDATE scans SET result_json=? WHERE id=?",
                                        (json.dumps(data, ensure_ascii=False, default=str), row["id"]))
        await self.conn.commit()
        return deleted

    # -- graph ------------------------------------------------------------
    async def upsert_node(self, node_id: str, ntype: str, label: str, risk: int = 0,
                          data: dict | None = None, seen: str | None = None) -> bool:
        """Insert or update a node. Returns True if the node is new."""
        seen = seen or iso()
        existing = await self.fetchone("SELECT risk, data_json FROM graph_nodes WHERE id=?", (node_id,))
        if existing:
            merged = {**json.loads(existing["data_json"] or "{}"), **(data or {})}
            await self.conn.execute(
                "UPDATE graph_nodes SET risk=MAX(risk, ?), data_json=?, last_seen=? WHERE id=?",
                (risk, json.dumps(merged, ensure_ascii=False), seen, node_id),
            )
            await self.conn.commit()
            return False
        cur = await self.conn.execute(  # OR IGNORE: two scans of the same new domain at once (email "scan all")
            "INSERT OR IGNORE INTO graph_nodes (id, type, label, risk, data_json, first_seen, last_seen) VALUES (?,?,?,?,?,?,?)",
            (node_id, ntype, label, risk, json.dumps(data or {}, ensure_ascii=False), seen, seen),
        )
        await self.conn.commit()
        if cur.rowcount == 0:  # lost the race: the other scan inserted it first, so merge like an update
            return await self.upsert_node(node_id, ntype, label, risk, data, seen)
        return True

    async def upsert_edge(self, source: str, target: str, etype: str, data: dict | None = None,
                          created: str | None = None) -> bool:
        cur = await self.conn.execute(
            "INSERT OR IGNORE INTO graph_edges (source, target, type, data_json, created_at) VALUES (?,?,?,?,?)",
            (source, target, etype, json.dumps(data or {}, ensure_ascii=False), created or iso()),
        )
        await self.conn.commit()
        return cur.rowcount > 0


db = Database(settings.database_path)


async def seed_if_empty() -> bool:
    """Seed graph, syndicates, CT history and historical scans. Idempotent."""
    from . import seed_data as S
    from .intel.registry import ENTITY_BY_ID

    if await db.fetchone("SELECT 1 FROM syndicates LIMIT 1"):
        return False
    now = utcnow()

    for syn in S.SYNDICATES:
        await db.conn.execute(
            "INSERT INTO syndicates (id, name, name_ar, seed_node, description, created_at) VALUES (?,?,?,?,?,?)",
            (syn["id"], syn["name"], syn["name_ar"], syn["seed_node"], syn["description"], iso(now - timedelta(days=2))),
        )
    await db.conn.commit()

    for domain, d in S.DEMO_INTEL.items():
        seen = iso(now - timedelta(hours=d["registered_hours_ago"]))
        ent = ENTITY_BY_ID[d["entity"]]
        await db.upsert_node(f"domain:{domain}", "domain", domain, 92 if d["registered_hours_ago"] < 72 else 80,
                             {"impersonated_entity": ent.name_en, "ssl_issuer": d["ssl_issuer"],
                              "registrar": d["registrar"], "source": "seed"}, seen)
        await db.upsert_node(f"ip:{d['ip']}", "ip_address", d["ip"], 85,
                             {"asn": d["asn"], "asn_org": d["asn_org"], "country": d["country"]}, seen)
        await db.upsert_edge(f"domain:{domain}", f"ip:{d['ip']}", "hosted_on", {"record": "A"}, seen)

    for pin in S.MAP_PINS:
        from .intel.registry import normalise_phone

        phone = normalise_phone(pin["phone"])
        await db.upsert_node(pin["id"], "map_pin", pin["name"], 88,
                             {k: pin[k] for k in ("lat", "lng", "area", "website", "phone", "place_type", "verified")})
        await db.upsert_node(f"phone:{phone}", "phone_number", pin["phone"], 80, {"normalized": phone})
        await db.upsert_edge(pin["id"], f"domain:{pin['website']}", "linked_to_pin")
        await db.upsert_edge(pin["id"], f"phone:{phone}", "shares_phone")

    for r in S.CITIZEN_REPORTS:
        ts = iso(now - timedelta(hours=r["hours_ago"]))
        await db.upsert_node(r["id"], "citizen_report", r["id"].split(":")[1], 0,
                             {"channel": r["channel"], "message": r["message"]}, ts)
        tgt = r["target"] if r["target"].startswith("pin:") else f"domain:{r['target']}"
        await db.upsert_edge(tgt, r["id"], "reported_by_citizen", {"channel": r["channel"]}, ts)

    for domain, hrs in S.CT_SEED:
        from .intel.domain_intel import analyze_lexical

        lex = analyze_lexical(domain)
        await db.conn.execute(
            "INSERT INTO ct_events (domain, seen_at, score, entity, source, data_json) VALUES (?,?,?,?,?,?)",
            (domain, iso(now - timedelta(hours=hrs)), lex.score,
             lex.impersonated.name_en if lex.impersonated else None, "seed",
             json.dumps({"issuer": "Let's Encrypt", "flags": [f.code for f in lex.flags]})),
        )
    await db.conn.commit()
    return True
