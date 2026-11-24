"""Citizen "Report a false alarm" queue for officers.

Privacy: a report keeps ONLY the scan's domain (never the full URL), verdict, score, the citizen's
optional note (<= 280 chars), timestamps and a status. Email scans have no domain and get a neutral
label: the sender and subject are never copied here.

State lives in memory (newest MAX_ITEMS reports) and in the `false_alarms` table, loaded on start.
"confirmed" only records that an officer agrees it was a false alarm: nothing is whitelisted or
unblocked automatically.
"""
from __future__ import annotations

import hashlib
import secrets
from collections import OrderedDict
from typing import Any

from .db import db, iso

MAX_ITEMS = 200
MAX_NOTE = 280
STATUSES = ("open", "confirmed", "dismissed")
EMAIL_LABEL = "email message"
MAPS_LABEL = "maps listing"


def _label(scan: dict[str, Any]) -> str:
    if scan.get("kind") == "email":
        return EMAIL_LABEL
    domain = (scan.get("domain") or "").strip().lower()
    if domain:
        return domain[:253]
    return MAPS_LABEL if scan.get("kind") == "maps" else "link"


class FeedbackState:
    def __init__(self) -> None:
        self.items: OrderedDict[str, dict[str, Any]] = OrderedDict()  # id -> report, oldest first
        self._by_scan: dict[str, str] = {}
        self._seen: set[str] = set()  # sha256(client|scan): de-duplicates repeat reports (memory only)
        self.loaded = False

    def _index(self, item: dict[str, Any]) -> None:
        self.items[item["id"]] = item
        self.items.move_to_end(item["id"])
        self._by_scan[item["scan_id"]] = item["id"]
        while len(self.items) > MAX_ITEMS:
            _, old = self.items.popitem(last=False)
            self._by_scan.pop(old["scan_id"], None)

    async def load(self) -> None:
        self.items.clear()
        self._by_scan.clear()
        rows = await db.fetchall("SELECT * FROM false_alarms ORDER BY last_reported_at DESC LIMIT ?", (MAX_ITEMS,))
        for row in reversed(rows):
            self._index(dict(row))
        self.loaded = True

    async def _ensure(self) -> None:
        if not self.loaded:
            await self.load()

    async def report(self, scan: dict[str, Any], note: str, client: str) -> tuple[dict[str, Any], bool]:
        """Record a report. Returns (report, deduplicated)."""
        await self._ensure()
        note = (note or "").strip()[:MAX_NOTE]
        scan_id = scan["scan_id"]
        fp = hashlib.sha256(f"{client}|{scan_id}".encode()).hexdigest()
        if len(self._seen) > 5000:  # bounded: losing it only means a repeat report is counted twice
            self._seen.clear()
        now = iso()
        existing_id = self._by_scan.get(scan_id)
        existing = self.items.get(existing_id) if existing_id else None
        if existing is None:
            row = await db.fetchone("SELECT * FROM false_alarms WHERE scan_id=?", (scan_id,))
            existing = dict(row) if row else None
        if existing is not None:
            dup = fp in self._seen
            if not dup:
                existing["reports"] = int(existing.get("reports") or 1) + 1
            if note and not existing.get("note"):
                existing["note"] = note
            existing["last_reported_at"] = now
            self._seen.add(fp)
            await db.execute("UPDATE false_alarms SET reports=?, note=?, last_reported_at=? WHERE id=?",
                             (existing["reports"], existing["note"], now, existing["id"]))
            self._index(existing)
            return existing, dup
        item = {
            "id": f"FA-{secrets.token_hex(5).upper()}", "scan_id": scan_id, "kind": scan.get("kind") or "url",
            "label": _label(scan), "verdict": str(scan.get("verdict") or ""),
            "score": int(scan.get("risk_score") or 0), "note": note, "reports": 1, "status": "open",
            "created_at": now, "last_reported_at": now, "resolved_at": None,
        }
        await db.execute(
            "INSERT INTO false_alarms (id, scan_id, kind, label, verdict, score, note, reports, status, created_at, "
            "last_reported_at, resolved_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            tuple(item[k] for k in ("id", "scan_id", "kind", "label", "verdict", "score", "note", "reports",
                                    "status", "created_at", "last_reported_at", "resolved_at")))
        self._seen.add(fp)
        self._index(item)
        return item, False

    async def listing(self) -> dict[str, Any]:
        await self._ensure()
        items = sorted(self.items.values(), key=lambda i: i["last_reported_at"], reverse=True)
        counts = {s: 0 for s in STATUSES}
        for i in items:
            counts[i["status"]] = counts.get(i["status"], 0) + 1
        return {"items": [dict(i) for i in items], "counts": {**counts, "total": len(items)}}

    async def resolve(self, report_id: str, status: str) -> dict[str, Any] | None:
        await self._ensure()
        item = self.items.get(report_id)
        if item is None:
            row = await db.fetchone("SELECT * FROM false_alarms WHERE id=?", (report_id,))
            if not row:
                return None
            item = dict(row)
        item["status"] = status
        item["resolved_at"] = iso()
        await db.execute("UPDATE false_alarms SET status=?, resolved_at=? WHERE id=?",
                         (status, item["resolved_at"], report_id))
        if report_id in self.items:
            self.items[report_id] = item
        return item


feedback_state = FeedbackState()
