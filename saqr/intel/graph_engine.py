"""Module 4 — Criminal syndicate graph engine.

Nodes: domain | map_pin | ip_address | phone_number | citizen_report
Edges: hosted_on | linked_to_pin | shares_phone | reported_by_citizen

Connected components (union-find) over the infrastructure graph become syndicates.
IPs on shared infrastructure (Cloudflare, AWS, ...) are kept as nodes but are NOT used
to merge clusters, so unrelated sites behind a CDN don't get falsely linked.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any

from ..db import db, iso
from .registry import normalise_phone

INFRA_TYPES = {"domain", "map_pin"}
CODENAMES = [
    ("Black Dhow Network", "شبكة الداو الأسود"), ("Desert Scorpion Ring", "عصابة عقرب الصحراء"),
    ("Falcon Shadow Cell", "خلية ظل الصقر"), ("Oryx Ghost Group", "مجموعة شبح المها"),
    ("Dune Jackal Crew", "مجموعة ابن آوى الكثبان"), ("Pearl Serpent Ring", "عصابة أفعى اللؤلؤ"),
    ("Mirage Hawk Network", "شبكة صقر السراب"), ("Sabkha Wolf Cell", "خلية ذئب السبخة"),
    ("Ghaf Spider Group", "مجموعة عنكبوت الغاف"), ("Corniche Phantom Crew", "مجموعة شبح الكورنيش"),
]


class _UF:
    def __init__(self) -> None:
        self.p: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.p.setdefault(x, x)
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.p[rb] = ra


async def _load() -> tuple[list[dict], list[dict]]:
    nodes = await db.fetchall("SELECT * FROM graph_nodes")
    edges = await db.fetchall("SELECT * FROM graph_edges")
    for n in nodes:
        n["data"] = json.loads(n.pop("data_json") or "{}")
    for e in edges:
        e["data"] = json.loads(e.pop("data_json") or "{}")
    return nodes, edges


async def compute_clusters() -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]], list[dict], list[dict]]:
    """Return (node_id -> syndicate, syndicates, nodes, edges)."""
    nodes, edges = await _load()
    by_id = {n["id"]: n for n in nodes}
    uf = _UF()
    for n in nodes:
        uf.find(n["id"])
    for e in edges:
        tgt = by_id.get(e["target"])
        if tgt and tgt["type"] == "ip_address" and tgt["data"].get("shared_infrastructure"):
            continue
        if e["source"] in by_id and e["target"] in by_id:
            uf.union(e["source"], e["target"])

    comps: dict[str, list[str]] = {}
    for nid in by_id:
        comps.setdefault(uf.find(nid), []).append(nid)

    syn_rows = await db.fetchall("SELECT * FROM syndicates ORDER BY created_at ASC")
    node_syn: dict[str, dict[str, Any]] = {}
    syndicates: list[dict[str, Any]] = []
    used_ids: set[str] = set()

    for members in comps.values():
        infra = [m for m in members if by_id[m]["type"] in INFRA_TYPES]
        if len(infra) < 2:
            continue
        mset = set(members)
        named = [r for r in syn_rows if r["seed_node"] in mset and r["id"] not in used_ids]
        if named:
            syn = dict(named[0])
            syn["merged_from"] = [r["id"] for r in named[1:]]
        else:
            seed = min(infra, key=lambda m: (by_id[m]["first_seen"], m))
            sid = "SYN-" + hashlib.sha1(seed.encode()).hexdigest()[:6].upper()
            existing = next((r for r in syn_rows if r["id"] == sid), None)
            if existing:
                syn = dict(existing)
            else:
                name, name_ar = CODENAMES[int(hashlib.sha1(seed.encode()).hexdigest(), 16) % len(CODENAMES)]
                syn = {"id": sid, "name": name, "name_ar": name_ar, "seed_node": seed,
                       "description": "Auto-discovered cluster of shared scam infrastructure.", "created_at": iso()}
                await db.execute(
                    "INSERT OR IGNORE INTO syndicates (id, name, name_ar, seed_node, description, created_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (sid, name, name_ar, seed, syn["description"], syn["created_at"]))
            syn["merged_from"] = []
        used_ids.add(syn["id"])

        def of(t: str) -> list[str]:
            return sorted(by_id[m]["label"] for m in members if by_id[m]["type"] == t)

        domains = [by_id[m] for m in members if by_id[m]["type"] == "domain"]
        entities = sorted({d["data"].get("impersonated_entity") for d in domains if d["data"].get("impersonated_entity")})
        ssl = sorted({d["data"].get("ssl_issuer") for d in domains if d["data"].get("ssl_issuer")})
        summary = {
            "id": syn["id"], "name": syn["name"], "name_ar": syn.get("name_ar"),
            "description": syn.get("description"), "first_seen": min(by_id[m]["first_seen"] for m in members),
            "last_activity": max(by_id[m]["last_seen"] for m in members),
            "node_count": len(members), "domains": of("domain"), "ip_addresses": of("ip_address"),
            "map_pins": of("map_pin"), "phone_numbers": of("phone_number"),
            "citizen_reports": len(of("citizen_report")), "impersonated_entities": entities,
            "shared_ssl_issuers": ssl, "risk": max(by_id[m]["risk"] for m in members),
            "merged_from": syn.get("merged_from", []),
        }
        syndicates.append(summary)
        for m in members:
            node_syn[m] = summary
    syndicates.sort(key=lambda s: (-s["node_count"], s["id"]))
    return node_syn, syndicates, nodes, edges


async def build_graph(syndicate_id: str | None = None, include_reports: bool = True) -> dict[str, Any]:
    node_syn, syndicates, nodes, edges = await compute_clusters()
    out_nodes = []
    keep: set[str] = set()
    for n in nodes:
        syn = node_syn.get(n["id"])
        if syndicate_id and (not syn or syn["id"] != syndicate_id):
            continue
        if not include_reports and n["type"] == "citizen_report":
            continue
        keep.add(n["id"])
        out_nodes.append({
            "id": n["id"], "type": n["type"], "label": n["label"], "risk": n["risk"],
            "syndicate_id": syn["id"] if syn else None, "syndicate_name": syn["name"] if syn else None,
            "group": syn["id"] if syn else "unclustered",
            "val": {"ip_address": 8, "domain": 6, "map_pin": 6, "phone_number": 5}.get(n["type"], 3),
            "first_seen": n["first_seen"], "last_seen": n["last_seen"], "data": n["data"],
        })
    out_edges = [{"source": e["source"], "target": e["target"], "type": e["type"], "created_at": e["created_at"]}
                 for e in edges if e["source"] in keep and e["target"] in keep]
    sy = [s for s in syndicates if not syndicate_id or s["id"] == syndicate_id]
    return {
        "nodes": out_nodes, "edges": out_edges, "links": out_edges, "syndicates": sy,
        "stats": {"nodes": len(out_nodes), "edges": len(out_edges), "syndicates": len(sy),
                  "by_type": {t: sum(1 for n in out_nodes if n["type"] == t)
                              for t in ("domain", "map_pin", "ip_address", "phone_number", "citizen_report")}},
        "generated_at": iso(),
    }


async def syndicate_for(node_ids: list[str]) -> dict[str, Any] | None:
    """Return the syndicate any of the given (existing) nodes belongs to."""
    node_syn, *_ = await compute_clusters()
    for nid in node_ids:
        if nid in node_syn:
            return node_syn[nid]
    return None


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------
async def ingest_url_scan(scan: dict[str, Any]) -> dict[str, Any]:
    ti = scan.get("technical_indicators", {})
    domain = scan["domain"]
    new_nodes, new_edges = [], []
    dn = f"domain:{domain}"
    if await db.upsert_node(dn, "domain", domain, scan["risk_score"], {
            "impersonated_entity": scan.get("impersonated_entity"), "ssl_issuer": ti.get("ssl_issuer"),
            "registrar": ti.get("registrar"), "last_scan_id": scan["scan_id"], "verdict": scan["verdict"]}):
        new_nodes.append(dn)
    for ip in ti.get("ip_addresses", [])[:4]:
        inode = f"ip:{ip}"
        if await db.upsert_node(inode, "ip_address", ip, scan["risk_score"], {
                "asn": ti.get("asn"), "asn_org": ti.get("asn_org"), "country": ti.get("ip_country"),
                "shared_infrastructure": bool(ti.get("shared_infrastructure"))}):
            new_nodes.append(inode)
        if await db.upsert_edge(dn, inode, "hosted_on", {"record": "A"}):
            new_edges.append((dn, inode, "hosted_on"))
    rn = f"report:{scan['scan_id']}"
    if await db.upsert_node(rn, "citizen_report", scan["scan_id"], 0,
                            {"channel": scan.get("channel"), "message": (scan.get("message_text") or "")[:500]}):
        new_nodes.append(rn)
    if await db.upsert_edge(dn, rn, "reported_by_citizen", {"channel": scan.get("channel")}):
        new_edges.append((dn, rn, "reported_by_citizen"))
    syn = await syndicate_for([dn])
    return {"new_nodes": new_nodes, "new_edges": [dict(zip(("source", "target", "type"), e)) for e in new_edges],
            "syndicate": _syn_brief(syn)}


async def ingest_map_scan(scan: dict[str, Any]) -> dict[str, Any]:
    pin = scan["listing"]
    pid = pin["pin_id"]
    new_nodes, new_edges = [], []
    if await db.upsert_node(pid, "map_pin", pin.get("name") or pid, scan["risk_score"], {
            "lat": pin.get("lat"), "lng": pin.get("lng"), "website": pin.get("website_domain"),
            "phone": pin.get("phone"), "place_type": pin.get("place_type"), "last_scan_id": scan["scan_id"]}):
        new_nodes.append(pid)
    if pin.get("website_domain"):
        dn = f"domain:{pin['website_domain']}"
        if await db.upsert_node(dn, "domain", pin["website_domain"], scan.get("website_risk", scan["risk_score"]),
                                {"impersonated_entity": scan.get("impersonated_entity")}):
            new_nodes.append(dn)
        if await db.upsert_edge(pid, dn, "linked_to_pin"):
            new_edges.append((pid, dn, "linked_to_pin"))
    phone = normalise_phone(pin.get("phone"))
    if phone:
        ph = f"phone:{phone}"
        if await db.upsert_node(ph, "phone_number", pin.get("phone") or phone, scan["risk_score"], {"normalized": phone}):
            new_nodes.append(ph)
        if await db.upsert_edge(pid, ph, "shares_phone"):
            new_edges.append((pid, ph, "shares_phone"))
    rn = f"report:{scan['scan_id']}"
    if await db.upsert_node(rn, "citizen_report", scan["scan_id"], 0, {"channel": "maps"}):
        new_nodes.append(rn)
    if await db.upsert_edge(pid, rn, "reported_by_citizen", {"channel": "maps"}):
        new_edges.append((pid, rn, "reported_by_citizen"))
    syn = await syndicate_for([pid])
    return {"new_nodes": new_nodes, "new_edges": [dict(zip(("source", "target", "type"), e)) for e in new_edges],
            "syndicate": _syn_brief(syn)}


def _syn_brief(syn: dict[str, Any] | None) -> dict[str, Any] | None:
    if not syn:
        return None
    return {"id": syn["id"], "name": syn["name"], "name_ar": syn.get("name_ar"), "node_count": syn["node_count"],
            "domains": syn["domains"], "ip_addresses": syn["ip_addresses"]}
