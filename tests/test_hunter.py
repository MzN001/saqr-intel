"""Proactive hunter: look-alike generator, triage, sources, cycles, lead time, API. Run: pytest -q"""
import asyncio
import base64
import io
import json
import os
import tempfile
import zipfile
from datetime import timedelta

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ.setdefault("CT_MODE", "off")
os.environ.setdefault("OFFLINE_MODE", "true")
os.environ.setdefault("LLM_PROVIDER", "rules")
os.environ.setdefault("RATE_LIMIT_PER_MINUTE", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.config import settings  # noqa: E402
from saqr.db import db, iso, utcnow  # noqa: E402
from saqr.intel import hunter as H  # noqa: E402
from saqr.intel import lookalike_gen as G  # noqa: E402
from saqr.intel.ct_monitor import ct_monitor  # noqa: E402
from saqr.intel.domain_intel import analyze_lexical  # noqa: E402
from saqr.intel.registry import ENTITIES, ENTITY_BY_ID, OFFICIAL_DOMAINS  # noqa: E402


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


class FixedLeads(H.Source):
    name = "lookalike_sweep"

    def __init__(self, leads):
        super().__init__()
        self.leads = leads

    async def collect(self):
        return list(self.leads)


# -- look-alike generator ----------------------------------------------------------------------
def test_generator_never_returns_an_official_or_trusted_domain():
    cands = G.generate_all(10_000)
    assert len(cands) > 3000
    for c in cands:
        assert not G.is_official(c.domain), c
        assert c.domain not in OFFICIAL_DOMAINS
    assert not any(analyze_lexical(c.domain).is_whitelisted for c in cands[::7])


def test_generator_is_deterministic_bounded_and_unique():
    first, second = G.generate_all(120), G.generate_all(120)
    assert first == second
    assert len({c.domain for c in first}) == len(first)
    for ent in ENTITIES:
        assert len(G.generate(ent, 120)) <= 120
        assert G.generate(ent, 25) == G.generate(ent, 120)[:25]
        assert G.generate(ent, 0) == []
    assert len(first) <= 120 * len(ENTITIES)


def test_generator_covers_every_technique_with_valid_registrable_names():
    uaepass = G.generate(ENTITY_BY_ID["uaepass"], 400)
    assert {c.technique for c in uaepass} == set(G.TECHNIQUES)
    names = {c.domain for c in uaepass}
    assert {"uaepass.com", "uaepass-verify.com", "uae-pass.com", "uaepas.com", "uaepsas.com", "uaeppass.com",
            "uaepa5s.com"} <= names
    everything = G.generate_all(10_000)
    assert {"tamm-fine-pay.com", "adcb-secure-login.com", "adpolice-fines.com"} <= {c.domain for c in everything}
    for c in everything:
        assert H.HOSTNAME.match(c.domain), c
        assert not c.domain.endswith((".gov.ae", ".abudhabi")), c  # nobody can register there
    assert any(c.domain.startswith("xn--") for c in everything)  # Cyrillic look-alike letters


def test_short_brands_get_no_typo_variants():
    assert {c.technique for c in G.generate(ENTITY_BY_ID["du"], 10_000)} == {"tld_swap", "brand_lure"}


# -- triage --------------------------------------------------------------------------------------
def test_triage_scores_lookalikes_and_drops_what_must_never_be_hunted():
    hit = H.triage("tamm-fine-pay.xyz")
    assert hit.drop_reason is None and hit.score >= settings.hunter_triage_threshold
    assert hit.entity == "TAMM Abu Dhabi" and hit.uae and "BRAND_IMPERSONATION" in hit.flags
    assert H.triage("*.UAEPASS-verify.com").domain == "uaepass-verify.com"
    assert H.triage("www.tamm.abudhabi").drop_reason == "official"
    assert H.triage("login.adcb.com").drop_reason == "official"
    assert H.triage("vercel.app").drop_reason == "shared_platform"
    assert H.triage("wikipedia.org").drop_reason == "popular_site"
    assert H.triage("not a domain").drop_reason == "invalid"
    assert H.triage(settings.demo_scam_domains[0]).drop_reason == "own_host"
    assert H.triage("abudhabi-yoga-studio.com").score < settings.hunter_triage_threshold


# -- sources -------------------------------------------------------------------------------------
def test_lookalike_sweep_keeps_registered_names_and_skips_wildcard_endings():
    cands = [G.Candidate("uaepass-verify.com", "uaepass", "brand_lure", "uaepass"),
             G.Candidate("uaepas.com", "uaepass", "omission", "uaepass"),
             G.Candidate("uaepass.ws", "uaepass", "tld_swap", "uaepass"),
             G.Candidate("uaepass-login.net", "uaepass", "brand_lure", "uaepass")]
    asked = []

    async def resolver(domain):
        asked.append(domain)
        if domain.endswith(".ws"):
            return "registered"  # an ending that answers for every name
        return {"uaepass-verify.com": "registered", "uaepas.com": "nxdomain"}.get(domain, "unknown")

    sweep = H.LookalikeSweep(resolver=resolver, candidates=cands, batch=3)
    leads = asyncio.run(sweep.run())
    assert [(lead.domain, lead.source, lead.entity_id) for lead in leads] == [
        ("uaepass-verify.com", "lookalike_sweep", "uaepass")]
    assert leads[0].detail == {"technique": "brand_lure", "imitates": "uaepass"}
    assert sweep.wildcard_tlds == {"com": False, "ws": True} and "uaepass.ws" not in asked
    assert sweep.cursor == 3
    again = asyncio.run(sweep.run())  # wraps around: 4 names in slices of 3 (the cycle drops repeats)
    assert [lead.domain for lead in again] == ["uaepass-verify.com"] and sweep.cursor == 2


def test_crtsh_dedupes_by_certificate_id_and_keeps_only_recent_names():
    recent, old = iso(utcnow() - timedelta(hours=5)), iso(utcnow() - timedelta(days=60))
    rows = [{"id": 1, "entry_timestamp": recent, "name_value": "*.tamm-pay-now.xyz\ntamm-pay-now.xyz",
             "issuer_name": "C=US, O=Let's Encrypt, CN=R11"},
            {"id": 2, "entry_timestamp": old, "name_value": "tamm-old-cert.com"},
            {"id": 3, "not_before": recent[:19], "name_value": "docs.uaepass.ae\nnot a host"},
            {"id": "x", "entry_timestamp": recent, "name_value": "bad-id.com"}]
    src = H.CrtSh(patterns=["%tamm-%"])
    leads = src.parse(json.dumps(rows).encode(), "%tamm-%")
    assert sorted(lead.domain for lead in leads) == ["docs.uaepass.ae", "tamm-pay-now.xyz"]
    assert leads[0].detail["cert_id"] == 1 and leads[0].source == "crtsh"
    assert src.parse(json.dumps(rows).encode(), "%tamm-%") == []  # same certificates again


def test_crtsh_rests_after_a_failure_instead_of_retrying_every_cycle():
    calls = []

    async def broken(pattern):
        calls.append(pattern)
        raise TimeoutError("crt.sh did not answer")

    src = H.CrtSh(fetch=broken, patterns=["%uaepass%", "%tamm-%"], pause_s=0)
    assert asyncio.run(src.run()) == [] and src.last_error.startswith("TimeoutError")
    assert src.rest_until > utcnow() and len(calls) == 1
    assert asyncio.run(src.run()) == [] and len(calls) == 1 and "resting" in src.note


def test_crtsh_patterns_skip_two_and_three_letter_brands():
    patterns = H.crtsh_patterns()
    assert "%tamm-%" in patterns and "%emiratespost%" in patterns and "%uaepas%" in patterns
    assert "%uaepass%" not in patterns  # covered by the wider %uaepas%
    assert not any(p.strip("%-") in {"du", "fab"} for p in patterns)


def test_newly_registered_list_is_filtered_by_brand_keyword_and_read_once_a_day():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("domain-names.txt", "coffee-house-22.com\nuaepass-verify-id.top\nBAD LINE\ntamm-refund.site\n")
    fetched = []

    async def fetch(url):
        fetched.append(url)
        return buf.getvalue()

    src = H.NewlyRegistered(fetch=fetch)
    leads = asyncio.run(src.run())
    assert sorted(lead.domain for lead in leads) == ["tamm-refund.site", "uaepass-verify-id.top"]
    yesterday = (utcnow().date() - timedelta(days=1)).isoformat()
    assert fetched == [H.NewlyRegistered.url_for(yesterday)]
    assert base64.b64decode(fetched[0].split("/")[-2]).decode() == f"{yesterday}.zip"
    assert asyncio.run(src.run()) == [] and len(fetched) == 1


def test_newly_registered_falls_back_one_day_and_reports_when_nothing_is_published():
    async def empty(url):
        return b""

    src = H.NewlyRegistered(fetch=empty)
    assert asyncio.run(src.run()) == [] and "no list published" in src.note and src.done_day is None


def test_ct_queue_ignores_the_synthetic_stream_in_a_live_hunt():
    live, sim = H.CTQueue(), H.CTQueue(accept_simulated=True)
    for q in (live, sim):
        q.push({"domain": "tamm-pay-7.xyz", "issuer": "Let's Encrypt R11", "source": "simulated"})
        q.push({"domain": "*.adcb-verify.top", "issuer": "ZeroSSL", "source": "certstream"})
    assert [(lead.domain, lead.simulated) for lead in asyncio.run(live.run())] == [("adcb-verify.top", False)]
    assert live.ignored_simulated == 1
    assert [(lead.domain, lead.simulated) for lead in asyncio.run(sim.run())] == [
        ("tamm-pay-7.xyz", True), ("adcb-verify.top", False)]


def test_ct_monitor_hands_its_detections_to_listeners(client):
    q = H.CTQueue(accept_simulated=True)
    ct_monitor.listeners.append(q.push)
    try:
        event = client.portal.call(ct_monitor.evaluate, "tamm-fines-hunter-test.xyz", "Let's Encrypt R11", "simulated")
        assert client.portal.call(ct_monitor.evaluate, "coffee-house-hunter.com", "Sectigo DV", "simulated") is None
    finally:
        ct_monitor.listeners.remove(q.push)
    assert event and [lead.domain for lead in q.queue] == ["tamm-fines-hunter-test.xyz"]


# -- status rules --------------------------------------------------------------------------------
def test_status_for_keeps_mild_warnings_on_old_domains_out_of_the_detections():
    assert H.status_for(80, "HIGH-RISK SCAM", 20 * 365 * 24) == "confirmed"
    assert H.status_for(40, "SUSPICIOUS", 12.0) == "suspicious"
    assert H.status_for(40, "SUSPICIOUS", None) == "suspicious"
    assert H.status_for(40, "SUSPICIOUS", 10 * 365 * 24) == "cleared"
    assert H.status_for(10, "SAFE", 5.0) == "cleared"


# -- cycles --------------------------------------------------------------------------------------
def test_mode_is_simulated_offline_and_seeds_labelled_rows(client):
    assert H.hunter.mode == "simulated" and H.effective_mode() == "simulated"
    body = client.get("/api/hunter/detections").json()
    assert body["mode"] == "simulated" and body["data"] == "simulated" and body["count"] >= 8
    for d in body["detections"]:
        assert d["simulated"] is True and d["data"] == "simulated" and d["scan_id"] is None
        assert d["published_to_blocklist"] is False and d["source"] in H.SOURCES
    assert client.portal.call(H.hunter.seed_simulated) == 0  # idempotent


def test_simulated_cycle_writes_rows_and_broadcasts(client):
    before = client.get("/api/hunter/detections?limit=200&include_cleared=true").json()["count"]
    with client.websocket_connect("/ws/live?topics=hunter") as ws:
        assert ws.receive_json()["event"] == "hello"
        r = client.post("/api/hunter/sweep?wait=true")
        assert r.status_code == 200, r.text
        cycle = r.json()["cycle"]
        assert r.json()["started"] and cycle["mode"] == "simulated" and 1 <= cycle["scanned"] <= 3
        events = [ws.receive_json() for _ in range(cycle["confirmed"] + cycle["suspicious"] + 1)]
    assert [e["event"] for e in events][-1] == "hunter.cycle"
    for e in events[:-1]:
        assert e["event"] == "hunter.detection" and e["data"]["data"] == "simulated"
        assert e["data"]["defanged_domain"] == e["data"]["domain"].replace(".", "[.]")
    after = client.get("/api/hunter/detections?limit=200&include_cleared=true").json()["count"]
    assert after == before + cycle["scanned"]
    published = {d["domain"] for d in client.get("/api/dns-blocklist?min_score=0").json()["domains"]}
    simulated = {d["domain"] for d in client.get("/api/hunter/detections?limit=200").json()["detections"]}
    assert simulated and not simulated & published  # synthetic names never reach a real blocklist


def test_live_cycle_runs_the_full_scan_and_feeds_the_blocklist(client):
    leads = [H.Lead("tamm-fine-pay-hunt.xyz", "lookalike_sweep", entity_id="tamm", detail={"technique": "brand_lure"}),
             H.Lead("uaepass-verify-hunt.top", "crtsh", detail={"cert_id": 7}),
             H.Lead("www.tamm.abudhabi", "nrd"), H.Lead("abudhabi-yoga-studio.com", "nrd"),
             H.Lead("tamm-fine-pay-hunt.xyz", "nrd")]
    hunt = H.Hunter(mode="live", sources=[FixedLeads(leads)])
    with client.websocket_connect("/ws/live?topics=hunter,police") as ws:
        assert ws.receive_json()["event"] == "hello"
        cycle = client.portal.call(hunt.run_cycle)
        events = [ws.receive_json() for _ in range(5)]
    assert cycle["leads"] == 5 and cycle["dropped"] == {"official": 1} and cycle["below_threshold"] == 1
    assert cycle["already_known"] == 1 and cycle["scanned"] == 2 and cycle["confirmed"] == 2
    assert cycle["no_brand_evidence"] == 0
    names = [e["event"] for e in events]  # the two scans run side by side, so their events interleave
    assert sorted(names[:4]) == ["hunter.detection"] * 2 + ["police.proactive_detection"] * 2
    assert names[4] == "hunter.cycle"

    rows = {d["domain"]: d for d in client.get("/api/hunter/detections?limit=200").json()["detections"]}
    tamm = rows["tamm-fine-pay-hunt.xyz"]
    assert tamm["data"] == "real" and tamm["status"] == "confirmed" and tamm["verdict"] == "HIGH-RISK SCAM"
    assert tamm["entity"] == "TAMM Abu Dhabi" and tamm["source"] == "lookalike_sweep"
    assert tamm["citizen_visits"] == 0 and tamm["lead_time_hours"] is None and tamm["published_to_blocklist"]
    assert rows["uaepass-verify-hunt.top"]["detail"] == {"cert_id": 7}
    scan = client.get(f"/api/scans/{tamm['scan_id']}").json()
    assert scan["interception_channel"] == "PROACTIVE_HUNTER" and scan["reporter"] == "hunter"
    published = {d["domain"] for d in client.get("/api/dns-blocklist").json()["domains"]}
    assert {"tamm-fine-pay-hunt.xyz", "uaepass-verify-hunt.top"} <= published

    again = client.portal.call(hunt.run_cycle)  # the same leads are not scanned twice
    assert again["scanned"] == 0 and again["already_known"] == 3


def test_feed_leads_need_brand_evidence_and_du_needs_a_lure_word(client):
    assert H.AMBIGUOUS_BRANDS == {"du"}
    assert H.triage("uaepass-verify-id.top").names_a_brand and H.triage("du-prize-winner.top").names_a_brand
    french = H.triage("au-bon-coin-du-monde.com")  # "du" = "of the": scored by the lexical rules, not hunted
    assert french.entity_id == "du" and not french.names_a_brand
    leads = [H.Lead("au-bon-coin-du-monde.com", "nrd"), H.Lead("tamm-refund-brandrule.xyz", "nrd"),
             H.Lead("du-brandrule.xyz", "lookalike_sweep", entity_id="du")]
    cycle = client.portal.call(H.Hunter(mode="live", sources=[FixedLeads(leads)]).run_cycle)
    assert cycle["no_brand_evidence"] == 1 and cycle["scanned"] == 2  # the generated du name is still checked


def test_scan_cap_per_cycle_leaves_the_rest_in_the_backlog(client):
    names = [f"adcb-secure-login-cap{i}.xyz" for i in range(5)]
    hunt = H.Hunter(mode="live", sources=[FixedLeads([H.Lead(n, "nrd") for n in names])])
    hunt.max_scans = 2
    first = client.portal.call(hunt.run_cycle)
    assert first["scanned"] == 2 and first["backlog"] == 3
    hunt.sources = []
    second = client.portal.call(hunt.run_cycle)
    assert second["scanned"] == 2 and second["backlog"] == 1


def test_citizen_visits_and_lead_time_are_counted_after_detection(client):
    domain = "adpolice-fines-leadtime.xyz"

    async def backdated():
        hunt = H.Hunter(mode="live", sources=[FixedLeads([H.Lead(domain, "ct", iso(utcnow() - timedelta(hours=6)))])])
        return await hunt.run_cycle()

    assert client.portal.call(backdated)["confirmed"] == 1
    for sub in ("", "www."):
        r = client.post("/api/analyze-url", json={"url": f"https://{sub}{domain}/pay", "channel": "sms"})
        assert r.status_code == 200 and r.json()["verdict"] != "SAFE"
    row = next(d for d in client.get("/api/hunter/detections?limit=200").json()["detections"] if d["domain"] == domain)
    assert row["citizen_visits"] == 2  # the hunter's own scan is not a citizen
    assert 5.9 <= row["lead_time_hours"] <= 6.1 and 5.9 <= row["hours_since_detection"] <= 6.1
    assert row["first_citizen_at"] >= row["scanned_at"]


def test_domain_a_citizen_already_scanned_is_not_a_pre_victim_detection(client):
    domain = "tamm-refund-seen-first.xyz"
    assert client.post("/api/analyze-url", json={"url": f"https://{domain}/"}).status_code == 200
    hunt = H.Hunter(mode="live", sources=[FixedLeads([H.Lead(domain, "nrd")])])
    cycle = client.portal.call(hunt.run_cycle)
    assert cycle["already_known"] == 1 and cycle["scanned"] == 0


def test_a_failing_source_does_not_stop_the_cycle(client):
    class Broken(H.Source):
        name = "crtsh"

        async def collect(self):
            raise RuntimeError("502 Bad Gateway")

    broken = Broken()
    hunt = H.Hunter(mode="live", sources=[broken, FixedLeads([H.Lead("etisalat-rewards-ok.top", "nrd")])])
    assert client.portal.call(hunt.run_cycle)["scanned"] == 1
    assert broken.status()["last_error"] == "RuntimeError: 502 Bad Gateway" and broken.status()["last_ok"] is None


# -- API -----------------------------------------------------------------------------------------
def test_status_labels_real_and_simulated_counts(client):
    s = client.get("/api/hunter/status").json()
    assert s["mode"] == "simulated" and s["data"] == "simulated" and s["cycles"] >= 1
    assert s["sources"] == [dict(s["sources"][0], name="simulated", data="simulated")]
    assert s["last_cycle"]["mode"] == "simulated"
    assert s["detections_by_source"]["lookalike_sweep"]["real"]["confirmed"] >= 1
    assert sum(s["detections_by_source"]["lookalike_sweep"]["simulated"].values()) >= 1
    assert s["limits"]["max_scans_per_cycle"] == settings.hunter_max_scans_per_cycle > 0
    assert s["totals"]["confirmed"] >= 3


def test_live_status_lists_the_four_real_sources():
    assert [s.name for s in H.default_sources("live")] == ["lookalike_sweep", "crtsh", "ct", "nrd"]
    assert all(s.status()["data"] == "real" for s in H.default_sources("live"))
    assert H.default_sources("off") == []


def test_sweep_is_refused_when_the_hunter_is_off(client, monkeypatch):
    monkeypatch.setattr(H.hunter, "mode", "off")
    assert client.post("/api/hunter/sweep").status_code == 409


def test_sweep_without_wait_kicks_the_background_loop(client):
    r = client.post("/api/hunter/sweep").json()
    assert r == {"started": True, "mode": "simulated", "cycle": None}


def test_police_snapshot_exposes_proactive_detections(client):
    s = client.get("/api/police/state").json()
    confirmed = client.get("/api/hunter/detections").json()["pre_victim_detections"]
    assert s["kpis"]["pre_victim_detections"] == confirmed >= 3
    assert 1 <= len(s["proactive_detections"]) <= 20 and s["hunter_mode"] == "simulated"
    first = s["proactive_detections"][0]
    assert {"domain", "source", "score", "status", "citizen_visits", "lead_time_hours", "hours_since_detection",
            "data"} <= set(first)
    assert all(d["status"] != "cleared" for d in s["proactive_detections"])


def test_proactive_hunter_is_a_valid_interception_channel(client):
    r = client.post("/api/analyze-url", json={"url": "https://www.tamm.abudhabi/", "run_sandbox": False,
                                              "interception_channel": "PROACTIVE_HUNTER"})
    assert r.status_code == 200 and r.json()["interception_channel"] == "PROACTIVE_HUNTER"
