"""Evasion resistance: shorteners, redirect chains (30x / meta / JS / parameters) and HTTP-only
cloaking. Everything runs against httpx.MockTransport: no request leaves the machine."""
import asyncio
import ipaddress
import os
import tempfile

os.environ.setdefault("DATABASE_PATH", os.path.join(tempfile.mkdtemp(), "test.db"))
os.environ["CT_MODE"] = "off"
os.environ["OFFLINE_MODE"] = "true"
os.environ["LLM_PROVIDER"] = "rules"
os.environ["RATE_LIMIT_PER_MINUTE"] = "0"

import httpx  # noqa: E402
import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from main import app  # noqa: E402
from saqr.config import settings  # noqa: E402
from saqr.intel import redirects, sandbox as sandbox_mod  # noqa: E402
from saqr.intel.threat_feeds import threat_feeds  # noqa: E402

SCAM = "tamm-refund-verify.xyz"
HTML = {"content-type": "text/html; charset=utf-8"}


async def fake_guard(host: str):
    """The real SSRF rule for IP literals, without DNS for names."""
    try:
        return ipaddress.ip_address(host).is_global, [host]
    except ValueError:
        return host != "localhost", []


@pytest.fixture
def web(monkeypatch):
    """Install a fake internet: routes maps 'host/path' to (status, headers, body). Returns the
    routes dict and the list of requests that were made."""
    routes: dict[str, tuple[int, dict, str]] = {}
    calls: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, str(request.url)))
        key = request.url.host + request.url.path
        if key not in routes:
            return httpx.Response(404, headers=HTML, text="not found")
        status, headers, body = routes[key]
        return httpx.Response(status, headers=headers, text="" if request.method == "HEAD" else body)

    transport = httpx.MockTransport(handler)
    monkeypatch.setattr(redirects, "TRANSPORT", transport)
    monkeypatch.setattr(sandbox_mod, "TRANSPORT", transport)
    monkeypatch.setattr(redirects, "host_is_safe_target", fake_guard)
    monkeypatch.setattr(sandbox_mod, "host_is_safe_target", fake_guard)
    return routes, calls


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        yield c


def chain(url: str, **kw) -> list[dict]:
    return asyncio.run(redirects.resolve_chain(url, **kw))


def scan(client, url: str, run_sandbox: bool = False) -> dict:
    r = client.post("/api/analyze-url", json={"url": url, "run_sandbox": run_sandbox, "use_llm": False})
    assert r.status_code == 200, r.text
    return r.json()


def codes(body: dict) -> set[str]:
    return {f["code"] for f in body["red_flags"]}


# --- resolve_chain ---------------------------------------------------------------------
def test_shortener_list_is_real_and_matches_whole_hosts():
    assert len(redirects.SHORTENERS) >= 80
    assert redirects.is_shortener("bit.ly") and redirects.is_shortener("www.tinyurl.com")
    assert not redirects.is_shortener("rabbit.ly") and not redirects.is_shortener("bit.ly.evil.com")


def test_http_redirect_chain_is_followed_hop_by_hop(web):
    routes, calls = web
    routes["bit.ly/abc"] = (301, {"location": "https://hop.example/go"}, "")
    routes["hop.example/go"] = (302, {"location": "/landing"}, "")
    routes["hop.example/landing"] = (200, HTML, "<html><body>" + "welcome " * 100 + "</body></html>")
    hops = chain("https://bit.ly/abc")
    assert [(h["host"], h["status"], h["via"]) for h in hops] == [
        ("bit.ly", 301, "input"), ("hop.example", 302, "http"), ("hop.example", 200, "http")]
    assert calls[0] == ("HEAD", "https://bit.ly/abc")


def test_meta_refresh_and_javascript_hops(web):
    routes, _ = web
    routes["t.co/x"] = (200, HTML, '<html><head><noscript><meta http-equiv="refresh" '
                                   'content="0;URL=https://stub.example/r"></noscript></head></html>')
    routes["stub.example/r"] = (200, HTML, '<script>window.location.replace("https:\\/\\/final.example\\/pay");</script>')
    routes["final.example/pay"] = (200, HTML, "<html><body><h1>Pay</h1></body></html>")
    hops = chain("https://t.co/x")
    assert [(h["host"], h["via"]) for h in hops] == [("t.co", "input"), ("stub.example", "meta"), ("final.example", "js")]
    assert hops[-1]["url"] == "https://final.example/pay"


def test_script_on_a_real_page_is_not_a_redirect():
    page = "<html><body>" + "<p>Our clinic offers dental care in Abu Dhabi.</p>" * 20 + \
           "<script>btn.onclick = () => { location.href = 'https://booking.example/'; }</script></body></html>"
    assert redirects.html_redirect(page) == (None, None)
    assert redirects.html_redirect('<meta http-equiv="refresh" content="300">') == (None, None)


def test_loop_ends_the_chain(web):
    routes, calls = web
    routes["a.example/"] = (302, {"location": "https://b.example/"}, "")
    routes["b.example/"] = (302, {"location": "https://a.example/"}, "")
    hops = chain("https://a.example/")
    assert [h["host"] for h in hops] == ["a.example", "b.example"]
    assert hops[-1]["note"] == "loop"
    assert len(calls) == 2


def test_hop_limit(web):
    routes, _ = web
    for i in range(20):
        routes[f"h{i}.example/"] = (302, {"location": f"https://h{i + 1}.example/"}, "")
    hops = chain("https://h0.example/", max_hops=3)
    assert len(hops) == 4 and hops[-1]["note"] == "max_hops"


def test_redirect_to_private_address_is_never_fetched(web):
    routes, calls = web
    routes["bit.ly/meta"] = (301, {"location": "http://169.254.169.254/latest/meta-data/"}, "")
    hops = chain("https://bit.ly/meta")
    assert hops[-1]["host"] == "169.254.169.254" and hops[-1]["note"] == "blocked_private"
    assert all("169.254" not in url for _, url in calls)


def test_timeout_and_unreachable_end_cleanly(monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "slow.example":
            raise httpx.ReadTimeout("slow", request=request)
        raise httpx.ConnectError("down", request=request)

    monkeypatch.setattr(redirects, "TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(redirects, "host_is_safe_target", fake_guard)
    assert chain("https://slow.example/")[-1]["note"] == "timeout"
    assert chain("https://down.example/")[-1]["note"] == "unreachable"


def test_redirect_parameter_is_unwrapped_without_network(monkeypatch):
    monkeypatch.setattr(redirects, "TRANSPORT", None)
    assert settings.offline_mode
    hops = chain(f"https://www.google.com/url?q=https://{SCAM}/login&sa=D")
    assert [(h["host"], h["via"]) for h in hops] == [("www.google.com", "input"), (SCAM, "param")]


def test_fast_mode_uses_the_network_only_for_shorteners(web):
    routes, calls = web
    routes["plain.example/"] = (302, {"location": "https://other.example/"}, "")
    routes["bit.ly/f"] = (301, {"location": "https://plain.example/"}, "")
    assert len(chain("https://plain.example/", fast=True)) == 1 and not calls
    assert [h["host"] for h in chain("https://bit.ly/f", fast=True)] == ["bit.ly", "plain.example", "other.example"]
    assert {m for m, _ in calls} == {"HEAD"}


def test_official_and_seeded_hosts_are_never_fetched(web):
    routes, calls = web
    routes["bit.ly/gov"] = (301, {"location": "https://www.adpolice.gov.ae/"}, "")
    routes["bit.ly/seed"] = (301, {"location": "https://tamm-smart-pay.net/refund"}, "")
    chain("https://bit.ly/gov")
    chain("https://bit.ly/seed")
    assert {httpx.URL(u).host for _, u in calls} == {"bit.ly"}


# --- pipeline --------------------------------------------------------------------------
@pytest.mark.parametrize("run_sandbox", [False, True])
def test_shortener_to_scam_is_reported_as_the_scam_host(client, web, run_sandbox):
    routes, _ = web
    routes["bit.ly/refund"] = (301, {"location": f"https://{SCAM}/claim"}, "")
    routes[f"{SCAM}/claim"] = (200, HTML, "<html><body>" + "claim your refund " * 60 + "</body></html>")
    body = scan(client, "https://bit.ly/refund", run_sandbox)
    assert body["verdict"] == "HIGH-RISK SCAM"
    assert body["domain"] == SCAM and body["input_domain"] == "bit.ly"
    assert body["input_url"] == "https://bit.ly/refund"
    assert {"REDIRECTS_TO_FLAGGED", "URL_SHORTENER", "BRAND_IMPERSONATION"} <= codes(body)
    assert all(f["points"] == 0 for f in body["red_flags"] if f["code"] in ("REDIRECTS_TO_FLAGGED", "URL_SHORTENER"))
    assert [h["host"] for h in body["technical_indicators"]["redirect_chain"]] == ["bit.ly", SCAM]
    assert SCAM in body["citizen_explanation_en"] and SCAM in body["citizen_explanation_ar"]


def test_shortener_to_seeded_scam_gets_the_full_dossier(client, web):
    routes, _ = web
    routes["tinyurl.com/tamm"] = (301, {"location": "https://tamm-smart-pay.net/refund"}, "")
    body = scan(client, "https://tinyurl.com/tamm", run_sandbox=True)
    assert body["verdict"] == "HIGH-RISK SCAM" and body["domain"] == "tamm-smart-pay.net"
    assert body["impersonated_entity"] == "TAMM Abu Dhabi"
    assert "OTP" in body["technical_indicators"]["harvested_fields"]


def test_shortener_to_official_site_is_safe(client, web):
    routes, _ = web
    routes["bit.ly/police"] = (301, {"location": "https://www.adpolice.gov.ae/en/services"}, "")
    body = scan(client, "https://bit.ly/police")
    assert body["verdict"] == "SAFE" and body["risk_score"] == 0
    assert body["domain"] == "www.adpolice.gov.ae" and body["is_official_domain"] is True
    assert "URL_SHORTENER" in codes(body) and "REDIRECTS_TO_FLAGGED" not in codes(body)


def test_shortener_to_ordinary_site_is_safe(client, web):
    routes, _ = web
    routes["rb.gy/shop"] = (302, {"location": "https://dubai-dental.com/book"}, "")
    routes["dubai-dental.com/book"] = (200, HTML, "<html><body>" + "book a visit " * 60 + "</body></html>")
    body = scan(client, "https://rb.gy/shop", run_sandbox=True)
    assert body["verdict"] == "SAFE" and body["domain"] == "dubai-dental.com"


def test_scam_hop_that_bounces_to_a_famous_site_is_still_judged(client, web):
    routes, _ = web
    routes["bit.ly/b"] = (301, {"location": f"https://{SCAM}/"}, "")
    routes[f"{SCAM}/"] = (302, {"location": "https://www.google.com/"}, "")
    body = scan(client, "https://bit.ly/b")
    assert body["domain"] == SCAM and body["verdict"] == "HIGH-RISK SCAM"
    assert "REDIRECT_CHAIN" in codes(body)


def test_open_redirect_parameter_names_the_real_destination(client, web):
    body = scan(client, f"https://www.google.com/url?q=https://{SCAM}/login")
    assert body["domain"] == SCAM and body["verdict"] != "SAFE"
    assert "REDIRECTS_TO_FLAGGED" in codes(body) and "URL_SHORTENER" not in codes(body)


def test_decoy_parameter_cannot_whitewash_a_scam_address(client, web):
    body = scan(client, f"https://{SCAM}/login?url=https://www.adpolice.gov.ae/")
    assert body["domain"] == SCAM and body["verdict"] == "HIGH-RISK SCAM"


def test_site_that_stays_on_its_own_domain_is_unchanged(client, web):
    routes, _ = web
    routes["dubai-dental.com/"] = (301, {"location": "https://dubai-dental.com/home"}, "")
    routes["dubai-dental.com/home"] = (200, HTML, "<html><body>" + "smile " * 100 + "</body></html>")
    body = scan(client, "https://dubai-dental.com/", run_sandbox=True)
    assert body["verdict"] == "SAFE" and body["domain"] == body["input_domain"] == "dubai-dental.com"
    assert not codes(body) & {"URL_SHORTENER", "REDIRECT_CHAIN", "REDIRECTS_TO_FLAGGED"}


def test_blocklist_lists_the_destination_never_the_shortener(client, web, monkeypatch):
    routes, _ = web
    routes["cutt.ly/fine"] = (301, {"location": "https://uaepass-login-secure.top/"}, "")
    assert scan(client, "https://cutt.ly/fine")["verdict"] != "SAFE"
    # A dead short link that a threat feed lists must not put the shortener itself on the blocklist.
    monkeypatch.setattr(threat_feeds, "lookup", lambda host: "TestFeed" if host == "t.ly" else None)
    dead = scan(client, "https://t.ly/gone")
    assert dead["verdict"] == "HIGH-RISK SCAM" and dead["domain"] == "t.ly"
    published = {d["domain"] for d in client.get("/api/dns-blocklist?min_score=0").json()["domains"]}
    assert "uaepass-login-secure.top" in published
    assert not published & {"cutt.ly", "t.ly", "bit.ly", "tinyurl.com", "rb.gy", "google.com", "www.google.com"}


# --- cloaking without a browser --------------------------------------------------------
PAY_FORM = ('<html><head><title>TAMM Pay</title></head><body><h1>Pay your fine</h1><form action="/p">'
            '<input name="cardnumber"><input name="cvv"><input name="otp"></form></body></html>')


@pytest.fixture
def http_only():
    saved = {n: getattr(settings, n) for n in ("offline_mode", "sandbox_enabled")}
    object.__setattr__(settings, "offline_mode", False)  # Settings is a frozen dataclass
    object.__setattr__(settings, "sandbox_enabled", False)
    yield sandbox_mod.Sandbox()
    for name, value in saved.items():
        object.__setattr__(settings, name, value)


def cloak_site(monkeypatch, bot_response: httpx.Response, visitor_html: str) -> list[dict]:
    seen: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append({"ua": request.headers["user-agent"], "referer": request.headers.get("referer")})
        if "iPhone" in request.headers["user-agent"]:
            return httpx.Response(200, headers=HTML, text=visitor_html)
        return bot_response

    monkeypatch.setattr(sandbox_mod, "TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(sandbox_mod, "host_is_safe_target", fake_guard)
    return seen


def test_http_only_cloaking_is_detected(http_only, monkeypatch):
    decoy = httpx.Response(200, headers=HTML, text="<html><head><title>Under Construction</title></head>"
                                                   "<body>Coming soon</body></html>")
    seen = cloak_site(monkeypatch, decoy, PAY_FORM)
    page = asyncio.run(http_only.inspect("https://pay.example/", "pay.example"))
    assert page["cloaking"]["detected"] is True and page["cloaking"]["naive_title"] == "Under Construction"
    assert page["page_title"] == "TAMM Pay" and {"CARD_NUMBER", "CVV", "OTP"} <= set(page["harvested_fields"])
    assert {(s["ua"] == sandbox_mod.BOT_USER_AGENT, s["referer"]) for s in seen} == {
        (True, None), (False, "https://www.google.com/")}


def test_http_only_same_page_for_everyone_is_not_cloaking(http_only, monkeypatch):
    cloak_site(monkeypatch, httpx.Response(200, headers=HTML, text=PAY_FORM), PAY_FORM)
    page = asyncio.run(http_only.inspect("https://pay.example/", "pay.example"))
    assert page["cloaking"]["detected"] is False and "CVV" in page["harvested_fields"]


def test_http_only_403_to_bots_is_not_cloaking(http_only, monkeypatch):
    article = "<html><head><title>Gulf Daily</title></head><body>" + "<p>Today's headlines.</p>" * 30 + "</body></html>"
    cloak_site(monkeypatch, httpx.Response(403, headers=HTML, text="Forbidden"), article)
    page = asyncio.run(http_only.inspect("https://news.example/", "news.example"))
    assert page["status"] == "ok" and page["http_status"] == 200
    assert page["cloaking"]["detected"] is False and page["cloaking"]["naive_status"] == 403


def test_http_only_falls_back_to_the_bot_view_when_the_visitor_fetch_fails(http_only, monkeypatch):
    def handler(request: httpx.Request) -> httpx.Response:
        if "iPhone" in request.headers["user-agent"]:
            raise httpx.ConnectError("reset", request=request)
        return httpx.Response(200, headers=HTML, text=PAY_FORM)

    monkeypatch.setattr(sandbox_mod, "TRANSPORT", httpx.MockTransport(handler))
    monkeypatch.setattr(sandbox_mod, "host_is_safe_target", fake_guard)
    page = asyncio.run(http_only.inspect("https://pay.example/", "pay.example"))
    assert page["status"] == "ok" and page["cloaking"]["detected"] is False
