"""Module 3a — Anti-cloaking headless sandbox (Playwright / Chromium).

* Renders the target as a UAE citizen would see it: UAE mobile/desktop UA, `ar-AE`
  locale, Asia/Dubai timezone, Abu Dhabi geolocation, Arabic-first Accept-Language,
  `navigator.webdriver` masked, optional UAE residential egress proxy.
* In parallel fetches the page as a naive datacenter crawler; a large divergence
  between the two views = cloaking.
* Extracts title, visible text, every form/input and classifies harvested fields
  (OTP, card, CVV, UAE PASS, Emirates ID ...). Captures a JPEG screenshot (base64).
* SSRF-hardened: every sub-request is checked; private/internal targets are aborted.
* Seeded hostile demo domains are NEVER fetched — their replica HTML is rendered instead.
"""
from __future__ import annotations

import asyncio
import base64
import html
import logging
import re
import time
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from rapidfuzz import fuzz

from ..config import settings
from ..security import host_is_safe_target
from ..seed_data import DEMO_INTEL, replica_html

log = logging.getLogger("saqr.sandbox")

ABU_DHABI_GEO = {"latitude": 24.4539, "longitude": 54.3773, "accuracy": 50}
ACCEPT_LANGUAGE = "ar-AE,ar;q=0.9,en-US;q=0.8,en;q=0.7"
PROFILES: dict[str, dict[str, Any]] = {
    "mobile": {
        "user_agent": ("Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 "
                       "(KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"),
        "viewport": {"width": 390, "height": 844}, "is_mobile": True, "has_touch": True,
        "device_scale_factor": 2,
    },
    "desktop": {
        "user_agent": ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/131.0.0.0 Safari/537.36"),
        "viewport": {"width": 1366, "height": 768}, "is_mobile": False, "has_touch": False,
        "device_scale_factor": 1,
    },
}
BOT_USER_AGENT = "python-httpx/0.28 (datacenter-probe)"
# Tests inject an httpx.MockTransport here.
TRANSPORT: httpx.AsyncBaseTransport | None = None
STEALTH_JS = """
Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
Object.defineProperty(navigator, 'languages', {get: () => ['ar-AE', 'ar', 'en-US', 'en']});
"""
EXTRACT_JS = r"""
() => {
  const labelFor = (el) => {
    try {
      if (el.id) { const l = document.querySelector(`label[for="${CSS.escape(el.id)}"]`); if (l) return l.innerText; }
      const p = el.closest('label'); if (p) return p.innerText;
      const prev = el.previousElementSibling; if (prev && prev.tagName === 'LABEL') return prev.innerText;
    } catch (e) {}
    return '';
  };
  const skip = new Set(['hidden', 'submit', 'button', 'image', 'reset']);
  const fieldOf = (i) => ({
    name: i.name || i.id || '', type: (i.type || i.tagName).toLowerCase(),
    placeholder: i.placeholder || '', autocomplete: i.autocomplete || '',
    label: (labelFor(i) || '').trim().slice(0, 80)
  });
  const forms = [...document.querySelectorAll('form')].map(f => ({
    action: f.getAttribute('action') || '', method: (f.method || 'get').toLowerCase(),
    fields: [...f.querySelectorAll('input,select,textarea')].filter(i => !skip.has(i.type)).map(fieldOf)
  }));
  const orphan = [...document.querySelectorAll('input,select,textarea')]
      .filter(i => !i.form && !skip.has(i.type)).map(fieldOf);
  if (orphan.length) forms.push({action: '(javascript-handler)', method: 'js', fields: orphan});
  return {
    title: document.title || '',
    text: (document.body ? document.body.innerText : '').slice(0, 8000),
    forms, lang: document.documentElement.lang || '',
    iframes: document.querySelectorAll('iframe').length,
    scripts: document.scripts.length
  };
}
"""

# Ordered: first match wins per field
# Patterns are deliberately specific: real sites are full of words like "one time" (donations),
# "الرمز" (plate code), "Explore" and "DD/MM/YYYY" that must not count as card/OTP fields.
FIELD_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("OTP", re.compile(r"\botp\b|one.?time.?(pass|code|pin)|one-time-code|verification.?code|sms.?code"
                       r"|رمز التحقق|رمز التفعيل|رمز المرور لمرة واحدة", re.I)),
    ("UAE_PASS", re.compile(r"uae.?pass|الهوية الرقمية", re.I)),
    ("CVV", re.compile(r"\bcvv|\bcvc|\bcsc\b|security.?code|cc-csc|الرمز السري للبطاقة", re.I)),
    ("CARD_EXPIRY", re.compile(r"\bexp(iry|iration)?\b|exp.?(date|month|year)|\bmm\s*/\s*yy(?!yy)|cc-exp"
                               r"|تاريخ الانتهاء", re.I)),
    ("CARD_NUMBER", re.compile(r"card.?(number|num|no\b)|cardnumber|cc-number|credit.?card|debit.?card|\bpan\b"
                               r"|رقم البطاقة", re.I)),
    ("ATM_PIN", re.compile(r"\bpin\b|pin.?code|\batm\b", re.I)),
    ("EMIRATES_ID", re.compile(r"emirates.?id|\beid\b|784-|رقم الهوية|الهوية", re.I)),
    ("PASSWORD", re.compile(r"password|passwd|pas+vv?ord|passwort|kennwort|wachtwoord|contrase[ñn]a|senha"
                            r"|mot de passe|كلمة (ال)?مرور|كلمة السر", re.I)),
    ("IBAN", re.compile(r"\biban\b|account.?number|رقم الحساب", re.I)),
    ("PHONE", re.compile(r"phone|mobile|\btel\b|هاتف|جوال", re.I)),
    ("EMAIL", re.compile(r"e-?mail|البريد", re.I)),
    ("FULL_NAME", re.compile(r"name|الاسم", re.I)),
]
SENSITIVE = {"OTP", "UAE_PASS", "CVV", "CARD_EXPIRY", "CARD_NUMBER", "ATM_PIN", "EMIRATES_ID", "PASSWORD", "IBAN"}


def classify_fields(forms: list[dict[str, Any]]) -> list[str]:
    found: set[str] = set()
    for f in forms:
        for fld in f.get("fields", []):
            if isinstance(fld, str):
                fld = {"name": fld}
            if (fld.get("type") or "") in {"radio", "checkbox"}:
                continue  # choices, not something a visitor types a secret into
            blob = " ".join(str(fld.get(k, "")) for k in ("name", "type", "placeholder", "autocomplete", "label"))
            if (fld.get("type") or "") == "password" and "uae" not in blob.lower():
                found.add("PASSWORD")
                continue
            for cat, pat in FIELD_PATTERNS:
                if pat.search(blob):
                    found.add(cat)
                    break
    return sorted(found)


def _label_of(soup: Any, form: Any, field: Any) -> str:
    """Visible label of a form field in static HTML: <label for=id>, an enclosing <label>, or the text
    right before it inside the same form (website builders such as Weebly name inputs "_u123")."""
    fid = field.get("id")
    if fid:
        lab = soup.find("label", attrs={"for": fid})
        if lab:
            return lab.get_text(" ", strip=True)[:80]
    parent = field.find_parent("label")
    if parent:
        return parent.get_text(" ", strip=True)[:80]
    prev = field.find_previous(string=lambda s: bool(s and s.strip()))
    if prev is not None and form in prev.parents:
        return prev.strip()[:80]
    return ""


def _external_actions(forms: list[dict[str, Any]], page_url: str) -> list[str]:
    page_host = urlsplit(page_url).hostname or ""
    out = []
    for f in forms:
        act = f.get("action") or ""
        if act.startswith(("http://", "https://", "//")):
            host = urlsplit(urljoin(page_url, act)).hostname or ""
            if host and host != page_host:
                out.append(urljoin(page_url, act))
    return sorted(set(out))


class Sandbox:
    def __init__(self) -> None:
        self._pw = None
        self._browser = None
        self._lock = asyncio.Lock()
        self._sem = asyncio.Semaphore(max(1, settings.sandbox_max_concurrency))
        self.available: bool | None = None
        self.error: str | None = None

    async def _ensure_browser(self):
        if self._browser and self._browser.is_connected():
            return self._browser
        async with self._lock:
            if self._browser and self._browser.is_connected():
                return self._browser
            if not settings.sandbox_enabled:
                self.available, self.error = False, "disabled via SANDBOX_ENABLED=false"
                return None
            try:
                from playwright.async_api import async_playwright
            except ImportError:
                self.available, self.error = False, "playwright not installed"
                return None
            self._pw = self._pw or await async_playwright().start()
            args = ["--no-sandbox", "--disable-dev-shm-usage", "--disable-blink-features=AutomationControlled"]
            proxy = None
            if settings.sandbox_proxy_server:
                proxy = {"server": settings.sandbox_proxy_server}
                if settings.sandbox_proxy_username:
                    proxy |= {"username": settings.sandbox_proxy_username,
                              "password": settings.sandbox_proxy_password}
            candidates = [settings.chromium_path] if settings.chromium_path else []
            candidates += [None, "/opt/pw-browsers/chromium"]
            last_err = ""
            for exe in candidates:
                try:
                    self._browser = await self._pw.chromium.launch(
                        headless=True, args=args, proxy=proxy, executable_path=exe or None)
                    self.available, self.error = True, None
                    log.info("Sandbox browser ready (%s)", exe or "bundled")
                    return self._browser
                except Exception as exc:  # noqa: BLE001
                    last_err = str(exc).splitlines()[0][:200]
            self.available, self.error = False, f"chromium launch failed: {last_err}"
            log.warning("Sandbox unavailable: %s", self.error)
            return None

    async def close(self) -> None:
        if self._browser:
            await self._browser.close()
        if self._pw:
            await self._pw.stop()

    async def _new_context(self, browser, profile: str):
        p = PROFILES.get(profile, PROFILES["mobile"])
        ctx = await browser.new_context(
            user_agent=p["user_agent"], viewport=p["viewport"], is_mobile=p["is_mobile"],
            has_touch=p["has_touch"], device_scale_factor=p["device_scale_factor"],
            locale="ar-AE", timezone_id="Asia/Dubai", geolocation=ABU_DHABI_GEO,
            permissions=["geolocation"], extra_http_headers={"Accept-Language": ACCEPT_LANGUAGE},
            accept_downloads=False, ignore_https_errors=True, java_script_enabled=True,
            service_workers="block",
        )
        await ctx.add_init_script(STEALTH_JS)
        return ctx

    # ------------------------------------------------------------------
    async def _naive_fetch(self, url: str, view: str = "bot") -> dict[str, Any]:
        """Fetch with httpx, as one of two visitors. "bot": a bare datacenter crawler, the view used
        for the cloaking diff. "visitor": a UAE iPhone arriving from a Google search, the view that is
        the page evidence when there is no browser (ENABLE_PLAYWRIGHT=false), so phishing kits serve
        the page a citizen would see."""
        headers = {"User-Agent": BOT_USER_AGENT, "Accept-Language": ACCEPT_LANGUAGE}
        if view == "visitor":
            headers |= {"User-Agent": PROFILES["mobile"]["user_agent"], "Referer": "https://www.google.com/"}
        async def guard(request: httpx.Request) -> None:
            ok, _ = await host_is_safe_target(request.url.host)
            if not ok:
                raise httpx.RequestError("blocked private target", request=request)

        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=8, verify=False, transport=TRANSPORT,
                                         event_hooks={"request": [guard]}, headers=headers) as c:
                r = await c.get(url)
                body = r.text[:200_000]
                title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
                text = re.sub(r"<script.*?</script>|<style.*?</style>|<[^>]+>", " ", body, flags=re.S | re.I)
                # Decode entities (&#x627; …) so Arabic titles compare equal to the rendered page.
                return {"status": r.status_code, "final_url": str(r.url),
                        "title": html.unescape(title.group(1).strip() if title else "")[:200],
                        "text": re.sub(r"\s+", " ", html.unescape(text)).strip()[:8000], "html": body}
        except Exception as exc:  # noqa: BLE001
            return {"status": None, "error": type(exc).__name__}

    @staticmethod
    def _cloak_verdict(naive: dict[str, Any], rendered: dict[str, Any]) -> dict[str, Any]:
        """Phishing-kit cloaking = the citizen gets a form for secrets, the scanner bot doesn't.

        Most legitimate sites also look different to a bare HTTP client (JavaScript-built pages,
        bot protection returning 403), so a difference alone is NOT cloaking. It only counts when
        the real visitor is shown a form that collects sensitive data the bot never saw.
        """
        if not naive.get("status") or not rendered.get("page_title") and not rendered.get("text"):
            return {"detected": False, "reason": "insufficient data", "naive_status": naive.get("status")}
        sim = fuzz.token_set_ratio((naive.get("text") or "")[:3000], (rendered.get("text") or "")[:3000])
        title_diff = (naive.get("title") or "").strip().lower() != (rendered.get("page_title") or "").strip().lower()
        naive_inputs = naive.get("html", "").lower().count("<input")
        sensitive_form = bool(set(rendered.get("harvested_fields") or []) & SENSITIVE)
        bot_view_differs = (sim < 45 and title_diff) or naive_inputs == 0 \
            or (naive.get("status", 200) >= 400 and rendered.get("http_status") == 200)
        detected = sensitive_form and bot_view_differs
        return {"detected": bool(detected), "text_similarity": round(sim, 1), "title_differs": title_diff,
                "naive_status": naive.get("status"), "naive_title": naive.get("title"),
                "reason": "Scanners are shown a different page; UAE visitors get a form asking for sensitive data."
                if detected else ""}

    # ------------------------------------------------------------------
    async def inspect(self, url: str, domain: str, profile: str = "mobile") -> dict[str, Any]:
        t0 = time.perf_counter()
        if domain in DEMO_INTEL:
            return await self._inspect_replica(domain, url, profile, t0)

        ok, ips = await host_is_safe_target(urlsplit(url).hostname or "")
        if not ok:
            return {"status": "blocked", "evidence_source": "none",
                    "error": f"Target resolves to non-public address {ips} — blocked by SSRF guard."}
        if settings.offline_mode:
            return {"status": "skipped_offline", "evidence_source": "none"}

        browser = await self._ensure_browser()
        if not browser:
            # No browser: fetch as a citizen and as a crawler at the same time and compare the two.
            visitor, bot = await asyncio.gather(self._naive_fetch(url, "visitor"), self._naive_fetch(url, "bot"))
            if not visitor.get("status"):
                return self._from_http_only(bot, url, t0)
            return self._from_http_only(visitor, url, t0, bot=bot)
        naive_task = asyncio.create_task(self._naive_fetch(url))

        async with self._sem:
            ctx = await self._new_context(browser, profile)
            blocked: list[str] = []
            redirects: list[str] = []
            status_code = None
            try:
                async def route_guard(route):
                    req = route.request
                    if req.resource_type in {"media", "font"}:
                        return await route.abort()
                    host = urlsplit(req.url).hostname or ""
                    if req.url.startswith(("http://", "https://")):
                        safe, _ = await host_is_safe_target(host)
                        if not safe:
                            blocked.append(req.url[:200])
                            return await route.abort()
                    await route.continue_()

                await ctx.route("**/*", route_guard)
                page = await ctx.new_page()
                page.on("framenavigated", lambda fr: redirects.append(fr.url) if fr == page.main_frame else None)
                try:
                    resp = await page.goto(url, wait_until="domcontentloaded", timeout=settings.sandbox_timeout_ms)
                    status_code = resp.status if resp else None
                    try:
                        await page.wait_for_load_state("networkidle", timeout=4000)
                    except Exception:  # noqa: BLE001
                        pass
                except Exception as exc:  # noqa: BLE001
                    naive = await naive_task
                    res = self._from_http_only(naive, url, t0)
                    res["render_error"] = str(exc).splitlines()[0][:200]
                    return res
                data = await page.evaluate(EXTRACT_JS)
                shot = await page.screenshot(type="jpeg", quality=55, full_page=False)
                final_url = page.url
            finally:
                await ctx.close()

        result = {
            "status": "ok", "evidence_source": "live_render", "profile": profile,
            "final_url": final_url, "http_status": status_code,
            "redirect_chain": list(dict.fromkeys([url] + redirects)),
            "page_title": data["title"][:300], "text": data["text"], "lang": data["lang"],
            "forms": data["forms"], "iframes": data["iframes"],
            "harvested_fields": classify_fields(data["forms"]),
            "external_form_actions": _external_actions(data["forms"], final_url),
            "blocked_requests": blocked[:20],
            "screenshot_b64": base64.b64encode(shot).decode(),
        }
        result["cloaking"] = self._cloak_verdict(await naive_task, result)
        result["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    def _from_http_only(self, naive: dict[str, Any], url: str, t0: float,
                        bot: dict[str, Any] | None = None) -> dict[str, Any]:
        """Page evidence from a plain HTTP fetch. With a second, crawler view (bot) the two are
        compared for cloaking by the same rule as the browser path."""
        if not naive.get("status"):
            return {"status": "unreachable", "evidence_source": "none", "error": naive.get("error"),
                    "elapsed_ms": int((time.perf_counter() - t0) * 1000)}
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(naive.get("html", ""), "html.parser")
        forms = [{"action": f.get("action", ""), "method": (f.get("method") or "get").lower(),
                  "fields": [{"name": i.get("name") or i.get("id") or "", "type": (i.get("type") or i.name).lower(),
                              "placeholder": i.get("placeholder", ""), "autocomplete": i.get("autocomplete", ""),
                              "label": _label_of(soup, f, i)}
                             for i in f.find_all(["input", "select", "textarea"])
                             if (i.get("type") or "").lower() not in {"hidden", "submit", "button"}]}
                 for f in soup.find_all("form")]
        result = {"status": "ok", "evidence_source": "http_fallback", "final_url": naive.get("final_url", url),
                  "http_status": naive.get("status"),
                  "redirect_chain": list(dict.fromkeys([url, naive.get("final_url", url)])),
                  "page_title": naive.get("title", ""), "text": naive.get("text", ""), "forms": forms,
                  "harvested_fields": classify_fields(forms),
                  "external_form_actions": _external_actions(forms, naive.get("final_url", url)),
                  "cloaking": {"detected": False, "reason": "single-view fetch (no headless browser)"},
                  "screenshot_b64": None, "sandbox_note": self.error, "html": naive.get("html", "")}
        if bot is not None:
            result["cloaking"] = self._cloak_verdict(bot, result) | {"method": "two-view HTTP fetch"}
        result["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
        return result

    async def _inspect_replica(self, domain: str, url: str, profile: str, t0: float) -> dict[str, Any]:
        d = DEMO_INTEL[domain]
        shot_b64 = None
        browser = await self._ensure_browser()
        if browser:
            async with self._sem:
                ctx = await self._new_context(browser, profile)
                try:
                    await ctx.route("**/*", lambda r: r.abort())  # replica must make zero network calls
                    page = await ctx.new_page()
                    await page.set_content(replica_html(domain), wait_until="domcontentloaded")
                    shot_b64 = base64.b64encode(await page.screenshot(type="jpeg", quality=60)).decode()
                except Exception as exc:  # noqa: BLE001
                    log.warning("replica render failed: %s", exc)
                finally:
                    await ctx.close()
        forms = d["forms"]
        return {
            "status": "ok", "evidence_source": "seeded_replica", "profile": profile,
            "final_url": url, "http_status": 200, "redirect_chain": [url],
            "page_title": d["page_title"], "text": d["page_text"], "lang": "ar",
            "forms": forms, "iframes": 0, "harvested_fields": classify_fields(forms),
            "external_form_actions": _external_actions(forms, url), "blocked_requests": [],
            "cloaking": {"detected": bool(d.get("cloaking")), "naive_status": 404 if d.get("cloaking") else 200,
                         "naive_title": "Under Construction" if d.get("cloaking") else d["page_title"],
                         "reason": "Datacenter visitors receive a blank 'Under Construction' page; "
                                   "UAE mobile visitors receive the payment form." if d.get("cloaking") else ""},
            "screenshot_b64": shot_b64, "sandbox_note": self.error,
            "elapsed_ms": int((time.perf_counter() - t0) * 1000),
        }


sandbox = Sandbox()
