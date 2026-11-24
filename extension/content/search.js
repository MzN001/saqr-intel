// Saqr | Search & Maps shield — content script for Google Search (google.com, google.ae and other
// country domains), Bing and Google Maps place panels.
//
// Before the user clicks anything it collects the organic result links, the SPONSORED ads (Google /
// Bing ad-click wrappers resolved to the advertiser's address from the DOM), the website button of a
// Maps place panel, and the phone numbers shown in ads, knowledge panels and Maps cards. They go to
// background.js (message types searchSettings / searchVerdicts / checkPhones only), which asks
// POST /api/batch-verdict and POST /api/check-phone. Each result then gets a small badge:
//   red    "Saqr: scam — imitates TAMM" (reasons on hover); the link is locked until the user confirms
//   amber  suspicious
//   green  ONLY for verified official UAE websites / numbers
//   nothing for ordinary sites (no noise).
// Google and Bing change their markup often: known selectors first, then a heuristic fallback (any
// link inside the results area). textContent only, never innerHTML; nothing is passed to the page's
// own JavaScript.

(function (root, factory) {
  const api = factory(root, root.SaqrSearchCore);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrSearch = api;
  if (typeof document !== "undefined" && document.documentElement && typeof chrome !== "undefined" &&
      chrome.runtime && chrome.runtime.id && !root.__saqrSearchStarted) {
    root.__saqrSearchStarted = true;
    api.start();
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function (root, C) {
  "use strict";

  const DEBOUNCE_MS = 450;
  const MAX_URLS_PER_PASS = 120;
  const MAX_PHONES_PER_PASS = 12;
  const MAX_RETRIES = 3;
  const LEVEL_RANK = { official: 1, warn: 2, danger: 3 };
  const GLYPH = { danger: "⛔ ", warn: "⚠ ", official: "✓ " };

  const SEL = {
    google: {
      areas: "#search, #rso, #center_col, #botstuff, #tads, #tadsb, #bottomads, #rhs",
      adAreas: "#tads, #tadsb, #bottomads",
      adBlocks: "[data-text-ad], #tads [data-ta-slot], #tadsb [data-ta-slot], #bottomads [data-ta-slot]",
      organic: "#rso a[href], #botstuff a[href]",
      panel: "#rhs",
      panelTitle: "[data-attrid='title'], [role='heading'], h2",
      block: "[data-text-ad], div.g, div.MjjYud, [data-hveid], li",
    },
    bing: {
      areas: "#b_results, #b_context",
      adAreas: "#b_results .b_ad, .b_adTop, .b_adBottom",
      adBlocks: ".b_ad li, .b_adTop li, .b_adBottom li",
      organic: "#b_results li.b_algo h2 a",
      panel: "#b_context",
      panelTitle: "h2, .b_entityTitle",
      block: "li.b_algo, .b_ad li, li",
    },
  };

  const qsa = (n, s) => {
    try {
      return n ? Array.from(n.querySelectorAll(s)) : [];
    } catch {
      return [];
    }
  };
  const qs = (n, s) => qsa(n, s)[0] || null;
  const text = (n) => String((n && n.textContent) || "").replace(/\s+/g, " ").trim();
  const closest = (n, s) => {
    try {
      return n && n.closest ? n.closest(s) : null;
    } catch {
      return null;
    }
  };

  function hostOf(url) {
    try {
      return new URL(url).hostname.toLowerCase();
    } catch {
      return "";
    }
  }

  // ------------------------------------------------------------------------------------- collect
  /** Links worth a badge: [{anchor, url, kind: ad|organic|result|panel|maps, block, quiet}]. */
  function collectLinks(doc, site) {
    const items = [];
    const seen = new Set();
    const push = (a, kind, block, { quiet = false, fallbackUrl = null } = {}) => {
      if (!a || seen.has(a)) return;
      const href = String(a.getAttribute("href") || "").trim();
      if (!href || /^(?:#|javascript:|tel:|mailto:|data:)/i.test(href)) return;
      const url = C.resolveHref(href, (k) => a.getAttribute(k)) || (kind === "ad" ? fallbackUrl : null);
      const host = hostOf(url);
      if (!host || C.isEngineHost(host)) return;
      seen.add(a);
      items.push({ anchor: a, url, kind, block: block || a, quiet });
    };

    if (site === "maps") {
      const main = qs(doc, "div[role='main']") || doc;
      for (const a of qsa(main, "a[data-item-id='authority'], a[data-item-id^='authority']")) push(a, "maps", a);
      for (const a of qsa(main, "a[href]")) {
        if (/website|web site|الموقع/i.test(a.getAttribute("aria-label") || "")) push(a, "maps", a);
      }
      return items;
    }
    const S = SEL[site];
    if (!S) return items;

    // 1) Sponsored ads: one block per ad; every link in it goes to the advertiser.
    for (const block of adBlocks(doc, site)) {
      const display = C.parseDisplayUrl(text(qs(block, "cite, [data-dtld], .b_adurl, .b_attribution")));
      for (const a of qsa(block, "a[href]")) push(a, "ad", block, { quiet: true, fallbackUrl: display });
    }
    // 2) Organic results (title links).
    for (const a of qsa(doc, S.organic)) {
      if (site === "google" && !qs(a, "h3")) continue;
      push(a, "organic", closest(a, S.block) || a);
    }
    // 3) Knowledge / entity panel: only its "Website" button may earn a green tick.
    for (const a of qsa(qs(doc, S.panel), "a[href]")) {
      const label = (a.getAttribute("aria-label") || "") + " " + text(a);
      push(a, "panel", closest(a, "[data-attrid]") || a, { quiet: !/website|web site|الموقع/i.test(label) });
    }
    // 4) Fallback: any other link in the results area (the markup changed): red / amber only.
    const adArea = qsa(doc, S.adAreas);
    for (const area of qsa(doc, S.areas)) {
      for (const a of qsa(area, "a[href]")) {
        const ad = adArea.find((x) => x.contains(a));
        if (ad) push(a, "ad", closest(a, S.block) || ad, { quiet: true });
        else push(a, "result", closest(a, S.block) || a, { quiet: true });
      }
    }
    return items;
  }

  function adBlocks(doc, site) {
    const S = SEL[site];
    if (!S) return [];
    const blocks = qsa(doc, S.adBlocks).filter((b, i, all) => !all.some((o) => o !== b && o.contains(b)));
    if (blocks.length) return blocks;
    // Fallback: each direct child of an ad area that holds a link.
    return qsa(doc, S.adAreas).flatMap((area) => (area.children || []).filter((c) => qs(c, "a[href]")));
  }

  function adClaim(block) {
    const head = text(qs(block, "[role='heading'], h3, h2")) || text(qs(block, "a[href]"));
    const who = text(qs(block, "[data-dtld], .b_adurl, cite"));
    return (head + " " + who).trim().slice(0, 200);
  }

  /** The deepest element in block whose text contains s (where a free-text phone badge goes). */
  function deepestWith(block, s) {
    let best = block;
    for (const e of qsa(block, "*")) if (text(e).includes(s)) best = e;
    return best;
  }

  /** Phones next to an institution's name: [{node, phone, claim, context: ad|panel|maps}]. */
  function collectPhones(doc, site) {
    const out = [];
    const seen = new Set();
    const add = (node, phone, claim, context) => {
      if (!node || !phone) return;
      const key = C.digits(phone) + "|" + claim + "|" + context;
      if (C.digits(phone).length < 3 || seen.has(key)) return;
      seen.add(key);
      out.push({ node, phone, claim: claim || null, context });
    };
    /** Phone fields (tel: links, Maps phone buttons, ad call extensions); returns how many were seen. */
    const fromFields = (scope, claim, context) => {
      let n = 0;
      for (const b of qsa(scope, "[data-item-id^='phone:tel:']")) {
        add(b, C.phoneFromTel(b.getAttribute("data-item-id")), claim, context);
        n++;
      }
      for (const a of qsa(scope, "a[href^='tel:']")) {
        add(a, C.phoneFromTel(a.getAttribute("href")), claim, context);
        n++;
      }
      for (const f of qsa(scope, "[data-dtype='d3ph'], [data-attrid*='phone']")) {
        for (const p of C.findPhones(text(f), true)) {
          add(deepestWith(f, p), p, claim, context);
          n++;
        }
      }
      return n;
    };

    if (site === "maps") {
      const main = qs(doc, "div[role='main']") || doc;
      const claim = text(qs(main, "h1")).slice(0, 200);
      if (!fromFields(main, claim, "maps")) {
        for (const b of qsa(main, "button[aria-label], [data-tooltip]")) {
          const label = b.getAttribute("aria-label") || b.getAttribute("data-tooltip") || "";
          if (/phone|call|هاتف|اتصال/i.test(label)) for (const p of C.findPhones(label + " " + text(b), true)) add(b, p, claim, "maps");
        }
      }
      return out;
    }
    const S = SEL[site];
    if (!S) return out;
    for (const block of adBlocks(doc, site)) {
      const claim = adClaim(block);
      fromFields(block, claim, "ad");
      for (const p of C.findPhones(text(block))) add(deepestWith(block, p), p, claim, "ad");
    }
    const panel = qs(doc, S.panel);
    if (panel) {
      const claim = text(qs(panel, S.panelTitle)).slice(0, 200);
      if (claim) {
        fromFields(panel, claim, "panel");
        for (const p of C.findPhones(text(panel))) add(deepestWith(panel, p), p, claim, "panel");
      }
    }
    return out;
  }

  // ------------------------------------------------------------------------------------- render
  function makeBadge(doc, d, lang) {
    const b = doc.createElement("span");
    b.setAttribute("class", "saqr-sb-badge");
    b.setAttribute("data-saqr-level", d.level);
    b.setAttribute("role", "note");
    b.setAttribute("lang", lang);
    b.setAttribute("dir", lang === "ar" ? "rtl" : "ltr");
    fillBadge(b, d);
    return b;
  }

  function fillBadge(b, d) {
    b.setAttribute("data-saqr-level", d.level);
    b.setAttribute("title", d.tip);
    b.setAttribute("aria-label", d.label);
    b.textContent = (GLYPH[d.level] || "") + d.label;
  }

  function createShield({ doc, site, send, lang, navigate }) {
    const state = {
      links: new Map(), // url -> compact verdict | null
      phones: new Map(), // key -> compact phone check | null
      badges: new WeakMap(), // block / phone node -> badge element
      locked: new WeakMap(), // anchor -> {url, domain, decision, verdict}
      guard: null,
      failures: 0,
      busy: false,
      again: false,
      timer: null,
    };
    const L = () => (typeof lang === "function" ? lang() : lang) || "en";
    const siteNow = () => (typeof site === "function" ? site() : site);

    function place(anchorOrNode, owner, d, where) {
      const old = state.badges.get(owner);
      if (old && old.parentNode) {
        fillBadge(old, d);
        return old;
      }
      const b = makeBadge(doc, d, L());
      anchorOrNode.insertAdjacentElement(where, b);
      state.badges.set(owner, b);
      return b;
    }

    function lock(a, it, d, v) {
      a.setAttribute("data-saqr-inert", "1");
      a.setAttribute("aria-disabled", "true");
      state.locked.set(a, { url: it.url, domain: v.domain || hostOf(it.url), decision: d, verdict: v });
    }

    function renderLinks(items) {
      const groups = new Map();
      for (const it of items) {
        if (!state.links.has(it.url)) continue;
        const v = state.links.get(it.url);
        const d = C.decideLink(v, L(), { quiet: it.quiet });
        if (d && d.inert) lock(it.anchor, it, d, v);
        const g = groups.get(it.block) || { first: it, best: null };
        if (d && (!g.best || LEVEL_RANK[d.level] > LEVEL_RANK[g.best.level])) g.best = d;
        groups.set(it.block, g);
      }
      let n = 0;
      for (const [block, g] of groups) {
        if (!g.best) continue;
        place(g.first.anchor, block, g.best, "beforebegin");
        n++;
      }
      return n;
    }

    function phoneKey(p) {
      return C.digits(p.phone) + "|" + (p.claim || "") + "|" + p.context;
    }

    function renderPhones(phones) {
      let n = 0;
      for (const p of phones) {
        const r = state.phones.get(phoneKey(p));
        const d = C.decidePhone(r, L());
        if (!d) continue;
        place(p.node, p.node, d, "afterend");
        n++;
      }
      return n;
    }

    async function pass() {
      const s = siteNow();
      if (!s) return { links: 0, phones: 0 };
      const items = collectLinks(doc, s);
      const phones = collectPhones(doc, s);
      const urls = [...new Set(items.map((i) => i.url))].filter((u) => !state.links.has(u)).slice(0, MAX_URLS_PER_PASS);
      const wanted = phones.filter((p) => !state.phones.has(phoneKey(p))).slice(0, MAX_PHONES_PER_PASS);
      for (const u of urls) state.links.set(u, undefined);
      for (const p of wanted) state.phones.set(phoneKey(p), undefined);
      const [lr, pr] = await Promise.all([
        urls.length ? send({ type: "searchVerdicts", urls }) : null,
        wanted.length ? send({ type: "checkPhones", items: wanted.map((p) => ({ phone: p.phone, claimed_entity: p.claim, context: p.context })) }) : null,
      ]);
      // A failed lookup (backend asleep / offline) is forgotten, so a later pass asks again (a few times).
      const retry = state.failures < MAX_RETRIES;
      if (urls.length && !(lr && lr.ok)) state.failures++;
      if (wanted.length && !(pr && pr.ok)) state.failures++;
      for (const u of urls) {
        if (lr && lr.ok) state.links.set(u, (lr.results && lr.results[u]) || null);
        else if (retry) state.links.delete(u);
        else state.links.set(u, null);
      }
      wanted.forEach((p, i) => {
        if (pr && pr.ok) state.phones.set(phoneKey(p), (pr.results && pr.results[i]) || null);
        else if (retry) state.phones.delete(phoneKey(p));
        else state.phones.set(phoneKey(p), null);
      });
      return { links: renderLinks(items), phones: renderPhones(phones) };
    }

    async function run() {
      if (state.busy) {
        state.again = true;
        return;
      }
      state.busy = true;
      try {
        do {
          state.again = false;
          await pass();
        } while (state.again);
      } catch (err) {
        console.debug("[SAQR] search shield pass failed", err);
      } finally {
        state.busy = false;
      }
    }

    function schedule() {
      clearTimeout(state.timer);
      state.timer = setTimeout(run, DEBOUNCE_MS);
    }

    // -- locked links: ask before opening -----------------------------------------------------
    function onActivate(e) {
      if (e.type === "keydown" && e.key !== "Enter") return;
      if (e.type === "auxclick" && e.button !== 1) return;
      const a = closest(e.target, "a[data-saqr-inert]");
      const info = a && state.locked.get(a);
      if (!info) return;
      e.preventDefault();
      e.stopImmediatePropagation();
      showGuard(a, info);
    }

    function el(tag, props = {}, kids = [], label = null) {
      const n = doc.createElement(tag);
      for (const [k, v] of Object.entries(props)) n.setAttribute(k, v);
      for (const k of kids) if (k) n.appendChild(k);
      if (label != null) n.textContent = label;
      return n;
    }

    function closeGuard() {
      if (state.guard) state.guard.remove();
      state.guard = null;
    }

    function showGuard(a, info) {
      closeGuard();
      const lg = L();
      const v = info.verdict || {};
      const host = doc.createElement("saqr-search-guard");
      const shadow = typeof host.attachShadow === "function" ? host.attachShadow({ mode: "closed" }) : host;
      const style = doc.createElement("style");
      style.textContent = GUARD_CSS;
      const domains = (v.entity && v.entity.officialDomains) || [];
      const title = el("h2", {}, [], C.t("gTitle", lg));
      const body = el("p", {}, [], C.t("gBody", lg, info.domain));
      const list = el("ul", {}, (v.reasons || []).slice(0, 4).map((r) => el("li", {}, [], lg === "ar" ? r.ar || r.en : r.en || r.ar)));
      const official = domains.length ? el("p", { class: "official" }, [], C.t("tipOfficial", lg, domains.join(", "))) : null;
      const report = el("p", { class: "report" }, [], C.t("gReport", lg));
      const stay = el("button", { type: "button", class: "stay" }, [], C.t("gStay", lg));
      const go = el("button", { type: "button", class: "go" }, [], C.t("gGo", lg));
      const box = el("div", { class: "box", role: "alertdialog", "aria-modal": "true", dir: lg === "ar" ? "rtl" : "ltr", lang: lg });
      for (const n of [title, body, list, official, report, el("div", { class: "row" }, [stay, go])]) if (n) box.appendChild(n);
      const wrap = el("div", { class: "veil" }, [box]);
      shadow.appendChild(style);
      shadow.appendChild(wrap);
      stay.addEventListener("click", closeGuard);
      go.addEventListener("click", () => {
        closeGuard();
        state.locked.delete(a);
        a.removeAttribute("data-saqr-inert");
        a.removeAttribute("aria-disabled");
        navigate(info.url);
      });
      box.addEventListener("keydown", (e) => {
        if (e.key === "Escape") closeGuard();
      });
      (doc.body || doc.documentElement).appendChild(host);
      state.guard = host;
      stay.focus();
      return host;
    }

    function install() {
      for (const type of ["click", "auxclick", "keydown"]) doc.addEventListener(type, onActivate, true);
    }

    return { state, pass, run, schedule, install, onActivate, showGuard, closeGuard };
  }

  const GUARD_CSS = `
    /* Saqr tokens (frontend/DESIGN.md): white card on a dimmed page, obsidian primary, scam-ink title. */
    .veil { --surface: #fff; --muted: #f1eee6; --line: #e6e2d8; --ink: #111315; --soft: #475569; --primary: #111315; --primary-hover: #1e293b;
            --on-primary: #faf8f5; --scam-ink: #b91c1c; --safe-ink: #047857;
            position: fixed; inset: 0; z-index: 2147483647; background: rgba(17, 19, 21, .5); display: grid; place-items: center;
            font: 15px/1.55 Inter, "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Tahoma, "IBM Plex Sans Arabic", sans-serif; }
    .box { max-width: 440px; margin: 16px; padding: 24px; border-radius: 18px; background: var(--surface); color: var(--ink);
           border: 1px solid var(--line); box-shadow: 0 24px 60px -20px rgba(17,19,21,.45); }
    h2 { margin: 0 0 8px; font-size: 20px; font-weight: 600; line-height: 1.25; color: var(--scam-ink); }
    p { margin: 0 0 8px; }
    ul { margin: 0 0 8px; padding-inline-start: 18px; }
    li { margin: 2px 0; }
    .official { font-weight: 600; color: var(--safe-ink); }
    .report { font-size: 13px; color: var(--soft); }
    .row { display: flex; gap: 8px; flex-wrap: wrap; margin-top: 16px; }
    button { font: inherit; font-weight: 600; border-radius: 12px; min-height: 44px; padding: 10px 16px; cursor: pointer;
             border: 1px solid var(--line); background: var(--surface); color: var(--ink); }
    button:hover { background: var(--muted); }
    button:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }
    .stay { background: var(--primary); border-color: var(--primary); color: var(--on-primary); }
    .stay:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
    .go { color: var(--ink); }
    @media (prefers-color-scheme: dark) {
      .veil { --surface: #171a1f; --muted: #1f232a; --line: #2a2f37; --ink: #faf8f5; --soft: #a3acb9; --primary: #faf8f5;
              --primary-hover: #e7e3da; --on-primary: #111315; --scam-ink: #f87171; --safe-ink: #34d399; }
    }
  `;

  /** chrome.runtime.sendMessage that never throws: resolves {ok:false} instead. */
  function send(msg) {
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          if (chrome.runtime.lastError) resolve({ ok: false, error: chrome.runtime.lastError.message });
          else resolve(res || { ok: false });
        });
      } catch (err) {
        resolve({ ok: false, error: String((err && err.message) || err) });
      }
    });
  }

  function start() {
    if (!C) return;
    const site = () => C.siteOf(root.location);
    send({ type: "searchSettings" }).then((s) => {
      if (!s || !s.ok || !s.enabled) return;
      const shield = createShield({
        doc: document,
        site,
        send,
        lang: () => C.pickLang(document.documentElement.getAttribute("lang"), navigator.languages || [navigator.language]),
        navigate: (url) => root.location.assign(url),
      });
      shield.install();
      shield.schedule();
      new MutationObserver(() => shield.schedule()).observe(document.documentElement, { childList: true, subtree: true });
    });
  }

  return { SEL, collectLinks, collectPhones, adBlocks, createShield, start };
});
