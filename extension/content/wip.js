// SAQR-INTEL | "work in progress" pill for webmail sites the email shield does not support yet
// (Yahoo Mail, Proton Mail, iCloud Mail, AOL Mail, Zoho Mail — see manifest.json).
//
// Shows a small dismissible <saqr-wip-pill> once per browser session:
//   "SAQR email scanning for <Provider> is a work in progress — paste the email at <app>"
// Closed Shadow DOM, textContent only, EN/AR following the page/browser language. It reads nothing
// from the mail page.

(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrWip = api;
  if (root.document && root.location && api.providerFor(root.location.hostname, root.location.pathname)) {
    try {
      api.show();
    } catch (err) {
      console.debug("[SAQR] wip pill failed", String((err && err.message) || err));
    }
  }
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  // The citizen web app (paste an email there): lib/config.js, loaded before this file by manifest.json.
  const config = root.SaqrConfig || (typeof require === "function" ? require("../lib/config.js") : null);
  if (!config) throw new Error("load lib/config.js before content/wip.js");
  const APP_URL = config.APP_URL;
  const PROVIDERS = [
    { host: "mail.yahoo.com", name: "Yahoo Mail" },
    { host: "mail.proton.me", name: "Proton Mail" },
    { host: "www.icloud.com", path: /^\/mail/, name: "iCloud Mail" },
    { host: "mail.aol.com", name: "AOL Mail" },
    { host: "mail.zoho.com", name: "Zoho Mail" },
  ];

  const TEXT = {
    en: (p, app) => ["SAQR email scanning for " + p + " is a work in progress — paste the email at ", app],
    ar: (p, app) => ["فحص البريد من صقر لـ " + p + " قيد التطوير — الصق الرسالة في ", app],
    close: { en: "Close", ar: "إغلاق" },
  };

  function providerFor(host, pathname) {
    const h = String(host || "").toLowerCase();
    const p = PROVIDERS.find((x) => x.host === h && (!x.path || x.path.test(String(pathname || ""))));
    return p ? p.name : null;
  }

  function pickLang(pageLang, browserLangs) {
    const page = String(pageLang || "").trim().toLowerCase();
    if (page) return page.startsWith("ar") ? "ar" : "en";
    const first = String((Array.isArray(browserLangs) ? browserLangs : [browserLangs]).find((l) => l) || "").toLowerCase();
    return first.startsWith("ar") ? "ar" : "en";
  }

  /** "https://saqr-intel.vercel.app/citizen" → "saqr-intel.vercel.app/citizen" (shorter to read). */
  function displayUrl(url) {
    return String(url || "").replace(/^https?:\/\//i, "").replace(/\/$/, "");
  }

  // "Once per session": chrome.storage.session when content scripts may use it, else this page only.
  const memory = new Set();
  async function alreadyShown(key) {
    if (memory.has(key)) return true;
    memory.add(key);
    try {
      const store = root.chrome && chrome.storage && chrome.storage.session;
      if (!store) return false;
      const got = await store.get(key);
      if (got && got[key]) return true;
      await store.set({ [key]: true });
    } catch {
      /* storage.session not open to content scripts: the in-memory flag is enough */
    }
    return false;
  }

  async function show() {
    const provider = providerFor(location.hostname, location.pathname);
    if (!provider || document.querySelector("saqr-wip-pill")) return;
    if (await alreadyShown("saqrWipPill:" + location.hostname)) return;

    const lang = pickLang(document.documentElement.getAttribute("lang"), navigator.languages || [navigator.language]);
    const dark = !!(root.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches);
    const host = document.createElement("saqr-wip-pill");
    host.style.cssText = "position:fixed;inset-block-end:16px;inset-inline-start:16px;z-index:2147483000;";
    const shadow = host.attachShadow({ mode: "closed" });
    const css =
      ":host{all:initial}" +
      ".p{display:flex;align-items:center;gap:8px;max-width:460px;padding:8px 8px 8px 14px;border-radius:999px;" +
      "font:13px/1.4 system-ui,-apple-system,'Segoe UI',Tahoma,'Noto Sans Arabic',sans-serif;" +
      "background:#fff;color:#0f172a;border:1px solid #e2e8f0;box-shadow:0 4px 16px rgba(0,0,0,.18)}" +
      ".p.dark{background:#111827;color:#f1f5f9;border-color:#334155}" +
      ".dot{width:10px;height:10px;border-radius:50%;background:#f59e0b;flex:none}" +
      "a{color:#0f766e;font-weight:600}.dark a{color:#5eead4}" +
      "button{all:unset;cursor:pointer;padding:0 6px;font-size:18px;line-height:1;opacity:.7}" +
      "button:focus-visible{outline:2px solid #0f766e;border-radius:4px}";
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      shadow.adoptedStyleSheets = [sheet];
    } catch {
      const s = document.createElement("style");
      s.textContent = css;
      shadow.appendChild(s);
    }
    const [before, app] = TEXT[lang](provider, displayUrl(APP_URL));
    const pill = document.createElement("div");
    pill.className = "p" + (dark ? " dark" : "");
    pill.setAttribute("role", "status");
    pill.setAttribute("dir", lang === "ar" ? "rtl" : "ltr");
    pill.setAttribute("lang", lang);
    const dot = document.createElement("span");
    dot.className = "dot";
    const text = document.createElement("span");
    text.textContent = before;
    const link = document.createElement("a");
    link.href = APP_URL;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = app;
    text.appendChild(link);
    const close = document.createElement("button");
    close.textContent = "×";
    close.setAttribute("aria-label", TEXT.close[lang]);
    close.title = TEXT.close[lang];
    close.addEventListener("click", () => host.remove());
    pill.append(dot, text, close);
    shadow.appendChild(pill);
    document.documentElement.appendChild(host);
  }

  return { APP_URL, PROVIDERS, providerFor, pickLang, displayUrl, show };
});
