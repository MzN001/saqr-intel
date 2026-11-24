// Saqr | "work in progress" pill for webmail sites the email shield does not support yet
// (Yahoo Mail, Proton Mail, iCloud Mail, AOL Mail, Zoho Mail — see manifest.json).
//
// Shows a small dismissible <saqr-wip-pill> once per browser session:
//   "Saqr email scanning for <Provider> is a work in progress — paste the email at <app>"
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
    en: (p, app) => ["Saqr email scanning for " + p + " is a work in progress — paste the email at ", app],
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
    const FALCON =
      "url(\"data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%2720 20 472 472%27%3E%3Cpath fill-rule=%27evenodd%27 d=%27" +
      "M260 24L354 51L371 78L394 97C403 110 405 128 400 146L390 172L380 145L354 146L344 182L352 203L424 284L368 379L274 219L341 136L289 141L213 249L128 312L159 369L168 306L248 244L163 402L89 284L145 218L179 81ZM210 101L259 89L259 97L283 121L317 112L253 164ZM191 127L206 150L177 184ZM211 212L196 234L153 268L161 238ZM323 188L356 272L299 222ZM357 97L371 106L362 119L344 116ZM259 250L294 427L254 489L253 303L227 453L188 382ZM270 237L344 362L311 444Z".replace(/ /g, "%20") +
      "%27/%3E%3C/svg%3E\")";
    const host = document.createElement("saqr-wip-pill");
    host.style.cssText = "position:fixed;inset-block-end:16px;inset-inline-start:16px;z-index:2147483000;";
    const shadow = host.attachShadow({ mode: "closed" });
    const css =
      // Saqr tokens (frontend/DESIGN.md): surface + hairline, ink text, obsidian/ivory focus; the dot is the
      // falcon mark (neutral ink: "work in progress" is not a verdict, so no verdict colour).
      ":host{all:initial}" +
      ".p{--surface:#fff;--line:#e6e2d8;--ink:#111315;--soft:#475569;display:flex;align-items:center;gap:10px;max-width:460px;" +
      "padding:8px 8px 8px 14px;border-radius:9999px;" +
      "font:500 13px/1.45 Inter,'Segoe UI Variable Text','Segoe UI',system-ui,-apple-system,Tahoma,'IBM Plex Sans Arabic',sans-serif;" +
      "background:var(--surface);color:var(--ink);border:1px solid var(--line);" +
      "box-shadow:0 1px 2px rgba(17,19,21,.04),0 8px 24px -12px rgba(17,19,21,.2)}" +
      ".p.dark{--surface:#171a1f;--line:#2a2f37;--ink:#faf8f5;--soft:#a3acb9}" +
      ".dot{width:16px;height:16px;flex:none;background:var(--ink);" +
      "-webkit-mask:" + FALCON + " center/contain no-repeat;mask:" + FALCON + " center/contain no-repeat}" +
      "a{color:var(--ink);font-weight:600;text-decoration:underline;text-underline-offset:3px}" +
      "button{all:unset;cursor:pointer;padding:0 6px;font-size:18px;line-height:1;color:var(--soft)}" +
      "button:focus-visible{outline:2px solid var(--ink);outline-offset:2px;border-radius:4px}";
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
