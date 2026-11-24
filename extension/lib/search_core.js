// Saqr | Search & Maps shield — shared pure logic (no DOM, no chrome.*).
// Loaded by content/search.js (manifest.json), importScripts in background.js and the node tests.
// Publishes globalThis.SaqrSearchCore.

(function (root, factory) {
  const api = factory();
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrSearchCore = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  "use strict";

  const HIGH_RISK_SCORE = 65; // backend: >= 65 HIGH-RISK SCAM
  const SUSPICIOUS_SCORE = 30; // backend: >= 30 SUSPICIOUS

  // www.google.com, google.ae, google.co.uk, google.com.sa ... and Bing.
  const GOOGLE_HOST_RE = /^(?:www\.)?google\.(?:[a-z]{2,3}|co\.[a-z]{2}|com\.[a-z]{2})$/;
  const BING_HOST_RE = /^(?:www\.|cn\.)?bing\.com$/;
  // Hosts of the search engines themselves: their links are navigation, never a result to badge.
  const ENGINE_HOST_RE = /(?:^|\.)(?:google\.(?:[a-z]{2,3}|co\.[a-z]{2}|com\.[a-z]{2})|googleadservices\.com|googlesyndication\.com|doubleclick\.net|gstatic\.com|googleusercontent\.com|bing\.com|bing\.net|msn\.com|microsoft\.com)$/;

  /** "google" (web search) | "maps" (Google Maps) | "bing" | null for a page location. */
  function siteOf(loc) {
    const host = String((loc && loc.hostname) || "").toLowerCase();
    const path = String((loc && loc.pathname) || "/");
    if (GOOGLE_HOST_RE.test(host)) {
      if (path === "/search" || path.startsWith("/search/")) return "google";
      if (path === "/maps" || path.startsWith("/maps/")) return "maps";
      return null;
    }
    if (BING_HOST_RE.test(host) && (path === "/search" || path.startsWith("/search/"))) return "bing";
    return null;
  }

  /** Which engine a content-script message may come from (background.js check). */
  function engineOfUrl(url) {
    let u;
    try {
      u = new URL(String(url || ""));
    } catch {
      return null;
    }
    if (u.protocol !== "https:") return null;
    const site = siteOf(u);
    return site === "maps" ? "google" : site;
  }

  function isEngineHost(host) {
    return ENGINE_HOST_RE.test(String(host || "").toLowerCase());
  }

  function httpUrl(s) {
    if (!s) return null;
    try {
      const u = new URL(String(s).trim());
      return u.protocol === "http:" || u.protocol === "https:" ? u.href : null;
    } catch {
      return null;
    }
  }

  function base64UrlDecode(s) {
    let b = String(s).replace(/-/g, "+").replace(/_/g, "/");
    while (b.length % 4) b += "=";
    try {
      return typeof atob === "function" ? atob(b) : null;
    } catch {
      return null;
    }
  }

  /** "https://tamm-smart-pay.net › traffic-fines" / "www.example.com/path" -> https://host/ */
  function parseDisplayUrl(text) {
    const first = String(text || "").trim().split(/[\s›>]+/)[0] || "";
    const m = first.match(/^(?:https?:\/\/)?((?:[a-z0-9\u00a1-\uffff-]+\.)+[a-z\u00a1-\uffff]{2,24})(?:[/:]|$)/i);
    return m ? "https://" + m[1].toLowerCase() + "/" : null;
  }

  /**
   * Where a result / ad link really goes, without the network:
   * google.com|.ae|… /url?q=…, Google ad clicks (/aclk?…&adurl=…, googleadservices.com, data-pcu / data-dtld
   * on the ad), Bing click wrappers (/ck/a?…&u=a1<base64>, /aclk?…&u=…). null = not a website.
   */
  function resolveHref(href, attr) {
    const get = typeof attr === "function" ? attr : () => null;
    let u;
    try {
      u = new URL(String(href || ""), "https://www.google.com/");
    } catch {
      return null;
    }
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const host = u.hostname.toLowerCase();
    const q = (k) => u.searchParams.get(k);
    const fromAttrs = () => {
      for (const part of String(get("data-pcu") || "").split(",")) {
        const v = httpUrl(part);
        if (v) return v;
      }
      const dtld = get("data-dtld");
      return dtld ? parseDisplayUrl(dtld) : null;
    };
    if (GOOGLE_HOST_RE.test(host) || host.endsWith("googleadservices.com")) {
      if (u.pathname === "/url" || u.pathname === "/url/") return httpUrl(q("q") || q("url"));
      if (/^\/(?:aclk|pagead\/aclk)/.test(u.pathname) || host.endsWith("googleadservices.com")) {
        return httpUrl(q("adurl")) || fromAttrs();
      }
      return fromAttrs();
    }
    if (BING_HOST_RE.test(host)) {
      if (/^\/(?:ck\/a|aclk|aclick)/.test(u.pathname)) {
        const raw = q("u") || "";
        if (/^a1/.test(raw)) return httpUrl(base64UrlDecode(raw.slice(2)));
        return httpUrl(raw);
      }
      return null;
    }
    return u.href;
  }

  // UAE numbers: +971 / 00971 / 0 prefixed mobiles and landlines, and toll-free 800 / 600 numbers.
  const PHONE_FULL_RE = /(?:\+|00)\s?971[\s.-]?\(?0?\d{1,2}\)?[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)|(?<![\d+])0(?:5\d|[234679])[\s.-]?\d{3}[\s.-]?\d{4}(?!\d)/g;
  const PHONE_TOLLFREE_RE = /(?<![\d+])(?:800|600)[\s.-]?\d{2,3}(?:[\s.-]?\d{2,4})?(?!\d)/g;
  // A toll-free-looking number in free text counts only right after a phone word ("AED 600 500" is a price).
  const PHONE_CUE_RE = /(?:call|phone|tel|toll[\s-]?free|toll|hotline|helpline|contact|☎|📞|هاتف|اتصل|رقم|الخط)\W{0,4}$/i;

  function digits(s) {
    return String(s || "").replace(/\D/g, "");
  }

  /** Phone numbers in a piece of text. trusted=true: the text IS a phone field (no cue needed). */
  function findPhones(text, trusted = false) {
    const t = String(text || "");
    const out = [];
    const seen = new Set();
    const add = (raw) => {
      const d = digits(raw);
      if (d.length >= 6 && !seen.has(d)) {
        seen.add(d);
        out.push(raw.trim());
      }
    };
    for (const m of t.matchAll(PHONE_FULL_RE)) add(m[0]);
    for (const m of t.matchAll(PHONE_TOLLFREE_RE)) {
      if (trusted || PHONE_CUE_RE.test(t.slice(Math.max(0, m.index - 16), m.index))) add(m[0]);
    }
    return out;
  }

  /** "tel:+971800555" / "phone:tel:+971800555" -> "+971800555" */
  function phoneFromTel(v) {
    const m = String(v || "").match(/tel:([+\d][\d\s().-]{2,24})/i);
    return m ? m[1].trim() : null;
  }

  // ------------------------------------------------------------------------------- wording (EN + AR)
  const STR = {
    scam: ["Saqr: scam", "صقر: احتيال"],
    scamImitates: ["Saqr: scam — imitates {0}", "صقر: احتيال — ينتحل صفة {0}"],
    suspicious: ["Saqr: suspicious", "صقر: مشبوه"],
    suspiciousImitates: ["Saqr: suspicious — may imitate {0}", "صقر: مشبوه — قد ينتحل صفة {0}"],
    official: ["Official: {0}", "رسمي: {0}"],
    officialSite: ["Official UAE website", "موقع إماراتي رسمي"],
    phoneFake: ["Not the official number (official: {0})", "ليس الرقم الرسمي (الرسمي: {0})"],
    phoneScam: ["Scam number: linked to fake listings", "رقم احتيالي: مرتبط بإدراجات مزيفة"],
    phoneUnlisted: ["Not on the official list (official: {0})", "غير مدرج في القائمة الرسمية (الرسمي: {0})"],
    phoneOfficial: ["Official {0} number", "رقم رسمي لـ{0}"],
    tipHead: ["Saqr checked this before you click:", "فحص صقر هذا قبل أن تنقر:"],
    tipOfficial: ["Use only: {0}", "استخدم فقط: {0}"],
    tipLocked: ["The link is locked: Saqr asks before opening it.", "الرابط مقفل: سيسألك صقر قبل فتحه."],
    gTitle: ["Wait! This link looks like a scam", "انتظر! هذا الرابط يبدو احتيالياً"],
    gBody: ["Saqr thinks {0} is a fake website. It may steal your card, OTP or UAE PASS details.", "يعتقد صقر أن {0} موقع مزيف. قد يسرق بيانات بطاقتك أو رمز التحقق أو UAE PASS."],
    gStay: ["Don't open (recommended)", "لا تفتح (موصى به)"],
    gGo: ["Open anyway", "افتح على أي حال"],
    gReport: ["Report fraud: Aman 8002626", "أبلغ عن الاحتيال: أمان 8002626"],
  };

  function pickLang(pageLang, browserLangs) {
    const page = String(pageLang || "").trim().toLowerCase();
    if (page) return page.startsWith("ar") ? "ar" : "en";
    const list = Array.isArray(browserLangs) ? browserLangs : [browserLangs];
    return String(list.find((l) => l) || "").toLowerCase().startsWith("ar") ? "ar" : "en";
  }

  function t(key, lang, ...args) {
    const pair = STR[key] || [key, key];
    return (lang === "ar" ? pair[1] : pair[0]).replace(/\{(\d+)\}/g, (_, i) => (args[i] == null ? "" : String(args[i])));
  }

  function entityName(e, lang) {
    if (!e) return "";
    return (lang === "ar" ? e.nameAr || e.name_ar : e.nameEn || e.name_en) || e.nameEn || e.name_en || "";
  }

  function reasonLines(reasons, lang) {
    return (reasons || []).map((r) => "• " + (lang === "ar" ? r.ar || r.en : r.en || r.ar)).filter((l) => l.length > 2);
  }

  /**
   * Badge for a link verdict (compact form from background.js), or null for "show nothing":
   * red (danger, link locked) for scams, amber for suspicious, green tick ONLY for verified official
   * UAE websites. Unknown-but-safe sites get nothing, so search pages stay quiet.
   */
  function decideLink(v, lang, { quiet = false } = {}) {
    if (!v || !v.verdict) return null;
    const name = entityName(v.entity, lang);
    const head = t("tipHead", lang);
    const reasons = reasonLines(v.reasons, lang);
    if (v.verdict === "HIGH-RISK SCAM" || v.score >= HIGH_RISK_SCORE) {
      const tip = [head, ...reasons];
      if (v.entity && v.entity.officialDomains && v.entity.officialDomains.length) tip.push(t("tipOfficial", lang, v.entity.officialDomains.join(", ")));
      tip.push(t("tipLocked", lang));
      return { level: "danger", inert: true, label: name ? t("scamImitates", lang, name) : t("scam", lang), tip: tip.join("\n") };
    }
    if (v.verdict === "SUSPICIOUS" || v.score >= SUSPICIOUS_SCORE) {
      return { level: "warn", inert: false, label: name ? t("suspiciousImitates", lang, name) : t("suspicious", lang), tip: [head, ...reasons].join("\n") };
    }
    if (v.official && !quiet) {
      return { level: "official", inert: false, label: name ? t("official", lang, name) : t("officialSite", lang), tip: [head, ...reasons].join("\n") };
    }
    return null;
  }

  /** Badge for a phone check (POST /api/check-phone, compact), or null. */
  function decidePhone(p, lang) {
    if (!p || !p.level || p.level === "none") return null;
    const name = entityName(p.entity, lang);
    const shown = ((p.entity && p.entity.officialPhones) || []).join(", ");
    const tip = [t("tipHead", lang), ...reasonLines(p.reasons, lang)].join("\n");
    if (p.level === "official") return { level: "official", inert: false, label: t("phoneOfficial", lang, name), tip };
    if (p.level === "danger") {
      const label = shown ? t("phoneFake", lang, shown) : t("phoneScam", lang);
      return { level: "danger", inert: false, label, tip };
    }
    if (p.level === "caution") return { level: "warn", inert: false, label: shown ? t("phoneUnlisted", lang, shown) : t("suspicious", lang), tip };
    return null;
  }

  return {
    HIGH_RISK_SCORE, SUSPICIOUS_SCORE, STR,
    siteOf, engineOfUrl, isEngineHost, httpUrl, resolveHref, parseDisplayUrl, base64UrlDecode,
    findPhones, phoneFromTel, digits, pickLang, t, entityName, decideLink, decidePhone,
  };
});
