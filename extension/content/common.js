// Saqr | mail content scripts — shared core (Gmail + Outlook).
//
// Loaded by manifest.json AFTER lib/email_features.js + lib/campaign_match.js (globalThis.SaqrModel,
// globalThis.SaqrCampaigns) and BEFORE content/gmail.js or content/outlook.js. Publishes
// globalThis.SaqrMail = { util, start(adapter) }.
//
// What it does in the mail page:
//   - <saqr-scan-all>   small floating control: "Scan all emails in this inbox view" (+ "Scan this email").
//   - row badges        <span class="saqr-row-badge" data-saqr-row="campaign|model|scam|suspicious|safe">
//                       painted next to each inbox row (cheap local checks first, backend scan after).
//   - <saqr-mail-banner> verdict banner above an opened message (closed Shadow DOM, textContent only).
//   - link guard        for dangerous mail: clicks on links in the body ask for confirmation first.
//
// Safety rules (owner + contract): never throw into the page, never innerHTML, never pass mail content
// to the page's own JavaScript (closed shadow roots, no window.postMessage), and when a selector
// misses we simply show nothing and log ONE console.debug "selector health" line.
//
// Background protocol (contract section 5): emailScan (+ priority:"open" for an opened email),
// campaigns, modelPredict, modelLabel, emailSettings (autoScan, learnSpam), openEmailVerdict
// {provider, message_key} for "Full report". Optional extra we try and tolerate being refused: gmailIk.

(function (root, factory) {
  const api = factory(root);
  if (typeof module === "object" && module.exports) module.exports = api;
  root.SaqrMail = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function (root) {
  "use strict";

  // ---------------------------------------------------------------------------------------------
  // Constants
  // ---------------------------------------------------------------------------------------------
  const HIGH_RISK_SCORE = 65; // contract: >= 65 HIGH-RISK SCAM
  const SUSPICIOUS_SCORE = 30; // contract: >= 30 SUSPICIOUS
  const MODEL_SCAM_P = 0.9; // contract: USER_MODEL_SCAM when p >= 0.9
  const RAW_CAP_BYTES = 2 * 1024 * 1024; // send at most 2 MB of original source
  const BODY_CAP = 200000; // contract: meta.body_text 200k chars
  const LINKS_CAP = 100; // contract: meta.links 100
  const SCAN_SPACING_MS = 500; // "Scan all" pacing between Gmail "Show original" fetches (background also queues backend scans)
  const FEED_TTL_MS = 30 * 60 * 1000;
  const TICK_MS = 450;

  // Same invisible set the shared libs strip (soft hyphen, CGJ, ZWSP..RLM, LRE..RLO, WJ..PDI, BOM).
  const INVISIBLE_RE = /[­͏​-‏‪-‮⁠-⁩﻿]/g;
  // Invisible characters that matter when they sit INSIDE a Latin word (contract INVISIBLE_IN_TOKEN).
  const ZERO_WIDTH = /[​-‍⁠﻿­͏]/;
  const BIDI_ANY = /[‪-‮⁦-⁩]/;
  const BIDI_OVERRIDE = /[‭‮]/; // RLO / LRO: the "reversed file name" trick
  const EMAIL_RE = /[A-Za-z0-9._%+\-À-\uffff]+@[A-Za-z0-9.\-À-\uffff]+\.[A-Za-zÀ-\uffff]{2,}/;

  // Fallback lists, used only if lib/email_features.js did not load (should not happen).
  const FREEMAIL_FALLBACK = new Set(
    "gmail.com googlemail.com outlook.com hotmail.com live.com msn.com yahoo.com ymail.com icloud.com me.com aol.com proton.me protonmail.com gmx.com mail.com zoho.com yandex.com yandex.ru mail.ru".split(" "),
  );

  // Brands checked locally (sender address / display name / subject). Small on purpose: the backend
  // has the full registry. "common" names are ordinary words or surnames (Apple, Amazon, du...) and
  // are not treated as a brand claim in a display name on their own. Short names match whole tokens.
  const BRANDS = [
    { id: "paypal", names: ["paypal", "باي بال"], domains: ["paypal.com", "paypal.me", "paypalobjects.com"] },
    { id: "microsoft", names: ["microsoft", "office 365", "microsoft 365", "outlook team"], domains: ["microsoft.com", "microsoftonline.com", "office.com", "office365.com", "live.com", "outlook.com", "hotmail.com"] },
    { id: "apple", names: ["apple", "icloud", "apple id"], domains: ["apple.com", "icloud.com", "me.com"], common: true },
    { id: "amazon", names: ["amazon"], domains: ["amazon.com", "amazon.ae", "amazon.co.uk", "amazon.sa", "amazonaws.com"], common: true },
    { id: "google", names: ["google", "gmail"], domains: ["google.com", "gmail.com", "youtube.com", "googlemail.com"] },
    { id: "netflix", names: ["netflix"], domains: ["netflix.com"] },
    { id: "dhl", names: ["dhl"], domains: ["dhl.com", "dhl.ae"] },
    { id: "aramex", names: ["aramex", "أرامكس"], domains: ["aramex.com"] },
    { id: "fedex", names: ["fedex"], domains: ["fedex.com"] },
    { id: "emiratespost", names: ["emirates post", "emiratespost", "بريد الإمارات"], domains: ["emiratespost.ae"] },
    { id: "tamm", names: ["tamm", "تم"], domains: ["tamm.abudhabi"], arabicCommon: true },
    { id: "uaepass", names: ["uae pass", "uaepass", "الهوية الرقمية"], domains: ["uaepass.ae"] },
    { id: "adcb", names: ["adcb"], domains: ["adcb.com"] },
    { id: "fab", names: ["first abu dhabi bank", "bankfab"], domains: ["bankfab.com"] },
    { id: "emiratesnbd", names: ["emirates nbd", "emiratesnbd", "الإمارات دبي الوطني"], domains: ["emiratesnbd.com"] },
    { id: "mashreq", names: ["mashreq", "المشرق"], domains: ["mashreq.com", "mashreqbank.com"] },
    { id: "etisalat", names: ["etisalat", "اتصالات"], domains: ["etisalat.ae", "eand.com", "etisalat.com"] },
    { id: "du", names: ["du telecom"], domains: ["du.ae"] },
    { id: "adnoc", names: ["adnoc", "أدنوك"], domains: ["adnoc.ae"] },
    { id: "adpolice", names: ["abu dhabi police", "adpolice", "شرطة أبوظبي"], domains: ["adpolice.gov.ae"] },
    { id: "dubaipolice", names: ["dubai police", "شرطة دبي"], domains: ["dubaipolice.gov.ae"] },
    { id: "facebook", names: ["facebook", "instagram", "meta"], domains: ["facebook.com", "facebookmail.com", "instagram.com", "meta.com"], common: true },
    { id: "whatsapp", names: ["whatsapp", "واتساب"], domains: ["whatsapp.com"] },
    { id: "binance", names: ["binance"], domains: ["binance.com"] },
  ];

  // Cyrillic / Greek / IPA letters that look like Latin ones (a subset of Unicode confusables).
  const CONFUSABLE = {
    "а": "a", "в": "b", "с": "c", "ԁ": "d", "е": "e", "ё": "e", "һ": "h", "і": "i", "ї": "i", "ј": "j", "к": "k",
    "ӏ": "l", "м": "m", "н": "h", "о": "o", "р": "p", "ԛ": "q", "г": "r", "ѕ": "s", "т": "t", "у": "y", "ү": "y",
    "х": "x", "ԝ": "w", "ь": "b", "ɑ": "a", "ɡ": "g", "ɩ": "i", "ɪ": "i", "ʏ": "y",
    "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "i", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u", "χ": "x", "ω": "w",
  };
  // Extra ASCII tricks for domain names only (paypa1, micr0soft, rnicrosoft, vvhatsapp).
  const ASCII_TRICKS = [[/rn/g, "m"], [/vv/g, "w"], [/0/g, "o"], [/1/g, "l"], [/3/g, "e"], [/5/g, "s"]];

  // ---------------------------------------------------------------------------------------------
  // Citizen-facing text (EN + AR). Keep it short and simple.
  // ---------------------------------------------------------------------------------------------
  const STR = {
    scanAll: ["Scan all emails in this inbox view", "افحص كل الرسائل في هذه الصفحة"],
    scanThis: ["Scan this email", "افحص هذه الرسالة"],
    cancel: ["Cancel", "إلغاء"],
    close: ["Close", "إغلاق"],
    progress: ["{0} / {1}", "{0} / {1}"],
    checking: ["Checking…", "جارٍ الفحص…"],
    noRows: ["No emails found in this view.", "لا توجد رسائل في هذه الصفحة."],
    summary: ["{0} dangerous, {1} suspicious, {2} with no warning signs", "{0} خطيرة، {1} مشبوهة، {2} بلا علامات تحذير"],
    summaryLocal: ["Some emails can only be checked fully when you open them.", "بعض الرسائل لا يمكن فحصها بالكامل إلا عند فتحها."],
    cancelled: ["Stopped.", "تم الإيقاف."],
    brand: ["Saqr Email Shield", "درع صقر للبريد"],

    tScanning: ["Saqr is checking this email…", "صقر يفحص هذه الرسالة…"],
    tSafe: ["No scam signs found", "لم نجد علامات احتيال"],
    tSuspicious: ["Be careful: this email looks suspicious", "انتبه: هذه الرسالة تبدو مشبوهة"],
    tDangerous: ["Danger: this email looks like a scam", "خطر: هذه الرسالة تبدو احتيالية"],
    tError: ["Saqr could not check this email", "تعذّر على صقر فحص هذه الرسالة"],
    errHint: ["Check your internet connection or the Saqr extension settings, then press Rescan.", "تحقّق من الاتصال بالإنترنت أو من إعدادات إضافة صقر، ثم اضغط «إعادة الفحص»."],
    errReload: ["Saqr was updated. Reload this page to keep checking your emails.", "تم تحديث صقر. أعد تحميل هذه الصفحة لمتابعة فحص رسائلك."],
    safeHint: ["Still be careful with links and never share codes (OTP) or card details.", "ومع ذلك كن حذراً مع الروابط ولا تشارك رموز التحقق أو بيانات البطاقة أبداً."],
    score: ["Risk {0}/100", "الخطورة {0}/100"],
    headersNotVerified: ["Sender not verified (headers not available)", "لم يتم التحقق من المرسل (الترويسات غير متاحة)"],
    sourceHint: [
      "To check the sender too: open this email's menu → View → View message source. Saqr reads it automatically. Or paste that source into the Saqr web app (Email tab).",
      "للتحقق من المرسل أيضاً: افتح قائمة هذه الرسالة ← عرض ← عرض مصدر الرسالة، وسيقرؤه صقر تلقائياً. أو الصق المصدر في تطبيق صقر على الويب (تبويب البريد).",
    ],
    campaign: ["Matches a known scam campaign: {0}", "تطابق حملة احتيال معروفة: {0}"],
    lookalike: ["Look-alike or hidden letters:", "أحرف مشابهة أو مخفية:"],
    linksGuarded: ["Links in this email are locked. Saqr will ask before opening them.", "الروابط في هذه الرسالة مقفلة. سيسألك صقر قبل فتحها."],
    fullReport: ["Full report", "التقرير الكامل"],
    isScam: ["This is a scam", "هذه رسالة احتيال"],
    isSafe: ["This is safe", "هذه رسالة آمنة"],
    rescan: ["Rescan", "إعادة الفحص"],
    thanks: ["Thank you. Saqr will remember this ({0} emails learned).", "شكراً لك. سيتذكر صقر ذلك (تعلّم من {0} رسائل)."],
    thanksShort: ["Thank you. Saqr will remember this.", "شكراً لك. سيتذكر صقر ذلك."],
    labelFail: ["Could not save your answer. Try again.", "تعذّر حفظ إجابتك. حاول مرة أخرى."],
    reportFail: ["Could not open the report.", "تعذّر فتح التقرير."],
    localOnly: ["Quick check only — open the email to scan it fully.", "فحص سريع فقط — افتح الرسالة لفحصها بالكامل."],

    gTitle: ["Wait! This email looks dangerous", "انتظر! هذه الرسالة تبدو خطيرة"],
    gBody: ["Saqr thinks this email is a scam. This link may steal your password, card or money. Are you sure you want to open it?", "يعتقد صقر أن هذه الرسالة احتيالية. قد يسرق هذا الرابط كلمة المرور أو بيانات البطاقة أو أموالك. هل أنت متأكد أنك تريد فتحه؟"],
    gStay: ["Don't open (recommended)", "لا تفتح (موصى به)"],
    gOpen: ["Open anyway", "افتح على أي حال"],

    rowScam: ["Dangerous", "خطيرة"],
    rowSuspicious: ["Suspicious", "مشبوهة"],
    rowCampaign: ["Scam campaign", "حملة احتيال"],
    rowModel: ["Looks like your scams", "تشبه رسائل احتيال سابقة"],
    rowSafe: ["No warning signs", "بلا علامات تحذير"],
    rowOpen: ["Open to scan fully", "افتح للفحص الكامل"],
    rowScanning: ["Checking…", "جارٍ الفحص…"],

    // Local finding texts
    fMixed: ["The name \"{0}\" mixes Latin letters with look-alike letters from another alphabet.", "الاسم «{0}» يخلط حروفاً لاتينية مع حروف مشابهة من أبجدية أخرى."],
    fWholeConf: ["\"{0}\" is written with look-alike letters to imitate \"{1}\".", "«{0}» مكتوبة بحروف مشابهة لتقليد «{1}»."],
    fBidi: ["Hidden direction characters are used to disguise text: {0}", "تُستخدم رموز اتجاه مخفية لتمويه النص: {0}"],
    fInvisible: ["Hidden invisible characters are placed inside a word: {0}", "توجد رموز مخفية داخل كلمة: {0}"],
    fPunycode: ["The sender's address uses unusual international letters ({0}).", "عنوان المرسل يستخدم حروفاً دولية غير معتادة ({0})."],
    fLookalike: ["The sender's address {0} imitates the official {1} address.", "عنوان المرسل {0} يقلّد العنوان الرسمي لـ {1}."],
    fBrandDomain: ["The sender's address {0} uses the name {1} but is not an official {1} address.", "عنوان المرسل {0} يستخدم اسم {1} لكنه ليس عنواناً رسمياً لـ {1}."],
    fFreemail: ["The sender says \"{0}\" but writes from a free email account ({1}).", "يدّعي المرسل أنه «{0}» لكنه يراسلك من حساب بريد مجاني ({1})."],
    fNameAddr: ["The sender's name shows the address {0} but the email really came from {1}.", "يظهر في اسم المرسل العنوان {0} لكن الرسالة جاءت فعلياً من {1}."],
  };

  // ---------------------------------------------------------------------------------------------
  // Pure helpers (unit-tested in extension/tests/content/)
  // ---------------------------------------------------------------------------------------------

  /** "ar" when the page (or, if the page says nothing, the browser) uses Arabic; otherwise "en". */
  function pickLang(pageLang, browserLangs) {
    const page = String(pageLang || "").trim().toLowerCase();
    if (page) return page.startsWith("ar") ? "ar" : "en";
    const list = Array.isArray(browserLangs) ? browserLangs : [browserLangs];
    const first = String(list.find((l) => l) || "").toLowerCase();
    return first.startsWith("ar") ? "ar" : "en";
  }

  /** Translate a STR key, filling {0}, {1}… */
  function t(key, lang, ...args) {
    const pair = STR[key] || [key, key];
    const s = lang === "ar" ? pair[1] : pair[0];
    return s.replace(/\{(\d+)\}/g, (_, i) => (args[i] == null ? "" : String(args[i])));
  }

  /** Parse "rgb(…)/rgba(…)" → true (dark) / false (light) / null (transparent or unknown). */
  function isDarkColor(css) {
    const m = String(css || "").match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)(?:[,\s/]+([\d.]+%?))?/i);
    if (!m) return null;
    const alpha = m[4] == null ? 1 : m[4].endsWith("%") ? parseFloat(m[4]) / 100 : parseFloat(m[4]);
    if (alpha < 0.5) return null;
    const lin = (c) => {
      const v = Number(c) / 255;
      return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
    };
    const lum = 0.2126 * lin(m[1]) + 0.7152 * lin(m[2]) + 0.0722 * lin(m[3]);
    return lum < 0.2;
  }

  /**
   * Remove click-tracking / security wrappers so we see where a link really goes:
   * google.com/url?q=…, Outlook Safe Links (*.safelinks.protection.outlook.com/?url=…).
   * Nested wrappers are unwrapped up to 4 times. Anything unparseable is returned unchanged.
   */
  function unwrapLink(href) {
    let cur = String(href || "").trim();
    for (let i = 0; i < 4; i++) {
      let u;
      try {
        u = new URL(cur);
      } catch {
        return cur;
      }
      const host = u.hostname.toLowerCase();
      let inner = null;
      if (/(^|\.)google\.[a-z.]{2,6}$/.test(host) && u.pathname === "/url") {
        inner = u.searchParams.get("q") || u.searchParams.get("url");
      } else if (host.endsWith(".safelinks.protection.outlook.com") || host === "safelinks.protection.outlook.com") {
        inner = u.searchParams.get("url");
      } else if (host === "statics.teams.cdn.office.net" && u.searchParams.get("url")) {
        inner = u.searchParams.get("url");
      }
      if (!inner || !/^https?:\/\//i.test(inner)) return cur;
      cur = inner;
    }
    return cur;
  }

  /** Lower-case hostname of a URL or bare host, "" if none. */
  function hostOf(urlOrHost) {
    const s = String(urlOrHost || "").trim();
    if (!s) return "";
    try {
      return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : "http://" + s).hostname.toLowerCase().replace(/\.$/, "");
    } catch {
      return "";
    }
  }

  function regdom(host) {
    const M = root.SaqrModel;
    if (M && typeof M.regdom === "function") return M.regdom(host);
    const labels = String(host || "").toLowerCase().replace(/\.$/, "").split(".").filter(Boolean);
    return labels.slice(-2).join(".");
  }

  function isFreemail(domain) {
    const M = root.SaqrModel;
    const d = regdom(domain);
    if (M && M.FREEMAIL instanceof Set) return M.FREEMAIL.has(d);
    return FREEMAIL_FALLBACK.has(d);
  }

  /** "Name <a@b.com>" / "a@b.com" / "Name" → {name, address}. */
  function parseAddress(s) {
    const str = String(s || "").trim();
    const angle = str.match(/^(.*?)<\s*([^<>\s]+@[^<>\s]+)\s*>\s*$/);
    if (angle) return { name: angle[1].trim().replace(/^"(.*)"$/, "$1").trim(), address: angle[2].trim() };
    const m = str.match(EMAIL_RE);
    if (m && m[0].length === str.length) return { name: "", address: str };
    return { name: str, address: m ? m[0] : "" };
  }

  /** Decode one punycode label body (the part after "xn--"), RFC 3492. Throws on bad input. */
  function punyDecode(input) {
    const base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700;
    const adapt = (delta, numPoints, first) => {
      delta = first ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / numPoints);
      let k = 0;
      while (delta > ((base - tMin) * tMax) >> 1) {
        delta = Math.floor(delta / (base - tMin));
        k += base;
      }
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    };
    const out = [];
    let n = 128, i = 0, bias = 72;
    let b = input.lastIndexOf("-");
    if (b < 0) b = 0;
    for (let j = 0; j < b; j++) {
      const c = input.charCodeAt(j);
      if (c >= 0x80) throw new Error("bad punycode");
      out.push(c);
    }
    for (let idx = b > 0 ? b + 1 : 0; idx < input.length; ) {
      const oldi = i;
      let w = 1;
      for (let k = base; ; k += base) {
        if (idx >= input.length) throw new Error("bad punycode");
        const c = input.charCodeAt(idx++);
        const digit = c >= 48 && c <= 57 ? c - 22 : c >= 65 && c <= 90 ? c - 65 : c >= 97 && c <= 122 ? c - 97 : base;
        if (digit >= base) throw new Error("bad punycode");
        i += digit * w;
        if (i > 0x10ffff * 64) throw new Error("bad punycode");
        const tt = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < tt) break;
        w *= base - tt;
      }
      const len = out.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len);
      i %= len;
      if (n > 0x10ffff) throw new Error("bad punycode");
      out.splice(i++, 0, n);
    }
    return String.fromCodePoint(...out);
  }

  /** Unicode form of a host ("xn--pypal-4ve.com" → "pаypal.com"); bad labels are kept as-is. */
  function toUnicodeHost(host) {
    return String(host || "")
      .toLowerCase()
      .split(".")
      .map((l) => {
        if (!l.startsWith("xn--")) return l;
        try {
          return punyDecode(l.slice(4));
        } catch {
          return l;
        }
      })
      .join(".");
  }

  /** "pаypal" → "p\\u0430ypal" (shows the hidden letter safely, like the backend's sample_escaped). */
  function escapeNonAscii(s) {
    let out = "";
    for (const ch of String(s || "")) {
      const cp = ch.codePointAt(0);
      if (cp >= 0x20 && cp < 0x7f) out += ch;
      else if (cp <= 0xffff) out += "\\u" + cp.toString(16).padStart(4, "0");
      else out += "\\u{" + cp.toString(16) + "}";
    }
    return out;
  }

  /** Latin "skeleton": look-alike letters mapped to Latin, invisibles removed, NFKC + lowercase. */
  function skeleton(s) {
    let out = "";
    for (const ch of String(s || "").normalize("NFKC").toLowerCase().replace(INVISIBLE_RE, "")) {
      out += CONFUSABLE[ch] || ch;
    }
    return out;
  }

  function asciiSkeleton(label) {
    let s = skeleton(label);
    for (const [re, rep] of ASCII_TRICKS) s = s.replace(re, rep);
    return s;
  }

  const RE_LATIN = /\p{Script=Latin}/u;
  const RE_FOREIGN_LOOKALIKE = /[\p{Script=Cyrillic}\p{Script=Greek}]/u;
  const RE_FANCY = /[\u{1D400}-\u{1D7FF}Ａ-Ｚａ-ｚ]/u;

  function brandKeys() {
    const out = [];
    for (const b of BRANDS) {
      for (const d of b.domains) out.push({ brand: b, label: regdom(d).split(".")[0] });
    }
    return out;
  }

  /** Does normalised text contain the brand name as whole word(s)? */
  function textHasBrand(text, brand) {
    const norm = skeleton(text).replace(/\s+/g, " ");
    return brand.names.some((n) => {
      if (brand.arabicCommon && /[؀-ۿ]/.test(n)) return false; // "تم" is an ordinary Arabic word
      const esc = n.toLowerCase().replace(/[.*+?^$\{}()|[\]\\]/g, "\\$&");
      return new RegExp("(?<![\\p{L}\\p{N}])" + esc + "(?![\\p{L}\\p{N}])", "u").test(norm);
    });
  }

  function brandForDomain(domain) {
    const rd = regdom(domain);
    return BRANDS.find((b) => b.domains.some((d) => regdom(d) === rd)) || null;
  }

  /**
   * Cheap, offline look-alike checks on what an inbox row shows (sender name + address, subject).
   * Returns findings [{code, level:"scam"|"suspicious", en, ar, evidence}]. Designed to stay quiet on
   * ordinary mail: plain Arabic or other non-Latin text is never flagged, only Latin words with
   * foreign look-alike letters, hidden characters inside words, and fake brand addresses.
   */
  function localChecks(input) {
    const i = input || {};
    const findings = [];
    const seen = new Set();
    const add = (code, level, key, args, evidence) => {
      const sig = code + "|" + evidence;
      if (seen.has(sig)) return;
      seen.add(sig);
      findings.push({ code, level, en: t(key, "en", ...args), ar: t(key, "ar", ...args), evidence });
    };

    const address = String(i.from_address || "").trim();
    const name = String(i.from_name || "").trim();
    const subject = String(i.subject || "");
    const domain = address.includes("@") ? address.split("@").pop().toLowerCase().replace(/[>\s]+$/, "") : "";
    const officialBrand = domain ? brandForDomain(toUnicodeHost(domain)) : null;

    // 1. Words in the display name / subject: Latin letters mixed with Cyrillic/Greek look-alikes,
    //    hidden characters inside a Latin word, reversed-text (RLO/LRO) tricks, "fancy" styled brands.
    const TOKEN_SPLIT = /[^\p{L}\p{N}\p{M}­͏​-‏‪-‮⁠-⁩﻿]+/u;
    for (const [where, text] of [["display_name", name], ["subject", subject]]) {
      for (const tok of text.split(TOKEN_SPLIT)) {
        if (!tok) continue;
        const core = tok.replace(INVISIBLE_RE, "");
        if (RE_LATIN.test(core) && RE_FOREIGN_LOOKALIKE.test(core)) {
          add("DISPLAY_NAME_CONFUSABLE", "scam", "fMixed", [escapeNonAscii(core)], where + ": " + escapeNonAscii(core));
        } else if (!RE_LATIN.test(core) && RE_FOREIGN_LOOKALIKE.test(core) && core.length >= 3) {
          const sk = skeleton(core);
          const hit = BRANDS.find((b) => b.names.some((n) => n.replace(/\s+/g, "") === sk));
          if (hit) add("DISPLAY_NAME_CONFUSABLE", "scam", "fWholeConf", [escapeNonAscii(core), sk], where + ": " + escapeNonAscii(core));
        }
        // Hidden character between two Latin letters/digits ("Pay​Pal").
        const chars = Array.from(tok);
        for (let k = 1; k < chars.length - 1; k++) {
          if (!ZERO_WIDTH.test(chars[k])) continue;
          let a = k - 1, b = k + 1;
          while (a > 0 && ZERO_WIDTH.test(chars[a])) a--;
          while (b < chars.length - 1 && ZERO_WIDTH.test(chars[b])) b++;
          if (/[A-Za-z0-9]/.test(chars[a]) && /[A-Za-z0-9]/.test(chars[b])) {
            add("INVISIBLE_IN_TOKEN", "suspicious", "fInvisible", [escapeNonAscii(tok)], where + ": " + escapeNonAscii(tok));
            break;
          }
        }
        if (BIDI_OVERRIDE.test(tok) && RE_LATIN.test(core)) {
          add("BIDI_OVERRIDE", "scam", "fBidi", [escapeNonAscii(tok)], where + ": " + escapeNonAscii(tok));
        }
        if (RE_FANCY.test(core)) {
          const plain = core.normalize("NFKC");
          const hit = BRANDS.find((b) => textHasBrand(plain, b));
          if (hit && !officialBrand) add("FANCY_UNICODE", "suspicious", "fWholeConf", [core, plain], where + ": " + escapeNonAscii(core));
        }
      }
    }

    // 2. The sender's address itself.
    if (address) {
      if (BIDI_ANY.test(address)) add("BIDI_OVERRIDE", "scam", "fBidi", [escapeNonAscii(address)], "from.address: " + escapeNonAscii(address));
      if (ZERO_WIDTH.test(address)) add("INVISIBLE_IN_TOKEN", "scam", "fInvisible", [escapeNonAscii(address)], "from.address: " + escapeNonAscii(address));
    }
    if (domain && !officialBrand) {
      const uni = toUnicodeHost(domain);
      const rd = regdom(uni);
      const label = rd.split(".")[0] || "";
      const isPuny = domain.split(".").some((l) => l.startsWith("xn--")) || /[^\x00-\x7f]/.test(domain);
      let lookalike = null;
      if (RE_LATIN.test(label) && RE_FOREIGN_LOOKALIKE.test(label)) {
        lookalike = skeleton(label);
        add("IDN_MIXED_SCRIPT", "scam", "fLookalike", [escapeNonAscii(uni), lookalike], "from.domain: " + escapeNonAscii(uni));
      }
      const sk = asciiSkeleton(label);
      const bk = lookalike ? null : brandKeys().find((k) => k.label.length >= 4 && k.label === sk && k.label !== label);
      if (bk) add("SENDER_LOOKALIKE", "scam", "fLookalike", [escapeNonAscii(uni), bk.brand.names[0]], "from.domain: " + escapeNonAscii(uni));
      else if (!lookalike) {
        // Brand name glued into another domain: "paypal-support-center.com", "dhl-parcel.info".
        const parts = skeleton(label).split(/[-_]/);
        const hit = brandKeys().find((k) => k.label.length >= 5 && parts.length > 1 && parts.includes(k.label));
        if (hit) add("SENDER_LOOKALIKE", "suspicious", "fBrandDomain", [escapeNonAscii(uni), hit.brand.names[0]], "from.domain: " + escapeNonAscii(uni));
      }
      if (isPuny && !findings.some((f) => f.code === "IDN_MIXED_SCRIPT")) {
        add("PUNYCODE_DOMAIN", "suspicious", "fPunycode", [escapeNonAscii(uni)], "from.domain: " + domain);
      }
    }

    // 3. Display name claims a brand but the mail comes from a free account (Gmail, Outlook.com…).
    if (domain && name && isFreemail(domain)) {
      const claimed = BRANDS.find((b) => !b.common && !b.domains.some((d) => regdom(d) === regdom(domain)) && textHasBrand(name, b));
      if (claimed) add("FREEMAIL_BRAND_SENDER", "suspicious", "fFreemail", [name, domain], "display name \"" + name + "\", from " + domain);
    }

    // 4. Display name contains a different e-mail address ("support@paypal.com" <x@evil.example>).
    const nameAddr = name.match(EMAIL_RE);
    if (nameAddr && address) {
      const shown = nameAddr[0].toLowerCase();
      const shownDom = regdom(shown.split("@").pop());
      if (shown !== address.toLowerCase() && shownDom !== regdom(domain)) {
        add("DISPLAY_NAME_ADDRESS_SPOOF", "suspicious", "fNameAddr", [shown, address], "display name shows " + shown);
      }
    }
    return findings;
  }

  /** Verdict tone for banner/badges. */
  function toneOf(verdict, score) {
    const s = score == null || score === "" ? NaN : Number(score);
    if (verdict === "HIGH-RISK SCAM" || (!verdict && s >= HIGH_RISK_SCORE)) return "dangerous";
    if (verdict === "SUSPICIOUS" || (!verdict && s >= SUSPICIOUS_SCORE)) return "suspicious";
    if (verdict === "SAFE") return "safe";
    return Number.isFinite(s) ? (s >= HIGH_RISK_SCORE ? "dangerous" : s >= SUSPICIOUS_SCORE ? "suspicious" : "safe") : "error";
  }

  function authValue(x) {
    if (x == null) return "not_checked";
    if (typeof x === "string") return x || "not_checked";
    if (Array.isArray(x)) {
      if (!x.length) return "none";
      const rs = x.map(authValue);
      return rs.includes("pass") ? "pass" : rs[0];
    }
    return String(x.result || "not_checked");
  }

  /**
   * Turn the background's {ok, verdict:<summarised>, full:<response subset>} into one UI-ready
   * object. Field names are read from either shape (summarised camelCase or the raw contract).
   */
  function normaliseResult(resp) {
    const v = (resp && resp.verdict && typeof resp.verdict === "object" ? resp.verdict : {}) || {};
    const f = (resp && resp.full && typeof resp.full === "object" ? resp.full : {}) || {};
    const pick = (...xs) => xs.find((x) => x !== undefined && x !== null);
    const scoreRaw = pick(v.score, v.risk_score, f.risk_score);
    const score = Number.isFinite(Number(scoreRaw)) ? Math.max(0, Math.min(100, Math.round(Number(scoreRaw)))) : null;
    const verdict = pick(typeof resp?.verdict === "string" ? resp.verdict : undefined, v.verdict, f.verdict) || null;
    // Prefer the full response (it has points); the summarised flags are already the scoring ones.
    const flagsAll = pick(f.red_flags, v.red_flags, v.flags) || [];
    const flags = flagsAll
      .filter((x) => x && (x.points == null ? x.sev !== "info" : Number(x.points) > 0))
      .sort((a, b) => Number(b.points) - Number(a.points))
      .map((x) => ({ code: String(x.code || ""), en: String(x.en || ""), ar: String(x.ar || x.en || ""), points: Number(x.points) || 0 }));
    const allCodes = flagsAll.map((x) => String(x && x.code || "")).filter(Boolean);
    const auth = pick(v.auth, v.authentication, f.authentication) || null;
    const emailInfo = pick(v.email, f.email) || {};
    let hasHeaders = pick(v.hasHeaders, v.has_headers, emailInfo.has_headers);
    if (hasHeaders == null) hasHeaders = !allCodes.includes("HEADERS_NOT_AVAILABLE") && !!auth;
    const unicodeRaw = pick(f.unicode, v.unicode) || [];
    const unicode = (Array.isArray(unicodeRaw) ? unicodeRaw : Array.isArray(unicodeRaw.findings) ? unicodeRaw.findings : [])
      .filter((u) => u && typeof u === "object")
      .map((u) => ({ where: u.where, kind: u.kind, sample_escaped: String(u.sample_escaped || u.sample || ""), skeleton: String(u.skeleton || "") }));
    const userModel = pick(v.userModel, v.user_model, f.user_model) || null;
    return {
      verdict,
      score,
      tone: toneOf(verdict, score),
      flags,
      codes: allCodes,
      explanationEn: String(pick(v.explanationEn, v.citizen_explanation_en, f.citizen_explanation_en) || ""),
      explanationAr: String(pick(v.explanationAr, v.citizen_explanation_ar, f.citizen_explanation_ar) || ""),
      auth: auth
        ? { spf: authValue(auth.spf), dkim: authValue(auth.dkim), dmarc: authValue(auth.dmarc) }
        : null,
      hasHeaders: !!hasHeaders,
      campaigns: (pick(f.campaigns, v.campaigns) || [])
        .filter((c) => c && typeof c === "object")
        .map((c) => ({ id: c.id, match: c.match, points: c.points, title_en: String(c.title_en || c.titleEn || ""), title_ar: String(c.title_ar || c.titleAr || "") })),
      unicode,
      scanId: pick(v.scanId, v.scan_id, f.scan_id) || null,
      features: pick(f.model_features, v.model_features, v.features) || null,
      userModel,
      summary: resp && resp.verdict && typeof resp.verdict === "object" ? resp.verdict : null,
    };
  }

  /**
   * Keep the original source under the cap: all headers + as much body as fits.
   * Returns {raw, truncated}. (The server then knows DKIM body hashes can't be checked.)
   */
  function capRaw(raw, cap = RAW_CAP_BYTES) {
    const s = String(raw || "");
    const enc = typeof TextEncoder !== "undefined" ? new TextEncoder() : null;
    const bytes = (x) => (enc ? enc.encode(x).length : x.length * 3);
    if (s.length <= cap / 3 || bytes(s) <= cap) return { raw: s, truncated: false };
    const sep = s.search(/\r?\n\r?\n/);
    const note = "\r\n\r\n[Saqr: message truncated]\r\n";
    let head = sep >= 0 ? s.slice(0, sep) : s.slice(0, 65536);
    if (bytes(head) > cap / 2) head = head.slice(0, Math.floor(cap / 6));
    let budget = cap - bytes(head) - bytes(note) - 8;
    let body = sep >= 0 ? s.slice(sep) : "";
    // Characters can be up to 3 bytes; shrink until it fits.
    body = body.slice(0, Math.max(0, budget));
    while (body && bytes(body) > budget) body = body.slice(0, Math.floor(body.length * 0.9));
    return { raw: head + body + note, truncated: true };
  }

  /** Does this text look like an RFC 5322 message (headers, blank line, body)? */
  function looksLikeRawEmail(text) {
    const s = String(text || "").slice(0, 200000);
    if (!/\r?\n\r?\n/.test(s)) return false;
    const head = s.slice(0, s.search(/\r?\n\r?\n/));
    return /^(?:from|date|subject|received|message-id|return-path|delivered-to|mime-version|to):/im.test(head) &&
      /^[!-9;-~]+:/.test(head);
  }

  /** Model input (contract section 4) from what we know about a message. */
  function modelInput(meta, extra) {
    const m = meta || {};
    const e = extra || {};
    return {
      from_address: String(m.from_address || ""),
      from_name: String(m.from_name || ""),
      reply_to: String(m.reply_to || ""),
      subject: String(m.subject || ""),
      body_text: String(m.body_text || ""),
      link_domains: (m.links || []).map((l) => hostOf(l.href)).filter(Boolean).slice(0, 20),
      auth: e.auth ? { spf: e.auth.spf || "none", dkim: e.auth.dkim || "none", dmarc: e.auth.dmarc || "none" } : { spf: "none", dkim: "none", dmarc: "none" },
      flags: Array.isArray(e.flags) ? e.flags : [],
    };
  }

  /** Campaign-matcher input (contract section 3). */
  function campaignInput(meta) {
    const m = meta || {};
    const addr = String(m.from_address || "");
    return {
      sender_domain: addr.includes("@") ? addr.split("@").pop().toLowerCase() : "",
      link_domains: (m.links || []).map((l) => hostOf(l.href)).filter(Boolean),
      subject: String(m.subject || ""),
      body_text: String(m.body_text || ""),
      display_name: String(m.from_name || ""),
    };
  }

  /** Row badge level from local evidence: scam > suspicious > campaign > model > null. */
  function localLevel(findings, campaigns, model) {
    const fs = findings || [];
    const cs = campaigns || [];
    if (cs.some((c) => c.match === "ioc") || fs.some((f) => f.level === "scam")) return "scam";
    if (fs.some((f) => f.level === "suspicious")) return "suspicious";
    if (cs.length) return "campaign";
    if (model && model.available && Number(model.p_scam) >= MODEL_SCAM_P) return "model";
    return null;
  }

  async function sha256Hex(text) {
    const subtle = root.crypto && root.crypto.subtle;
    const data = new TextEncoder().encode(String(text));
    if (subtle) {
      const buf = await subtle.digest("SHA-256", data);
      return Array.from(new Uint8Array(buf), (b) => b.toString(16).padStart(2, "0")).join("");
    }
    // Fallback (no WebCrypto): FNV-1a 32 repeated — only used to dedupe, never for security.
    let h = 0x811c9dc5;
    for (const b of data) h = Math.imul(h ^ b, 0x01000193) >>> 0;
    return h.toString(16).padStart(8, "0").repeat(8);
  }

  function decodeEntities(s) {
    return String(s || "").replace(/&(#x[0-9a-f]+|#\d+|lt|gt|amp|quot|apos|#39|nbsp);/gi, (m, e) => {
      const k = e.toLowerCase();
      if (k === "lt") return "<";
      if (k === "gt") return ">";
      if (k === "amp") return "&";
      if (k === "quot") return '"';
      if (k === "apos") return "'";
      if (k === "nbsp") return " ";
      const cp = k.startsWith("#x") ? parseInt(k.slice(2), 16) : parseInt(k.slice(1), 10);
      return Number.isFinite(cp) && cp <= 0x10ffff ? String.fromCodePoint(cp) : m;
    });
  }

  const util = {
    HIGH_RISK_SCORE, SUSPICIOUS_SCORE, RAW_CAP_BYTES, BODY_CAP, LINKS_CAP, STR, BRANDS,
    pickLang, t, isDarkColor, unwrapLink, hostOf, regdom, isFreemail, parseAddress, punyDecode,
    toUnicodeHost, escapeNonAscii, skeleton, asciiSkeleton, localChecks, toneOf, normaliseResult,
    capRaw, looksLikeRawEmail, modelInput, campaignInput, localLevel, sha256Hex, decodeEntities,
  };

  // =============================================================================================
  // Browser part — everything below only runs inside a mail page.
  // =============================================================================================

  /** chrome.runtime.sendMessage that never throws: resolves {ok:false,error} instead. */
  function send(msg) {
    return new Promise((resolve) => {
      try {
        if (!root.chrome || !chrome.runtime || !chrome.runtime.sendMessage) return resolve({ ok: false, error: "no runtime" });
        chrome.runtime.sendMessage(msg, (resp) => {
          const err = chrome.runtime.lastError;
          if (err) resolve({ ok: false, error: String(err.message || err) });
          else resolve(resp && typeof resp === "object" ? resp : { ok: false, error: "empty response" });
        });
      } catch (err) {
        resolve({ ok: false, error: String((err && err.message) || err) }); // extension reloaded etc.
      }
    });
  }

  /** Create an element with text only (never HTML). */
  function el(tag, props, children) {
    const n = document.createElement(tag);
    const p = props || {};
    if (p.cls) n.className = p.cls;
    if (p.text != null) n.textContent = String(p.text);
    if (p.attrs) for (const [k, v] of Object.entries(p.attrs)) if (v != null) n.setAttribute(k, String(v));
    if (p.on) for (const [k, fn] of Object.entries(p.on)) n.addEventListener(k, fn);
    for (const c of children || []) if (c) n.appendChild(c);
    return n;
  }

  function addStyles(shadow, css) {
    try {
      const sheet = new CSSStyleSheet();
      sheet.replaceSync(css);
      shadow.adoptedStyleSheets = [sheet];
    } catch {
      const s = document.createElement("style");
      s.textContent = css;
      shadow.appendChild(s);
    }
  }

  // Saqr brand tokens (frontend/DESIGN.md) for every Shadow DOM widget, light and dark.
  const FALCON_MASK = "url(\"data:image/svg+xml,%3Csvg xmlns=%27http://www.w3.org/2000/svg%27 viewBox=%2720 20 472 472%27%3E%3Cpath fill-rule=%27evenodd%27 d=%27M260%2024L354%2051L371%2078L394%2097C403%20110%20405%20128%20400%20146L390%20172L380%20145L354%20146L344%20182L352%20203L424%20284L368%20379L274%20219L341%20136L289%20141L213%20249L128%20312L159%20369L168%20306L248%20244L163%20402L89%20284L145%20218L179%2081ZM210%20101L259%2089L259%2097L283%20121L317%20112L253%20164ZM191%20127L206%20150L177%20184ZM211%20212L196%20234L153%20268L161%20238ZM323%20188L356%20272L299%20222ZM357%2097L371%20106L362%20119L344%20116ZM259%20250L294%20427L254%20489L253%20303L227%20453L188%20382ZM270%20237L344%20362L311%20444Z%27/%3E%3C/svg%3E\")";
  const BASE_CSS = String.raw`
    :host { all: initial; display: block; font: 14px/1.5 Inter, "Segoe UI Variable Text", "Segoe UI", system-ui, -apple-system, Tahoma, "IBM Plex Sans Arabic", sans-serif; }
    * { box-sizing: border-box; }
    [lang="ar"] { font-family: "IBM Plex Sans Arabic", "Segoe UI", Tahoma, "Geeza Pro", sans-serif; }
    .w { --surface:#ffffff; --muted:#f1eee6; --line:#e6e2d8; --ink:#111315; --soft:#475569;
         --primary:#111315; --primary-hover:#1e293b; --on-primary:#faf8f5; --focus:#111315;
         --safe-fill:#10b981; --suspicious-fill:#f59e0b; --scam-fill:#dc2626;
         --safe:#047857; --safe-bg:#e8f6ef; --warn:#92400e; --warn-bg:#fdf3e1; --bad:#b91c1c; --bad-bg:#fcebeb;
         --info:#475569; --info-bg:#ffffff; --chip:#f1eee6; --bg:var(--surface); --accent:var(--primary);
         --shadow: 0 1px 2px rgba(17,19,21,.04), 0 8px 24px -12px rgba(17,19,21,.14); color: var(--ink); }
    .w.dark { --surface:#171a1f; --muted:#1f232a; --line:#2a2f37; --ink:#faf8f5; --soft:#a3acb9;
         --primary:#faf8f5; --primary-hover:#e7e3da; --on-primary:#111315; --focus:#faf8f5;
         --safe:#34d399; --safe-bg:#0f2a21; --warn:#fbbf24; --warn-bg:#2e2310; --bad:#f87171; --bad-bg:#311617;
         --info:#a3acb9; --info-bg:#171a1f; --chip:#1f232a;
         --shadow: 0 1px 2px rgba(0,0,0,.4), 0 12px 32px -16px rgba(0,0,0,.6); }
    button { font: inherit; font-weight: 600; cursor: pointer; border-radius: 12px; border: 1px solid var(--line);
             background: var(--surface); color: var(--ink); padding: 6px 14px; min-height: 34px; }
    button:hover { background: var(--muted); }
    button:focus-visible { outline: 2px solid var(--focus); outline-offset: 2px; }
    button.primary { background: var(--primary); border-color: var(--primary); color: var(--on-primary); }
    button.primary:hover { background: var(--primary-hover); border-color: var(--primary-hover); }
    .hidden { display: none !important; }
  `;

  const BANNER_CSS = BASE_CSS + String.raw`
    .w { margin: 8px 0 12px; border: 1px solid var(--line); border-radius: 18px; background: var(--surface);
         box-shadow: var(--shadow); padding: 14px 16px; }
    .w.safe { background: var(--surface); }
    .w.suspicious { background: var(--warn-bg); border-color: transparent; }
    .w.dangerous { background: var(--bad-bg); border-color: transparent; }
    .top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .dot { width: 10px; height: 10px; border-radius: 50%; background: var(--info); flex: none; }
    .safe .dot { background: var(--safe-fill); } .suspicious .dot { background: var(--suspicious-fill); } .dangerous .dot { background: var(--scam-fill); }
    .scanning .dot { animation: pulse 1s ease-in-out infinite; }
    @keyframes pulse { 50% { opacity: .25; } }
    @media (prefers-reduced-motion: reduce) { .scanning .dot { animation: none; } }
    .title { font-weight: 600; font-size: 15px; }
    .safe .title { color: var(--safe); } .suspicious .title { color: var(--warn); } .dangerous .title { color: var(--bad); }
    .score { margin-inline-start: auto; font-weight: 600; font-size: 13px; font-variant-numeric: tabular-nums; color: var(--soft); }
    .by { font-size: 12px; font-weight: 500; color: var(--soft); }
    .x { border: none; background: transparent; padding: 0 6px; min-height: 0; font-size: 18px; line-height: 1; color: var(--soft); }
    .x:hover { background: transparent; color: var(--ink); }
    p { margin: 8px 0 0; color: var(--ink); }
    ul { margin: 8px 0 0; padding-inline-start: 20px; }
    li { margin: 2px 0; }
    .chips { display: flex; flex-wrap: wrap; gap: 6px; margin-top: 8px; }
    .chip { font-size: 12px; font-weight: 600; padding: 2px 10px; border-radius: 9999px; background: var(--chip); color: var(--soft); }
    .chip.pass { color: var(--safe); } .chip.fail { color: var(--bad); }
    .evidence { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 12px; direction: ltr; unicode-bidi: isolate; }
    .actions { display: flex; flex-wrap: wrap; gap: 8px; margin-top: 12px; }
    .note { font-size: 12px; color: var(--soft); margin-top: 8px; }
  `;

  const DIALOG_CSS = BASE_CSS + String.raw`
    .back { position: fixed; inset: 0; background: rgba(17,19,21,.5); display: flex; align-items: center; justify-content: center; z-index: 2147483647; }
    .w { background: var(--surface); border-radius: 18px; max-width: 440px; width: calc(100% - 32px); padding: 24px;
         border: 1px solid var(--line); box-shadow: 0 24px 60px -20px rgba(17,19,21,.45); }
    h2 { margin: 0 0 8px; font-size: 20px; font-weight: 600; line-height: 1.25; color: var(--bad); }
    p { margin: 0 0 12px; font-size: 15px; line-height: 1.55; }
    .url { font-family: ui-monospace, "Cascadia Mono", Consolas, monospace; font-size: 13px; word-break: break-all; color: var(--ink);
           background: var(--muted); border-radius: 12px; padding: 8px 10px; direction: ltr; unicode-bidi: isolate; }
    .actions { display: flex; gap: 8px; justify-content: flex-end; flex-wrap: wrap; margin-top: 16px; }
    .actions button { min-height: 44px; }
  `;

  const SCANALL_CSS = BASE_CSS + String.raw`
    .w { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; max-width: 440px; padding: 6px 8px 6px 12px;
         background: var(--surface); border: 1px solid var(--line); border-radius: 9999px; box-shadow: var(--shadow); font-size: 13px; }
    .w.open { border-radius: 18px; }
    .logo { width: 18px; height: 18px; flex: none; background: var(--ink); -webkit-mask: ${FALCON_MASK} center / contain no-repeat; mask: ${FALCON_MASK} center / contain no-repeat; }
    .msg { color: var(--soft); }
    .bar { height: 4px; width: 100%; background: var(--muted); border-radius: 4px; overflow: hidden; }
    .bar i { display: block; height: 100%; width: 0; background: var(--primary); transition: width .2s; }
    .x { border: none; background: transparent; padding: 0 4px; min-height: 0; font-size: 16px; color: var(--soft); }
    .x:hover { background: transparent; color: var(--ink); }
  `;

  /**
   * Start the mail shield for one provider. The adapter (gmail.js / outlook.js) knows the page; this
   * controller does everything else. Adapter shape:
   *   provider, label, selectorsVersion, canFetchRaw,
   *   observeRoot(): Element|null
   *   listRows(): [{el, id, badgeAnchor:{parent, before}, meta}]       visible inbox rows
   *   openMessages(): [{el, id, body, bannerAnchor:{parent, before}, meta}]
   *   fetchRaw(item): Promise<string|null>  (only when canFetchRaw)
   *   isSpamView(): boolean
   *   selectedRowId(): string|null    (optional; Outlook: row of the open message)
   *   health(): object                (selector health snapshot for console.debug)
   */
  function start(adapter) {
    if (!root.document || !adapter || start.started) return;
    start.started = true;

    const state = {
      settings: null,
      settingsAt: 0,
      feed: null,
      feedAt: 0,
      keys: new Map(), // provider id -> sha256 message_key
      results: new Map(), // message_key -> {status:"scanning"|"done"|"error", result, error, local}
      rowLocal: new Map(), // message_key -> {level, findings, campaigns, model}
      rowChecked: new Set(), // provider row ids that already had their automatic quick local check
      inflight: new Map(),
      labelled: new Set(),
      scanAll: null, // {total, done, cancelled, counts}
      healthLogged: new Set(),
      banners: new Map(), // message_key -> host element
      guarded: new WeakSet(),
      dismissed: new Set(),
      pageRaw: new Map(), // message_key -> original source the user opened on the page (Outlook "View message source")
      lastPageRaw: null,
    };

    const lang = () => pickLang(document.documentElement.getAttribute("lang"), navigator.languages || [navigator.language]);
    const dark = () => {
      const candidates = [adapter.observeRoot && adapter.observeRoot(), document.body, document.documentElement];
      for (const n of candidates) {
        if (!n) continue;
        const d = isDarkColor(getComputedStyle(n).backgroundColor);
        if (d !== null) return d;
      }
      return !!(root.matchMedia && matchMedia("(prefers-color-scheme: dark)").matches);
    };

    function logHealth(reason) {
      try {
        const h = Object.assign({ provider: adapter.provider, selectors: adapter.selectorsVersion, reason }, adapter.health ? adapter.health() : {});
        const sig = JSON.stringify(h);
        if (state.healthLogged.has(sig) || state.healthLogged.size > 20) return;
        state.healthLogged.add(sig);
        console.debug("[SAQR] selector health", h);
      } catch {
        /* never throw into the page */
      }
    }

    async function settings() {
      if (state.settings && Date.now() - state.settingsAt < 60000) return state.settings;
      const r = await send({ type: "emailSettings" });
      state.settings = r && r.ok !== false ? r : { autoScan: true };
      state.settingsAt = Date.now();
      return state.settings;
    }

    async function feed() {
      if (state.feedAt && Date.now() - state.feedAt < (state.feed ? FEED_TTL_MS : 60000)) return state.feed;
      if (state.feedJob) return state.feedJob;
      state.feedJob = send({ type: "campaigns" }).then((r) => {
        if (r && r.ok && r.feed) state.feed = r.feed;
        state.feedAt = Date.now(); // a failure is retried after one minute, not once per row
        state.feedJob = null;
        return state.feed;
      });
      return state.feedJob;
    }

    async function keyFor(id, meta) {
      const base = id ? adapter.provider + ":" + id : adapter.provider + ":" + [meta.from_address, meta.subject, meta.date, String(meta.body_text || "").slice(0, 2000)].join("|");
      if (state.keys.has(base)) return state.keys.get(base);
      const k = await sha256Hex(base);
      if (state.keys.size > 5000) state.keys.clear();
      state.keys.set(base, k);
      return k;
    }

    // ----------------------------------------------------------------- local (cheap) checks
    async function localFor(meta) {
      const findings = localChecks(meta);
      let campaigns = [];
      const C = root.SaqrCampaigns;
      const f = await feed();
      if (f && C && typeof C.matchFeed === "function") {
        try {
          campaigns = C.matchFeed(f, campaignInput(meta));
        } catch {
          campaigns = [];
        }
      }
      const mp = await send({ type: "modelPredict", input: modelInput(meta, { flags: findings.map((x) => x.code) }) });
      const model = mp && mp.ok ? { available: !!mp.available, p_scam: mp.p_scam, labels: mp.labels } : null;
      return { findings, campaigns, model, level: localLevel(findings, campaigns, model) };
    }

    // ----------------------------------------------------------------- backend scan
    async function fullScan(key, item, { force = false, priority = null } = {}) {
      const cur = state.results.get(key);
      if (!force && cur && cur.status === "done") return cur;
      if (state.inflight.has(key)) return state.inflight.get(key);
      const job = (async () => {
        state.results.set(key, { status: "scanning" });
        let raw = null;
        let truncated = false;
        if (adapter.canFetchRaw && adapter.fetchRaw) {
          try {
            const got = await adapter.fetchRaw(item);
            if (got && looksLikeRawEmail(got)) ({ raw, truncated } = capRaw(got));
          } catch {
            raw = null;
          }
          if (!raw) logHealth("raw original not available, using page text");
        }
        if (!raw && state.pageRaw.has(key)) ({ raw, truncated } = capRaw(state.pageRaw.get(key)));
        const msg = { type: "emailScan", provider: adapter.provider, message_key: key, meta: Object.assign({}, item.meta, { provider: adapter.provider, message_key: key }) };
        if (raw) msg.raw = raw;
        if (truncated) msg.truncated = true;
        if (force) msg.force = true;
        if (priority) msg.priority = priority; // an opened email jumps the background's scan queue
        const resp = await send(msg);
        let rec;
        if (resp && resp.ok) rec = { status: "done", result: normaliseResult(resp), meta: item.meta };
        else rec = { status: "error", error: String((resp && resp.error) || "unknown error").slice(0, 200), meta: item.meta };
        state.results.set(key, rec);
        return rec;
      })();
      state.inflight.set(key, job);
      try {
        return await job;
      } finally {
        state.inflight.delete(key);
      }
    }

    // ----------------------------------------------------------------- row badges
    function paintBadge(row, key) {
      try {
        const anchor = row.badgeAnchor;
        if (!anchor || !anchor.parent) return;
        // The anchor can move (e.g. subject not found for a moment): never leave a second badge behind.
        if (row.el && row.el.querySelectorAll) for (const old of row.el.querySelectorAll(".saqr-row-badge")) if (old.parentNode !== anchor.parent) old.remove();
        let badge = anchor.parent.querySelector(":scope > .saqr-row-badge");
        const rec = state.results.get(key);
        const loc = state.rowLocal.get(key);
        let level = null, scope = "local", text = null;
        if (rec && rec.status === "done") {
          scope = "full";
          // The backend saw the whole message (and runs the same look-alike checks): it decides.
          level = rec.result.tone === "dangerous" ? "scam" : rec.result.tone === "suspicious" ? "suspicious" : "safe";
        } else if (rec && rec.status === "scanning") {
          level = loc && loc.level ? loc.level : null;
          text = t("rowScanning", lang());
          scope = "scanning";
        } else if (loc) {
          level = loc.level || (adapter.canFetchRaw ? null : "safe");
          if (!loc.level && !adapter.canFetchRaw) text = t("rowOpen", lang());
        }
        if (!level && !text) {
          if (badge) badge.remove();
          return;
        }
        if (!badge) {
          badge = document.createElement("span");
          badge.className = "saqr-row-badge";
          anchor.parent.insertBefore(badge, anchor.before && anchor.before.parentNode === anchor.parent ? anchor.before : anchor.parent.firstChild);
        }
        const label = text || t({ scam: "rowScam", suspicious: "rowSuspicious", campaign: "rowCampaign", model: "rowModel", safe: "rowSafe" }[level], lang());
        if (level) badge.setAttribute("data-saqr-row", level);
        else badge.removeAttribute("data-saqr-row");
        badge.setAttribute("data-saqr-scope", scope);
        badge.setAttribute("data-saqr-theme", state.dark ? "dark" : "light");
        badge.setAttribute("data-saqr-message-key", key);
        const tip = [];
        if (rec && rec.status === "done" && rec.result.score != null) tip.push(t("score", lang(), rec.result.score));
        if (loc) for (const f of loc.findings) tip.push(lang() === "ar" ? f.ar : f.en);
        if (loc) for (const c of loc.campaigns) tip.push(t("campaign", lang(), lang() === "ar" ? c.title_ar : c.title_en));
        if (scope === "local" && !adapter.canFetchRaw) tip.push(t("localOnly", lang()));
        badge.title = tip.join("\n");
        if (badge.textContent !== label) badge.textContent = label;
      } catch {
        /* row re-rendered under us */
      }
    }

    // ----------------------------------------------------------------- banner
    function bannerFor(msg, key) {
      let host = state.banners.get(key);
      const anchor = msg.bannerAnchor;
      if (!anchor || !anchor.parent) return null;
      if (!host || !host.isConnected) {
        host = document.createElement("saqr-mail-banner");
        host.setAttribute("data-saqr-message-key", key);
        const shadow = host.attachShadow({ mode: "closed" });
        addStyles(shadow, BANNER_CSS);
        host._saqr = { shadow, wrap: el("div", { cls: "w" }) }; // own property, isolated world only
        shadow.appendChild(host._saqr.wrap);
        state.banners.set(key, host);
      }
      if (host.parentNode !== anchor.parent || (anchor.before && host.nextSibling !== anchor.before)) {
        anchor.parent.insertBefore(host, anchor.before && anchor.before.parentNode === anchor.parent ? anchor.before : anchor.parent.firstChild);
      }
      return host;
    }

    function renderBanner(host, msg, key, local) {
      const L = lang();
      const rec = state.results.get(key);
      const wrap = host._saqr.wrap;
      const tone = !rec || rec.status === "scanning" ? "scanning" : rec.status === "error" ? "error" : rec.result.tone;
      const r = rec && rec.status === "done" ? rec.result : null;
      host.setAttribute("data-saqr-verdict", { scanning: "SCANNING", error: "ERROR", safe: "SAFE", suspicious: "SUSPICIOUS", dangerous: "HIGH-RISK SCAM" }[tone] || "ERROR");
      if (r && r.score != null) host.setAttribute("data-saqr-score", String(r.score));
      else host.removeAttribute("data-saqr-score");

      wrap.className = "w " + tone + (dark() ? " dark" : "");
      wrap.setAttribute("dir", L === "ar" ? "rtl" : "ltr");
      wrap.setAttribute("lang", L);
      wrap.setAttribute("role", tone === "dangerous" ? "alert" : "status");
      wrap.replaceChildren();

      const titleKey = { scanning: "tScanning", safe: "tSafe", suspicious: "tSuspicious", dangerous: "tDangerous", error: "tError" }[tone];
      const top = el("div", { cls: "top" }, [
        el("span", { cls: "dot", attrs: { "aria-hidden": "true" } }),
        el("span", { cls: "title", text: t(titleKey, L) }),
        el("span", { cls: "by", text: "· " + t("brand", L) }),
        r && r.score != null ? el("span", { cls: "score", text: t("score", L, r.score) }) : null,
        el("button", {
          cls: "x",
          text: "×",
          attrs: { title: t("close", L), "aria-label": t("close", L) },
          on: { click: () => { state.dismissed.add(key); host.remove(); } },
        }),
      ]);
      wrap.appendChild(top);

      if (tone === "error") {
        // The extension was reloaded/updated: this old content script can no longer reach it.
        const stale = !!(rec && /context invalidated/i.test(String(rec.error || "")));
        wrap.appendChild(el("p", { text: t(stale ? "errReload" : "errHint", L) }));
        if (rec && rec.error) wrap.appendChild(el("div", { cls: "note", text: rec.error }));
      }

      if (r) {
        const expl = L === "ar" ? r.explanationAr || r.explanationEn : r.explanationEn || r.explanationAr;
        if (expl) wrap.appendChild(el("p", { text: expl }));
        else if (tone === "safe") wrap.appendChild(el("p", { text: t("safeHint", L) }));
        const reasons = r.flags.slice(0, 3);
        if (reasons.length && tone !== "safe") {
          wrap.appendChild(el("ul", null, reasons.map((f) => el("li", { text: L === "ar" ? f.ar : f.en }))));
        }
      }

      // Evidence: campaign match + look-alike letters (backend first, else our local findings).
      const campaigns = (r && r.campaigns.length ? r.campaigns : local ? local.campaigns : []) || [];
      for (const c of campaigns.slice(0, 2)) {
        wrap.appendChild(el("div", { cls: "note", text: t("campaign", L, L === "ar" ? c.title_ar || c.title_en : c.title_en || c.title_ar) }));
      }
      // One line per sample: the backend can report the same look-alike twice (mixed_script + punycode).
      const uni = r ? r.unicode.filter((u, i, a) => a.findIndex((x) => x.sample_escaped === u.sample_escaped && x.skeleton === u.skeleton) === i) : [];
      if (uni.length) {
        for (const u of uni.slice(0, 2)) {
          // The sample is shown escaped (PаyPal) and always left-to-right, even in Arabic.
          const sample = u.sample_escaped || u.kind || "";
          const shown = u.skeleton && u.skeleton !== sample ? sample + "  →  " + u.skeleton : sample;
          wrap.appendChild(el("div", { cls: "note" }, [
            document.createTextNode(t("lookalike", L) + " "),
            el("bdi", { cls: "evidence", text: shown, attrs: { dir: "ltr" } }),
          ]));
        }
      } else if (local && local.findings.length && (!r || tone !== "safe")) {
        for (const f of local.findings.slice(0, 2)) wrap.appendChild(el("div", { cls: "note", text: L === "ar" ? f.ar : f.en }));
      }

      // SPF / DKIM / DMARC chips, or "headers not verified".
      if (r) {
        const chips = el("div", { cls: "chips" });
        const checked = r.auth && ["spf", "dkim", "dmarc"].some((k) => !["not_checked", "none"].includes(r.auth[k]));
        if (r.hasHeaders && checked) {
          for (const k of ["spf", "dkim", "dmarc"]) {
            const v = r.auth[k];
            const cls = v === "pass" ? "chip pass" : ["fail", "softfail", "permerror"].includes(v) ? "chip fail" : "chip";
            chips.appendChild(el("span", { cls, text: k.toUpperCase() + ": " + v.replace("_", " ") }));
          }
        } else {
          chips.appendChild(el("span", { cls: "chip", text: t("headersNotVerified", L) }));
        }
        wrap.appendChild(chips);
        if (!(r.hasHeaders && checked) && adapter.rawFromPage) wrap.appendChild(el("div", { cls: "note", text: t("sourceHint", L) }));
      }

      if (tone === "dangerous" && msg.body) wrap.appendChild(el("div", { cls: "note", text: t("linksGuarded", L) }));

      // Buttons.
      const status = el("div", { cls: "note hidden", attrs: { "aria-live": "polite" } });
      const actions = el("div", { cls: "actions" });
      if (r) {
        actions.appendChild(el("button", { cls: "primary", text: t("fullReport", L), on: { click: () => openReport(key, r, status) } }));
        actions.appendChild(el("button", { text: t("isScam", L), on: { click: () => label(msg, key, "scam", "user", status) } }));
        actions.appendChild(el("button", { text: t("isSafe", L), on: { click: () => label(msg, key, "ham", "user", status) } }));
      }
      if (tone !== "scanning") {
        actions.appendChild(el("button", { text: t("rescan", L), on: { click: () => scanOpen(msg, { force: true }) } }));
      }
      if (actions.childNodes.length) wrap.appendChild(actions);
      wrap.appendChild(status);
    }

    async function openReport(key, r, status) {
      // The background opens blocked.html?mode=check&d=<its summary> from its own cache.
      const resp = await send({ type: "openEmailVerdict", provider: adapter.provider, message_key: key });
      if (resp && resp.ok) return;
      const d = r.summary || { kind: "email", verdict: r.verdict, score: r.score, flags: r.flags.slice(0, 6), explanationEn: r.explanationEn, explanationAr: r.explanationAr, scanId: r.scanId };
      try {
        // Fallback (older background): open the extension's own result page ourselves.
        const url = chrome.runtime.getURL("blocked.html") + "?mode=check&d=" + encodeURIComponent(JSON.stringify(d));
        const w = window.open(url, "_blank", "noopener,noreferrer");
        if (w === null && status) {
          /* noopener returns null even on success in some browsers; nothing to do */
        }
      } catch {
        if (status) {
          status.textContent = t("reportFail", lang());
          status.classList.remove("hidden");
        }
      }
    }

    async function label(msg, key, lbl, source, status) {
      const rec = state.results.get(key);
      const r = rec && rec.status === "done" ? rec.result : null;
      const input = modelInput(msg.meta, { auth: r && r.auth, flags: r ? r.codes : [] });
      const resp = await send({ type: "modelLabel", input, label: lbl, source, scan_id: r ? r.scanId : null, features: r ? r.features : null, message_key: key });
      state.labelled.add(key);
      if (!status) return resp;
      const L = lang();
      status.textContent = resp && resp.ok ? (resp.labels != null ? t("thanks", L, resp.labels) : t("thanksShort", L)) : t("labelFail", L);      status.classList.remove("hidden");
      return resp;
    }

    // ----------------------------------------------------------------- link guard (dangerous mail)
    function guardLinks(msg, key) {
      const body = msg.body;
      if (!body || state.guarded.has(body)) return;
      state.guarded.add(body);
      const isDangerous = () => {
        const rec = state.results.get(key);
        return rec && rec.status === "done" && rec.result.tone === "dangerous";
      };
      const handler = (ev) => {
        try {
          if (!isDangerous()) return;
          if (ev.type === "auxclick" && ev.button !== 1) return;
          const a = ev.target && ev.target.closest ? ev.target.closest("a[href]") : null;
          if (!a || !body.contains(a)) return;
          const href = a.getAttribute("originalsrc") || a.href;
          if (!/^https?:/i.test(href)) return;
          ev.preventDefault();
          ev.stopImmediatePropagation();
          confirmLink(href);
        } catch {
          /* fail safe */
        }
      };
      body.addEventListener("click", handler, true);
      body.addEventListener("auxclick", handler, true);
      markLinks(body, key);
    }

    function markLinks(body, key) {
      const rec = state.results.get(key);
      const on = rec && rec.status === "done" && rec.result.tone === "dangerous";
      for (const a of body.querySelectorAll("a[href]")) {
        if (on) a.setAttribute("data-saqr-link", "guarded");
        else a.removeAttribute("data-saqr-link");
      }
    }

    function confirmLink(href) {
      const L = lang();
      const host = document.createElement("saqr-link-guard");
      const shadow = host.attachShadow({ mode: "closed" });
      addStyles(shadow, DIALOG_CSS);
      const close = () => host.remove();
      const real = unwrapLink(href);
      const stay = el("button", { cls: "primary", text: t("gStay", L), on: { click: close } });
      const box = el("div", { cls: "w" + (dark() ? " dark" : ""), attrs: { role: "alertdialog", "aria-modal": "true", dir: L === "ar" ? "rtl" : "ltr", lang: L } }, [
        el("h2", { text: t("gTitle", L) }),
        el("p", { text: t("gBody", L) }),
        el("div", { cls: "url", text: real }),
        el("div", { cls: "actions" }, [
          el("button", { text: t("gOpen", L), on: { click: () => { close(); window.open(href, "_blank", "noopener,noreferrer"); } } }),
          stay,
        ]),
      ]);
      const back = el("div", { cls: "back", on: { click: (e) => { if (e.target === back) close(); } } }, [box]);
      back.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
      shadow.appendChild(back);
      document.documentElement.appendChild(host);
      stay.focus();
    }

    // ----------------------------------------------------------------- opened messages
    async function scanOpen(msg, { force = false } = {}) {
      try {
        const key = msg.key || (msg.key = await keyFor(msg.id, msg.meta));
        if (force) state.dismissed.delete(key);
        const host = bannerFor(msg, key);
        if (!host) return logHealth("no place for the banner");
        if (!msg.meta.from_address) logHealth("sender address not found");
        const local = await localFor(msg.meta);
        state.rowLocal.set(key, local);
        if (force || !state.results.has(key) || state.results.get(key).status === "error") {
          state.results.set(key, { status: "scanning" });
        }
        renderBanner(host, msg, key, local);
        const rec = await fullScan(key, msg, { force, priority: "open" });
        const h2 = bannerFor(msg, key);
        if (h2 && !state.dismissed.has(key)) renderBanner(h2, msg, key, local);
        if (msg.body) {
          if (rec.status === "done" && rec.result.tone === "dangerous") guardLinks(msg, key);
          markLinks(msg.body, key);
        }
        // Outlook: the inbox row of the open message gets the full verdict too.
        const selId = adapter.selectedRowId && adapter.selectedRowId();
        if (selId) {
          const rowKey = await keyFor(selId, {});
          if (rowKey !== key && rec.status === "done") state.results.set(rowKey, rec);
        }
        await maybeLearnSpam(msg, key);
      } catch (err) {
        logHealth("scan failed: " + String((err && err.message) || err).slice(0, 80));
      }
    }

    /** Outlook: the open message's inbox row gets its full verdict once the list has loaded. */
    async function linkSelectedRow(msg, key) {
      const rec = state.results.get(key);
      const selId = adapter.selectedRowId && adapter.selectedRowId();
      if (!selId || !rec || rec.status !== "done") return;
      const rowKey = await keyFor(selId, {});
      if (rowKey === key || state.results.get(rowKey) === rec) return;
      const norm = (s) => String(s || "").replace(/\s+/g, " ").trim();
      const row = safe(() => adapter.listRows(), []).find((r) => r.id === selId);
      if (!row || !norm(row.meta.subject) || norm(row.meta.subject) !== norm(msg.meta.subject)) return; // pane not switched yet
      state.results.set(rowKey, rec);
    }

    async function maybeLearnSpam(msg, key) {
      if (state.labelled.has(key) || !adapter.isSpamView || !adapter.isSpamView()) return;
      const s = await settings();
      if (!s || (s.learnSpam !== true && s.spamFolderLearning !== true)) return; // opt-in only (emailSettings.learnSpam)
      await label(msg, key, "scam", "spam_folder", null);
    }

    // ----------------------------------------------------------------- "Scan all" control
    let scanAllHost = null;
    let ui = null;

    function ensureScanAll(rowCount, hasOpen) {
      if (!scanAllHost || !scanAllHost.isConnected) {
        scanAllHost = document.createElement("saqr-scan-all");
        const shadow = scanAllHost.attachShadow({ mode: "closed" });
        addStyles(shadow, SCANALL_CSS);
        ui = {
          wrap: el("div", { cls: "w" }),
          logo: el("span", { cls: "logo", attrs: { "aria-hidden": "true" } }),
          scan: el("button", { cls: "primary", on: { click: () => runScanAll() } }),
          scanThis: el("button", { on: { click: () => scanThisClick() } }),
          cancel: el("button", { cls: "hidden", on: { click: () => { if (state.scanAll) state.scanAll.cancelled = true; } } }),
          msg: el("span", { cls: "msg", attrs: { "aria-live": "polite" } }),
          bar: el("div", { cls: "bar hidden" }, [el("i")]),
          x: el("button", { cls: "x", text: "×", on: { click: () => { ui.hiddenByUser = true; scanAllHost.style.display = "none"; } } }),
        };
        ui.wrap.append(ui.logo, ui.scan, ui.scanThis, ui.cancel, ui.msg, ui.x, ui.bar);
        shadow.appendChild(ui.wrap);
        document.documentElement.appendChild(scanAllHost);
      }
      const L = lang();
      ui.wrap.className = "w" + (dark() ? " dark" : "") + (state.scanAll || ui.msg.textContent ? " open" : "");
      ui.wrap.setAttribute("dir", L === "ar" ? "rtl" : "ltr");
      ui.wrap.setAttribute("lang", L);
      ui.scan.textContent = t("scanAll", L);
      ui.scanThis.textContent = t("scanThis", L);
      ui.cancel.textContent = t("cancel", L);
      ui.x.setAttribute("aria-label", t("close", L));
      ui.x.title = t("close", L);
      const busy = !!state.scanAll;
      ui.scan.classList.toggle("hidden", busy || rowCount === 0);
      ui.scanThis.classList.toggle("hidden", busy || !hasOpen || ui.autoScan !== false);
      ui.cancel.classList.toggle("hidden", !busy);
      const show = !ui.hiddenByUser && (rowCount > 0 || hasOpen || busy || !!ui.msg.textContent);
      scanAllHost.style.display = show ? "" : "none";
    }

    async function scanThisClick() {
      const msgs = safe(() => adapter.openMessages(), []);
      for (const m of msgs.slice(-3)) await scanOpen(m, { force: true });
    }

    async function runScanAll() {
      if (state.scanAll) return;
      const L = lang();
      const rows = safe(() => adapter.listRows(), []);
      if (!rows.length) {
        ui.msg.textContent = t("noRows", L);
        logHealth("scan all: no rows");
        return;
      }
      const run = { total: rows.length, done: 0, cancelled: false, counts: { scam: 0, suspicious: 0, safe: 0 }, localOnly: 0 };
      state.scanAll = run;
      ui.bar.classList.remove("hidden");
      const progress = () => {
        ui.msg.textContent = t("progress", L, run.done, run.total);
        ui.bar.firstChild.style.width = Math.round((run.done / Math.max(1, run.total)) * 100) + "%";
      };
      tick();
      progress();

      // Pass 1 — cheap local checks for every row, painted immediately.
      const items = [];
      for (const row of rows) {
        if (run.cancelled) break;
        try {
          const key = await keyFor(row.id, row.meta);
          state.rowLocal.set(key, await localFor(row.meta));
          paintBadge(row, key);
          items.push({ row, key });
        } catch {
          /* skip this row */
        }
      }
      // Pass 2 — full backend scans, one at a time (backend rate limit), only where we can get
      // the whole message without opening it (Gmail "Show original").
      let lastAt = 0;
      for (const { row, key } of items) {
        if (run.cancelled) break;
        const loc = state.rowLocal.get(key);
        if (adapter.canFetchRaw) {
          const prev = state.results.get(key);
          if (!(prev && prev.status === "done")) {
            const wait = SCAN_SPACING_MS - (Date.now() - lastAt);
            if (wait > 0) await sleep(wait);
            if (run.cancelled) break;
            lastAt = Date.now();
            state.results.set(key, { status: "scanning" });
            paintBadge(row, key);
            await fullScan(key, row);
          }
        } else {
          run.localOnly++;
        }
        paintBadge(liveRow(row) || row, key);
        const rec = state.results.get(key);
        const level = rec && rec.status === "done" ? (rec.result.tone === "dangerous" ? "scam" : rec.result.tone === "suspicious" ? "suspicious" : "safe") : null;
        const lv = level || (loc && loc.level) || "safe";
        if (lv === "scam") run.counts.scam++;
        else if (lv === "safe") run.counts.safe++;
        else run.counts.suspicious++;
        run.done++;
        progress();
      }
      const msg = run.cancelled
        ? t("cancelled", L) + " " + t("summary", L, run.counts.scam, run.counts.suspicious, run.counts.safe)
        : t("summary", L, run.counts.scam, run.counts.suspicious, run.counts.safe) + (run.localOnly ? ". " + t("summaryLocal", L) : "");
      state.scanAll = null;
      ui.bar.classList.add("hidden");
      ui.msg.textContent = msg;
      tick();
    }

    /**
     * Automatic quick local check of inbox rows (campaign feed, personal model, look-alike letters):
     * no backend call, one row at a time, each row once. Only a row with a finding gets a badge.
     */
    function checkRowsLocally(rows) {
      if (state.scanAll) return; // "Scan all" runs the same check itself
      for (const row of rows) {
        const base = adapter.provider + ":" + row.id;
        if (!row.id || state.rowChecked.has(base)) continue;
        if (state.rowChecked.size > 5000) state.rowChecked.clear();
        state.rowChecked.add(base);
        state.rowQueue = (state.rowQueue || Promise.resolve()).then(async () => {
          try {
            const key = await keyFor(row.id, row.meta);
            if (state.rowLocal.has(key) || state.results.has(key)) return;
            const local = await localFor(row.meta);
            if (!local.level || state.rowLocal.has(key)) return;
            state.rowLocal.set(key, local);
            const live = liveRow(row);
            if (live) paintBadge(live, key);
          } catch {
            /* a row we could not read: no badge */
          }
        });
      }
    }

    /** Gmail re-renders rows; find the current element for the same message. */
    function liveRow(row) {
      if (row.el && row.el.isConnected) return row;
      return safe(() => adapter.listRows(), []).find((r) => r.id && r.id === row.id) || null;
    }

    // ----------------------------------------------------------------- main loop
    function safe(fn, fallback) {
      try {
        return fn();
      } catch (err) {
        logHealth("adapter error: " + String((err && err.message) || err).slice(0, 80));
        return fallback;
      }
    }

    let tickTimer = null;
    let ticking = false;
    function schedule() {
      clearTimeout(tickTimer);
      tickTimer = setTimeout(() => tick(), TICK_MS);
    }

    async function tick() {
      if (ticking) return schedule();
      ticking = true;
      try {
        const s = await settings();
        state.dark = dark();
        const rows = safe(() => adapter.listRows(), []);
        const msgs = safe(() => adapter.openMessages(), []);
        if (ui) ui.autoScan = s.autoScan !== false;
        ensureScanAll(rows.length, msgs.length > 0);
        // Selector health: a mail page where we recognise nothing means Gmail/Outlook changed.
        if (!rows.length && !msgs.length && performance.now() > 8000) logHealth("no rows or messages found");

        // Repaint badges for rows we already know about (Gmail/Outlook re-render rows often).
        for (const row of rows) {
          const key = state.keys.get(adapter.provider + ":" + row.id);
          if (key && (state.rowLocal.has(key) || state.results.has(key))) paintBadge(row, key);
        }
        checkRowsLocally(rows);

        // Outlook: the user opened "View message source" -> rescan that message with real headers.
        const pr = adapter.rawFromPage ? safe(() => adapter.rawFromPage(), null) : null;
        if (pr && pr.raw && pr.raw !== state.lastPageRaw && looksLikeRawEmail(pr.raw)) {
          const same = (m) => !pr.from || !m.meta.from_address || m.meta.from_address.toLowerCase() === pr.from;
          const target = msgs.length === 1 ? (same(msgs[0]) ? msgs[0] : null) : msgs.find((m) => pr.from && m.meta.from_address && same(m)) || null;
          if (target) {
            state.lastPageRaw = pr.raw;
            const k = target.key || (target.key = await keyFor(target.id, target.meta));
            state.pageRaw.set(k, pr.raw);
            if (state.pageRaw.size > 20) state.pageRaw.delete(state.pageRaw.keys().next().value);
            scanOpen(target, { force: true });
          }
        }

        // Opened messages: banner + automatic scan (at most the last 3 expanded ones in a thread).
        for (const m of msgs.slice(-3)) {
          const key = m.key || (m.key = await keyFor(m.id, m.meta));
          if (state.dismissed.has(key)) continue;
          const existing = state.banners.get(key);
          if (existing && existing.isConnected) {
            if (m.body) markLinks(m.body, key);
            await linkSelectedRow(m, key); // Outlook: the list can load after the reading pane
            continue;
          }
          if (state.results.has(key) || state.inflight.has(key)) {
            const host = bannerFor(m, key);
            if (host) renderBanner(host, m, key, state.rowLocal.get(key));
            if (m.body && state.results.get(key)?.result?.tone === "dangerous") guardLinks(m, key);
            continue;
          }
          if (s.autoScan !== false) scanOpen(m);
          else await maybeLearnSpam(m, key);
        }
      } catch (err) {
        logHealth("tick failed: " + String((err && err.message) || err).slice(0, 80));
      } finally {
        ticking = false;
      }
    }

    // Watch the SPA: DOM changes (ignoring our own widgets) + URL hash changes.
    const OWN = /^(SAQR-MAIL-BANNER|SAQR-SCAN-ALL|SAQR-LINK-GUARD|SAQR-WIP-PILL)$/;
    const ours = (n) => !!n && (OWN.test(n.nodeName) || (n.classList && n.classList.contains("saqr-row-badge")));
    const observer = new MutationObserver((records) => {
      for (const r of records) {
        if (ours(r.target)) continue; // text change inside one of our badges
        const nodes = [...r.addedNodes, ...r.removedNodes];
        if (nodes.length && nodes.every(ours)) continue;
        return schedule();
      }
    });
    let observed = null;
    function observe() {
      const target = safe(() => adapter.observeRoot(), null) || document.body;
      if (!target || target === observed) return;
      observer.disconnect();
      observer.observe(target, { childList: true, subtree: true });
      observed = target;
    }
    setInterval(() => { observe(); }, 3000); // the main region can be replaced on navigation
    observe();
    window.addEventListener("hashchange", schedule);
    window.addEventListener("popstate", schedule);
    schedule();
  }

  function sleep(ms) {
    return new Promise((r) => setTimeout(r, ms));
  }

  /** Helpers for adapters: first element matching any selector of a list (data-driven tables). */
  function pick(rootEl, selectors, hits, name) {
    const list = Array.isArray(selectors) ? selectors : [selectors];
    for (let i = 0; i < list.length; i++) {
      let n = null;
      try {
        n = rootEl ? rootEl.querySelector(list[i]) : null;
      } catch {
        n = null;
      }
      if (n) {
        if (hits && name) hits[name] = i;
        return n;
      }
    }
    if (hits && name && !(name in hits)) hits[name] = -1;
    return null;
  }

  function pickAll(rootEl, selectors, hits, name) {
    const list = Array.isArray(selectors) ? selectors : [selectors];
    for (let i = 0; i < list.length; i++) {
      let ns = [];
      try {
        ns = rootEl ? Array.from(rootEl.querySelectorAll(list[i])) : [];
      } catch {
        ns = [];
      }
      if (ns.length) {
        if (hits && name) hits[name] = i;
        return ns;
      }
    }
    if (hits && name && !(name in hits)) hits[name] = -1;
    return [];
  }

  function isVisible(n) {
    return !!(n && n.getClientRects && n.getClientRects().length);
  }

  /** Visible links of a message body, unwrapped, capped (contract meta.links). */
  function collectLinks(body, attrPrefs) {
    const out = [];
    if (!body) return out;
    for (const a of body.querySelectorAll("a[href]")) {
      let href = "";
      for (const attr of attrPrefs || []) {
        const v = a.getAttribute(attr);
        if (v && /^https?:/i.test(v)) {
          href = v;
          break;
        }
      }
      href = unwrapLink(href || a.href || "");
      if (!/^https?:/i.test(href)) continue;
      out.push({ href: href.slice(0, 2000), text: String(a.textContent || "").replace(/\s+/g, " ").trim().slice(0, 300) });
      if (out.length >= LINKS_CAP) break;
    }
    return out;
  }

  function bodyText(body) {
    if (!body) return "";
    const s = String(body.innerText || body.textContent || "");
    return s.length > BODY_CAP ? s.slice(0, BODY_CAP) : s;
  }

  /** Define obj[name] computed on first read (message meta reads the body text: only when needed). */
  function lazy(obj, name, compute) {
    let done = false, value;
    Object.defineProperty(obj, name, {
      enumerable: true,
      configurable: true,
      get() {
        if (!done) {
          value = compute();
          done = true;
        }
        return value;
      },
    });
    return obj;
  }

  return { util, start, send, pick, pickAll, isVisible, collectLinks, bodyText, sleep, lazy };
});
