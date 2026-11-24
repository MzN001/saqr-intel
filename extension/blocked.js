// Saqr block / verdict page. Data arrives in the URL (?mode=block|check|error&d=<json>[&lang=en|ar]).
// Everything from the backend is inserted with textContent, never innerHTML.

const X_LIMIT = 280;
const $ = (id) => document.getElementById(id);

const params = new URLSearchParams(location.search);
const mode = params.get("mode") || "block";
// Page language: ?lang=, else the browser's language. The toggle in the header switches it.
let lang = (params.get("lang") || navigator.language || "en").toLowerCase().startsWith("ar") ? "ar" : "en";
let v = {};
try {
  v = JSON.parse(params.get("d") || "{}");
} catch {
  v = { error: "Could not read the scan result." };
}

const tone = v.error ? "warn" : v.verdict === "HIGH-RISK SCAM" || v.score >= 70 ? "danger" : v.verdict === "SUSPICIOUS" ? "warn" : "safe";

// ---------------------------------------------------------------- helpers
function defang(domain) {
  return String(domain || "")
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/\./g, "[.]");
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return url || "";
  }
}

const LIGHT_RANGES = [
  [0, 4351],
  [8192, 8205],
  [8208, 8223],
  [8242, 8247],
];
/** X's weighted length: Latin/Arabic count 1, emoji and CJK count 2. */
function xLength(text) {
  const graphemes =
    typeof Intl !== "undefined" && Intl.Segmenter
      ? Array.from(new Intl.Segmenter("en", { granularity: "grapheme" }).segment(text), (s) => s.segment)
      : Array.from(text);
  let total = 0;
  for (const g of graphemes) {
    if (/\p{Extended_Pictographic}/u.test(g)) {
      total += 2;
      continue;
    }
    for (const ch of g) {
      const cp = ch.codePointAt(0) || 0;
      total += LIGHT_RANGES.some(([a, b]) => cp >= a && cp <= b) ? 1 : 2;
    }
  }
  return total;
}

const REASONS = {
  CREDENTIAL_HARVESTING: ["it asks for card and OTP details", "يطلب بيانات البطاقة ورمز التحقق"],
  NEWLY_REGISTERED: ["the site was created only hours ago", "أُنشئ الموقع قبل ساعات فقط"],
  KNOWN_SYNDICATE_INFRA: ["it is linked to a known scam network", "مرتبط بشبكة احتيال معروفة"],
  UNOFFICIAL_DOMAIN_ON_LISTING: ["a fake Google Maps listing", "إدراج مزيف على خرائط جوجل"],
  INSTITUTION_MESSAGING_LINK: ["a fake Google Maps listing that links to a WhatsApp chat or social page", "إدراج مزيف على خرائط جوجل يربط بمحادثة واتساب أو صفحة تواصل اجتماعي"],
  FOREIGN_NUMBER_FOR_INSTITUTION: ["a foreign phone number for a UAE institution", "رقم هاتف أجنبي لجهة إماراتية"],
  HOMOGLYPH_SPOOF: ["look-alike letters in the web address", "أحرف مشابهة في عنوان الموقع"],
  BRAND_IMPERSONATION: ["it is not the official website", "ليس الموقع الرسمي"],
  TYPOSQUAT: ["a misspelled copy of the official address", "نسخة بأخطاء إملائية من العنوان الرسمي"],
  TLD_SWAP: ["the official name with the wrong ending", "الاسم الرسمي بامتداد خاطئ"],
  CLOAKING: ["it hides from security scanners", "يتخفّى من أنظمة الفحص الأمني"],
  REDIRECTS_TO_FLAGGED: ["the link secretly leads to a dangerous website", "الرابط يقود خفيةً إلى موقع خطير"],
  URL_SHORTENER: ["a shortened link hides the real address", "رابط مختصر يخفي العنوان الحقيقي"],
  PROVIDER_PHISHING_WARNING: ["its hosting provider already shows a phishing warning on it", "مزود الاستضافة يعرض عليه تحذيراً من التصيّد"],
  SHORTLINK_DISABLED: ["the link-shortening service has disabled this link for abuse", "خدمة اختصار الروابط عطّلت هذا الرابط بسبب إساءة الاستخدام"],
  FORM_SERVICE_CREDENTIALS: ["it sends passwords or card details to a third-party form service", "يرسل كلمات المرور أو بيانات البطاقة إلى خدمة نماذج خارجية"],
  BRAND_LOGIN_PAGE: ["a log-in page using a known brand's name on an unrelated site", "صفحة تسجيل دخول تحمل اسم جهة معروفة على موقع لا يتبعها"],
  AI_NEW_DOMAIN: ["a brand-new domain whose address looks like phishing", "نطاق حديث جداً وعنوانه يشبه مواقع التصيّد"],
  SITE_TAKEN_DOWN: ["the site has already vanished and its address looks like phishing", "الموقع اختفى بالفعل وعنوانه يشبه مواقع التصيّد"],
  CERT_RENEWED: ["its security certificate was renewed very recently", "شهادة الأمان جُدّدت حديثاً جداً"],
  REDIRECT_CHAIN: ["it passes through hidden redirects", "يمر عبر تحويلات مخفية"],
  // Email Shield flag codes (email contract, section 2)
  KNOWN_PHISHING_LINK: ["it links to a known phishing website", "يحتوي على رابط لموقع تصيّد معروف"],
  CAMPAIGN_IOC_MATCH: ["it comes from a known scam campaign", "مرتبط بحملة احتيال معروفة"],
  LINK_HIGH_RISK: ["its link opens a scam website", "رابطه يفتح موقعاً احتيالياً"],
  IDN_MIXED_SCRIPT: ["look-alike letters in the sender or link address", "أحرف مشابهة في عنوان المرسل أو الرابط"],
  DISPLAY_NAME_CONFUSABLE: ["a brand name spelled with fake look-alike letters", "اسم علامة تجارية مكتوب بأحرف مزيفة مشابهة"],
  BIDI_OVERRIDE: ["hidden characters that reverse the text", "أحرف مخفية تعكس اتجاه النص"],
  SENDER_LOOKALIKE: ["the sender's address imitates an official one", "عنوان المرسل يقلّد عنواناً رسمياً"],
  DANGEROUS_ATTACHMENT: ["a dangerous file is attached", "مرفق ملف خطير"],
  INVISIBLE_IN_TOKEN: ["invisible characters hidden inside words or links", "أحرف غير مرئية مخفية داخل الكلمات أو الروابط"],
  PUNYCODE_DOMAIN: ["an unusual encoded web address", "عنوان ويب مُرمّز بشكل غير معتاد"],
  DISPLAY_NAME_ADDRESS_SPOOF: ["the sender name shows a fake email address", "اسم المرسل يعرض عنوان بريد مزيفاً"],
  DMARC_FAIL: ["the sender's address failed the official check", "فشل عنوان المرسل في التحقق الرسمي"],
  DISPLAY_NAME_BRAND_SPOOF: ["a company name on an address that is not the company's", "اسم شركة على عنوان لا يتبع الشركة"],
  FREEMAIL_BRAND_SENDER: ["a 'company' writing from a free email account", "«شركة» تراسلك من حساب بريد مجاني"],
  LINK_TEXT_MISMATCH: ["a link that shows one address but opens another", "رابط يُظهر عنواناً ويفتح عنواناً آخر"],
  SENDER_NEW_DOMAIN: ["the sender's domain was created days ago", "أُنشئ نطاق المرسل قبل أيام"],
  CALLBACK_MOBILE_FOR_INSTITUTION: ["it gives a personal mobile number for an institution", "يذكر رقم هاتف متحرك شخصي باسم جهة رسمية"],
  CALLBACK_FOREIGN_FOR_INSTITUTION: ["it gives a foreign phone number for a UAE institution", "يذكر رقم هاتف أجنبياً باسم جهة إماراتية"],
  SENDER_NO_MX: ["the sender's domain has no mail server", "نطاق المرسل لا يملك خادم بريد"],
  TLS_INVALID: ["its security certificate is not valid", "شهادة الأمان الخاصة به غير صالحة"],
  LINK_SUSPICIOUS: ["its link opens a suspicious website", "رابطه يفتح موقعاً مشبوهاً"],
  REPLY_TO_FREEMAIL_BRAND: ["replies go to a free email account", "الردود تذهب إلى حساب بريد مجاني"],
  OFFICIAL_SENDER_UNAUTHENTICATED: ["it pretends to come from an official address", "يدّعي أنه صادر من عنوان رسمي"],
  SPF_FAIL: ["the sending server is not allowed to send for that address", "خادم الإرسال غير مخوّل بالإرسال باسم هذا العنوان"],
  SPF_SOFTFAIL: ["the sending server is probably not allowed to send for that address", "خادم الإرسال على الأرجح غير مخوّل بالإرسال باسم هذا العنوان"],
  DKIM_FAIL: ["the email's digital signature is broken", "التوقيع الرقمي للرسالة غير صالح"],
  DMARC_FAIL_P_NONE: ["the sender's address failed the domain check", "فشل عنوان المرسل في فحص النطاق"],
  NO_AUTHENTICATION: ["the sender could not be verified at all", "تعذّر التحقق من المرسل إطلاقاً"],
  CREDENTIAL_REQUEST: ["it asks for your password or card details", "يطلب كلمة المرور أو بيانات البطاقة"],
  PAYMENT_REQUEST: ["it asks you to pay a fee", "يطلب منك دفع رسوم"],
  URGENCY_LANGUAGE: ["fake deadlines and threats", "مهل وتهديدات مزيفة"],
  CAMPAIGN_LURE_MATCH: ["it uses the wording of a known scam wave", "يستخدم صياغة موجة احتيال معروفة"],
  USER_MODEL_SCAM: ["it looks like emails you marked as scams", "يشبه رسائل صنّفتها سابقاً كاحتيال"],
  REPLY_TO_MISMATCH: ["replies go to a different address", "الردود تذهب إلى عنوان مختلف"],
  RETURN_PATH_MISMATCH: ["its hidden return address belongs to someone else", "عنوان الإرجاع المخفي يتبع جهة أخرى"],
  FANCY_UNICODE: ["text written in unusual styled letters", "نص مكتوب بأحرف مزخرفة غير معتادة"],
  BRAND_MENTION: ["it uses a well-known company's name", "يستخدم اسم جهة معروفة"],
  ATTACHMENT_ARCHIVE: ["a compressed file is attached", "مرفق ملف مضغوط"],
  // Info flags (0 points) are never picked as "the red flag" (only flags with points reach this page).
  HEADERS_NOT_AVAILABLE: ["only the visible text could be checked", "تم فحص النص الظاهر فقط"],
  DMARC_PASS: ["the sender's domain passed DMARC", "اجتاز نطاق المرسل فحص DMARC"],
  ARC_PASS: ["a trusted mail server vouched for the forwarding", "أكّد خادم بريد موثوق سلامة إعادة التوجيه"],
  BULK_SENDER: ["it is a newsletter or mailing-list message", "رسالة نشرة بريدية أو قائمة مراسلات"],
  OFFICIAL_SENDER: ["it was sent from an official address", "أُرسلت من عنوان رسمي"],
  USER_MODEL_TRUSTED: ["it looks like emails you marked as safe", "تشبه رسائل صنّفتها كآمنة"],
};
function reason() {
  const hit = (v.flags || []).find((f) => REASONS[f.code]);
  return hit ? REASONS[hit.code] : ["it fails official verification", "لم يجتز التحقق الرسمي"];
}

const isEmail = v.kind === "email";

/** For an email: the most dangerous linked site, else the sender's address (masked later). */
function emailSite() {
  const risky = (v.links || []).find((l) => l.domain && (l.verdict === "HIGH-RISK SCAM" || l.verdict === "SUSPICIOUS" || l.mismatch));
  if (risky) return risky.domain;
  return v.from?.freemail ? "" : v.from?.address || "";
}

function draft(lang) {
  const site = isEmail ? emailSite() : v.domain || hostOf(v.url);
  const masked = site ? ` (${defang(site)})` : "";
  const [rEn, rAr] = reason();
  if (lang === "ar") {
    const who = v.entityAr ? `روابط مزيفة تنتحل صفة ${v.entityAr}` : "روابط مزيفة";
    return `⚠️ تحذير احتيال في أبوظبي: احذروا ${who}${masked}. علامة الخطر: ${rAr}. تحقّقوا قبل الضغط وأبلغوا أمان 8002626 / رسالة 2828. #أبوظبي #الأمن_السيبراني #Aman8002626`;
  }
  const who = v.entityEn ? `fake ${v.entityEn} links` : "fake links";
  return `⚠️ Fraud Alert in Abu Dhabi: Watch out for ${who}${masked}. Red flag: ${rEn}. Verify before clicking & report to Aman 8002626 / SMS 2828. #AbuDhabi #CyberSafety #Aman8002626`;
}

function amanReport() {
  const when = new Date(v.at || Date.now()).toLocaleString("en-GB", { timeZone: "Asia/Dubai", dateStyle: "medium", timeStyle: "short" });
  const site = (isEmail ? defang(emailSite()) : defang(v.domain || hostOf(v.url))) || "—";
  const lines = [
    "Saqr fraud report → Aman 8002626 / SMS 2828",
    v.scanId ? `Scan ID: ${v.scanId}` : null,
    `Time: ${when} (UAE)`,
    `Verdict: ${v.verdict} (${v.score}/100)`,
    v.entityEn ? `Impersonating: ${v.entityEn}` : null,
    isEmail ? `Suspicious email from (masked): ${defang(v.from?.address || "") || "—"}` : null,
    isEmail && v.subject ? `Subject: ${v.subject}` : null,
    `${isEmail ? "Linked site" : "Suspicious site"} (masked): ${site}`,
    isEmail
      ? `Detected via: Email Shield (${v.provider === "outlook" ? "Outlook" : v.provider === "gmail" ? "Gmail" : "webmail"} in the Chrome/Edge extension)`
      : "Detected via: PC Browser Shield (Chrome/Edge extension)",
    v.flags?.length ? `Red flags:\n${v.flags.map((f) => `- ${f.en}`).join("\n")}` : null,
    "",
    "بلاغ احتيال — صقر",
    v.entityAr ? `ينتحل صفة: ${v.entityAr}` : null,
    isEmail ? `البريد المشبوه من (معطّل): ${defang(v.from?.address || "") || "—"}` : null,
    `${isEmail ? "الموقع المرتبط" : "الموقع المشبوه"} (معطّل): ${site}`,
    isEmail ? "طريقة الكشف: درع البريد الإلكتروني (إضافة المتصفح)" : "طريقة الكشف: درع المتصفح (إضافة Chrome/Edge)",
    v.flags?.length ? `علامات الخطر:\n${v.flags.map((f) => `- ${f.ar}`).join("\n")}` : null,
  ];
  return lines.filter((l) => l !== null).join("\n");
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    const ta = document.createElement("textarea");
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    ta.remove();
    return ok;
  }
}

function toast(text, ok = true) {
  const t = $("toast");
  t.textContent = text;
  t.classList.toggle("err", !ok);
  t.classList.remove("hidden");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.add("hidden"), 3500);
}

function hide(...ids) {
  ids.forEach((id) => $(id).classList.add("hidden"));
}

// ---------------------------------------------------------------- render
const UI = {
  safety: ["Go back to safety", "العودة إلى الأمان"],
  close: ["Close this tab", "إغلاق هذه الصفحة"],
  goOfficial: ["Go to official site", "الذهاب إلى الموقع الرسمي"],
  callAman: ["Call Aman 8002626", "اتصل بأمان 8002626"],
  continue: ["Continue anyway (not recommended)", "المتابعة على أي حال (غير موصى به)"],
  synced: ["Reported to the Saqr live radar", "تم الإبلاغ إلى رادار صقر المباشر"],
  impersonating: ["Pretends to be", "ينتحل صفة"],
  officialSite: ["Official website", "الموقع الرسمي"],
  whyDanger: ["Why this is dangerous", "لماذا هذا خطير"],
  whySuspicious: ["Why this looks suspicious", "لماذا يبدو مشبوهاً"],
  whySafe: ["Why this is safe", "لماذا هذا آمن"],
  fullExplanation: ["Full explanation", "الشرح الكامل"],
  zSafe: ["Safe", "آمن"],
  zSuspicious: ["Suspicious", "مشبوه"],
  zScam: ["Scam", "احتيال"],
  helpOthers: ["Help others", "ساعد الآخرين"],
  xTitle: ["Warn others on X or report to Aman", "حذّر الآخرين على X أو أبلغ أمان"],
  xSub: [
    "Nothing posts without your permission. The scam link is masked with [.] so nobody can click it by accident.",
    "لا يُنشر أي شيء دون إذنك. يتم تعطيل رابط الاحتيال بـ [.] حتى لا يضغط عليه أحد بالخطأ.",
  ],
  xReview: ["Review a warning post for X", "مراجعة منشور تحذير على X"],
  copyAman: ["Copy report for Aman (8002626 / 2828)", "نسخ بلاغ لأمان (8002626 / 2828)"],
  postLang: ["Post language", "لغة المنشور"],
  xOpen: ["Approve and open X", "موافقة وفتح X"],
  draftHint: ["You can edit the text. X opens in a new tab; nothing posts until you press Post there.", "يمكنك تعديل النص. يفتح X في صفحة جديدة، ولا يُنشر شيء حتى تضغط «نشر» هناك."],
  draftLong: ["Too long for X. Shorten it to 280 characters.", "النص طويل جداً على X. اختصره إلى 280 حرفاً."],
  copied: ["Report copied. Paste it into an SMS to 2828 or read it to Aman 8002626.", "تم نسخ البلاغ. الصقه في رسالة إلى 2828 أو اقرأه لأمان 8002626."],
  copyFail: ["Couldn't copy. Select the text manually.", "تعذّر النسخ. حدّد النص يدوياً."],
  confirm: [
    "This website was blocked as a scam. Continue anyway? Never enter card details, OTP codes or UAE PASS logins here.",
    "تم حظر هذا الموقع لأنه احتيالي. هل تريد المتابعة؟ لا تُدخل أبداً بيانات البطاقة أو رمز التحقق أو بيانات UAE PASS هنا.",
  ],
  riskScore: ["Risk score", "درجة الخطورة"],
  scoreLabel: ["Risk score {0} out of 100", "درجة الخطورة {0} من 100"],
  byBlock: ["Saqr stopped this page before it could load.", "أوقف صقر هذه الصفحة قبل أن تُفتح."],
  byCheck: ["Checked by Saqr.", "تم الفحص بواسطة صقر."],
  byEmail: ["Checked by the Saqr Email Shield.", "تم الفحص بواسطة درع صقر للبريد."],
  failed: ["Scan failed", "فشل الفحص"],
  failedTitle: ["Could not complete the scan", "تعذّر إكمال الفحص"],
  failedBy: ["{0} — Is the Saqr server reachable? Check the address in the extension popup.", "{0} — هل خادم صقر متاح؟ تحقّق من العنوان في نافذة الإضافة."],
  from: ["From", "من"],
  fallbackReason: ["It fails official verification.", "لم يجتز التحقق الرسمي."],
};
const VERDICT_WORD = {
  danger: ["High-risk scam", "احتيال عالي الخطورة"],
  warn: ["Suspicious", "مشبوه"],
  safe: ["No major red flags", "لا توجد مؤشرات خطر كبيرة"],
};
const TONE = { danger: "scam", warn: "suspicious", safe: "safe" };
const tr = (key, ...args) => {
  const pair = UI[key] || [key, key];
  return (lang === "ar" ? pair[1] : pair[0]).replace(/\{(\d+)\}/g, (_, i) => (args[i] == null ? "" : String(args[i])));
};
const pick = (pair) => (lang === "ar" ? pair[1] : pair[0]);

function renderGauge(score) {
  const s = Math.max(0, Math.min(100, Number(score) || 0));
  const marker = $("gauge-marker");
  marker.style.insetInlineStart = "0%";
  requestAnimationFrame(() => requestAnimationFrame(() => (marker.style.insetInlineStart = `${s}%`)));
  $("gauge-num").textContent = String(Math.round(s));
  $("gauge").setAttribute("aria-label", tr("scoreLabel", Math.round(s)));
}

function stripBullets(t) {
  return String(t || "")
    .split(/\n\s*\n/)
    .filter((p) => !/^\s*(red flags|علامات الخطر)\s*:/i.test(p) && !/^\s*•/.test(p))
    .join("\n\n")
    .trim();
}

function render() {
  const root = document.documentElement;
  root.lang = lang;
  root.dir = lang === "ar" ? "rtl" : "ltr";
  document.querySelectorAll("[data-i18n]").forEach((n) => (n.textContent = tr(n.dataset.i18n)));
  $("lang-toggle").textContent = lang === "ar" ? "English" : "العربية";
  $("lang-toggle").lang = lang === "ar" ? "en" : "ar";

  const toneName = TONE[tone];
  const badge = $("verdict-badge");
  badge.className = `chip chip-${toneName}`;
  $("hero").dataset.tone = toneName;
  $("safety").textContent = mode === "block" || v.error ? tr("safety") : tr("close");

  if (v.error) {
    badge.textContent = tr("failed");
    $("title-en").textContent = tr("failedTitle");
    $("by").textContent = tr("failedBy", v.error);
    $("target").textContent = v.url || "";
    if (!v.url) hide("target");
    document.title = `${tr("failedTitle")} · Saqr`;
    hide("score-block", "sync", "entity-row", "flags-card", "x-card", "call-aman");
    return;
  }

  const titles = isEmail
    ? {
        danger: ["Scam email: do not click its links", "رسالة احتيالية: لا تضغط على روابطها"],
        warn: ["Warning: this email looks suspicious", "تحذير: هذه الرسالة تبدو مشبوهة"],
        safe: ["No scam signs found in this email", "لم نجد علامات احتيال في هذه الرسالة"],
      }[tone]
    : {
        danger:
          mode === "block"
            ? ["Website blocked for your protection", "تم حظر الموقع لحمايتك"]
            : ["Dangerous website: do not open it", "موقع خطير: لا تفتحه"],
        warn: ["Warning: this website looks suspicious", "تحذير: هذا الموقع يبدو مشبوهاً"],
        safe: ["Verified safe", "تم التحقق: آمن"],
      }[tone];
  badge.textContent = pick(VERDICT_WORD[tone]);
  $("title-en").textContent = pick(titles);
  document.title = `${pick(titles)} · Saqr`;
  $("by").textContent = isEmail ? tr("byEmail") : mode === "block" && tone !== "safe" ? tr("byBlock") : tr("byCheck");

  const word = $("verdict-word");
  word.textContent = tr("riskScore");

  let path = "";
  try {
    path = new URL(v.url).pathname.replace(/\/$/, "");
  } catch {
    path = "";
  }
  // Demo pages (/mock-scam/<slug>) stand in for a seeded scam domain: show that domain instead.
  const isDemo = path.startsWith("/mock-scam/");
  const target = isEmail
    ? [v.from?.address ? `${tr("from")}: ${defang(v.from.address)}` : null, v.subject ? `“${v.subject}”` : null].filter(Boolean).join(" · ") ||
      v.target ||
      ""
    : v.kind === "maps"
      ? `${v.target}${v.domain ? ` → ${defang(v.domain)}` : ""}`
      : isDemo && v.domain
        ? defang(v.domain)
        : defang(hostOf(v.url)) + path;
  $("target").textContent = target;
  if (!target) hide("target");
  renderGauge(Number(v.score) || 0);

  $("case").textContent = [v.scanId ? `#${v.scanId}` : null, new Date(v.at || Date.now()).toLocaleTimeString("en-GB", { timeZone: "Asia/Dubai" })]
    .filter(Boolean)
    .join(" · ");

  if (v.entityEn && tone !== "safe") {
    $("entity-en").textContent = lang === "ar" ? v.entityAr || v.entityEn : v.entityEn;
    $("entity-ar").textContent = lang === "ar" ? (v.entityAr ? v.entityEn : "") : v.entityAr || "";
    $("entity-ar").lang = lang === "ar" ? "en" : "ar";
  } else {
    hide("entity-card");
  }
  if (v.official?.length) {
    $("official").textContent = v.official[0];
    const go = $("go-official");
    go.href = `https://${v.official[0]}`;
    go.classList.remove("hidden");
  } else {
    hide("official-card");
  }
  if ($("entity-card").classList.contains("hidden") && $("official-card").classList.contains("hidden")) hide("entity-row");

  $("reasons-title").textContent = tr(tone === "safe" ? "whySafe" : tone === "warn" ? "whySuspicious" : "whyDanger");
  // 2–3 reasons in the page language; the full explanation stays one click away.
  const list = $("flags");
  list.replaceChildren();
  const flags = (v.flags || []).slice(0, 3);
  flags.forEach((f) => {
    const li = document.createElement("li");
    li.textContent = (lang === "ar" ? f.ar || f.en : f.en || f.ar) || "";
    li.dataset.sev = f.sev || "";
    list.append(li);
  });
  const explanation = stripBullets(lang === "ar" ? v.explanationAr || v.explanationEn : v.explanationEn || v.explanationAr);
  if (!flags.length && tone !== "safe") {
    const li = document.createElement("li");
    li.textContent = explanation ? explanation.split(/\n/)[0] : tr("fallbackReason");
    list.append(li);
  }
  if (explanation) $("explain").textContent = explanation;
  else hide("explain-card");
  if (!list.children.length && !explanation) hide("flags-card");

  if (tone === "safe" || (Number(v.score) || 0) < 60) hide("x-card");
  if (tone === "safe") hide("sync", "call-aman");

  if (mode === "block" && v.url) $("continue").classList.remove("hidden");
}

$("lang-toggle").addEventListener("click", () => {
  lang = lang === "ar" ? "en" : "ar";
  render();
  if (!$("x-editor").classList.contains("hidden")) syncDraft();
});

// ---------------------------------------------------------------- X composer
let draftLang = lang;
const drafts = { en: "", ar: "" };

function syncDraft() {
  const text = $("draft").value;
  drafts[draftLang] = text;
  const len = xLength(text);
  const over = len > X_LIMIT || !text.trim();
  $("count").textContent = `${len}/${X_LIMIT}`;
  $("count").classList.toggle("over", len > X_LIMIT);
  $("draft").classList.toggle("over", len > X_LIMIT);
  $("draft-hint").textContent =
    len > X_LIMIT ? tr("draftLong") : tr("draftHint");
  const open = $("x-open");
  open.setAttribute("aria-disabled", String(over));
  open.href = over ? "#" : `https://x.com/intent/post?text=${encodeURIComponent(text)}`;
}

function setDraftLang(lang) {
  draftLang = lang;
  document.querySelectorAll(".seg button").forEach((b) => b.setAttribute("aria-checked", String(b.dataset.lang === lang)));
  const ta = $("draft");
  ta.value = drafts[lang];
  ta.dir = lang === "ar" ? "rtl" : "ltr";
  syncDraft();
}

$("x-review").addEventListener("click", () => {
  drafts.en = drafts.en || draft("en");
  drafts.ar = drafts.ar || draft("ar");
  $("x-editor").classList.remove("hidden");
  setDraftLang(draftLang);
  $("draft").focus();
});
document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => setDraftLang(b.dataset.lang)));
$("draft").addEventListener("input", syncDraft);
$("x-open").addEventListener("click", (e) => {
  if ($("x-open").getAttribute("aria-disabled") === "true") e.preventDefault();
});
$("copy-aman").addEventListener("click", async () => {
  const ok = await copy(amanReport());
  toast(ok ? tr("copied") : tr("copyFail"), ok);
});

// ---------------------------------------------------------------- navigation buttons
$("safety").addEventListener("click", async () => {
  const tab = await chrome.tabs.getCurrent();
  if (mode !== "block" && tab?.id != null) {
    chrome.tabs.remove(tab.id);
    return;
  }
  chrome.tabs.update(tab?.id, { url: "chrome://newtab/" });
});
$("continue").addEventListener("click", async () => {
  if (!confirm(tr("confirm"))) return;
  await chrome.runtime.sendMessage({ type: "allowHost", host: hostOf(v.url) });
  location.replace(v.url);
});

render();
