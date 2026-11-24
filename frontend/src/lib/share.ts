import type { InterceptionChannel, ScanVerdict } from "./api";
import type { DictKey, Lang } from "./i18n";

export const CHANNEL_DICT_KEY: Record<InterceptionChannel, DictKey> = {
  AUTO_TELECOM_DNS: "channelDns",
  AUTO_SMS_GUARD: "channelSms",
  MOBILE_OS_SHARE_SHEET: "channelShare",
  CITIZEN_MANUAL_CHECK: "channelManual",
  PC_BROWSER_EXTENSION: "channelPc",
  ANDROID_APP_GUARD: "channelAndroid",
  DIRECT_API: "channelApi",
  MANUAL: "channelManual",
};

export const X_LIMIT = 280;

/** Arabic names for the impersonated entities the backend reports in English. */
export const ENTITY_AR: Record<string, string> = {
  "Abu Dhabi Police": "شرطة أبوظبي",
  "TAMM Abu Dhabi": "منصة تم",
  "Emirates Post": "بريد الإمارات",
  "e& (Etisalat)": "اتصالات",
  du: "دو",
  "UAE PASS": "UAE PASS",
  "First Abu Dhabi Bank (FAB)": "بنك أبوظبي الأول",
  ADCB: "بنك أبوظبي التجاري",
};

/** Make a domain unclickable everywhere it is pasted: tamm-pay.net -> tamm-pay[.]net */
export function defang(domain: string): string {
  return domain
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/\./g, "[.]");
}

const LIGHT_RANGES: [number, number][] = [
  [0, 4351],
  [8192, 8205],
  [8208, 8223],
  [8242, 8247],
];

/** X's weighted length: Latin/Arabic characters count 1, emoji and CJK count 2. */
export function xLength(text: string): number {
  const graphemes =
    typeof Intl !== "undefined" && "Segmenter" in Intl
      ? Array.from(new Intl.Segmenter("en", { granularity: "grapheme" }).segment(text), (s) => s.segment)
      : Array.from(text);
  let total = 0;
  for (const g of graphemes) {
    if (/\p{Extended_Pictographic}/u.test(g)) {
      total += 2;
      continue;
    }
    for (const ch of g) {
      const cp = ch.codePointAt(0) ?? 0;
      total += LIGHT_RANGES.some(([a, b]) => cp >= a && cp <= b) ? 1 : 2;
    }
  }
  return total;
}

const REASON_BY_FLAG: Record<string, { en: string; ar: string }> = {
  CREDENTIAL_HARVESTING: { en: "it asks for card and OTP details", ar: "يطلب بيانات البطاقة ورمز التحقق" },
  NEWLY_REGISTERED: { en: "the site was created only hours ago", ar: "أُنشئ الموقع قبل ساعات فقط" },
  KNOWN_SYNDICATE_INFRA: { en: "it is linked to a known scam network", ar: "مرتبط بشبكة احتيال معروفة" },
  UNOFFICIAL_DOMAIN_ON_LISTING: { en: "a fake Google Maps listing", ar: "إدراج مزيف على خرائط جوجل" },
  INSTITUTION_MESSAGING_LINK: {
    en: "a fake Google Maps listing that links to a WhatsApp chat or social page",
    ar: "إدراج مزيف على خرائط جوجل يربط بمحادثة واتساب أو صفحة تواصل اجتماعي",
  },
  FOREIGN_NUMBER_FOR_INSTITUTION: { en: "a foreign phone number for a UAE institution", ar: "رقم هاتف أجنبي لجهة إماراتية" },
  HOMOGLYPH_SPOOF: { en: "look-alike letters in the web address", ar: "أحرف مشابهة في عنوان الموقع" },
  BRAND_IMPERSONATION: { en: "it is not the official website", ar: "ليس الموقع الرسمي" },
  TYPOSQUAT: { en: "a misspelled copy of the official address", ar: "نسخة بأخطاء إملائية من العنوان الرسمي" },
  TLD_SWAP: { en: "the official name with the wrong ending", ar: "الاسم الرسمي بامتداد خاطئ" },
  CLOAKING: { en: "it hides from security scanners", ar: "يتخفّى من أنظمة الفحص الأمني" },
  REDIRECTS_TO_FLAGGED: { en: "the link secretly leads to a dangerous website", ar: "الرابط يقود خفيةً إلى موقع خطير" },
  URL_SHORTENER: { en: "a shortened link hides the real address", ar: "رابط مختصر يخفي العنوان الحقيقي" },
  PROVIDER_PHISHING_WARNING: { en: "its hosting provider already shows a phishing warning on it", ar: "مزود الاستضافة يعرض عليه تحذيراً من التصيّد" },
  SHORTLINK_DISABLED: { en: "the link-shortening service has disabled this link for abuse", ar: "خدمة اختصار الروابط عطّلت هذا الرابط بسبب إساءة الاستخدام" },
  FORM_SERVICE_CREDENTIALS: { en: "it sends passwords or card details to a third-party form service", ar: "يرسل كلمات المرور أو بيانات البطاقة إلى خدمة نماذج خارجية" },
  BRAND_LOGIN_PAGE: { en: "a log-in page using a known brand's name on an unrelated site", ar: "صفحة تسجيل دخول تحمل اسم جهة معروفة على موقع لا يتبعها" },
  AI_NEW_DOMAIN: { en: "a brand-new domain whose address looks like phishing", ar: "نطاق حديث جداً وعنوانه يشبه مواقع التصيّد" },
  SITE_TAKEN_DOWN: { en: "the site has already vanished and its address looks like phishing", ar: "الموقع اختفى بالفعل وعنوانه يشبه مواقع التصيّد" },
  CERT_RENEWED: { en: "its security certificate was renewed very recently", ar: "شهادة الأمان جُدّدت حديثاً جداً" },
  REDIRECT_CHAIN: { en: "it passes through hidden redirects", ar: "يمر عبر تحويلات مخفية" },
  YOUNG_DOMAIN: { en: "a very new website", ar: "موقع حديث جداً" },
  URGENCY_PRESSURE: { en: "fake deadlines and threats", ar: "مهل وتهديدات مزيفة" },
  SUSPICIOUS_TLD: { en: "an unusual web address", ar: "عنوان موقع غير مألوف" },
  // Email scans (POST /api/analyze-email)
  KNOWN_PHISHING_LINK: { en: "it links to a known phishing website", ar: "يحتوي على رابط لموقع تصيّد معروف" },
  LINK_HIGH_RISK: { en: "it links to a scam website", ar: "يحتوي على رابط لموقع احتيالي" },
  CAMPAIGN_IOC_MATCH: { en: "it is part of a scam wave spreading now", ar: "جزء من موجة احتيال منتشرة الآن" },
  IDN_MIXED_SCRIPT: { en: "look-alike letters in the sender's address", ar: "أحرف مشابهة في عنوان المرسل" },
  DISPLAY_NAME_CONFUSABLE: { en: "look-alike letters hiding a fake brand name", ar: "أحرف مشابهة تخفي اسماً تجارياً مزيفاً" },
  BIDI_OVERRIDE: { en: "a hidden text-direction trick", ar: "خدعة مخفية في اتجاه النص" },
  DANGEROUS_ATTACHMENT: { en: "a dangerous attached file", ar: "ملف مرفق خطير" },
  SENDER_LOOKALIKE: { en: "a fake copy of the official sender address", ar: "نسخة مزيفة من عنوان المرسل الرسمي" },
  FREEMAIL_BRAND_SENDER: { en: "it comes from a free email account, not the company", ar: "أُرسل من حساب بريد مجاني وليس من الجهة نفسها" },
  DISPLAY_NAME_BRAND_SPOOF: { en: "a fake sender name", ar: "اسم مرسل مزيف" },
  LINK_TEXT_MISMATCH: { en: "links that open a different website than shown", ar: "روابط تفتح موقعاً غير الظاهر" },
  DMARC_FAIL: { en: "the sender's address is forged", ar: "عنوان المرسل مزوّر" },
  INVISIBLE_IN_TOKEN: { en: "invisible characters hidden inside words or links", ar: "أحرف غير مرئية مخفية داخل الكلمات أو الروابط" },
  PUNYCODE_DOMAIN: { en: "an unusual encoded web address", ar: "عنوان ويب مُرمّز بشكل غير معتاد" },
  FANCY_UNICODE: { en: "text written in unusual styled letters", ar: "نص مكتوب بأحرف مزخرفة غير معتادة" },
  DISPLAY_NAME_ADDRESS_SPOOF: { en: "the sender name shows a fake email address", ar: "اسم المرسل يعرض عنوان بريد مزيفاً" },
  REPLY_TO_FREEMAIL_BRAND: { en: "replies go to a free email account", ar: "الردود تذهب إلى حساب بريد مجاني" },
  REPLY_TO_MISMATCH: { en: "replies go to a different address", ar: "الردود تذهب إلى عنوان مختلف" },
  RETURN_PATH_MISMATCH: { en: "its hidden return address belongs to someone else", ar: "عنوان الإرجاع المخفي يتبع جهة أخرى" },
  SENDER_NEW_DOMAIN: { en: "the sender's domain was created days ago", ar: "أُنشئ نطاق المرسل قبل أيام" },
  CALLBACK_MOBILE_FOR_INSTITUTION: { en: "it gives a personal mobile number for an institution", ar: "يذكر رقم هاتف متحرك شخصي باسم جهة رسمية" },
  CALLBACK_FOREIGN_FOR_INSTITUTION: { en: "it gives a foreign phone number for a UAE institution", ar: "يذكر رقم هاتف أجنبياً باسم جهة إماراتية" },
  SENDER_NO_MX: { en: "the sender's domain has no mail server", ar: "نطاق المرسل لا يملك خادم بريد" },
  TLS_INVALID: { en: "its security certificate is not valid", ar: "شهادة الأمان الخاصة به غير صالحة" },
  MSG_SCAM_LINK: { en: "its link leads to a scam website", ar: "رابطها يقود إلى موقع احتيالي" },
  MSG_SUSPICIOUS_LINK: { en: "its link leads to a suspicious website", ar: "رابطها يقود إلى موقع مشبوه" },
  MSG_LOOKALIKE_LINK: { en: "its link imitates an official website", ar: "رابطها يقلّد موقعاً رسمياً" },
  MSG_CREDENTIAL_REQUEST: { en: "it asks you to send your OTP, PIN or card details", ar: "تطلب منك إرسال رمز التحقق أو الرقم السري أو بيانات البطاقة" },
  SENDER_MOBILE_FOR_INSTITUTION: { en: "an institution would never text from a personal mobile", ar: "الجهات الرسمية لا ترسل رسائل من أرقام شخصية" },
  SENDER_FOREIGN_FOR_INSTITUTION: { en: "a UAE institution would never text from a foreign number", ar: "الجهات الإماراتية لا ترسل رسائل من أرقام أجنبية" },
  MSG_PHONE_LINKED_TO_SCAM: { en: "its phone number is linked to known fraud", ar: "رقم الهاتف مرتبط باحتيال معروف" },
  OFFICIAL_SENDER_UNAUTHENTICATED: { en: "it pretends to come from an official address", ar: "يدّعي أنه صادر من عنوان رسمي" },
  HEADERS_NOT_AVAILABLE: { en: "only the visible text could be checked", ar: "تم فحص النص الظاهر فقط" },
  DMARC_FAIL_P_NONE: { en: "the sender's address failed the domain check", ar: "فشل عنوان المرسل في فحص النطاق" },
  SPF_FAIL: { en: "the sending server is not allowed to send for that address", ar: "خادم الإرسال غير مخوّل بالإرسال باسم هذا العنوان" },
  SPF_SOFTFAIL: { en: "the sending server is probably not allowed to send for that address", ar: "خادم الإرسال على الأرجح غير مخوّل بالإرسال باسم هذا العنوان" },
  DKIM_FAIL: { en: "the email's digital signature is broken", ar: "التوقيع الرقمي للرسالة غير صالح" },
  NO_AUTHENTICATION: { en: "the sender could not be verified at all", ar: "تعذّر التحقق من المرسل إطلاقاً" },
  DMARC_PASS: { en: "the sender's domain passed DMARC", ar: "اجتاز نطاق المرسل فحص DMARC" },
  ARC_PASS: { en: "a trusted mail server vouched for the forwarding", ar: "أكّد خادم بريد موثوق سلامة إعادة التوجيه" },
  BULK_SENDER: { en: "it is a newsletter or mailing-list message", ar: "رسالة نشرة بريدية أو قائمة مراسلات" },
  OFFICIAL_SENDER: { en: "it was sent from an official address", ar: "أُرسلت من عنوان رسمي" },
  LINK_SUSPICIOUS: { en: "its link opens a suspicious website", ar: "رابطه يفتح موقعاً مشبوهاً" },
  ATTACHMENT_ARCHIVE: { en: "a compressed file is attached", ar: "مرفق ملف مضغوط" },
  CAMPAIGN_LURE_MATCH: { en: "it uses the wording of a known scam wave", ar: "يستخدم صياغة موجة احتيال معروفة" },
  CREDENTIAL_REQUEST: { en: "it asks for your password or card details", ar: "يطلب كلمة المرور أو بيانات البطاقة" },
  PAYMENT_REQUEST: { en: "it asks you to pay a fee", ar: "يطلب منك دفع رسوم" },
  URGENCY_LANGUAGE: { en: "fake deadlines and threats", ar: "مهل وتهديدات مزيفة" },
  BRAND_MENTION: { en: "it uses a well-known company's name", ar: "يستخدم اسم جهة معروفة" },
  USER_MODEL_SCAM: { en: "it looks like emails you marked as scams", ar: "يشبه رسائل صنّفتها سابقاً كاحتيال" },
  USER_MODEL_TRUSTED: { en: "it looks like emails you marked as safe", ar: "تشبه رسائل صنّفتها كآمنة" },
};
const DEFAULT_REASON = { en: "it fails official verification", ar: "لم يجتز التحقق الرسمي" };

export interface WarningInfo {
  entityEn: string | null;
  entityAr: string | null;
  domain: string | null;
  reasonEn: string;
  reasonAr: string;
  verdict: string;
  riskScore: number;
  caseId: string | null;
  flagsEn: string[];
  flagsAr: string[];
  channel: InterceptionChannel | null;
  detectedAt: Date;
  /** "email" / "message" word the community post as fake emails / messages instead of fake links. */
  kind?: "url" | "maps" | "email" | "message";
}

function reasonFor(codes: { code: string; points: number }[]) {
  const best = [...codes].sort((a, b) => b.points - a.points).find((f) => REASON_BY_FLAG[f.code]);
  return best ? REASON_BY_FLAG[best.code] : DEFAULT_REASON;
}

export function warningFromVerdict(r: ScanVerdict): WarningInfo {
  const reason = reasonFor(r.redFlags);
  const top = [...r.redFlags].sort((a, b) => b.points - a.points).slice(0, 5);
  return {
    entityEn: r.entityEn,
    entityAr: r.entityAr,
    domain: r.scamDomain,
    reasonEn: reason.en,
    reasonAr: reason.ar,
    verdict: r.verdict,
    riskScore: r.riskScore,
    caseId: r.scanId,
    flagsEn: top.map((f) => f.en),
    flagsAr: top.map((f) => f.ar),
    channel: r.interception,
    detectedAt: new Date(),
    kind: r.kind,
  };
}

export interface LiveBlock {
  id: string;
  kind: "url" | "maps" | "email";
  verdict: string;
  riskScore: number;
  entity: string | null;
  domain: string | null;
  channel: InterceptionChannel | null;
  harvested: string[];
  flagCodes: string[];
  at: Date;
}

export function warningFromLive(b: LiveBlock, entityAr: string | null): WarningInfo {
  const codes = [
    ...b.flagCodes.map((code) => ({ code, points: 1 })),
    ...(b.harvested.some((h) => ["OTP", "CARD_NUMBER", "CVV", "ATM_PIN"].includes(h))
      ? [{ code: "CREDENTIAL_HARVESTING", points: 10 }]
      : []),
    ...(b.entity ? [{ code: "BRAND_IMPERSONATION", points: 5 }] : []),
  ];
  const reason = reasonFor(codes);
  return {
    entityEn: b.entity,
    entityAr,
    domain: b.domain,
    reasonEn: reason.en,
    reasonAr: reason.ar,
    verdict: b.verdict,
    riskScore: b.riskScore,
    caseId: b.id,
    flagsEn: [reason.en],
    flagsAr: [reason.ar],
    channel: b.channel,
    detectedAt: b.at,
    kind: b.kind,
  };
}

export function buildXDraft(w: WarningInfo, lang: Lang): string {
  const masked = w.domain ? defang(w.domain) : null;
  if (lang === "ar") {
    const what = w.kind === "email" ? "رسائل بريد مزيفة" : w.kind === "message" ? "رسائل نصية مزيفة" : "روابط مزيفة";
    const who = w.entityAr ? `${what} تنتحل صفة ${w.entityAr}` : what;
    return (
      `⚠️ تحذير احتيال في أبوظبي: احذروا ${who}${masked ? ` (${masked})` : ""}. ` +
      `علامة الخطر: ${w.reasonAr}. تحقّقوا قبل الضغط وأبلغوا أمان 8002626 / رسالة 2828. ` +
      `#أبوظبي #الأمن_السيبراني #Aman8002626`
    );
  }
  const noun = w.kind === "email" ? "emails" : w.kind === "message" ? "text messages" : "links";
  const who = w.entityEn ? `fake ${w.entityEn} ${noun}` : `fake ${noun}`;
  return (
    `⚠️ Fraud Alert in Abu Dhabi: Watch out for ${who}${masked ? ` (${masked})` : ""}. ` +
    `Red flag: ${w.reasonEn}. Verify before clicking & report to Aman 8002626 / SMS 2828. ` +
    `#AbuDhabi #CyberSafety #Aman8002626`
  );
}

export function xIntentUrl(text: string): string {
  return `https://x.com/intent/post?text=${encodeURIComponent(text)}`;
}

export function buildAmanReport(w: WarningInfo, lang: Lang, channelLabel: string | null): string {
  const when = w.detectedAt.toLocaleString(lang === "ar" ? "ar-AE" : "en-GB", {
    timeZone: "Asia/Dubai",
    dateStyle: "medium",
    timeStyle: "short",
  });
  const flags = (lang === "ar" ? w.flagsAr : w.flagsEn).map((f) => `- ${f}`).join("\n");
  const site = w.domain ? defang(w.domain) : "—";
  if (lang === "ar") {
    return [
      "بلاغ احتيال — صقر → أمان 2828",
      w.caseId ? `رقم الفحص: ${w.caseId}` : null,
      `الوقت: ${when} (توقيت الإمارات)`,
      `النتيجة: ${w.verdict} (${w.riskScore}/100)`,
      w.entityAr ? `ينتحل صفة: ${w.entityAr}` : null,
      `الموقع المشبوه (معطّل): ${site}`,
      channelLabel ? `طريقة الرصد: ${channelLabel}` : null,
      flags ? `علامات الخطر:\n${flags}` : null,
    ]
      .filter(Boolean)
      .join("\n");
  }
  return [
    "Saqr fraud report → Aman 2828",
    w.caseId ? `Scan ID: ${w.caseId}` : null,
    `Time: ${when} (UAE)`,
    `Verdict: ${w.verdict} (${w.riskScore}/100)`,
    w.entityEn ? `Impersonating: ${w.entityEn}` : null,
    `Suspicious site (masked): ${site}`,
    channelLabel ? `Detected via: ${channelLabel}` : null,
    flags ? `Red flags:\n${flags}` : null,
  ]
    .filter(Boolean)
    .join("\n");
}

/** Copy text, falling back to a hidden textarea where the Clipboard API is blocked (plain-http LAN IPs). */
export async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to the legacy path */
  }
  try {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  } catch {
    return false;
  }
}
