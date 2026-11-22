import type { InterceptionChannel, ScanVerdict } from "./api";
import type { DictKey, Lang } from "./i18n";

export const CHANNEL_DICT_KEY: Record<InterceptionChannel, DictKey> = {
  AUTO_TELECOM_DNS: "channelDns",
  AUTO_SMS_GUARD: "channelSms",
  MOBILE_OS_SHARE_SHEET: "channelShare",
  CITIZEN_MANUAL_CHECK: "channelManual",
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
  HOMOGLYPH_SPOOF: { en: "look-alike letters in the web address", ar: "أحرف مشابهة في عنوان الموقع" },
  BRAND_IMPERSONATION: { en: "it is not the official website", ar: "ليس الموقع الرسمي" },
  TYPOSQUAT: { en: "a misspelled copy of the official address", ar: "نسخة بأخطاء إملائية من العنوان الرسمي" },
  TLD_SWAP: { en: "the official name with the wrong ending", ar: "الاسم الرسمي بامتداد خاطئ" },
  CLOAKING: { en: "it hides from security scanners", ar: "يتخفّى من أنظمة الفحص الأمني" },
  YOUNG_DOMAIN: { en: "a very new website", ar: "موقع حديث جداً" },
  URGENCY_PRESSURE: { en: "fake deadlines and threats", ar: "مهل وتهديدات مزيفة" },
  SUSPICIOUS_TLD: { en: "an unusual web address", ar: "عنوان موقع غير مألوف" },
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
  };
}

export interface LiveBlock {
  id: string;
  kind: "url" | "maps";
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
  };
}

export function buildXDraft(w: WarningInfo, lang: Lang): string {
  const masked = w.domain ? defang(w.domain) : null;
  if (lang === "ar") {
    const who = w.entityAr ? `روابط مزيفة تنتحل صفة ${w.entityAr}` : "روابط مزيفة";
    return (
      `⚠️ تحذير احتيال في أبوظبي: احذروا ${who}${masked ? ` (${masked})` : ""}. ` +
      `علامة الخطر: ${w.reasonAr}. تحقّقوا قبل الضغط وأبلغوا أمان 8002626 / رسالة 2828. ` +
      `#أبوظبي #الأمن_السيبراني #Aman8002626`
    );
  }
  const who = w.entityEn ? `fake ${w.entityEn} links` : "fake links";
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
      "بلاغ احتيال — صقر للاستخبارات → أمان 2828",
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
    "SAQR-INTEL fraud report → Aman 2828",
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
