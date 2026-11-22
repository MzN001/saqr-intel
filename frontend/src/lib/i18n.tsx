"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from "react";

export type Lang = "en" | "ar";

const dict = {
  appName: { en: "SAQR-INTEL", ar: "صقر للاستخبارات" },
  appTagline: { en: "Citizen Shield · Abu Dhabi", ar: "درع المواطن · أبوظبي" },
  banner: {
    en: "Agentless Cloud Shield Active • Zero App Install • Zero Phone Battery or RAM Usage",
    ar: "الدرع السحابي نشط بدون تطبيق • لا حاجة لتثبيت أي تطبيق • لا استهلاك لبطارية الهاتف أو ذاكرته",
  },
  aman: { en: "Aman", ar: "أمان" },
  sms: { en: "SMS", ar: "رسالة" },
  checkTitle: { en: "Check any link", ar: "افحص أي رابط" },
  checkHint: {
    en: "Got a link by SMS, WhatsApp or email? Paste it here and SAQR checks it in a secure cloud sandbox before you open it.",
    ar: "وصلك رابط عبر رسالة نصية أو واتساب أو بريد إلكتروني؟ الصقه هنا وسيفحصه صقر في بيئة سحابية آمنة قبل أن تفتحه.",
  },
  checkPlaceholder: {
    en: "Paste or type any website URL, Google Maps link, or SMS...",
    ar: "الصق أو اكتب أي رابط موقع أو رابط خرائط جوجل أو رسالة نصية...",
  },
  checkButton: { en: "Scan Now", ar: "افحص الآن" },
  checkClear: { en: "Clear", ar: "مسح" },
  checkInvalid: {
    en: "No website link found. Paste a URL, a Google Maps link or the whole SMS.",
    ar: "لم يتم العثور على رابط. الصق رابط موقع أو رابط خرائط جوجل أو الرسالة كاملة.",
  },
  checkTry: { en: "Try:", ar: "جرّب:" },
  exampleScam: { en: "Test Fake TAMM Fine", ar: "اختبر مخالفة تم المزيفة" },
  exampleSafe: { en: "Test Verified adpolice.gov.ae", ar: "اختبر adpolice.gov.ae الموثّق" },
  bgTitle: { en: "Activate System-Wide Background Shield (Zero App Required)", ar: "فعّل الدرع الخلفي على مستوى الجهاز (بدون أي تطبيق)" },
  bgIntro: {
    en: "One-time setup. Your phone then checks every website in every app (Chrome, Safari, Maps, WhatsApp) through an encrypted security DNS that blocks known phishing sites.",
    ar: "إعداد لمرة واحدة. بعدها يفحص هاتفك كل موقع في كل التطبيقات (كروم وسفاري والخرائط وواتساب) عبر نظام DNS آمن ومشفّر يحظر مواقع التصيّد المعروفة.",
  },
  bgPlatform: { en: "Your phone", ar: "هاتفك" },
  bgAndroid: { en: "Android", ar: "أندرويد" },
  bgIphone: { en: "iPhone (iOS)", ar: "آيفون (iOS)" },
  bgDetected: { en: "detected", ar: "تم التعرّف عليه" },
  bgNextdns: { en: "Custom NextDNS Filter ID (Optional for Live Demo)", ar: "معرّف فلتر NextDNS مخصص (اختياري للعرض المباشر)" },
  bgNextdnsHint: {
    en: "Leave empty to use Cloudflare's free security DNS. Paste your NextDNS ID (e.g. abc123) to block your own test domains on stage.",
    ar: "اتركه فارغاً لاستخدام DNS الأمني المجاني من Cloudflare. الصق معرّف NextDNS (مثل abc123) لحظر نطاقات الاختبار الخاصة بك أثناء العرض.",
  },
  bgNextdnsInvalid: { en: "A NextDNS ID is 4-16 letters and digits only.", ar: "معرّف NextDNS يتكون من 4 إلى 16 حرفاً ورقماً فقط." },
  bgAndroidHost: { en: "Private DNS hostname", ar: "اسم مضيف DNS الخاص" },
  bgCopyAndroid: { en: "Copy Android Private DNS", ar: "نسخ DNS الخاص لأندرويد" },
  bgCopied: { en: "Copied! Now paste it in Private DNS settings.", ar: "تم النسخ! الصقه الآن في إعدادات DNS الخاص." },
  bgA1: { en: "Open Android Settings → Network & Internet (Samsung: Connections → More connection settings).", ar: "افتح إعدادات أندرويد ← الشبكة والإنترنت (سامسونج: الاتصالات ← المزيد من إعدادات الاتصال)." },
  bgA2: { en: "Tap Private DNS → Private DNS provider hostname.", ar: "اضغط DNS الخاص ← اسم مضيف مزوّد DNS الخاص." },
  bgA3: { en: "Paste the copied hostname and tap Save. Phishing domains are now blocked in Chrome, Maps and all apps in the background.", ar: "الصق اسم المضيف المنسوخ واضغط حفظ. أصبحت نطاقات التصيّد محظورة في كروم والخرائط وجميع التطبيقات في الخلفية." },
  bgAndroidTip: {
    en: "Tip: Tap Browser Menu (⋮) → Add to Home Screen to also add 'SAQR Verify' to your Android Share menu.",
    ar: "نصيحة: اضغط قائمة المتصفح (⋮) ← إضافة إلى الشاشة الرئيسية لإضافة «SAQR Verify» إلى قائمة المشاركة في أندرويد.",
  },
  bgDownloadIos: { en: "Download iPhone DNS Profile", ar: "تنزيل ملف DNS للآيفون" },
  bgI1: { en: "Tap Download above, then tap Allow in Safari.", ar: "اضغط تنزيل بالأعلى، ثم اضغط سماح في سفاري." },
  bgI2: { en: "Open iPhone Settings → General → VPN, DNS & Device Management.", ar: "افتح إعدادات الآيفون ← عام ← VPN وDNS وإدارة الجهاز." },
  bgI3: { en: "Tap SAQR-INTEL Citizen DNS Shield → Install.", ar: "اضغط SAQR-INTEL Citizen DNS Shield ← تثبيت." },
  bgIosNote: { en: "Open this page in Safari on the iPhone. Remove the profile any time in the same settings screen.", ar: "افتح هذه الصفحة في سفاري على الآيفون. يمكنك حذف الملف في أي وقت من نفس شاشة الإعدادات." },
  bgFootnote: {
    en: "Cloudflare 1.1.1.2 blocks known malware & phishing worldwide. With an e& / du partnership, SAQR's own live detections would be added to this shield.",
    ar: "يحظر Cloudflare 1.1.1.2 البرمجيات الخبيثة ومواقع التصيّد المعروفة عالمياً. وبالشراكة مع اتصالات ودو ستُضاف اكتشافات صقر المباشرة إلى هذا الدرع.",
  },
  shareQr: { en: "Share App QR", ar: "رمز QR للتطبيق" },
  shareQrTitle: { en: "Scan to open SAQR Verify", ar: "امسح لفتح صقر للتحقق" },
  shareQrHint: {
    en: "Point a phone camera at the code to open the Citizen Shield. No app install needed.",
    ar: "وجّه كاميرا الهاتف نحو الرمز لفتح درع المواطن. لا حاجة لتثبيت أي تطبيق.",
  },
  shareQrLocal: {
    en: "This address only works on this computer. Open the app through your Wi-Fi IP or a Cloudflare tunnel so phones can reach it.",
    ar: "هذا العنوان يعمل على هذا الجهاز فقط. افتح التطبيق عبر عنوان شبكة الواي فاي أو نفق Cloudflare ليتمكن الهاتف من الوصول إليه.",
  },
  copyLink: { en: "Copy link", ar: "نسخ الرابط" },
  copied: { en: "Copied", ar: "تم النسخ" },
  copyFailed: { en: "Couldn't copy. Select the text and copy it manually.", ar: "تعذّر النسخ. حدّد النص وانسخه يدوياً." },
  xPromptTitle: { en: "Warn Others in Abu Dhabi? / ساعد في حماية المجتمع", ar: "ساعد في حماية المجتمع / Warn Others in Abu Dhabi?" },
  xPromptBody: {
    en: "Your permission is required: Nothing is posted automatically. Scam links are masked ([.]) so nobody can accidentally click them.",
    ar: "موافقتك مطلوبة: لا يُنشر أي شيء تلقائياً. تُعطَّل روابط الاحتيال ([.]) حتى لا يضغط عليها أحد بالخطأ.",
  },
  xYes: { en: "Yes, Preview X Warning", ar: "نعم، معاينة التحذير على X" },
  xNo: { en: "No Thanks", ar: "لا، شكراً" },
  xDeclined: { en: "Nothing was shared.", ar: "لم تتم مشاركة أي شيء." },
  xChangeMind: { en: "Preview the warning", ar: "معاينة التحذير" },
  xModalTitle: { en: "Preview your X warning", ar: "معاينة تحذيرك على X" },
  xDraftLang: { en: "Post language", ar: "لغة المنشور" },
  xEditHint: { en: "You can edit the text before posting.", ar: "يمكنك تعديل النص قبل النشر." },
  xApprove: { en: "Approve & Open X to Post", ar: "موافقة وفتح X للنشر" },
  xTooLong: { en: "Too long for X. Shorten it to 280 characters.", ar: "النص أطول من المسموح في X. اختصره إلى 280 حرفاً." },
  xNothingPosted: {
    en: "X opens in a new tab with your text. Nothing is posted until you press Post there.",
    ar: "سيُفتح X في نافذة جديدة مع نصك. لن يُنشر شيء حتى تضغط «نشر» هناك.",
  },
  copyAman: { en: "Copy Aman (2828) Report", ar: "نسخ بلاغ أمان (2828)" },
  amanCopied: { en: "Report copied. Paste it into an SMS to 2828.", ar: "تم نسخ البلاغ. الصقه في رسالة نصية إلى 2828." },
  warnOnX: { en: "Warn on X", ar: "حذّر على X" },
  liveTitle: { en: "Live Crowd-Shield", ar: "درع المجتمع المباشر" },
  liveIntro: {
    en: "Scams being blocked across Abu Dhabi right now. Anonymized: no resident names, numbers or locations.",
    ar: "عمليات احتيال يتم حظرها في أبوظبي الآن. بيانات مجهولة الهوية: لا أسماء أو أرقام أو مواقع للسكان.",
  },
  liveConnecting: { en: "Connecting…", ar: "جارٍ الاتصال…" },
  liveOn: { en: "Live", ar: "مباشر" },
  liveOff: { en: "Offline · retrying", ar: "غير متصل · إعادة المحاولة" },
  liveEmpty: {
    en: "No blocks yet. Run a scan above or play the SMS demo and it appears here instantly.",
    ar: "لا توجد عمليات حظر بعد. افحص رابطاً بالأعلى أو شغّل عرض الرسائل وستظهر هنا فوراً.",
  },
  liveBlocked: { en: "Blocked", ar: "محظور" },
  liveFlagged: { en: "Flagged", ar: "مشبوه" },
  themeToDark:{ en: "Switch to dark mode", ar: "التبديل إلى الوضع الداكن" },
  themeToLight: { en: "Switch to light mode", ar: "التبديل إلى الوضع الفاتح" },
  tabSearch: { en: "Search & Maps Shield", ar: "درع البحث والخرائط" },
  tabSearchShort: { en: "Search & Maps", ar: "البحث والخرائط" },
  tabSms: { en: "SMS Smishing Guard", ar: "حارس الرسائل الاحتيالية" },
  tabSmsShort: { en: "SMS Guard", ar: "حارس الرسائل" },
  tabRadar: { en: "Crowd-Shield Radar", ar: "رادار درع المجتمع" },
  tabRadarShort: { en: "Radar", ar: "الرادار" },
  searchIntro: {
    en: "Browse like any resident. Tap the sponsored result or “Visit Website”: the telecom DNS shield intercepts it automatically.",
    ar: "تصفّح كأي مقيم. اضغط على النتيجة الممولة أو «زيارة الموقع الإلكتروني» وسيعترضها درع DNS لدى مزوّد الاتصالات تلقائياً.",
  },
  searchQuery: { en: "abu dhabi police traffic fine payment", ar: "دفع مخالفات المرور شرطة أبوظبي" },
  sponsored: { en: "Sponsored", ar: "إعلان ممول" },
  adTitle: { en: "Abu Dhabi Police Traffic Fine Payment", ar: "دفع مخالفات المرور - شرطة أبوظبي" },
  adBody: {
    en: "Pay your traffic fines online in 2 minutes. 50% discount ends today. Avoid vehicle impoundment.",
    ar: "ادفع مخالفاتك المرورية إلكترونياً خلال دقيقتين. خصم 50٪ ينتهي اليوم. تجنّب حجز المركبة.",
  },
  organicTitle: { en: "Abu Dhabi Police – Official Website", ar: "شرطة أبوظبي - الموقع الرسمي" },
  organicBody: {
    en: "Official e-services of Abu Dhabi Police. Traffic fines are paid via TAMM or the AD Police app.",
    ar: "الخدمات الإلكترونية الرسمية لشرطة أبوظبي. تُدفع المخالفات عبر منصة تم أو تطبيق شرطة أبوظبي.",
  },
  mapsCardTitle: { en: "Emirates Post Customer Center - Abu Dhabi", ar: "مركز خدمة عملاء بريد الإمارات - أبوظبي" },
  mapsCategory: { en: "Post office · Mussafah M-37", ar: "مكتب بريد · مصفح م-37" },
  openNow: { en: "Open 24 hours", ar: "مفتوح 24 ساعة" },
  directions: { en: "Directions", ar: "الاتجاهات" },
  call: { en: "Call", ar: "اتصال" },
  visitWebsite: { en: "Visit Website", ar: "زيارة الموقع" },
  save: { en: "Save", ar: "حفظ" },
  dnsIntercepting: { en: "Telecom DNS shield intercepting request…", ar: "درع DNS لدى مزوّد الاتصالات يعترض الطلب…" },
  scanningTitle: { en: "Verifying this link in the cloud", ar: "جارٍ التحقق من الرابط سحابياً" },
  stepIntercept: { en: "Request intercepted before it loads", ar: "تم اعتراض الطلب قبل تحميله" },
  stepRegistry: { en: "Checking UAE official registry", ar: "مطابقة السجل الرسمي في الدولة" },
  stepSandbox: { en: "Opening page in secure cloud sandbox", ar: "فتح الصفحة في بيئة سحابية معزولة" },
  stepAi: { en: "AI inspector reading the page", ar: "المحلّل الذكي يقرأ محتوى الصفحة" },
  stepPolice: { en: "Cross-checking police intelligence", ar: "مطابقة معلومات الشرطة الاستخباراتية" },
  blockedTitle: { en: "Website blocked for your protection", ar: "تم حظر الموقع لحمايتك" },
  suspiciousTitle: { en: "Warning: this website looks suspicious", ar: "تحذير: هذا الموقع يبدو مشبوهاً" },
  safeTitle: { en: "Verified safe", ar: "تم التحقق: آمن" },
  blockedBy: { en: "Automatic block by Abu Dhabi Police & UAE telecom providers", ar: "حظر تلقائي من شرطة أبوظبي ومزوّدي الاتصالات في الدولة" },
  riskScore: { en: "Risk score", ar: "درجة الخطورة" },
  impersonating: { en: "Impersonating", ar: "ينتحل صفة" },
  unknownEntity: { en: "Unknown entity", ar: "جهة غير معروفة" },
  officialSite: { en: "Official website", ar: "الموقع الرسمي" },
  whyDangerous: { en: "Why this is dangerous", ar: "لماذا هذا خطير" },
  whySafe: { en: "Why this is safe", ar: "لماذا هذا آمن" },
  redFlags: { en: "Red flags", ar: "علامات الخطر" },
  wantsYour: { en: "This page tries to steal", ar: "تحاول هذه الصفحة سرقة" },
  syndicateLink: { en: "Linked to criminal network", ar: "مرتبط بشبكة إجرامية" },
  syncedBadge: { en: "Incident automatically synced to Abu Dhabi Police Command Center", ar: "تمت مزامنة البلاغ تلقائياً مع مركز القيادة في شرطة أبوظبي" },
  caseId: { en: "Case", ar: "رقم البلاغ" },
  backToSafety: { en: "Back to safety", ar: "العودة إلى الأمان" },
  goOfficial: { en: "Go to official site", ar: "الانتقال إلى الموقع الرسمي" },
  callAman: { en: "Call Aman 8002626", ar: "اتصل بأمان 8002626" },
  continueSite: { en: "Continue to website", ar: "المتابعة إلى الموقع" },
  otherLanguage: { en: "عرض بالعربية", ar: "Show in English" },
  evidence: { en: "Captured evidence (sandbox)", ar: "الدليل المُلتقط (البيئة المعزولة)" },
  registered: { en: "Registered", ar: "تاريخ التسجيل" },
  hoursAgo: { en: "h ago", ar: "ساعة مضت" },
  hostedOn: { en: "Hosted on", ar: "مستضاف على" },
  cloaking: { en: "Hides from security scanners", ar: "يتخفّى من أنظمة الفحص الأمني" },
  scanFailed: { en: "Could not complete the scan", ar: "تعذّر إكمال الفحص" },
  retry: { en: "Try again", ar: "إعادة المحاولة" },
  close: { en: "Close", ar: "إغلاق" },
  channelDns: { en: "Telecom DNS Shield", ar: "درع DNS للاتصالات" },
  channelSms: { en: "SMS Smishing Guard", ar: "حارس الرسائل" },
  channelShare: { en: "Phone Share Sheet", ar: "قائمة المشاركة في الهاتف" },
  channelManual: { en: "Manual check", ar: "فحص يدوي" },
  channelPc: { en: "PC Browser Shield", ar: "درع متصفح الكمبيوتر" },
  channelApi: { en: "Partner API", ar: "واجهة الشركاء" },
  smsIntro: {
    en: "A scam SMS arrives. SAQR scans it in the background and quarantines it before you can tap the link.",
    ar: "تصل رسالة احتيالية. يفحصها صقر في الخلفية ويعزلها قبل أن تتمكن من الضغط على الرابط.",
  },
  messages: { en: "Messages", ar: "الرسائل" },
  inbox: { en: "Inbox", ar: "الوارد" },
  quarantine: { en: "Quarantined Phishing", ar: "رسائل احتيال معزولة" },
  now: { en: "now", ar: "الآن" },
  smsScanning: { en: "SAQR scanning link in the cloud…", ar: "صقر يفحص الرابط سحابياً…" },
  smsQuarantined: { en: "Moved to quarantine · link disabled", ar: "نُقلت إلى العزل · تم تعطيل الرابط" },
  smsSafeFlag: { en: "Checked by SAQR · safe", ar: "تم الفحص بواسطة صقر · آمنة" },
  replay: { en: "Replay demo", ar: "إعادة العرض" },
  viewWarning: { en: "View warning", ar: "عرض التحذير" },
  emptyQuarantine: { en: "No quarantined messages yet", ar: "لا توجد رسائل معزولة بعد" },
  newMessage: { en: "New message", ar: "رسالة جديدة" },
  radarTitle: { en: "Live Community Crowd-Shield Radar", ar: "رادار درع المجتمع المباشر" },
  radarIntro: {
    en: "Active scam waves detected across Abu Dhabi, with the official bilingual alerts broadcast to residents in affected areas.",
    ar: "موجات الاحتيال النشطة المرصودة في أبوظبي، مع التنبيهات الرسمية ثنائية اللغة المرسلة إلى السكان في المناطق المتأثرة.",
  },
  activeWaves: { en: "Active scam waves", ar: "موجات احتيال نشطة" },
  severity: { en: "Severity", ar: "مستوى الخطورة" },
  reports: { en: "reports", ar: "بلاغات" },
  certificates: { en: "new fake certificates", ar: "شهادات مزيفة جديدة" },
  scans: { en: "scans", ar: "عمليات فحص" },
  targetAreas: { en: "Broadcast zones", ar: "مناطق البث" },
  safetyTips: { en: "Safety tips", ar: "نصائح السلامة" },
  broadcastAt: { en: "Broadcast", ar: "تم البث" },
  refresh: { en: "Refresh", ar: "تحديث" },
  noWaves: { en: "No active scam waves right now. Stay alert.", ar: "لا توجد موجات احتيال نشطة حالياً. ابقَ يقظاً." },
  backendOffline: { en: "Can't reach SAQR-INTEL backend. Start it on port 8000.", ar: "تعذّر الاتصال بخادم صقر. شغّله على المنفذ 8000." },
  high: { en: "HIGH", ar: "مرتفع" },
  medium: { en: "MEDIUM", ar: "متوسط" },
  low: { en: "LOW", ar: "منخفض" },
  lastUpdated: { en: "Updated", ar: "آخر تحديث" },
  sharedLink: { en: "Shared to SAQR Verify", ar: "تمت المشاركة إلى صقر للتحقق" },
  footer: {
    en: "Report fraud: Aman 8002626 · SMS 2828 · Emergency 999",
    ar: "للإبلاغ عن الاحتيال: أمان 8002626 · رسالة نصية 2828 · الطوارئ 999",
  },
} as const;

export type DictKey = keyof typeof dict;

interface LangContextValue {
  lang: Lang;
  dir: "ltr" | "rtl";
  setLang: (l: Lang) => void;
  toggle: () => void;
  t: (key: DictKey) => string;
}

const LangContext = createContext<LangContextValue | null>(null);

const STORAGE_KEY = "saqr-lang";
const listeners = new Set<() => void>();
let currentLang: Lang | null = null;

function readStoredLang(): Lang {
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "ar" ? "ar" : "en";
  } catch {
    return "en";
  }
}

const langStore = {
  subscribe(cb: () => void) {
    listeners.add(cb);
    return () => {
      listeners.delete(cb);
    };
  },
  getSnapshot(): Lang {
    if (currentLang === null) currentLang = readStoredLang();
    return currentLang;
  },
  getServerSnapshot(): Lang {
    return "en";
  },
  set(l: Lang) {
    currentLang = l;
    try {
      window.localStorage.setItem(STORAGE_KEY, l);
    } catch {
      /* storage unavailable (private mode) */
    }
    listeners.forEach((cb) => cb());
  },
};

export function LanguageProvider({ children }: { children: ReactNode }) {
  const lang = useSyncExternalStore(langStore.subscribe, langStore.getSnapshot, langStore.getServerSnapshot);

  useEffect(() => {
    document.documentElement.lang = lang;
    document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  }, [lang]);

  const setLang = useCallback((l: Lang) => langStore.set(l), []);

  const value = useMemo<LangContextValue>(
    () => ({
      lang,
      dir: lang === "ar" ? "rtl" : "ltr",
      setLang,
      toggle: () => setLang(lang === "en" ? "ar" : "en"),
      t: (key) => dict[key][lang],
    }),
    [lang, setLang],
  );

  return <LangContext.Provider value={value}>{children}</LangContext.Provider>;
}

export function useLang(): LangContextValue {
  const ctx = useContext(LangContext);
  if (!ctx) throw new Error("useLang must be used inside <LanguageProvider>");
  return ctx;
}
