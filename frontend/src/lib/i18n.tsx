"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useSyncExternalStore, type ReactNode } from "react";

export type Lang = "en" | "ar";

const dict = {
  appName: { en: "SAQR-INTEL", ar: "صقر للاستخبارات" },
  appTagline: { en: "Citizen Shield · Abu Dhabi", ar: "درع المواطن · أبوظبي" },
  banner: {
    en: "Agentless Cloud Shield Active • No App to Install • Checks Run in the Cloud, Not on Your Phone",
    ar: "الدرع السحابي نشط بدون تطبيق • لا حاجة لتثبيت أي تطبيق • يتم الفحص سحابياً وليس على هاتفك",
  },
  // Phones: the first claim of `banner` only, so the strip stays on one line.
  bannerShort: { en: "Agentless Cloud Shield Active", ar: "الدرع السحابي نشط بدون تطبيق" },
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
  // Shown instead of the raw demo address (http://127.0.0.1:8000/mock-scam/...), which looks broken to judges.
  exampleScamLabel: { en: "Example scam page (safe demo)", ar: "صفحة احتيال تجريبية (عرض آمن)" },
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
  alTitle: { en: "Scam Alerts on This Phone", ar: "تنبيهات الاحتيال على هذا الهاتف" },
  alIntro: {
    en: "Get an instant notification whenever SAQR blocks a scam website you or a link tried to open, with what it was and how to stay safe.",
    ar: "احصل على إشعار فوري كلما حظر صقر موقعاً احتيالياً حاولت فتحه، مع توضيح ما هو وكيف تبقى آمناً.",
  },
  alPreviewApp: { en: "SAQR", ar: "صقر" },
  alPreviewNow: { en: "now", ar: "الآن" },
  alPreviewTitle: { en: "🛑 SAQR blocked a scam website", ar: "🛑 صقر حظر موقعاً احتيالياً" },
  alPreviewBody: {
    en: "A fake TAMM Abu Dhabi website was blocked on your phone. Never enter card or OTP details.",
    ar: "تم حظر موقع تم المزيف على هاتفك. لا تُدخل أبداً بيانات البطاقة أو رمز التحقق.",
  },
  alEnable: { en: "Enable Scam Alerts", ar: "تفعيل تنبيهات الاحتيال" },
  alEnabling: { en: "Turning on…", ar: "جارٍ التفعيل…" },
  alOn: { en: "Scam alerts are ON for this phone", ar: "تنبيهات الاحتيال مفعّلة على هذا الهاتف" },
  alOnSub: { en: "You'll be notified the moment SAQR blocks a scam.", ar: "سيتم إشعارك فور حظر صقر لأي موقع احتيالي." },
  alOnlyThis: {
    en: "Alerts go to this phone only. Set up the shield on this phone (once) so SAQR knows the block was yours:",
    ar: "تصل التنبيهات إلى هذا الهاتف فقط. فعّل الدرع على هذا الهاتف (مرة واحدة) ليعرف صقر أن الحظر كان لديك:",
  },
  alLinkIos: { en: "Install this iPhone's shield", ar: "ثبّت درع هذا الآيفون" },
  alLinkAndroid: {
    en: "Android: copy the Private DNS hostname from the shield card again and save it in Settings.",
    ar: "أندرويد: انسخ اسم مضيف DNS الخاص من بطاقة الدرع مرة أخرى واحفظه في الإعدادات.",
  },
  alTest: { en: "Send test alert", ar: "إرسال تنبيه تجريبي" },
  alTestSent: { en: "Test alert sent. It should appear in a few seconds.", ar: "تم إرسال التنبيه التجريبي. سيظهر خلال ثوانٍ." },
  alOff: { en: "Turn off", ar: "إيقاف" },
  alIosTitle: { en: "One step first on iPhone", ar: "خطوة واحدة أولاً على الآيفون" },
  alIosIntro: {
    en: "Apple only allows alerts for websites added to the Home Screen. It takes 10 seconds:",
    ar: "تسمح آبل بالتنبيهات فقط للمواقع المضافة إلى الشاشة الرئيسية. يستغرق ذلك 10 ثوانٍ:",
  },
  alIos1: { en: "Tap the Share button in Safari", ar: "اضغط زر المشاركة في سفاري" },
  alIos2: { en: "Choose “Add to Home Screen”, then Add", ar: "اختر «إضافة إلى الشاشة الرئيسية» ثم إضافة" },
  alIos3: { en: "Open SAQR from your Home Screen and tap Enable", ar: "افتح صقر من الشاشة الرئيسية واضغط تفعيل" },
  alIosOld: { en: "Needs iOS 16.4 or newer (Settings → General → About).", ar: "يتطلب iOS 16.4 أو أحدث (الإعدادات ← عام ← حول)." },
  alUnsupported: {
    en: "This browser can't receive alerts. On Android use Chrome or Samsung Internet; on iPhone use Safari and add SAQR to the Home Screen.",
    ar: "هذا المتصفح لا يدعم التنبيهات. على أندرويد استخدم كروم أو سامسونج إنترنت، وعلى الآيفون استخدم سفاري وأضف صقر إلى الشاشة الرئيسية.",
  },
  alDenied: { en: "Notifications are blocked for SAQR", ar: "الإشعارات محظورة لصقر" },
  alDeniedIos: { en: "iPhone: Settings → Notifications → SAQR → Allow Notifications.", ar: "آيفون: الإعدادات ← الإشعارات ← صقر ← السماح بالإشعارات." },
  alDeniedAndroid: {
    en: "Android: tap the lock icon next to the address → Permissions → Notifications → Allow.",
    ar: "أندرويد: اضغط رمز القفل بجانب العنوان ← الأذونات ← الإشعارات ← سماح.",
  },
  alError: { en: "Couldn't turn on alerts. Check the connection and try again.", ar: "تعذّر تفعيل التنبيهات. تحقق من الاتصال وحاول مجدداً." },
  alHow: {
    en: "How it works: your SAQR DNS shield blocks the site, SAQR spots the blocked attempt, and this phone gets the alert.",
    ar: "طريقة العمل: يحظر درع DNS الخاص بصقر الموقع، ويرصد صقر محاولة الدخول المحظورة، فيصلك التنبيه على هذا الهاتف.",
  },
  bgFeedOn:{ en: "SAQR live threat feed connected", ar: "خلاصة تهديدات صقر المباشرة متصلة" },
  bgFeedError: { en: "SAQR feed paused: check the NextDNS key on the server", ar: "خلاصة صقر متوقفة: تحقق من مفتاح NextDNS على الخادم" },
  bgFeedDomains: { en: "scam domains blocked", ar: "نطاق احتيالي محظور" },
  bgFeedUsing: {
    en: "Your phone will block every scam SAQR detects, within seconds, in all apps.",
    ar: "سيحظر هاتفك كل موقع احتيالي يكتشفه صقر خلال ثوانٍ وفي جميع التطبيقات.",
  },
  bgAndroidHost:{ en: "Private DNS hostname", ar: "اسم مضيف DNS الخاص" },
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
  bgShowSteps: { en: "Show the 3 setup steps", ar: "اعرض خطوات الإعداد الثلاث" },
  bgAdvanced: { en: "Advanced: demo filter & DNS details", ar: "متقدم: مرشّح العرض وتفاصيل DNS" },
  howItWorks: { en: "How it works", ar: "كيف يعمل" },
  reportFraud: { en: "Report fraud", ar: "بلّغ عن احتيال" },
  emergency: { en: "Emergency", ar: "الطوارئ" },
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
  backendOffline: { en: "Can't reach the SAQR-INTEL server right now (it may be waking up). Try again in 30 seconds.", ar: "تعذّر الاتصال بخادم صقر حالياً (قد يكون قيد التشغيل). حاول مرة أخرى بعد 30 ثانية." },
  high: { en: "HIGH", ar: "مرتفع" },
  medium: { en: "MEDIUM", ar: "متوسط" },
  low: { en: "LOW", ar: "منخفض" },
  sevCritical: { en: "CRITICAL", ar: "حرج" },
  sevInfo: { en: "INFO", ar: "معلومة" },
  verdictHighRisk: { en: "HIGH-RISK SCAM", ar: "احتيال عالي الخطورة" },
  verdictSuspicious: { en: "SUSPICIOUS", ar: "مشبوه" },
  verdictSafe: { en: "SAFE", ar: "آمن" },
  lastUpdated: { en: "Updated", ar: "آخر تحديث" },
  sharedLink: { en: "Shared to SAQR Verify", ar: "تمت المشاركة إلى صقر للتحقق" },
  footer: {
    en: "Report fraud: Aman 8002626 · SMS 2828 · Emergency 999",
    ar: "للإبلاغ عن الاحتيال: أمان 8002626 · رسالة نصية 2828 · الطوارئ 999",
  },
  // ---------------------------------------------------------------- privacy + "report a false alarm"
  privacyLine: {
    en: "SAQR keeps this check and its result for 30 days to help protect others; links found to be scams stay longer as police evidence. No account needed.",
    ar: "يحتفظ صقر بهذا الفحص ونتيجته 30 يوماً لحماية الآخرين، وتبقى الروابط الاحتيالية مدة أطول كدليل لدى الشرطة. لا حاجة إلى حساب.",
  },
  privTitle: { en: "Privacy: what SAQR keeps", ar: "الخصوصية: ما يحتفظ به صقر" },
  privStored: {
    en: "What is stored: the address of the link you check and its result, any message text you paste with it, and for emails the sender, subject and a short excerpt (never the full email or its files). For a safe link the part after “?” is not stored.",
    ar: "ما يُحفظ: عنوان الرابط الذي تفحصه ونتيجته، وأي نص رسالة تلصقه معه، وفي البريد المرسل والموضوع ومقتطف قصير (لا الرسالة كاملة ولا مرفقاتها). في الرابط الآمن لا يُحفظ الجزء الذي بعد «؟».",
  },
  privRetention: {
    en: "How long: safe results and email checks are deleted after 30 days. Links found to be scams are kept as police evidence for the blocklist, and the message text you pasted is removed from them after 30 days.",
    ar: "المدة: تُحذف النتائج الآمنة وفحوص البريد بعد 30 يوماً. تُحفظ الروابط الاحتيالية دليلاً لدى الشرطة لقائمة الحظر، ويُحذف منها نص الرسالة الذي لصقته بعد 30 يوماً.",
  },
  privReports: {
    en: "Reports: “Report a false alarm” sends only the website name, the result and your optional note to SAQR officers for review.",
    ar: "البلاغات: «الإبلاغ عن إنذار خاطئ» يرسل اسم الموقع والنتيجة وملاحظتك الاختيارية فقط إلى ضباط صقر للمراجعة.",
  },
  privNoAccount: {
    en: "No account, name or phone number is ever asked for.",
    ar: "لا نطلب أبداً حساباً أو اسماً أو رقم هاتف.",
  },
  faReport: { en: "Report a false alarm", ar: "الإبلاغ عن إنذار خاطئ" },
  faNoteLabel: { en: "Why do you think this is a mistake? (optional)", ar: "لماذا تعتقد أن هذا خطأ؟ (اختياري)" },
  faNotePlaceholder: { en: "e.g. This is my bank's real website", ar: "مثال: هذا الموقع الرسمي لبنكي" },
  faSend: { en: "Send for review", ar: "أرسل للمراجعة" },
  faSending: { en: "Sending…", ar: "جارٍ الإرسال…" },
  faCancel: { en: "Cancel", ar: "إلغاء" },
  faSentWhat: {
    en: "Only the website name, the result and your note are sent. Keep the warning in mind until an officer has looked.",
    ar: "يُرسل اسم الموقع والنتيجة وملاحظتك فقط. خذ التحذير بعين الاعتبار حتى يراجعه ضابط.",
  },
  faThanks: {
    en: "Thank you. An officer will review this report.",
    ar: "شكراً لك. سيراجع أحد الضباط هذا البلاغ.",
  },
  faAlready: {
    en: "Thanks, your report for this check is already with an officer for review.",
    ar: "شكراً، بلاغك عن هذا الفحص لدى أحد الضباط للمراجعة.",
  },
  faRateLimited: {
    en: "Too many reports in one minute. Please try again shortly.",
    ar: "بلاغات كثيرة خلال دقيقة. حاول مرة أخرى بعد قليل.",
  },
  faNotFound: {
    en: "This check is no longer stored, so it can't be reported.",
    ar: "لم يعد هذا الفحص محفوظاً، لذا لا يمكن الإبلاغ عنه.",
  },
  faFailed: {
    en: "Couldn't send the report. Check your connection and try again.",
    ar: "تعذّر إرسال البلاغ. تحقق من اتصالك وحاول مرة أخرى.",
  },
  // ---------------------------------------------------------------- email scanning (EmailGuard + verdict)
  emTab: { en: "Email Scam Check", ar: "فحص البريد الاحتيالي" },
  emTabShort: { en: "Email", ar: "البريد" },
  emIntro: {
    en: "Got an email that looks wrong? SAQR checks who really sent it, hidden lookalike letters, every link and every attachment, without opening anything on your device.",
    ar: "وصلتك رسالة بريد مريبة؟ يتحقق صقر من المرسل الحقيقي ومن الأحرف المتشابهة المخفية ومن كل رابط ومرفق، دون فتح أي شيء على جهازك.",
  },
  emTitle: { en: "Check a suspicious email", ar: "افحص رسالة بريد مشبوهة" },
  emHint: {
    en: "Paste the email, paste its full source, or upload the email file. Do not click anything inside it first.",
    ar: "الصق الرسالة أو مصدرها الكامل أو ارفع ملف الرسالة. لا تضغط على أي شيء داخلها قبل الفحص.",
  },
  emModeText: { en: "Paste the email", ar: "الصق الرسالة" },
  emModeRaw: { en: "Paste full source", ar: "الصق المصدر الكامل" },
  emModeFile: { en: "Upload a file", ar: "ارفع ملفاً" },
  emTextLabel: { en: "Email text", ar: "نص الرسالة" },
  emTextPlaceholder: {
    en: "Paste the whole email here: the sender, the subject and the message...",
    ar: "الصق الرسالة كاملة هنا: المرسل والعنوان والنص...",
  },
  emRawLabel: { en: "Full email source", ar: "المصدر الكامل للرسالة" },
  emRawPlaceholder: {
    en: "Paste the full original here (it starts with lines like “Received:” or “Delivered-To:”)...",
    ar: "الصق النص الأصلي الكامل هنا (يبدأ بأسطر مثل “Received:” أو “Delivered-To:”)...",
  },
  emRawWhy: {
    en: "The full source lets SAQR check SPF, DKIM and DMARC: the proof of who really sent the email.",
    ar: "يتيح المصدر الكامل لصقر فحص SPF وDKIM وDMARC: وهي الإثبات على هوية المرسل الحقيقي.",
  },
  emHowTo: { en: "How do I copy the full source?", ar: "كيف أنسخ المصدر الكامل؟" },
  emGmailHow: {
    en: "Gmail (computer): open the email → ⋮ More → Show original → Copy to clipboard.",
    ar: "Gmail (على الكمبيوتر): افتح الرسالة ← ⋮ المزيد ← عرض الرسالة الأصلية ← نسخ إلى الحافظة.",
  },
  emOutlookHow: {
    en: "Outlook.com / new Outlook: open the email → … More actions → View → View message source → copy all.",
    ar: "Outlook.com / Outlook الجديد: افتح الرسالة ← … المزيد من الإجراءات ← عرض ← عرض مصدر الرسالة ← انسخ الكل.",
  },
  emOutlookDesktopHow: {
    en: "Outlook desktop: drag the email to your desktop and upload the .msg file here.",
    ar: "Outlook على الكمبيوتر: اسحب الرسالة إلى سطح المكتب ثم ارفع ملف .msg هنا.",
  },
  emAppleHow: {
    en: "Apple Mail (Mac): open the email → View → Message → Raw Source → copy all.",
    ar: "Apple Mail (ماك): افتح الرسالة ← عرض ← الرسالة ← المصدر الخام ← انسخ الكل.",
  },
  emDrop: { en: "Drag an .eml or .msg email file here", ar: "اسحب ملف رسالة .eml أو .msg إلى هنا" },
  emPick: { en: "Choose a file", ar: "اختر ملفاً" },
  emFileHint: {
    en: "Gmail: ⋮ More → Download message (.eml). Outlook: drag the email to your desktop (.msg). Max 3 MB.",
    ar: "Gmail: ⋮ المزيد ← تنزيل الرسالة (.eml). Outlook: اسحب الرسالة إلى سطح المكتب (.msg). الحد الأقصى 3 ميغابايت.",
  },
  emFileTooBig: {
    en: "This file is too big to check (max 3 MB). Large emails are usually big because of their attachments: forward the email to yourself without them, download it again and upload that file.",
    ar: "هذا الملف كبير جداً للفحص (الحد الأقصى 3 ميغابايت). غالباً ما يكون حجم الرسالة كبيراً بسبب مرفقاتها: أعد توجيه الرسالة إلى نفسك بدون المرفقات، ثم نزّلها مرة أخرى وارفع ذلك الملف.",
  },
  emFileType: { en: "Only .eml or .msg email files can be checked here.", ar: "يمكن فحص ملفات البريد .eml أو .msg فقط." },
  emFileRead: {
    en: "Could not read this file. Try again or paste the email instead.",
    ar: "تعذّرت قراءة هذا الملف. حاول مرة أخرى أو الصق الرسالة بدلاً من ذلك.",
  },
  emFileRemove: { en: "Remove file", ar: "إزالة الملف" },
  emEmpty: { en: "Paste an email or choose a file first.", ar: "الصق رسالة أو اختر ملفاً أولاً." },
  emTooLong: { en: "That is too long to check (max 200,000 characters).", ar: "النص طويل جداً للفحص (الحد الأقصى 200,000 حرف)." },
  emScan: { en: "Scan Email", ar: "افحص الرسالة" },
  emTrySample: { en: "Try a sample scam email", ar: "جرّب رسالة احتيال تجريبية" },
  emPrivacy: {
    en: "SAQR keeps only a short excerpt of the email with the result: never the full message, the source or attachments.",
    ar: "يحتفظ صقر بمقتطف قصير فقط من الرسالة مع النتيجة، ولا يحتفظ أبداً بالرسالة كاملة أو مصدرها أو مرفقاتها.",
  },
  emDetectedRaw: {
    en: "Looks like a full source with headers: SAQR will check the sender's proof too.",
    ar: "يبدو أنه مصدر كامل مع الترويسات: سيتحقق صقر أيضاً من إثبات المرسل.",
  },
  llmTitle: { en: "Use my own AI (OpenAI-compatible)", ar: "استخدم ذكائي الاصطناعي الخاص (متوافق مع OpenAI)" },
  llmHint: {
    en: "Optional, for advanced users. SAQR already uses its own AI. You can use any AI service that works like OpenAI's instead (for example OpenRouter, Groq or your company's gateway).",
    ar: "اختياري للمستخدمين المتقدمين. يستخدم صقر ذكاءه الاصطناعي الخاص أصلاً. يمكنك بدلاً من ذلك استخدام أي خدمة ذكاء اصطناعي تعمل مثل OpenAI (مثل OpenRouter أو Groq أو بوابة شركتك).",
  },
  llmBaseUrl: { en: "Base URL", ar: "عنوان الخدمة (Base URL)" },
  llmApiKey: { en: "API key", ar: "مفتاح API" },
  llmModel: { en: "Model name", ar: "اسم النموذج" },
  llmPrivacy: {
    en: "Your key stays in this browser tab only and is erased when you close it. It is sent with each scan and SAQR never saves or logs it. The email is shared with that AI service, so only use one you trust.",
    ar: "يبقى مفتاحك في علامة التبويب هذه فقط ويُحذف عند إغلاقها. يُرسل مع كل فحص ولا يحفظه صقر أو يسجّله أبداً. تتم مشاركة الرسالة مع خدمة الذكاء الاصطناعي تلك، فاستخدم خدمة تثق بها فقط.",
  },
  llmClear: { en: "Clear my AI settings", ar: "مسح إعدادات الذكاء الاصطناعي" },
  llmActive: { en: "On", ar: "مفعّل" },
  llmIncomplete: {
    en: "Fill in the base URL and the model name, or clear all fields to use SAQR's AI.",
    ar: "أدخل عنوان الخدمة واسم النموذج، أو امسح كل الحقول لاستخدام ذكاء صقر الاصطناعي.",
  },
  llmBadUrl: { en: "The base URL must start with https://", ar: "يجب أن يبدأ عنوان الخدمة بـ https://" },
  llmUsed: { en: "Also checked with your own AI", ar: "تم الفحص أيضاً بذكائك الاصطناعي الخاص" },
  llmFailed: {
    en: "Your own AI could not be used, so SAQR's built-in checks were used instead.",
    ar: "تعذّر استخدام ذكائك الاصطناعي الخاص، فاستُخدمت فحوصات صقر المدمجة بدلاً منه.",
  },
  emScanningTitle: { en: "Checking this email in the cloud", ar: "جارٍ فحص هذه الرسالة سحابياً" },
  emStepParse: { en: "Reading the sender and the headers", ar: "قراءة بيانات المرسل والترويسات" },
  emStepAuth: { en: "Checking SPF, DKIM and DMARC proof", ar: "التحقق من إثبات SPF وDKIM وDMARC" },
  emStepUnicode: { en: "Looking for lookalike and hidden letters", ar: "البحث عن الأحرف المتشابهة والمخفية" },
  emStepLinks: { en: "Scanning every link in a secure sandbox", ar: "فحص كل رابط في بيئة معزولة آمنة" },
  emStepAi: { en: "AI inspector reading the message", ar: "المحلّل الذكي يقرأ الرسالة" },
  emBlockedTitle: { en: "Scam email: do not click, reply or pay", ar: "رسالة احتيالية: لا تضغط ولا ترد ولا تدفع" },
  emSuspiciousTitle: { en: "Warning: this email looks suspicious", ar: "تحذير: هذه الرسالة تبدو مشبوهة" },
  emSafeTitle: { en: "No signs of a scam found", ar: "لم يتم العثور على علامات احتيال" },
  emCheckedBy: {
    en: "Checked by SAQR-INTEL. Nothing in the email was opened on your device.",
    ar: "تم الفحص بواسطة صقر. لم يُفتح أي شيء من الرسالة على جهازك.",
  },
  emSafeNote: {
    en: "Still be careful: never share an OTP, PIN or password by email, even with senders you know.",
    ar: "ابقَ حذراً: لا تشارك أبداً رمز التحقق أو الرقم السري أو كلمة المرور عبر البريد، حتى مع مرسلين تعرفهم.",
  },
  emSender: { en: "Who sent this", ar: "من أرسل هذه الرسالة" },
  emShownName: { en: "Name shown", ar: "الاسم الظاهر" },
  emRealAddress: { en: "Real address", ar: "العنوان الحقيقي" },
  emRealLetters: { en: "In its real letters", ar: "بأحرفه الحقيقية" },
  emFreemail: { en: "Free email account", ar: "حساب بريد مجاني" },
  emOfficial: { en: "Official sender", ar: "مرسل رسمي" },
  emOfficialUnproven: { en: "Official address, not proven", ar: "عنوان رسمي غير مُثبت" },
  emReplyTo: { en: "Replies go to", ar: "الردود تذهب إلى" },
  emSubject: { en: "Subject", ar: "العنوان" },
  emNoSender: { en: "No sender found in what you pasted.", ar: "لم يتم العثور على مرسل في النص الملصق." },
  emAuthTitle: { en: "Proof of sender", ar: "إثبات هوية المرسل" },
  emSpfMeaning: {
    en: "Was it sent from a server the domain allows?",
    ar: "هل أُرسلت من خادم يسمح به النطاق؟",
  },
  emDkimMeaning: {
    en: "Does it carry the domain's valid digital signature?",
    ar: "هل تحمل توقيعاً رقمياً صالحاً للنطاق؟",
  },
  emDmarcMeaning: {
    en: "Does the domain owner confirm the From address?",
    ar: "هل يؤكد مالك النطاق عنوان المرسل الظاهر؟",
  },
  emAuthPass: { en: "Pass", ar: "ناجح" },
  emAuthFail: { en: "Fail", ar: "فاشل" },
  emAuthSoft: { en: "Weak fail", ar: "فشل جزئي" },
  emAuthNone: { en: "Not set up", ar: "غير مُعدّ" },
  emAuthNeutral: { en: "No answer", ar: "بلا نتيجة" },
  emAuthError: { en: "Error", ar: "خطأ" },
  emAuthNotChecked: { en: "Not checked", ar: "لم يُفحص" },
  emNoHeaders: {
    en: "These checks need the full source. Use “Paste full source” or upload the .eml file to see them.",
    ar: "تحتاج هذه الفحوصات إلى المصدر الكامل. استخدم «الصق المصدر الكامل» أو ارفع ملف .eml لرؤيتها.",
  },
  emPassFreemail: {
    en: "A pass only proves the email really came from this free account. Anyone can open one.",
    ar: "النجاح يثبت فقط أن الرسالة جاءت فعلاً من هذا الحساب المجاني، وأي شخص يستطيع إنشاء حساب كهذا.",
  },
  emUnicodeTitle: { en: "Lookalike characters found", ar: "تم العثور على أحرف متشابهة" },
  emUnicodeIntro: {
    en: "These letters look normal but come from another alphabet or are invisible. Scammers use them to fake a trusted name.",
    ar: "تبدو هذه الأحرف عادية لكنها من أبجدية أخرى أو غير مرئية. يستخدمها المحتالون لتزييف اسم موثوق.",
  },
  emImitates: { en: "Pretends to be", ar: "يتظاهر بأنه" },
  emWhereFromDomain: { en: "Sender domain", ar: "نطاق المرسل" },
  emWhereFromAddress: { en: "Sender address", ar: "عنوان المرسل" },
  emWhereReplyTo: { en: "Reply-to address", ar: "عنوان الرد" },
  emWhereReturnPath: { en: "Return address", ar: "عنوان الإرجاع" },
  emWhereSubject: { en: "Subject", ar: "العنوان" },
  emWhereDisplayName: { en: "Sender name", ar: "اسم المرسل" },
  emWhereBody: { en: "Message text", ar: "نص الرسالة" },
  emWhereLink: { en: "A link", ar: "رابط" },
  emWhereAttachment: { en: "An attachment", ar: "مرفق" },
  emKindPunycode: { en: "Foreign-letter web address", ar: "عنوان بأحرف أجنبية" },
  emKindMixed: { en: "Mixed alphabets", ar: "أبجديات مختلطة" },
  emKindWhole: { en: "Fake lookalike word", ar: "كلمة مزيفة متشابهة" },
  emKindInvisible: { en: "Invisible characters", ar: "أحرف غير مرئية" },
  emKindBidi: { en: "Text-direction trick", ar: "خدعة اتجاه النص" },
  emKindFancy: { en: "Styled letters", ar: "أحرف مزخرفة" },
  emLinksTitle: { en: "Links in this email", ar: "الروابط في هذه الرسالة" },
  emLinksDisabled: { en: "Links are disabled here for your safety.", ar: "الروابط معطّلة هنا حفاظاً على سلامتك." },
  emLinkShows: { en: "Shows", ar: "يظهر" },
  emLinkOpens: { en: "Really opens", ar: "يفتح فعلياً" },
  emLinkMismatch: { en: "The text and the real address do not match", ar: "النص الظاهر لا يطابق العنوان الحقيقي" },
  emLinkUnwrapped: { en: "Hidden behind a redirect link", ar: "مخفي خلف رابط إعادة توجيه" },
  emLinkNotScanned: { en: "Not scanned", ar: "لم يُفحص" },
  emLinksMore: { en: "more links not shown", ar: "روابط أخرى غير معروضة" },
  emAttachTitle: { en: "Attachments", ar: "المرفقات" },
  emAttachRisky: { en: "Dangerous file: do not open", ar: "ملف خطير: لا تفتحه" },
  emCampaignTitle: { en: "Matches a scam wave spreading now", ar: "تطابق موجة احتيال منتشرة الآن" },
  emCampaignIoc: { en: "Uses a known scam website or sender", ar: "يستخدم موقعاً أو مرسلاً احتيالياً معروفاً" },
  emCampaignLure: { en: "Uses the same wording as the scam wave", ar: "يستخدم نفس صياغة موجة الاحتيال" },
  emCampaignSources: { en: "Sources", ar: "المصادر" },
  emModelTitle: { en: "Your personal filter", ar: "مرشّحك الشخصي" },
  emModelLearning: {
    en: "Still learning from your answers ({n} so far). It starts helping after 10 scam and 10 fine emails.",
    ar: "ما زال يتعلم من إجاباتك ({n} حتى الآن). يبدأ بالمساعدة بعد 10 رسائل احتيال و10 رسائل سليمة.",
  },
  emModelScore: {
    en: "Your personal filter says {p}% likely a scam (from {n} answers).",
    ar: "يقول مرشّحك الشخصي إن احتمال الاحتيال {p}٪ (من {n} إجابة).",
  },
  emModelAsk: {
    en: "Was this a scam? Your answer trains your own filter. Only anonymous number codes are kept, never the email.",
    ar: "هل كانت هذه رسالة احتيال؟ إجابتك تدرّب مرشّحك الخاص. تُحفظ رموز رقمية مجهولة فقط، وليس الرسالة أبداً.",
  },
  emLabelScam: { en: "This was a scam", ar: "كانت احتيالاً" },
  emLabelHam: { en: "This was fine", ar: "كانت سليمة" },
  emLabelSaved: { en: "Thanks! Saved to your personal filter.", ar: "شكراً! تم الحفظ في مرشّحك الشخصي." },
  emLabelFailed: { en: "Could not save your answer right now. Try again later.", ar: "تعذّر حفظ إجابتك الآن. حاول لاحقاً." },
  emModelDownload: { en: "Download my model", ar: "تنزيل نموذجي" },
  emAiNotes: { en: "The AI also noticed", ar: "لاحظ الذكاء الاصطناعي أيضاً" },
  emLiveScamEmail: { en: "Scam email", ar: "بريد احتيالي" },
  emLiveSuspiciousEmail: { en: "Suspicious email", ar: "بريد مشبوه" },
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
