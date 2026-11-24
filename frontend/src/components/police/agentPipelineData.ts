/**
 * Data for <AgentPipeline />: a SIMULATED replay of one sample case through Saqr's pipeline stages.
 * Diagram coordinates are in a 1200 x 520 viewBox (left-to-right in both languages).
 * Bands match the real scorer: < 30 SAFE, 30-64 SUSPICIOUS, 65+ HIGH-RISK SCAM. Domains are defanged.
 */

export type Bi = { en: string; ar: string };
export type BiLines = { en: string[]; ar: string[] };

export type NodeId =
  | "citizen"
  | "officer"
  | "ops"
  | "orch"
  | "scout"
  | "cloak"
  | "judge"
  | "enforce"
  | "maps"
  | "redirect"
  | "urlml"
  | "whois"
  | "dnsbl";

export type NodeShape = "person" | "orchestrator" | "agent" | "tool";

export interface PipelineNode {
  id: NodeId;
  shape: NodeShape;
  x: number; // centre
  y: number; // centre
  w: number;
  h: number;
  lines: BiLines;
  sub?: Bi;
  /** Tool boxes: dashed = read-only, solid = writes (staged until an officer approves). */
  dashed?: boolean;
}

export type StepKind = "goal" | "coordination" | "tool_read" | "approval" | "command" | "guardrail" | "notification";

export interface TraceStep {
  id: number;
  t: string; // mm:ss offset from the citizen's paste
  kind: StepKind;
  from: NodeId;
  to: NodeId;
  title: Bi;
  summary: Bi;
  payload: Record<string, unknown>;
  visual?: "cloaking" | "verdict" | "outcome";
}

export const VIEW_W = 1200;
export const VIEW_H = 520;
export const LABEL_X = 16;

export const ROWS: { y: number; label: Bi }[] = [
  { y: 62, label: { en: "People & endpoints", ar: "الأشخاص والجهات" } },
  { y: 172, label: { en: "Orchestrator", ar: "المنسّق" } },
  { y: 292, label: { en: "Agents", ar: "الوكلاء" } },
  { y: 440, label: { en: "Tools & systems", ar: "الأدوات والأنظمة" } },
];

const person = (id: NodeId, x: number, en: string, ar: string): PipelineNode => ({
  id,
  shape: "person",
  x,
  y: ROWS[0].y,
  w: 214,
  h: 50,
  lines: { en: [en], ar: [ar] },
});

const agent = (id: NodeId, x: number, en: string, ar: string, sub: Bi): PipelineNode => ({
  id,
  shape: "agent",
  x,
  y: ROWS[2].y,
  w: 234,
  h: 60,
  lines: { en: [en], ar: [ar] },
  sub,
});

const tool = (id: NodeId, x: number, en: string[], ar: string[], dashed: boolean): PipelineNode => ({
  id,
  shape: "tool",
  x,
  y: ROWS[3].y,
  w: 184,
  h: 74,
  lines: { en, ar },
  sub: dashed ? { en: "Read-only", ar: "قراءة فقط" } : { en: "Write · staged", ar: "كتابة · مُعلّقة" },
  dashed,
});

export const NODES: PipelineNode[] = [
  person("citizen", 340, "Abu Dhabi Citizen", "مواطن في أبوظبي"),
  person("officer", 665, "AD Police Duty Officer", "ضابط مناوب - شرطة أبوظبي"),
  person("ops", 990, "Telecom / Registrar Ops", "عمليات الاتصالات / المسجّل"),
  {
    id: "orch",
    shape: "orchestrator",
    x: 665,
    y: ROWS[1].y,
    w: 300,
    h: 62,
    lines: { en: ["SAQR Command Orchestrator"], ar: ["منسّق القيادة صقر"] },
    sub: { en: "Orchestrator", ar: "المنسّق" },
  },
  agent("scout", 275, "Scout & Hunt Agent", "وكيل الاستطلاع والتعقّب", { en: "Proactive", ar: "استباقي" }),
  agent("cloak", 535, "Cloaking & Forensics Agent", "وكيل التمويه والأدلة", { en: "Sandbox", ar: "بيئة معزولة" }),
  agent("judge", 795, "Risk & Bilingual Judge", "وكيل المخاطر والحكم", { en: "Scoring", ar: "التقييم" }),
  agent("enforce", 1055, "Enforcement & Alert Agent", "وكيل الإنفاذ والتنبيه", { en: "Action", ar: "إجراء" }),
  tool("maps", 255, ["Maps & Search", "Spoof Check"], ["فحص انتحال", "الخرائط والبحث"], true),
  tool("redirect", 460, ["Redirect &", "Cloaking Diff"], ["مقارنة التحويل", "والتمويه"], true),
  tool("urlml", 665, ["URL ML &", "Threat Feeds"], ["نموذج الروابط", "وقوائم التهديد"], true),
  tool("whois", 870, ["WHOIS / DNS /", "TLS Age"], ["عمر النطاق", "والشهادة"], true),
  tool("dnsbl", 1075, ["DNS Blocklist", "& Dossier"], ["قائمة الحجب", "وملف الأدلة"], false),
];

export const EDGES: [NodeId, NodeId][] = [
  ["citizen", "orch"],
  ["officer", "orch"],
  ["ops", "orch"],
  ["orch", "scout"],
  ["orch", "cloak"],
  ["orch", "judge"],
  ["orch", "enforce"],
  ["scout", "maps"],
  ["scout", "urlml"],
  ["cloak", "redirect"],
  ["judge", "whois"],
  ["judge", "urlml"],
  ["enforce", "dnsbl"],
];

export const KIND_LABEL: Record<StepKind, Bi> = {
  goal: { en: "Goal or event", ar: "هدف أو حدث" },
  coordination: { en: "Agent coordination", ar: "تنسيق الوكلاء" },
  tool_read: { en: "Tool call (read)", ar: "استدعاء أداة (قراءة)" },
  approval: { en: "Human approval", ar: "موافقة بشرية" },
  command: { en: "Command (write)", ar: "أمر (كتابة)" },
  guardrail: { en: "Guardrail", ar: "ضابط أمان" },
  notification: { en: "Notification", ar: "إشعار" },
};

export const KINDS = Object.keys(KIND_LABEL) as StepKind[];

const DOMAIN = "tamm-smart-pay[.]net";
const PIN = "Emirates Post Customer Center - Mussafah M-37";

export const STEPS: TraceStep[] = [
  {
    id: 1, t: "00:00", kind: "goal", from: "citizen", to: "orch",
    title: { en: "Citizen asks: is this link safe?", ar: "المواطن يسأل: هل الرابط آمن؟" },
    summary: { en: `"TAMM fine" link ${DOMAIN} pasted`, ar: `رابط "مخالفة تم" ${DOMAIN}` },
    payload: { channel: "CITIZEN_MANUAL_CHECK", url: `https://${DOMAIN}/fine/pay`, lang: "en" },
  },
  {
    id: 2, t: "00:01", kind: "coordination", from: "orch", to: "cloak",
    title: { en: "Open the link in the sandbox", ar: "فتح الرابط في بيئة معزولة" },
    summary: { en: "Follow redirects, compare bot vs phone view", ar: "تتبّع التحويلات ومقارنة العرضين" },
    payload: { task: "follow_redirects + cloak_diff", profiles: ["crawler", "uae_mobile"] },
  },
  {
    id: 3, t: "00:02", kind: "tool_read", from: "cloak", to: "redirect",
    title: { en: "Fetch as crawler and as UAE phone", ar: "جلب الصفحة كزاحف وكهاتف إماراتي" },
    summary: { en: "Two fetches, hop by hop", ar: "جلبان، خطوة بخطوة" },
    payload: { tool: "redirect_cloak_diff", max_hops: 10, timeout_s: 15 },
  },
  {
    id: 4, t: "00:09", kind: "tool_read", from: "redirect", to: "cloak", visual: "cloaking",
    title: { en: "Cloaking found", ar: "تم رصد تمويه" },
    summary: { en: "2 redirects; bot sees parked page, phone sees card form", ar: "تحويلان؛ الزاحف يرى صفحة مركونة والهاتف يرى نموذج بطاقة" },
    payload: { hops: 2, bot_view: "parked page", phone_view: "card + OTP form", flag: "MOBILE_CLOAKING_DETECTED" },
  },
  {
    id: 5, t: "00:10", kind: "coordination", from: "orch", to: "judge",
    title: { en: "Score the evidence", ar: "تقييم الأدلة" },
    summary: { en: "Cloaking evidence handed to the judge", ar: "تسليم أدلة التمويه للحَكَم" },
    payload: { task: "score", evidence: ["MOBILE_CLOAKING_DETECTED", "EXFIL_FORM"] },
  },
  {
    id: 6, t: "00:12", kind: "tool_read", from: "whois", to: "judge",
    title: { en: "Domain and certificate age", ar: "عمر النطاق والشهادة" },
    summary: { en: "Registered 5 h ago; TLS certificate 3 h old", ar: "سُجّل قبل 5 ساعات؛ الشهادة عمرها 3 ساعات" },
    payload: { domain: DOMAIN, registered_hours_ago: 5, cert_hours_old: 3, flags: ["NEW_DOMAIN", "NEW_CERT"] },
  },
  {
    id: 7, t: "00:13", kind: "tool_read", from: "urlml", to: "judge",
    title: { en: "URL model and threat feeds", ar: "نموذج الروابط وقوائم التهديد" },
    summary: { en: "Model 0.99; look-alike of tamm.abudhabi; on no feed yet", ar: "النموذج 0.99؛ يشبه tamm.abudhabi؛ غير مدرج بعد" },
    payload: { model_probability: 0.99, lookalike_of: "tamm.abudhabi", feeds_hit: 0 },
  },
  {
    id: 8, t: "00:15", kind: "goal", from: "judge", to: "orch", visual: "verdict",
    title: { en: "Verdict: 96 / 100, HIGH-RISK SCAM", ar: "الحكم: 96 / 100، احتيال عالي الخطورة" },
    summary: { en: "Fake TAMM fine page; do not pay", ar: "صفحة مخالفة تم مزيفة؛ لا تدفع" },
    payload: { score: 96, verdict: "HIGH-RISK SCAM", top_flags: ["LOOKALIKE", "NEW_DOMAIN", "MOBILE_CLOAKING_DETECTED"] },
  },
  {
    id: 9, t: "00:16", kind: "notification", from: "orch", to: "citizen",
    title: { en: "Citizen warned", ar: "تحذير المواطن" },
    summary: { en: "Blocked: new copy of TAMM, asks for card + OTP", ar: "محجوب: نسخة جديدة من تم تطلب البطاقة والرمز" },
    payload: { shown: "block page", reasons: 3, languages: ["en", "ar"] },
  },
  {
    id: 10, t: "00:18", kind: "coordination", from: "orch", to: "scout",
    title: { en: "Hunt for sibling scams", ar: "البحث عن عمليات مرتبطة" },
    summary: { en: "Same network: hosts, phones, Maps pins", ar: "نفس الشبكة: خوادم وأرقام ودبابيس خرائط" },
    payload: { seed: DOMAIN, pivot_on: ["ip", "phone", "registrar"] },
  },
  {
    id: 11, t: "00:31", kind: "tool_read", from: "maps", to: "scout",
    title: { en: "Hijacked Maps pin found", ar: "رصد دبوس خرائط مخترق" },
    summary: { en: `"${PIN}" lists a personal mobile`, ar: `"${PIN}" يعرض رقماً شخصياً` },
    payload: { listing: PIN, phone: "+971 5x xxx 0137", flag: "PERSONAL_MOBILE_FOR_INSTITUTION", same_network: true },
  },
  {
    id: 12, t: "00:32", kind: "guardrail", from: "scout", to: "orch",
    title: { en: "Guardrails checked", ar: "التحقق من ضوابط الأمان" },
    summary: { en: "Official and trusted sites never queued; nothing sent without an officer", ar: "لا تُدرج المواقع الرسمية؛ لا إرسال دون ضابط" },
    payload: { official_excluded: ["tamm.abudhabi", "epg.gov.ae"], requires_officer: true },
  },
  {
    id: 13, t: "00:33", kind: "coordination", from: "orch", to: "enforce",
    title: { en: "Prepare enforcement", ar: "تجهيز الإنفاذ" },
    summary: { en: "Domain + Maps pin handed to enforcement", ar: "تسليم النطاق والدبوس للإنفاذ" },
    payload: { targets: [DOMAIN, PIN] },
  },
  {
    id: 14, t: "00:36", kind: "tool_read", from: "enforce", to: "dnsbl",
    title: { en: "Dossier built, actions staged", ar: "إعداد الملف وتجهيز الإجراءات" },
    summary: { en: "Evidence dossier, registrar notice draft, blocklist entry queued", ar: "ملف أدلة، مسودة بلاغ للمسجّل، إدخال حجب معلّق" },
    payload: { dossier: "SQ-0418 (sample)", sha256: "9f2c…e71a", notice: "draft", blocklist: "queued", published: false },
  },
  {
    id: 15, t: "00:37", kind: "approval", from: "orch", to: "officer",
    title: { en: "Officer approval requested", ar: "طلب موافقة الضابط" },
    summary: { en: "Publish blocklist entry and send notice?", ar: "نشر إدخال الحجب وإرسال البلاغ؟" },
    payload: { request: "approve_enforcement", score: 96, dossier: "SQ-0418 (sample)" },
  },
  {
    id: 16, t: "01:52", kind: "approval", from: "officer", to: "orch",
    title: { en: "Officer approves", ar: "الضابط يوافق" },
    summary: { en: "Approved by the duty officer", ar: "وافق الضابط المناوب" },
    payload: { decision: "approved", officer: "Duty officer (sample)" },
  },
  {
    id: 17, t: "01:53", kind: "command", from: "enforce", to: "ops",
    title: { en: "Blocklist published (simulated)", ar: "نشر قائمة الحجب (محاكاة)" },
    summary: { en: "DNS blocklist entry published; registrar notice drafted", ar: "نُشر إدخال الحجب؛ صيغت مسودة البلاغ" },
    payload: { rpz: `${DOMAIN} CNAME .`, registrar_notice: "drafted", simulated: true },
  },
  {
    id: 18, t: "01:55", kind: "notification", from: "orch", to: "citizen", visual: "outcome",
    title: { en: "Public alert issued", ar: "إصدار تنبيه عام" },
    summary: { en: "Citizen and public warned about the fake TAMM fine", ar: "تحذير المواطن والجمهور من مخالفة تم المزيفة" },
    payload: { alert: "fake TAMM fine", languages: ["en", "ar"], simulated: true },
  },
];

export const TEXT = {
  title: { en: "Live Autonomous Agents Pipeline", ar: "مسار الوكلاء الذاتيين" },
  subtitle: { en: "pipeline stages, replayed on a sample case", ar: "مراحل المسار، معادة على حالة نموذجية" },
  badge: { en: "Simulated trace · Demo data", ar: "تتبّع محاكى · بيانات تجريبية" },
  caption: {
    en: "A replay of how Saqr's pipeline stages handle one sample case. Not a live feed; telecom, registrar and police endpoints are simulated.",
    ar: "إعادة عرض لكيفية تعامل مراحل صقر مع حالة نموذجية واحدة. ليست بثاً مباشراً؛ جهات الاتصالات والمسجّل والشرطة محاكاة.",
  },
  restart: { en: "Restart", ar: "إعادة" },
  back: { en: "Back", ar: "رجوع" },
  play: { en: "Play", ar: "تشغيل" },
  pause: { en: "Pause", ar: "إيقاف" },
  next: { en: "Next", ar: "التالي" },
  of: { en: "of", ar: "من" },
  speed: { en: "Playback speed", ar: "سرعة التشغيل" },
  seek: { en: "Step", ar: "الخطوة" },
  payload: { en: "Payload", ar: "البيانات" },
  log: { en: "Message log", ar: "سجل الرسائل" },
  botView: { en: "Bot view", ar: "عرض الزاحف" },
  phoneView: { en: "UAE phone view", ar: "عرض هاتف إماراتي" },
  parked: { en: "This domain is parked", ar: "هذا النطاق مركون" },
  fineTitle: { en: "Traffic fine: AED 400", ar: "مخالفة مرورية: 400 درهم" },
  card: { en: "Card number", ar: "رقم البطاقة" },
  otp: { en: "OTP code", ar: "رمز التحقق" },
  verdictChip: { en: "HIGH-RISK SCAM / احتيال عالي الخطورة", ar: "HIGH-RISK SCAM / احتيال عالي الخطورة" },
  verdictEn: "Fake TAMM fine page on a 5-hour-old look-alike domain that shows a card and OTP form only to UAE phones. Do not pay.",
  verdictAr: "صفحة مخالفة تم مزيفة على نطاق مشابه عمره 5 ساعات تعرض نموذج البطاقة ورمز التحقق لهواتف الإمارات فقط. لا تدفع.",
  outcome: { en: "Outcome", ar: "النتيجة" },
  simulated: { en: "Simulated", ar: "محاكاة" },
  outcomeRows: [
    { k: { en: "Blocked", ar: "محجوب" }, v: { en: `${DOMAIN} on the DNS blocklist`, ar: `${DOMAIN} في قائمة حجب DNS` } },
    { k: { en: "Drafted", ar: "مسودة" }, v: { en: "Registrar abuse notice + evidence dossier", ar: "بلاغ إساءة للمسجّل + ملف أدلة" } },
    { k: { en: "Awaits", ar: "بانتظار" }, v: { en: `Maps pin "${PIN}" report to Google`, ar: `بلاغ دبوس "${PIN}" إلى Google` } },
  ],
  diagramAlt: {
    en: "Pipeline diagram: three people and endpoints connect to the SAQR Command Orchestrator, which coordinates four agents, each using its tools.",
    ar: "مخطط المسار: ثلاثة أشخاص وجهات يتصلون بمنسّق صقر الذي ينسّق أربعة وكلاء يستخدم كل منهم أدواته.",
  },
} as const;
