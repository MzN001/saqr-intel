"use client";

import { useCallback, useEffect, useState } from "react";
import { apiUrl } from "./api";

/* ---------- types (mirror saqr/police_state.py) ---------- */
export type PoliceChannel =
  | "AUTO_TELECOM_DNS"
  | "AUTO_SMS_GUARD"
  | "CITIZEN_MANUAL_CHECK"
  | "MOBILE_OS_SHARE_SHEET"
  | "PC_BROWSER_EXTENSION"
  | "ANDROID_APP_GUARD"
  | "X_COMMUNITY_ALERT";

export type CampaignStatus = "ACTIVE" | "SYNCED_TO_TELECOM_DNS" | "COMMUNITY_FLAGGED_X";

export interface PoliceEvent {
  id: string;
  ts: string;
  channel: PoliceChannel;
  kind: "url" | "maps" | "email" | "message";
  domain: string | null;
  defanged_domain: string;
  risk_score: number;
  verdict: string;
  impersonated_entity: string | null;
  campaign_id: string | null;
  title: string | null;
  /** true = pre-loaded demo event (saqr/police_state.seed), not a real interception. */
  seeded?: boolean;
}

export interface Campaign {
  campaign_id: string;
  domain: string;
  defanged_domain: string;
  impersonated_entity: string | null;
  risk_score: number;
  hit_count: number;
  channels: string[];
  ip_asn: string;
  ssl_age: string;
  status: CampaignStatus;
  last_seen: string;
  syndicate?: string | null;
}

export interface MapPin {
  id: string;
  lat: number;
  lng: number;
  title: string;
  type: "SPOOFED" | "VERIFIED";
  domain: string | null;
  registry_note: string;
}

export interface OfficialWarning {
  id: string;
  issued_at: string;
  title_en: string;
  title_ar: string;
  message_en: string;
  message_ar: string;
  domain: string | null;
  defanged_domain: string;
  issuer_en: string;
  issuer_ar: string;
  verified: boolean;
}

export type HunterSource = "lookalike_sweep" | "nrd" | "ct" | "crtsh";
export type HunterMode = "live" | "simulated" | "off";

/** A Proactive Hunter detection (saqr/intel/hunter.latest_detections + citizen_visits_blocked). */
export interface ProactiveDetection {
  id: number;
  domain: string;
  defanged_domain: string;
  source: HunterSource | string;
  first_seen: string;
  scanned_at: string | null;
  score: number;
  triage_score: number;
  verdict: string;
  status: "confirmed" | "suspicious" | "cleared";
  entity: string | null;
  flags: string[];
  domain_age_hours: number | null;
  registrar: string | null;
  scan_id: string | null;
  simulated: boolean;
  citizen_visits: number;
  citizen_visits_blocked?: number;
  lead_time_hours: number | null;
  hours_since_detection: number | null;
  published_to_blocklist?: boolean;
}

export interface PoliceState {
  kpis: {
    citizens_protected: number;
    active_entities: number;
    hijacked_pins: number;
    x_alerts_dispatched: number;
    pre_victim_detections?: number;
  };
  /** The fixed demo numbers inside kpis.citizens_protected / x_alerts_dispatched (kpi = demo_baseline + live_counts). */
  demo_baseline?: { citizens_protected: number; x_alerts_dispatched: number };
  /** What really happened since the backend started. */
  live_counts?: { citizens_protected: number; x_alerts_dispatched: number };
  proactive_detections?: ProactiveDetection[];
  hunter_mode?: HunterMode;
  campaigns: Campaign[];
  recent_events: PoliceEvent[];
  map_pins: MapPin[];
  telecom_synced: string[];
  latest_warning: OfficialWarning | null;
  generated_at: string;
}

export interface TakedownDossier {
  aman_ref_id: string;
  campaign_id: string;
  issuing_unit: string;
  issuing_unit_ar: string;
  target_domain: string;
  defanged_domain: string;
  impersonated_entity: string | null;
  risk_score: number;
  ip_address: string | null;
  all_ip_addresses: string[];
  asn: string | null;
  registrar: string | null;
  registrar_abuse_email: string | null;
  all_abuse_contacts: string[];
  ssl_age: string;
  channels: string[];
  status: CampaignStatus;
  red_flags: { code: string; severity: string; en: string; ar: string }[];
  citizen_reports_count: number;
  last_seen: string;
  requested_actions: string[];
  generated_at: string;
  scan_id?: string | null;
  evidence?: EvidenceDossier | null;
}

export interface DossierFlag {
  code: string;
  severity: string;
  points?: number;
  en: string;
  ar: string;
}

export interface RedirectHop {
  url: string;
  host: string | null;
  status: number | null;
  via: string | null;
  risk: string | null;
  note: string | null;
}

export interface DetectionContext {
  detection_id: number;
  domain: string;
  defanged_domain: string;
  source: string;
  source_label: string;
  first_seen: string;
  scanned_at: string | null;
  status: string;
  triage_score: number;
  score: number;
  verdict: string | null;
  entity: string | null;
  domain_age_hours: number | null;
  registrar: string | null;
  ip: string | null;
  asn: string | null;
  scan_id: string | null;
  simulated: boolean;
  citizen_visits: number;
  citizen_visits_blocked: number;
  first_citizen_at: string | null;
  lead_time_hours: number | null;
  hours_since_detection: number | null;
}

/** saqr/intel/takedown.build_dossier: the full evidence record of one flagged scan. */
export interface EvidenceDossier {
  dossier_id: string;
  case_reference: string;
  classification: string;
  generated_at: string;
  generated_by: string;
  scan_id: string;
  summary: {
    target: string | null;
    target_defanged: string;
    verdict: string;
    risk_score: number;
    impersonated_entity: string | null;
    official_domains: string[];
    harvested_data_types: string[];
    citizen_reports: number;
    narrative_en?: string | null;
  };
  whois: {
    registrar: string | null;
    creation_date: string | null;
    domain_age_hours: number | null;
    registrant_country: string | null;
    abuse_contacts: string[];
    name_servers: string[];
  };
  dns: { a: string[]; aaaa: string[]; mx: string[]; ns: string[]; status: string | null };
  network: { ip_addresses: string[]; asn: string | null; asn_org: string | null; country: string | null; prefix: string | null };
  tls: { issuer: string | null; not_before: string | null; cert_age_hours: number | null; sha256: string | null; valid: boolean | null };
  sandbox_evidence: {
    input_domain?: string | null;
    final_url: string | null;
    redirect_chain: RedirectHop[];
    http_status?: number | null;
    page_title: string | null;
    screenshot_available?: boolean;
    screenshot_note?: string | null;
  };
  detection?: DetectionContext | null;
  timestamps?: { first_seen: string; scanned_at: string; generated_at: string; timezone: string };
  red_flags: DossierFlag[];
  evidence_integrity: Record<string, string | null>;
  timeline: { ts: string; event: string; source: string }[];
  recommended_actions: { priority: number; action: string; addressee: string }[];
  notices: { registrar_abuse: string; hosting_abuse: string };
  syndicate?: { id: string; name: string; name_ar?: string } | null;
}

export interface DetectionDossier {
  detection: DetectionContext;
  triage_reasons: DossierFlag[];
  evidence: EvidenceDossier | null;
  note: string | null;
  generated_at: string;
}

/** GET /api/model/metrics: every field optional (the endpoint may be missing: card hidden). */
export interface ModelMetrics {
  model?: { name?: string; version?: string; trained_at?: string; training_rows?: number };
  datasets?: { name?: string; rows?: number }[];
  holdout?: { name?: string; rows?: number; precision?: number; recall?: number; f1?: number; fpr?: number; threshold?: number };
  fp_suite?: {
    rows?: number;
    false_positives?: number;
    by_source?: Record<string, { rows?: number; warn_30?: number; block_65?: number }>;
  };
  live?: { rows?: number; date?: string; no_feeds?: { warn_30?: CutMetrics; block_65?: CutMetrics } };
}

export interface CutMetrics {
  precision?: number;
  recall?: number;
  f1?: number;
  fpr?: number;
}

export interface SweepCycle {
  leads?: number;
  scanned?: number;
  confirmed?: number;
  suspicious?: number;
  cleared?: number;
  finished_at?: string;
  skipped?: string;
}

/* ---------- API ---------- */
/** Officer-only calls go through the same-origin proxy (/api/officer/*), which adds the police key on the server. */
export function officerUrl(p: string): string {
  return p.startsWith("/api/") ? `/api/officer/${p.slice("/api/".length)}` : p;
}

function toLogin(): void {
  if (typeof window === "undefined" || window.location.pathname.startsWith("/police/login")) return;
  const next = window.location.pathname + window.location.search;
  window.location.replace(`/police/login?next=${encodeURIComponent(next)}`);
}

/** Officer call (cookie session). A 401 means the session expired: back to the sign-in page. */
async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(officerUrl(path), {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    credentials: "same-origin",
    cache: "no-store",
  });
  const body = await res.json().catch(() => ({}));
  if (res.status === 401) toLogin();
  if (!res.ok) throw new Error(typeof body?.detail === "string" ? body.detail : `Request failed (${res.status})`);
  return body as T;
}

/** Public backend call (citizen pages import these too). */
async function publicCall<T>(path: string): Promise<T> {
  const res = await fetch(apiUrl(path), { cache: "no-store" });
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof body?.detail === "string" ? body.detail : `Request failed (${res.status})`);
  return body as T;
}

export const getPoliceState = () => call<PoliceState>("/api/police/state");
export const syncTelecom = (campaign_id: string, domain: string) =>
  call<{ ok: boolean; rpz_record: string; synced_at: string }>("/api/police/sync-telecom", {
    method: "POST",
    body: JSON.stringify({ campaign_id, domain }),
  });
export const broadcastWarning = (w: { title_en: string; title_ar: string; message_en: string; message_ar: string; domain: string | null }) =>
  call<{ ok: boolean; warning: OfficialWarning }>("/api/police/broadcast-warning", { method: "POST", body: JSON.stringify(w) });
export const getTakedown = (campaignId: string) => call<TakedownDossier>(`/api/police/takedown/${encodeURIComponent(campaignId)}`);
export const getDetectionDossier = (id: number) => call<DetectionDossier>(`/api/police/detections/${id}/dossier`);
export const evidencePackUrl = (dossierId: string) => officerUrl(`/api/dossiers/${encodeURIComponent(dossierId)}/evidence-pack`);
export const screenshotUrl = (scanId: string) => officerUrl(`/api/scans/${encodeURIComponent(scanId)}/screenshot`);
export const startHunterSweep = () =>
  call<{ started: boolean; reason?: string; mode: HunterMode; cycle: SweepCycle | null }>("/api/hunter/sweep", { method: "POST" });
/** Citizen "false alarm" reports. Stores only the domain (or "email message"), never the full URL. */
export type FalseAlarmStatus = "open" | "confirmed" | "dismissed";
export interface FalseAlarm {
  id: string;
  scan_id: string;
  kind: "url" | "maps" | "email" | string;
  label: string;
  verdict: string;
  score: number;
  note: string;
  reports: number;
  status: FalseAlarmStatus;
  created_at: string;
  last_reported_at: string;
  resolved_at: string | null;
}
export interface FalseAlarmList {
  items: FalseAlarm[];
  counts: Record<FalseAlarmStatus, number> & { total: number };
}
export const getFalseAlarms = () => call<FalseAlarmList>("/api/feedback/false-alarms");
/** Records the officer's decision only: nothing is whitelisted or unblocked automatically. */
export const resolveFalseAlarm = (id: string, status: Exclude<FalseAlarmStatus, "open">) =>
  call<FalseAlarm>(`/api/feedback/false-alarms/${encodeURIComponent(id)}`, { method: "POST", body: JSON.stringify({ status }) });
export const getHunterStatus = () => call<{ mode: HunterMode; cycle_running: boolean; last_cycle: SweepCycle | null }>("/api/hunter/status");

/** null when the backend has no metrics endpoint (404) or is unreachable: the card is then hidden. */
export async function getModelMetrics(): Promise<ModelMetrics | null> {
  try {
    const res = await fetch(apiUrl("/api/model/metrics"), { cache: "no-store" });
    if (!res.ok) return null;
    const body = (await res.json()) as unknown;
    return body && typeof body === "object" ? (body as ModelMetrics) : null;
  } catch {
    return null;
  }
}
export const getLatestWarning = () => publicCall<{ warning: OfficialWarning | null }>("/api/police/warning/latest");

/** Citizen side: count an X warning on /police. Fire-and-forget; never blocks or throws. */
export function logXAlert(domain: string | null, impersonatedEntity: string | null): void {
  if (!domain) return;
  try {
    void fetch(apiUrl("/api/police/log-x-alert"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ domain, impersonated_entity: impersonatedEntity }),
      keepalive: true, // survives the tab switching to X
    }).catch(() => undefined);
  } catch {
    /* ignore */
  }
}

/* ---------- live subscription ---------- */
export type LinkState = "live" | "polling" | "offline";

/**
 * Live /police state: a 4-second GET /api/officer/police/state poll (cookie session, no WebSocket:
 * the socket could not carry the officer key). "live" = the last poll succeeded.
 */
export function usePoliceLive() {
  const [state, setState] = useState<PoliceState | null>(null);
  const [link, setLink] = useState<LinkState>("polling");
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await getPoliceState();
      setState(s);
      setError(null);
      setLink("live");
    } catch (e) {
      setError(e instanceof Error ? e.message : "offline");
      setLink("offline");
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void refresh(), 0);
    const poll = window.setInterval(() => void refresh(), 4000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(poll);
    };
  }, [refresh]);

  return { state, link, error, refresh };
}

/* ---------- labels ---------- */
export const CHANNEL_LABEL: Record<string, { en: string; ar: string; tone: string; short: { en: string; ar: string } }> = {
  AUTO_TELECOM_DNS: { en: "Telecom DNS", ar: "حظر شبكة الاتصالات", tone: "bg-sky-500/15 text-sky-300 ring-sky-400/30", short: { en: "DNS", ar: "DNS" } },
  AUTO_SMS_GUARD: { en: "SMS Guard", ar: "حارس الرسائل", tone: "bg-violet-500/15 text-violet-300 ring-violet-400/30", short: { en: "SMS", ar: "رسائل" } },
  CITIZEN_MANUAL_CHECK: { en: "Citizen Check", ar: "فحص المواطن", tone: "bg-emerald-500/15 text-emerald-300 ring-emerald-400/30", short: { en: "Check", ar: "فحص" } },
  MOBILE_OS_SHARE_SHEET: { en: "Share Sheet", ar: "قائمة المشاركة", tone: "bg-teal-500/15 text-teal-300 ring-teal-400/30", short: { en: "Share", ar: "مشاركة" } },
  PC_BROWSER_EXTENSION: { en: "PC Extension", ar: "إضافة المتصفح", tone: "bg-amber-500/15 text-amber-300 ring-amber-400/30", short: { en: "Browser", ar: "متصفح" } },
  ANDROID_APP_GUARD: { en: "Android Shield", ar: "درع أندرويد", tone: "bg-lime-500/15 text-lime-300 ring-lime-400/30", short: { en: "Android", ar: "أندرويد" } },
  X_COMMUNITY_ALERT: { en: "X Community Alert", ar: "تنبيه مجتمعي على X", tone: "bg-white/10 text-white ring-white/25", short: { en: "X alert", ar: "تنبيه X" } },
};

export const STATUS_LABEL: Record<CampaignStatus, { en: string; ar: string; tone: string }> = {
  ACTIVE: { en: "Active", ar: "نشطة", tone: "bg-crimson-600 text-white" },
  SYNCED_TO_TELECOM_DNS: { en: "Synced to e& / du DNS", ar: "مُزامنة مع e& / du", tone: "bg-emerald-600 text-white" },
  COMMUNITY_FLAGGED_X: { en: "Community-flagged on X", ar: "مُبلّغ عنها على X", tone: "bg-white text-navy-900" },
};

export const P = {
  title: { en: "SAQR-INTEL · AD Police Cyber-Patrol", ar: "صقر · الدوريات الإلكترونية لشرطة أبوظبي" },
  subtitle: { en: "Cyber-Patrol Command Center", ar: "مركز القيادة للدوريات الإلكترونية" },
  live: { en: "LIVE SYNCED WITH CITIZEN SHIELD", ar: "مُزامن مباشرة مع درع المواطن" },
  polling: { en: "SYNCED (POLLING)", ar: "مُزامن (تحديث دوري)" },
  offline: { en: "RECONNECTING TO BACKEND…", ar: "جارٍ إعادة الاتصال بالخادم…" },
  citizenPortal: { en: "Citizen Portal", ar: "بوابة المواطن" },
  stageQr: { en: "Stage QR", ar: "رمز QR للعرض" },
  stageQrTitle: { en: "Scan to open the Citizen Shield", ar: "امسح لفتح درع المواطن" },
  stageQrHint: {
    en: "Judges: scan, check a link on your phone, and watch this Command Center react live.",
    ar: "للحكّام: امسحوا الرمز وافحصوا رابطاً من هواتفكم، وشاهدوا مركز القيادة يتفاعل مباشرة.",
  },
  kProtected: { en: "Citizens Protected Today", ar: "مواطنون تمت حمايتهم اليوم" },
  kEntities: { en: "Active Impersonated UAE Entities", ar: "جهات إماراتية منتحلة نشطة" },
  kPins: { en: "Hijacked Abu Dhabi Maps Pins", ar: "دبابيس خرائط مخترقة في أبوظبي" },
  kX: { en: "Community X Alerts Dispatched", ar: "تنبيهات مجتمعية على X" },
  kProtectedShort: { en: "Protected", ar: "تمت حمايتهم" },
  kEntitiesShort: { en: "Entities", ar: "الجهات" },
  kPinsShort: { en: "Hijacked pins", ar: "دبابيس مخترقة" },
  kXShort: { en: "X alerts", ar: "تنبيهات X" },
  kPreVictimShort: { en: "Pre-victim", ar: "قبل الضحايا" },
  preVictimContext: { en: "Found before any citizen visited", ar: "رُصدت قبل أن يزورها أي مواطن" },
  thisSession: { en: "this session", ar: "في هذه الجلسة" },
  lastBlock: { en: "Last block", ar: "آخر حظر" },
  lastPost: { en: "Last post", ar: "آخر منشور" },
  channelMix: { en: "Where interceptions come from", ar: "مصادر عمليات الاعتراض" },
  demoData: { en: "Demo data · resets on restart", ar: "بيانات تجريبية · تُعاد عند إعادة التشغيل" },
  includesDemo: { en: "Includes {demo} demo baseline · {live} live", ar: "يشمل {demo} رقماً تجريبياً · {live} مباشرة" },
  demoRow: { en: "Demo", ar: "تجريبي" },
  demoRowHint: { en: "Pre-loaded demo event, not a real interception", ar: "حدث تجريبي محمّل مسبقاً، وليس اعتراضاً حقيقياً" },
  stream: { en: "Live Citizen Interception Stream", ar: "بث مباشر لعمليات اعتراض المواطنين" },
  streamHint: { en: "Click an interception to inspect its campaign", ar: "اضغط على أي عملية لفحص الحملة المرتبطة بها" },
  map: { en: "Abu Dhabi Geo-Spoof Sentinel", ar: "رادار تزييف المواقع الجغرافية في أبوظبي" },
  spoofed: { en: "Spoofed pin", ar: "دبوس مزيف" },
  verified: { en: "Verified .gov.ae", ar: "موقع حكومي موثّق" },
  campaigns: { en: "Coordinated Phishing Campaigns", ar: "حملات تصيّد منسّقة" },
  hits: { en: "hits", ar: "بلاغ" },
  action: { en: "1-Click Law-Enforcement Action Center", ar: "مركز الإجراءات بنقرة واحدة" },
  selectCampaign: { en: "Select a campaign to act on it.", ar: "اختر حملة لاتخاذ إجراء." },
  syncTelecom: { en: "Sync to e& / du Telecom Blocklist", ar: "مزامنة مع قائمة حظر e& / du" },
  synced: { en: "RPZ record live", ar: "سجل RPZ مُفعّل" },
  broadcast: { en: "Broadcast Official Warning to /citizen", ar: "بث تحذير رسمي إلى بوابة المواطن" },
  broadcasted: { en: "Warning is live on /citizen", ar: "التحذير ظاهر الآن لدى المواطنين" },
  dossier: { en: "Export Official Takedown Dossier (PDF / JSON)", ar: "تصدير ملف الإزالة الرسمي (PDF / JSON)" },
  dossierTitle: { en: "Abu Dhabi Police — Takedown Dossier", ar: "شرطة أبوظبي — ملف طلب الإزالة" },
  downloadJson: { en: "Download JSON", ar: "تحميل JSON" },
  printPdf: { en: "Print / Save PDF", ar: "طباعة / حفظ PDF" },
  hosting: { en: "Hosting IP / ASN", ar: "عنوان الاستضافة / ASN" },
  sslAge: { en: "SSL age", ar: "عمر الشهادة" },
  lastSeen: { en: "Last seen", ar: "آخر ظهور" },
  channels: { en: "Channels", ar: "القنوات" },
  noEvents: { en: "Waiting for citizen interceptions…", ar: "بانتظار عمليات الاعتراض…" },
  loading: { en: "Connecting to the SAQR-INTEL backend…", ar: "جارٍ الاتصال بخادم صقر…" },
  failed: { en: "Action failed", ar: "فشل الإجراء" },
  registry: { en: "Registry check", ar: "التحقق من السجل الرسمي" },

  /* Proactive Hunt */
  hunt: { en: "Proactive Hunt · caught before any citizen visited", ar: "الصيد الاستباقي · رُصدت قبل أن يزورها أي مواطن" },
  huntHint: {
    en: "SAQR searches look-alike names, newly registered domains and certificate logs on its own, before anyone reports them.",
    ar: "يبحث صقر بنفسه في النطاقات الشبيهة والنطاقات المسجّلة حديثاً وسجلات الشهادات، قبل أن يبلّغ عنها أحد.",
  },
  kPreVictim: { en: "Threats Caught Pre-Victim", ar: "تهديدات رُصدت قبل وقوع ضحايا" },
  srcLookalike: { en: "Look-alike sweep", ar: "مسح النطاقات الشبيهة" },
  srcNrd: { en: "Newly registered", ar: "مسجّل حديثاً" },
  srcCt: { en: "CT log", ar: "سجل شفافية الشهادات" },
  srcCrtsh: { en: "crt.sh", ar: "crt.sh" },
  simulated: { en: "SIMULATED", ar: "محاكاة" },
  simulatedHint: {
    en: "Simulated mode: synthetic demo leads, clearly labelled and never published to any blocklist.",
    ar: "وضع المحاكاة: نطاقات تجريبية مُعلَّمة بوضوح ولا تُنشر في أي قائمة حظر.",
  },
  liveHunt: { en: "LIVE SOURCES", ar: "مصادر حقيقية" },
  hunterOff: { en: "The proactive hunter is switched off on this server.", ar: "الصيد الاستباقي متوقف على هذا الخادم." },
  detected: { en: "Detected", ar: "رُصد" },
  domainAge: { en: "Domain age", ar: "عمر النطاق" },
  citizensMet: { en: "Citizens who met it since", ar: "مواطنون صادفوه منذ ذلك" },
  allBlocked: { en: "all blocked", ar: "حُظروا جميعاً" },
  blockedOf: { en: "blocked", ar: "محظور" },
  noCitizenYet: { en: "No citizen has seen it yet", ar: "لم يصادفه أي مواطن بعد" },
  leadTime: { en: "Lead time before the first citizen", ar: "الفارق الزمني قبل أول مواطن" },
  hoursShort: { en: "h", ar: "س" },
  daysShort: { en: "d", ar: "ي" },
  runSweep: { en: "Run sweep now", ar: "تشغيل المسح الآن" },
  sweeping: { en: "Sweeping…", ar: "جارٍ المسح…" },
  sweepDone: { en: "Sweep finished", ar: "اكتمل المسح" },
  sweepLeads: { en: "leads", ar: "نطاقات مرشّحة" },
  sweepScanned: { en: "scanned", ar: "تم فحصها" },
  sweepConfirmed: { en: "confirmed", ar: "مؤكدة" },
  noDetections: { en: "No proactive detections yet. Run a sweep.", ar: "لا توجد عمليات رصد استباقي بعد. شغّل المسح." },
  faQueue: { en: "False-alarm reports", ar: "بلاغات الإنذار الخاطئ" },
  faHint: {
    en: "Citizens who think a warning was wrong. Confirming only records your decision: nothing is unblocked or whitelisted automatically.",
    ar: "مواطنون يعتقدون أن التحذير خاطئ. التأكيد يسجّل قرارك فقط: لا يُرفع أي حظر ولا يُضاف أي موقع إلى القائمة الآمنة تلقائياً.",
  },
  faOpen: { en: "open", ar: "مفتوح" },
  faEmpty: { en: "No false-alarm reports. Citizens can send one from a warning screen.", ar: "لا توجد بلاغات إنذار خاطئ. يمكن للمواطن إرسال بلاغ من شاشة التحذير." },
  faConfirm: { en: "Confirm false alarm", ar: "تأكيد أنه إنذار خاطئ" },
  faDismiss: { en: "Dismiss", ar: "رفض" },
  faConfirmed: { en: "Confirmed false alarm", ar: "إنذار خاطئ مؤكَّد" },
  faDismissed: { en: "Dismissed", ar: "مرفوض" },
  faNoNote: { en: "No note", ar: "بلا ملاحظة" },
  faReports: { en: "reports", ar: "بلاغات" },
  faLoadFailed: { en: "Could not load reports", ar: "تعذّر تحميل البلاغات" },
  statusConfirmed: { en: "Confirmed scam", ar: "احتيال مؤكد" },
  statusSuspicious: { en: "Suspicious", ar: "مشبوه" },
  openDossier: { en: "Evidence dossier", ar: "ملف الأدلة" },

  /* Evidence dossier */
  loadingDossier: { en: "Building the evidence dossier…", ar: "جارٍ إعداد ملف الأدلة…" },
  caseRef: { en: "Case reference", ar: "رقم القضية" },
  amanRef: { en: "Aman reference", ar: "مرجع أمان" },
  riskScore: { en: "Risk score", ar: "درجة الخطورة" },
  reasons: { en: "Why this score: every reason", ar: "سبب هذه الدرجة: جميع الأسباب" },
  triageReasons: { en: "Triage reasons (offline rules + URL model)", ar: "أسباب الفرز (قواعد محلية + نموذج الروابط)" },
  pts: { en: "pts", ar: "نقطة" },
  whois: { en: "WHOIS & registrar", ar: "بيانات WHOIS والمسجّل" },
  registrar: { en: "Registrar", ar: "المسجّل" },
  registered: { en: "Registered", ar: "تاريخ التسجيل" },
  registrantCountry: { en: "Registrant country", ar: "دولة المسجِّل" },
  abuseContacts: { en: "Abuse contacts", ar: "جهات الإبلاغ عن الإساءة" },
  nameServers: { en: "Name servers", ar: "خوادم الأسماء" },
  hostingTitle: { en: "Hosting · IP · ASN", ar: "الاستضافة · IP · ASN" },
  ipAddresses: { en: "IP addresses", ar: "عناوين IP" },
  asn: { en: "ASN", ar: "ASN" },
  country: { en: "Country", ar: "الدولة" },
  mx: { en: "Mail servers (MX)", ar: "خوادم البريد (MX)" },
  tls: { en: "TLS certificate", ar: "شهادة TLS" },
  issuer: { en: "Issuer", ar: "الجهة المُصدِرة" },
  issued: { en: "Issued", ar: "تاريخ الإصدار" },
  certAge: { en: "Certificate age", ar: "عمر الشهادة" },
  fingerprint: { en: "SHA-256 fingerprint", ar: "بصمة SHA-256" },
  redirectChain: { en: "Redirect chain", ar: "سلسلة إعادة التوجيه" },
  noRedirects: { en: "No redirects: the link opens this page directly.", ar: "لا توجد إعادة توجيه: الرابط يفتح الصفحة مباشرة." },
  screenshot: { en: "Sandbox screenshot", ar: "لقطة شاشة من بيئة العزل" },
  noShotCloud: {
    en: "No screenshot in cloud mode: the page was fetched over HTTP only (no browser sandbox on the free server).",
    ar: "لا توجد لقطة شاشة في الوضع السحابي: جُلبت الصفحة عبر HTTP فقط (لا يوجد متصفح عزل على الخادم المجاني).",
  },
  noShotFast: { en: "No screenshot: this was a fast scan without the browser sandbox.", ar: "لا توجد لقطة شاشة: كان فحصاً سريعاً دون متصفح العزل." },
  noShotUnavailable: {
    en: "No screenshot: the browser sandbox is not available on this server.",
    ar: "لا توجد لقطة شاشة: متصفح العزل غير متاح على هذا الخادم.",
  },
  noShotFailed: { en: "No screenshot: the page did not render in the sandbox.", ar: "لا توجد لقطة شاشة: لم تُعرض الصفحة في بيئة العزل." },
  timestamps: { en: "Timestamps (UTC, ISO 8601)", ar: "الطوابع الزمنية (UTC، ISO 8601)" },
  firstSeen: { en: "First seen", ar: "أول رصد" },
  scannedAt: { en: "Scanned", ar: "وقت الفحص" },
  generatedAt: { en: "Dossier generated", ar: "وقت إنشاء الملف" },
  hashes: { en: "Evidence integrity (SHA-256)", ar: "سلامة الأدلة (SHA-256)" },
  timeline: { en: "Timeline (UTC)", ar: "التسلسل الزمني (UTC)" },
  notices: { en: "Ready-to-send abuse notices", ar: "إشعارات إساءة جاهزة للإرسال" },
  registrarNotice: { en: "Registrar abuse notice", ar: "إشعار إلى المسجّل" },
  hostingNotice: { en: "Hosting abuse notice", ar: "إشعار إلى مزوّد الاستضافة" },
  copy: { en: "Copy", ar: "نسخ" },
  copied: { en: "Copied", ar: "تم النسخ" },
  detectionBlock: { en: "Proactive detection", ar: "الرصد الاستباقي" },
  source: { en: "Source", ar: "المصدر" },
  downloadZip: { en: "Download evidence pack (.zip)", ar: "تحميل حزمة الأدلة (.zip)" },
  noEvidenceSim: {
    en: "Simulated lead: no live WHOIS / DNS / TLS / page evidence exists for it.",
    ar: "نطاق محاكاة: لا توجد له أدلة حقيقية من WHOIS أو DNS أو TLS أو الصفحة.",
  },
  noEvidenceLead: {
    en: "No flagged full scan yet: only the triage evidence is shown.",
    ar: "لا يوجد فحص كامل مُبلَّغ عنه بعد: تُعرض أدلة الفرز فقط.",
  },
  syndicate: { en: "Linked syndicate", ar: "الشبكة الإجرامية المرتبطة" },
  targetDomain: { en: "Target domain", ar: "النطاق المستهدف" },
  impersonated: { en: "Impersonated entity", ar: "الجهة المنتحلة" },
  registrarAbuse: { en: "Registrar abuse email", ar: "بريد الإبلاغ لدى المسجّل" },
  citizenReports: { en: "Citizen reports", ar: "بلاغات المواطنين" },
  campaignStatus: { en: "Campaign status", ar: "حالة الحملة" },
  requestedActions: { en: "Requested actions", ar: "الإجراءات المطلوبة" },
  redFlags: { en: "Red flags", ar: "علامات الخطر" },
  verdictHigh: { en: "High-risk scam", ar: "احتيال عالي الخطورة" },
  verdictSuspicious: { en: "Suspicious", ar: "مشبوه" },
  verdictSafe: { en: "Safe", ar: "آمن" },

  /* Detection model */
  model: { en: "Detection Model", ar: "نموذج الكشف" },
  trained: { en: "Trained", ar: "تاريخ التدريب" },
  trainingRows: { en: "Training rows", ar: "صفوف التدريب" },
  holdout: { en: "Hold-out test set", ar: "مجموعة اختبار منفصلة" },
  precision: { en: "Precision", ar: "الدقة" },
  recall: { en: "Recall", ar: "الاسترجاع" },
  f1: { en: "F1", ar: "F1" },
  fpr: { en: "False-positive rate", ar: "معدل الإنذار الكاذب" },
  threshold: { en: "Threshold", ar: "العتبة" },
  fpSuite: { en: "Legitimate sites (incl. long-tail and free hosting)", ar: "مواقع سليمة (تشمل المواقع الصغيرة والاستضافة المجانية)" },
  officialSuite: { en: "UAE official, bank and government pages", ar: "صفحات الجهات الرسمية والبنوك والحكومة" },
  liveSystem: { en: "Full live scan · fresh phishing + legitimate pages", ar: "الفحص الحي الكامل · تصيّد حديث + صفحات سليمة" },
  liveNote: { en: "warn level, threat feeds off", ar: "مستوى التحذير، بدون قوائم التهديدات" },
  addressOnly: { en: "Address-only model", ar: "نموذج العنوان فقط" },
  more: { en: "more", ar: "أخرى" },
  falseAlarms: { en: "false alarms", ar: "إنذارات كاذبة" },
  datasets: { en: "Datasets", ar: "مجموعات البيانات" },
  rows: { en: "rows", ar: "صف" },

  /* Officer sign-in */
  loginTitle: { en: "Officer sign-in", ar: "دخول الضباط" },
  loginIntro: { en: "Enter the Command Center passcode to continue.", ar: "أدخل رمز الدخول إلى مركز القيادة للمتابعة." },
  passcode: { en: "Officer passcode", ar: "رمز دخول الضابط" },
  signIn: { en: "Sign in", ar: "تسجيل الدخول" },
  signingIn: { en: "Checking…", ar: "جارٍ التحقق…" },
  wrongPasscode: { en: "That passcode is not correct.", ar: "رمز الدخول غير صحيح." },
  tooManyTries: { en: "Too many attempts. Try again in a few minutes.", ar: "محاولات كثيرة. حاول مرة أخرى بعد بضع دقائق." },
  loginFailed: { en: "Sign-in failed. Check the connection and try again.", ar: "تعذّر تسجيل الدخول. تحقق من الاتصال وحاول مرة أخرى." },
  notConfigured: {
    en: "Police access is not configured on this server.",
    ar: "لم يتم إعداد دخول الشرطة على هذا الخادم.",
  },
  hackathonNote: {
    en: "Hackathon access. A real rollout would use police single sign-on.",
    ar: "دخول خاص بالهاكاثون. النشر الفعلي سيستخدم الدخول الموحّد للشرطة.",
  },
  logout: { en: "Sign out", ar: "تسجيل الخروج" },
  devUnlocked: { en: "Dev: unlocked", ar: "تطوير: بدون قفل" },
} as const;
