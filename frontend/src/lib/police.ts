"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { apiUrl, getWsUrl } from "./api";

/* ---------- types (mirror saqr/police_state.py) ---------- */
export type PoliceChannel =
  | "AUTO_TELECOM_DNS"
  | "AUTO_SMS_GUARD"
  | "CITIZEN_MANUAL_CHECK"
  | "MOBILE_OS_SHARE_SHEET"
  | "PC_BROWSER_EXTENSION"
  | "X_COMMUNITY_ALERT";

export type CampaignStatus = "ACTIVE" | "SYNCED_TO_TELECOM_DNS" | "COMMUNITY_FLAGGED_X";

export interface PoliceEvent {
  id: string;
  ts: string;
  channel: PoliceChannel;
  kind: "url" | "maps";
  domain: string | null;
  defanged_domain: string;
  risk_score: number;
  verdict: string;
  impersonated_entity: string | null;
  campaign_id: string | null;
  title: string | null;
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

export interface PoliceState {
  kpis: { citizens_protected: number; active_entities: number; hijacked_pins: number; x_alerts_dispatched: number };
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
}

/* ---------- API ---------- */
async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(apiUrl(path), {
    ...init,
    headers: { "content-type": "application/json", ...(init?.headers ?? {}) },
    cache: "no-store",
  });
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
export const getLatestWarning = () => call<{ warning: OfficialWarning | null }>("/api/police/warning/latest");

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
 * Live /police state: WebSocket (`police.*` + scan events) for instant updates, plus a 4-second
 * GET /api/police/state poll so a Render free-tier restart or a dropped socket never loses state.
 */
export function usePoliceLive() {
  const [state, setState] = useState<PoliceState | null>(null);
  const [link, setLink] = useState<LinkState>("polling");
  const [error, setError] = useState<string | null>(null);
  const wsUp = useRef(false);
  const refreshTimer = useRef<number | null>(null);

  const refresh = useCallback(async () => {
    try {
      const s = await getPoliceState();
      setState(s);
      setError(null);
      setLink(wsUp.current ? "live" : "polling");
    } catch (e) {
      setError(e instanceof Error ? e.message : "offline");
      if (!wsUp.current) setLink("offline");
    }
  }, []);

  const refreshSoon = useCallback(() => {
    if (refreshTimer.current) window.clearTimeout(refreshTimer.current);
    refreshTimer.current = window.setTimeout(() => void refresh(), 250);
  }, [refresh]);

  useEffect(() => {
    const first = window.setTimeout(() => void refresh(), 0);
    const poll = window.setInterval(() => void refresh(), 4000);
    let ws: WebSocket | null = null;
    let retry: number | null = null;
    let closed = false;
    let backoff = 1000;

    const connect = () => {
      try {
        ws = new WebSocket(`${getWsUrl()}?topics=police,url_scan,maps_scan`);
      } catch {
        return;
      }
      ws.onopen = () => {
        wsUp.current = true;
        backoff = 1000;
        setLink("live");
      };
      ws.onmessage = (m) => {
        try {
          const msg = JSON.parse(m.data) as { event: string; data: unknown };
          if (msg.event === "police.event") {
            const ev = msg.data as PoliceEvent;
            setState((s) => (s ? { ...s, recent_events: [ev, ...s.recent_events.filter((e) => e.id !== ev.id)].slice(0, 25) } : s));
          }
          if (msg.event.startsWith("police.") || msg.event.endsWith(".completed")) refreshSoon();
        } catch {
          /* ignore */
        }
      };
      ws.onclose = () => {
        wsUp.current = false;
        setLink((l) => (l === "live" ? "polling" : l));
        if (!closed) retry = window.setTimeout(connect, (backoff = Math.min(backoff * 2, 15000)));
      };
      ws.onerror = () => ws?.close();
    };
    connect();
    return () => {
      closed = true;
      window.clearTimeout(first);
      window.clearInterval(poll);
      if (retry) window.clearTimeout(retry);
      if (refreshTimer.current) window.clearTimeout(refreshTimer.current);
      ws?.close();
    };
  }, [refresh, refreshSoon]);

  return { state, link, error, refresh };
}

/* ---------- labels ---------- */
export const CHANNEL_LABEL: Record<string, { en: string; ar: string; tone: string; short: { en: string; ar: string } }> = {
  AUTO_TELECOM_DNS: { en: "Telecom DNS", ar: "حظر شبكة الاتصالات", tone: "bg-sky-500/15 text-sky-300 ring-sky-400/30", short: { en: "DNS", ar: "DNS" } },
  AUTO_SMS_GUARD: { en: "SMS Guard", ar: "حارس الرسائل", tone: "bg-violet-500/15 text-violet-300 ring-violet-400/30", short: { en: "SMS", ar: "رسائل" } },
  CITIZEN_MANUAL_CHECK: { en: "Citizen Check", ar: "فحص المواطن", tone: "bg-emerald-500/15 text-emerald-300 ring-emerald-400/30", short: { en: "Check", ar: "فحص" } },
  MOBILE_OS_SHARE_SHEET: { en: "Share Sheet", ar: "قائمة المشاركة", tone: "bg-teal-500/15 text-teal-300 ring-teal-400/30", short: { en: "Share", ar: "مشاركة" } },
  PC_BROWSER_EXTENSION: { en: "PC Extension", ar: "إضافة المتصفح", tone: "bg-amber-500/15 text-amber-300 ring-amber-400/30", short: { en: "Browser", ar: "متصفح" } },
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
  thisSession: { en: "this session", ar: "في هذه الجلسة" },
  lastBlock: { en: "Last block", ar: "آخر حظر" },
  lastPost: { en: "Last post", ar: "آخر منشور" },
  channelMix: { en: "Where interceptions come from", ar: "مصادر عمليات الاعتراض" },
  demoData: { en: "Demo data · resets on restart", ar: "بيانات تجريبية · تُعاد عند إعادة التشغيل" },
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
} as const;
