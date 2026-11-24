"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Mail, MapPinned, MessageSquareWarning, Monitor, Radio, ScanSearch, Share2, ShieldBan, TriangleAlert, Wifi } from "lucide-react";
import { useEffect, useState } from "react";
import { API_BASE_URL, getWsUrl, type InterceptionChannel, type VerdictLabel } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { CHANNEL_DICT_KEY, defang, ENTITY_AR, warningFromLive, type LiveBlock } from "@/lib/share";
import { WarnOnXButton } from "./XAlertComposer";

type Status = "connecting" | "live" | "offline";

interface LiveMessage {
  event: string;
  ts: string;
  data: Record<string, unknown>;
}

const MAX_ITEMS = 10;
const CHANNEL_ICON: Record<InterceptionChannel, typeof Wifi> = {
  AUTO_TELECOM_DNS: Wifi,
  AUTO_SMS_GUARD: MessageSquareWarning,
  MOBILE_OS_SHARE_SHEET: Share2,
  CITIZEN_MANUAL_CHECK: ScanSearch,
  PC_BROWSER_EXTENSION: Monitor,
  DIRECT_API: Radio,
  MANUAL: ScanSearch,
};

const LIVE_EVENTS = new Set(["url_scan.completed", "maps_scan.completed", "email_scan.completed"]);

function toBlock(msg: LiveMessage): LiveBlock | null {
  if (!LIVE_EVENTS.has(msg.event)) return null;
  const d = msg.data;
  const kind: LiveBlock["kind"] = msg.event.startsWith("maps") ? "maps" : msg.event.startsWith("email") ? "email" : "url";
  const verdict = d.verdict as VerdictLabel | undefined;
  if (!verdict || verdict === "SAFE" || typeof d.scan_id !== "string") return null;
  const listing = (d.listing ?? {}) as { website_domain?: string | null };
  const channel = d.interception_channel as InterceptionChannel | null | undefined;
  return {
    id: d.scan_id,
    kind,
    verdict,
    riskScore: Number(d.risk_score ?? 0),
    entity: (d.impersonated_entity as string | null) ?? null,
    // Email events never carry a domain: the sender's (often gmail.com) must not appear as "the scam site".
    domain: kind === "email" ? null : ((kind === "maps" ? listing.website_domain : (d.domain as string | null)) ?? null),
    channel: channel && channel in CHANNEL_DICT_KEY ? channel : null,
    harvested: Array.isArray(d.harvested_fields) ? (d.harvested_fields as string[]) : [],
    flagCodes: Array.isArray(d.red_flags) ? (d.red_flags as string[]) : Array.isArray(d.top_flags) ? (d.top_flags as string[]) : [],
    at: new Date(typeof d.created_at === "string" ? d.created_at : msg.ts),
  };
}

function merge(list: LiveBlock[], incoming: LiveBlock[]): LiveBlock[] {
  const byId = new Map(list.map((b) => [b.id, b]));
  for (const b of incoming) byId.set(b.id, b);
  return [...byId.values()].sort((a, b) => b.at.getTime() - a.at.getTime()).slice(0, MAX_ITEMS);
}

/** getWsUrl() (NEXT_PUBLIC_API_URL or same-origin proxy), then the backend port directly on plain http. */
function socketUrls(): string[] {
  const query = "?topics=url_scan,maps_scan,email_scan";
  const urls = [`${getWsUrl()}${query}`];
  if (!API_BASE_URL && window.location.protocol === "http:") urls.push(`ws://${window.location.hostname}:8000/ws/live${query}`);
  return urls;
}

function useLiveBlocks() {
  const [items, setItems] = useState<LiveBlock[]>([]);
  const [status, setStatus] = useState<Status>("connecting");

  useEffect(() => {
    let ws: WebSocket | null = null;
    let stopped = false;
    let attempt = 0;
    let retry: number | undefined;
    let ping: number | undefined;

    const connect = () => {
      const urls = socketUrls();
      const url = urls[attempt % urls.length];
      let opened = false;
      setStatus((s) => (s === "live" ? "offline" : s));
      ws = new WebSocket(url);
      ws.onopen = () => {
        opened = true;
        attempt = 0;
        setStatus("live");
        ping = window.setInterval(() => ws?.readyState === WebSocket.OPEN && ws.send("ping"), 25_000);
      };
      ws.onmessage = (e) => {
        let msg: LiveMessage;
        try {
          msg = JSON.parse(e.data as string) as LiveMessage;
        } catch {
          return;
        }
        if (msg.event === "hello") {
          const recent = Array.isArray(msg.data.recent) ? (msg.data.recent as LiveMessage[]) : [];
          setItems((list) => merge(list, recent.map(toBlock).filter((b): b is LiveBlock => b !== null)));
          return;
        }
        const block = toBlock(msg);
        if (block) setItems((list) => merge(list, [block]));
      };
      ws.onclose = () => {
        window.clearInterval(ping);
        if (stopped) return;
        attempt += 1;
        setStatus(opened ? "offline" : attempt < socketUrls().length ? "connecting" : "offline");
        const delay = opened || attempt < socketUrls().length ? 600 : Math.min(15_000, 1500 * attempt);
        retry = window.setTimeout(connect, delay);
      };
    };

    connect();
    return () => {
      stopped = true;
      window.clearTimeout(retry);
      window.clearInterval(ping);
      ws?.close();
    };
  }, []);

  return { items, status };
}

function useNow(intervalMs: number) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), intervalMs);
    return () => window.clearInterval(id);
  }, [intervalMs]);
  return now;
}

function timeAgo(at: Date, now: number, lang: "en" | "ar"): string {
  const rtf = new Intl.RelativeTimeFormat(lang === "ar" ? "ar" : "en", { numeric: "auto" });
  const secs = Math.round((at.getTime() - now) / 1000);
  if (Math.abs(secs) < 60) return rtf.format(Math.min(0, secs), "second");
  const mins = Math.round(secs / 60);
  if (Math.abs(mins) < 60) return rtf.format(mins, "minute");
  const hours = Math.round(mins / 60);
  if (Math.abs(hours) < 24) return rtf.format(hours, "hour");
  return rtf.format(Math.round(hours / 24), "day");
}

export function LiveCrowdShield() {
  const { t, lang } = useLang();
  const { items, status } = useLiveBlocks();
  const now = useNow(20_000);

  const statusStyle =
    status === "live"
      ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
      : status === "connecting"
        ? "bg-amber-500/15 text-amber-800 dark:text-amber-300"
        : "bg-crimson-600/15 text-crimson-700 dark:text-red-300";

  return (
    <section aria-labelledby="live-title" className="rounded-[20px] border border-line bg-surface p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <h2 id="live-title" className="flex items-center gap-2 font-extrabold text-ink">
            <Radio className="size-4 text-emerald-600" /> {t("liveTitle")}
          </h2>
          <p className="mt-1 text-xs leading-relaxed text-ink-soft">{t("liveIntro")}</p>
        </div>
        <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-2.5 py-1 text-[11px] font-bold ${statusStyle}`} aria-live="polite">
          <span className="relative flex size-2">
            {status === "live" && <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-500 opacity-70" />}
            <span className={`relative inline-flex size-2 rounded-full ${status === "live" ? "bg-emerald-500" : status === "connecting" ? "bg-amber-500" : "bg-crimson-600"}`} />
          </span>
          {status === "live" ? t("liveOn") : status === "connecting" ? t("liveConnecting") : t("liveOff")}
        </span>
      </div>

      <ul className="mt-4 space-y-2">
        <AnimatePresence initial={false}>
          {items.map((b) => {
            const Icon = b.kind === "email" ? Mail : b.kind === "maps" ? MapPinned : b.channel ? CHANNEL_ICON[b.channel] : ShieldBan;
            const entityAr = b.entity ? ENTITY_AR[b.entity] ?? b.entity : null;
            const entity = lang === "ar" ? entityAr : b.entity;
            const blocked = b.verdict === "HIGH-RISK SCAM";
            return (
              <motion.li
                key={b.id}
                layout
                initial={{ opacity: 0, y: -12, backgroundColor: "rgba(16,185,129,0.18)" }}
                animate={{ opacity: 1, y: 0, backgroundColor: "rgba(16,185,129,0)" }}
                exit={{ opacity: 0 }}
                transition={{ duration: 0.5 }}
                className="flex items-center gap-3 rounded-2xl p-2.5 ring-1 ring-line"
              >
                <span className={`grid size-9 shrink-0 place-items-center rounded-xl text-white ${blocked ? "bg-crimson-600" : "bg-amber-500"}`}>
                  <Icon className="size-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="flex flex-wrap items-center gap-x-2 text-sm font-bold text-ink">
                    <span className="truncate">{entity ?? t("unknownEntity")}</span>
                    <span className={`rounded px-1.5 py-px text-[11px] font-extrabold uppercase ${blocked ? "bg-crimson-600 text-white" : "bg-amber-500 text-white"}`}>
                      {blocked ? t("liveBlocked") : t("liveFlagged")} · {b.riskScore}
                    </span>
                  </p>
                  <p className="truncate text-xs text-ink-soft">
                    {b.domain && (
                      <span dir="ltr" className="font-mono">
                        {defang(b.domain)}
                      </span>
                    )}
                    {!b.domain && b.kind === "email" && <span>{t(blocked ? "emLiveScamEmail" : "emLiveSuspiciousEmail")}</span>}
                    {(b.domain || b.kind === "email") && " · "}
                    {b.channel ? t(CHANNEL_DICT_KEY[b.channel]) : null}
                    {b.channel && " · "}
                    {timeAgo(b.at, now, lang)}
                  </p>
                </div>
                <WarnOnXButton warning={warningFromLive(b, entityAr)} />
              </motion.li>
            );
          })}
        </AnimatePresence>
        {items.length === 0 && (
          <li className="flex items-center gap-2 rounded-2xl bg-muted p-3 text-xs text-ink-soft">
            <TriangleAlert className="size-4 shrink-0 text-amber-500" /> {t("liveEmpty")}
          </li>
        )}
      </ul>
    </section>
  );
}
