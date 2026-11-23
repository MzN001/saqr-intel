"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ExternalLink, Flag, Globe2, Loader2, MapPinned, QrCode, Radar, ShieldCheck, Siren, Users } from "lucide-react";
import dynamic from "next/dynamic";
import { QRCodeSVG } from "qrcode.react";
import { useMemo, useState, useSyncExternalStore, type ReactNode } from "react";
import { Modal } from "@/components/Modal";
import { useLang } from "@/lib/i18n";
import { CHANNEL_LABEL, P, STATUS_LABEL, usePoliceLive, type Campaign, type MapPin, type PoliceEvent } from "@/lib/police";
import { ActionCenter } from "./ActionCenter";

const AbuDhabiMap = dynamic(() => import("@/components/AbuDhabiMap"), {
  ssr: false,
  loading: () => (
    <div className="grid h-full place-items-center text-sm text-white/50">
      <Loader2 className="size-5 animate-spin" />
    </div>
  ),
});

type L = (k: keyof typeof P) => string;
const noSubscribe = () => () => {};

function timeAgo(ts: string, lang: "en" | "ar"): string {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang === "ar" ? "ar" : "en", { numeric: "auto" });
  if (s < 60) return rtf.format(-Math.round(s), "second");
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}

function riskTone(score: number) {
  return score >= 65 ? "bg-crimson-600 text-white" : score >= 30 ? "bg-amber-500 text-navy-900" : "bg-emerald-600 text-white";
}

function Card({ title, icon, children, right, className = "" }: { title: string; icon: ReactNode; children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <section className={`rounded-3xl bg-navy-900/70 p-4 ring-1 ring-white/10 backdrop-blur ${className}`}>
      <div className="mb-3 flex items-center gap-2">
        <span className="grid size-8 place-items-center rounded-xl bg-white/10 text-white">{icon}</span>
        <h2 className="text-sm font-extrabold uppercase tracking-wider text-white">{title}</h2>
        <div className="ms-auto">{right}</div>
      </div>
      {children}
    </section>
  );
}

function Header({ link, lang, setLang, L }: { link: string; lang: "en" | "ar"; setLang: (l: "en" | "ar") => void; L: L }) {
  const [qrOpen, setQrOpen] = useState(false);
  const origin = useSyncExternalStore(noSubscribe, () => window.location.origin, () => "");
  const citizenUrl = `${origin}/citizen`;
  const badge =
    link === "offline"
      ? { text: L("offline"), dot: "bg-amber-400", ring: "ring-amber-400/40 text-amber-200" }
      : { text: link === "live" ? L("live") : L("polling"), dot: "bg-emerald-400", ring: "ring-emerald-400/40 text-emerald-200" };

  return (
    <header className="sticky top-0 z-30 border-b border-white/10 bg-navy-900 shadow-lg">
      <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-3 px-4 py-3 sm:px-6">
        <div className="relative grid size-11 shrink-0 place-items-center rounded-2xl bg-navy-950 shadow-md ring-2 ring-gold-500/60">
          <ShieldCheck className="size-6 text-gold-500" />
          <span className="absolute -bottom-0.5 -end-0.5 size-3 rounded-full border-2 border-navy-900 bg-emerald-500" />
        </div>
        <div className="min-w-0">
          <h1 className="text-base font-extrabold leading-tight tracking-tight text-white sm:text-lg">{L("title")}</h1>
          <p className="text-xs font-medium text-white/60">{L("subtitle")}</p>
        </div>

        <span className={`ms-auto inline-flex items-center gap-2 rounded-full bg-white/5 px-3 py-1.5 text-[11px] font-extrabold tracking-wider ring-1 ${badge.ring}`}>
          <span className="relative flex size-2.5">
            <span className={`absolute inline-flex size-full animate-ping rounded-full opacity-75 ${badge.dot}`} />
            <span className={`relative inline-flex size-2.5 rounded-full ${badge.dot}`} />
          </span>
          {badge.text}
        </span>

        <div className="flex items-center gap-2">
          <a href="/citizen" target="_blank" rel="noopener"
            className="inline-flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1.5 text-xs font-bold text-white ring-1 ring-white/15 hover:bg-white/20">
            {L("citizenPortal")} <ExternalLink className="size-3.5" />
          </a>
          <button type="button" onClick={() => setQrOpen(true)}
            className="inline-flex items-center gap-1.5 rounded-full bg-gold-500 px-3 py-1.5 text-xs font-extrabold text-navy-900 hover:brightness-110">
            <QrCode className="size-3.5" /> {L("stageQr")}
          </button>
          <div role="radiogroup" aria-label="Language" className="flex rounded-full bg-navy-950 p-1 text-xs font-bold ring-1 ring-white/15" dir="ltr">
            {(["en", "ar"] as const).map((l) => (
              <button key={l} role="radio" aria-checked={lang === l} onClick={() => setLang(l)}
                className={`rounded-full px-3 py-1.5 transition-colors ${lang === l ? "bg-white text-navy-900" : "text-white/75 hover:text-white"}`}>
                {l === "en" ? "English" : "العربية"}
              </button>
            ))}
          </div>
        </div>
      </div>

      <Modal open={qrOpen} onClose={() => setQrOpen(false)} title={L("stageQrTitle")}>
        <div className="flex flex-col items-center gap-4 py-2 text-center">
          <div className="rounded-3xl bg-white p-4 shadow-inner ring-1 ring-line">
            {origin && <QRCodeSVG value={citizenUrl} size={240} level="M" marginSize={1} />}
          </div>
          <p className="font-mono text-sm font-bold text-ink" dir="ltr">{citizenUrl}</p>
          <p className="max-w-sm text-sm text-ink-soft">{L("stageQrHint")}</p>
        </div>
      </Modal>
    </header>
  );
}

function Kpi({ label, value, icon, tone }: { label: string; value: number | undefined; icon: ReactNode; tone: string }) {
  return (
    <div className="relative overflow-hidden rounded-3xl bg-navy-900/80 p-4 ring-1 ring-white/10">
      <div className={`absolute -end-6 -top-6 size-24 rounded-full opacity-20 blur-2xl ${tone}`} />
      <div className="flex items-center gap-2 text-white/70">
        {icon}
        <p className="text-xs font-bold uppercase tracking-wider">{label}</p>
      </div>
      <motion.p key={value} initial={{ scale: 1.15, opacity: 0.4 }} animate={{ scale: 1, opacity: 1 }}
        className="mt-2 text-4xl font-black tabular-nums text-white" dir="ltr">
        {value === undefined ? "—" : value.toLocaleString("en-US")}
      </motion.p>
    </div>
  );
}

function Stream({ events, selected, onPick, lang, L }: { events: PoliceEvent[]; selected: string | null; onPick: (e: PoliceEvent) => void; lang: "en" | "ar"; L: L }) {
  return (
    <ul className="max-h-[420px] space-y-2 overflow-y-auto pe-1">
      {events.length === 0 && <li className="p-4 text-sm text-white/50">{L("noEvents")}</li>}
      <AnimatePresence initial={false}>
        {events.map((e) => {
          const ch = CHANNEL_LABEL[e.channel] ?? CHANNEL_LABEL.CITIZEN_MANUAL_CHECK;
          const active = selected !== null && e.campaign_id === selected;
          return (
            <motion.li key={e.id} layout initial={{ opacity: 0, y: -18, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0 }} transition={{ type: "spring", stiffness: 380, damping: 32 }}>
              <button type="button" onClick={() => onPick(e)}
                className={`flex w-full items-center gap-3 rounded-2xl px-3 py-2.5 text-start ring-1 transition ${active ? "bg-white/15 ring-gold-500/70" : "bg-white/5 ring-white/10 hover:bg-white/10"}`}>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-[10px] font-extrabold uppercase tracking-wide ring-1 ${ch.tone}`}>{ch[lang]}</span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-sm font-bold text-white" dir="ltr">{e.title ?? e.defanged_domain}</span>
                  <span className="block truncate text-xs text-white/55">
                    {e.impersonated_entity ?? "—"} · {timeAgo(e.ts, lang)}
                  </span>
                </span>
                <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-black tabular-nums ${riskTone(e.risk_score)}`}>{e.risk_score}</span>
              </button>
            </motion.li>
          );
        })}
      </AnimatePresence>
    </ul>
  );
}

function Campaigns({ list, selected, onPick, lang, L }: { list: Campaign[]; selected: string | null; onPick: (c: Campaign) => void; lang: "en" | "ar"; L: L }) {
  return (
    <ul className="max-h-[440px] space-y-2 overflow-y-auto pe-1">
      {list.map((c) => {
        const st = STATUS_LABEL[c.status];
        const active = c.campaign_id === selected;
        return (
          <li key={c.campaign_id}>
            <button type="button" onClick={() => onPick(c)}
              className={`w-full rounded-2xl p-3 text-start ring-1 transition ${active ? "bg-white/15 ring-gold-500/70" : "bg-white/5 ring-white/10 hover:bg-white/10"}`}>
              <div className="flex items-center gap-2">
                <span className="min-w-0 flex-1 truncate font-mono text-sm font-bold text-white" dir="ltr">{c.defanged_domain}</span>
                <span className={`rounded-full px-2 py-0.5 text-xs font-black tabular-nums ${riskTone(c.risk_score)}`}>{c.risk_score}</span>
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-white/60">
                <span className="font-semibold text-white/80">{c.impersonated_entity ?? "—"}</span>
                <span>·</span>
                <span className="font-bold text-white">{c.hit_count}</span> {L("hits")}
                <span className={`ms-auto rounded-full px-2 py-0.5 text-[10px] font-extrabold ${st.tone}`}>{st[lang]}</span>
              </div>
              <div className="mt-1.5 grid grid-cols-2 gap-2 text-[11px] text-white/50">
                <span className="truncate" dir="ltr" title={c.ip_asn}>{L("hosting")}: {c.ip_asn}</span>
                <span className="truncate text-end" dir="ltr">{L("sslAge")}: {c.ssl_age}</span>
              </div>
            </button>
          </li>
        );
      })}
    </ul>
  );
}

export function CommandCenter() {
  const { lang, setLang } = useLang();
  const L: L = (k) => P[k][lang];
  const { state, link, refresh } = usePoliceLive();
  const [picked, setPicked] = useState<string | null>(null);
  const [pin, setPin] = useState<MapPin | null>(null);

  const campaigns = useMemo(() => state?.campaigns ?? [], [state]);
  // Until the officer picks one, the most severe campaign is selected.
  const selected = picked ?? campaigns[0]?.campaign_id ?? null;
  const setSelected = setPicked;
  const current = campaigns.find((c) => c.campaign_id === selected) ?? null;

  const pickPin = (p: MapPin) => {
    setPin(p);
    const c = campaigns.find((x) => x.domain === p.domain);
    if (c) setSelected(c.campaign_id);
  };

  return (
    <div className="min-h-dvh bg-navy-950 text-white" style={{ backgroundImage: "radial-gradient(circle at 20% -10%, rgba(30,58,95,.55), transparent 45%)" }}>
      <Header link={link} lang={lang} setLang={setLang} L={L} />

      <main className="mx-auto max-w-[1500px] space-y-4 px-4 py-5 sm:px-6">
        {!state && (
          <p className="flex items-center gap-2 rounded-2xl bg-white/5 p-4 text-sm text-white/70 ring-1 ring-white/10">
            <Loader2 className="size-4 animate-spin" /> {L("loading")}
          </p>
        )}

        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <Kpi label={L("kProtected")} value={state?.kpis.citizens_protected} icon={<Users className="size-4" />} tone="bg-emerald-400" />
          <Kpi label={L("kEntities")} value={state?.kpis.active_entities} icon={<Siren className="size-4" />} tone="bg-crimson-600" />
          <Kpi label={L("kPins")} value={state?.kpis.hijacked_pins} icon={<MapPinned className="size-4" />} tone="bg-amber-400" />
          <Kpi label={L("kX")} value={state?.kpis.x_alerts_dispatched} icon={<Flag className="size-4" />} tone="bg-sky-400" />
        </div>

        <div className="grid gap-4 lg:grid-cols-5">
          <div className="space-y-4 lg:col-span-3">
            <Card title={L("stream")} icon={<Radar className="size-4" />} right={<span className="hidden text-[11px] text-white/50 sm:block">{L("streamHint")}</span>}>
              <Stream events={state?.recent_events ?? []} selected={selected} lang={lang} L={L}
                onPick={(e) => e.campaign_id && setSelected(e.campaign_id)} />
            </Card>

            <Card title={L("map")} icon={<Globe2 className="size-4" />}
              right={
                <span className="flex items-center gap-3 text-[11px] text-white/70">
                  <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-crimson-600" />{L("spoofed")}</span>
                  <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-emerald-500" />{L("verified")}</span>
                </span>
              }>
              <div className="relative h-[380px] overflow-hidden rounded-2xl ring-1 ring-white/10" dir="ltr">
                <AbuDhabiMap pins={state?.map_pins ?? []} selectedId={pin?.id ?? null} onSelect={pickPin} />
                {pin && (
                  <div className="absolute inset-x-3 bottom-3 z-[500] rounded-2xl bg-navy-950/95 p-3 shadow-xl ring-1 ring-white/15" dir={lang === "ar" ? "rtl" : "ltr"}>
                    <div className="flex items-start gap-2">
                      <span className={`mt-0.5 rounded-full px-2 py-0.5 text-[10px] font-extrabold ${pin.type === "SPOOFED" ? "bg-crimson-600" : "bg-emerald-600"}`}>
                        {pin.type === "SPOOFED" ? L("spoofed") : L("verified")}
                      </span>
                      <p className="min-w-0 flex-1 text-sm font-bold">{pin.title}</p>
                      <button type="button" onClick={() => setPin(null)} className="text-white/50 hover:text-white" aria-label="Close">✕</button>
                    </div>
                    <p className="mt-1.5 text-xs leading-relaxed text-white/75">
                      <span className="font-bold text-white">{L("registry")}: </span>{pin.registry_note}
                    </p>
                    {pin.domain && <p className="mt-1 font-mono text-xs text-white/60" dir="ltr">{pin.domain.replace(/\./g, "[.]")}</p>}
                  </div>
                )}
              </div>
            </Card>
          </div>

          <div className="space-y-4 lg:col-span-2">
            <Card title={L("campaigns")} icon={<Siren className="size-4" />}>
              <Campaigns list={campaigns} selected={selected} onPick={(c) => setSelected(c.campaign_id)} lang={lang} L={L} />
            </Card>
            <Card title={L("action")} icon={<ShieldCheck className="size-4" />}>
              <ActionCenter campaign={current} onChanged={() => void refresh()} />
            </Card>
          </div>
        </div>
      </main>
    </div>
  );
}
