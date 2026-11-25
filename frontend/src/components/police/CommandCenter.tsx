"use client";

import { AnimatePresence, MotionConfig, motion } from "framer-motion";
import { Crosshair, ExternalLink, Flag, Loader2, LogOut, Menu, QrCode, Search, ShieldCheck, Siren, Users, X, MapPinned } from "lucide-react";
import { useRouter } from "next/navigation";
import { QRCodeSVG } from "qrcode.react";
import { useEffect, useMemo, useRef, useState, useSyncExternalStore, type KeyboardEvent, type ReactNode } from "react";
import { CityGridMap, MAP_ASPECT, type GridPin } from "@/components/CityGrid";
import { Modal } from "@/components/Modal";
import { ThemeToggle } from "@/components/ThemeToggle";
import { useLang } from "@/lib/i18n";
import { CHANNEL_LABEL, P, STATUS_LABEL, getModelMetrics, usePoliceLive, type Campaign, type CampaignStatus, type MapPin, type ModelMetrics, type PoliceEvent } from "@/lib/police";
import { SaqrLogo } from "@/components/SaqrLogo";
import { ActionCenter } from "./ActionCenter";
import AgentPipeline from "./AgentPipeline";
import { FalseAlarmQueue } from "./FalseAlarmQueue";
import { ModelCard } from "./ModelCard";
import { ProactiveHunt } from "./ProactiveHunt";
import { riskTone } from "./ui";

type L = (k: keyof typeof P) => string;
type Section = "desk" | "campaigns" | "map" | "hunt" | "actions";
const noSubscribe = () => () => {};
const EASE = [0.16, 1, 0.3, 1] as const;

const NAV: { id: Section; en: string; ar: string }[] = [
  { id: "desk", en: "Live desk", ar: "المكتب المباشر" },
  { id: "campaigns", en: "Campaigns", ar: "الحملات" },
  { id: "map", en: "Geo-spoof map", ar: "خريطة التزييف" },
  { id: "hunt", en: "Proactive hunt", ar: "الرصد الاستباقي" },
  { id: "actions", en: "Takedowns", ar: "الإزالة" },
];

function timeAgo(ts: string, lang: "en" | "ar"): string {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang === "ar" ? "ar" : "en", { numeric: "auto" });
  if (s < 60) return rtf.format(-Math.round(s), "second");
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}

/** "now", "18m", "3h" — short enough to never be the part that gets cut off. */
function shortAgo(ts: string, lang: "en" | "ar"): string {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  if (s < 60) return lang === "ar" ? "الآن" : "now";
  if (s < 3600) return `${Math.round(s / 60)}${lang === "ar" ? " د" : "m"}`;
  if (s < 86400) return `${Math.round(s / 3600)}${lang === "ar" ? " س" : "h"}`;
  return `${Math.round(s / 86400)}${lang === "ar" ? " ي" : "d"}`;
}

/** Score badge by verdict band: crimson = scam (65+), amber = suspicious (30-64), neutral below. */
function Score({ v }: { v: number }) {
  return <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-bold tabular-nums ${riskTone(v)}`} dir="ltr">{v}</span>;
}

/** States stamp themselves onto the row: green = synced (official block), amber = needs officer follow-up, crimson = active scam. */
export function Stamp({ status, lang }: { status: CampaignStatus; lang: "en" | "ar" }) {
  const tone =
    status === "SYNCED_TO_TELECOM_DNS" ? "text-safe-ink" : status === "COMMUNITY_FLAGGED_X" ? "text-suspicious-ink" : "text-scam-ink";
  return (
    <span className={`verdict-stamp text-[11px] font-extrabold uppercase tracking-[0.12em] ${tone}`}>
      {STATUS_LABEL[status][lang]}
    </span>
  );
}

/** Channels are neutral tags with a small dot; the X community channel gets the amber dot (officer follow-up). */
function channelDot(ch: string) {
  return ch === "X_COMMUNITY_ALERT" ? "bg-suspicious" : ch === "AUTO_TELECOM_DNS" ? "bg-safe" : "bg-ink-soft";
}

function Tile({ title, icon, right, children, className = "", id }: { title: string; icon: ReactNode; right?: ReactNode; children: ReactNode; className?: string; id?: string }) {
  return (
    <section id={id} className={`card scroll-mt-40 p-4 sm:p-5 ${className}`}>
      <div className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="text-ink-soft">{icon}</span>
        <h2 className="label-caps">{title}</h2>
        <div className="ms-auto">{right}</div>
      </div>
      {children}
    </section>
  );
}

/* ------------------------------------------------------------------ top bar (Saqr header, same look as /citizen) */

/** EN | عربي segmented pill (same look as the citizen header). Stays left-to-right in both languages. */
function LangPill() {
  const { lang, setLang } = useLang();
  return (
    <div role="radiogroup" aria-label="Language / اللغة" dir="ltr" className="flex shrink-0 rounded-full border border-line bg-surface p-0.5">
      {(["en", "ar"] as const).map((l) => (
        <button
          key={l}
          type="button"
          role="radio"
          aria-checked={lang === l}
          onClick={() => setLang(l)}
          lang={l}
          className={`min-h-9 min-w-10 rounded-full px-3 text-[13px] font-semibold transition-colors md:min-w-0 ${lang === l ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"}`}
        >
          {l === "en" ? (
            "EN"
          ) : (
            <>
              <span className="md:hidden">ع</span>
              <span className="hidden md:inline">عربي</span>
            </>
          )}
        </button>
      ))}
    </div>
  );
}

/* Desk view (Map | Pipeline flow), remembered for the tab in sessionStorage. */
type DeskView = "map" | "pipeline";
const VIEW_KEY = "saqr-police-desk-view";
const DESK_PANEL_ID = "desk-view-panel";
const CAMPAIGN_LIMIT = 15;
let memView: DeskView | null = null;
const viewListeners = new Set<() => void>();
function readView(): DeskView {
  if (memView) return memView;
  try {
    return window.sessionStorage.getItem(VIEW_KEY) === "pipeline" ? "pipeline" : "map";
  } catch {
    return "map";
  }
}
function writeView(v: DeskView) {
  memView = v;
  try {
    window.sessionStorage.setItem(VIEW_KEY, v);
  } catch {
    /* storage blocked: the in-memory choice still works for this page */
  }
  viewListeners.forEach((f) => f());
}
function subscribeView(f: () => void) {
  viewListeners.add(f);
  return () => {
    viewListeners.delete(f);
  };
}
function useDeskView(): [DeskView, (v: DeskView) => void] {
  const v = useSyncExternalStore(subscribeView, readView, () => "map" as DeskView);
  return [v, writeView];
}

/** Map | Pipeline flow segmented control (same look as the language pill). */
function DeskSwitch({ view, setView, L }: { view: DeskView; setView: (v: DeskView) => void; L: L }) {
  const opts: { id: DeskView; label: string }[] = [
    { id: "map", label: L("viewMap") },
    { id: "pipeline", label: L("viewPipeline") },
  ];
  const refs = useRef<(HTMLButtonElement | null)[]>([]);
  const onKey = (e: KeyboardEvent, i: number) => {
    const rtl = document.documentElement.dir === "rtl";
    let next = -1;
    if (e.key === "ArrowRight") next = rtl ? i - 1 : i + 1;
    else if (e.key === "ArrowLeft") next = rtl ? i + 1 : i - 1;
    else if (e.key === "Home") next = 0;
    else if (e.key === "End") next = opts.length - 1;
    if (next < 0) return;
    e.preventDefault();
    const j = (next + opts.length) % opts.length;
    setView(opts[j].id);
    refs.current[j]?.focus();
  };
  return (
    <div role="tablist" aria-label={L("deskView")} className="flex shrink-0 rounded-full border border-line bg-surface p-0.5">
      {opts.map((o, i) => {
        const on = view === o.id;
        return (
          <button
            key={o.id}
            ref={(el) => {
              refs.current[i] = el;
            }}
            type="button"
            role="tab"
            aria-selected={on}
            aria-controls={DESK_PANEL_ID}
            tabIndex={on ? 0 : -1}
            onClick={() => setView(o.id)}
            onKeyDown={(e) => onKey(e, i)}
            className={`min-h-10 whitespace-nowrap rounded-full px-3.5 text-[13px] font-semibold normal-case tracking-normal transition-colors ${on ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"}`}
          >
            {o.label}
          </button>
        );
      })}
    </div>
  );
}

function TopBar({ L, link, query, setQuery, devOpen, onGo }: { L: L; link: string; query: string; setQuery: (q: string) => void; devOpen: boolean; onGo: (id: Section) => void }) {
  const { lang } = useLang();
  const [active, setActive] = useState<Section>("desk");
  const [searchOpen, setSearchOpen] = useState(false);
  const [menuOpen, setMenuOpen] = useState(false);
  const [qrOpen, setQrOpen] = useState(false);
  const origin = useSyncExternalStore(noSubscribe, () => window.location.origin, () => "");
  const searchRef = useRef<HTMLInputElement>(null);
  const router = useRouter();

  const signOut = async () => {
    try {
      await fetch("/api/officer/logout", { method: "POST", credentials: "same-origin" });
    } catch {
      /* the cookie may already be gone; go to the sign-in page anyway */
    }
    router.replace("/police/login");
  };

  useEffect(() => {
    if (searchOpen) searchRef.current?.focus();
  }, [searchOpen]);

  const go = (id: Section) => {
    setActive(id);
    setMenuOpen(false);
    onGo(id); // e.g. "Geo-spoof map" switches the desk back to the map first
    // Wait a frame so a just-mounted map card exists before scrolling to it.
    requestAnimationFrame(() => document.getElementById(id)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  };
  const badge =
    link === "offline"
      ? { text: L("offline"), dot: "bg-suspicious" }
      : { text: link === "live" ? L("live") : L("polling"), dot: "bg-safe" };

  const iconBtn = "grid size-10 shrink-0 place-items-center rounded-full text-ink-soft transition-colors hover:bg-muted hover:text-ink";
  const pillBtn = "press inline-flex min-h-9 items-center gap-1.5 rounded-full border border-line bg-surface px-3 text-xs font-semibold text-ink transition-colors hover:bg-muted";

  return (
    <header className="sticky top-0 z-40 border-b border-line bg-surface/95 backdrop-blur-md">
      <div className="mx-auto flex h-16 max-w-[1500px] items-center gap-1.5 px-3 sm:gap-3 sm:px-6">
        <button type="button" className={`${iconBtn} xl:hidden`} aria-label="Menu" aria-expanded={menuOpen} onClick={() => setMenuOpen((v) => !v)}>
          {menuOpen ? <X className="size-5" /> : <Menu className="size-5" />}
        </button>
        <a href="/police" aria-label={`Saqr · ${L("brandLabel")}`} className="flex shrink-0 items-center gap-3 rounded-md">
          <SaqrLogo variant="full" size={26} />
          <span className="hidden h-6 w-px bg-line sm:block" aria-hidden />
          <span className="label-caps hidden whitespace-nowrap sm:block">{L("brandLabel")}</span>
        </a>

        <nav aria-label={lang === "ar" ? "أقسام مركز القيادة" : "Command Center sections"} className="ms-4 hidden h-full min-w-0 flex-1 items-center justify-center xl:flex">
          <ul className="flex items-center gap-1">
            {NAV.map((n) => (
              <li key={n.id}>
                <button
                  type="button"
                  onClick={() => go(n.id)}
                  aria-current={active === n.id ? "true" : undefined}
                  className={`relative inline-flex min-h-10 items-center whitespace-nowrap rounded-full px-3.5 text-[14px] transition-colors ${active === n.id ? "font-semibold text-ink" : "font-medium text-ink-soft hover:bg-muted hover:text-ink"}`}
                >
                  {lang === "ar" ? n.ar : n.en}
                  {active === n.id && <motion.span layoutId="adp-nav" className="absolute inset-x-3 -bottom-[13px] h-0.5 rounded-full bg-ink" transition={{ type: "spring", stiffness: 500, damping: 40 }} />}
                </button>
              </li>
            ))}
          </ul>
        </nav>

        <div className="ms-auto flex shrink-0 items-center gap-1.5 sm:gap-2 xl:ms-0">
          <div className="flex items-center">
            <button type="button" className={iconBtn} aria-label={lang === "ar" ? "بحث" : "Search"} aria-expanded={searchOpen} onClick={() => setSearchOpen((v) => !v)}>
              <Search className="size-5" />
            </button>
            <AnimatePresence initial={false}>
              {searchOpen && (
                <motion.input
                  ref={searchRef}
                  key="q"
                  initial={{ width: 0, opacity: 0 }}
                  animate={{ width: 200, opacity: 1 }}
                  exit={{ width: 0, opacity: 0 }}
                  transition={{ duration: 0.22, ease: EASE }}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={(e) => e.key === "Escape" && (setQuery(""), setSearchOpen(false))}
                  placeholder={lang === "ar" ? "ابحث عن نطاق أو جهة…" : "Search domain or entity…"}
                  className="h-9 max-w-[38vw] rounded-full border border-line bg-muted px-3 text-sm text-ink outline-hidden transition-shadow placeholder:text-ink-soft focus-visible:ring-2 focus-visible:ring-focus"
                  dir="ltr"
                />
              )}
            </AnimatePresence>
          </div>
          <LangPill />
          <ThemeToggle variant="saqr" />
        </div>
      </div>

      {/* status strip */}
      <div className="border-t border-line bg-muted">
        <div className="mx-auto flex max-w-[1500px] flex-wrap items-center gap-x-3 gap-y-2 px-3 py-2 sm:px-6">
          <span className="inline-flex items-center gap-2 text-[11px] font-bold uppercase tracking-[0.1em] text-ink">
            <span className={`size-2 rounded-full ${badge.dot}`} aria-hidden /> {badge.text}
          </span>
          <span className="hidden text-xs text-ink-soft lg:inline">{L("title")}</span>
          <span className="chip bg-surface ring-1 ring-line">{L("demoData")}</span>
          {devOpen && <span className="chip chip-suspicious">{L("devUnlocked")}</span>}
          <div className="ms-auto flex flex-wrap items-center gap-2">
            <a href="/citizen" target="_blank" rel="noopener" className={pillBtn}>
              {L("citizenPortal")} <ExternalLink className="size-3.5" aria-hidden />
            </a>
            <button type="button" onClick={() => setQrOpen(true)} className={pillBtn}>
              <QrCode className="size-3.5" aria-hidden /> {L("stageQr")}
            </button>
            {!devOpen && (
              <button type="button" onClick={() => void signOut()} className={pillBtn}>
                <LogOut className="size-3.5" aria-hidden /> {L("logout")}
              </button>
            )}
          </div>
        </div>
      </div>

      {/* phone / tablet menu */}
      <AnimatePresence>
        {menuOpen && (
          <motion.nav
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: "auto", opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-line bg-surface xl:hidden"
          >
            <div className="flex flex-col p-2">
              <p className="label-caps px-4 pt-2 pb-1 sm:hidden">{L("brandLabel")}</p>
              {NAV.map((n) => (
                <button key={n.id} type="button" onClick={() => go(n.id)} className={`min-h-12 rounded-xl px-4 text-start text-sm ${active === n.id ? "bg-muted font-semibold text-ink" : "font-medium text-ink-soft hover:bg-muted hover:text-ink"}`}>
                  {lang === "ar" ? n.ar : n.en}
                </button>
              ))}
            </div>
          </motion.nav>
        )}
      </AnimatePresence>

      <Modal open={qrOpen} onClose={() => setQrOpen(false)} title={L("stageQrTitle")}>
        <div className="flex flex-col items-center gap-4 py-2 text-center">
          <div className="rounded-3xl bg-white p-4 ring-1 ring-line">{origin && <QRCodeSVG value={`${origin}/citizen`} size={240} level="M" marginSize={1} />}</div>
          <p className="font-mono text-sm font-bold text-ink" dir="ltr">{origin}/citizen</p>
          <p className="max-w-sm text-sm text-ink-soft">{L("stageQrHint")}</p>
        </div>
      </Modal>
    </header>
  );
}

/* ------------------------------------------------------------------ desk */

function Kpi({ label, short, value, icon, accent, context, note, className = "" }: {
  label: string; short: string; value: number | undefined; icon: ReactNode; accent: string; context?: ReactNode; note?: string; className?: string;
}) {
  return (
    <div className={`card min-w-0 p-4 ${className}`}>
      <div className="flex items-center gap-2" title={label}>
        <span className={accent}>{icon}</span>
        <p className="label-caps min-w-0"><span className="sm:hidden">{short}</span><span className="hidden sm:inline">{label}</span></p>
      </div>
      <motion.p key={value} initial={{ opacity: 0.35 }} animate={{ opacity: 1 }} transition={{ duration: 0.4 }} className="mt-2 text-[40px] font-semibold leading-none tracking-tight text-ink tabular-nums" dir="ltr">
        {value === undefined ? "—" : value.toLocaleString("en-US")}
      </motion.p>
      {/* Honest numbers: how much of the figure is the fixed demo baseline and how much is live. */}
      {note && <p className="mt-1.5 text-[11px] font-semibold leading-snug text-ink-soft">{note}</p>}
      {context && <p className="mt-2 line-clamp-2 text-xs leading-snug text-ink-soft">{context}</p>}
    </div>
  );
}

function Stream({ events, selected, onPick, lang, L }: { events: PoliceEvent[]; selected: string | null; onPick: (e: PoliceEvent) => void; lang: "en" | "ar"; L: L }) {
  return (
    <ul className="max-h-[360px] overflow-y-auto pe-1 [mask-image:linear-gradient(to_bottom,#000_calc(100%-36px),transparent)] pb-6">
      {events.length === 0 && <li className="p-3 text-sm text-ink-soft">{L("noEvents")}</li>}
      <AnimatePresence initial={false}>
        {events.map((e) => {
          const ch = CHANNEL_LABEL[e.channel] ?? CHANNEL_LABEL.CITIZEN_MANUAL_CHECK;
          const on = selected !== null && e.campaign_id === selected;
          return (
            <motion.li key={e.id} layout initial={{ opacity: 0, y: -12 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3, ease: EASE }} className="border-t border-line first:border-0">
              <button type="button" onClick={() => onPick(e)} className={`flex w-full items-center gap-3 rounded-xl px-2 py-2.5 text-start transition-colors ${on ? "bg-muted" : "hover:bg-muted/60"}`}>
                <span className="chip w-[4.75rem] shrink-0 justify-start truncate" title={ch[lang]}>
                  <span className={`size-1.5 shrink-0 rounded-full ${channelDot(e.channel)}`} aria-hidden />
                  <span className="truncate">{ch.short[lang]}</span>
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate font-mono text-[13px] font-bold text-ink" dir="ltr">{e.title ?? e.defanged_domain}</span>
                  <span className="block truncate text-xs text-ink-soft">{e.impersonated_entity ?? "—"}</span>
                </span>
                {e.seeded && (
                  <span className="chip-tag shrink-0" title={L("demoRowHint")}>
                    {L("demoRow")}
                  </span>
                )}
                <span className="shrink-0 text-xs tabular-nums text-ink-soft">{shortAgo(e.ts, lang)}</span>
                <Score v={e.risk_score} />
              </button>
            </motion.li>
          );
        })}
      </AnimatePresence>
    </ul>
  );
}

function Roster({ list, selected, onPick, lang, L }: { list: Campaign[]; selected: string | null; onPick: (c: Campaign) => void; lang: "en" | "ar"; L: L }) {
  return (
    <ol className="grid sm:grid-cols-2 sm:gap-x-6">
      {list.map((c, i) => {
        const on = c.campaign_id === selected;
        return (
          <li key={c.campaign_id}>
            <button type="button" onClick={() => onPick(c)} className={`flex w-full items-start gap-3 border-t border-line px-1 py-3 text-start transition-colors ${on ? "bg-muted" : "hover:bg-muted/60"}`}>
              <span className="w-6 shrink-0 pt-0.5 text-sm font-light text-ink-soft tabular-nums">{String(i + 1).padStart(2, "0")}</span>
              <span className="min-w-0 flex-1">
                <span className="flex items-center gap-2">
                  <span className="min-w-0 flex-1 truncate font-mono text-[13px] font-bold text-ink" dir="ltr">{c.defanged_domain}</span>
                  <Score v={c.risk_score} />
                </span>
                <span className="mt-0.5 block text-xs text-ink-soft">
                  {c.impersonated_entity ?? "—"} · <b className="font-semibold text-ink">{c.hit_count}</b> {L("hits")} · <span dir="ltr">{c.ip_asn}</span>
                </span>
                <span className="mt-2 block"><Stamp status={c.status} lang={lang} /></span>
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}

export function CommandCenter({ devOpen = false }: { devOpen?: boolean }) {
  const { lang } = useLang();
  const L: L = (k) => P[k][lang];
  const { state, link, refresh } = usePoliceLive();
  const [picked, setPicked] = useState<string | null>(null);
  // undefined = show the newest scam pin automatically; null = the officer closed the card.
  const [pinChoice, setPinChoice] = useState<MapPin | null | undefined>(undefined);
  const [query, setQuery] = useState("");
  const [metrics, setMetrics] = useState<ModelMetrics | null>(null);

  useEffect(() => {
    let alive = true;
    void getModelMetrics().then((m) => alive && setMetrics(m));
    return () => {
      alive = false;
    };
  }, []);

  const q = query.trim().toLowerCase();
  const match = (s: (string | null | undefined)[]) => !q || s.some((x) => x?.toLowerCase().includes(q));
  const campaigns = useMemo(() => state?.campaigns ?? [], [state]);
  const shownCampaigns = campaigns.filter((c) => match([c.domain, c.impersonated_entity]));
  // Backend already orders campaigns by impact (risk score x hits, then hits): show the top 15 only.
  const topCampaigns = shownCampaigns.slice(0, CAMPAIGN_LIMIT);
  const [view, setView] = useDeskView();
  const deskSwitch = <DeskSwitch view={view} setView={setView} L={L} />;
  const shownEvents = (state?.recent_events ?? []).filter((e) => match([e.domain, e.impersonated_entity, e.title]));
  const selected = picked ?? campaigns[0]?.campaign_id ?? null;
  const current = campaigns.find((c) => c.campaign_id === selected) ?? null;
  const pins: GridPin[] = (state?.map_pins ?? []).map((p) => ({ id: p.id, lat: p.lat, lng: p.lng, title: p.title, type: p.type }));
  const pin = pinChoice === undefined ? (state?.map_pins.find((p) => p.type === "SPOOFED") ?? null) : pinChoice;
  const latest = state?.recent_events[0];
  // KPI context: when and how the last block happened, the last X post, the entities impersonated.
  const lastX = state?.recent_events.find((e) => e.channel === "X_COMMUNITY_ALERT");
  const mix = Object.entries(
    (state?.recent_events ?? []).reduce<Record<string, number>>((m, e) => ((m[e.channel] = (m[e.channel] ?? 0) + 1), m), {}),
  ).sort((a, b) => b[1] - a[1]);
  const mixMax = Math.max(1, ...mix.map(([, n]) => n));
  // "Includes 1,284 demo baseline · 3 live": shown only when the backend reports the split.
  const demoNote = (k: "citizens_protected" | "x_alerts_dispatched") => {
    const base = state?.demo_baseline?.[k];
    const live = state?.live_counts?.[k];
    if (base === undefined || live === undefined) return undefined;
    return L("includesDemo").replace("{demo}", base.toLocaleString("en-US")).replace("{live}", live.toLocaleString("en-US"));
  };
  const entityNames = [...new Set(campaigns.map((c) => c.impersonated_entity).filter(Boolean))].slice(0, 3).join(" · ");

  const pickPin = (g: GridPin) => {
    const p = state?.map_pins.find((x) => x.id === g.id) ?? null;
    setPinChoice(p);
    const c = p && campaigns.find((x) => x.domain === p.domain);
    if (c) setPicked(c.campaign_id);
  };

  return (
    <MotionConfig reducedMotion="user">
      <div className="min-h-dvh bg-canvas text-ink">
        <TopBar L={L} link={link} query={query} setQuery={setQuery} devOpen={devOpen} onGo={(id) => id === "map" && setView("map")} />

        <main id="desk" className="mx-auto max-w-[1500px] scroll-mt-40 space-y-4 px-4 py-5 sm:px-6">
          {!state && (
            <p className="card flex items-center gap-2 p-4 text-sm text-ink-soft">
              <Loader2 className="size-4 animate-spin" /> {L("loading")}
            </p>
          )}

          {/* Pipeline flow: lifted above the desk grid into its own full-width row (the diagram needs ~960px). */}
          {view === "pipeline" && (
            <motion.div key="pipeline-view" id={DESK_PANEL_ID} role="tabpanel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2, ease: EASE }}>
              <AgentPipeline toolbar={deskSwitch} />
            </motion.div>
          )}

          <div className="grid grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-[260px_minmax(0,1fr)_380px]">
            <div className="grid min-w-0 grid-cols-[repeat(2,minmax(0,1fr))] gap-3 sm:gap-4 lg:grid-cols-1 lg:content-start">
              <Kpi label={L("kProtected")} short={L("kProtectedShort")} value={state?.kpis.citizens_protected} icon={<Users className="size-4" />} accent="text-safe-ink"
                note={demoNote("citizens_protected")}
                context={latest ? `${L("lastBlock")} ${shortAgo(latest.ts, lang)} · ${(CHANNEL_LABEL[latest.channel] ?? CHANNEL_LABEL.CITIZEN_MANUAL_CHECK)[lang]}` : undefined} />
              <Kpi label={L("kEntities")} short={L("kEntitiesShort")} value={state?.kpis.active_entities} icon={<Siren className="size-4" />} accent="text-scam-ink"
                context={entityNames} />
              <Kpi label={L("kPins")} short={L("kPinsShort")} value={state?.kpis.hijacked_pins} icon={<MapPinned className="size-4" />} accent="text-scam-ink"
                context={state?.map_pins.find((p) => p.type === "SPOOFED")?.title} />
              <Kpi label={L("kX")} short={L("kXShort")} value={state?.kpis.x_alerts_dispatched} icon={<Flag className="size-4" />} accent="text-suspicious-ink"
                note={demoNote("x_alerts_dispatched")}
                context={lastX ? `${L("lastPost")} ${shortAgo(lastX.ts, lang)} · ${lastX.defanged_domain}` : undefined} />
              <Kpi label={L("kPreVictim")} short={L("kPreVictimShort")} value={state?.kpis.pre_victim_detections} icon={<Crosshair className="size-4" />} accent="text-suspicious-ink"
                className="col-span-2 lg:col-span-1" context={L("preVictimContext")} />
              <section className="card col-span-2 p-4 lg:col-span-1">
                <h2 className="label-caps mb-3">{L("channelMix")}</h2>
                <ul className="space-y-2">
                  {mix.map(([ch, n]) => (
                    <li key={ch} className="grid grid-cols-[4.5rem_1fr_1.5rem] items-center gap-2 text-xs">
                      <span className="truncate font-semibold text-ink">{(CHANNEL_LABEL[ch] ?? CHANNEL_LABEL.CITIZEN_MANUAL_CHECK).short[lang]}</span>
                      <span className="h-1.5 overflow-hidden rounded-full bg-muted">
                        <span className="block h-full rounded-full bg-ink-soft" style={{ width: `${(n / mixMax) * 100}%` }} />
                      </span>
                      <span className="text-end tabular-nums text-ink-soft">{n}</span>
                    </li>
                  ))}
                </ul>
              </section>
            </div>

            <div className="min-w-0 space-y-4">
              {view === "map" && (
              <motion.div key="map-view" id={DESK_PANEL_ID} role="tabpanel" initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.2, ease: EASE }}>
              <Tile id="map" title={L("map")} icon={<MapPinned className="size-4" />}
                right={
                  <span className="flex flex-wrap items-center justify-end gap-3">
                    <span className="flex items-center gap-3 whitespace-nowrap text-xs text-ink-soft">
                      <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-scam" />{L("spoofed")}</span>
                      <span className="flex items-center gap-1"><span className="size-2.5 rounded-full bg-safe" />{L("verified")}</span>
                    </span>
                    {deskSwitch}
                  </span>
                }
                className="flex flex-col"
              >
                {latest && (
                <p className="mb-2 flex min-w-0 items-center gap-2 text-xs text-ink-soft" aria-live="polite">
                  <span className="size-2 shrink-0 rounded-full bg-scam" />
                  <span className="min-w-0 truncate">
                    <b className="font-mono font-bold text-ink" dir="ltr">{latest.title ?? latest.defanged_domain}</b>
                    {" · "}{(CHANNEL_LABEL[latest.channel] ?? CHANNEL_LABEL.CITIZEN_MANUAL_CHECK)[lang]}
                    {latest.impersonated_entity ? ` · ${latest.impersonated_entity}` : ""} · {timeAgo(latest.ts, lang)}
                  </span>
                </p>
              )}
              <div className="relative w-full overflow-hidden rounded-xl border border-line bg-canvas" style={{ aspectRatio: MAP_ASPECT }}>
                  <CityGridMap pins={pins} selectedId={pin?.id ?? null} onSelect={pickPin} label={L("map")} lang={lang} />
                </div>
                  <AnimatePresence>
                    {pin && (
                      <motion.div
                        initial={{ opacity: 0, y: 10 }}
                        animate={{ opacity: 1, y: 0 }}
                        exit={{ opacity: 0, y: 6 }}
                        transition={{ duration: 0.24, ease: EASE }}
                        className="mt-3 border-t border-line pt-3"
                      >
                        <div className="flex items-start gap-2">
                          <span className={`chip mt-0.5 shrink-0 ${pin.type === "SPOOFED" ? "chip-scam" : "chip-safe"}`}>
                            {pin.type === "SPOOFED" ? L("spoofed") : L("verified")}
                          </span>
                          <p className="min-w-0 flex-1 text-sm font-bold text-ink">{pin.title}</p>
                          <button type="button" onClick={() => setPinChoice(null)} className="grid size-9 shrink-0 place-items-center rounded-full text-ink-soft hover:bg-muted hover:text-ink" aria-label="Close"><X className="size-4" /></button>
                        </div>
                        <p className="mt-1.5 max-w-[68ch] text-xs leading-relaxed text-ink-soft"><b className="text-ink">{L("registry")}: </b>{pin.registry_note}</p>
                      </motion.div>
                    )}
                  </AnimatePresence>
              </Tile>
              </motion.div>
              )}
                <Tile id="campaigns" title={L("campaigns")} icon={<Siren className="size-4" />}
              right={
                <span className="text-xs text-ink-soft tabular-nums">
                  {shownCampaigns.length > CAMPAIGN_LIMIT
                    ? L("topOf").replace("{shown}", String(CAMPAIGN_LIMIT)).replace("{total}", String(shownCampaigns.length))
                    : shownCampaigns.length}
                </span>
              }>
              <Roster list={topCampaigns} selected={selected} onPick={(c) => setPicked(c.campaign_id)} lang={lang} L={L} />
            </Tile>
            </div>

            <div className="space-y-4">
              <Tile title={L("stream")} icon={<Siren className="size-4" />} right={<span className="text-xs text-ink-soft tabular-nums">{shownEvents.length}</span>}>
                <Stream events={shownEvents} selected={selected} lang={lang} L={L} onPick={(e) => e.campaign_id && setPicked(e.campaign_id)} />
              </Tile>
              <Tile id="actions" title={L("action")} icon={<ShieldCheck className="size-4" />}>
                <ActionCenter campaign={current} onChanged={() => void refresh()} />
              </Tile>
            </div>
          </div>

          <div id="hunt" className="grid scroll-mt-40 grid-cols-[minmax(0,1fr)] gap-4 lg:grid-cols-5">
            <ProactiveHunt
              className={metrics ? "lg:col-span-3" : "lg:col-span-5"}
              detections={state?.proactive_detections ?? []}
              mode={state?.hunter_mode}
              onSwept={() => void refresh()}
            />
            {metrics && <ModelCard metrics={metrics} className="lg:col-span-2" />}
          </div>

          <FalseAlarmQueue />

        </main>
      </div>
    </MotionConfig>
  );
}
