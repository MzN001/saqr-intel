"use client";

import { AnimatePresence, motion } from "framer-motion";
import { BellRing, ChevronDown, FileWarning, Hash, MapPin, Megaphone, Radio, RefreshCw, Satellite, ShieldCheck, Users } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { getAwareness, type AwarenessAlert, type AwarenessWave } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { ENTITY_AR, type WarningInfo } from "@/lib/share";
import { LiveCrowdShield } from "./LiveCrowdShield";
import { WarnOnXButton } from "./XAlertComposer";

interface AlertCardData {
  entity: string;
  severity: "HIGH" | "MEDIUM" | "LOW";
  wave: AwarenessWave;
  titleEn: string;
  titleAr: string;
  postEn: string;
  postAr: string;
  tipsEn: string[];
  tipsAr: string[];
  hashtags: string[];
  generatedAt: string;
  xPostEn: string;
  xPostAr: string;
}

const SEVERITY_STYLE = {
  HIGH: { pill: "bg-crimson-600 text-white", dot: "#c8102e", ring: "ring-crimson-600/30" },
  MEDIUM: { pill: "bg-amber-500 text-white", dot: "#d97706", ring: "ring-amber-500/30" },
  LOW: { pill: "bg-emerald-600 text-white", dot: "#0e9f6e", ring: "ring-emerald-600/30" },
} as const;

const AREA_AR: Record<string, string> = {
  "Abu Dhabi City": "مدينة أبوظبي",
  Mussafah: "مصفح",
  "Mussafah M-37": "مصفح م-37",
  "Khalifa City": "مدينة خليفة",
  "Khalifa City A": "مدينة خليفة أ",
  "Al Ain": "العين",
  "Al Dhafra": "الظفرة",
};

function toCard(a: AwarenessAlert): AlertCardData | null {
  if (a.status !== "active_wave" || !a.wave || !a.trending_entity) return null;
  return {
    entity: a.trending_entity,
    severity: a.severity ?? "LOW",
    wave: a.wave,
    titleEn: a.title_en ?? "",
    titleAr: a.title_ar ?? "",
    postEn: a.post_en ?? "",
    postAr: a.post_ar ?? "",
    tipsEn: a.safety_tips_en ?? [],
    tipsAr: a.safety_tips_ar ?? [],
    hashtags: a.hashtags ?? [],
    generatedAt: a.generated_at,
    xPostEn: a.x_post_en ?? "",
    xPostAr: a.x_post_ar ?? "",
  };
}

function hashAngle(s: string): number {
  let h = 0;
  for (const ch of s) h = (h * 31 + ch.charCodeAt(0)) % 360;
  return h;
}

function Radar({ cards }: { cards: AlertCardData[] }) {
  const { lang } = useLang();
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[340px]">
      <div className="absolute inset-0 rounded-full bg-[radial-gradient(circle,#13294a_0%,#0b192c_70%)] shadow-[inset_0_0_60px_rgba(16,185,129,0.15)]" />
      {[0.25, 0.5, 0.75, 1].map((s) => (
        <span key={s} className="absolute rounded-full border border-emerald-400/20" style={{ inset: `${(1 - s) * 50}%` }} />
      ))}
      <span className="absolute inset-x-0 top-1/2 h-px bg-emerald-400/15" />
      <span className="absolute inset-y-0 left-1/2 w-px bg-emerald-400/15" />
      <span className="absolute inset-0 overflow-hidden rounded-full"><span className="absolute inset-0 animate-sweep bg-[conic-gradient(from_0deg,rgba(16,185,129,0.45),rgba(16,185,129,0.08)_18%,transparent_30%)]" /></span>
      <span className="absolute left-1/2 top-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-gold-500 shadow-[0_0_12px_#c5a572]" />
      <span className="absolute left-1/2 top-[54%] -translate-x-1/2 text-[10px] font-semibold uppercase tracking-widest text-white/50">
        {lang === "ar" ? "أبوظبي" : "Abu Dhabi"}
      </span>
      {cards.map((c, i) => {
        const angle = (hashAngle(c.entity) * Math.PI) / 180;
        const r = c.severity === "HIGH" ? 0.28 : c.severity === "MEDIUM" ? 0.52 : 0.72;
        const x = 50 + Math.cos(angle) * r * 50;
        const y = 50 + Math.sin(angle) * r * 50;
        const color = SEVERITY_STYLE[c.severity].dot;
        return (
          <motion.div
            key={c.entity}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.3 + i * 0.2, type: "spring", stiffness: 300, damping: 14 }}
            className="absolute -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <span className="absolute left-1/2 top-1/2 size-8 -translate-x-1/2 -translate-y-1/2 animate-ping-slow rounded-full" style={{ backgroundColor: `${color}55` }} />
            <span className="relative block size-3.5 rounded-full ring-2 ring-white" style={{ backgroundColor: color }} />
            <span className="absolute left-1/2 top-5 -translate-x-1/2 whitespace-nowrap rounded bg-black/40 px-1.5 py-0.5 text-[10px] font-semibold text-white">
              {lang === "ar" ? ENTITY_AR[c.entity] ?? c.entity : c.entity}
            </span>
          </motion.div>
        );
      })}
    </div>
  );
}

function AlertCard({ card, index }: { card: AlertCardData; index: number }) {
  const { t, lang } = useLang();
  const [open, setOpen] = useState(index === 0);
  const s = SEVERITY_STYLE[card.severity];
  const areas = card.wave.target_areas ?? [];
  const entity = lang === "ar" ? ENTITY_AR[card.entity] ?? card.entity : card.entity;
  const title = lang === "ar" ? card.titleAr : card.titleEn;
  const post = lang === "ar" ? card.postAr : card.postEn;
  const tips = lang === "ar" ? card.tipsAr : card.tipsEn;
  const sevLabel = card.severity === "HIGH" ? t("high") : card.severity === "MEDIUM" ? t("medium") : t("low");
  const warning: WarningInfo = {
    entityEn: card.entity,
    entityAr: ENTITY_AR[card.entity] ?? card.entity,
    domain: card.wave.domains?.[0] ?? null,
    reasonEn: card.titleEn || "an active scam wave",
    reasonAr: card.titleAr || "موجة احتيال نشطة",
    verdict: `${card.severity} scam wave`,
    riskScore: card.wave.score,
    caseId: null,
    flagsEn: card.tipsEn.slice(0, 3),
    flagsAr: card.tipsAr.slice(0, 3),
    channel: null,
    detectedAt: new Date(card.generatedAt),
  };

  return (
    <motion.article
      layout
      initial={{ opacity: 0, y: 24 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.12, type: "spring", stiffness: 220, damping: 24 }}
      className={`overflow-hidden rounded-3xl bg-surface shadow-sm ring-1 ${s.ring}`}
    >
      <div className="flex items-start gap-3 border-b border-line bg-muted/70 p-4">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-navy-900 text-gold-500 shadow">
          <BellRing className="size-5" />
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2 text-[11px] font-semibold text-ink-soft/70">
            <span>{lang === "ar" ? "شرطة أبوظبي" : "Abu Dhabi Police"}</span>·
            <span>
              {t("broadcastAt")} {new Date(card.generatedAt).toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE", { hour: "2-digit", minute: "2-digit" })}
            </span>
            <span className={`rounded-full px-2 py-0.5 text-[10px] font-bold ${s.pill}`}>
              {t("severity")}: {sevLabel}
            </span>
          </div>
          <h3 className="mt-1 text-base font-bold leading-snug text-ink">{title}</h3>
          <p className="text-xs font-medium text-crimson-700 dark:text-red-300">{entity}</p>
        </div>
      </div>

      <div className="space-y-3 p-4">
        <p className="whitespace-pre-line text-[14px] leading-relaxed text-ink">{post}</p>

        <div>
          <p className="mb-1.5 text-[11px] font-semibold uppercase tracking-wider text-ink-soft/70">{t("targetAreas")}</p>
          <div className="flex flex-wrap gap-1.5">
            {areas.map((a, i) => (
              <motion.span
                key={a}
                initial={{ opacity: 0, scale: 0.8 }}
                animate={{ opacity: 1, scale: 1 }}
                transition={{ delay: 0.2 + i * 0.06 }}
                className="inline-flex items-center gap-1 rounded-full bg-navy-900 px-2.5 py-1 text-[11px] font-semibold text-white dark:bg-navy-700"
              >
                <MapPin className="size-3 text-gold-500" /> {lang === "ar" ? AREA_AR[a] ?? a : a}
              </motion.span>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-3 gap-2 text-center">
          {[
            { icon: Users, value: card.wave.citizen_reports, label: t("reports") },
            { icon: Satellite, value: card.wave.ct_detections, label: t("certificates") },
            { icon: FileWarning, value: card.wave.scans, label: t("scans") },
          ].map(({ icon: Icon, value, label }) => (
            <div key={label} className="rounded-2xl bg-muted p-2.5">
              <Icon className="mx-auto size-4 text-ink-soft" />
              <p className="mt-1 text-lg font-extrabold tabular-nums text-ink">{value}</p>
              <p className="text-[10px] font-medium leading-tight text-ink-soft/70">{label}</p>
            </div>
          ))}
        </div>

        {tips.length > 0 && (
          <div className="rounded-2xl bg-emerald-50 ring-1 ring-emerald-600/15 dark:bg-emerald-500/10 dark:ring-emerald-400/20">
            <button onClick={() => setOpen((o) => !o)} className="flex w-full items-center justify-between p-3 text-sm font-bold text-emerald-800 dark:text-emerald-300">
              <span className="flex items-center gap-2">
                <ShieldCheck className="size-4" /> {t("safetyTips")}
              </span>
              <ChevronDown className={`size-4 transition-transform ${open ? "rotate-180" : ""}`} />
            </button>
            <AnimatePresence initial={false}>
              {open && (
                <motion.ul
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  className="space-y-1.5 overflow-hidden px-3 pb-3 text-[13px] text-emerald-900 dark:text-emerald-100"
                >
                  {tips.map((tip) => (
                    <li key={tip} className="flex gap-2">
                      <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-emerald-600" />
                      {tip}
                    </li>
                  ))}
                </motion.ul>
              )}
            </AnimatePresence>
          </div>
        )}

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap gap-1.5">
            {card.hashtags.map((h) => (
              <span key={h} className="inline-flex items-center gap-0.5 text-[12px] font-semibold text-[#1a73e8] dark:text-[#8ab4f8]">
                <Hash className="size-3" />
                {h.replace(/^#/, "")}
              </span>
            ))}
          </div>
          <WarnOnXButton warning={warning} presetDrafts={{ en: card.xPostEn, ar: card.xPostAr }} />
        </div>
      </div>
    </motion.article>
  );
}

export function AwarenessRadar() {
  const { t, lang } = useLang();
  const [cards, setCards] = useState<AlertCardData[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [updated, setUpdated] = useState<Date | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const main = await getAwareness();
      const others = (main.other_waves ?? []).slice(0, 3);
      const extra = await Promise.allSettled(others.map((w) => getAwareness({ entity: w.entity, useLlm: false })));
      const list = [main, ...extra.flatMap((r) => (r.status === "fulfilled" ? [r.value] : []))]
        .map(toCard)
        .filter((c): c is AlertCardData => c !== null);
      const unique = list.filter((c, i) => list.findIndex((x) => x.entity === c.entity) === i);
      setCards(unique);
      setUpdated(new Date());
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const first = window.setTimeout(() => void load(), 0);
    const id = window.setInterval(() => void load(), 45_000);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(id);
    };
  }, [load]);

  return (
    <div className="grid gap-6 lg:grid-cols-[minmax(0,380px)_minmax(0,1fr)]">
      <div className="space-y-4">
        <div className="overflow-hidden rounded-3xl bg-navy-900 p-5 text-white shadow-xl dark:bg-navy-950 dark:ring-1 dark:ring-white/10">
          <div className="flex items-center justify-between">
            <p className="flex items-center gap-2 text-sm font-bold">
              <Radio className="size-4 text-emerald-400" /> {t("activeWaves")}
            </p>
            <button
              onClick={() => void load()}
              disabled={loading}
              className="inline-flex items-center gap-1.5 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold hover:bg-white/20 disabled:opacity-60"
            >
              <RefreshCw className={`size-3.5 ${loading ? "animate-spin" : ""}`} /> {t("refresh")}
            </button>
          </div>
          <div className="mt-4">
            <Radar cards={cards} />
          </div>
          <div className="mt-4 flex items-center justify-between text-xs text-white/60">
            <span className="flex items-center gap-2">
              <span className="relative flex size-2">
                <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
                <span className="relative inline-flex size-2 rounded-full bg-emerald-400" />
              </span>
              {cards.length} · {t("activeWaves")}
            </span>
            {updated && (
              <span>
                {t("lastUpdated")} {updated.toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
            )}
          </div>
        </div>
        <LiveCrowdShield />
        <div className="flex gap-3 rounded-3xl bg-surface p-4 text-sm text-ink-soft ring-1 ring-line">
          <Megaphone className="size-5 shrink-0 text-gold-500" />
          <p>{t("radarIntro")}</p>
        </div>
      </div>

      <div className="space-y-4">
        {error && (
          <div className="rounded-3xl bg-crimson-50 p-5 text-sm font-semibold text-crimson-700 ring-1 ring-crimson-600/20 dark:bg-crimson-600/15 dark:text-red-300 dark:ring-crimson-600/40">
            {t("backendOffline")} <span className="block font-normal text-crimson-700/80 dark:text-red-300/80">{error}</span>
          </div>
        )}
        {loading && cards.length === 0 && !error && (
          <div className="space-y-4">
            {[0, 1].map((i) => (
              <div key={i} className="h-56 animate-pulse rounded-3xl bg-surface ring-1 ring-line" />
            ))}
          </div>
        )}
        {!loading && !error && cards.length === 0 && (
          <div className="rounded-3xl bg-surface p-8 text-center text-ink-soft ring-1 ring-line">
            <ShieldCheck className="mx-auto size-10 text-emerald-600" />
            <p className="mt-3 font-semibold">{t("noWaves")}</p>
          </div>
        )}
        {cards.map((c, i) => (
          <AlertCard key={`${c.entity}-${lang}`} card={c} index={i} />
        ))}
      </div>
    </div>
  );
}
