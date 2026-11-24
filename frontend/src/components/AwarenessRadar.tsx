"use client";

import { motion } from "framer-motion";
import { Info, RefreshCw, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { getAwareness, type AwarenessAlert, type AwarenessWave } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { Disclosure } from "./Disclosure";
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

/** Severity: HIGH is a scam wave, MEDIUM suspicious, LOW neutral (a quiet wave is not "safe"). */
const SEVERITY_STYLE = {
  HIGH: { chip: "chip chip-scam", dot: "bg-scam" },
  MEDIUM: { chip: "chip chip-suspicious", dot: "bg-suspicious" },
  LOW: { chip: "chip", dot: "bg-ink-soft" },
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

/** Quiet radar on the dot-matrix ground: rings in hairline, waves as verdict-coloured dots. */
function Radar({ cards }: { cards: AlertCardData[] }) {
  const { lang } = useLang();
  return (
    <div className="relative mx-auto aspect-square w-full max-w-[300px]" aria-hidden>
      <div className="night-grid absolute inset-0 rounded-full border border-line bg-muted" />
      {[0.25, 0.5, 0.75].map((s) => (
        <span key={s} className="absolute rounded-full border border-line" style={{ inset: `${(1 - s) * 50}%` }} />
      ))}
      <span className="absolute inset-0 overflow-hidden rounded-full">
        <span className="absolute inset-0 animate-sweep bg-[conic-gradient(from_0deg,color-mix(in_oklab,var(--color-ink)_14%,transparent),transparent_26%)]" />
      </span>
      <span className="absolute left-1/2 top-1/2 size-2.5 -translate-x-1/2 -translate-y-1/2 rounded-full bg-ink" />
      <span className="absolute left-1/2 top-[54%] -translate-x-1/2 text-[11px] font-semibold uppercase tracking-[0.12em] text-ink-soft rtl:tracking-normal">
        {lang === "ar" ? "أبوظبي" : "Abu Dhabi"}
      </span>
      {cards.map((c, i) => {
        const angle = (hashAngle(c.entity) * Math.PI) / 180;
        const r = c.severity === "HIGH" ? 0.28 : c.severity === "MEDIUM" ? 0.52 : 0.72;
        const x = 50 + Math.cos(angle) * r * 50;
        const y = 50 + Math.sin(angle) * r * 50;
        return (
          <motion.div
            key={c.entity}
            initial={{ scale: 0, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ delay: 0.2 + i * 0.12, duration: 0.2 }}
            className="absolute -translate-x-1/2 -translate-y-1/2"
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <span className={`relative block size-3.5 rounded-full ring-2 ring-surface ${SEVERITY_STYLE[c.severity].dot}`} />
            <span className="absolute left-1/2 top-5 max-w-[110px] -translate-x-1/2 truncate whitespace-nowrap rounded bg-surface px-1.5 py-0.5 text-[11px] font-semibold text-ink shadow-card">
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
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: index * 0.08, duration: 0.2, ease: [0.16, 1, 0.3, 1] }}
      className="card p-5"
      data-testid="awareness-card"
    >
      <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-ink-soft">
        <span className="font-semibold text-ink">{lang === "ar" ? "شرطة أبوظبي" : "Abu Dhabi Police"}</span>
        <span aria-hidden>·</span>
        <span>
          {t("broadcastAt")}{" "}
          <span className="tabular-nums">
            {new Date(card.generatedAt).toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE", { hour: "2-digit", minute: "2-digit" })}
          </span>
        </span>
        <span className={`${s.chip} ms-auto`}>
          {t("severity")}: {sevLabel}
        </span>
      </p>
      <h3 className="mt-2 text-[17px] font-semibold leading-snug text-ink">{title}</h3>
      <p className="text-[14px] font-medium text-ink-soft">{entity}</p>

      <p className="mt-3 whitespace-pre-line text-[15px] leading-relaxed text-ink">{post}</p>

      <dl className="mt-4 grid grid-cols-3 divide-x divide-line rounded-control bg-muted py-2.5 text-center rtl:divide-x-reverse">
        {[
          { value: card.wave.citizen_reports, label: t("reports") },
          { value: card.wave.ct_detections, label: t("certificates") },
          { value: card.wave.scans, label: t("scans") },
        ].map(({ value, label }) => (
          <div key={label} className="flex flex-col-reverse px-1">
            <dt className="text-[12px] leading-tight text-ink-soft">{label}</dt>
            <dd className="text-[19px] font-bold tabular-nums text-ink">{value}</dd>
          </div>
        ))}
      </dl>

      {(areas.length > 0 || tips.length > 0) && (
        <Disclosure summary={t("details")} className="mt-4">
          {areas.length > 0 && (
            <>
              <p className="label-caps">{t("targetAreas")}</p>
              <p className="mt-1 text-[14px] text-ink">{areas.map((a) => (lang === "ar" ? AREA_AR[a] ?? a : a)).join(" · ")}</p>
            </>
          )}
          {tips.length > 0 && (
            <>
              <p className="label-caps mt-3">{t("safetyTips")}</p>
              <ul className="mt-1 space-y-1.5 text-[14px] text-ink">
                {tips.map((tip) => (
                  <li key={tip} className="flex gap-2">
                    <span className="mt-2 size-1.5 shrink-0 rounded-full bg-ink-soft" aria-hidden />
                    {tip}
                  </li>
                ))}
              </ul>
            </>
          )}
          {card.hashtags.length > 0 && (
            <p className="mt-3 text-[13px] text-ink-soft" dir="auto">
              {card.hashtags.map((h) => `#${h.replace(/^#/, "")}`).join(" ")}
            </p>
          )}
        </Disclosure>
      )}

      <div className="mt-3 flex justify-end">
        <WarnOnXButton warning={warning} presetDrafts={{ en: card.xPostEn, ar: card.xPostAr }} />
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
    <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
      <div className="space-y-4">
        <section className="card overflow-hidden p-5" aria-labelledby="waves-title" data-testid="awareness-radar">
          <div className="flex items-center justify-between gap-3">
            <h2 id="waves-title" className="text-[17px] font-semibold text-ink">
              {t("activeWaves")} <span className="tabular-nums text-ink-soft">· {cards.length}</span>
            </h2>
            <button type="button" onClick={() => void load()} disabled={loading} className="btn-secondary min-h-10 px-3 text-[13px]">
              <RefreshCw className={`size-3.5 ${loading ? "animate-spin" : ""}`} aria-hidden /> {t("refresh")}
            </button>
          </div>
          <div className="mt-4">
            <Radar cards={cards} />
          </div>
          {updated && (
            <p className="mt-3 text-[13px] text-ink-soft">
              {t("lastUpdated")}{" "}
              <span className="tabular-nums">
                {updated.toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE", { hour: "2-digit", minute: "2-digit", second: "2-digit" })}
              </span>
            </p>
          )}
        </section>
        <LiveCrowdShield />
      </div>

      <div className="space-y-4">
        {error && (
          <div className="card p-5 text-[15px] text-ink" role="alert">
            <p className="flex items-center gap-2 font-semibold">
              <Info className="size-4 shrink-0 text-ink-soft" aria-hidden /> {t("backendOffline")}
            </p>
            <p className="mt-1 text-[13px] text-ink-soft">{error}</p>
          </div>
        )}
        {loading && cards.length === 0 && !error && (
          <div className="space-y-4">
            {[0, 1].map((i) => (
              <div key={i} className="h-56 animate-pulse rounded-card border border-line bg-surface" />
            ))}
          </div>
        )}
        {!loading && !error && cards.length === 0 && (
          <div className="card p-8 text-center text-ink-soft">
            <ShieldCheck className="mx-auto size-8" aria-hidden />
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
