"use client";

import { BrainCircuit } from "lucide-react";
import { useLang } from "@/lib/i18n";
import { P, type ModelMetrics } from "@/lib/police";
import { Card, type L } from "./ui";

/** 0.973 -> "97.3%" (a value above 1 is taken as already a percentage). */
function pct(v: number | undefined, digits = 1): string | null {
  if (typeof v !== "number" || Number.isNaN(v)) return null;
  const p = v <= 1 ? v * 100 : v;
  return `${p.toFixed(p > 0 && p < 1 ? 2 : digits)}%`;
}

/** Sources of the false-alarm suite that are official / bank / government pages. */
const OFFICIAL_SOURCES = ["harvest_uae_official", "harvest_brand_official", "fp_extra_bank_gov"];
const MAX_DATASETS = 8;

const num = (v: number | undefined) => (typeof v === "number" ? v.toLocaleString("en-US") : null);

function Stat({ label, value, tone }: { label: string; value: string | null; tone: string }) {
  if (value === null) return null;
  return (
    <div className="border-t border-line pt-2">
      <p className="label-caps">{label}</p>
      <p className={`text-2xl font-semibold tabular-nums ${tone}`} dir="ltr">{value}</p>
    </div>
  );
}

export function ModelCard({ metrics, className = "" }: { metrics: ModelMetrics; className?: string }) {
  const { lang } = useLang();
  const L: L = (k) => P[k][lang];
  const m = metrics.model ?? {};
  const h = metrics.holdout ?? {};
  const fp = metrics.fp_suite;
  const live = metrics.live?.no_feeds?.warn_30;
  const official = Object.entries(fp?.by_source ?? {}).filter(([k]) => OFFICIAL_SOURCES.includes(k));
  const officialRows = official.reduce((n, [, v]) => n + (v.rows ?? 0), 0);
  const officialAlarms = official.reduce((n, [, v]) => n + (v.warn_30 ?? 0), 0);
  const allSets = (metrics.datasets ?? []).filter((d) => d.name);
  const datasets = allSets.filter((d) => !d.name?.includes("+evasion")).slice(0, MAX_DATASETS);
  const trained = m.trained_at ? m.trained_at.slice(0, 10) : null;

  return (
    <Card className={className} title={L("model")} icon={<BrainCircuit className="size-4" />}>
      {(m.name || m.version) && (
        <p className="font-mono text-sm font-bold text-ink" dir="ltr">
          {[m.name, m.version && `v${m.version}`].filter(Boolean).join(" · ")}
        </p>
      )}
      <p className="mt-0.5 text-xs text-ink-soft">
        {[trained && `${L("trained")}: ${trained}`, typeof m.training_rows === "number" && `${L("trainingRows")}: ${num(m.training_rows)}`]
          .filter(Boolean)
          .join(" · ")}
      </p>

      {live && (
        <>
          <p className="mt-3 text-[11px] font-bold uppercase tracking-wider text-ink-soft">
            {L("liveSystem")}
            {typeof metrics.live?.rows === "number" && <span className="text-ink-soft" dir="ltr"> · {num(metrics.live.rows)} {L("rows")}</span>}
            <span className="normal-case text-ink-soft"> · {L("liveNote")}</span>
          </p>
          <div className="mt-1.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label={L("precision")} value={pct(live.precision)} tone="text-ink" />
            <Stat label={L("recall")} value={pct(live.recall)} tone="text-ink" />
            <Stat label={L("f1")} value={pct(live.f1)} tone="text-ink" />
            <Stat label={L("fpr")} value={pct(live.fpr, 2)} tone="text-ink" />
          </div>
        </>
      )}

      {(h.precision !== undefined || h.recall !== undefined || h.f1 !== undefined || h.fpr !== undefined) && (
        <>
          <p className="mt-3 text-[11px] font-bold uppercase tracking-wider text-ink-soft">
            {L("addressOnly")} · {L("holdout")}
            {h.name && <span className="normal-case text-ink-soft" dir="ltr"> · {h.name}</span>}
            {typeof h.rows === "number" && <span className="text-ink-soft" dir="ltr"> · {num(h.rows)} {L("rows")}</span>}
            {typeof h.threshold === "number" && <span className="text-ink-soft" dir="ltr"> · {L("threshold")} {h.threshold.toFixed(3)}</span>}
          </p>
          <div className="mt-1.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label={L("precision")} value={pct(h.precision)} tone="text-ink" />
            <Stat label={L("recall")} value={pct(h.recall)} tone="text-ink" />
            <Stat label={L("f1")} value={pct(h.f1)} tone="text-ink" />
            <Stat label={L("fpr")} value={pct(h.fpr, 2)} tone="text-ink" />
          </div>
        </>
      )}

      {fp && typeof fp.rows === "number" && (
        <p className="mt-3 border-t border-line pt-3 text-xs text-safe-ink">
          {L("fpSuite")}: <b className="tabular-nums" dir="ltr">{num(fp.false_positives ?? 0)}</b> {L("falseAlarms")} /{" "}
          <b className="tabular-nums" dir="ltr">{num(fp.rows)}</b>
          {officialRows > 0 && (
            <>
              <br />
              {L("officialSuite")}: <b className="tabular-nums" dir="ltr">{num(officialAlarms)}</b> {L("falseAlarms")} /{" "}
              <b className="tabular-nums" dir="ltr">{num(officialRows)}</b>
            </>
          )}
        </p>
      )}

      {datasets.length > 0 && (
        <div className="mt-3">
          <p className="text-[11px] font-bold uppercase tracking-wider text-ink-soft">{L("datasets")}</p>
          <ul className="mt-1 flex flex-wrap gap-1.5" dir="ltr">
            {datasets.map((d) => (
              <li key={d.name} className="rounded-full bg-muted px-2 py-0.5 text-[11px] text-ink-soft ring-1 ring-line">
                {d.name}
                {typeof d.rows === "number" && <span className="text-ink-soft"> · {num(d.rows)}</span>}
              </li>
            ))}
            {allSets.length > datasets.length && (
              <li className="px-1 py-0.5 text-[11px] text-ink-soft">
                +{allSets.length - datasets.length} {L("more")}
              </li>
            )}
          </ul>
        </div>
      )}
    </Card>
  );
}
