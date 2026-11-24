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

const num = (v: number | undefined) => (typeof v === "number" ? v.toLocaleString("en-US") : null);

function Stat({ label, value, tone }: { label: string; value: string | null; tone: string }) {
  if (value === null) return null;
  return (
    <div className="rounded-2xl bg-white/5 p-2.5 ring-1 ring-white/10">
      <p className="text-[10px] font-bold uppercase tracking-wider text-white/55">{label}</p>
      <p className={`text-xl font-black tabular-nums ${tone}`} dir="ltr">{value}</p>
    </div>
  );
}

export function ModelCard({ metrics, className = "" }: { metrics: ModelMetrics; className?: string }) {
  const { lang } = useLang();
  const L: L = (k) => P[k][lang];
  const m = metrics.model ?? {};
  const h = metrics.holdout ?? {};
  const fp = metrics.fp_suite;
  const datasets = (metrics.datasets ?? []).filter((d) => d.name);
  const trained = m.trained_at ? m.trained_at.slice(0, 10) : null;

  return (
    <Card className={className} title={L("model")} icon={<BrainCircuit className="size-4" />}>
      {(m.name || m.version) && (
        <p className="font-mono text-sm font-bold text-white" dir="ltr">
          {[m.name, m.version && `v${m.version}`].filter(Boolean).join(" · ")}
        </p>
      )}
      <p className="mt-0.5 text-xs text-white/55">
        {[trained && `${L("trained")}: ${trained}`, typeof m.training_rows === "number" && `${L("trainingRows")}: ${num(m.training_rows)}`]
          .filter(Boolean)
          .join(" · ")}
      </p>

      {(h.precision !== undefined || h.recall !== undefined || h.f1 !== undefined || h.fpr !== undefined) && (
        <>
          <p className="mt-3 text-[11px] font-bold uppercase tracking-wider text-white/60">
            {L("holdout")}
            {h.name && <span className="normal-case text-white/45" dir="ltr"> · {h.name}</span>}
            {typeof h.rows === "number" && <span className="text-white/45" dir="ltr"> · {num(h.rows)} {L("rows")}</span>}
            {typeof h.threshold === "number" && <span className="text-white/45" dir="ltr"> · {L("threshold")} {h.threshold}</span>}
          </p>
          <div className="mt-1.5 grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat label={L("precision")} value={pct(h.precision)} tone="text-emerald-300" />
            <Stat label={L("recall")} value={pct(h.recall)} tone="text-sky-300" />
            <Stat label={L("f1")} value={pct(h.f1)} tone="text-white" />
            <Stat label={L("fpr")} value={pct(h.fpr, 2)} tone="text-amber-300" />
          </div>
        </>
      )}

      {fp && typeof fp.rows === "number" && (
        <p className="mt-3 rounded-xl bg-emerald-500/10 px-3 py-2 text-xs text-emerald-100 ring-1 ring-emerald-400/25">
          {L("fpSuite")}: <b className="tabular-nums" dir="ltr">{num(fp.false_positives ?? 0)}</b> {L("falseAlarms")} /{" "}
          <b className="tabular-nums" dir="ltr">{num(fp.rows)}</b>
        </p>
      )}

      {datasets.length > 0 && (
        <div className="mt-3">
          <p className="text-[11px] font-bold uppercase tracking-wider text-white/60">{L("datasets")}</p>
          <ul className="mt-1 flex flex-wrap gap-1.5" dir="ltr">
            {datasets.map((d) => (
              <li key={d.name} className="rounded-full bg-white/5 px-2 py-0.5 text-[11px] text-white/75 ring-1 ring-white/10">
                {d.name}
                {typeof d.rows === "number" && <span className="text-white/45"> · {num(d.rows)}</span>}
              </li>
            ))}
          </ul>
        </div>
      )}
    </Card>
  );
}
