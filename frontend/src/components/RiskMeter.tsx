"use client";

import type { VerdictLabel } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";

/**
 * Risk meter, three variants (DESIGN.md "Meter"):
 *  - "zones" (default; full report / block page `VerdictScreen`): Safe 0-29 | Suspicious 30-64 | Scam 65-100,
 *    zones split by 2px of surface, a 2px ink marker at the score, the zone words underneath in label-caps.
 *  - "line" (desktop verdict card `VerdictCard`): ONE thin line, pale track, filled to the score in the verdict
 *    colour, SAFE / SUSPICIOUS / SCAM tracked micro-labels underneath (start / centre / end).
 *  - "knob" (phone result `MobileResult`): the three-colour bar with a round white knob at the score.
 * All mirror in Arabic (logical start): the fill grows from the right and the labels swap sides.
 */
const ZONES: { from: number; to: number; fill: string; key: DictKey }[] = [
  { from: 0, to: 30, fill: "bg-safe", key: "meterSafe" },
  { from: 30, to: 65, fill: "bg-suspicious", key: "meterSuspicious" },
  { from: 65, to: 100, fill: "bg-scam", key: "meterScam" },
];

export type MeterVariant = "zones" | "line" | "knob";

/** Fill colour of the single-line meter per verdict: crimson / amber / brand green. */
const LINE_FILL: Record<Tone, string> = {
  scam: "bg-scam-mark",
  suspicious: "bg-suspicious",
  safe: "bg-brand",
};

export function RiskMeter({
  score,
  tone,
  variant = "zones",
  className = "",
}: {
  score: number;
  /** Needed by the "line" variant (fill colour); defaults to the tone of the score. */
  tone?: Tone;
  variant?: MeterVariant;
  className?: string;
}) {
  const { t } = useLang();
  const value = Math.max(0, Math.min(100, Math.round(score)));
  const meterProps = {
    role: "meter",
    "aria-valuemin": 0,
    "aria-valuemax": 100,
    "aria-valuenow": value,
    "aria-label": t("meterLabel").replace("{n}", String(value)),
  } as const;

  if (variant === "line") {
    const fill = LINE_FILL[tone ?? (value >= 65 ? "scam" : value >= 30 ? "suspicious" : "safe")];
    return (
      <div className={className}>
        <div {...meterProps} className="relative h-1.5 overflow-hidden rounded-full bg-meter-track">
          <span
            aria-hidden
            className={`absolute inset-y-0 start-0 rounded-full ${fill} transition-[width] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)]`}
            style={{ width: `${value}%` }}
          />
        </div>
        <div className="mt-2 grid grid-cols-3" aria-hidden>
          {ZONES.map((z, i) => (
            <span
              key={z.key}
              className={`text-[11px] font-bold uppercase leading-none tracking-[0.12em] text-ink-soft rtl:tracking-normal ${
                i === 0 ? "text-start" : i === 1 ? "text-center" : "text-end"
              }`}
            >
              {t(z.key)}
            </span>
          ))}
        </div>
      </div>
    );
  }

  if (variant === "knob") {
    return (
      <div className={className}>
        <div {...meterProps} className="relative h-1.5">
          <div className="flex h-full overflow-hidden rounded-full opacity-90">
            <span className="h-full w-[33%] bg-safe" />
            <span className="h-full w-[33%] bg-suspicious" />
            <span className="h-full w-[34%] bg-scam" />
          </div>
          <span
            aria-hidden
            className="absolute top-1/2 size-3.5 -translate-x-1/2 -translate-y-1/2 rounded-full border-[3px] border-ink bg-surface transition-[inset-inline-start] duration-500 ease-[cubic-bezier(0.16,1,0.3,1)] rtl:translate-x-1/2"
            style={{ insetInlineStart: `${value}%` }}
          />
        </div>
        <div className="mt-[7px] flex justify-between text-[11px] font-semibold text-ink-soft" aria-hidden>
          {ZONES.map((z) => (
            <span key={z.key}>{t(z.key)}</span>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className={className}>
      <div {...meterProps} className="relative h-2.5">
        <div className="flex h-full gap-[2px] overflow-hidden rounded-full">
          {ZONES.map((z) => (
            <span key={z.key} className={`h-full ${z.fill}`} style={{ width: `${z.to - z.from}%` }} />
          ))}
        </div>
        <span
          aria-hidden
          className="absolute -top-1 -bottom-1 w-[3px] -translate-x-1/2 rounded-full bg-ink ring-2 ring-surface transition-[inset-inline-start] duration-300 ease-[cubic-bezier(0.16,1,0.3,1)] rtl:translate-x-1/2"
          style={{ insetInlineStart: `${value}%` }}
        />
      </div>
      <div className="mt-2 flex justify-between" aria-hidden>
        {ZONES.map((z) => (
          <span key={z.key} className="label-caps">
            {t(z.key)}
          </span>
        ))}
      </div>
    </div>
  );
}

export type Tone = "scam" | "suspicious" | "safe";

export function toneOf(verdict: VerdictLabel | string): Tone {
  return verdict === "HIGH-RISK SCAM" ? "scam" : verdict === "SUSPICIOUS" ? "suspicious" : "safe";
}

/** Text colour of the verdict word, and its soft chip. Never used for anything else. */
export const TONE_TEXT: Record<Tone, string> = {
  scam: "text-scam-ink",
  suspicious: "text-suspicious-ink",
  safe: "text-safe-ink",
};
export const TONE_CHIP: Record<Tone, string> = {
  scam: "chip chip-scam",
  suspicious: "chip chip-suspicious",
  safe: "chip chip-safe",
};
