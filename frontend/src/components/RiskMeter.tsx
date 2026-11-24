"use client";

import type { VerdictLabel } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";

/**
 * Three-zone meter (DESIGN.md "Meter"): Safe 0-29 | Suspicious 30-64 | Scam 65-100, zones split by 2px of
 * surface, a 2px ink marker at the score, the zone words underneath in label-caps. Mirrors in Arabic
 * (logical start). The marker glides with a short transition (none with reduced motion, see globals.css).
 */
const ZONES: { from: number; to: number; fill: string; key: DictKey }[] = [
  { from: 0, to: 30, fill: "bg-safe", key: "meterSafe" },
  { from: 30, to: 65, fill: "bg-suspicious", key: "meterSuspicious" },
  { from: 65, to: 100, fill: "bg-scam", key: "meterScam" },
];

export function RiskMeter({ score, className = "" }: { score: number; className?: string }) {
  const { t } = useLang();
  const value = Math.max(0, Math.min(100, Math.round(score)));
  return (
    <div className={className}>
      <div
        role="meter"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={value}
        aria-label={t("meterLabel").replace("{n}", String(value))}
        className="relative h-2.5"
      >
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
