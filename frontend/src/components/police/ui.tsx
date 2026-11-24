"use client";

import type { ReactNode } from "react";
import { P } from "@/lib/police";

export type Lang = "en" | "ar";
export type L = (k: keyof typeof P) => string;

export function timeAgo(ts: string, lang: Lang): string {
  const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
  const rtf = new Intl.RelativeTimeFormat(lang === "ar" ? "ar" : "en", { numeric: "auto" });
  if (s < 60) return rtf.format(-Math.round(s), "second");
  if (s < 3600) return rtf.format(-Math.round(s / 60), "minute");
  if (s < 86400) return rtf.format(-Math.round(s / 3600), "hour");
  return rtf.format(-Math.round(s / 86400), "day");
}

/** Score badge colours by verdict band: crimson = scam, amber = suspicious, neutral below. */
export function riskTone(score: number) {
  return score >= 65 ? "chip-scam" : score >= 30 ? "chip-suspicious" : "bg-muted text-ink";
}

/** "36 h" / "4 d" for an age in hours. */
export function fmtHours(h: number | null | undefined, L: L): string {
  if (h === null || h === undefined || Number.isNaN(h)) return "—";
  if (h < 48) return `${h < 10 ? h.toFixed(1) : Math.round(h)} ${L("hoursShort")}`;
  return `${Math.round(h / 24)} ${L("daysShort")}`;
}

export function defangUrl(u: string | null | undefined): string {
  return (u ?? "").replace(/^http/i, "hxxp").replace(/\./g, "[.]");
}

/** Hunter sources are neutral tags (the word carries the meaning, not a colour). */
export const SOURCE_STYLE: Record<string, { key: keyof typeof P; tone: string }> = {
  lookalike_sweep: { key: "srcLookalike", tone: "bg-muted text-ink ring-line" },
  nrd: { key: "srcNrd", tone: "bg-muted text-ink ring-line" },
  ct: { key: "srcCt", tone: "bg-muted text-ink ring-line" },
  crtsh: { key: "srcCrtsh", tone: "bg-muted text-ink ring-line" },
};

export function verdictLabel(verdict: string | null | undefined, L: L): string {
  if (verdict === "HIGH-RISK SCAM") return L("verdictHigh");
  if (verdict === "SUSPICIOUS") return L("verdictSuspicious");
  if (verdict === "SAFE") return L("verdictSafe");
  return verdict ?? "—";
}

export function Card({ title, icon, children, right, className = "" }: { title: string; icon: ReactNode; children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <section className={`card p-4 sm:p-5 ${className}`}>
      <div className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="text-ink-soft">{icon}</span>
        <h2 className="label-caps">{title}</h2>
        <div className="ms-auto">{right}</div>
      </div>
      {children}
    </section>
  );
}
