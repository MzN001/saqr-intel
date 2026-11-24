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

export function riskTone(score: number) {
  return score >= 65 ? "bg-scam text-white" : score >= 30 ? "bg-gold-500 text-navy-950" : "bg-muted text-ink";
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

export const SOURCE_STYLE: Record<string, { key: keyof typeof P; tone: string }> = {
  lookalike_sweep: { key: "srcLookalike", tone: "bg-violet-500/15 text-violet-700 dark:text-violet-300 ring-violet-400/30" },
  nrd: { key: "srcNrd", tone: "bg-amber-500/15 text-amber-700 dark:text-amber-300 ring-amber-400/30" },
  ct: { key: "srcCt", tone: "bg-sky-500/15 text-sky-700 dark:text-sky-300 ring-sky-400/30" },
  crtsh: { key: "srcCrtsh", tone: "bg-teal-500/15 text-teal-700 dark:text-teal-300 ring-teal-400/30" },
};

export function verdictLabel(verdict: string | null | undefined, L: L): string {
  if (verdict === "HIGH-RISK SCAM") return L("verdictHigh");
  if (verdict === "SUSPICIOUS") return L("verdictSuspicious");
  if (verdict === "SAFE") return L("verdictSafe");
  return verdict ?? "—";
}

export function Card({ title, icon, children, right, className = "" }: { title: string; icon: ReactNode; children: ReactNode; right?: ReactNode; className?: string }) {
  return (
    <section className={`rounded-[20px] border border-line bg-surface p-4 ${className}`}>
      <div className="mb-3 flex flex-wrap items-center gap-x-2 gap-y-1">
        <span className="text-ink-soft">{icon}</span>
        <h2 className="text-[11px] font-bold uppercase tracking-[0.14em] text-ink-soft">{title}</h2>
        <div className="ms-auto">{right}</div>
      </div>
      {children}
    </section>
  );
}
