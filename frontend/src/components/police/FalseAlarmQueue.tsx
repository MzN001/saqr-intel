"use client";

import { Check, Flag, Loader2, X } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useLang } from "@/lib/i18n";
import { P, getFalseAlarms, resolveFalseAlarm, type FalseAlarm, type FalseAlarmList } from "@/lib/police";
import { Card, riskTone, timeAgo, verdictLabel, type L } from "./ui";

const POLL_MS = 15_000;

function shownLabel(a: FalseAlarm, lang: "en" | "ar"): string {
  if (a.kind === "email") return lang === "ar" ? "رسالة بريد" : "Email message";
  if (a.kind === "message") return lang === "ar" ? "رسالة نصية" : "Text message";
  if (a.label === "maps listing") return lang === "ar" ? "إدراج خرائط" : "Maps listing";
  return a.label.replace(/\./g, "[.]");
}

/** Citizen "Report a false alarm" queue: polls every 15 s while the tab is visible. */
export function FalseAlarmQueue({ className = "" }: { className?: string }) {
  const { lang } = useLang();
  const L: L = (k) => P[k][lang];
  const [data, setData] = useState<FalseAlarmList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setData(await getFalseAlarms());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    const tick = () => {
      if (document.visibilityState === "visible") void load();
    };
    const first = window.setTimeout(() => void load(), 0);
    const poll = window.setInterval(tick, POLL_MS);
    document.addEventListener("visibilitychange", tick);
    return () => {
      window.clearTimeout(first);
      window.clearInterval(poll);
      document.removeEventListener("visibilitychange", tick);
    };
  }, [load]);

  const decide = async (a: FalseAlarm, status: "confirmed" | "dismissed") => {
    setBusy(a.id);
    try {
      const updated = await resolveFalseAlarm(a.id, status);
      setData((d) => {
        if (!d) return d;
        const counts = { ...d.counts, [a.status]: Math.max(0, d.counts[a.status] - 1), [status]: d.counts[status] + 1 };
        return { items: d.items.map((i) => (i.id === a.id ? { ...i, ...updated } : i)), counts };
      });
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };

  const items = data?.items ?? [];
  const open = data?.counts.open ?? 0;

  return (
    <Card
      className={className}
      title={L("faQueue")}
      icon={<Flag className="size-4" />}
      right={
        <span className="text-xs text-ink-soft tabular-nums">
          <b className="font-bold text-ink">{open}</b> {L("faOpen")}
        </span>
      }
    >
      <p className="mb-2 text-xs leading-relaxed text-ink-soft">{L("faHint")}</p>
      {error && (
        <p className="mb-2 text-xs font-semibold text-ink" role="alert">
          {L("faLoadFailed")}: {error}
        </p>
      )}
      {!data && !error && (
        <p className="flex items-center gap-2 p-3 text-sm text-ink-soft">
          <Loader2 className="size-4 animate-spin" /> {L("loading")}
        </p>
      )}
      <ul className="max-h-[360px] overflow-y-auto pe-1">
        {data && items.length === 0 && <li className="p-3 text-sm text-ink-soft">{L("faEmpty")}</li>}
        {items.map((a) => (
          <li key={a.id} className="border-t border-line px-1 py-3 first:border-0">
            <div className="flex flex-wrap items-center gap-2">
              <span className="min-w-0 flex-1 truncate font-mono text-[13px] font-bold text-ink" dir="ltr">
                {shownLabel(a, lang)}
              </span>
              <span className={`shrink-0 rounded-full px-2 py-0.5 text-xs font-bold tabular-nums ${riskTone(a.score)}`} dir="ltr">
                {a.score}
              </span>
            </div>
            <p className="mt-0.5 flex flex-wrap gap-x-2 text-xs text-ink-soft">
              <span>{verdictLabel(a.verdict, L)}</span>
              <span>·</span>
              <span>{timeAgo(a.last_reported_at, lang)}</span>
              {a.reports > 1 && (
                <>
                  <span>·</span>
                  <span>
                    <b className="font-semibold text-ink tabular-nums">{a.reports}</b> {L("faReports")}
                  </span>
                </>
              )}
            </p>
            <p className={`mt-1 text-sm leading-snug ${a.note ? "text-ink" : "text-ink-soft"}`} dir="auto">
              {a.note || L("faNoNote")}
            </p>
            <div className="mt-2 flex flex-wrap items-center gap-2">
              {a.status === "open" ? (
                <>
                  <button
                    type="button"
                    disabled={busy === a.id}
                    onClick={() => void decide(a, "confirmed")}
                    className="press btn-secondary"
                  >
                    {busy === a.id ? <Loader2 className="size-3.5 animate-spin" /> : <Check className="size-3.5" />} {L("faConfirm")}
                  </button>
                  <button
                    type="button"
                    disabled={busy === a.id}
                    onClick={() => void decide(a, "dismissed")}
                    className="press btn-secondary"
                  >
                    <X className="size-3.5" /> {L("faDismiss")}
                  </button>
                </>
              ) : (
                <span
                  className={`inline-block -rotate-3 rounded-md border-2 border-current px-2 py-1 text-[11px] font-extrabold uppercase leading-none tracking-[0.12em] ${
                    a.status === "confirmed" ? "text-suspicious-ink" : "text-ink-soft"
                  }`}
                >
                  {a.status === "confirmed" ? L("faConfirmed") : L("faDismissed")}
                </span>
              )}
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
