"use client";

import { AnimatePresence, motion } from "framer-motion";
import { BadgeCheck, X } from "lucide-react";
import { useEffect, useState } from "react";
import { getWsUrl } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { getLatestWarning, type OfficialWarning } from "@/lib/police";

const DISMISSED_KEY = "saqr-dismissed-warning";

function readDismissed(): string | null {
  try {
    return window.sessionStorage.getItem(DISMISSED_KEY);
  } catch {
    return null;
  }
}

/**
 * "Abu Dhabi Police Verified Alert": an official warning an officer broadcast from /police.
 * Arrives instantly over /ws/live (`police.warning`) and is also polled every 20 s, so it still
 * shows up if the socket was down (Render free tier waking up).
 */
export function OfficialWarningBanner() {
  const { lang } = useLang();
  const [warning, setWarning] = useState<OfficialWarning | null>(null);
  // Read once on the client; the banner only renders after a warning loads, so SSR markup matches.
  const [dismissed, setDismissed] = useState<string | null>(() => (typeof window === "undefined" ? null : readDismissed()));

  useEffect(() => {
    let alive = true;
    const load = () =>
      getLatestWarning()
        .then((r) => alive && r.warning && setWarning(r.warning))
        .catch(() => undefined);
    void load();
    const poll = window.setInterval(load, 20000);

    let ws: WebSocket | null = null;
    let retry: number | null = null;
    const connect = () => {
      try {
        ws = new WebSocket(`${getWsUrl()}?topics=police.warning`);
      } catch {
        return;
      }
      ws.onmessage = (m) => {
        try {
          const msg = JSON.parse(m.data) as { event: string; data: OfficialWarning };
          if (msg.event === "police.warning") setWarning(msg.data);
        } catch {
          /* ignore */
        }
      };
      ws.onclose = () => {
        if (alive) retry = window.setTimeout(connect, 5000);
      };
    };
    connect();
    return () => {
      alive = false;
      window.clearInterval(poll);
      if (retry) window.clearTimeout(retry);
      ws?.close();
    };
  }, []);

  const show = warning && warning.id !== dismissed;
  const dismiss = () => {
    if (!warning) return;
    setDismissed(warning.id);
    try {
      window.sessionStorage.setItem(DISMISSED_KEY, warning.id);
    } catch {
      /* ignore */
    }
  };

  return (
    <AnimatePresence>
      {show && (
        <motion.div
          key={warning.id}
          initial={{ height: 0, opacity: 0 }}
          animate={{ height: "auto", opacity: 1 }}
          exit={{ height: 0, opacity: 0 }}
          className="overflow-hidden"
          role="alert"
        >
          <div className="border-b border-line bg-surface" data-testid="official-warning">
            <div className="mx-auto flex max-w-6xl items-start gap-3 px-4 py-3 sm:px-6">
              <span className="mt-0.5 grid size-9 shrink-0 place-items-center rounded-control bg-scam text-on-scam">
                <BadgeCheck className="size-5" aria-hidden />
              </span>
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2">
                  <span className="text-[11px] font-semibold uppercase tracking-[0.12em] text-scam-ink rtl:tracking-normal">{lang === "ar" ? "تنبيه موثّق من شرطة أبوظبي" : "Abu Dhabi Police verified alert"}</span>
                  <span className="chip font-mono" dir="ltr">
                    {warning.id}
                  </span>
                </p>
                <p className="mt-1 text-[15px] font-semibold text-ink">{lang === "ar" ? warning.title_ar : warning.title_en}</p>
                <p className="mt-0.5 text-[14px] leading-relaxed text-ink-soft">{lang === "ar" ? warning.message_ar : warning.message_en}</p>
              </div>
              <button
                type="button"
                onClick={dismiss}
                aria-label={lang === "ar" ? "إغلاق" : "Dismiss"}
                className="-me-2 grid size-11 shrink-0 place-items-center rounded-full text-ink-soft hover:bg-muted hover:text-ink"
              >
                <X className="size-4" aria-hidden />
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
