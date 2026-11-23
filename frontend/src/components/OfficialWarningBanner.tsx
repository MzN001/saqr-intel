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
          <div className="border-b-4 border-crimson-600 bg-navy-900 text-white">
            <div className="mx-auto flex max-w-7xl items-start gap-3 px-4 py-3 sm:px-6">
              <span className="mt-0.5 grid size-9 shrink-0 place-items-center rounded-xl bg-crimson-600">
                <BadgeCheck className="size-5" />
              </span>
              <div className="min-w-0 flex-1">
                <p className="flex flex-wrap items-center gap-2 text-[11px] font-extrabold uppercase tracking-widest text-gold-500">
                  {lang === "ar" ? "تنبيه موثّق من شرطة أبوظبي" : "Abu Dhabi Police Verified Alert"}
                  <span className="rounded-full bg-white/10 px-2 py-0.5 font-mono normal-case tracking-normal text-white/70" dir="ltr">
                    {warning.id}
                  </span>
                </p>
                <p className="mt-0.5 text-sm font-extrabold sm:text-base">{lang === "ar" ? warning.title_ar : warning.title_en}</p>
                <p className="mt-0.5 text-sm text-white/80">{lang === "ar" ? warning.message_ar : warning.message_en}</p>
              </div>
              <button type="button" onClick={dismiss} aria-label={lang === "ar" ? "إغلاق" : "Dismiss"}
                className="rounded-full p-1.5 text-white/60 hover:bg-white/10 hover:text-white">
                <X className="size-4" />
              </button>
            </div>
          </div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
