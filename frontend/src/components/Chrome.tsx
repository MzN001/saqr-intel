"use client";

import { motion } from "framer-motion";
import { BatteryFull, Cloud, MessageSquare, Phone, ShieldCheck, Signal, Wifi, Zap } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { useLang } from "@/lib/i18n";
import { ShareQrButton } from "./ShareQrButton";
import { ThemeToggle } from "./ThemeToggle";

export function Header() {
  const { t, lang, setLang } = useLang();
  return (
    <header className="sticky top-0 z-30 border-b border-line bg-surface/85 backdrop-blur-md">
      <div className="mx-auto flex max-w-7xl items-center gap-3 px-4 py-3 sm:px-6">
        <div className="relative grid size-11 shrink-0 place-items-center rounded-2xl bg-navy-900 shadow-md ring-2 ring-gold-500/60">
          <ShieldCheck className="size-6 text-gold-500" />
          <span className="absolute -bottom-0.5 -end-0.5 size-3 rounded-full border-2 border-surface bg-emerald-500" />
        </div>
        <div className="min-w-0">
          <p className="whitespace-nowrap text-lg font-extrabold leading-none tracking-tight text-ink">{t("appName")}</p>
          <p className="mt-1 truncate text-xs font-medium text-ink-soft/70">{t("appTagline")}</p>
        </div>

        <div className="ms-auto flex items-center gap-2">
          <a
            href="tel:8002626"
            className="hidden items-center gap-1.5 rounded-full bg-muted px-3 py-1.5 text-xs font-semibold text-ink ring-1 ring-line hover:bg-line md:inline-flex"
          >
            <Phone className="size-3.5 text-emerald-700 dark:text-emerald-400" /> {t("aman")} <span dir="ltr">8002626</span>
          </a>
          <a
            href="sms:2828"
            className="hidden items-center gap-1.5 rounded-full bg-muted px-3 py-1.5 text-xs font-semibold text-ink ring-1 ring-line hover:bg-line md:inline-flex"
          >
            <MessageSquare className="size-3.5 text-emerald-700 dark:text-emerald-400" /> {t("sms")} <span dir="ltr">2828</span>
          </a>

          <ShareQrButton />
          <div
            role="radiogroup"
            aria-label="Language"
            className="relative flex rounded-full bg-navy-900 p-1 text-xs font-bold dark:bg-navy-950 dark:ring-1 dark:ring-white/15"
            dir="ltr"
          >
            {(["en", "ar"] as const).map((l) => (
              <button
                key={l}
                role="radio"
                aria-checked={lang === l}
                onClick={() => setLang(l)}
                className={`relative z-10 rounded-full px-3 py-1.5 transition-colors ${lang === l ? "text-navy-900" : "text-white/80 hover:text-white"}`}
              >
                {lang === l && (
                  <motion.span
                    layoutId="lang-knob"
                    className="absolute inset-0 -z-10 rounded-full bg-white"
                    transition={{ type: "spring", stiffness: 500, damping: 34 }}
                  />
                )}
                <span className="sm:hidden" aria-hidden>
                  {l === "en" ? "EN" : "ع"}
                </span>
                <span className="sr-only sm:not-sr-only">{l === "en" ? "English" : "العربية"}</span>
              </button>
            ))}
          </div>

          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

export function StatusBanner() {
  const { t } = useLang();
  return (
    <div className="relative overflow-hidden bg-navy-900 text-white dark:border-b dark:border-white/5 dark:bg-navy-950">
      <div className="pointer-events-none absolute inset-0 animate-[shimmer_7s_linear_infinite] bg-[linear-gradient(90deg,transparent_30%,rgba(52,211,153,0.16)_50%,transparent_70%)] bg-[length:200%_100%]" />
      <div className="mx-auto flex max-w-7xl items-center justify-center gap-3 px-4 py-2.5 text-center text-xs font-semibold sm:text-sm">
        <span className="relative flex size-2.5 shrink-0">
          <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex size-2.5 rounded-full bg-emerald-400" />
        </span>
        <span>{t("banner")}</span>
        <span className="hidden items-center gap-2 text-emerald-300 sm:flex">
          <Cloud className="size-4" />
          <Zap className="size-4" />
          <BatteryFull className="size-4" />
        </span>
      </div>
    </div>
  );
}

function useClock(): string {
  const [time, setTime] = useState("");
  useEffect(() => {
    const tick = () =>
      setTime(new Date().toLocaleTimeString("en-GB", { hour: "2-digit", minute: "2-digit", timeZone: "Asia/Dubai" }));
    tick();
    const id = window.setInterval(tick, 15_000);
    return () => window.clearInterval(id);
  }, []);
  return time;
}

export function PhoneFrame({ children, carrier = "e&" }: { children: ReactNode; carrier?: string }) {
  const time = useClock();
  return (
    <div className="relative mx-auto w-full sm:w-[390px]">
      <div className="pointer-events-none absolute -inset-8 hidden rounded-[4rem] bg-gradient-to-br from-emerald-400/20 via-navy-700/10 to-gold-500/20 blur-3xl sm:block" />
      <div className="relative overflow-hidden bg-screen sm:rounded-[3.2rem] sm:border-[11px] sm:border-navy-900 sm:shadow-[0_30px_80px_-20px_rgba(11,25,44,0.55)] dark:bg-[#202124] dark:sm:border-black dark:sm:shadow-[0_30px_80px_-20px_rgba(0,0,0,0.8),0_0_0_1px_rgba(255,255,255,0.08)]">
        <div className="relative flex h-11 items-center justify-between bg-screen px-6 text-[13px] font-semibold text-navy-900 dark:bg-[#202124] dark:text-gray-100" dir="ltr">
          <span className="tabular-nums">{time}</span>
          <span className="absolute left-1/2 top-2 hidden h-7 w-28 -translate-x-1/2 rounded-full bg-navy-900 sm:block dark:bg-black" />
          <span className="flex items-center gap-1.5">
            <span className="text-[11px] font-bold">{carrier}</span>
            <Signal className="size-3.5" />
            <Wifi className="size-3.5" />
            <BatteryFull className="size-4" />
          </span>
        </div>
        <div className="relative h-[calc(100dvh-13rem)] min-h-[560px] overflow-y-auto no-scrollbar sm:h-[720px]">{children}</div>
        <div className="hidden h-6 items-center justify-center bg-screen sm:flex dark:bg-[#202124]">
          <span className="h-1 w-28 rounded-full bg-navy-900/80 dark:bg-white/70" />
        </div>
      </div>
    </div>
  );
}
