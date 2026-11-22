"use client";

import { AnimatePresence, animate, motion, useMotionValue, useTransform } from "framer-motion";
import {
  ArrowLeft,
  CircleCheck,
  Clock,
  CreditCard,
  ExternalLink,
  EyeOff,
  Fingerprint,
  KeyRound,
  Languages,
  Network,
  PhoneCall,
  RefreshCw,
  Server,
  ShieldAlert,
  ShieldCheck,
  TriangleAlert,
  X,
} from "lucide-react";
import { useEffect, useState } from "react";
import type { InterceptionChannel, RedFlag, ScanVerdict } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";
import { CHANNEL_DICT_KEY as CHANNEL_KEY, warningFromVerdict } from "@/lib/share";
import { XAlertPrompt } from "./XAlertComposer";

export type ScanState =
  | { status: "idle" }
  | { status: "scanning"; target: string; interception: InterceptionChannel }
  | { status: "done"; result: ScanVerdict }
  | { status: "error"; target: string; interception: InterceptionChannel; message: string };

const HARVEST_LABELS: Record<string, { en: string; ar: string; icon: typeof CreditCard }> = {
  OTP: { en: "OTP codes", ar: "رموز التحقق", icon: KeyRound },
  CARD_NUMBER: { en: "Card number", ar: "رقم البطاقة", icon: CreditCard },
  CVV: { en: "CVV", ar: "رمز CVV", icon: CreditCard },
  CARD_EXPIRY: { en: "Card expiry", ar: "تاريخ انتهاء البطاقة", icon: CreditCard },
  UAE_PASS: { en: "UAE PASS login", ar: "دخول UAE PASS", icon: Fingerprint },
  EMIRATES_ID: { en: "Emirates ID", ar: "الهوية الإماراتية", icon: Fingerprint },
  PASSWORD: { en: "Password", ar: "كلمة المرور", icon: KeyRound },
  ATM_PIN: { en: "ATM PIN", ar: "الرقم السري", icon: KeyRound },
  IBAN: { en: "Bank account", ar: "الحساب البنكي", icon: CreditCard },
};

const SEVERITY_STYLE: Record<RedFlag["severity"], string> = {
  critical: "bg-crimson-600 text-white",
  high: "bg-crimson-50 text-crimson-700 dark:bg-crimson-600/20 dark:text-red-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-500/20 dark:text-amber-300",
  low: "bg-line text-ink-soft",
  info: "bg-line text-ink-soft",
};

const SCAN_STEPS: DictKey[] = ["stepIntercept", "stepRegistry", "stepSandbox", "stepAi", "stepPolice"];

function stripBullets(text: string): string {
  return text
    .split(/\n\s*\n/)
    .filter((p) => !/^\s*(red flags|علامات الخطر)\s*:/i.test(p) && !/^\s*•/.test(p))
    .join("\n\n")
    .trim();
}

function RiskGauge({ score, tone }: { score: number; tone: "danger" | "warn" | "safe" }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const value = useMotionValue(0);
  const offset = useTransform(value, (v) => circumference - (v / 100) * circumference);
  const [display, setDisplay] = useState(0);

  useEffect(() => {
    const controls = animate(value, score, { duration: 1.4, ease: [0.16, 1, 0.3, 1] });
    const unsub = value.on("change", (v) => setDisplay(Math.round(v)));
    return () => {
      controls.stop();
      unsub();
    };
  }, [score, value]);

  const glow = tone === "danger" ? "rgba(255,180,190,0.9)" : tone === "warn" ? "rgba(255,230,160,0.9)" : "rgba(170,255,215,0.9)";
  return (
    <div className="relative grid size-36 shrink-0 place-items-center">
      <svg viewBox="0 0 128 128" className="absolute inset-0 -rotate-90">
        <circle cx="64" cy="64" r={radius} fill="none" stroke="rgba(255,255,255,0.18)" strokeWidth="10" />
        <motion.circle
          cx="64"
          cy="64"
          r={radius}
          fill="none"
          stroke="#ffffff"
          strokeWidth="10"
          style={{ strokeDashoffset: offset, filter: `drop-shadow(0 0 6px ${glow})` }}
          strokeLinecap="round"
          strokeDasharray={circumference}
        />
      </svg>
      <div className="text-center">
        <div className="text-4xl font-extrabold tabular-nums text-white">{display}</div>
        <div className="text-[11px] font-semibold uppercase tracking-wider text-white/70">/ 100</div>
      </div>
    </div>
  );
}

function ScanningView({ target, interception }: { target: string; interception: InterceptionChannel }) {
  const { t } = useLang();
  const [step, setStep] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setStep((s) => Math.min(s + 1, SCAN_STEPS.length - 1)), 650);
    return () => window.clearInterval(id);
  }, []);

  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-navy-900 px-6 py-16 text-white">
      <div className="relative grid size-56 place-items-center overflow-hidden rounded-full">
        {[0, 1, 2].map((i) => (
          <span key={i} className="absolute inset-0 rounded-full border border-emerald-400/30" style={{ transform: `scale(${0.45 + i * 0.27})` }} />
        ))}
        <span className="absolute inset-0 animate-sweep rounded-full bg-[conic-gradient(from_0deg,rgba(16,185,129,0.55),transparent_28%)]" />
        <span className="absolute size-20 animate-ping-slow rounded-full bg-emerald-400/30" />
        <div className="relative grid size-20 place-items-center rounded-2xl bg-white/10 ring-1 ring-white/20 backdrop-blur">
          <ShieldCheck className="size-10 text-emerald-300" />
        </div>
      </div>
      <p className="mt-6 rounded-full bg-white/10 px-3 py-1 text-xs font-semibold uppercase tracking-wider text-emerald-300">
        {t(CHANNEL_KEY[interception])}
      </p>
      <h2 className="shimmer-text mt-3 text-center text-2xl font-bold">{t("scanningTitle")}</h2>
      <p className="mt-2 max-w-xs truncate text-center font-mono text-sm text-white/60" dir="ltr">
        {target}
      </p>
      <ul className="mt-8 w-full max-w-sm space-y-2.5">
        {SCAN_STEPS.map((key, i) => (
          <motion.li
            key={key}
            initial={{ opacity: 0, x: -12 }}
            animate={{ opacity: i <= step ? 1 : 0.35, x: 0 }}
            transition={{ delay: i * 0.08 }}
            className="flex items-center gap-3 text-sm"
          >
            {i < step ? (
              <CircleCheck className="size-5 text-emerald-400" />
            ) : i === step ? (
              <RefreshCw className="size-5 animate-spin text-emerald-300" />
            ) : (
              <span className="size-5 rounded-full border border-white/30" />
            )}
            <span>{t(key)}</span>
          </motion.li>
        ))}
      </ul>
    </div>
  );
}

function ResultView({ result, onClose }: { result: ScanVerdict; onClose: () => void }) {
  const { t, lang } = useLang();
  const [showOther, setShowOther] = useState(false);
  const tone = result.verdict === "HIGH-RISK SCAM" ? "danger" : result.verdict === "SUSPICIOUS" ? "warn" : "safe";
  const header =
    tone === "danger"
      ? "from-crimson-700 via-crimson-600 to-[#7a0a1c]"
      : tone === "warn"
        ? "from-amber-600 via-amber-500 to-amber-700"
        : "from-emerald-700 via-emerald-600 to-emerald-800";
  const entity = (lang === "ar" ? result.entityAr : result.entityEn) ?? result.entityEn ?? t("unknownEntity");
  const primary = stripBullets(lang === "ar" ? result.explanationAr : result.explanationEn);
  const secondary = stripBullets(lang === "ar" ? result.explanationEn : result.explanationAr);
  const official = result.officialDomains[0];
  const syndicate = lang === "ar" ? result.syndicateAr ?? result.syndicateEn : result.syndicateEn;
  const title = tone === "danger" ? t("blockedTitle") : tone === "warn" ? t("suspiciousTitle") : t("safeTitle");
  const HeaderIcon = tone === "safe" ? ShieldCheck : tone === "warn" ? TriangleAlert : ShieldAlert;

  return (
    <div className="min-h-full bg-canvas">
      <div className={`relative overflow-hidden bg-gradient-to-br ${header} px-5 pb-8 pt-5 text-white`}>
        <div className="pointer-events-none absolute -end-16 -top-16 size-56 rounded-full bg-white/10 blur-2xl" />
        <div className="relative mx-auto max-w-2xl">
          <div className="flex items-center justify-between">
            <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-semibold">
              <span dir="ltr" className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">AD Police</span>
              <span dir="ltr" className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">e&amp;</span>
              <span dir="ltr" className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">du</span>
              <span className="rounded-full bg-white/15 px-2.5 py-1 ring-1 ring-white/25">{t(CHANNEL_KEY[result.interception])}</span>
            </div>
            <button onClick={onClose} aria-label={t("close")} className="rounded-full bg-white/15 p-2 hover:bg-white/25">
              <X className="size-5" />
            </button>
          </div>

          <div className="mt-6 flex items-center gap-5">
            <RiskGauge score={result.riskScore} tone={tone} />
            <div className="min-w-0">
              <motion.div
                initial={{ scale: 0.6, opacity: 0 }}
                animate={{ scale: 1, opacity: 1 }}
                transition={{ type: "spring", stiffness: 260, damping: 14, delay: 0.2 }}
                className="mb-2 inline-flex items-center gap-2 rounded-lg bg-white px-2.5 py-1 text-sm font-extrabold tracking-wide"
                style={{ color: tone === "danger" ? "#c8102e" : tone === "warn" ? "#b45309" : "#047857" }}
              >
                <HeaderIcon className="size-4" /> {result.verdict}
              </motion.div>
              <h2 className="text-2xl font-extrabold leading-tight sm:text-3xl">{title}</h2>
              {tone !== "safe" && <p className="mt-1 text-sm text-white/80">{t("blockedBy")}</p>}
              <p className="mt-2 truncate font-mono text-xs text-white/70" dir="ltr">
                {result.target}
              </p>
            </div>
          </div>
        </div>
      </div>

      <div className="mx-auto -mt-4 max-w-2xl space-y-4 px-4 pb-10">
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.25 }}
          className="relative overflow-hidden rounded-2xl bg-navy-900 p-4 text-white shadow-lg dark:bg-navy-800 dark:ring-1 dark:ring-white/10"
        >
          <div className="flex items-center gap-3">
            <span className="relative flex size-3">
              <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex size-3 rounded-full bg-emerald-400" />
            </span>
            <p className="text-sm font-semibold">{t("syncedBadge")}</p>
          </div>
          <p className="mt-1 ps-6 font-mono text-xs text-white/60" dir="ltr">
            {t("caseId")} {result.scanId} · {new Date().toLocaleTimeString(lang === "ar" ? "ar-AE" : "en-AE")}
          </p>
        </motion.div>

        {tone !== "safe" && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.35 }}
            className="grid gap-3 sm:grid-cols-2"
          >
            <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/70">{t("impersonating")}</p>
              <p className="mt-1 text-lg font-bold text-crimson-700 dark:text-red-300">{entity}</p>
            </div>
            {official && (
              <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
                <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/70">{t("officialSite")}</p>
                <p className="mt-1 flex items-center gap-2 text-lg font-bold text-emerald-700 dark:text-emerald-400" dir="ltr">
                  <ShieldCheck className="size-5" /> {official}
                </p>
              </div>
            )}
          </motion.div>
        )}

        {result.harvested.length > 0 && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.45 }}
            className="rounded-2xl border border-crimson-600/20 bg-crimson-50 p-4 dark:border-crimson-600/40 dark:bg-crimson-600/15"
          >
            <p className="text-sm font-bold text-crimson-700 dark:text-red-300">{t("wantsYour")}</p>
            <div className="mt-2 flex flex-wrap gap-2">
              {result.harvested
                .filter((h) => HARVEST_LABELS[h])
                .map((h) => {
                  const Icon = HARVEST_LABELS[h].icon;
                  return (
                    <span key={h} className="inline-flex items-center gap-1.5 rounded-full bg-white px-3 py-1 text-xs font-semibold text-crimson-700 ring-1 ring-crimson-600/20 dark:bg-black/30 dark:text-red-300 dark:ring-crimson-600/40">
                      <Icon className="size-3.5" /> {HARVEST_LABELS[h][lang]}
                    </span>
                  );
                })}
            </div>
          </motion.div>
        )}

        {primary && (
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.5 }}
            className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line"
          >
            <div className="flex items-center justify-between gap-2">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/70">{t(tone === "safe" ? "whySafe" : "whyDangerous")}</p>
              <button
                onClick={() => setShowOther((s) => !s)}
                className="inline-flex items-center gap-1 rounded-full bg-muted px-2.5 py-1 text-xs font-semibold text-ink-soft hover:bg-line"
              >
                <Languages className="size-3.5" /> {t("otherLanguage")}
              </button>
            </div>
            <p className="mt-2 whitespace-pre-line text-[15px] leading-relaxed text-ink">{primary}</p>
            <AnimatePresence>
              {showOther && secondary && (
                <motion.p
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  dir={lang === "ar" ? "ltr" : "rtl"}
                  className="mt-3 overflow-hidden whitespace-pre-line border-t border-line pt-3 text-[15px] leading-relaxed text-ink-soft"
                >
                  {secondary}
                </motion.p>
              )}
            </AnimatePresence>
          </motion.div>
        )}

        {result.redFlags.length > 0 && (
          <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/70">{t("redFlags")}</p>
            <ul className="mt-2 space-y-2">
              {[...result.redFlags]
                .sort((a, b) => b.points - a.points)
                .map((f, i) => (
                  <motion.li
                    key={f.code}
                    initial={{ opacity: 0, x: lang === "ar" ? 16 : -16 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.55 + i * 0.07 }}
                    className="flex gap-3 rounded-xl bg-muted p-3"
                  >
                    <span className={`h-fit shrink-0 rounded-md px-1.5 py-0.5 text-[10px] font-bold uppercase ${SEVERITY_STYLE[f.severity]}`}>
                      {f.severity}
                    </span>
                    <span className="text-sm leading-snug text-ink">{lang === "ar" ? f.ar : f.en}</span>
                  </motion.li>
                ))}
            </ul>
          </div>
        )}

        {tone !== "safe" && result.riskScore >= 60 && <XAlertPrompt warning={warningFromVerdict(result)} />}

        {(syndicate || result.ip || result.domainAgeHours !== null || result.cloaking) && (
          <div className="grid gap-3 sm:grid-cols-2">
            {syndicate && (
              <div className="rounded-2xl bg-navy-900 p-4 text-white sm:col-span-2 dark:bg-navy-800 dark:ring-1 dark:ring-white/10">
                <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-white/60">
                  <Network className="size-4" /> {t("syndicateLink")}
                </p>
                <p className="mt-1 text-lg font-bold text-gold-500">{syndicate}</p>
              </div>
            )}
            {result.domainAgeHours !== null && (
              <div className="flex items-center gap-3 rounded-2xl bg-surface p-4 ring-1 ring-line">
                <Clock className="size-5 text-crimson-600" />
                <div>
                  <p className="text-xs text-ink-soft/70">{t("registered")}</p>
                  <p className="font-bold">
                    {Math.round(result.domainAgeHours)} {t("hoursAgo")}
                  </p>
                </div>
              </div>
            )}
            {result.ip && (
              <div className="flex items-center gap-3 rounded-2xl bg-surface p-4 ring-1 ring-line">
                <Server className="size-5 text-ink-soft" />
                <div>
                  <p className="text-xs text-ink-soft/70">{t("hostedOn")}</p>
                  <p className="font-mono font-bold" dir="ltr">
                    {result.ip}
                  </p>
                </div>
              </div>
            )}
            {result.cloaking && (
              <div className="flex items-center gap-3 rounded-2xl bg-surface p-4 ring-1 ring-line sm:col-span-2">
                <EyeOff className="size-5 text-amber-600" />
                <p className="font-semibold">{t("cloaking")}</p>
              </div>
            )}
          </div>
        )}

        {result.screenshot && (
          <div className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line">
            <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/70">{t("evidence")}</p>
            <div className="relative mt-2 overflow-hidden rounded-xl ring-1 ring-line">
              {/* eslint-disable-next-line @next/next/no-img-element */}
              <img
                src={`data:image/jpeg;base64,${result.screenshot}`}
                alt="Sandbox screenshot of the blocked page"
                className="max-h-80 w-full object-cover object-top opacity-90 blur-[1px] grayscale-[30%]"
              />
              <div className="absolute inset-0 grid place-items-center bg-crimson-600/10">
                <span className="rotate-[-12deg] rounded-lg border-4 border-crimson-600 bg-white/90 px-4 py-1 text-2xl font-black tracking-widest text-crimson-600">
                  BLOCKED
                </span>
              </div>
            </div>
          </div>
        )}

        <div className="sticky bottom-0 -mx-4 space-y-2 bg-gradient-to-t from-canvas via-canvas to-transparent px-4 pb-4 pt-6">
          <button
            onClick={onClose}
            className="flex w-full items-center justify-center gap-2 rounded-2xl bg-navy-900 py-3.5 text-base font-bold text-white shadow-lg transition hover:bg-navy-800 active:scale-[0.98] dark:bg-navy-700 dark:hover:bg-navy-800"
          >
            <ArrowLeft className="size-5 rtl:rotate-180" /> {t("backToSafety")}
          </button>
          <div className="grid grid-cols-2 gap-2">
            {tone === "safe" ? (
              <a
                href={official ? `https://${official}` : "#"}
                target="_blank"
                rel="noopener noreferrer"
                className="col-span-2 flex items-center justify-center gap-2 rounded-2xl bg-emerald-600 py-3 text-sm font-bold text-white"
              >
                <ExternalLink className="size-4" /> {t("continueSite")}
              </a>
            ) : (
              <>
                {official ? (
                  <a
                    href={`https://${official}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center justify-center gap-2 rounded-2xl bg-emerald-600 py-3 text-sm font-bold text-white"
                  >
                    <ShieldCheck className="size-4" /> {t("goOfficial")}
                  </a>
                ) : (
                  <span />
                )}
                <a
                  href="tel:8002626"
                  className={`flex items-center justify-center gap-2 rounded-2xl bg-surface py-3 text-sm font-bold text-ink ring-1 ring-line ${official ? "" : "col-span-2"}`}
                >
                  <PhoneCall className="size-4" /> {t("callAman")}
                </a>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

function ErrorView({ message, onRetry, onClose }: { message: string; onRetry: () => void; onClose: () => void }) {
  const { t } = useLang();
  return (
    <div className="flex min-h-full flex-col items-center justify-center bg-navy-900 px-6 text-center text-white">
      <TriangleAlert className="size-14 text-amber-400" />
      <h2 className="mt-4 text-2xl font-bold">{t("scanFailed")}</h2>
      <p className="mt-2 max-w-sm text-sm text-white/70">{message}</p>
      <div className="mt-6 flex gap-3">
        <button onClick={onRetry} className="rounded-xl bg-emerald-600 px-5 py-2.5 font-semibold">
          {t("retry")}
        </button>
        <button onClick={onClose} className="rounded-xl bg-white/10 px-5 py-2.5 font-semibold">
          {t("close")}
        </button>
      </div>
    </div>
  );
}

export function VerdictScreen({ state, onClose, onRetry }: { state: ScanState; onClose: () => void; onRetry: () => void }) {
  const open = state.status !== "idle";

  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => {
      document.body.style.overflow = prev;
      window.removeEventListener("keydown", onKey);
    };
  }, [open, onClose]);

  return (
    <AnimatePresence>
      {open && (
        <motion.div
          key="verdict-sheet"
          role="dialog"
          aria-modal="true"
          initial={{ y: "100%" }}
          animate={{ y: 0 }}
          exit={{ y: "100%" }}
          transition={{ type: "spring", stiffness: 210, damping: 28 }}
          className="fixed inset-0 z-50 overflow-y-auto overscroll-contain bg-navy-900 no-scrollbar"
        >
          <AnimatePresence mode="wait">
            <motion.div
              key={state.status}
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.25 }}
              className="min-h-full"
            >
              {state.status === "scanning" && <ScanningView target={state.target} interception={state.interception} />}
              {state.status === "done" && <ResultView result={state.result} onClose={onClose} />}
              {state.status === "error" && <ErrorView message={state.message} onRetry={onRetry} onClose={onClose} />}
            </motion.div>
          </AnimatePresence>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
