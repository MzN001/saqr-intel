"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ChevronLeft, Inbox, MessageCircle, RefreshCw, ShieldAlert, ShieldBan, ShieldCheck } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type MouseEvent } from "react";
import { analyzeMessage, type ScanVerdict } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { useHydrated } from "@/lib/useHydrated";
import { PhoneFrame } from "./Chrome";
import { SCAM_POST_URL } from "./SearchMapsShield";

type Phase = "idle" | "arriving" | "scanning" | "quarantined" | "safe" | "error";
type Folder = "inbox" | "quarantine";

const SCAM_TEXT_EN = `Emirates Post: Parcel held at Abu Dhabi customs. Pay AED 14.50 at ${SCAM_POST_URL}`;

const BENIGN = [
  { from: { en: "Ahmed", ar: "أحمد" }, text: { en: "See you at the majlis tonight 👍", ar: "نلتقي في المجلس الليلة 👍" }, time: "09:12", color: "bg-sky-500" },
  { from: { en: "Mama", ar: "أمي" }, text: { en: "Don't forget to bring bread on your way home", ar: "لا تنسَ إحضار الخبز في طريقك إلى البيت" }, time: "08:47", color: "bg-pink-500" },
  { from: { en: "Al Reem Gym", ar: "نادي الريم" }, text: { en: "Your membership renews on 1 December.", ar: "يتجدد اشتراكك في 1 ديسمبر." }, time: "Yesterday", color: "bg-violet-500" },
];

const sleep = (ms: number) => new Promise((r) => window.setTimeout(r, ms));

function ScamBody({ phase, onLink }: { phase: Phase; onLink: (e: MouseEvent) => void }) {
  const disabled = phase === "quarantined";
  const hydrated = useHydrated();
  const [before, url] = [SCAM_TEXT_EN.replace(SCAM_POST_URL, ""), SCAM_POST_URL];
  return (
    <p className="mt-0.5 text-[13px] leading-snug text-gray-700 dark:text-gray-300" dir="ltr">
      {before}
      <a
        href={hydrated ? url : undefined}
        onClick={onLink}
        className={`break-all ${disabled ? "pointer-events-none text-gray-400 line-through dark:text-gray-500" : "text-[#1a73e8] underline dark:text-[#8ab4f8]"}`}
      >
        {url}
      </a>
    </p>
  );
}

/**
 * `onVerdict(v, "auto")`: the guard quarantined the SMS by itself (shown in the inline verdict card).
 * `onVerdict(v, "open")`: the resident tapped the scam link (shown as the full-screen block page).
 */
export function SmsGuard({ onVerdict }: { onVerdict: (v: ScanVerdict, how: "auto" | "open") => void }) {
  const { t, lang } = useLang();
  const [phase, setPhase] = useState<Phase>("idle");
  const [folder, setFolder] = useState<Folder>("inbox");
  const [toast, setToast] = useState(false);
  const [result, setResult] = useState<ScanVerdict | null>(null);
  const [error, setError] = useState<string | null>(null);
  const runId = useRef(0);

  const start = useCallback(async () => {
    const id = ++runId.current;
    const alive = () => runId.current === id;
    setPhase("idle");
    setFolder("inbox");
    setResult(null);
    setError(null);
    await sleep(700);
    if (!alive()) return;
    setPhase("arriving");
    setToast(true);
    await sleep(1300);
    if (!alive()) return;
    setToast(false);
    setPhase("scanning");
    try {
      const [verdict] = await Promise.all([analyzeMessage(SCAM_TEXT_EN, "AUTO_SMS_GUARD", "EmiratesPost"), sleep(2200)]);
      if (!alive()) return;
      setResult(verdict);
      if (verdict.verdict === "SAFE") {
        setPhase("safe");
        return;
      }
      setPhase("quarantined");
      await sleep(650);
      if (!alive()) return;
      setFolder("quarantine");
      await sleep(900);
      if (!alive()) return;
      onVerdict(verdict, "auto");
    } catch (e) {
      if (!alive()) return;
      setError(e instanceof Error ? e.message : String(e));
      setPhase("error");
    }
  }, [onVerdict]);

  useEffect(() => {
    const first = window.setTimeout(() => void start(), 0);
    const runs = runId;
    return () => {
      window.clearTimeout(first);
      runs.current += 1;
    };
  }, [start]);

  const onLink = (e: MouseEvent) => {
    e.preventDefault();
    if (result) onVerdict(result, "open");
  };

  const scamVisibleInInbox = phase === "arriving" || phase === "scanning" || phase === "safe" || phase === "error";
  const quarantineCount = phase === "quarantined" ? 1 : 0;

  const scamRow = (where: Folder) => (
    <motion.li
      layoutId="scam-sms"
      key={`scam-${where}`}
      initial={where === "inbox" ? { opacity: 0, y: -24, scale: 0.97 } : { opacity: 0, x: lang === "ar" ? -40 : 40 }}
      animate={{ opacity: 1, y: 0, x: 0, scale: 1 }}
      exit={{ opacity: 0, x: lang === "ar" ? -80 : 80, transition: { duration: 0.35 } }}
      transition={{ type: "spring", stiffness: 260, damping: 26 }}
      className={`relative overflow-hidden rounded-2xl p-3 ${where === "quarantine" ? "bg-scam-soft ring-1 ring-scam/30" : "bg-[#eef3ff] dark:bg-[#1f2b44]"}`}
    >
      {phase === "scanning" && (
        <span className="pointer-events-none absolute inset-x-0 top-0 h-1/3 animate-scanline bg-gradient-to-b from-transparent via-[#1a73e8]/20 to-transparent" />
      )}
      <div className="flex gap-3">
        <span className={`grid size-10 shrink-0 place-items-center rounded-full text-sm font-bold text-white ${where === "quarantine" ? "bg-scam" : "bg-[#f59e0b]"}`}>
          {where === "quarantine" ? <ShieldBan className="size-5" /> : "EP"}
        </span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center justify-between gap-2">
            <p className="truncate text-[14px] font-bold text-gray-900 dark:text-gray-100" dir="ltr">
              EmiratesPost
            </p>
            <span className="shrink-0 text-[11px] text-gray-500 dark:text-gray-400">{t("now")}</span>
          </div>
          <ScamBody phase={phase} onLink={onLink} />
          <AnimatePresence mode="wait">
            {phase === "scanning" && (
              <motion.p key="s" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="mt-2 flex items-center gap-1.5 text-[12px] font-semibold text-gray-700 dark:text-gray-300">
                <RefreshCw className="size-3.5 animate-spin" /> {t("smsScanning")}
              </motion.p>
            )}
            {phase === "quarantined" && result && (
              <motion.button
                key="q"
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                onClick={() => onVerdict(result, "open")}
                className="mt-2 flex min-h-11 w-full items-center justify-between gap-2 rounded-xl bg-white px-3 py-2 text-start text-[12px] font-semibold text-scam-ink ring-1 ring-scam/20 dark:bg-black/30"
              >
                <span className="flex items-center gap-1.5">
                  <ShieldAlert className="size-4" /> {t("smsQuarantined")} · {result.riskScore}/100
                </span>
                <span className="underline">{t("viewWarning")}</span>
              </motion.button>
            )}
            {phase === "safe" && (
              <motion.p key="ok" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-2 flex items-center gap-1.5 text-[12px] font-semibold text-safe-ink">
                <ShieldCheck className="size-4" /> {t("smsSafeFlag")}
              </motion.p>
            )}
            {phase === "error" && (
              <motion.p key="e" initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="mt-2 text-[12px] font-semibold text-gray-700 dark:text-gray-300">
                {error}
              </motion.p>
            )}
          </AnimatePresence>
        </div>
      </div>
    </motion.li>
  );

  return (
    <div className="space-y-4">
      <PhoneFrame carrier="du">
        <div className="relative min-h-full bg-screen dark:bg-[#202124]">
          <AnimatePresence>
            {toast && (
              <motion.div
                initial={{ y: -90, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                exit={{ y: -90, opacity: 0 }}
                transition={{ type: "spring", stiffness: 300, damping: 26 }}
                className="absolute inset-x-3 top-2 z-20 rounded-2xl bg-white/95 p-3 shadow-xl ring-1 ring-black/5 backdrop-blur dark:bg-[#303134]/95 dark:ring-white/10"
              >
                <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-gray-500 dark:text-gray-400">
                  <MessageCircle className="size-3.5 text-[#34c759]" /> {t("messages")} · {t("now")}
                </div>
                <p className="mt-1 text-[13px] font-bold text-gray-900 dark:text-gray-100" dir="ltr">
                  EmiratesPost
                </p>
                <p className="line-clamp-2 text-[12px] text-gray-700 dark:text-gray-300" dir="ltr">
                  {SCAM_TEXT_EN}
                </p>
              </motion.div>
            )}
          </AnimatePresence>

          <div className="flex items-center gap-2 px-4 pb-2 pt-3">
            <ChevronLeft className="size-5 text-[#1a73e8] rtl:rotate-180 dark:text-[#8ab4f8]" />
            <h3 className="text-[26px] font-bold text-gray-900 dark:text-gray-100">{t("messages")}</h3>
          </div>

          <div className="mx-4 grid grid-cols-2 rounded-xl bg-gray-100 p-1 text-[12px] font-semibold dark:bg-[#303134]">
            {(["inbox", "quarantine"] as const).map((f) => (
              <button key={f} onClick={() => setFolder(f)} className={`relative flex items-center justify-center gap-1.5 rounded-lg py-2 ${folder === f ? "text-gray-900 dark:text-gray-100" : "text-gray-500 dark:text-gray-400"}`}>
                {folder === f && <motion.span layoutId="sms-folder" className="absolute inset-0 rounded-lg bg-white shadow-sm dark:bg-[#4a4d52]" transition={{ type: "spring", stiffness: 420, damping: 34 }} />}
                <span className="relative flex items-center gap-1.5">
                  {f === "inbox" ? <Inbox className="size-3.5" /> : <ShieldBan className="size-3.5 text-scam" />}
                  {f === "inbox" ? t("inbox") : t("quarantine")}
                  {f === "quarantine" && (
                    <AnimatePresence>
                      {quarantineCount > 0 && (
                        <motion.span
                          initial={{ scale: 0 }}
                          animate={{ scale: [0, 1.4, 1] }}
                          exit={{ scale: 0 }}
                          className="grid size-4 place-items-center rounded-full bg-scam text-[11px] text-on-scam"
                        >
                          {quarantineCount}
                        </motion.span>
                      )}
                    </AnimatePresence>
                  )}
                </span>
              </button>
            ))}
          </div>

          <ul className="space-y-2 px-3 pb-6 pt-3">
            <AnimatePresence mode="popLayout" initial={false}>
              {folder === "inbox" && scamVisibleInInbox && scamRow("inbox")}
              {folder === "quarantine" && phase === "quarantined" && scamRow("quarantine")}
              {folder === "quarantine" && phase !== "quarantined" && (
                <motion.li key="empty" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="py-16 text-center text-sm text-gray-500 dark:text-gray-400">
                  {t("emptyQuarantine")}
                </motion.li>
              )}
              {folder === "inbox" &&
                BENIGN.map((m) => (
                  <motion.li layout key={m.from.en} initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex gap-3 rounded-2xl p-3">
                    <span className={`grid size-10 shrink-0 place-items-center rounded-full text-sm font-bold text-white ${m.color}`}>{m.from[lang].slice(0, 1)}</span>
                    <div className="min-w-0 flex-1 border-b border-gray-100 pb-3 dark:border-[#3c4043]">
                      <div className="flex items-center justify-between gap-2">
                        <p className="truncate text-[14px] font-semibold text-gray-900 dark:text-gray-100">{m.from[lang]}</p>
                        <span className="shrink-0 text-[11px] text-gray-500 dark:text-gray-400">{m.time}</span>
                      </div>
                      <p className="truncate text-[13px] text-gray-600 dark:text-gray-400">{m.text[lang]}</p>
                    </div>
                  </motion.li>
                ))}
            </AnimatePresence>
          </ul>
        </div>
      </PhoneFrame>
      <div className="flex justify-center">
        <button type="button" onClick={() => void start()} className="btn-secondary" data-testid="sms-replay">
          <RefreshCw className="size-4" aria-hidden /> {t("replay")}
        </button>
      </div>
    </div>
  );
}
