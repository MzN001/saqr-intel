"use client";

import { AnimatePresence, MotionConfig, motion, type Variants } from "framer-motion";
import { AtSign, Cpu, Globe, Link2Off, Mail, MessageSquareWarning, Network, Radar, ScanSearch, ShieldCheck, Smartphone } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { analyzeEmail, analyzeUrl, getAlertVerdict, scanMaps, type EmailScanInput, type InterceptionChannel, type ScanVerdict } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";
import { hostOf, isMapsUrl } from "@/lib/url";
import { AwarenessRadar } from "./AwarenessRadar";
import { BackgroundShieldCard } from "./BackgroundShieldCard";
import { Header, StatusBanner } from "./Chrome";
import { EmailGuard } from "./EmailGuard";
import { OfficialWarningBanner } from "./OfficialWarningBanner";
import { LinkChecker } from "./LinkChecker";
import { ScamAlertsCard } from "./ScamAlertsCard";
import { SearchMapsShield } from "./SearchMapsShield";
import { SmsGuard } from "./SmsGuard";
import { VerdictScreen, type ScanState } from "./VerdictScreen";

type Tab = "search" | "sms" | "email" | "radar";
type DemoTab = Exclude<Tab, "radar">;

const TABS: { id: Tab; label: DictKey; short: DictKey; icon: typeof Globe }[] = [
  { id: "search", label: "tabSearch", short: "tabSearchShort", icon: Globe },
  { id: "sms", label: "tabSms", short: "tabSmsShort", icon: MessageSquareWarning },
  { id: "email", label: "emTab", short: "emTabShort", icon: Mail },
  { id: "radar", label: "tabRadar", short: "tabRadarShort", icon: Radar },
];

const SIDE_COPY: Record<DemoTab, { title: DictKey; intro: DictKey }> = {
  search: { title: "tabSearch", intro: "searchIntro" },
  sms: { title: "tabSms", intro: "smsIntro" },
  email: { title: "emTab", intro: "emIntro" },
};

const STEP_COPY: Record<DemoTab, { icon: typeof Globe; en: string; ar: string }[]> = {
  search: [
    { icon: Smartphone, en: "Resident taps a search ad or a Maps “Visit Website” button.", ar: "يضغط المقيم على إعلان بحث أو زر «زيارة الموقع» في الخرائط." },
    { icon: Network, en: "e& / du DNS shield holds the request and asks SAQR-INTEL.", ar: "يحتجز درع DNS لدى اتصالات ودو الطلب ويستعلم من صقر." },
    { icon: Cpu, en: "Cloud sandbox + AI verify the site against the UAE registry.", ar: "تتحقق البيئة السحابية المعزولة والذكاء الاصطناعي من الموقع مقابل السجل الرسمي." },
    { icon: ShieldCheck, en: "Scams are blocked and synced to AD Police instantly.", ar: "يتم حظر المواقع الاحتيالية ومزامنتها فوراً مع شرطة أبوظبي." },
  ],
  sms: [
    { icon: MessageSquareWarning, en: "A smishing SMS lands in the inbox.", ar: "تصل رسالة نصية احتيالية إلى صندوق الوارد." },
    { icon: ScanSearch, en: "The OS filter sends the link to SAQR-INTEL in the background.", ar: "يرسل مرشّح النظام الرابط إلى صقر في الخلفية." },
    { icon: ShieldCheck, en: "Scam messages move to Quarantine with the link disabled.", ar: "تُنقل الرسائل الاحتيالية إلى العزل مع تعطيل الرابط." },
    { icon: Network, en: "Police receive the report — the citizen never had to tap.", ar: "تتلقى الشرطة البلاغ دون أن يضغط المواطن على أي شيء." },
  ],
  email: [
    { icon: Mail, en: "Paste the email, its full source, or drop the .eml / .msg file.", ar: "الصق الرسالة أو مصدرها الكامل أو اسحب ملف .eml / .msg." },
    { icon: AtSign, en: "SAQR checks the real sender: SPF, DKIM, DMARC and lookalike letters.", ar: "يتحقق صقر من المرسل الحقيقي: SPF وDKIM وDMARC والأحرف المتشابهة." },
    { icon: Link2Off, en: "Every link and attachment is checked in the cloud, never on your phone.", ar: "يُفحص كل رابط ومرفق سحابياً، وليس على هاتفك أبداً." },
    { icon: ShieldCheck, en: "Matches against scam waves spreading now and your personal filter.", ar: "مطابقة مع موجات الاحتيال المنتشرة الآن ومع مرشّحك الشخصي." },
  ],
};

const sleep = (ms: number) => new Promise((r) => window.setTimeout(r, ms));

/** Confident arrival, no bounce (exponential ease-out). */
const EASE_OUT = [0.16, 1, 0.3, 1] as const;

/**
 * Tab content travels in from the side of the tab that was picked (mirrored in Arabic), with a short
 * focus pull, so switching reads as moving sideways through the same shield rather than a page swap.
 * Exit is faster than entrance. With "reduce motion" on, MotionConfig drops the travel and keeps the fade.
 */
const panelVariants: Variants = {
  enter: (dir: number) => ({ opacity: 0, x: 40 * dir, filter: "blur(6px)" }),
  center: { opacity: 1, x: 0, filter: "blur(0px)", transition: { duration: 0.42, ease: EASE_OUT } },
  exit: (dir: number) => ({ opacity: 0, x: -24 * dir, filter: "blur(4px)", transition: { duration: 0.18, ease: [0.4, 0, 1, 1] } }),
};

function SidePanel({ tab }: { tab: DemoTab }) {
  const { t, lang } = useLang();
  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-3xl font-extrabold leading-tight tracking-tight text-ink sm:text-4xl">
          {t(SIDE_COPY[tab].title)}
        </h1>
        <p className="mt-3 text-base leading-relaxed text-ink-soft">{t(SIDE_COPY[tab].intro)}</p>
      </div>
      <ol className="space-y-3">
        {STEP_COPY[tab].map((s, i) => (
          <motion.li
            key={`${tab}-${i}`}
            initial={{ opacity: 0, x: lang === "ar" ? 12 : -12 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ delay: 0.12 + i * 0.05, duration: 0.3, ease: EASE_OUT }}
            className="flex items-start gap-3 rounded-2xl bg-surface p-3.5 shadow-sm ring-1 ring-line"
          >
            <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-navy-900 text-gold-500 dark:bg-navy-950 dark:ring-1 dark:ring-white/10">
              <s.icon className="size-4.5" />
            </span>
            <span className="pt-1.5 text-sm font-medium text-ink">{s[lang]}</span>
          </motion.li>
        ))}
      </ol>
    </div>
  );
}

function Stage({ children, side }: { children: ReactNode; side: ReactNode }) {
  return (
    <div className="grid grid-cols-[minmax(0,1fr)] items-start gap-10 lg:grid-cols-[minmax(0,1fr)_auto]">
      <div className="order-2 min-w-0 lg:order-1 lg:pt-8">{side}</div>
      <div className="order-1 -mx-4 min-w-0 sm:mx-0 lg:order-2">{children}</div>
    </div>
  );
}

export function CitizenShell({
  sharedTarget,
  alertDomain,
  onSharedDone,
}: {
  sharedTarget: string | null;
  alertDomain: string | null;
  onSharedDone: () => void;
}) {
  const { t, dir: textDir } = useLang();
  const [tab, setTab] = useState<Tab>("search");
  const [travel, setTravel] = useState(1); // +1: content arrives from the reading-end side
  const panelRef = useRef<HTMLElement>(null);

  const selectTab = useCallback(
    (next: Tab, button?: HTMLElement | null) => {
      if (next === tab) return;
      const step = Math.sign(TABS.findIndex((x) => x.id === next) - TABS.findIndex((x) => x.id === tab));
      setTravel(textDir === "rtl" ? -step : step);
      setTab(next);
      const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      // The demo area sits below the link checker: bring it into view so the switch is visible.
      const panel = panelRef.current;
      if (panel && panel.getBoundingClientRect().top > window.innerHeight * 0.45) {
        panel.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
      }
      button?.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "nearest", inline: "nearest" });
    },
    [tab, textDir],
  );

  /** Arrow keys move between tabs (WAI-ARIA tabs pattern), mirrored for Arabic. */
  const onTabKey = (e: KeyboardEvent<HTMLDivElement>) => {
    const keys = textDir === "rtl" ? { ArrowLeft: 1, ArrowRight: -1 } : { ArrowLeft: -1, ArrowRight: 1 };
    const delta = keys[e.key as keyof typeof keys];
    if (!delta) return;
    e.preventDefault();
    const i = (TABS.findIndex((x) => x.id === tab) + delta + TABS.length) % TABS.length;
    const btn = e.currentTarget.querySelector<HTMLButtonElement>(`#tab-${TABS[i].id}`);
    btn?.focus();
    selectTab(TABS[i].id, btn);
  };
  const [scan, setScan] = useState<ScanState>({ status: "idle" });
  const lastJob = useRef<{
    target: string;
    interception: InterceptionChannel;
    job: () => Promise<ScanVerdict>;
    kind?: ScanVerdict["kind"];
  } | null>(null);
  const sharedHandled = useRef<string | null>(null);
  const fromShare = useRef(false);

  /** `kind` only changes the scanning animation's steps (e.g. "email" shows SPF/DKIM/link steps). */
  const execute = useCallback(
    async (target: string, interception: InterceptionChannel, job: () => Promise<ScanVerdict>, kind?: ScanVerdict["kind"]) => {
      lastJob.current = { target, interception, job, kind };
      setScan({ status: "scanning", target, interception, kind });
      try {
        const [result] = await Promise.all([job(), sleep(2600)]);
        setScan({ status: "done", result });
      } catch (e) {
        setScan({ status: "error", target, interception, message: e instanceof Error ? e.message : String(e) });
      }
    },
    [],
  );

  const runDnsScan = useCallback(
    (target: string, job: () => Promise<ScanVerdict>) => void execute(target, "AUTO_TELECOM_DNS", job),
    [execute],
  );

  const runManualScan = useCallback(
    (url: string, rawText?: string) => {
      const maps = isMapsUrl(url);
      const job = maps
        ? () => scanMaps({ maps_url: url }, "CITIZEN_MANUAL_CHECK")
        : () => analyzeUrl(url, "CITIZEN_MANUAL_CHECK", rawText ? "sms" : "web", rawText);
      void execute(maps ? "Google Maps listing" : hostOf(url), "CITIZEN_MANUAL_CHECK", job);
    },
    [execute],
  );

  const runEmailScan = useCallback(
    (input: EmailScanInput, target: string) =>
      void execute(target, "CITIZEN_MANUAL_CHECK", () => analyzeEmail(input, "CITIZEN_MANUAL_CHECK"), "email"),
    [execute],
  );

  const showVerdict = useCallback((result: ScanVerdict) => setScan({ status: "done", result }), []);

  const close = useCallback(() => {
    setScan({ status: "idle" });
    if (fromShare.current) {
      fromShare.current = false;
      onSharedDone();
    }
  }, [onSharedDone]);

  const retry = useCallback(() => {
    const j = lastJob.current;
    if (j) void execute(j.target, j.interception, j.job, j.kind);
  }, [execute]);

  useEffect(() => {
    if (!sharedTarget || sharedHandled.current === sharedTarget) return;
    sharedHandled.current = sharedTarget;
    fromShare.current = true;
    const job = isMapsUrl(sharedTarget)
      ? () => scanMaps({ maps_url: sharedTarget }, "MOBILE_OS_SHARE_SHEET")
      : () => analyzeUrl(sharedTarget, "MOBILE_OS_SHARE_SHEET", "social");
    void execute(sharedTarget, "MOBILE_OS_SHARE_SHEET", job);
  }, [sharedTarget, execute]);

  // Opened from a SAQR scam-alert notification: show the police warning for the blocked site.
  const alertHandled = useRef<string | null>(null);
  useEffect(() => {
    if (!alertDomain || alertHandled.current === alertDomain) return;
    alertHandled.current = alertDomain;
    fromShare.current = true;
    void execute(alertDomain, "AUTO_TELECOM_DNS", () => getAlertVerdict(alertDomain));
  }, [alertDomain, execute]);

  useEffect(() => {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    }
  }, []);

  return (
    <MotionConfig reducedMotion="user">
    <div className="min-h-dvh">
      <Header />
      <OfficialWarningBanner />
      <StatusBanner />

      <nav className="sticky top-[69px] z-20 border-b border-line bg-canvas/90 backdrop-blur">
        <div
          role="tablist"
          aria-label={t("appTagline")}
          onKeyDown={onTabKey}
          className="tab-scroller mx-auto flex max-w-7xl gap-1 overflow-x-auto px-4 no-scrollbar sm:px-6"
        >
          {TABS.map(({ id, label, short, icon: Icon }) => (
            <button
              key={id}
              id={`tab-${id}`}
              role="tab"
              aria-selected={tab === id}
              aria-controls="tab-panel"
              tabIndex={tab === id ? 0 : -1}
              onClick={(e) => selectTab(id, e.currentTarget)}
              className={`relative flex shrink-0 items-center gap-2 rounded-t-lg px-3 py-3.5 text-sm font-semibold transition-colors duration-150 sm:px-4 ${tab === id ? "text-ink" : "text-ink-soft/80 hover:text-ink"}`}
            >
              <Icon className={`size-4 ${tab === id ? "text-emerald-600 dark:text-emerald-400" : ""}`} />
              <span className="sm:hidden">{t(short)}</span>
              <span className="hidden sm:inline">{t(label)}</span>
              {tab === id && (
                <motion.span
                  layoutId="tab-underline"
                  transition={{ type: "spring", stiffness: 520, damping: 42 }}
                  className="absolute inset-x-2 -bottom-px h-[3px] rounded-full bg-ink"
                />
              )}
            </button>
          ))}
        </div>
      </nav>

      <main className="mx-auto max-w-7xl overflow-x-clip px-4 py-8 sm:px-6 lg:py-12">
        <div className="mb-8 grid gap-4 lg:mb-10">
          <LinkChecker onCheck={runManualScan} />
          <div className="grid items-start gap-4 lg:grid-cols-2">
            <BackgroundShieldCard />
            <ScamAlertsCard />
          </div>
        </div>
        <section ref={panelRef} id="tab-panel" role="tabpanel" aria-labelledby={`tab-${tab}`} className="scroll-mt-36">
        <AnimatePresence mode="wait" custom={travel} initial={false}>
          <motion.div key={tab} custom={travel} variants={panelVariants} initial="enter" animate="center" exit="exit">
            {tab === "search" && (
              <Stage side={<SidePanel tab="search" />}>
                <SearchMapsShield runScan={runDnsScan} />
              </Stage>
            )}
            {tab === "sms" && (
              <Stage side={<SidePanel tab="sms" />}>
                <SmsGuard onVerdict={showVerdict} />
              </Stage>
            )}
            {tab === "email" && (
              <Stage side={<SidePanel tab="email" />}>
                <div className="px-4 sm:px-0">
                  <EmailGuard onScan={runEmailScan} />
                </div>
              </Stage>
            )}
            {tab === "radar" && (
              <div className="space-y-6">
                <div>
                  <h1 className="text-3xl font-extrabold tracking-tight text-ink sm:text-4xl">{t("radarTitle")}</h1>
                  <p className="mt-2 max-w-3xl text-ink-soft">{t("radarIntro")}</p>
                </div>
                <AwarenessRadar />
              </div>
            )}
          </motion.div>
        </AnimatePresence>
        </section>
      </main>

      <footer className="border-t border-line bg-surface">
        <div className="mx-auto max-w-7xl px-4 py-5 text-center text-xs font-medium text-ink-soft sm:px-6">
          {t("footer")}
          <a href="/police" className="ms-3 text-ink-soft/80 underline-offset-2 hover:text-ink hover:underline">
            {t("commandCenter")}
          </a>
        </div>
      </footer>

      <VerdictScreen state={scan} onClose={close} onRetry={retry} />
    </div>
    </MotionConfig>
  );
}
