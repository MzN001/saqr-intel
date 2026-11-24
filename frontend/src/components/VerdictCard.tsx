"use client";

import { AnimatePresence, motion } from "framer-motion";
import { BadgeCheck, CircleAlert, CircleCheck, FileText, Info, RefreshCw, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import type { ScanVerdict } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { CHANNEL_DICT_KEY, defang, warningFromVerdict } from "@/lib/share";
import { RiskMeter, toneOf, type Tone } from "./RiskMeter";
import { FalseAlarmReport, isVerifiedOfficial, scanSteps, scanTitle, stripBullets, visible, type ScanState } from "./VerdictScreen";
import { CopyAmanButton, Toast, useToast, WarnOnXButton } from "./XAlertComposer";

/*
 * "What you will see" card (desktop / tablet). Idle: a static DEMO EXAMPLE (or, in the compact tool windows, an
 * empty placeholder). While a check runs it shows the scanning steps in place (no full-screen takeover), then
 * the LIVE VERDICT for any kind of check (link, message, email, Maps): every result is a `ScanVerdict`.
 * Styling follows the owner's reference (DESIGN.md "Verdict card"): translucent white card, light score,
 * tilted outlined stamp, single-line meter, white reason rows. The card reserves its height so the page
 * below does not jump when the state changes.
 */

export type Bilingual = { en: string; ar: string };

const DEMO = {
  target: "tamm-fines-abudhabi[.]com",
  score: 92,
  reasons: [
    { en: "Pretends to be TAMM, but it is not a gov.ae website", ar: "يدّعي أنه TAMM لكنه ليس موقعاً حكومياً" },
    { en: "Asks for your card details to pay a fine", ar: "يطلب بيانات بطاقتك لدفع مخالفة" },
    { en: "Website address was created only days ago", ar: "عنوان الموقع أُنشئ قبل أيام فقط" },
  ] as Bilingual[],
};

export const VERDICT_WORDS: Record<Tone, Bilingual> = {
  scam: { en: "HIGH-RISK SCAM", ar: "احتيال عالي الخطورة" },
  suspicious: { en: "SUSPICIOUS", ar: "مشبوه" },
  safe: { en: "SAFE", ar: "آمن" },
};

/** Stamp, reason icons: crimson (reference value) for scam, amber ink for suspicious, brand green for safe. */
export const MARK_TEXT: Record<Tone, string> = {
  scam: "text-scam-mark",
  suspicious: "text-suspicious-ink",
  safe: "text-brand-ink",
};

export const REASON_ICON: Record<Tone, typeof CircleAlert> = {
  scam: CircleAlert,
  suspicious: TriangleAlert,
  safe: CircleCheck,
};

function firstSentence(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  const m = /^(.{20,220}?[.!؟?])(\s|$)/.exec(flat);
  return m ? m[1] : flat.slice(0, 200);
}

/** Top three reasons in both languages: the strongest red flags, else the first sentence of the explanation. */
export function topReasons(r: ScanVerdict): Bilingual[] {
  const flags = [...r.redFlags]
    .sort((a, b) => b.points - a.points)
    .slice(0, 3)
    .map((f) => ({ en: f.en, ar: f.ar }));
  if (flags.length) return flags;
  const en = firstSentence(stripBullets(r.explanationEn ?? ""));
  const ar = firstSentence(stripBullets(r.explanationAr ?? ""));
  return en || ar ? [{ en, ar }] : [];
}

/** The verdict as an outlined, tilted stamp: tracked caps over the Arabic word. Stays readable in RTL. */
function VerdictStamp({ tone }: { tone: Tone }) {
  const words = VERDICT_WORDS[tone];
  return (
    <span className={`verdict-stamp shrink-0 ${MARK_TEXT[tone]}`} data-testid="verdict-stamp">
      <span lang="en" dir="ltr" className="text-[12px] font-bold uppercase tracking-[0.08em]">
        {words.en}
      </span>
      <span lang="ar" dir="rtl" className="text-[15px] font-bold leading-tight">
        {words.ar}
      </span>
    </span>
  );
}

function ScoreRow({ score, tone }: { score: number; tone: Tone }) {
  return (
    <>
      <div className="mt-1 flex items-start justify-between gap-3">
        <p className="flex items-baseline text-ink">
          <span className="text-[64px] font-light leading-none tracking-[-0.03em] tabular-nums">{score}</span>
          <span className="ms-3 text-[15px] text-ink-soft tabular-nums">/ 100</span>
        </p>
        <span className="pt-1">
          <VerdictStamp tone={tone} />
        </span>
      </div>
      <RiskMeter score={score} tone={tone} variant="line" className="mt-3" />
    </>
  );
}

/** White hairline rows: icon in the verdict colour, bold line in the page language, the other language under it. */
export function Reasons({ items, tone, className = "mt-4" }: { items: Bilingual[]; tone: Tone; className?: string }) {
  const { lang } = useLang();
  const Icon = REASON_ICON[tone];
  const other = lang === "ar" ? "en" : "ar";
  return (
    <ul className={`space-y-2 ${className}`}>
      {items.map((r, i) => (
        <li key={i} className="row-card flex gap-3 px-4 py-3">
          <Icon className={`mt-0.5 size-[18px] shrink-0 ${MARK_TEXT[tone]}`} strokeWidth={2.2} aria-hidden />
          <div className="min-w-0 flex-1">
            <p lang={lang} className="line-clamp-2 text-[14px] font-semibold leading-snug text-ink">
              {r[lang] || r[other]}
            </p>
            {r[other] && r[other] !== r[lang] && (
              <p lang={other} dir={other === "ar" ? "rtl" : "ltr"} className="mt-1 line-clamp-2 text-[14px] leading-snug text-ink">
                {r[other]}
              </p>
            )}
          </div>
        </li>
      ))}
    </ul>
  );
}

function CardHeader({ title, chip }: { title: string; chip?: string }) {
  return (
    <div className="flex min-h-6 items-center justify-between gap-3">
      <h2 className="text-[17px] font-bold text-ink">{title}</h2>
      {chip && <span className="chip-tag shrink-0 rtl:tracking-normal">{chip}</span>}
    </div>
  );
}

/** Underlined text link look (the reference's "Report a false alarm"), also applied to FalseAlarmReport's button. */
export const TEXT_LINK =
  "inline-flex min-h-12 items-center text-[14px] font-medium text-ink-soft underline decoration-1 underline-offset-[5px] hover:text-ink";
export const FALSE_ALARM_AS_LINK =
  "[&_[data-testid=false-alarm-open]]:min-h-12 [&_[data-testid=false-alarm-open]]:font-medium [&_[data-testid=false-alarm-open]]:underline [&_[data-testid=false-alarm-open]]:decoration-1 [&_[data-testid=false-alarm-open]]:underline-offset-[5px] [&_[data-testid=false-alarm-open]_svg]:hidden";

function DemoContent({ onDemoAction }: { onDemoAction?: () => void }) {
  const { t } = useLang();
  const [note, setNote] = useState(false);
  return (
    <>
      <CardHeader title={t("vcWhatYouSee")} chip={t("vcDemoChip")} />
      <p className="mt-4 truncate font-mono text-[14px] text-ink" dir="ltr" lang="en">
        {DEMO.target}
      </p>
      <ScoreRow score={DEMO.score} tone="scam" />
      <Reasons items={DEMO.reasons} tone="scam" />
      <div className="mt-auto pt-5">
        <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
          <button type="button" onClick={onDemoAction} className="btn-primary" data-testid="verdict-demo-action">
            {t("vcDontOpen")}
          </button>
          <button type="button" onClick={() => setNote((v) => !v)} aria-expanded={note} className={TEXT_LINK} data-testid="verdict-demo-false-alarm">
            {t("faReport")}
          </button>
        </div>
        {note && <p className="mt-2 text-[13px] text-ink-soft">{t("vcDemoFalseAlarm")}</p>}
      </div>
    </>
  );
}

export function ScanningContent({ state }: { state: Extract<ScanState, { status: "scanning" }> }) {
  const { t } = useLang();
  const steps = scanSteps(state.kind);
  const [step, setStep] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setStep((s) => Math.min(s + 1, steps.length - 1)), state.kind === "email" ? 520 : 650);
    return () => window.clearInterval(id);
  }, [steps.length, state.kind]);
  return (
    <>
      <CardHeader title={t("vcYourResult")} chip={t(CHANNEL_DICT_KEY[state.interception])} />
      <p className="mt-4 truncate font-mono text-[14px] text-ink-soft" dir="ltr" lang="en">
        {visible(state.target)}
      </p>
      <p className="shimmer-text mt-6 text-[22px] font-bold leading-tight tracking-tight text-ink" role="status">
        {t(scanTitle(state.kind))}
      </p>
      <p className="mt-1 text-[14px] text-ink-soft">{t("vcScanningSub")}</p>
      <ul className="mt-6 space-y-3">
        {steps.map((key, i) => (
          <li key={key} className={`flex items-center gap-3 text-[15px] transition-opacity duration-200 ${i <= step ? "opacity-100" : "opacity-40"}`}>
            {i < step ? (
              <CircleCheck className="size-5 shrink-0" aria-hidden />
            ) : i === step ? (
              <RefreshCw className="size-5 shrink-0 animate-spin" aria-hidden />
            ) : (
              <span className="size-5 shrink-0 rounded-full border border-line" aria-hidden />
            )}
            <span>{t(key)}</span>
          </li>
        ))}
      </ul>
    </>
  );
}

export function ErrorContent({ message, onRetry }: { message: string; onRetry: () => void }) {
  const { t } = useLang();
  return (
    <>
      <CardHeader title={t("vcYourResult")} chip={t("vcLiveChip")} />
      <div className="flex flex-1 flex-col items-start justify-center py-8" role="alert">
        <Info className="size-8 text-ink-soft" aria-hidden />
        <p className="mt-3 text-[19px] font-semibold text-ink">{t("scanFailed")}</p>
        <p className="mt-1 text-[14px] text-ink-soft">{message}</p>
        <button type="button" onClick={onRetry} className="btn-primary mt-5" data-testid="verdict-retry">
          {t("retry")}
        </button>
      </div>
    </>
  );
}

/**
 * Live-result actions in the reference's language: black primary (Full report) with the underlined
 * "Report a false alarm" beside it, then outlined secondaries (Warn community on X, Copy Aman report).
 */
export function LiveActions({ result, onFullReport }: { result: ScanVerdict; onFullReport: () => void }) {
  const { t } = useLang();
  const tone = toneOf(result.verdict);
  const canWarn = tone !== "safe" && result.riskScore >= 60;
  const [toast, setToast] = useToast();
  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-x-5 gap-y-1">
        <button type="button" onClick={onFullReport} className="btn-primary" data-testid="verdict-full-report">
          <FileText className="size-4" aria-hidden /> {t("vcFullReport")}
        </button>
        {tone !== "safe" && (
          <div className={`min-w-0 flex-1 basis-40 ${FALSE_ALARM_AS_LINK}`}>
            <FalseAlarmReport key={result.scanId} scanId={result.scanId} compact />
          </div>
        )}
      </div>
      {tone !== "safe" && (
        <div className="grid gap-2 sm:grid-cols-2">
          {canWarn && (
            <WarnOnXButton warning={warningFromVerdict(result)} label={t("vcWarnX")} className="btn-secondary w-full px-3 text-[14px]" testId="verdict-warn-x" />
          )}
          <CopyAmanButton
            warning={warningFromVerdict(result)}
            label={t("vcCopyAman")}
            className={`btn-secondary w-full px-3 text-[14px] ${canWarn ? "" : "sm:col-span-2"}`}
            onDone={(ok) => setToast({ ok, text: ok ? t("amanCopied") : t("copyFailed") })}
          />
        </div>
      )}
      <Toast msg={toast} />
    </div>
  );
}

function LiveContent({ result, onFullReport }: { result: ScanVerdict; onFullReport: () => void }) {
  const { t, lang } = useLang();
  const tone = toneOf(result.verdict);
  const verified = isVerifiedOfficial(result);
  const reasons = topReasons(result);
  const entity = lang === "ar" ? result.entityAr ?? result.entityEn : result.entityEn;
  const official = result.officialDomains[0];
  const advice = tone === "scam" ? t("vcAdviceScam") : tone === "suspicious" ? t("vcAdviceSuspicious") : t("vcAdviceSafe");

  return (
    <>
      <CardHeader title={t("vcYourResult")} chip={t("vcLiveChip")} />
      <p className="mt-4 truncate font-mono text-[14px] text-ink" dir="ltr" lang="en" data-testid="verdict-target">
        {visible(result.kind === "url" ? defang(result.target) : result.target)}
      </p>
      <ScoreRow score={result.riskScore} tone={tone} />

      {verified ? (
        <p className="mt-4 flex items-center gap-2 text-[15px] font-semibold text-brand-ink" data-testid="verdict-verified">
          <BadgeCheck className="size-5 shrink-0" aria-hidden /> {t("vcVerified")}
          {official && (
            <span dir="ltr" className="truncate font-mono text-[13px] font-medium">
              {official}
            </span>
          )}
        </p>
      ) : (
        <p className="mt-4 text-[15px] font-semibold leading-snug text-ink">{advice}</p>
      )}
      {tone !== "safe" && (entity || official) && (
        <p className="mt-1.5 text-[14px] text-ink-soft">
          {entity && (
            <>
              {t("vcPretends")} <span className="font-semibold text-ink">{entity}</span>
            </>
          )}
          {entity && official && " · "}
          {official && (
            <>
              {t("vcOfficial")}:{" "}
              <span dir="ltr" className="font-mono text-[13px] font-semibold text-ink">
                {official}
              </span>
            </>
          )}
        </p>
      )}

      {reasons.length > 0 && <Reasons items={reasons} tone={tone} />}

      <div className="mt-auto pt-5">
        <LiveActions result={result} onFullReport={onFullReport} />
      </div>
    </>
  );
}

export function VerdictCard({
  scan,
  compact = false,
  onFullReport,
  onRetry,
  onDemoAction,
  className = "",
}: {
  scan: ScanState;
  /** Tool windows: smaller reserved height and an empty placeholder instead of the demo sample. */
  compact?: boolean;
  onFullReport: () => void;
  onRetry: () => void;
  /** Demo primary button: brings the resident back to the input. */
  onDemoAction?: () => void;
  className?: string;
}) {
  const { t } = useLang();
  const announce =
    scan.status === "done"
      ? `${t("vcLiveChip")}: ${VERDICT_WORDS[toneOf(scan.result.verdict)].en} · ${scan.result.riskScore} / 100`
      : scan.status === "error"
        ? t("scanFailed")
        : "";
  const key =
    scan.status === "done" ? `done-${scan.result.scanId}` : scan.status === "scanning" ? `scan-${scan.target}` : scan.status;

  return (
    <section
      aria-label={t(scan.status === "idle" && !compact ? "vcWhatYouSee" : "vcYourResult")}
      aria-busy={scan.status === "scanning"}
      data-testid="verdict-card"
      data-state={scan.status === "idle" ? "demo" : scan.status}
      className={`card-glass scroll-mt-36 p-5 sm:p-6 ${compact ? "min-h-[20rem]" : "min-h-[32rem] lg:min-h-[33rem]"} flex flex-col ${className}`}
    >
      <p className="sr-only" aria-live="polite">
        {announce}
      </p>
      <AnimatePresence mode="wait" initial={false}>
        <motion.div
          key={key}
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -4 }}
          transition={{ duration: 0.18, ease: [0.16, 1, 0.3, 1] }}
          className="flex flex-1 flex-col"
        >
          {scan.status === "idle" &&
            (compact ? (
              <>
                <CardHeader title={t("vcEmptyTitle")} />
                <div className="flex flex-1 flex-col items-center justify-center gap-3 py-10 text-center">
                  <ShieldCheck className="size-8 text-ink-soft" aria-hidden />
                  <p className="max-w-[28ch] text-[15px] text-ink-soft">{t("vcEmpty")}</p>
                </div>
              </>
            ) : (
              <DemoContent onDemoAction={onDemoAction} />
            ))}
          {scan.status === "scanning" && <ScanningContent state={scan} />}
          {scan.status === "error" && <ErrorContent message={scan.message} onRetry={onRetry} />}
          {scan.status === "done" && <LiveContent result={scan.result} onFullReport={onFullReport} />}
        </motion.div>
      </AnimatePresence>
    </section>
  );
}
