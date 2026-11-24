"use client";

import { AnimatePresence, motion } from "framer-motion";
import { BadgeCheck, CircleAlert, CircleCheck, FileText, Info, RefreshCw, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { useEffect, useState } from "react";
import type { ScanVerdict } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { CHANNEL_DICT_KEY, defang, warningFromVerdict } from "@/lib/share";
import { RiskMeter, TONE_CHIP, toneOf, type Tone } from "./RiskMeter";
import { FalseAlarmReport, isVerifiedOfficial, scanSteps, scanTitle, stripBullets, visible, type ScanState } from "./VerdictScreen";
import { CopyAmanButton, Toast, useToast, WarnOnXButton } from "./XAlertComposer";

/*
 * "What you will see" card. Idle: a static DEMO EXAMPLE (or, in the compact tool windows, an empty
 * placeholder). While a check runs it shows the scanning steps in place (no full-screen takeover), then the
 * LIVE VERDICT for any kind of check (link, message, email, Maps): every result is a `ScanVerdict`.
 * The card reserves its height so the page below does not jump when the state changes.
 */

type Bilingual = { en: string; ar: string };

const DEMO = {
  target: "tamm-fines-abudhabi[.]com",
  score: 92,
  reasons: [
    { en: "Pretends to be TAMM, but it is not a gov.ae website", ar: "يدّعي أنه تم، لكنه ليس موقعاً حكومياً" },
    { en: "Asks for your card details to pay a fine", ar: "يطلب بيانات بطاقتك لدفع مخالفة" },
    { en: "Website address was created only days ago", ar: "عنوان الموقع أُنشئ قبل أيام فقط" },
  ] as Bilingual[],
};

const VERDICT_WORDS: Record<Tone, Bilingual> = {
  scam: { en: "HIGH-RISK SCAM", ar: "احتيال عالي الخطورة" },
  suspicious: { en: "SUSPICIOUS", ar: "مشبوه" },
  safe: { en: "SAFE", ar: "آمن" },
};

const REASON_ICON: Record<Tone, { icon: typeof CircleAlert; cls: string }> = {
  scam: { icon: CircleAlert, cls: "text-scam-ink" },
  suspicious: { icon: TriangleAlert, cls: "text-suspicious-ink" },
  safe: { icon: CircleCheck, cls: "text-safe-ink" },
};

function firstSentence(text: string): string {
  const flat = text.replace(/\s+/g, " ").trim();
  const m = /^(.{20,220}?[.!؟?])(\s|$)/.exec(flat);
  return m ? m[1] : flat.slice(0, 200);
}

/** Top three reasons in both languages: the strongest red flags, else the first sentence of the explanation. */
function topReasons(r: ScanVerdict): Bilingual[] {
  const flags = [...r.redFlags]
    .sort((a, b) => b.points - a.points)
    .slice(0, 3)
    .map((f) => ({ en: f.en, ar: f.ar }));
  if (flags.length) return flags;
  const en = firstSentence(stripBullets(r.explanationEn ?? ""));
  const ar = firstSentence(stripBullets(r.explanationAr ?? ""));
  return en || ar ? [{ en, ar }] : [];
}

/** The verdict word in both languages, on a soft chip of its colour (the "stamp"). */
function VerdictStamp({ tone }: { tone: Tone }) {
  const Icon = tone === "safe" ? ShieldCheck : tone === "suspicious" ? TriangleAlert : ShieldAlert;
  const words = VERDICT_WORDS[tone];
  return (
    <span className={`${TONE_CHIP[tone]} min-h-0 flex-col items-end gap-1 rounded-control px-3 py-2 text-end leading-tight`} data-testid="verdict-stamp">
      <span lang="en" dir="ltr" className="inline-flex items-center gap-1.5 text-[12px] font-bold tracking-wide">
        <Icon className="size-3.5" aria-hidden /> {words.en}
      </span>
      <span lang="ar" dir="rtl" className="text-[13px] font-semibold">
        {words.ar}
      </span>
    </span>
  );
}

function ScoreRow({ score, tone }: { score: number; tone: Tone }) {
  return (
    <>
      <div className="mt-3 flex items-center justify-between gap-3">
        <p className="text-ink">
          <span className="text-[44px] font-bold leading-none tracking-tight tabular-nums">{score}</span>
          <span className="ms-1.5 text-[15px] text-ink-soft tabular-nums">/ 100</span>
        </p>
        <VerdictStamp tone={tone} />
      </div>
      <RiskMeter score={score} className="mt-4" />
    </>
  );
}

function Reasons({ items, tone }: { items: Bilingual[]; tone: Tone }) {
  const { lang } = useLang();
  const { icon: Icon, cls } = REASON_ICON[tone];
  const other = lang === "ar" ? "en" : "ar";
  return (
    <ul className="mt-5 space-y-2">
      {items.map((r, i) => (
        <li key={i} className="flex gap-3 rounded-control bg-muted px-3 py-2.5">
          <Icon className={`mt-0.5 size-4 shrink-0 ${cls}`} aria-hidden />
          <div className="min-w-0">
            <p lang={lang} className="line-clamp-2 text-[14px] font-semibold leading-snug text-ink">
              {r[lang] || r[other]}
            </p>
            {r[other] && r[other] !== r[lang] && (
              <p lang={other} dir={other === "ar" ? "rtl" : "ltr"} className="mt-0.5 line-clamp-2 text-[13px] leading-snug text-ink-soft">
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
      <h2 className="text-[17px] font-semibold text-ink">{title}</h2>
      {chip && <span className="chip shrink-0 uppercase tracking-[0.08em] rtl:tracking-normal">{chip}</span>}
    </div>
  );
}

function DemoContent({ onDemoAction }: { onDemoAction?: () => void }) {
  const { t } = useLang();
  return (
    <>
      <CardHeader title={t("vcWhatYouSee")} chip={t("vcDemoChip")} />
      <p className="mt-4 truncate font-mono text-[14px] text-ink" dir="ltr">
        {DEMO.target}
      </p>
      <ScoreRow score={DEMO.score} tone="scam" />
      <Reasons items={DEMO.reasons} tone="scam" />
      <div className="mt-auto pt-5">
        <button type="button" onClick={onDemoAction} className="btn-primary w-full sm:w-auto" data-testid="verdict-demo-action">
          {t("vcDontOpen")}
        </button>
      </div>
    </>
  );
}

function ScanningContent({ state }: { state: Extract<ScanState, { status: "scanning" }> }) {
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
      <p className="mt-4 truncate font-mono text-[14px] text-ink-soft" dir="ltr">
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

function ErrorContent({ message, onRetry }: { message: string; onRetry: () => void }) {
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

function LiveContent({ result, onFullReport }: { result: ScanVerdict; onFullReport: () => void }) {
  const { t, lang } = useLang();
  const tone = toneOf(result.verdict);
  const verified = isVerifiedOfficial(result);
  const reasons = topReasons(result);
  const entity = lang === "ar" ? result.entityAr ?? result.entityEn : result.entityEn;
  const official = result.officialDomains[0];
  const canWarn = tone !== "safe" && result.riskScore >= 60;
  const [toast, setToast] = useToast();
  const advice = tone === "scam" ? t("vcAdviceScam") : tone === "suspicious" ? t("vcAdviceSuspicious") : t("vcAdviceSafe");

  return (
    <>
      <CardHeader title={t("vcYourResult")} chip={t("vcLiveChip")} />
      <p className="mt-4 truncate font-mono text-[14px] text-ink" dir="ltr" data-testid="verdict-target">
        {visible(result.kind === "url" ? defang(result.target) : result.target)}
      </p>
      <ScoreRow score={result.riskScore} tone={tone} />

      {verified ? (
        <p className="mt-4 flex items-center gap-2 text-[15px] font-semibold text-safe-ink" data-testid="verdict-verified">
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

      <div className="mt-auto space-y-2 pt-5">
        <button type="button" onClick={onFullReport} className="btn-primary w-full" data-testid="verdict-full-report">
          <FileText className="size-4" aria-hidden /> {t("vcFullReport")}
        </button>
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
        {tone !== "safe" && <FalseAlarmReport key={result.scanId} scanId={result.scanId} compact />}
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
      className={`card scroll-mt-36 p-5 sm:p-6 ${compact ? "min-h-[20rem]" : "min-h-[32rem] lg:min-h-[38rem]"} flex flex-col ${className}`}
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
