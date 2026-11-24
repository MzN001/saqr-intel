"use client";

import { ArrowLeft, ArrowRight, CircleCheck, Lock, type LucideIcon } from "lucide-react";
import type { ScanVerdict } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";
import { defang } from "@/lib/share";
import { RiskMeter, toneOf, type Tone } from "./RiskMeter";
import { useSetupProgress } from "./SetupSteps";
import { ErrorContent, LiveActions, MARK_TEXT, Reasons, ScanningContent, TEXT_LINK, topReasons, VERDICT_WORDS } from "./VerdictCard";
import { isVerifiedOfficial, visible, type ScanState } from "./VerdictScreen";

/*
 * Phone result (< 768px), shown in place of the home content after a check (design-refs/citizen-mobile-reference.jpg,
 * right screen): "You checked" + target, ring gauge + verdict headline, the three-colour meter with a knob,
 * up to three reason rows, the phone-shield row, actions for warnings, a privacy footnote.
 * Every safe-result row is derived from a real field of the result; a fact that is not known is left out.
 */

const HEADLINE: Record<Tone, DictKey> = { safe: "mrHeadSafe", suspicious: "mrHeadSuspicious", scam: "mrHeadScam" };
const RING_STROKE: Record<Tone, string> = { safe: "stroke-brand", suspicious: "stroke-suspicious", scam: "stroke-scam-mark" };

const R = 37;
const C = 2 * Math.PI * R;

function Ring({ score, tone }: { score: number; tone: Tone }) {
  const value = Math.max(0, Math.min(100, Math.round(score)));
  return (
    <div className="relative size-[84px] shrink-0" aria-hidden>
      <svg viewBox="0 0 84 84" className="size-full -rotate-90 rtl:-scale-y-100">
        <circle cx="42" cy="42" r={R} fill="none" strokeWidth="7" className="stroke-meter-track" />
        <circle
          cx="42"
          cy="42"
          r={R}
          fill="none"
          strokeWidth="7"
          strokeLinecap="round"
          strokeDasharray={C}
          strokeDashoffset={C * (1 - value / 100)}
          className={`${RING_STROKE[tone]} transition-[stroke-dashoffset] duration-700 ease-[cubic-bezier(0.16,1,0.3,1)]`}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center leading-none text-ink">
        <span className="text-[26px] font-light tabular-nums">{value}</span>
        <span className="mt-0.5 text-[11px] text-ink-soft tabular-nums">/ 100</span>
      </div>
    </div>
  );
}

type Row = { key: DictKey; icon: LucideIcon };

/** Safe-result rows, each only when the result proves it. */
function safeRows(r: ScanVerdict): Row[] {
  const rows: Row[] = [];
  if (isVerifiedOfficial(r)) {
    const host = (r.scamDomain ?? r.target ?? "").toLowerCase();
    rows.push({ key: host === "gov.ae" || host.endsWith(".gov.ae") ? "mrRowGovAe" : "mrRowOfficial", icon: CircleCheck });
  }
  if (r.kind === "url" && r.sslValid === true) rows.push({ key: "mrRowTls", icon: Lock });
  if (r.kind === "url" && r.pageChecked && r.harvested.length === 0) rows.push({ key: "mrRowNoHarvest", icon: CircleCheck });
  return rows;
}

function ShieldRow({ onOpenShield }: { onOpenShield: () => void }) {
  const { t } = useLang();
  const { done } = useSetupProgress();
  const set = done[1];
  return (
    <div className="flex items-center gap-3 rounded-inner border border-line bg-surface py-3 ps-4 pe-2" data-testid="mobile-shield-row">
      <span className="grid size-[34px] shrink-0 place-items-center rounded-[10px] border border-brand-line bg-brand-soft text-brand-ink" aria-hidden>
        <Lock className="size-4" />
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-[14px] font-semibold leading-snug text-ink">{t(set ? "mrShieldSet" : "mrShieldOff")}</p>
        <p className="text-[12px] leading-snug text-ink-soft">{t(set ? "mrShieldSetBody" : "mrShieldOffBody")}</p>
      </div>
      <button type="button" onClick={onOpenShield} className="min-h-12 shrink-0 rounded-control px-2 text-[13px] font-semibold text-brand-ink hover:underline">
        {t(set ? "mrReview" : "mStepSetUp")}
      </button>
    </div>
  );
}

function Done({ result, onFullReport, onOpenShield }: { result: ScanVerdict; onFullReport: () => void; onOpenShield: () => void }) {
  const { t, lang } = useLang();
  const tone = toneOf(result.verdict);
  const verified = isVerifiedOfficial(result);
  const entity = lang === "ar" ? result.entityAr ?? result.entityEn : result.entityEn;
  const fill = (key: DictKey, x: string) => t(key).replace("{x}", x);
  const line =
    tone === "safe"
      ? verified
        ? entity
          ? fill("mrOfficialOf", entity)
          : t("mrOfficialSite")
        : t("mrNoSigns")
      : entity
        ? fill("mrPretendsTo", entity)
        : tone === "scam"
          ? t("vcDontOpen")
          : t("vcAdviceSuspicious");
  const rows = tone === "safe" ? safeRows(result) : [];
  const reasons = rows.length ? [] : topReasons(result);

  return (
    <div data-testid="mobile-result-done">
      <p className="text-[11px] font-semibold tracking-[0.02em] text-ink-soft">{t("mrYouChecked")}</p>
      <p className="mt-0.5 break-all font-mono text-[14px] text-ink" dir="ltr" lang="en" data-testid="verdict-target">
        {visible(result.kind === "url" ? defang(result.target) : result.target)}
      </p>

      <div className="mt-3.5 flex items-center gap-4">
        <Ring score={result.riskScore} tone={tone} />
        <div className="min-w-0">
          <p className={`text-[21px] font-extrabold leading-[1.05] tracking-[-0.01em] ${MARK_TEXT[tone]}`} data-testid="mobile-verdict-headline">
            {t(HEADLINE[tone])}
          </p>
          <p className="mt-1.5 text-[14px] font-bold leading-snug text-ink-soft">{line}</p>
        </div>
      </div>

      <RiskMeter score={result.riskScore} variant="knob" className="mt-4" />

      {rows.length > 0 && (
        <ul className="mt-4 space-y-2">
          {rows.map(({ key, icon: Icon }) => (
            <li key={key} className="row-card flex items-start gap-2.5 px-3 py-[11px]">
              <Icon className={`mt-px size-[18px] shrink-0 ${MARK_TEXT[tone]}`} strokeWidth={2} aria-hidden />
              <span className="text-[14px] font-medium leading-[1.4] text-ink">{t(key)}</span>
            </li>
          ))}
        </ul>
      )}
      {reasons.length > 0 && <Reasons items={reasons} tone={tone} />}

      <div className="mt-4">
        <ShieldRow onOpenShield={onOpenShield} />
      </div>

      <div className="mt-4">
        {tone === "safe" ? (
          <button type="button" onClick={onFullReport} className={TEXT_LINK} data-testid="verdict-full-report">
            {t("vcFullReport")}
          </button>
        ) : (
          <LiveActions result={result} onFullReport={onFullReport} />
        )}
      </div>

      <p className="mt-3 text-[12px] leading-normal text-ink-soft">{tone === "safe" ? t("mrFootSafe") : t("privacyLine")}</p>
      <p className="sr-only" aria-live="polite">{`${t("vcLiveChip")}: ${VERDICT_WORDS[tone].en} · ${result.riskScore} / 100`}</p>
    </div>
  );
}

export function MobileResult({
  scan,
  onFullReport,
  onRetry,
  onNewCheck,
  onOpenShield,
}: {
  scan: Exclude<ScanState, { status: "idle" }>;
  onFullReport: () => void;
  onRetry: () => void;
  onNewCheck: () => void;
  onOpenShield: () => void;
}) {
  const { t, dir } = useLang();
  const Back = dir === "rtl" ? ArrowRight : ArrowLeft;
  return (
    <section aria-label={t("vcYourResult")} aria-busy={scan.status === "scanning"} data-testid="mobile-result" data-state={scan.status}>
      <button
        type="button"
        onClick={onNewCheck}
        className="-ms-1 mb-2 inline-flex min-h-12 items-center gap-1.5 rounded-control px-1 text-[14px] font-semibold text-ink-soft hover:text-ink"
        data-testid="mobile-new-check"
      >
        <Back className="size-4" aria-hidden /> {t("mrNewCheck")}
      </button>
      <h1 id="view-title" tabIndex={-1} className="sr-only">
        {t("vcYourResult")}
      </h1>
      {scan.status === "done" ? (
        <Done result={scan.result} onFullReport={onFullReport} onOpenShield={onOpenShield} />
      ) : (
        <div className="flex min-h-[24rem] flex-col rounded-tile border border-line bg-surface p-5">
          {scan.status === "scanning" ? <ScanningContent state={scan} /> : <ErrorContent message={scan.message} onRetry={onRetry} />}
        </div>
      )}
    </section>
  );
}
