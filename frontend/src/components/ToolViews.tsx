"use client";

import { ArrowLeft, ArrowRight, ChevronLeft, ChevronRight, Info, Mail, MapPinned, MessageSquareText } from "lucide-react";
import { useEffect, useId, useState, type FormEvent, type ReactNode } from "react";
import { MESSAGE_MAX_CHARS, type EmailScanInput, type MapsScanInput, type ScanVerdict } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";
import type { View } from "@/lib/view";
import { AwarenessRadar } from "./AwarenessRadar";
import { PhoneShieldPanel, type Platform } from "./BackgroundShieldCard";
import { ScamAlertsPanel } from "./ScamAlertsCard";
import { ApkDownloadRow } from "./SetupDrawer";
import { markSetupStep } from "./SetupSteps";
import { EmailGuard } from "./EmailGuard";
import { MapsListingCheck } from "./MapsListingCheck";
import { SearchMapsShield } from "./SearchMapsShield";
import { SmsGuard } from "./SmsGuard";
import { VerdictCard } from "./VerdictCard";
import type { ScanState } from "./VerdictScreen";

/**
 * A focused window: back link, one title, one line of intro, then just that tool.
 * Back link: desktop -> the link checker. Phone: the SMS / Email / Maps tools -> "Learn" (their tab); the
 * tab windows themselves (shield, alerts, learn) have no back link on phones: the bottom navigation is there.
 */
function ToolWindow({
  title,
  intro,
  onBack,
  onMobileBack,
  children,
}: {
  title: string;
  intro: string;
  onBack: () => void;
  onMobileBack?: () => void;
  children: ReactNode;
}) {
  const { t, dir } = useLang();
  const Back = dir === "rtl" ? ArrowRight : ArrowLeft;
  const backCls = "-ms-1 min-h-11 items-center gap-1.5 rounded-control px-1 text-[14px] font-semibold text-ink-soft hover:text-ink";
  return (
    <div>
      <button type="button" onClick={onBack} className={`hidden md:inline-flex ${backCls}`} data-testid="back-to-check">
        <Back className="size-4" aria-hidden /> {t("backToCheck")}
      </button>
      {onMobileBack && (
        <button type="button" onClick={onMobileBack} className={`inline-flex min-h-12 md:hidden ${backCls}`} data-testid="back-to-learn">
          <Back className="size-4" aria-hidden /> {t("backToLearn")}
        </button>
      )}
      <h1 id="view-title" tabIndex={-1} className="mt-2 text-[26px] max-md:mt-0 font-bold leading-[1.1] tracking-[-0.02em] text-ink outline-hidden sm:text-[32px] rtl:tracking-normal">
        {title}
      </h1>
      <p className="mt-2 max-w-[68ch] text-[16px] leading-relaxed text-ink-soft">{intro}</p>
      <div className="mt-8">{children}</div>
    </div>
  );
}

/** "Check a text message" for the SMS window: the same message scan as the home input, with room to paste. */
function MessageCheck({ onCheck }: { onCheck: (text: string, sender?: string) => void }) {
  const { t } = useLang();
  const id = useId();
  const [text, setText] = useState("");
  const [sender, setSender] = useState("");
  const [empty, setEmpty] = useState(false);
  const submit = (e: FormEvent) => {
    e.preventDefault();
    const value = text.trim();
    if (!value) {
      setEmpty(true);
      return;
    }
    setEmpty(false);
    onCheck(value, sender.trim() || undefined);
  };
  return (
    <section aria-labelledby={`${id}-title`} className="card p-5 sm:p-6" data-testid="message-check">
      <h2 id={`${id}-title`} className="text-[20px] font-semibold leading-tight text-ink">
        {t("msgCheckTitle")}
      </h2>
      <form onSubmit={submit} noValidate className="mt-4 grid gap-3">
        <label htmlFor={`${id}-text`} className="sr-only">
          {t("msgCheckTitle")}
        </label>
        <textarea
          id={`${id}-text`}
          value={text}
          onChange={(e) => {
            setText(e.target.value.slice(0, MESSAGE_MAX_CHARS));
            if (empty) setEmpty(false);
          }}
          rows={4}
          dir="auto"
          placeholder={t("msgCheckPlaceholder")}
          aria-invalid={empty || undefined}
          aria-describedby={empty ? `${id}-error` : undefined}
          className={`field resize-y py-3 leading-relaxed ${empty ? "border-ink" : ""}`}
          data-testid="message-check-input"
        />
        <div className="grid gap-1.5">
          <label htmlFor={`${id}-sender`} className="text-[13px] font-semibold text-ink">
            {t("msgSenderLabel")} <span className="font-normal text-ink-soft">({t("msgSenderOptional")})</span>
          </label>
          <input
            id={`${id}-sender`}
            type="text"
            dir="ltr"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            maxLength={64}
            value={sender}
            onChange={(e) => setSender(e.target.value)}
            placeholder={t("msgSenderPlaceholder")}
            className="field"
          />
        </div>
        {empty && (
          <p id={`${id}-error`} role="alert" className="flex items-center gap-1.5 text-[14px] font-medium text-ink">
            <Info className="size-4 shrink-0" aria-hidden /> {t("msgCheckEmpty")}
          </p>
        )}
        <button type="submit" className="btn-primary w-full sm:w-auto sm:justify-self-start" data-testid="message-check-submit">
          {t("checkMessageButton")}
        </button>
      </form>
    </section>
  );
}

/** Phone "Shield" tab (also a desktop window): pick iPhone / Android, then the same setup as the drawer. */
function ShieldWindow() {
  const { t } = useLang();
  const [platform, setPlatform] = useState<Platform>("ios");
  // Opening the setup is what step 2 can honestly record (a web page cannot see the phone's DNS setting).
  useEffect(() => markSetupStep("shield"), []);
  return (
    <div className="max-w-2xl space-y-4">
      <div role="radiogroup" aria-label={t("shieldPick")} className="inline-flex rounded-full border border-line bg-surface p-1" dir="ltr">
        {(["ios", "android"] as const).map((p) => (
          <button
            key={p}
            type="button"
            role="radio"
            aria-checked={platform === p}
            onClick={() => setPlatform(p)}
            data-testid={`shield-pick-${p}`}
            className={`min-h-11 rounded-full px-5 text-[14px] font-semibold transition-colors ${platform === p ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"}`}
          >
            {t(p === "ios" ? "iphone" : "android")}
          </button>
        ))}
      </div>
      <section className="rounded-tile border border-line bg-surface p-5 sm:p-6" aria-label={t(p2title(platform))}>
        <h2 className="mb-4 text-[17px] font-semibold text-ink">{t(p2title(platform))}</h2>
        <PhoneShieldPanel key={platform} platform={platform} />
        {platform === "android" && <ApkDownloadRow />}
      </section>
    </div>
  );
}
const p2title = (p: Platform): DictKey => (p === "android" ? "shieldAndroidTitle" : "shieldIosTitle");

/** Phone "Alerts" tab: scam-alert setup, then the live feed (official warnings arrive as the banner above). */
function AlertsWindow() {
  const { t } = useLang();
  return (
    <div className="space-y-8">
      <section className="max-w-2xl rounded-tile border border-line bg-surface p-5 sm:p-6" aria-labelledby="alerts-setup-title">
        <h2 id="alerts-setup-title" className="mb-4 text-[17px] font-semibold text-ink">
          {t("alertsDrawerTitle")}
        </h2>
        <ScamAlertsPanel />
      </section>
      <section aria-labelledby="alerts-live-title" className="min-w-0">
        <h2 id="alerts-live-title" className="mb-4 text-[20px] font-bold text-ink">
          {t("alertsLiveTitle")}
        </h2>
        <AwarenessRadar />
      </section>
    </div>
  );
}

const LEARN: { view: View; title: DictKey; body: DictKey; icon: typeof Mail }[] = [
  { view: "sms", title: "moreSmsTitle", body: "moreSmsBody", icon: MessageSquareText },
  { view: "email", title: "moreEmailTitle", body: "moreEmailBody", icon: Mail },
  { view: "maps", title: "moreMapsTitle", body: "moreMapsBody", icon: MapPinned },
];

/** Phone "Learn" tab: more ways to check, one row per tool window. */
function LearnWindow({ onView }: { onView: (v: View) => void }) {
  const { t, dir } = useLang();
  const Chevron = dir === "rtl" ? ChevronLeft : ChevronRight;
  return (
    <ul className="max-w-2xl space-y-[9px]">
      {LEARN.map(({ view, title, body, icon: Icon }) => (
        <li key={view}>
          <button
            type="button"
            onClick={() => onView(view)}
            className="flex min-h-[72px] w-full items-center gap-3 rounded-inner border border-line bg-surface px-4 py-3 text-start transition-colors hover:bg-muted"
            data-testid={`open-${view}`}
          >
            <span className="grid size-[34px] shrink-0 place-items-center rounded-[10px] border border-line bg-surface text-ink" aria-hidden>
              <Icon className="size-4" />
            </span>
            <span className="min-w-0 flex-1">
              <span className="block text-[15px] font-semibold text-ink">{t(title)}</span>
              <span className="block text-[13px] leading-snug text-ink-soft">{t(body)}</span>
            </span>
            <Chevron className="size-4 shrink-0 text-ink-soft" aria-hidden />
          </button>
        </li>
      ))}
    </ul>
  );
}

export function ToolView({
  view,
  scan,
  onBack,
  onView,
  onFullReport,
  onRetry,
  runDnsScan,
  runListingScan,
  runMessageScan,
  runEmailScan,
  onSmsVerdict,
}: {
  view: Exclude<View, "check">;
  scan: ScanState;
  onBack: () => void;
  onView: (v: View) => void;
  onFullReport: () => void;
  onRetry: () => void;
  runDnsScan: (target: string, job: () => Promise<ScanVerdict>) => void;
  runListingScan: (input: MapsScanInput) => void;
  runMessageScan: (text: string, sender?: string) => void;
  runEmailScan: (input: EmailScanInput, target: string) => void;
  onSmsVerdict: (v: ScanVerdict, how: "auto" | "open") => void;
}) {
  const { t } = useLang();
  const card = <VerdictCard scan={scan} compact onFullReport={onFullReport} onRetry={onRetry} />;
  const toLearn = () => onView("learn");

  if (view === "shield") {
    return (
      <ToolWindow title={t("shieldViewTitle")} intro={t("shieldViewIntro")} onBack={onBack}>
        <ShieldWindow />
      </ToolWindow>
    );
  }
  if (view === "alerts") {
    return (
      <ToolWindow title={t("alertsDrawerTitle")} intro={t("alertsViewIntro")} onBack={onBack}>
        <AlertsWindow />
      </ToolWindow>
    );
  }
  if (view === "learn") {
    return (
      <ToolWindow title={t("moreTitle")} intro={t("learnViewIntro")} onBack={onBack}>
        <LearnWindow onView={onView} />
      </ToolWindow>
    );
  }

  if (view === "maps") {
    return (
      <ToolWindow title={t("moreMapsTitle")} intro={t("searchIntro")} onBack={onBack} onMobileBack={toLearn}>
        <div className="grid grid-cols-1 items-start gap-8 lg:grid-cols-[auto_minmax(0,1fr)]">
          <SearchMapsShield runScan={runDnsScan} />
          <div className="min-w-0 space-y-6 lg:sticky lg:top-24">
            <MapsListingCheck onCheck={runListingScan} />
            {card}
          </div>
        </div>
      </ToolWindow>
    );
  }
  if (view === "sms") {
    return (
      <ToolWindow title={t("moreSmsTitle")} intro={t("viewSmsIntro")} onBack={onBack} onMobileBack={toLearn}>
        <div className="grid grid-cols-1 items-start gap-8 lg:grid-cols-[minmax(0,1fr)_auto]">
          <div className="min-w-0 space-y-6 lg:order-2 lg:w-[390px]">
            <MessageCheck onCheck={runMessageScan} />
            {card}
          </div>
          <section aria-labelledby="sms-demo-title" className="min-w-0 lg:order-1">
            <h2 id="sms-demo-title" className="label-caps mb-3 text-center rtl:tracking-normal lg:text-start">
              {t("smsDemoTitle")}
            </h2>
            <SmsGuard onVerdict={onSmsVerdict} />
          </section>
        </div>
      </ToolWindow>
    );
  }
  if (view === "email") {
    return (
      <ToolWindow title={t("moreEmailTitle")} intro={t("emIntro")} onBack={onBack} onMobileBack={toLearn}>
        <div className="grid grid-cols-1 items-start gap-8 lg:grid-cols-[minmax(0,1fr)_380px]">
          <div className="min-w-0">
            <EmailGuard onScan={runEmailScan} />
          </div>
          <div className="min-w-0 lg:sticky lg:top-24">{card}</div>
        </div>
      </ToolWindow>
    );
  }
  return (
    <ToolWindow title={t("moreLiveTitle")} intro={t("viewLiveIntro")} onBack={onBack}>
      <AwarenessRadar />
    </ToolWindow>
  );
}
