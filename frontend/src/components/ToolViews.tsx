"use client";

import { ArrowLeft, ArrowRight, Info } from "lucide-react";
import { useId, useState, type FormEvent, type ReactNode } from "react";
import { MESSAGE_MAX_CHARS, type EmailScanInput, type MapsScanInput, type ScanVerdict } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import type { View } from "@/lib/view";
import { AwarenessRadar } from "./AwarenessRadar";
import { EmailGuard } from "./EmailGuard";
import { MapsListingCheck } from "./MapsListingCheck";
import { SearchMapsShield } from "./SearchMapsShield";
import { SmsGuard } from "./SmsGuard";
import { VerdictCard } from "./VerdictCard";
import type { ScanState } from "./VerdictScreen";

/** A focused window: back link, one title, one line of intro, then just that tool. */
function ToolWindow({ title, intro, onBack, children }: { title: string; intro: string; onBack: () => void; children: ReactNode }) {
  const { t, dir } = useLang();
  const Back = dir === "rtl" ? ArrowRight : ArrowLeft;
  return (
    <div>
      <button
        type="button"
        onClick={onBack}
        className="-ms-1 inline-flex min-h-11 items-center gap-1.5 rounded-control px-1 text-[14px] font-semibold text-ink-soft hover:text-ink"
        data-testid="back-to-check"
      >
        <Back className="size-4" aria-hidden /> {t("backToCheck")}
      </button>
      <h1 id="view-title" tabIndex={-1} className="mt-2 text-[26px] font-bold leading-[1.1] tracking-[-0.02em] text-ink outline-hidden sm:text-[32px] rtl:tracking-normal">
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

export function ToolView({
  view,
  scan,
  onBack,
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

  if (view === "maps") {
    return (
      <ToolWindow title={t("moreMapsTitle")} intro={t("searchIntro")} onBack={onBack}>
        <div className="grid items-start gap-8 lg:grid-cols-[auto_minmax(0,1fr)]">
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
      <ToolWindow title={t("moreSmsTitle")} intro={t("viewSmsIntro")} onBack={onBack}>
        <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_auto]">
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
      <ToolWindow title={t("moreEmailTitle")} intro={t("emIntro")} onBack={onBack}>
        <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_380px]">
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
