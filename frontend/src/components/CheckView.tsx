"use client";

import { ArrowLeft, ArrowRight, Check, Mail, MapPinned, MessageSquareText, Radio } from "lucide-react";
import { useState, type ReactNode } from "react";
import { useLang, type DictKey } from "@/lib/i18n";
import type { View } from "@/lib/view";
import { PhoneShieldPanel, type Platform } from "./BackgroundShieldCard";
import { LinkChecker } from "./LinkChecker";
import { ScamAlertsPanel, useScamAlertsOn } from "./ScamAlertsCard";
import { SetupDrawer } from "./SetupDrawer";
import { VerdictCard } from "./VerdictCard";
import type { ScanState } from "./VerdictScreen";

type Drawer = Platform | "alerts" | null;

function SectionHead({ id, title, sub }: { id: string; title: string; sub: string }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-1">
      <h2 id={id} className="text-[20px] font-semibold leading-tight text-ink">
        {title}
      </h2>
      <p className="text-[14px] text-ink-soft">{sub}</p>
    </div>
  );
}

function Step({ n, done, title, body, children }: { n: number; done: boolean; title: string; body: string; children: ReactNode }) {
  const { t } = useLang();
  return (
    <li className="card flex flex-col p-5" data-testid={`step-${n}`} data-done={done || undefined}>
      <div className="flex items-center gap-2">
        {done ? (
          <span className="grid size-8 place-items-center rounded-full bg-primary text-on-primary" aria-hidden>
            <Check className="size-4" />
          </span>
        ) : (
          <span className="grid size-8 place-items-center rounded-full border border-line text-[14px] font-semibold tabular-nums text-ink" aria-hidden>
            {n}
          </span>
        )}
        {done && <span className="text-[13px] font-semibold text-ink">{t("stepDone")}</span>}
        <span className="sr-only">{done ? `${n}. ${t("stepDone")}` : `${n}.`}</span>
      </div>
      <h3 className="mt-3 text-[17px] font-semibold leading-snug text-ink">{title}</h3>
      <p className="mt-1 text-[15px] leading-relaxed text-ink-soft">{body}</p>
      <div className="mt-auto flex flex-wrap gap-2 pt-4">{children}</div>
    </li>
  );
}

const MORE: { view: View; title: DictKey; body: DictKey; icon: typeof Mail; chip?: DictKey }[] = [
  { view: "sms", title: "moreSmsTitle", body: "moreSmsBody", icon: MessageSquareText },
  { view: "email", title: "moreEmailTitle", body: "moreEmailBody", icon: Mail },
  { view: "maps", title: "moreMapsTitle", body: "moreMapsBody", icon: MapPinned },
  // The live feed is real; the scam waves shown with it are partly seeded demo data.
  { view: "live", title: "moreLiveTitle", body: "moreLiveBody", icon: Radio, chip: "demoDataChip" },
];

export function CheckView({
  scan,
  checkedOnce,
  onCheck,
  onCheckMessage,
  onFullReport,
  onRetry,
  onFocusInput,
  onView,
}: {
  scan: ScanState;
  checkedOnce: boolean;
  onCheck: (url: string, rawText?: string) => void;
  onCheckMessage: (text: string, sender?: string) => void;
  onFullReport: () => void;
  onRetry: () => void;
  onFocusInput: () => void;
  onView: (v: View) => void;
}) {
  const { t, dir } = useLang();
  const [drawer, setDrawer] = useState<Drawer>(null);
  // Kept after closing so the drawer keeps its content while it slides out.
  const [platform, setPlatform] = useState<Platform>("ios");
  const openShield = (p: Platform) => {
    setPlatform(p);
    setDrawer(p);
  };
  const alertsOn = useScamAlertsOn();
  const Arrow = dir === "rtl" ? ArrowLeft : ArrowRight;
  const close = () => setDrawer(null);

  return (
    <div className="space-y-14 sm:space-y-16">
      {/* Hero: the question, the input and the verdict card */}
      <section aria-labelledby="view-title" className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_minmax(0,440px)] lg:gap-10">
        <div className="min-w-0 lg:pt-4">
          <p className="label-caps rtl:tracking-normal">{t("heroEyebrow")}</p>
          <h1 id="view-title" tabIndex={-1} className="mt-3 max-w-[18ch] text-[26px] font-bold leading-[1.1] tracking-[-0.02em] text-ink outline-hidden sm:text-[32px] lg:text-[40px] rtl:tracking-normal">
            {t("heroTitle")}
          </h1>
          <p className="mt-4 max-w-[52ch] text-[16px] leading-relaxed text-ink-soft sm:text-[17px]">{t("heroSub")}</p>
          <div className="mt-6">
            <LinkChecker onCheck={onCheck} onCheckMessage={onCheckMessage} />
          </div>
        </div>
        <VerdictCard scan={scan} onFullReport={onFullReport} onRetry={onRetry} onDemoAction={onFocusInput} />
      </section>

      {/* Set up in three steps */}
      <section aria-labelledby="setup-title">
        <SectionHead id="setup-title" title={t("setupTitle")} sub={t("setupSub")} />
        <ol className="mt-5 grid gap-4 md:grid-cols-3">
          <Step n={1} done={checkedOnce} title={t("step1Title")} body={t("step1Body")}>
            <button
              type="button"
              onClick={onFocusInput}
              className="btn-secondary min-h-11 px-4 text-[13px] uppercase tracking-[0.08em] rtl:tracking-normal"
              data-testid="step-check"
            >
              {t("startHere")}
            </button>
          </Step>
          <Step n={2} done={false} title={t("step2Title")} body={t("step2Body")}>
            <button type="button" onClick={() => openShield("ios")} className="btn-secondary min-h-11 px-4 text-[14px]" data-testid="step-shield-ios">
              {t("iphone")}
            </button>
            <button type="button" onClick={() => openShield("android")} className="btn-secondary min-h-11 px-4 text-[14px]" data-testid="step-shield-android">
              {t("android")}
            </button>
          </Step>
          <Step n={3} done={alertsOn} title={t("step3Title")} body={t("step3Body")}>
            <button type="button" onClick={() => setDrawer("alerts")} className="btn-secondary min-h-11 px-4 text-[14px]" data-testid="step-alerts">
              {alertsOn ? t("alertsManage") : t("alertsOpen")}
            </button>
          </Step>
        </ol>
      </section>

      {/* More ways to check */}
      <section aria-labelledby="more-title">
        <SectionHead id="more-title" title={t("moreTitle")} sub={t("moreSub")} />
        <ul className="mt-5 grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {MORE.map(({ view, title, body, icon: Icon, chip }) => (
            <li key={view} className="card flex flex-col p-5">
              <span className="grid size-10 place-items-center rounded-control bg-muted text-ink" aria-hidden>
                <Icon className="size-5" />
              </span>
              <h3 className="mt-3 text-[17px] font-semibold text-ink">{t(title)}</h3>
              <p className="mt-1 text-[15px] leading-relaxed text-ink-soft">{t(body)}</p>
              <div className="mt-auto flex flex-wrap items-center justify-between gap-2 pt-4">
                <button
                  type="button"
                  onClick={() => onView(view)}
                  className="-ms-1 inline-flex min-h-11 items-center gap-1.5 rounded-control px-1 text-[15px] font-semibold text-ink underline-offset-4 hover:underline"
                  data-testid={`open-${view}`}
                  aria-label={`${t("moreOpen")}: ${t(title)}`}
                >
                  {t("moreOpen")} <Arrow className="size-4" aria-hidden />
                </button>
                {chip && <span className="chip">{t(chip)}</span>}
              </div>
            </li>
          ))}
        </ul>
      </section>

      <SetupDrawer
        open={drawer === "ios" || drawer === "android"}
        onClose={close}
        title={platform === "android" ? t("shieldAndroidTitle") : t("shieldIosTitle")}
        testId={`drawer-shield-${platform}`}
      >
        <PhoneShieldPanel key={platform} platform={platform} />
      </SetupDrawer>
      <SetupDrawer open={drawer === "alerts"} onClose={close} title={t("alertsDrawerTitle")} testId="drawer-alerts">
        <ScamAlertsPanel />
      </SetupDrawer>
    </div>
  );
}
