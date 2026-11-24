"use client";

import { ArrowLeft, ArrowRight, Mail, MapPinned, MessageSquareText, Radio } from "lucide-react";
import { useState } from "react";
import { useLang, type DictKey } from "@/lib/i18n";
import type { View } from "@/lib/view";
import { useViewport } from "@/lib/viewport";
import { PhoneShieldPanel, type Platform } from "./BackgroundShieldCard";
import { MobileNotice } from "./CitizenChrome";
import { LinkChecker } from "./LinkChecker";
import { MobileResult } from "./MobileResult";
import { ScamAlertsPanel, useScamAlertsOn } from "./ScamAlertsCard";
import { SetupCards, SetupRows, markSetupStep, useSetupProgress } from "./SetupSteps";
import { SetupDrawer } from "./SetupDrawer";
import { VerdictCard } from "./VerdictCard";
import type { ScanState } from "./VerdictScreen";

type Drawer = Platform | "alerts" | null;

function SectionHead({ id, title, sub }: { id: string; title: string; sub: string }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-x-6 gap-y-1">
      <h2 id={id} className="text-[20px] font-bold leading-tight text-ink">
        {title}
      </h2>
      <p className="text-[14px] text-ink-soft">{sub}</p>
    </div>
  );
}

const MORE: { view: View; title: DictKey; body: DictKey; icon: typeof Mail; chip?: DictKey }[] = [
  { view: "sms", title: "moreSmsTitle", body: "moreSmsBody", icon: MessageSquareText },
  { view: "email", title: "moreEmailTitle", body: "moreEmailBody", icon: Mail },
  { view: "maps", title: "moreMapsTitle", body: "moreMapsBody", icon: MapPinned },
  // The live feed is real; the scam waves shown with it are partly seeded demo data.
  { view: "live", title: "moreLiveTitle", body: "moreLiveBody", icon: Radio, chip: "demoDataChip" },
];

/** Small trailing text action of a phone step row ("Set up", "Turn on"). 48px tall. */
const ROW_ACTION = "inline-flex min-h-12 items-center rounded-control px-2 text-[13px] font-semibold text-brand-ink hover:underline";

/**
 * The home window. Desktop / tablet (>= 768px): hero (question, green check card, "What you will see" card),
 * three setup cards, "More ways to check". Phone: notice card, the short question, the check card and the
 * three setup rows; after a check the phone shows `MobileResult` in place of the home content.
 * Both layouts are in the server HTML (CSS shows one); after hydration only the matching one stays mounted.
 */
export function CheckView({
  scan,
  onCheck,
  onCheckMessage,
  onFullReport,
  onRetry,
  onFocusInput,
  onView,
  onNewCheck,
}: {
  scan: ScanState;
  onCheck: (url: string, rawText?: string) => void;
  onCheckMessage: (text: string, sender?: string) => void;
  onFullReport: () => void;
  onRetry: () => void;
  onFocusInput: () => void;
  onView: (v: View) => void;
  /** Phone result: back to the empty home. */
  onNewCheck: () => void;
}) {
  const { t, dir } = useLang();
  const vp = useViewport();
  const [drawer, setDrawer] = useState<Drawer>(null);
  // Kept after closing so the drawer keeps its content while it slides out.
  const [platform, setPlatform] = useState<Platform>("ios");
  const openShield = (p: Platform) => {
    setPlatform(p);
    setDrawer(p);
    markSetupStep("shield");
  };
  const alertsOn = useScamAlertsOn();
  const { done } = useSetupProgress();
  const Arrow = dir === "rtl" ? ArrowLeft : ArrowRight;
  const close = () => setDrawer(null);

  return (
    <>
      {vp !== "mobile" && (
        <div className="hidden space-y-14 sm:space-y-16 md:block">
          {/* Hero: the question, the input and the verdict card */}
          <section aria-labelledby="view-title" className="grid items-start gap-8 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)] lg:gap-[46px] lg:pt-3">
            <div className="min-w-0 lg:pt-2">
              <p className="text-[12px] leading-snug text-ink-soft">{t("heroEyebrow")}</p>
              <h1
                id="view-title"
                tabIndex={-1}
                className="mt-4 max-w-[17ch] text-[34px] font-extrabold leading-[1.08] tracking-[-0.025em] text-ink outline-hidden lg:text-[44px] rtl:tracking-normal"
              >
                {t("heroTitle")}
              </h1>
              <p className="mt-4 max-w-[54ch] text-[16px] leading-[1.65] text-ink-soft lg:text-[17px]">{t("heroSub")}</p>
              <div className="mt-7">
                <LinkChecker onCheck={onCheck} onCheckMessage={onCheckMessage} />
              </div>
            </div>
            <VerdictCard scan={scan} onFullReport={onFullReport} onRetry={onRetry} onDemoAction={onFocusInput} />
          </section>

          {/* Set up in three steps */}
          <section aria-labelledby="setup-title">
            <SectionHead id="setup-title" title={t("setupTitle")} sub={t("setupSub")} />
            <SetupCards
              steps={[
                {
                  title: "step1Title",
                  body: "step1Body",
                  action: (
                    <button type="button" onClick={onFocusInput} className="-my-3 inline-flex min-h-12 items-center rounded-control" data-testid="step-check">
                      <span className="chip-brand rtl:tracking-normal">{t("startHere")}</span>
                    </button>
                  ),
                },
                {
                  title: "step2Title",
                  body: "step2Body",
                  action: (
                    <>
                      <button type="button" onClick={() => openShield("ios")} className="btn-secondary px-4 text-[14px]" data-testid="step-shield-ios">
                        {t("iphone")}
                      </button>
                      <button type="button" onClick={() => openShield("android")} className="btn-secondary px-4 text-[14px]" data-testid="step-shield-android">
                        {t("android")}
                      </button>
                    </>
                  ),
                },
                {
                  title: "step3Title",
                  body: "step3Body",
                  action: (
                    <button type="button" onClick={() => setDrawer("alerts")} className="btn-secondary px-4 text-[14px]" data-testid="step-alerts">
                      {alertsOn ? t("alertsManage") : t("alertsOpen")}
                    </button>
                  ),
                },
              ]}
            />
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
      )}

      {vp !== "desktop" && (
        <div className="md:hidden">
          {scan.status !== "idle" ? (
            <MobileResult scan={scan} onFullReport={onFullReport} onRetry={onRetry} onNewCheck={onNewCheck} onOpenShield={() => onView("shield")} />
          ) : (
            <>
              <MobileNotice />
              <h1 id="view-title" tabIndex={-1} className="mt-6 text-[30px] font-extrabold leading-[1.08] tracking-[-0.02em] text-ink outline-hidden rtl:tracking-normal">
                {t("mHeroTitle")}
              </h1>
              <p className="mt-2.5 max-w-[36ch] text-[15px] leading-[1.5] text-ink-soft">{t("mHeroSub")}</p>
              <div className="mt-5">
                <LinkChecker onCheck={onCheck} onCheckMessage={onCheckMessage} variant="mobile" />
              </div>
              <section aria-labelledby="setup-title" className="mt-7">
                <h2 id="setup-title" className="text-[14px] font-bold text-ink">
                  {t("mStepsTitle")}
                </h2>
                <p className="mt-0.5 text-[13px] text-ink-soft">{t("mStepsSub")}</p>
                <SetupRows
                  steps={[
                    {
                      title: "step1Title",
                      body: "mStep1Body",
                      doneBody: "mStep1Done",
                      action: done[0] ? null : (
                        <button type="button" onClick={onFocusInput} className={ROW_ACTION} data-testid="step-check">
                          {t("mStepCheck")}
                        </button>
                      ),
                    },
                    {
                      title: "step2Title",
                      body: "mStep2Body",
                      doneBody: "mStep2Done",
                      action: (
                        <button type="button" onClick={() => onView("shield")} className={ROW_ACTION} data-testid="step-shield">
                          {t(done[1] ? "mrReview" : "mStepSetUp")}
                        </button>
                      ),
                    },
                    {
                      title: "step3Title",
                      body: "mStep3Body",
                      doneBody: "mStep3Done",
                      action: (
                        <button type="button" onClick={() => onView("alerts")} className={ROW_ACTION} data-testid="step-alerts">
                          {t(alertsOn ? "mStepManage" : "mStepTurnOn")}
                        </button>
                      ),
                    },
                  ]}
                />
              </section>
            </>
          )}
        </div>
      )}
    </>
  );
}
