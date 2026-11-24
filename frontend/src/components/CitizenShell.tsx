"use client";

import { AnimatePresence, MotionConfig, motion } from "framer-motion";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  analyzeEmail,
  analyzeMessage,
  analyzeUrl,
  getAlertVerdict,
  scanMaps,
  type EmailScanInput,
  type InterceptionChannel,
  type MapsScanInput,
  type ScanVerdict,
} from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { hostOf, isMapsUrl } from "@/lib/url";
import type { MobileTab, View } from "@/lib/view";
import { isMobileViewport, useViewport } from "@/lib/viewport";
import { CheckView } from "./CheckView";
import { BottomNav, CitizenFooter, CitizenHeader, NoticeStrip } from "./CitizenChrome";
import { CHECK_INPUT_ID } from "./LinkChecker";
import { OfficialWarningBanner } from "./OfficialWarningBanner";
import { isDemoScamUrl } from "./SearchMapsShield";
import { SetupDrawer } from "./SetupDrawer";
import { markSetupStep, useSetupProgress } from "./SetupSteps";
import { ToolView } from "./ToolViews";
import { ResultView, VerdictScreen, type ScanState } from "./VerdictScreen";

const sleep = (ms: number) => new Promise((r) => window.setTimeout(r, ms));

/**
 * How a result is shown:
 *  - "inline": the VerdictCard next to the tool (manual checks: link, message, email, Maps listing, the SMS
 *    guard quarantining by itself). The resident is checking something; the answer belongs beside the input.
 *  - "full": the full-screen block page (share target, scam-alert notification, DNS / tapped-link block).
 *    The resident was about to open something, so the warning takes over the screen before anything else.
 */
type Presentation = "inline" | "full";

type Job = {
  target: string;
  interception: InterceptionChannel;
  job: () => Promise<ScanVerdict>;
  kind?: ScanVerdict["kind"];
  present: Presentation;
};

/**
 * Home backdrop (desktop / tablet, `check` window only): porcelain ground, 22px dot grid, a sage circle
 * anchored top-right (partly off-screen) and a sand circle at the left edge by the check card. Sizes and
 * positions measured on design-refs/citizen-hero-reference.png (x1.6). Clipped by its own box, so it never
 * causes horizontal scroll; hidden on phones (the phone reference has a plain ground).
 */
function HomeBackdrop() {
  return (
    <div aria-hidden className="home-decor-in pointer-events-none absolute inset-0 -z-10 hidden overflow-hidden bg-home-ground md:block">
      <div className="home-dots absolute inset-0" />
      <div className="absolute -top-[275px] -right-[176px] size-[560px] rounded-full bg-home-sage" />
      <div className="absolute top-[328px] -left-[194px] size-[400px] rounded-full bg-home-sand max-lg:hidden" />
    </div>
  );
}

export function CitizenShell({
  view,
  onView,
  sharedTarget,
  alertDomain,
  onSharedDone,
}: {
  view: View;
  onView: (v: View) => void;
  sharedTarget: string | null;
  alertDomain: string | null;
  onSharedDone: () => void;
}) {
  const { t } = useLang();
  const [scan, setScan] = useState<ScanState>({ status: "idle" });
  const [present, setPresent] = useState<Presentation>("inline");
  const [reportOpen, setReportOpen] = useState(false);
  const lastJob = useRef<Job | null>(null);
  const runId = useRef(0);
  const sharedHandled = useRef<string | null>(null);
  const fromShare = useRef(false);
  const userSwitched = useRef(false);

  /** Runs a scan with the ~2.6 s scanning animation. `kind` only changes the animation's steps. */
  const execute = useCallback(async (next: Job) => {
    const id = ++runId.current;
    lastJob.current = next;
    setPresent(next.present);
    setReportOpen(false);
    setScan({ status: "scanning", target: next.target, interception: next.interception, kind: next.kind });
    try {
      const [result] = await Promise.all([next.job(), sleep(2600)]);
      if (id !== runId.current) return;
      setScan({ status: "done", result });
      markSetupStep("checked");
    } catch (e) {
      if (id !== runId.current) return;
      setScan({ status: "error", target: next.target, interception: next.interception, message: e instanceof Error ? e.message : String(e) });
    }
  }, []);

  /** Search & Maps demo taps: the telecom DNS shield intercepts a link the resident was about to open. */
  const runDnsScan = useCallback(
    (target: string, job: () => Promise<ScanVerdict>) => void execute({ target, interception: "AUTO_TELECOM_DNS", job, present: "full" }),
    [execute],
  );

  const runManualScan = useCallback(
    (url: string, rawText?: string) => {
      const maps = isMapsUrl(url);
      const job = maps
        ? () => scanMaps({ maps_url: url }, "CITIZEN_MANUAL_CHECK")
        : () => analyzeUrl(url, "CITIZEN_MANUAL_CHECK", rawText ? "sms" : "web", rawText);
      void execute({
        target: maps ? "Google Maps listing" : isDemoScamUrl(url) ? t("exampleScamLabel") : hostOf(url),
        interception: "CITIZEN_MANUAL_CHECK",
        job,
        present: "inline",
      });
    },
    [execute, t],
  );

  const runMessageScan = useCallback(
    (text: string, sender?: string) =>
      void execute({
        target: t("msgTarget"),
        interception: "CITIZEN_MANUAL_CHECK",
        job: () => analyzeMessage(text, "CITIZEN_MANUAL_CHECK", sender),
        kind: "message",
        present: "inline",
      }),
    [execute, t],
  );

  const runListingScan = useCallback(
    (input: MapsScanInput) =>
      void execute({
        target: input.business_name ?? "Google Maps listing",
        interception: "CITIZEN_MANUAL_CHECK",
        job: () => scanMaps(input, "CITIZEN_MANUAL_CHECK"),
        present: "inline",
      }),
    [execute],
  );

  const runEmailScan = useCallback(
    (input: EmailScanInput, target: string) =>
      void execute({
        target,
        interception: "CITIZEN_MANUAL_CHECK",
        job: () => analyzeEmail(input, "CITIZEN_MANUAL_CHECK"),
        kind: "email",
        present: "inline",
      }),
    [execute],
  );

  /** A verdict that is already known (SMS guard). Quarantined by itself: inline; the resident tapped the link: full screen. */
  const showVerdict = useCallback((result: ScanVerdict, how: "auto" | "open" = "open") => {
    runId.current += 1;
    lastJob.current = null;
    setPresent(how === "open" ? "full" : "inline");
    setReportOpen(false);
    setScan({ status: "done", result });
  }, []);

  /** Closing the block page keeps the result (or the running scan) in the inline card. */
  const closeFull = useCallback(() => {
    setPresent("inline");
    if (fromShare.current) {
      fromShare.current = false;
      onSharedDone();
    }
  }, [onSharedDone]);

  const retry = useCallback(() => {
    const j = lastJob.current;
    if (j) void execute(j);
  }, [execute]);

  // PWA share target: /citizen?url=&text=&title= -> scan, then the URL is cleaned (onSharedDone).
  useEffect(() => {
    if (!sharedTarget || sharedHandled.current === sharedTarget) return;
    sharedHandled.current = sharedTarget;
    fromShare.current = true;
    const job = isMapsUrl(sharedTarget)
      ? () => scanMaps({ maps_url: sharedTarget }, "MOBILE_OS_SHARE_SHEET")
      : () => analyzeUrl(sharedTarget, "MOBILE_OS_SHARE_SHEET", "social");
    void execute({ target: sharedTarget, interception: "MOBILE_OS_SHARE_SHEET", job, present: "full" });
  }, [sharedTarget, execute]);

  // Opened from a Saqr scam-alert notification (?alert=<domain>): show the police warning for the blocked site.
  const alertHandled = useRef<string | null>(null);
  useEffect(() => {
    if (!alertDomain || alertHandled.current === alertDomain) return;
    alertHandled.current = alertDomain;
    fromShare.current = true;
    void execute({ target: alertDomain, interception: "AUTO_TELECOM_DNS", job: () => getAlertVerdict(alertDomain), present: "full" });
  }, [alertDomain, execute]);

  useEffect(() => {
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker.register("/sw.js").catch(() => undefined);
    }
  }, []);

  // An inline check: on a phone the result replaces the home content, so go to the top; on a wider screen
  // bring the verdict card into view when it is below the fold.
  useEffect(() => {
    if (present !== "inline" || scan.status !== "scanning") return;
    if (view === "check" && isMobileViewport()) {
      window.scrollTo({ top: 0, behavior: "auto" });
      return;
    }
    const card = document.querySelector<HTMLElement>('[data-testid="verdict-card"]');
    if (!card) return;
    const r = card.getBoundingClientRect();
    if (r.top > window.innerHeight - 160 || r.bottom < 120) {
      const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
      card.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "start" });
    }
  }, [present, scan.status, view]);

  // A window switch the resident asked for: start at the top and move focus to the new window's title.
  const switchView = useCallback(
    (v: View) => {
      if (v === view) return;
      userSwitched.current = true;
      onView(v);
      window.scrollTo({ top: 0, behavior: "auto" });
    },
    [view, onView],
  );
  useEffect(() => {
    if (!userSwitched.current) return;
    userSwitched.current = false;
    const id = window.setTimeout(() => document.getElementById("view-title")?.focus({ preventScroll: true }), 220);
    return () => window.clearTimeout(id);
  }, [view]);

  const focusInput = useCallback(() => {
    const el = document.getElementById(CHECK_INPUT_ID) as HTMLInputElement | null;
    if (!el) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "center" });
    el.focus({ preventScroll: true });
  }, []);

  /** Phone result -> empty home again (cancels a running check). */
  const newCheck = useCallback(() => {
    runId.current += 1;
    lastJob.current = null;
    setReportOpen(false);
    setScan({ status: "idle" });
    window.scrollTo({ top: 0, behavior: "auto" });
  }, []);

  /** Bottom navigation: tapping "Check" while a result is open goes back to the empty home. */
  const selectTab = useCallback(
    (tab: MobileTab) => {
      if (tab === "check" && view === "check" && scan.status !== "idle" && present === "inline") newCheck();
      else switchView(tab);
    },
    [view, scan.status, present, newCheck, switchView],
  );

  const vp = useViewport();
  const { done } = useSetupProgress();
  const shieldChip = vp === "mobile" && view === "check" && scan.status === "done" && present === "inline" && done[1];

  const openReport = useCallback(() => setReportOpen(true), []);
  const closeReport = useCallback(() => setReportOpen(false), []);
  const backToCheck = useCallback(() => switchView("check"), [switchView]);

  return (
    <MotionConfig reducedMotion="user">
      <div className="pb-bottom-nav flex min-h-dvh flex-col">
        <a
          href="#main"
          className="sr-only z-50 rounded-control bg-primary px-4 py-3 font-semibold text-on-primary focus:not-sr-only focus:fixed focus:start-4 focus:top-4"
        >
          {t("navCheck")}
        </a>
        <CitizenHeader view={view} onView={switchView} shieldChip={shieldChip} />
        <OfficialWarningBanner />
        <NoticeStrip />

        <div className="relative isolate flex flex-1 flex-col">
        {view === "check" && <HomeBackdrop />}
        <main id="main" className="mx-auto w-full max-w-6xl flex-1 overflow-x-clip px-4 pt-4 pb-8 sm:px-6 md:pt-8 lg:py-12">
          <AnimatePresence mode="wait" initial={false}>
            <motion.div
              key={view}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0, transition: { duration: 0.2, ease: [0.16, 1, 0.3, 1] } }}
              exit={{ opacity: 0, transition: { duration: 0.12 } }}
              data-view={view}
            >
              {view === "check" ? (
                <CheckView
                  scan={scan}
                  onCheck={runManualScan}
                  onCheckMessage={runMessageScan}
                  onFullReport={openReport}
                  onRetry={retry}
                  onFocusInput={focusInput}
                  onView={switchView}
                  onNewCheck={newCheck}
                />
              ) : (
                <ToolView
                  view={view}
                  scan={scan}
                  onBack={backToCheck}
                  onView={switchView}
                  onFullReport={openReport}
                  onRetry={retry}
                  runDnsScan={runDnsScan}
                  runListingScan={runListingScan}
                  runMessageScan={runMessageScan}
                  runEmailScan={runEmailScan}
                  onSmsVerdict={showVerdict}
                />
              )}
            </motion.div>
          </AnimatePresence>
        </main>
        </div>

        <CitizenFooter />
        <BottomNav view={view} onSelect={selectTab} />

        <SetupDrawer open={reportOpen && scan.status === "done"} onClose={closeReport} title={t("vcFullReport")} testId="drawer-report" wide canvas>
          {scan.status === "done" && <ResultView key={scan.result.scanId} result={scan.result} onClose={closeReport} embedded />}
        </SetupDrawer>
        <VerdictScreen state={present === "full" ? scan : { status: "idle" }} onClose={closeFull} onRetry={retry} />
      </div>
    </MotionConfig>
  );
}
