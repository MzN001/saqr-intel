"use client";

import { useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { CitizenShell } from "@/components/CitizenShell";
import { WarmUp } from "@/components/WarmUp";
import { LanguageProvider } from "@/lib/i18n";
import { extractUrl } from "@/lib/url";
import { parseView, viewHref, type View } from "@/lib/view";

/**
 * Reads the URL: the PWA share target (?url=&text=&title=), the scam-alert deep link (?alert=<domain>) and
 * the current window (?view=check|maps|sms|email|live). Next integrates window.history.pushState with
 * useSearchParams, so switching windows (pushState) and back / forward (popstate) both land here.
 */
function UrlReader({
  onTarget,
  onAlert,
  onView,
}: {
  onTarget: (target: string) => void;
  onAlert: (domain: string) => void;
  onView: (view: View) => void;
}) {
  const params = useSearchParams();
  const url = params.get("url");
  const text = params.get("text");
  const title = params.get("title");
  const alert = params.get("alert");
  const view = parseView(params.get("view"));

  useEffect(() => {
    if (alert) {
      onAlert(alert);
      return;
    }
    const target = extractUrl(url) ?? extractUrl(text) ?? extractUrl(title);
    if (target) onTarget(target);
  }, [url, text, title, alert, onTarget, onAlert]);

  useEffect(() => onView(view), [view, onView]);

  return null;
}

function currentView(): View {
  return parseView(new URLSearchParams(window.location.search).get("view"));
}

export default function CitizenPage() {
  const [sharedTarget, setSharedTarget] = useState<string | null>(null);
  const [alertDomain, setAlertDomain] = useState<string | null>(null);
  const [view, setView] = useState<View>("check");

  const onTarget = useCallback((target: string) => setSharedTarget(target), []);
  const onAlert = useCallback((domain: string) => setAlertDomain(domain), []);

  /** A window switch: new history entry (deep-linkable, back works), no reload. */
  const changeView = useCallback((v: View) => {
    setView(v);
    if (currentView() !== v || /[?&](url|text|title|alert)=/.test(window.location.search)) {
      window.history.pushState(null, "", viewHref(v));
    }
  }, []);

  /** After a shared / alert scan: drop ?url= / ?alert= from the address, keep the current window. */
  const onSharedDone = useCallback(() => {
    setSharedTarget(null);
    setAlertDomain(null);
    window.history.replaceState(null, "", viewHref(currentView()));
  }, []);

  return (
    <LanguageProvider>
      <WarmUp />
      <Suspense fallback={null}>
        <UrlReader onTarget={onTarget} onAlert={onAlert} onView={setView} />
      </Suspense>
      <CitizenShell view={view} onView={changeView} sharedTarget={sharedTarget} alertDomain={alertDomain} onSharedDone={onSharedDone} />
    </LanguageProvider>
  );
}
