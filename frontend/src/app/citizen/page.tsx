"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { CitizenShell } from "@/components/CitizenShell";
import { WarmUp } from "@/components/WarmUp";
import { LanguageProvider } from "@/lib/i18n";
import { extractUrl } from "@/lib/url";

function ShareTargetReader({ onTarget, onAlert }: { onTarget: (target: string) => void; onAlert: (domain: string) => void }) {
  const params = useSearchParams();
  const url = params.get("url");
  const text = params.get("text");
  const title = params.get("title");
  const alert = params.get("alert");

  useEffect(() => {
    if (alert) {
      onAlert(alert);
      return;
    }
    const target = extractUrl(url) ?? extractUrl(text) ?? extractUrl(title);
    if (target) onTarget(target);
  }, [url, text, title, alert, onTarget, onAlert]);

  return null;
}

export default function CitizenPage() {
  const router = useRouter();
  const [sharedTarget, setSharedTarget] = useState<string | null>(null);
  const [alertDomain, setAlertDomain] = useState<string | null>(null);

  const onTarget = useCallback((target: string) => setSharedTarget(target), []);
  const onAlert = useCallback((domain: string) => setAlertDomain(domain), []);
  const onSharedDone = useCallback(() => {
    setSharedTarget(null);
    setAlertDomain(null);
    router.replace("/citizen");
  }, [router]);

  return (
    <LanguageProvider>
      <WarmUp />
      <Suspense fallback={null}>
        <ShareTargetReader onTarget={onTarget} onAlert={onAlert} />
      </Suspense>
      <CitizenShell sharedTarget={sharedTarget} alertDomain={alertDomain} onSharedDone={onSharedDone} />
    </LanguageProvider>
  );
}
