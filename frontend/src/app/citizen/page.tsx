"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useState } from "react";
import { CitizenShell } from "@/components/CitizenShell";
import { LanguageProvider } from "@/lib/i18n";
import { extractUrl } from "@/lib/url";

function ShareTargetReader({ onTarget }: { onTarget: (target: string) => void }) {
  const params = useSearchParams();
  const url = params.get("url");
  const text = params.get("text");
  const title = params.get("title");

  useEffect(() => {
    const target = extractUrl(url) ?? extractUrl(text) ?? extractUrl(title);
    if (target) onTarget(target);
  }, [url, text, title, onTarget]);

  return null;
}

export default function CitizenPage() {
  const router = useRouter();
  const [sharedTarget, setSharedTarget] = useState<string | null>(null);

  const onTarget = useCallback((target: string) => setSharedTarget(target), []);
  const onSharedDone = useCallback(() => {
    setSharedTarget(null);
    router.replace("/citizen");
  }, [router]);

  return (
    <LanguageProvider>
      <Suspense fallback={null}>
        <ShareTargetReader onTarget={onTarget} />
      </Suspense>
      <CitizenShell sharedTarget={sharedTarget} onSharedDone={onSharedDone} />
    </LanguageProvider>
  );
}
