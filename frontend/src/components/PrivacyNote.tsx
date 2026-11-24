"use client";

import { ChevronDown, Lock } from "lucide-react";
import { useLang } from "@/lib/i18n";

/** Footer disclosure: what SAQR stores, for how long, and where false-alarm reports go. */
export function PrivacyNote() {
  const { t } = useLang();
  return (
    <details className="group mx-auto mt-3 max-w-xl text-start">
      <summary className="mx-auto flex w-fit cursor-pointer list-none items-center gap-1.5 rounded-full px-2 py-1 text-xs font-semibold text-ink-soft hover:text-ink [&::-webkit-details-marker]:hidden">
        <Lock className="size-3.5" aria-hidden />
        {t("privTitle")}
        <ChevronDown className="size-3.5 transition-transform group-open:rotate-180" aria-hidden />
      </summary>
      <ul className="mt-2 space-y-1.5 border-t border-line pt-3 text-xs leading-relaxed text-ink-soft">
        <li>{t("privStored")}</li>
        <li>{t("privRetention")}</li>
        <li>{t("privReports")}</li>
        <li className="font-semibold text-ink">{t("privNoAccount")}</li>
      </ul>
    </details>
  );
}
