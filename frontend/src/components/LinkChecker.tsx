"use client";

import { AnimatePresence, motion } from "framer-motion";
import { CircleAlert, Link2, ScanSearch, ShieldCheck, X } from "lucide-react";
import { useRef, useState, type FormEvent } from "react";
import { useLang } from "@/lib/i18n";
import { extractUrl } from "@/lib/url";
import { SCAM_FINE_URL } from "./SearchMapsShield";

const OFFICIAL_EXAMPLE = "https://www.adpolice.gov.ae/";

/** Normalise whatever the user pasted into a full URL, or null if it isn't a link. */
function toUrl(input: string): string | null {
  const found = extractUrl(input);
  if (!found) return null;
  return /^https?:\/\//i.test(found) ? found : `https://${found}`;
}

/** `rawText` is what the citizen pasted when it was more than a bare link (e.g. a whole SMS). */
export function LinkChecker({ onCheck }: { onCheck: (url: string, rawText?: string) => void }) {
  const { t } = useLang();
  const [value, setValue] = useState("");
  const [invalid, setInvalid] = useState(false);
  const input = useRef<HTMLInputElement>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const url = toUrl(value);
    if (!url) {
      setInvalid(true);
      input.current?.focus();
      return;
    }
    setInvalid(false);
    const raw = value.trim();
    onCheck(url, /\s/.test(raw) ? raw : undefined);
  };

  const tryExample = (url: string) => {
    setValue(url);
    setInvalid(false);
    onCheck(url);
  };

  return (
    <section aria-labelledby="link-checker-title" className="rounded-3xl bg-surface p-4 shadow-sm ring-1 ring-line sm:p-5">
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-navy-900 text-gold-500 dark:bg-navy-950 dark:ring-1 dark:ring-white/10">
          <ScanSearch className="size-5" />
        </span>
        <div className="min-w-0">
          <h2 id="link-checker-title" className="text-balance text-base font-extrabold leading-snug text-ink sm:text-lg sm:leading-tight">
            {t("checkTitle")}
          </h2>
          <p className="mt-0.5 text-sm text-ink-soft">{t("checkHint")}</p>
        </div>
      </div>

      <form onSubmit={submit} noValidate className="mt-4 flex flex-col gap-2 sm:flex-row">
        <label htmlFor="link-checker-input" className="sr-only">
          {t("checkTitle")}
        </label>
        <div
          className={`flex min-w-0 flex-1 items-center gap-2 rounded-2xl bg-muted px-3.5 ring-1 transition-shadow focus-within:ring-2 ${
            invalid ? "ring-crimson-600" : "ring-line focus-within:ring-emerald-600"
          }`}
        >
          <Link2 className="size-4 shrink-0 text-ink-soft/80" />
          <input
            ref={input}
            id="link-checker-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            enterKeyHint="go"
            dir="ltr"
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              if (invalid) setInvalid(false);
            }}
            placeholder={t("checkPlaceholder")}
            aria-invalid={invalid}
            aria-describedby={invalid ? "link-checker-error" : undefined}
            className="min-w-0 flex-1 bg-transparent py-3 text-[15px] text-ink outline-none placeholder:text-ink-soft/80"
          />
          {value && (
            <button
              type="button"
              onClick={() => {
                setValue("");
                setInvalid(false);
                input.current?.focus();
              }}
              aria-label={t("checkClear")}
              className="rounded-full p-1 text-ink-soft/80 hover:bg-line hover:text-ink"
            >
              <X className="size-4" />
            </button>
          )}
        </div>
        <button
          type="submit"
          className="inline-flex shrink-0 items-center justify-center gap-2 rounded-2xl bg-emerald-700 px-4 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-emerald-800 active:scale-[0.97] sm:px-5 sm:py-0"
        >
          <ShieldCheck className="size-4" />
          {t("checkButton")}
        </button>
      </form>

      <AnimatePresence initial={false}>
        {invalid && (
          <motion.p
            id="link-checker-error"
            role="alert"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="flex items-center gap-1.5 overflow-hidden pt-2 text-sm font-medium text-crimson-700 dark:text-red-300"
          >
            <CircleAlert className="size-4 shrink-0" /> {t("checkInvalid")}
          </motion.p>
        )}
      </AnimatePresence>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold text-ink-soft/80">{t("checkTry")}</span>
        <button
          type="button"
          onClick={() => tryExample(SCAM_FINE_URL)}
          className="rounded-full bg-crimson-50 px-3 py-1 font-semibold text-crimson-700 ring-1 ring-crimson-600/20 hover:bg-crimson-600/15 dark:bg-crimson-600/15 dark:text-red-300 dark:ring-crimson-600/40"
        >
          {t("exampleScam")}
        </button>
        <button
          type="button"
          onClick={() => tryExample(OFFICIAL_EXAMPLE)}
          className="press rounded-full bg-emerald-50 px-3 py-1 font-semibold text-emerald-800 ring-1 ring-emerald-600/20 hover:bg-emerald-600/15 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/25"
        >
          {t("exampleSafe")}
        </button>
      </div>
    </section>
  );
}
