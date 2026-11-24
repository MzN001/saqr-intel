"use client";

import { AnimatePresence, motion } from "framer-motion";
import { CircleAlert, Link2, MessageSquareText, ScanSearch, ShieldCheck, UserRound, X } from "lucide-react";
import { useRef, useState, type ClipboardEvent, type FormEvent } from "react";
import { CityGridBackdrop, MAP_ASPECT } from "./CityGrid";
import { MESSAGE_MAX_CHARS } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { extractUrl, isMapsUrl } from "@/lib/url";
import { SCAM_FINE_URL, isDemoScamUrl } from "./SearchMapsShield";

const OFFICIAL_EXAMPLE = "https://www.adpolice.gov.ae/";

/** Normalise whatever the user pasted into a full URL, or null if it isn't a link. */
function toUrl(input: string): string | null {
  const found = extractUrl(input);
  if (!found) return null;
  return /^https?:\/\//i.test(found) ? found : `https://${found}`;
}

/** Free text (anything with a space: a whole SMS, with or without a link) is checked as a message. */
function isMessageText(input: string): boolean {
  return /\s/.test(input.trim());
}

/**
 * A bare link goes to `onCheck` (website / Maps scan). Pasted text (a whole SMS or WhatsApp message) goes to
 * `onCheckMessage` with the optional sender; a Maps link pasted with text is still checked as a Maps listing.
 */
export function LinkChecker({
  onCheck,
  onCheckMessage,
}: {
  onCheck: (url: string, rawText?: string) => void;
  onCheckMessage: (text: string, sender?: string) => void;
}) {
  const { t, lang } = useLang();
  const [value, setValue] = useState("");
  const [sender, setSender] = useState("");
  const [invalid, setInvalid] = useState(false);
  // The demo scam example shows a friendly label in the box; the real (replica) address stays here.
  const [example, setExample] = useState<string | null>(null);
  const textMode = !example && isMessageText(value);
  const input = useRef<HTMLInputElement>(null);

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (example) {
      onCheck(example);
      return;
    }
    const raw = value.trim();
    const url = toUrl(raw);
    if (isMessageText(raw) && !(url && isMapsUrl(url))) {
      setInvalid(false);
      onCheckMessage(raw, sender.trim() || undefined);
      return;
    }
    if (!url) {
      setInvalid(true);
      input.current?.focus();
      return;
    }
    setInvalid(false);
    onCheck(url, isMessageText(raw) ? raw : undefined);
  };

  /** A one-line box drops line breaks, gluing "fine.\nPay" into a fake domain: paste them as spaces. */
  const onPaste = (e: ClipboardEvent<HTMLInputElement>) => {
    const pasted = e.clipboardData.getData("text");
    if (!/[\r\n]/.test(pasted)) return;
    e.preventDefault();
    const el = e.currentTarget;
    const start = el.selectionStart ?? value.length;
    const end = el.selectionEnd ?? value.length;
    const flat = pasted.replace(/\s*[\r\n]+\s*/g, " ");
    setValue((value.slice(0, start) + flat + value.slice(end)).slice(0, MESSAGE_MAX_CHARS));
    setExample(null);
    if (invalid) setInvalid(false);
  };

  const tryExample = (url: string) => {
    const demo = isDemoScamUrl(url);
    setExample(demo ? url : null);
    setValue(demo ? t("exampleScamLabel") : url);
    setInvalid(false);
    onCheck(url);
  };

  return (
    <section aria-labelledby="link-checker-title" className="grid gap-5 rounded-[20px] border border-line bg-surface p-4 sm:p-6 lg:grid-cols-[minmax(0,1fr)_340px] lg:items-start">
      <div className="min-w-0">
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

      <form id="link-checker-form" onSubmit={submit} noValidate className="mt-4 flex flex-col gap-2 sm:flex-row">
        <label htmlFor="link-checker-input" className="sr-only">
          {t("checkTitle")}
        </label>
        <div
          className={`flex min-w-0 flex-1 items-center gap-2 rounded-2xl bg-muted px-3.5 ring-1 transition-shadow focus-within:ring-2 ${
            invalid ? "ring-crimson-600" : "ring-line focus-within:ring-emerald-600"
          }`}
        >
          {textMode ? (
            <MessageSquareText className="size-4 shrink-0 text-ink-soft/80" aria-hidden />
          ) : (
            <Link2 className="size-4 shrink-0 text-ink-soft/80" aria-hidden />
          )}
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
            dir={textMode ? "auto" : "ltr"}
            maxLength={MESSAGE_MAX_CHARS}
            value={value}
            onPaste={onPaste}
            onChange={(e) => {
              setValue(e.target.value);
              setExample(null);
              if (invalid) setInvalid(false);
            }}
            placeholder={t("checkPlaceholder")}
            aria-invalid={invalid}
            aria-describedby={invalid ? "link-checker-error" : undefined}
            className="min-w-0 flex-1 bg-transparent py-3 text-[15px] text-ink outline-hidden placeholder:text-ink-soft/80"
          />
          {value && (
            <button
              type="button"
              onClick={() => {
                setValue("");
                setExample(null);
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
        {textMode && (
          <motion.div
            key="sender"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <p className="flex items-center gap-1.5 pt-2 text-xs font-medium text-ink-soft">
              <MessageSquareText className="size-3.5 shrink-0" aria-hidden /> {t("msgModeNote")}
            </p>
            <label htmlFor="link-checker-sender" className="mt-2 block text-xs font-semibold text-ink">
              {t("msgSenderLabel")} <span className="font-medium text-ink-soft">({t("msgSenderOptional")})</span>
            </label>
            <div className="mt-1 flex items-center gap-2 rounded-2xl bg-muted px-3.5 ring-1 ring-line transition-shadow focus-within:ring-2 focus-within:ring-emerald-600 sm:max-w-sm">
              <UserRound className="size-4 shrink-0 text-ink-soft/80" aria-hidden />
              <input
                id="link-checker-sender"
                form="link-checker-form"
                type="text"
                autoComplete="off"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                enterKeyHint="go"
                dir="ltr"
                maxLength={64}
                value={sender}
                onChange={(e) => setSender(e.target.value)}
                placeholder={t("msgSenderPlaceholder")}
                className="min-w-0 flex-1 bg-transparent py-2.5 text-sm text-ink outline-hidden placeholder:text-ink-soft/80"
              />
            </div>
          </motion.div>
        )}
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
      </div>
      {/* Night Grid: Abu Dhabi at night, your shield lit in emerald around the island. */}
      <figure className="relative order-last hidden overflow-hidden rounded-2xl border border-line bg-canvas lg:block">
        <div className="relative w-full" style={{ aspectRatio: MAP_ASPECT }}>
          <CityGridBackdrop />
        </div>
        <figcaption className="absolute bottom-2 start-2 flex items-center gap-1.5 rounded-full border border-line bg-surface px-2.5 py-1 text-[11px] font-semibold text-ink">
          <span className="size-2 rounded-full bg-emerald-500" /> {lang === "ar" ? "درعك · جزيرة أبوظبي" : "Your shield · Abu Dhabi island"}
        </figcaption>
      </figure>
    </section>
  );
}
