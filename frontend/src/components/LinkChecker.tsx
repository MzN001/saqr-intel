"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ArrowLeft, ArrowRight, Info, MessageSquareText, X } from "lucide-react";
import { useRef, useState, type ClipboardEvent, type FormEvent } from "react";
import { MESSAGE_MAX_CHARS } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { extractUrl, isMapsUrl } from "@/lib/url";
import { SCAM_FINE_URL, isDemoScamUrl } from "./SearchMapsShield";

export const CHECK_INPUT_ID = "link-checker-input";

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
 * The "Check a link" card on the home window. A bare link goes to `onCheck` (website / Maps scan). Pasted
 * text (a whole SMS or WhatsApp message) goes to `onCheckMessage` with the optional sender, which only
 * appears then; a Maps link pasted with text is still checked as a Maps listing.
 */
export function LinkChecker({
  onCheck,
  onCheckMessage,
}: {
  onCheck: (url: string, rawText?: string) => void;
  onCheckMessage: (text: string, sender?: string) => void;
}) {
  const { t, dir } = useLang();
  const [value, setValue] = useState("");
  const [sender, setSender] = useState("");
  const [invalid, setInvalid] = useState(false);
  // The demo scam example shows a friendly label in the box; the real (replica) address stays here.
  const [example, setExample] = useState<string | null>(null);
  const textMode = !example && isMessageText(value);
  const input = useRef<HTMLInputElement>(null);
  const Arrow = dir === "rtl" ? ArrowLeft : ArrowRight;

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

  const tryExample = () => {
    setExample(SCAM_FINE_URL);
    setValue(isDemoScamUrl(SCAM_FINE_URL) ? t("exampleScamLabel") : SCAM_FINE_URL);
    setInvalid(false);
    onCheck(SCAM_FINE_URL);
  };

  return (
    <section aria-labelledby="link-checker-title" className="card p-5 sm:p-6" data-testid="check-card">
      <span className="chip uppercase tracking-[0.08em] rtl:tracking-normal">{t("startHere")}</span>
      <h2 id="link-checker-title" className="mt-3 text-[20px] font-semibold leading-tight text-ink">
        {t("checkCardTitle")}
      </h2>

      <form id="link-checker-form" onSubmit={submit} noValidate className="mt-4 flex flex-col gap-2 sm:flex-row">
        <label htmlFor={CHECK_INPUT_ID} className="sr-only">
          {t("checkInputLabel")}
        </label>
        <div className="relative min-w-0 flex-1">
          <input
            ref={input}
            id={CHECK_INPUT_ID}
            data-testid="check-input"
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
            aria-describedby={invalid ? "link-checker-error" : textMode ? "link-checker-mode" : undefined}
            className={`field pe-11 ${invalid ? "border-ink" : ""} ${dir === "rtl" && !textMode ? "text-right" : ""}`}
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
              className="absolute inset-y-0 end-0 grid w-11 place-items-center rounded-control text-ink-soft hover:text-ink"
            >
              <X className="size-4" aria-hidden />
            </button>
          )}
        </div>
        <button type="submit" className="btn-primary shrink-0" data-testid="check-button">
          {textMode ? t("checkMessageButton") : t("checkButton")} <Arrow className="size-4" aria-hidden />
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
            <p id="link-checker-mode" className="flex items-center gap-1.5 pt-3 text-[13px] text-ink-soft">
              <MessageSquareText className="size-3.5 shrink-0" aria-hidden /> {t("msgModeNote")}
            </p>
            <label htmlFor="link-checker-sender" className="mt-3 block text-[13px] font-semibold text-ink">
              {t("msgSenderLabel")} <span className="font-normal text-ink-soft">({t("msgSenderOptional")})</span>
            </label>
            <input
              id="link-checker-sender"
              data-testid="check-sender"
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
              className={`field mt-1.5 sm:max-w-sm ${dir === "rtl" ? "text-right" : ""}`}
            />
          </motion.div>
        )}
        {invalid && (
          <motion.p
            id="link-checker-error"
            role="alert"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="flex items-center gap-1.5 overflow-hidden pt-2 text-[14px] font-medium text-ink"
          >
            <Info className="size-4 shrink-0" aria-hidden /> {t("checkInvalid")}
          </motion.p>
        )}
      </AnimatePresence>

      <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2">
        <button type="button" onClick={tryExample} className="btn-secondary" data-testid="demo-button">
          {t("exampleScam")}
        </button>
        <p className="text-[14px] text-ink-soft">{t("shareHint")}</p>
      </div>
    </section>
  );
}
