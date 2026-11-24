"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, ClipboardCopy, Info, Megaphone, Send } from "lucide-react";
import { useEffect, useState } from "react";
import { useLang, type Lang } from "@/lib/i18n";
import {
  X_LIMIT,
  buildAmanReport,
  buildXDraft,
  CHANNEL_DICT_KEY,
  copyText,
  xIntentUrl,
  xLength,
  type WarningInfo,
} from "@/lib/share";
import { logXAlert } from "@/lib/police";
import { Modal } from "./Modal";

/** The X logo (lucide has no X/Twitter brand icon). */
export function XLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className} fill="currentColor">
      <path d="M18.9 2H22l-6.8 7.8L23.2 22h-6.3l-4.9-6.4L6.4 22H3.3l7.3-8.3L1 2h6.4l4.4 5.9L18.9 2Zm-1.1 18.1h1.7L6.3 3.8H4.5l13.3 16.3Z" />
    </svg>
  );
}

type ToastMsg = { text: string; ok: boolean } | null;

export function useToast() {
  const [msg, setMsg] = useState<ToastMsg>(null);
  useEffect(() => {
    if (!msg) return;
    const id = window.setTimeout(() => setMsg(null), 3200);
    return () => window.clearTimeout(id);
  }, [msg]);
  return [msg, setMsg] as const;
}

/** Neutral confirmation line: success and failure are both plain ink (neither is a verdict). */
export function Toast({ msg }: { msg: ToastMsg }) {
  return (
    <div aria-live="polite" className="min-h-0">
      <AnimatePresence>
        {msg && (
          <motion.p
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className="mt-3 flex items-center gap-2 rounded-control bg-muted px-3 py-2 text-[13px] font-semibold text-ink"
          >
            {msg.ok ? <Check className="size-4 shrink-0" aria-hidden /> : <Info className="size-4 shrink-0" aria-hidden />} {msg.text}
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
}

/** Copies the Aman report (share.ts) for an SMS to 2828. */
export function CopyAmanButton({
  warning,
  onDone,
  label,
  className = "btn-secondary",
}: {
  warning: WarningInfo;
  onDone: (ok: boolean) => void;
  label?: string;
  className?: string;
}) {
  const { t, lang } = useLang();
  const copy = async () => {
    const channel = warning.channel ? t(CHANNEL_DICT_KEY[warning.channel]) : null;
    onDone(await copyText(buildAmanReport(warning, lang, channel)));
  };
  return (
    <button type="button" onClick={copy} data-testid="copy-aman" className={className}>
      <ClipboardCopy className="size-4 shrink-0" aria-hidden /> {label ?? t("copyAman")}
    </button>
  );
}

/** Preview + edit modal. Nothing leaves the device until the user presses "Approve & Open X". */
export function XWarningModal({
  warning,
  open,
  onClose,
  presetDrafts,
}: {
  warning: WarningInfo;
  open: boolean;
  onClose: () => void;
  presetDrafts?: Partial<Record<Lang, string>>;
}) {
  const { t, lang } = useLang();
  const [draftLang, setDraftLang] = useState<Lang>(lang);
  const [drafts, setDrafts] = useState<Record<Lang, string>>(() => ({
    en: presetDrafts?.en || buildXDraft(warning, "en"),
    ar: presetDrafts?.ar || buildXDraft(warning, "ar"),
  }));
  const [toast, setToast] = useToast();

  const text = drafts[draftLang];
  const length = xLength(text);
  const tooLong = length > X_LIMIT;
  const empty = text.trim().length === 0;

  return (
    <Modal open={open} onClose={onClose} title={t("xModalTitle")}>
      <div className="space-y-3" data-testid="x-warning-modal">
        <div className="flex items-center justify-between gap-3">
          <span className="label-caps">{t("xDraftLang")}</span>
          <div role="radiogroup" aria-label={t("xDraftLang")} className="flex rounded-full border border-line bg-surface p-0.5" dir="ltr">
            {(["en", "ar"] as const).map((l) => (
              <button
                key={l}
                type="button"
                role="radio"
                aria-checked={draftLang === l}
                onClick={() => setDraftLang(l)}
                className={`min-h-9 rounded-full px-3 text-[13px] font-semibold transition-colors ${draftLang === l ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"}`}
              >
                {l === "en" ? "English" : "العربية"}
              </button>
            ))}
          </div>
        </div>

        <label className="block">
          <span className="sr-only">{t("xModalTitle")}</span>
          <textarea
            value={text}
            onChange={(e) => setDrafts((d) => ({ ...d, [draftLang]: e.target.value }))}
            dir={draftLang === "ar" ? "rtl" : "ltr"}
            rows={7}
            aria-invalid={tooLong}
            aria-describedby="x-count"
            className={`field resize-none py-3 leading-relaxed ${tooLong ? "border-ink" : ""}`}
          />
        </label>
        <div className="flex items-center justify-between gap-3 text-[13px]">
          <span className={tooLong ? "font-semibold text-ink" : "text-ink-soft"}>{tooLong ? t("xTooLong") : t("xEditHint")}</span>
          <span id="x-count" dir="ltr" className={`chip shrink-0 font-mono tabular-nums ${tooLong ? "bg-primary text-on-primary" : ""}`}>
            {length}/{X_LIMIT}
          </span>
        </div>

        <div className="grid gap-2 pt-1 sm:grid-cols-2">
          {tooLong || empty ? (
            <span aria-disabled="true" className="btn-primary cursor-not-allowed opacity-50">
              <XLogo className="size-4" /> {t("xApprove")}
            </span>
          ) : (
            <a
              href={xIntentUrl(text)}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => logXAlert(warning.domain, warning.entityEn)} // live counter on /police
              className="btn-primary"
              data-testid="x-approve"
            >
              <XLogo className="size-4" /> {t("xApprove")}
            </a>
          )}
          <CopyAmanButton warning={warning} onDone={(ok) => setToast({ ok, text: ok ? t("amanCopied") : t("copyFailed") })} />
        </div>
        <p className="flex items-start gap-1.5 text-[13px] text-ink-soft">
          <Send className="mt-0.5 size-3.5 shrink-0" aria-hidden /> {t("xNothingPosted")}
        </p>
        <Toast msg={toast} />
      </div>
    </Modal>
  );
}

/** "Warn on X" button used on live-feed and awareness cards (opens the preview; nothing posts by itself). */
export function WarnOnXButton({
  warning,
  presetDrafts,
  label,
  className,
  testId,
}: {
  warning: WarningInfo;
  presetDrafts?: Partial<Record<Lang, string>>;
  /** Defaults to "Warn on X". */
  label?: string;
  /** Defaults to a compact secondary pill. */
  className?: string;
  testId?: string;
}) {
  const { t } = useLang();
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        data-testid={testId}
        className={
          className ??
          "inline-flex min-h-10 shrink-0 items-center gap-1.5 rounded-full border border-line bg-surface px-3 text-[13px] font-semibold text-ink transition-colors hover:bg-muted"
        }
      >
        <XLogo className="size-3.5 shrink-0" /> {label ?? t("warnOnX")}
      </button>
      {open && <XWarningModal warning={warning} open={open} onClose={() => setOpen(false)} presetDrafts={presetDrafts} />}
    </>
  );
}

/** Permission prompt shown inside the full verdict report for risky results (score >= 60). */
export function XAlertPrompt({ warning }: { warning: WarningInfo }) {
  const { t } = useLang();
  const [state, setState] = useState<"ask" | "declined">("ask");
  const [open, setOpen] = useState(false);
  const [toast, setToast] = useToast();

  return (
    <section aria-labelledby="x-prompt-title" className="card p-5">
      {state === "ask" ? (
        <>
          <div className="flex items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-control bg-muted text-ink">
              <Megaphone className="size-5" aria-hidden />
            </span>
            <div className="min-w-0">
              <h3 id="x-prompt-title" className="text-[17px] font-semibold leading-snug text-ink">
                {t("xPromptTitle")}
              </h3>
              <p className="mt-1 text-[14px] leading-relaxed text-ink-soft">{t("xPromptBody")}</p>
            </div>
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <button type="button" onClick={() => setOpen(true)} className="btn-primary px-3">
              <XLogo className="size-4" /> {t("xYes")}
            </button>
            <button type="button" onClick={() => setState("declined")} className="btn-secondary px-3">
              {t("xNo")}
            </button>
            <CopyAmanButton
              warning={warning}
              className="btn-secondary px-3"
              onDone={(ok) => setToast({ ok, text: ok ? t("amanCopied") : t("copyFailed") })}
            />
          </div>
          <Toast msg={toast} />
        </>
      ) : (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[14px] text-ink-soft">
          <Check className="size-4" aria-hidden /> {t("xDeclined")}
          <button type="button" onClick={() => setOpen(true)} className="min-h-11 font-semibold text-ink underline underline-offset-2">
            {t("xChangeMind")}
          </button>
        </p>
      )}
      {open && <XWarningModal warning={warning} open={open} onClose={() => setOpen(false)} />}
    </section>
  );
}
