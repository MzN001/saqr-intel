"use client";

import { AnimatePresence, motion } from "framer-motion";
import { ClipboardCopy, Megaphone, Send, ShieldCheck } from "lucide-react";
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
function XLogo({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 24 24" aria-hidden className={className} fill="currentColor">
      <path d="M18.9 2H22l-6.8 7.8L23.2 22h-6.3l-4.9-6.4L6.4 22H3.3l7.3-8.3L1 2h6.4l4.4 5.9L18.9 2Zm-1.1 18.1h1.7L6.3 3.8H4.5l13.3 16.3Z" />
    </svg>
  );
}

function useToast() {
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  useEffect(() => {
    if (!msg) return;
    const id = window.setTimeout(() => setMsg(null), 3200);
    return () => window.clearTimeout(id);
  }, [msg]);
  return [msg, setMsg] as const;
}

function Toast({ msg }: { msg: { text: string; ok: boolean } | null }) {
  return (
    <div aria-live="polite" className="min-h-0">
      <AnimatePresence>
        {msg && (
          <motion.p
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            className={`mt-3 flex items-center gap-2 rounded-xl px-3 py-2 text-sm font-semibold ${
              msg.ok
                ? "bg-emerald-50 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200"
                : "bg-amber-50 text-amber-900 dark:bg-amber-500/15 dark:text-amber-200"
            }`}
          >
            <ShieldCheck className="size-4 shrink-0" /> {msg.text}
          </motion.p>
        )}
      </AnimatePresence>
    </div>
  );
}

function CopyAmanButton({ warning, onDone }: { warning: WarningInfo; onDone: (ok: boolean) => void }) {
  const { t, lang } = useLang();
  const copy = async () => {
    const channel = warning.channel ? t(CHANNEL_DICT_KEY[warning.channel]) : null;
    onDone(await copyText(buildAmanReport(warning, lang, channel)));
  };
  return (
    <button
      type="button"
      onClick={copy}
      className="inline-flex items-center justify-center gap-2 rounded-2xl bg-surface px-4 py-3 text-sm font-bold text-ink ring-1 ring-line transition hover:bg-muted"
    >
      <ClipboardCopy className="size-4" /> {t("copyAman")}
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
      <div className="space-y-3">
        <div className="flex items-center justify-between gap-3">
          <span className="text-xs font-semibold uppercase tracking-wider text-ink-soft/70">{t("xDraftLang")}</span>
          <div role="radiogroup" aria-label={t("xDraftLang")} className="flex rounded-full bg-muted p-1 text-xs font-bold ring-1 ring-line" dir="ltr">
            {(["en", "ar"] as const).map((l) => (
              <button
                key={l}
                type="button"
                role="radio"
                aria-checked={draftLang === l}
                onClick={() => setDraftLang(l)}
                className={`rounded-full px-3 py-1.5 transition-colors ${draftLang === l ? "bg-navy-900 text-white dark:bg-white dark:text-navy-900" : "text-ink-soft hover:text-ink"}`}
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
            className={`w-full resize-none rounded-2xl bg-muted p-3.5 text-[15px] leading-relaxed text-ink outline-none ring-1 focus:ring-2 ${
              tooLong ? "ring-crimson-600" : "ring-line focus:ring-emerald-600"
            }`}
          />
        </label>
        <div className="flex items-center justify-between gap-3 text-xs">
          <span className="text-ink-soft/80">{tooLong ? t("xTooLong") : t("xEditHint")}</span>
          <span
            id="x-count"
            dir="ltr"
            className={`shrink-0 rounded-full px-2 py-0.5 font-mono font-bold tabular-nums ${
              tooLong ? "bg-crimson-600 text-white" : length > X_LIMIT - 20 ? "bg-amber-500/20 text-amber-800 dark:text-amber-300" : "bg-muted text-ink-soft"
            }`}
          >
            {length}/{X_LIMIT}
          </span>
        </div>

        <div className="grid gap-2 pt-1 sm:grid-cols-2">
          {tooLong || empty ? (
            <span
              aria-disabled="true"
              className="inline-flex cursor-not-allowed items-center justify-center gap-2 rounded-2xl bg-navy-900/40 px-4 py-3 text-sm font-bold text-white/80"
            >
              <XLogo className="size-4" /> {t("xApprove")}
            </span>
          ) : (
            <a
              href={xIntentUrl(text)}
              target="_blank"
              rel="noopener noreferrer"
              onClick={() => logXAlert(warning.domain, warning.entityEn)} // live counter on /police
              className="inline-flex items-center justify-center gap-2 rounded-2xl bg-navy-900 px-4 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-navy-800 dark:bg-white dark:text-navy-900 dark:hover:bg-white/90"
            >
              <XLogo className="size-4" /> {t("xApprove")}
            </a>
          )}
          <CopyAmanButton warning={warning} onDone={(ok) => setToast({ ok, text: ok ? t("amanCopied") : t("copyFailed") })} />
        </div>
        <p className="flex items-start gap-1.5 text-xs text-ink-soft/80">
          <Send className="mt-0.5 size-3.5 shrink-0" /> {t("xNothingPosted")}
        </p>
        <Toast msg={toast} />
      </div>
    </Modal>
  );
}

/** Small "Warn on X" button used on live-feed and awareness cards. */
export function WarnOnXButton({
  warning,
  presetDrafts,
  tone = "light",
}: {
  warning: WarningInfo;
  presetDrafts?: Partial<Record<Lang, string>>;
  tone?: "light" | "dark";
}) {
  const { t } = useLang();
  const [open, setOpen] = useState(false);
  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        className={`inline-flex shrink-0 items-center gap-1.5 rounded-full px-3 py-1.5 text-xs font-bold transition ${
          tone === "dark"
            ? "bg-white/10 text-white hover:bg-white/20"
            : "bg-navy-900 text-white hover:bg-navy-800 dark:bg-white dark:text-navy-900 dark:hover:bg-white/90"
        }`}
      >
        <XLogo className="size-3.5" /> {t("warnOnX")}
      </button>
      {open && <XWarningModal warning={warning} open={open} onClose={() => setOpen(false)} presetDrafts={presetDrafts} />}
    </>
  );
}

/** Permission prompt shown inside the verdict screen for risky results (score >= 60). */
export function XAlertPrompt({ warning }: { warning: WarningInfo }) {
  const { t } = useLang();
  const [state, setState] = useState<"ask" | "declined">("ask");
  const [open, setOpen] = useState(false);
  const [toast, setToast] = useToast();

  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ delay: 0.4 }}
      aria-labelledby="x-prompt-title"
      className="rounded-2xl bg-surface p-4 shadow-sm ring-1 ring-line"
    >
      {state === "ask" ? (
        <>
          <div className="flex items-start gap-3">
            <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-navy-900 text-gold-500 dark:bg-navy-950 dark:ring-1 dark:ring-white/10">
              <Megaphone className="size-5" />
            </span>
            <div className="min-w-0">
              <h3 id="x-prompt-title" className="font-extrabold leading-snug text-ink">
                {t("xPromptTitle")}
              </h3>
              <p className="mt-1 text-sm leading-relaxed text-ink-soft">{t("xPromptBody")}</p>
            </div>
          </div>
          <div className="mt-4 grid gap-2 sm:grid-cols-3">
            <button
              type="button"
              onClick={() => setOpen(true)}
              className="inline-flex items-center justify-center gap-2 rounded-2xl bg-navy-900 px-4 py-3 text-sm font-bold text-white transition hover:bg-navy-800 dark:bg-white dark:text-navy-900 dark:hover:bg-white/90"
            >
              <XLogo className="size-4" /> {t("xYes")}
            </button>
            <button
              type="button"
              onClick={() => setState("declined")}
              className="rounded-2xl bg-muted px-4 py-3 text-sm font-bold text-ink-soft ring-1 ring-line transition hover:text-ink"
            >
              {t("xNo")}
            </button>
            <CopyAmanButton warning={warning} onDone={(ok) => setToast({ ok, text: ok ? t("amanCopied") : t("copyFailed") })} />
          </div>
          <Toast msg={toast} />
        </>
      ) : (
        <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm text-ink-soft">
          <ShieldCheck className="size-4 text-emerald-600" /> {t("xDeclined")}
          <button type="button" onClick={() => setOpen(true)} className="font-semibold text-ink underline underline-offset-2">
            {t("xChangeMind")}
          </button>
        </p>
      )}
      {open && <XWarningModal warning={warning} open={open} onClose={() => setOpen(false)} />}
    </motion.section>
  );
}
