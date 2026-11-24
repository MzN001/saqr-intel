"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Bot, ChevronDown, CircleAlert, ClipboardPaste, Eraser, FileCode, Info, Lock, Mail, ShieldCheck, Upload, X } from "lucide-react";
import { useCallback, useMemo, useRef, useState, useSyncExternalStore, type DragEvent, type FormEvent } from "react";
import type { EmailScanInput, EmailSource, UserLlmConfig } from "@/lib/api";
import { useLang, type DictKey } from "@/lib/i18n";

/**
 * Tab "Email": the citizen pastes an email (or its full source, or uploads the .eml/.msg file) and SAQR
 * checks the sender, SPF/DKIM/DMARC, lookalike letters, links and attachments (POST /api/analyze-email).
 * The verdict opens in the shared VerdictScreen through CitizenShell's execute() flow.
 */

type Mode = "text" | "raw" | "file";

/** Server limits (see the email contract): text 200k chars, file_base64 4M chars, whole body 4 MB.
 *  Base64 grows a file by 4/3, so ~2.9 MB of file is the most that still fits. */
const MAX_TEXT_CHARS = 200_000;
const MAX_FILE_BYTES = 2_900_000;

/** A fictitious demo scam: a free Gmail account pretending to be TAMM, linking to a seeded scam site. */
const SAMPLE_SCAM_EMAIL = `From: TAMM Abu Dhabi <tamm.refunds.uae@gmail.com>
Subject: Traffic fine refund of AED 1,250 - claim within 24 hours

Dear Resident,

Our records show that you paid a traffic fine twice. A refund of AED 1,250 is waiting for you.
To receive it, confirm your card details and the OTP code within 24 hours, or the refund will be cancelled.

Claim your refund: https://tamm-smart-pay.net/refund

TAMM Abu Dhabi Government Services`;

/** Header names that only appear in a message's full source ("Show original"), not in the visible text. */
const RAW_HEADER = /^(received|delivered-to|return-path|authentication-results|arc-seal|dkim-signature|received-spf|message-id|mime-version|x-[\w-]+):/im;

/** Pasted text that is really the full source (headers + body) is sent as "raw" so SPF/DKIM/DMARC get checked. */
function looksLikeRawSource(text: string): boolean {
  const head = text.slice(0, 4000);
  const headerLines = head.split(/\r?\n/).filter((l) => /^[A-Za-z][\w-]{1,40}:\s/.test(l)).length;
  return RAW_HEADER.test(head) && headerLines >= 3;
}

/** A short label for the scanning screen: "<sender> | <subject>" when the paste has those lines. */
function targetFor(text: string): string {
  const from = /^from:\s*(.+)$/im.exec(text)?.[1]?.trim();
  const subject = /^subject:\s*(.+)$/im.exec(text)?.[1]?.trim();
  if (from || subject) return [from, subject?.slice(0, 80)].filter(Boolean).join(" | ");
  const first = text.split(/\r?\n/).find((l) => l.trim())?.trim() ?? "";
  return first.length > 60 ? `${first.slice(0, 60)}…` : first;
}

function fileSource(file: File): Extract<EmailSource, "eml" | "msg"> | null {
  const name = file.name.toLowerCase();
  if (name.endsWith(".msg") || file.type === "application/vnd.ms-outlook") return "msg";
  if (name.endsWith(".eml") || file.type === "message/rfc822") return "eml";
  return null;
}

function readAsBase64(file: File): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(reader.error ?? new Error("read failed"));
    reader.onload = () => {
      const url = String(reader.result ?? "");
      const comma = url.indexOf(",");
      resolve(comma >= 0 ? url.slice(comma + 1) : "");
    };
    reader.readAsDataURL(file);
  });
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// ---------------------------------------------------------------- "my own AI" settings (sessionStorage only)

const LLM_KEY = "saqr-user-llm";
const llmListeners = new Set<() => void>();
const EMPTY_LLM: UserLlmConfig = { base_url: "", api_key: "", model: "" };

/** The raw JSON string is the snapshot: strings compare by value, so React sees no change between reads. */
const llmStore = {
  subscribe(cb: () => void) {
    llmListeners.add(cb);
    return () => {
      llmListeners.delete(cb);
    };
  },
  getSnapshot(): string {
    try {
      return window.sessionStorage.getItem(LLM_KEY) ?? "";
    } catch {
      return "";
    }
  },
  getServerSnapshot(): string {
    return "";
  },
  set(cfg: UserLlmConfig | null) {
    try {
      if (cfg && (cfg.base_url || cfg.api_key || cfg.model)) window.sessionStorage.setItem(LLM_KEY, JSON.stringify(cfg));
      else window.sessionStorage.removeItem(LLM_KEY);
    } catch {
      /* storage blocked: the settings simply aren't kept */
    }
    llmListeners.forEach((cb) => cb());
  },
};

function parseLlm(raw: string): UserLlmConfig {
  if (!raw) return EMPTY_LLM;
  try {
    const v = JSON.parse(raw) as Partial<UserLlmConfig>;
    return { base_url: String(v.base_url ?? ""), api_key: String(v.api_key ?? ""), model: String(v.model ?? "") };
  } catch {
    return EMPTY_LLM;
  }
}

/** null = use SAQR's own AI; a config = the user's endpoint; an error key = fix the form first. */
function checkLlm(cfg: UserLlmConfig): { cfg: UserLlmConfig | null; error: DictKey | null } {
  const c = { base_url: cfg.base_url.trim(), api_key: cfg.api_key.trim(), model: cfg.model.trim() };
  if (!c.base_url && !c.api_key && !c.model) return { cfg: null, error: null };
  if (!c.base_url || !c.model) return { cfg: null, error: "llmIncomplete" };
  if (!/^https:\/\/[^\s/]+/i.test(c.base_url)) return { cfg: null, error: "llmBadUrl" };
  return { cfg: c, error: null };
}

function LlmPanel({ open, onToggle, error }: { open: boolean; onToggle: () => void; error: DictKey | null }) {
  const { t } = useLang();
  const raw = useSyncExternalStore(llmStore.subscribe, llmStore.getSnapshot, llmStore.getServerSnapshot);
  const cfg = useMemo(() => parseLlm(raw), [raw]);
  const active = checkLlm(cfg).cfg !== null;
  const update = (patch: Partial<UserLlmConfig>) => llmStore.set({ ...cfg, ...patch });

  const field = (id: keyof UserLlmConfig, label: DictKey, placeholder: string, type = "text") => (
    <label className="block">
      <span className="text-xs font-semibold text-ink-soft">{t(label)}</span>
      <input
        type={type}
        value={cfg[id]}
        onChange={(e) => update({ [id]: e.target.value })}
        placeholder={placeholder}
        autoComplete="off"
        autoCapitalize="off"
        autoCorrect="off"
        spellCheck={false}
        dir="ltr"
        className="mt-1 w-full rounded-xl bg-muted px-3 py-2.5 font-mono text-sm text-ink outline-none ring-1 ring-line placeholder:text-ink-soft/80 focus:ring-2 focus:ring-emerald-600"
      />
    </label>
  );

  return (
    <div className="rounded-2xl bg-muted/60 ring-1 ring-line">
      <button
        type="button"
        onClick={onToggle}
        aria-expanded={open}
        aria-controls="email-llm-panel"
        className="flex w-full items-center gap-2 px-3.5 py-3 text-start text-sm font-bold text-ink"
      >
        <Bot className="size-4 shrink-0 text-ink-soft" />
        <span className="min-w-0 flex-1">{t("llmTitle")}</span>
        {active && (
          <span className="rounded-full bg-emerald-600 px-2 py-0.5 text-[11px] font-extrabold uppercase text-white">{t("llmActive")}</span>
        )}
        <ChevronDown className={`size-4 shrink-0 text-ink-soft transition-transform ${open ? "rotate-180" : ""}`} />
      </button>
      <AnimatePresence initial={false}>
        {open && (
          <motion.div
            id="email-llm-panel"
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: "auto" }}
            exit={{ opacity: 0, height: 0 }}
            className="overflow-hidden"
          >
            <div className="space-y-3 border-t border-line px-3.5 pb-3.5 pt-3">
              <p className="text-xs leading-relaxed text-ink-soft">{t("llmHint")}</p>
              {field("base_url", "llmBaseUrl", "https://api.example.com/v1", "url")}
              {field("api_key", "llmApiKey", "sk-...", "password")}
              {field("model", "llmModel", "gpt-4o-mini")}
              {error && (
                <p role="alert" className="flex items-center gap-1.5 text-sm font-medium text-crimson-700 dark:text-red-300">
                  <CircleAlert className="size-4 shrink-0" /> {t(error)}
                </p>
              )}
              <p className="flex items-start gap-1.5 text-xs leading-relaxed text-ink-soft">
                <Lock className="mt-0.5 size-3.5 shrink-0" /> {t("llmPrivacy")}
              </p>
              <button
                type="button"
                onClick={() => llmStore.set(null)}
                className="inline-flex items-center gap-1.5 rounded-full bg-surface px-3 py-1.5 text-xs font-bold text-ink-soft ring-1 ring-line hover:text-ink"
              >
                <Eraser className="size-3.5" /> {t("llmClear")}
              </button>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

// ---------------------------------------------------------------- the card

export function EmailGuard({ onScan }: { onScan: (input: EmailScanInput, target: string) => void }) {
  const { t } = useLang();
  const [mode, setMode] = useState<Mode>("text");
  const [text, setText] = useState("");
  const [raw, setRaw] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [dragging, setDragging] = useState(false);
  const [error, setError] = useState<DictKey | null>(null);
  const [llmOpen, setLlmOpen] = useState(false);
  const [llmError, setLlmError] = useState<DictKey | null>(null);
  const [busy, setBusy] = useState(false);
  const picker = useRef<HTMLInputElement>(null);

  const pasted = mode === "raw" ? raw : text;
  const autoRaw = mode === "text" && looksLikeRawSource(text);

  const chooseFile = useCallback((f: File | undefined | null) => {
    if (!f) return;
    const reject = (why: DictKey) => {
      // Never keep an earlier file around after a rejected choice: "Check" must not scan the old one.
      setFile(null);
      if (picker.current) picker.current.value = "";
      setError(why);
    };
    if (!fileSource(f)) {
      reject("emFileType");
      return;
    }
    if (f.size > MAX_FILE_BYTES) {
      reject("emFileTooBig");
      return;
    }
    setError(null);
    setFile(f);
    setMode("file");
  }, []);

  const onDrop = (e: DragEvent) => {
    setDragging(false);
    const dropped = e.dataTransfer.files?.[0];
    if (!dropped) return; // dropped text: let the textarea take it as usual
    e.preventDefault();
    setMode("file");
    chooseFile(dropped);
  };

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const llm = checkLlm(parseLlm(llmStore.getSnapshot()));
    setLlmError(llm.error);
    if (llm.error) {
      setLlmOpen(true);
      return;
    }

    if (mode === "file") {
      const src = file ? fileSource(file) : null;
      if (!file || !src) {
        setError("emEmpty");
        return;
      }
      setBusy(true);
      try {
        const fileBase64 = await readAsBase64(file);
        setError(null);
        onScan({ source: src, fileBase64, fileName: file.name, llm: llm.cfg }, file.name);
      } catch {
        setError("emFileRead");
      } finally {
        setBusy(false);
      }
      return;
    }

    const value = pasted.trim();
    if (!value) {
      setError("emEmpty");
      return;
    }
    if (value.length > MAX_TEXT_CHARS) {
      setError("emTooLong");
      return;
    }
    setError(null);
    const source: EmailSource = mode === "raw" || looksLikeRawSource(value) ? "raw" : "text";
    onScan({ source, text: value, llm: llm.cfg }, targetFor(value) || t("emTab"));
  };

  const modes: { id: Mode; label: DictKey; icon: typeof Mail }[] = [
    { id: "text", label: "emModeText", icon: ClipboardPaste },
    { id: "raw", label: "emModeRaw", icon: FileCode },
    { id: "file", label: "emModeFile", icon: Upload },
  ];

  return (
    <section
      aria-labelledby="email-guard-title"
      className="w-full rounded-[20px] border border-line bg-surface p-4 sm:p-5 lg:w-[560px]"
      onDragOver={(e) => {
        if (e.dataTransfer.types.includes("Files")) {
          e.preventDefault();
          setDragging(true);
        }
      }}
      onDragLeave={(e) => {
        if (e.currentTarget === e.target) setDragging(false);
      }}
      onDrop={onDrop}
    >
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-navy-900 text-gold-500 dark:bg-navy-950 dark:ring-1 dark:ring-white/10">
          <Mail className="size-5" />
        </span>
        <div className="min-w-0">
          <h2 id="email-guard-title" className="text-lg font-extrabold leading-tight text-ink">
            {t("emTitle")}
          </h2>
          <p className="mt-0.5 text-sm text-ink-soft">{t("emHint")}</p>
        </div>
      </div>

      <div role="tablist" aria-label={t("emTitle")} className="mt-4 grid grid-cols-3 gap-1 rounded-2xl bg-muted p-1 ring-1 ring-line">
        {modes.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            role="tab"
            aria-selected={mode === id}
            onClick={() => {
              setMode(id);
              setError(null);
            }}
            className={`flex items-center justify-center gap-1.5 rounded-xl px-2 py-2 text-xs font-bold transition-colors sm:text-sm ${
              mode === id ? "bg-navy-900 text-white shadow-sm dark:bg-white dark:text-navy-900" : "text-ink-soft hover:text-ink"
            }`}
          >
            <Icon className="size-4 shrink-0" />
            <span className="truncate">{t(label)}</span>
          </button>
        ))}
      </div>

      <form onSubmit={submit} noValidate className="mt-3 space-y-3">
        {mode !== "file" ? (
          <div>
            <label htmlFor="email-guard-text" className="sr-only">
              {t(mode === "raw" ? "emRawLabel" : "emTextLabel")}
            </label>
            <div
              className={`relative rounded-2xl bg-muted ring-1 transition-shadow focus-within:ring-2 ${
                error ? "ring-crimson-600" : "ring-line focus-within:ring-emerald-600"
              }`}
            >
              <textarea
                id="email-guard-text"
                key={mode}
                value={pasted}
                onChange={(e) => {
                  (mode === "raw" ? setRaw : setText)(e.target.value);
                  if (error) setError(null);
                }}
                rows={mode === "raw" ? 10 : 8}
                spellCheck={false}
                autoComplete="off"
                dir="auto"
                placeholder={t(mode === "raw" ? "emRawPlaceholder" : "emTextPlaceholder")}
                aria-invalid={Boolean(error)}
                aria-describedby={error ? "email-guard-error" : undefined}
                className={`block w-full resize-y rounded-2xl bg-transparent p-3.5 text-ink outline-none placeholder:text-ink-soft/80 ${
                  mode === "raw" ? "font-mono text-xs leading-relaxed" : "text-[15px] leading-relaxed"
                }`}
              />
              {pasted && (
                <button
                  type="button"
                  onClick={() => (mode === "raw" ? setRaw : setText)("")}
                  aria-label={t("checkClear")}
                  className="absolute end-2 top-2 rounded-full bg-surface/80 p-1 text-ink-soft/80 ring-1 ring-line hover:text-ink"
                >
                  <X className="size-4" />
                </button>
              )}
            </div>
            {autoRaw && (
              <p className="mt-2 flex items-start gap-1.5 text-xs font-medium text-emerald-700 dark:text-emerald-400">
                <ShieldCheck className="mt-0.5 size-3.5 shrink-0" /> {t("emDetectedRaw")}
              </p>
            )}
          </div>
        ) : (
          <div
            className={`grid place-items-center gap-2 rounded-2xl border-2 border-dashed p-6 text-center transition-colors ${
              dragging ? "border-emerald-600 bg-emerald-500/10" : error ? "border-crimson-600 bg-muted" : "border-line bg-muted"
            }`}
          >
            <Upload className="size-7 text-ink-soft" />
            {file ? (
              <p className="flex max-w-full items-center gap-2 text-sm font-bold text-ink">
                <span dir="ltr" className="truncate font-mono">
                  {file.name}
                </span>
                <span className="shrink-0 text-xs font-medium text-ink-soft">{formatSize(file.size)}</span>
                <button
                  type="button"
                  onClick={() => {
                    setFile(null);
                    if (picker.current) picker.current.value = "";
                  }}
                  aria-label={t("emFileRemove")}
                  className="shrink-0 rounded-full p-1 text-ink-soft/80 hover:bg-line hover:text-ink"
                >
                  <X className="size-4" />
                </button>
              </p>
            ) : (
              <p className="text-sm font-semibold text-ink">{t("emDrop")}</p>
            )}
            <button
              type="button"
              onClick={() => picker.current?.click()}
              className="rounded-full bg-surface px-4 py-1.5 text-sm font-bold text-ink ring-1 ring-line hover:bg-line"
            >
              {t("emPick")}
            </button>
            <input
              ref={picker}
              type="file"
              accept=".eml,.msg,message/rfc822,application/vnd.ms-outlook"
              className="sr-only"
              tabIndex={-1}
              aria-label={t("emPick")}
              onChange={(e) => chooseFile(e.target.files?.[0])}
            />
            <p className="max-w-sm text-xs leading-relaxed text-ink-soft">{t("emFileHint")}</p>
          </div>
        )}

        <AnimatePresence initial={false}>
          {error && (
            <motion.p
              id="email-guard-error"
              role="alert"
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              exit={{ opacity: 0, height: 0 }}
              className="flex items-center gap-1.5 overflow-hidden text-sm font-medium text-crimson-700 dark:text-red-300"
            >
              <CircleAlert className="size-4 shrink-0" /> {t(error)}
            </motion.p>
          )}
        </AnimatePresence>

        {mode === "raw" && (
          <details className="group rounded-2xl bg-muted/60 px-3.5 py-3 ring-1 ring-line">
            <summary className="flex cursor-pointer list-none items-center gap-2 text-sm font-bold text-ink">
              <Info className="size-4 shrink-0 text-ink-soft" />
              <span className="flex-1">{t("emHowTo")}</span>
              <ChevronDown className="size-4 shrink-0 text-ink-soft transition-transform group-open:rotate-180" />
            </summary>
            <p className="mt-2 text-xs leading-relaxed text-ink-soft">{t("emRawWhy")}</p>
            <ul className="mt-2 space-y-1.5 text-xs leading-relaxed text-ink">
              {(["emGmailHow", "emOutlookHow", "emOutlookDesktopHow", "emAppleHow"] as const).map((k) => (
                <li key={k} className="flex gap-2">
                  <span className="mt-1.5 size-1.5 shrink-0 rounded-full bg-emerald-600" />
                  <span>{t(k)}</span>
                </li>
              ))}
            </ul>
          </details>
        )}

        <LlmPanel open={llmOpen} onToggle={() => setLlmOpen((o) => !o)} error={llmError} />

        <button
          type="submit"
          disabled={busy}
          className="flex w-full items-center justify-center gap-2 rounded-2xl bg-emerald-700 px-4 py-3 text-sm font-bold text-white shadow-sm transition hover:bg-emerald-800 active:scale-[0.98] disabled:opacity-60"
        >
          <ShieldCheck className="size-4" />
          {t("emScan")}
        </button>
      </form>

      <div className="mt-3 flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold text-ink-soft/80">{t("checkTry")}</span>
        <button
          type="button"
          onClick={() => {
            setMode("text");
            setText(SAMPLE_SCAM_EMAIL);
            setError(null);
          }}
          className="rounded-full bg-crimson-50 px-3 py-1 font-semibold text-crimson-700 ring-1 ring-crimson-600/20 hover:bg-crimson-600/15 dark:bg-crimson-600/15 dark:text-red-300 dark:ring-crimson-600/40"
        >
          {t("emTrySample")}
        </button>
      </div>
      <p className="mt-3 flex items-start gap-1.5 text-xs leading-relaxed text-ink-soft/80">
        <Lock className="mt-0.5 size-3.5 shrink-0" /> {t("emPrivacy")}
      </p>
    </section>
  );
}
