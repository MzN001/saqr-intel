"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Download, Smartphone, X } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useLang } from "@/lib/i18n";
import { useHydrated } from "@/lib/useHydrated";

/** The published Saqr Android app: the "universal" edition (scam-site firewall + Share to Saqr), which
 *  installs from a plain download. Also served at /downloads/Saqr-Shield.apk (redirect in next.config.mjs:
 *  keep the two in step). */
export const APK_URL = "https://github.com/MzN001/saqr-intel/releases/download/android-v0.2.0/Saqr-Shield.apk";

/** Android setup only: one row offering the native app, under the DNS setup. Hairline top border, no card. */
export function ApkDownloadRow() {
  const { t } = useLang();
  return (
    <div className="mt-6 flex flex-wrap items-center gap-x-4 gap-y-3 border-t border-line pt-5">
      <span className="grid size-10 shrink-0 place-items-center rounded-control bg-muted text-ink" aria-hidden>
        <Smartphone className="size-5" />
      </span>
      <div className="min-w-0 flex-1 basis-48">
        <p className="text-[15px] font-semibold text-ink">{t("apkTitle")}</p>
        <p className="mt-0.5 text-[13px] leading-snug text-ink-soft">{t("apkBody")}</p>
      </div>
      <a href={APK_URL} download rel="noopener" className="btn-secondary shrink-0 px-4 text-[14px]" data-testid="apk-download">
        <Download className="size-4" aria-hidden />
        {t("apkDownload")}
      </a>
    </div>
  );
}

const FOCUSABLE = "a[href],button:not([disabled]),textarea:not([disabled]),input:not([disabled]),select:not([disabled]),[tabindex]:not([tabindex='-1'])";
const EASE = [0.16, 1, 0.3, 1] as const;

/**
 * Slide-over drawer (DESIGN.md "Drawers / sheets"): from the inline-end side on tablets and desktops
 * (left in Arabic), a full-screen sheet from the bottom on phones. Focus is trapped inside, Esc and the
 * scrim close it, the page behind does not scroll, and focus returns to the opener on close.
 * A Modal opened from inside (e.g. the setup video) is portalled elsewhere and keeps its own trap.
 */
export function SetupDrawer({
  open,
  onClose,
  title,
  children,
  testId,
  wide = false,
  footer,
  canvas = false,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
  testId?: string;
  wide?: boolean;
  /** Optional sticky bottom area (one primary action). */
  footer?: ReactNode;
  /** Canvas-coloured body, for content made of white cards (the full verdict report). */
  canvas?: boolean;
}) {
  const { t, dir } = useLang();
  const hydrated = useHydrated();
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    const focusables = () => (panel.current ? [...panel.current.querySelectorAll<HTMLElement>(FOCUSABLE)] : []);
    const id = window.setTimeout(() => (focusables()[0] ?? panel.current)?.focus(), 40);

    const onKey = (e: KeyboardEvent) => {
      const inside = panel.current?.contains(document.activeElement) || document.activeElement === document.body;
      if (!inside) return; // a dialog opened on top of the drawer handles its own keys
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab") return;
      const items = focusables();
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    window.addEventListener("keydown", onKey);
    return () => {
      window.clearTimeout(id);
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
      previous?.focus?.();
    };
  }, [open, onClose]);

  if (!hydrated) return null;

  // Read at render time (client only, after hydration): phones get a bottom sheet, wider screens a side drawer.
  const desktop = window.matchMedia("(min-width: 640px)").matches;
  const offX = dir === "rtl" ? "-100%" : "100%";
  const hidden = desktop ? { x: offX, y: 0 } : { x: 0, y: "100%" };

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div key="drawer" className="fixed inset-0 z-[60]" dir={dir} initial={{ opacity: 1 }} exit={{ opacity: 1 }}>
          <motion.button
            type="button"
            aria-label={t("close")}
            tabIndex={-1}
            onClick={onClose}
            className="absolute inset-0 cursor-default bg-obsidian/50"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
          />
          <motion.div
            ref={panel}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            tabIndex={-1}
            data-testid={testId}
            initial={hidden}
            animate={{ x: 0, y: 0 }}
            exit={hidden}
            transition={{ duration: 0.3, ease: EASE }}
            className={`absolute inset-0 flex flex-col bg-surface text-ink shadow-overlay outline-hidden sm:inset-y-0 sm:start-auto sm:end-0 sm:w-full sm:border-s sm:border-line ${
              wide ? "sm:max-w-2xl" : "sm:max-w-md"
            }`}
          >
            <div className="flex shrink-0 items-center gap-3 border-b border-line px-4 py-2 sm:px-5">
              <h2 id={titleId} className="min-w-0 flex-1 text-[17px] font-semibold leading-snug">
                {title}
              </h2>
              <button
                type="button"
                onClick={onClose}
                aria-label={t("close")}
                data-testid={testId ? `${testId}-close` : undefined}
                className="-me-2 grid size-12 shrink-0 place-items-center rounded-full text-ink-soft hover:bg-muted hover:text-ink"
              >
                <X className="size-5" />
              </button>
            </div>
            <div className={`min-h-0 flex-1 overflow-y-auto overscroll-contain px-4 pt-5 sm:px-5 ${canvas ? "bg-canvas pb-0" : "pb-5"}`}>{children}</div>
            {footer && <div className="shrink-0 border-t border-line px-4 py-3 sm:px-5">{footer}</div>}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}
