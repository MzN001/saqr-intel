"use client";

import { AnimatePresence, motion } from "framer-motion";
import { X } from "lucide-react";
import { useEffect, useId, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
import { useLang } from "@/lib/i18n";
import { useHydrated } from "@/lib/useHydrated";

export function Modal({
  open,
  onClose,
  title,
  children,
}: {
  open: boolean;
  onClose: () => void;
  title: ReactNode;
  children: ReactNode;
}) {
  const { t, dir } = useLang();
  const hydrated = useHydrated();
  const titleId = useId();
  const panel = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const previous = document.activeElement as HTMLElement | null;
    const focusables = () =>
      panel.current
        ? [...panel.current.querySelectorAll<HTMLElement>("a[href],button:not([disabled]),textarea,input,select")]
        : [];
    window.setTimeout(() => focusables()[0]?.focus(), 30);

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.stopPropagation();
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
    window.addEventListener("keydown", onKey, true);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      previous?.focus?.();
    };
  }, [open, onClose]);

  if (!hydrated) return null;

  return createPortal(
    <AnimatePresence>
      {open && (
        <motion.div
          key="modal"
          className="fixed inset-0 z-[70] flex items-end justify-center p-0 sm:items-center sm:p-6"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          dir={dir}
        >
          <button
            type="button"
            aria-label={t("close")}
            tabIndex={-1}
            onClick={onClose}
            className="absolute inset-0 cursor-default bg-navy-950/60 backdrop-blur-sm"
          />
          <motion.div
            ref={panel}
            role="dialog"
            aria-modal="true"
            aria-labelledby={titleId}
            initial={{ y: 40, opacity: 0, scale: 0.98 }}
            animate={{ y: 0, opacity: 1, scale: 1 }}
            exit={{ y: 40, opacity: 0, scale: 0.98 }}
            transition={{ type: "spring", stiffness: 320, damping: 30 }}
            className="relative max-h-[92dvh] w-full overflow-y-auto rounded-t-3xl bg-surface p-5 text-ink shadow-2xl ring-1 ring-line sm:max-w-lg sm:rounded-3xl"
          >
            <div className="mb-4 flex items-start justify-between gap-3">
              <h2 id={titleId} className="text-lg font-extrabold leading-snug">
                {title}
              </h2>
              <button
                type="button"
                onClick={onClose}
                aria-label={t("close")}
                className="-me-1 -mt-1 rounded-full p-2 text-ink-soft hover:bg-muted hover:text-ink"
              >
                <X className="size-5" />
              </button>
            </div>
            {children}
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>,
    document.body,
  );
}
