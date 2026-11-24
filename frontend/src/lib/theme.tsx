"use client";

import { useCallback, useLayoutEffect, useSyncExternalStore } from "react";
import { flushSync } from "react-dom";
import { THEME_STORAGE_KEY } from "./theme-script";

export type Theme = "light" | "dark";

const listeners = new Set<() => void>();

// Theme used when the visitor has not saved a choice: light everywhere (Saqr default).
const routeDefault: Theme = "light";

function readStored(): Theme {
  try {
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === "light" || saved === "dark") return saved; // a saved choice always wins
  } catch {
    /* storage unavailable (private mode) */
  }
  return routeDefault;
}

function applyToDocument(theme: Theme) {
  const root = document.documentElement;
  if (theme === "dark") root.setAttribute("data-theme", "dark");
  else root.removeAttribute("data-theme");
}

const themeStore = {
  subscribe(cb: () => void) {
    listeners.add(cb);
    return () => {
      listeners.delete(cb);
    };
  },
  getSnapshot(): Theme {
    return readStored();
  },
  getServerSnapshot(): Theme {
    return "light"; // Saqr default; the <head> script has already applied the real theme before paint
  },
  set(theme: Theme) {
    try {
      window.localStorage.setItem(THEME_STORAGE_KEY, theme);
    } catch {
      /* storage unavailable (private mode) */
    }
    applyToDocument(theme);
    listeners.forEach((cb) => cb());
  },
};

export function prefersReducedMotion(): boolean {
  return typeof window !== "undefined" && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

/**
 * Switch theme with a page-wide animation: a circle grows out of `origin`
 * (the toggle button) revealing the new colours. Falls back to a colour fade
 * where the View Transitions API is missing, and to an instant switch when the
 * user asked the OS for reduced motion.
 */
function switchTheme(next: Theme, origin?: { x: number; y: number }) {
  const apply = () => themeStore.set(next);

  if (prefersReducedMotion()) {
    apply();
    return;
  }

  if (typeof document.startViewTransition !== "function") {
    const root = document.documentElement;
    root.classList.add("theme-fading");
    apply();
    window.setTimeout(() => root.classList.remove("theme-fading"), 500);
    return;
  }

  const x = origin?.x ?? window.innerWidth / 2;
  const y = origin?.y ?? 0;
  const radius = Math.hypot(Math.max(x, window.innerWidth - x), Math.max(y, window.innerHeight - y));

  const transition = document.startViewTransition(() => flushSync(apply));
  transition.ready
    .then(() => {
      document.documentElement.animate(
        { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${radius}px at ${x}px ${y}px)`] },
        { duration: 700, easing: "cubic-bezier(0.65, 0, 0.35, 1)", pseudoElement: "::view-transition-new(root)" },
      );
    })
    .catch(() => undefined);
}

export function useTheme() {
  const theme = useSyncExternalStore(themeStore.subscribe, themeStore.getSnapshot, themeStore.getServerSnapshot);

  // The <head> script sets the attribute on first load; this re-applies it after
  // React's dev-mode remount clears attributes on <html>. It reads the store (not the
  // hydration-time server snapshot) so a dark visitor is never flipped to light for a frame.
  useLayoutEffect(() => {
    applyToDocument(themeStore.getSnapshot());
  }, [theme]);

  const toggle = useCallback(
    (origin?: { x: number; y: number }) => switchTheme(theme === "dark" ? "light" : "dark", origin),
    [theme],
  );

  return { theme, toggle };
}
