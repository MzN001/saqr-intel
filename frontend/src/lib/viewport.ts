import { useSyncExternalStore } from "react";

/**
 * "mobile" below 768px (Tailwind `md`), "desktop" from 768px, null during SSR / before hydration.
 * The citizen page renders both layouts on the server (CSS shows the right one), then keeps only the
 * matching one mounted, so test ids and element ids stay unique once React owns the page.
 */
export type Viewport = "mobile" | "desktop";

const QUERY = "(max-width: 767.98px)";

function subscribe(cb: () => void) {
  const mq = window.matchMedia(QUERY);
  mq.addEventListener("change", cb);
  return () => mq.removeEventListener("change", cb);
}

export function useViewport(): Viewport | null {
  return useSyncExternalStore<Viewport | null>(
    subscribe,
    () => (window.matchMedia(QUERY).matches ? "mobile" : "desktop"),
    () => null,
  );
}

/** Imperative check for event handlers / effects. */
export function isMobileViewport(): boolean {
  return typeof window !== "undefined" && window.matchMedia(QUERY).matches;
}
