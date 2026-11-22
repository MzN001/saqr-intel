import { useSyncExternalStore } from "react";

const noop = () => () => {};

/** False during SSR and before hydration, true once React owns the page. */
export function useHydrated(): boolean {
  return useSyncExternalStore(noop, () => true, () => false);
}
