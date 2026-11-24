"use client";

import { useEffect } from "react";
import { API_BASE_URL } from "@/lib/api";

const KEY = "saqr-warmed";

/**
 * Wakes the free Render backend as soon as a citizen opens the app, so the first real scan does not
 * wait ~30-60 s for a cold start. Once per browser tab session, fire-and-forget, no UI.
 * Skipped when API_BASE_URL is empty (local dev: the backend runs on the laptop and never sleeps,
 * and `/health` is not proxied by next.config).
 */
export function WarmUp() {
  useEffect(() => {
    if (!API_BASE_URL) return;
    try {
      if (window.sessionStorage.getItem(KEY)) return;
      window.sessionStorage.setItem(KEY, "1");
    } catch {
      /* storage blocked (private mode): ping anyway */
    }
    void fetch(`${API_BASE_URL}/health`, { mode: "no-cors", cache: "no-store" }).catch(() => undefined);
  }, []);
  return null;
}
