"use client";

import type { ReactNode } from "react";
import { useLegacyNightGridScope } from "@/lib/theme";

/**
 * Wraps a route that must keep the pre-Saqr "Night Grid" look (today: /police, until the owner
 * supplies its new format). The `.brand-night-grid` class re-declares every design token with its
 * old value (globals.css). The wrapper uses `display: contents`, so it adds no box to the layout.
 */
export function LegacyNightGridScope({ children }: { children: ReactNode }) {
  useLegacyNightGridScope();
  return <div className="brand-night-grid contents">{children}</div>;
}
