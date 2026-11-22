"use client";

import { THEME_INIT_SCRIPT } from "@/lib/theme-script";

// Runs during HTML parsing (server-rendered as text/javascript) so a saved dark
// theme is applied before first paint. On the client it renders as text/plain,
// which stops React warning about <script> tags (Next.js "preventing flash" guide).
export function ThemeScript() {
  return (
    <script
      type={typeof window === "undefined" ? "text/javascript" : "text/plain"}
      suppressHydrationWarning
      dangerouslySetInnerHTML={{ __html: THEME_INIT_SCRIPT }}
    />
  );
}
