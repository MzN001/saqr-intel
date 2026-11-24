/**
 * The citizen page's "windows": one tool on screen at a time, synced to `/citizen?view=`.
 * Desktop header tabs: check | maps | sms | email | live.
 * Phone bottom navigation (< 768px): check | shield | alerts | learn. `shield` (phone shield setup),
 * `alerts` (scam alerts + the live feed) and `learn` (more ways to check) also open on desktop as plain
 * windows with a back link, so a shared `?view=` link always lands somewhere sensible.
 */
export const VIEWS = ["check", "maps", "sms", "email", "live", "shield", "alerts", "learn"] as const;
export type View = (typeof VIEWS)[number];

/** Bottom-navigation tabs on phones. */
export const MOBILE_TABS = ["check", "shield", "alerts", "learn"] as const;
export type MobileTab = (typeof MOBILE_TABS)[number];

/** Which bottom tab is active for a window: tool windows sit under "Learn", the live feed under "Alerts". */
export function mobileTabOf(view: View): MobileTab {
  if (view === "check" || view === "shield" || view === "alerts" || view === "learn") return view;
  return view === "live" ? "alerts" : "learn";
}

export function parseView(raw: string | null | undefined): View {
  return (VIEWS as readonly string[]).includes(raw ?? "") ? (raw as View) : "check";
}

/** `/citizen` for the default window, `/citizen?view=<id>` otherwise. */
export function viewHref(view: View): string {
  return view === "check" ? "/citizen" : `/citizen?view=${view}`;
}
