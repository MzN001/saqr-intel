/** The citizen page's "windows": one tool on screen at a time, synced to `/citizen?view=`. */
export const VIEWS = ["check", "maps", "sms", "email", "live"] as const;
export type View = (typeof VIEWS)[number];

export function parseView(raw: string | null | undefined): View {
  return (VIEWS as readonly string[]).includes(raw ?? "") ? (raw as View) : "check";
}

/** `/citizen` for the default window, `/citizen?view=<id>` otherwise. */
export function viewHref(view: View): string {
  return view === "check" ? "/citizen" : `/citizen?view=${view}`;
}
