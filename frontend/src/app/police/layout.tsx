import type { Viewport } from "next";
import { LegacyNightGridScope } from "@/components/LegacyNightGridScope";

// /police (Command Center + login) intentionally stays on the legacy Night Grid design
// (palette, Barlow + Noto Kufi, dark by default) until the owner supplies its new format.
// See DESIGN.md "Legacy scope: /police".
export const viewport: Viewport = {
  themeColor: "#0B192C",
};

export default function PoliceLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return <LegacyNightGridScope>{children}</LegacyNightGridScope>;
}
