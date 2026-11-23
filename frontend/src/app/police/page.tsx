import type { Metadata } from "next";
import { CommandCenter } from "@/components/police/CommandCenter";
import { LanguageProvider } from "@/lib/i18n";

export const metadata: Metadata = {
  title: "SAQR-INTEL · AD Police Cyber-Patrol Command Center",
  description: "Abu Dhabi Police Cyber-Patrol Command Center — live citizen interceptions, phishing campaigns and takedowns.",
  robots: { index: false, follow: false },
};

export default function PolicePage() {
  return (
    <LanguageProvider>
      <CommandCenter />
    </LanguageProvider>
  );
}
