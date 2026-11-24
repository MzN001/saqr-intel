import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { CommandCenter } from "@/components/police/CommandCenter";
import { LanguageProvider } from "@/lib/i18n";
import { SESSION_COOKIE, authMode, sessionOk } from "@/lib/officer-session";

export const metadata: Metadata = {
  title: "SAQR-INTEL · AD Police Cyber-Patrol Command Center",
  description: "Abu Dhabi Police Cyber-Patrol Command Center — live citizen interceptions, phishing campaigns and takedowns.",
  robots: { index: false, follow: false },
};

export default async function PolicePage() {
  // Second check behind proxy.ts: never render the dashboard without a valid officer session.
  const cookieStore = await cookies();
  if (!sessionOk(cookieStore.get(SESSION_COOKIE)?.value)) redirect("/police/login?next=%2Fpolice");
  const devOpen = authMode() === "dev-open";
  return (
    <LanguageProvider>
      <CommandCenter devOpen={devOpen} />
    </LanguageProvider>
  );
}
