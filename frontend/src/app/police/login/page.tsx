import type { Metadata } from "next";
import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { LanguageProvider } from "@/lib/i18n";
import { SESSION_COOKIE, authMode, safeNext, verify } from "@/lib/officer-session";
import { LoginForm } from "./LoginForm";

export const metadata: Metadata = {
  title: "SAQR-INTEL · Officer sign-in",
  description: "Abu Dhabi Police Cyber-Patrol Command Center sign-in.",
  robots: { index: false, follow: false },
};

export default async function OfficerLoginPage({ searchParams }: { searchParams: Promise<{ next?: string | string[] }> }) {
  const sp = await searchParams;
  const next = safeNext(Array.isArray(sp.next) ? sp.next[0] : sp.next);
  const mode = authMode();
  if (mode === "dev-open") redirect(next);
  if (mode === "locked" && verify((await cookies()).get(SESSION_COOKIE)?.value)) redirect(next);
  return (
    <LanguageProvider>
      <LoginForm next={next} configured={mode === "locked"} />
    </LanguageProvider>
  );
}
