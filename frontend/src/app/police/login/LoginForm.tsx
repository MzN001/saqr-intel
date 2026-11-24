"use client";

import { KeyRound, Loader2 } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
import { SaqrLogo } from "@/components/SaqrLogo";
import { ThemeToggle } from "@/components/ThemeToggle";
import { API_BASE_URL } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { P } from "@/lib/police";

type Status = { state: "idle" } | { state: "busy" } | { state: "error"; key: "wrongPasscode" | "tooManyTries" | "loginFailed" | "notConfigured" };

export function LoginForm({ next, configured }: { next: string; configured: boolean }) {
  const { lang, setLang } = useLang();
  const L = (k: keyof typeof P) => P[k][lang];
  const router = useRouter();
  const [passcode, setPasscode] = useState("");
  const [status, setStatus] = useState<Status>({ state: "idle" });

  // Wake the (free-tier) backend while the officer types. Fire-and-forget; the answer is not read.
  useEffect(() => {
    if (!API_BASE_URL) return; // local backend: nothing to wake
    try {
      void fetch(`${API_BASE_URL}/health`, { mode: "no-cors", cache: "no-store" }).catch(() => undefined);
    } catch {
      /* ignore */
    }
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!configured || !passcode || status.state === "busy") return;
    setStatus({ state: "busy" });
    try {
      const res = await fetch("/api/officer/login", {
        method: "POST",
        headers: { "content-type": "application/json" },
        credentials: "same-origin",
        body: JSON.stringify({ passcode }),
      });
      if (res.ok) {
        router.replace(next.startsWith("/police") ? next : "/police");
        return;
      }
      setPasscode("");
      setStatus({
        state: "error",
        key: res.status === 429 ? "tooManyTries" : res.status === 401 ? "wrongPasscode" : res.status === 503 ? "notConfigured" : "loginFailed",
      });
    } catch {
      setStatus({ state: "error", key: "loginFailed" });
    }
  };

  const busy = status.state === "busy";

  return (
    <div className="flex min-h-dvh flex-col bg-canvas text-ink">
      <header className="border-b border-line bg-surface/95 backdrop-blur-md">
        <div className="mx-auto flex h-16 max-w-[1500px] items-center gap-3 px-4 sm:px-6">
          <span className="flex shrink-0 items-center gap-3">
            <SaqrLogo variant="full" size={26} />
            <span className="hidden h-6 w-px bg-line sm:block" aria-hidden />
            <span className="label-caps hidden whitespace-nowrap sm:block">{L("brandLabel")}</span>
          </span>
          <div className="ms-auto flex shrink-0 items-center gap-2">
            <div role="radiogroup" aria-label="Language / اللغة" dir="ltr" className="flex shrink-0 rounded-full border border-line bg-surface p-0.5">
              {(["en", "ar"] as const).map((l) => (
                <button
                  key={l}
                  type="button"
                  role="radio"
                  aria-checked={lang === l}
                  onClick={() => setLang(l)}
                  lang={l}
                  className={`min-h-9 min-w-10 rounded-full px-3 text-[13px] font-semibold transition-colors md:min-w-0 ${lang === l ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"}`}
                >
                  {l === "en" ? "EN" : "عربي"}
                </button>
              ))}
            </div>
            <ThemeToggle variant="saqr" />
          </div>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-4 py-10">
        <section className="card w-full max-w-md p-6 sm:p-8" aria-labelledby="officer-login-title">
          <SaqrLogo variant="full" size={36} className="mb-5" />
          <p className="label-caps">{L("subtitle")}</p>
          <h1 id="officer-login-title" className="mt-1 text-xl font-semibold leading-tight text-ink">{L("loginTitle")}</h1>

          {configured ? (
            <form onSubmit={submit} className="mt-5 space-y-4" noValidate>
              <p className="text-sm text-ink-soft">{L("loginIntro")}</p>
              <div>
                <label htmlFor="officer-passcode" className="label-caps mb-1.5 block">
                  {L("passcode")}
                </label>
                <div className="flex min-h-12 items-center gap-2 rounded-control border border-line bg-surface px-3.5 transition-shadow focus-within:border-transparent focus-within:outline-2 focus-within:outline-focus">
                  <KeyRound className="size-4 shrink-0 text-ink-soft" aria-hidden />
                  <input
                    id="officer-passcode"
                    type="password"
                    autoComplete="current-password"
                    autoFocus
                    required
                    value={passcode}
                    onChange={(e) => setPasscode(e.target.value)}
                    aria-invalid={status.state === "error" ? true : undefined}
                    aria-describedby={status.state === "error" ? "officer-login-error" : undefined}
                    className="h-12 min-w-0 flex-1 bg-transparent text-base text-ink outline-hidden"
                    dir="ltr"
                  />
                </div>
              </div>
              {status.state === "error" && (
                <p id="officer-login-error" role="alert" className="rounded-xl bg-scam-soft px-3 py-2 text-sm font-semibold text-scam-ink">{L(status.key)}</p>
              )}
              <button
                type="submit"
                disabled={busy || !passcode}
                className="btn-brand press w-full"
              >
                {busy && <Loader2 className="size-4 animate-spin" />} {busy ? L("signingIn") : L("signIn")}
              </button>
            </form>
          ) : (
            <p role="alert" className="mt-5 rounded-xl bg-suspicious-soft px-3 py-2 text-sm font-semibold text-suspicious-ink">{L("notConfigured")}</p>
          )}

          <p className="mt-6 border-t border-line pt-4 text-xs text-ink-soft">{L("hackathonNote")}</p>
        </section>
      </main>
    </div>
  );
}
