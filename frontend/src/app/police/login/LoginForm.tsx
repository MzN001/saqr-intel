"use client";

import { KeyRound, Loader2, ShieldCheck } from "lucide-react";
import { useRouter } from "next/navigation";
import { useEffect, useState, type FormEvent } from "react";
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
      <header className="border-b border-line bg-surface">
        <div className="mx-auto flex h-[76px] max-w-[1500px] items-center gap-3 px-4 sm:px-6">
          <button type="button" onClick={() => setLang(lang === "en" ? "ar" : "en")} className="rounded-full px-3 py-2 text-[15px] text-ink-soft hover:text-ink">
            {lang === "en" ? "العربية" : "English"}
          </button>
          <ThemeToggle />
          <div className="ms-auto flex items-center gap-3">
            <div className="text-end leading-tight">
              <p className="whitespace-nowrap text-lg font-bold text-ink sm:text-[22px]" lang="ar" dir="rtl">شرطة أبوظبي</p>
              <p className="whitespace-nowrap text-[11px] font-bold uppercase tracking-[0.06em] text-ink sm:text-[15px]">Abu Dhabi Police</p>
            </div>
            <span className="grid size-11 shrink-0 place-items-center rounded-full border-[3px] border-gold-500 bg-navy-900 sm:size-[54px]" aria-hidden>
              <ShieldCheck className="size-6 text-gold-500" />
            </span>
          </div>
        </div>
      </header>

      <main className="flex flex-1 items-center justify-center px-4 py-10">
        <section className="w-full max-w-md rounded-[20px] border border-line bg-surface p-6" aria-labelledby="officer-login-title">
          <p className="text-[11px] font-bold uppercase tracking-[0.14em] text-ink-soft">{L("subtitle")}</p>
          <h1 id="officer-login-title" className="mt-1 text-lg font-extrabold leading-tight text-ink">{L("loginTitle")}</h1>

          {configured ? (
            <form onSubmit={submit} className="mt-5 space-y-4" noValidate>
              <p className="text-sm text-ink-soft">{L("loginIntro")}</p>
              <div>
                <label htmlFor="officer-passcode" className="mb-1.5 block text-[11px] font-bold uppercase tracking-[0.14em] text-ink-soft">
                  {L("passcode")}
                </label>
                <div className="flex items-center gap-2 rounded-2xl bg-muted px-3.5 py-px ring-1 ring-line transition-shadow focus-within:ring-2 focus-within:ring-emerald-600">
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
                    className="h-12 min-w-0 flex-1 bg-transparent text-sm text-ink outline-hidden"
                    dir="ltr"
                  />
                </div>
              </div>
              {status.state === "error" && (
                <p id="officer-login-error" role="alert" className="text-sm font-semibold text-gold-ink">{L(status.key)}</p>
              )}
              <button
                type="submit"
                disabled={busy || !passcode}
                className="press inline-flex w-full items-center justify-center gap-2 rounded-2xl bg-gold-500 px-4 py-3 text-sm font-extrabold text-navy-950 hover:brightness-110 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {busy && <Loader2 className="size-4 animate-spin" />} {busy ? L("signingIn") : L("signIn")}
              </button>
            </form>
          ) : (
            <p role="alert" className="mt-5 text-sm font-semibold text-gold-ink">{L("notConfigured")}</p>
          )}

          <p className="mt-6 border-t border-line pt-4 text-xs text-ink-soft">{L("hackathonNote")}</p>
        </section>
      </main>
    </div>
  );
}
