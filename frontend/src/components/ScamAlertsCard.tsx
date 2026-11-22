"use client";

import { AnimatePresence, motion } from "framer-motion";
import { BellOff, BellRing, Check, CircleAlert, Loader2, PlusSquare, Send, Share, ShieldCheck, Smartphone } from "lucide-react";
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { deletePushSubscription, getVapidPublicKey, savePushSubscription, sendTestAlert } from "@/lib/api";
import { useLang } from "@/lib/i18n";

type State = "checking" | "ios-add-home" | "unsupported" | "denied" | "off" | "busy" | "on";

const noopSubscribe = () => () => {};

function isIos(): boolean {
  return /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

function isStandalone(): boolean {
  return window.matchMedia("(display-mode: standalone)").matches || (navigator as Navigator & { standalone?: boolean }).standalone === true;
}

function pushSupported(): boolean {
  return "serviceWorker" in navigator && "PushManager" in window && "Notification" in window;
}

function urlBase64ToUint8Array(base64: string): Uint8Array<ArrayBuffer> {
  const padding = "=".repeat((4 - (base64.length % 4)) % 4);
  const raw = atob((base64 + padding).replace(/-/g, "+").replace(/_/g, "/"));
  const out = new Uint8Array(new ArrayBuffer(raw.length));
  for (let i = 0; i < raw.length; i++) out[i] = raw.charCodeAt(i);
  return out;
}

async function registration(): Promise<ServiceWorkerRegistration> {
  const existing = await navigator.serviceWorker.getRegistration("/");
  return existing ?? navigator.serviceWorker.register("/sw.js");
}

/** iOS-style preview of the alert the phone will receive. */
function AlertPreview() {
  const { t } = useLang();
  return (
    <motion.div
      initial={{ opacity: 0, y: -8, scale: 0.98 }}
      animate={{ opacity: 1, y: 0, scale: 1 }}
      transition={{ type: "spring", stiffness: 260, damping: 22, delay: 0.15 }}
      className="rounded-2xl bg-white/80 p-3 shadow-[0_8px_30px_-12px_rgba(11,25,44,0.35)] ring-1 ring-black/5 backdrop-blur dark:bg-white/10 dark:ring-white/10"
      aria-hidden
    >
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-navy-900/60 dark:text-white/60">
        <span className="grid size-5 place-items-center rounded-md bg-navy-900 text-gold-500">
          <ShieldCheck className="size-3" />
        </span>
        {t("alPreviewApp")}
        <span className="ms-auto font-medium normal-case">{t("alPreviewNow")}</span>
      </div>
      <p className="mt-1.5 text-[13.5px] font-bold leading-snug text-navy-900 dark:text-white">{t("alPreviewTitle")}</p>
      <p className="mt-0.5 text-[12.5px] leading-snug text-navy-900/75 dark:text-white/75">{t("alPreviewBody")}</p>
    </motion.div>
  );
}

function IosSteps() {
  const { t } = useLang();
  const steps = [
    { icon: Share, text: t("alIos1") },
    { icon: PlusSquare, text: t("alIos2") },
    { icon: Smartphone, text: t("alIos3") },
  ];
  return (
    <div className="rounded-2xl bg-muted p-4 ring-1 ring-line">
      <p className="font-bold text-ink">{t("alIosTitle")}</p>
      <p className="mt-0.5 text-sm text-ink-soft">{t("alIosIntro")}</p>
      <ol className="mt-3 space-y-2.5">
        {steps.map(({ icon: Icon, text }, i) => (
          <li key={i} className="flex items-center gap-3">
            <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-surface text-[#0a84ff] shadow-sm ring-1 ring-line">
              <Icon className="size-4.5" />
            </span>
            <span className="text-sm font-medium text-ink">
              <span className="me-1.5 font-extrabold text-ink-soft/60">{i + 1}.</span>
              {text}
            </span>
          </li>
        ))}
      </ol>
      <p className="mt-3 text-xs text-ink-soft/75">{t("alIosOld")}</p>
    </div>
  );
}

export function ScamAlertsCard() {
  const { t, lang } = useLang();
  const ready = useSyncExternalStore(noopSubscribe, () => true, () => false);
  const [state, setState] = useState<State>("checking");
  const [endpoint, setEndpoint] = useState<string | null>(null);
  const [toast, setToast] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);

  const flash = useCallback((ok: boolean, text: string) => {
    setToast({ ok, text });
    window.setTimeout(() => setToast(null), 4000);
  }, []);

  // Work out what this device can do (runs once in the browser).
  useEffect(() => {
    if (!ready) return;
    let alive = true;
    (async () => {
      let next: State;
      let ep: string | null = null;
      if (!pushSupported()) next = isIos() && !isStandalone() ? "ios-add-home" : "unsupported";
      else if (isIos() && !isStandalone()) next = "ios-add-home";
      else if (Notification.permission === "denied") next = "denied";
      else {
        try {
          const sub = await (await registration()).pushManager.getSubscription();
          ep = sub?.endpoint ?? null;
          next = sub ? "on" : "off";
        } catch {
          next = "off";
        }
      }
      if (alive) {
        setEndpoint(ep);
        setState(next);
      }
    })();
    return () => {
      alive = false;
    };
  }, [ready]);

  const enable = async () => {
    setState("busy");
    try {
      const permission = await Notification.requestPermission();
      if (permission !== "granted") {
        setState(permission === "denied" ? "denied" : "off");
        return;
      }
      const reg = await registration();
      await navigator.serviceWorker.ready;
      const key = await getVapidPublicKey();
      const sub =
        (await reg.pushManager.getSubscription()) ??
        (await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: urlBase64ToUint8Array(key) }));
      await savePushSubscription(sub.toJSON(), lang);
      setEndpoint(sub.endpoint);
      setState("on");
    } catch {
      setState("off");
      flash(false, t("alError"));
    }
  };

  const disable = async () => {
    setState("busy");
    try {
      const sub = await (await registration()).pushManager.getSubscription();
      if (sub) {
        await deletePushSubscription(sub.endpoint).catch(() => undefined);
        await sub.unsubscribe();
      }
    } finally {
      setEndpoint(null);
      setState("off");
    }
  };

  const test = async () => {
    if (!endpoint) return;
    setTesting(true);
    try {
      await sendTestAlert(endpoint);
      flash(true, t("alTestSent"));
    } catch (e) {
      flash(false, e instanceof Error ? e.message : t("alError"));
    } finally {
      setTesting(false);
    }
  };

  const on = state === "on";

  return (
    <section aria-labelledby="alerts-title" className="overflow-hidden rounded-3xl bg-surface shadow-sm ring-1 ring-line">
      <div className={`relative overflow-hidden p-4 sm:p-5 ${on ? "bg-gradient-to-br from-emerald-700 via-emerald-600 to-emerald-800" : "bg-gradient-to-br from-navy-900 via-navy-800 to-navy-950"}`}>
        <div className="pointer-events-none absolute -end-10 -top-12 size-44 rounded-full bg-white/10 blur-2xl" />
        <div className="relative flex items-start gap-3 text-white">
          <motion.span
            className="grid size-11 shrink-0 place-items-center rounded-2xl bg-white/15 ring-1 ring-white/25"
            animate={on ? { rotate: [0, -14, 12, -8, 6, 0] } : { rotate: 0 }}
            transition={on ? { duration: 1.1, repeat: Infinity, repeatDelay: 3.5 } : undefined}
          >
            {on ? <BellRing className="size-5.5" /> : <BellRing className="size-5.5 text-gold-500" />}
          </motion.span>
          <div className="min-w-0">
            <h2 id="alerts-title" className="text-lg font-extrabold leading-tight">
              {t("alTitle")}
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-white/80">{on ? t("alOnSub") : t("alIntro")}</p>
          </div>
        </div>
        <div className="relative mt-4">
          <AlertPreview />
        </div>
      </div>

      <div className="space-y-3 p-4 sm:p-5">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div key={state} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }}>
            {state === "checking" && <div className="h-12 animate-pulse rounded-2xl bg-muted" />}

            {state === "ios-add-home" && <IosSteps />}

            {state === "unsupported" && (
              <p className="flex items-start gap-2 rounded-2xl bg-muted p-3 text-sm text-ink-soft ring-1 ring-line">
                <CircleAlert className="mt-0.5 size-4 shrink-0 text-amber-500" />
                {t("alUnsupported")}
              </p>
            )}

            {state === "denied" && (
              <div className="rounded-2xl bg-amber-50 p-3.5 text-sm text-amber-900 ring-1 ring-amber-500/30 dark:bg-amber-500/10 dark:text-amber-100">
                <p className="flex items-center gap-2 font-bold">
                  <BellOff className="size-4" /> {t("alDenied")}
                </p>
                <p className="mt-1.5">{isIos() ? t("alDeniedIos") : t("alDeniedAndroid")}</p>
              </div>
            )}

            {(state === "off" || state === "busy") && (
              <button
                type="button"
                onClick={enable}
                disabled={state === "busy"}
                className="group relative flex w-full items-center justify-center gap-2.5 overflow-hidden rounded-2xl bg-emerald-600 px-5 py-4 text-base font-extrabold text-white shadow-[0_10px_30px_-10px_rgba(16,185,129,0.8)] transition hover:bg-emerald-700 active:scale-[0.98] disabled:opacity-80"
              >
                <span className="pointer-events-none absolute inset-0 animate-[shimmer_3s_linear_infinite] bg-[linear-gradient(110deg,transparent_35%,rgba(255,255,255,0.25)_50%,transparent_65%)] bg-[length:200%_100%]" />
                {state === "busy" ? <Loader2 className="relative size-5 animate-spin" /> : <BellRing className="relative size-5" />}
                <span className="relative">{state === "busy" ? t("alEnabling") : t("alEnable")}</span>
              </button>
            )}

            {state === "on" && (
              <div className="space-y-3">
                <p className="flex items-center gap-2.5 rounded-2xl bg-emerald-50 p-3 text-sm font-bold text-emerald-800 ring-1 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-200">
                  <span className="grid size-6 place-items-center rounded-full bg-emerald-600 text-white">
                    <Check className="size-3.5" />
                  </span>
                  {t("alOn")}
                </p>
                <div className="grid grid-cols-[1fr_auto] gap-2">
                  <button
                    type="button"
                    onClick={test}
                    disabled={testing}
                    className="inline-flex items-center justify-center gap-2 rounded-2xl bg-navy-900 px-4 py-3 text-sm font-bold text-white transition hover:bg-navy-800 active:scale-[0.98] disabled:opacity-70 dark:bg-white dark:text-navy-900 dark:hover:bg-white/90"
                  >
                    {testing ? <Loader2 className="size-4 animate-spin" /> : <Send className="size-4" />}
                    {t("alTest")}
                  </button>
                  <button
                    type="button"
                    onClick={disable}
                    className="inline-flex items-center justify-center gap-2 rounded-2xl bg-muted px-4 py-3 text-sm font-bold text-ink-soft ring-1 ring-line transition hover:text-ink"
                  >
                    <BellOff className="size-4" />
                    {t("alOff")}
                  </button>
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>

        <AnimatePresence>
          {toast && (
            <motion.p
              role="status"
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              className={`rounded-xl px-3 py-2 text-sm font-semibold ${
                toast.ok ? "bg-emerald-50 text-emerald-800 dark:bg-emerald-500/15 dark:text-emerald-200" : "bg-amber-50 text-amber-900 dark:bg-amber-500/15 dark:text-amber-200"
              }`}
            >
              {toast.text}
            </motion.p>
          )}
        </AnimatePresence>

        <p className="text-[11px] leading-relaxed text-ink-soft/75">{t("alHow")}</p>
      </div>
    </section>
  );
}
