"use client";

import { getDeviceTag } from "@/lib/device";
import { AnimatePresence, motion } from "framer-motion";
import { BellOff, BellRing, Check, CircleAlert, Loader2, PlusSquare, Send, Share, ShieldCheck, Smartphone, Download } from "lucide-react";
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { apiUrl, deletePushSubscription, getVapidPublicKey, savePushSubscription, sendTestAlert } from "@/lib/api";
import { Disclosure } from "./Disclosure";
import { useLang } from "@/lib/i18n";

type State = "checking" | "ios-add-home" | "unsupported" | "denied" | "off" | "busy" | "on";

const noopSubscribe = () => () => {};

function isIos(): boolean {
  return /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

/** Alerts are per phone: the phone's DNS setting must carry its device tag (see lib/device.ts). */
function ThisPhoneOnly() {
  const { t } = useLang();
  const device = getDeviceTag();
  return (
    <div className="space-y-2 text-xs leading-relaxed text-ink-soft">
      <p>{t("alOnlyThis")}</p>
      {isIos() ? (
        <a
          href={apiUrl(`/api/ios-dns-profile${device ? `?device=${device}` : ""}`)}
          className="press inline-flex items-center gap-2 rounded-xl border border-line bg-canvas px-3 py-2 text-sm font-bold text-ink hover:bg-muted"
        >
          <Download className="size-4" /> {t("alLinkIos")}
        </a>
      ) : (
        <p>{t("alLinkAndroid")}</p>
      )}
    </div>
  );
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

/** Resolve `p`, or reject after `ms` so a stalled browser API can't leave the card loading forever. */
function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const id = window.setTimeout(() => reject(new Error("timeout")), ms);
    p.then(
      (v) => {
        window.clearTimeout(id);
        resolve(v);
      },
      (e) => {
        window.clearTimeout(id);
        reject(e);
      },
    );
  });
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
      className="border-t border-line pt-3"
      aria-hidden
    >
      <div className="flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-ink-soft">
        <span className="grid size-5 place-items-center rounded-md bg-navy-900 text-gold-500">
          <ShieldCheck className="size-3" />
        </span>
        {t("alPreviewApp")}
        <span className="ms-auto font-medium normal-case">{t("alPreviewNow")}</span>
      </div>
      <p className="mt-1.5 text-[13.5px] font-bold leading-snug text-ink">{t("alPreviewTitle")}</p>
      <p className="mt-0.5 text-[12.5px] leading-snug text-ink-soft">{t("alPreviewBody")}</p>
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
    <div className="border-t border-line pt-4">
      <p className="font-bold text-ink">{t("alIosTitle")}</p>
      <p className="mt-0.5 text-sm text-ink-soft">{t("alIosIntro")}</p>
      <ol className="mt-3 space-y-2.5">
        {steps.map(({ icon: Icon, text }, i) => (
          <li key={i} className="flex items-center gap-3">
            <span className="grid size-9 shrink-0 place-items-center rounded-xl bg-muted text-[#0a84ff]">
              <Icon className="size-4.5" />
            </span>
            <span className="text-sm font-medium text-ink">
              <span className="me-1.5 font-extrabold text-ink-soft/80">{i + 1}.</span>
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
          const sub = await withTimeout(registration().then((r) => r.pushManager.getSubscription()), 5000);
          ep = sub?.endpoint ?? null;
          next = sub ? "on" : "off";
          // Cloud backends can restart with an empty phone list (Render free tier): re-register
          // silently every time SAQR opens, so alerts keep working without tapping Enable again.
          if (sub) void savePushSubscription(sub.toJSON(), lang).catch(() => undefined);
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
  }, [ready, lang]);

  // An iPhone home-screen app resumes from the background without reloading, so also re-register
  // whenever SAQR comes back to the front (the cloud backend may have restarted meanwhile).
  useEffect(() => {
    if (!ready || state !== "on") return;
    const onVisible = async () => {
      if (document.visibilityState !== "visible") return;
      try {
        const sub = await (await registration()).pushManager.getSubscription();
        if (sub) await savePushSubscription(sub.toJSON(), lang);
      } catch {
        /* offline or waking up: the next resume tries again */
      }
    };
    document.addEventListener("visibilitychange", onVisible);
    window.addEventListener("pageshow", onVisible);
    return () => {
      document.removeEventListener("visibilitychange", onVisible);
      window.removeEventListener("pageshow", onVisible);
    };
  }, [ready, state, lang]);

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
    <section aria-labelledby="alerts-title" className="overflow-hidden rounded-[20px] border border-line bg-surface">
      <div className="p-4 pb-0 sm:p-5 sm:pb-0">
        <div className="flex items-start gap-3 text-ink">
          <motion.span
            className={`grid size-10 shrink-0 place-items-center rounded-xl ${on ? "bg-emerald-700 text-white" : "bg-navy-900 text-gold-500"}`}
            animate={on ? { rotate: [0, -14, 12, -8, 6, 0] } : { rotate: 0 }}
            transition={on ? { duration: 1.1, repeat: 1, repeatDelay: 1.5 } : undefined}
          >
            <BellRing className="size-5" />
          </motion.span>
          <div className="min-w-0">
            <h2 id="alerts-title" className="text-balance text-base font-extrabold leading-snug sm:text-lg sm:leading-tight">
              {t("alTitle")}
            </h2>
            <p className="mt-1 text-sm leading-relaxed text-ink-soft">{on ? t("alOnSub") : t("alIntro")}</p>
          </div>
        </div>
        <div className="mt-4">
          <AlertPreview />
        </div>
      </div>

      <div className="space-y-3 p-4 sm:p-5">
        <AnimatePresence mode="wait" initial={false}>
          <motion.div key={state} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }}>
            {state === "checking" && <div className="h-12 animate-pulse rounded-2xl bg-muted" />}

            {state === "ios-add-home" && <IosSteps />}

            {state === "unsupported" && (
              <p className="flex items-start gap-2 border-t border-line pt-3 text-sm text-ink-soft">
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
                className="group relative flex w-full items-center justify-center gap-2.5 overflow-hidden rounded-2xl bg-emerald-700 px-5 py-4 text-base font-extrabold text-white transition hover:bg-emerald-800 active:scale-[0.98] disabled:opacity-80"
              >
                <span className="pointer-events-none absolute inset-0 animate-[shimmer_2.5s_ease-out_1] bg-[linear-gradient(110deg,transparent_35%,rgba(255,255,255,0.25)_50%,transparent_65%)] bg-[length:200%_100%]" />
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
                <ThisPhoneOnly />
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

        <Disclosure summary={t("howItWorks")}>
          <p className="text-xs leading-relaxed text-ink-soft">{t("alHow")}</p>
        </Disclosure>
      </div>
    </section>
  );
}
