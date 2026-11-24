"use client";

import { getDeviceTag } from "@/lib/device";
import { AnimatePresence, motion } from "framer-motion";
import { BellOff, BellRing, Check, Info, Loader2, PlusSquare, Send, Share, Smartphone, Download } from "lucide-react";
import { useCallback, useEffect, useState, useSyncExternalStore } from "react";
import { apiUrl, deletePushSubscription, getVapidPublicKey, savePushSubscription, sendTestAlert } from "@/lib/api";
import { SaqrLogo } from "./SaqrLogo";
import { useLang } from "@/lib/i18n";

type State = "checking" | "ios-add-home" | "unsupported" | "denied" | "off" | "busy" | "on";

const noopSubscribe = () => () => {};

/* "Are alerts on for this phone?" shared with the setup steps (done state). null = not known yet. */
let alertsOn: boolean | null = null;
const alertsListeners = new Set<() => void>();
function setAlertsOn(v: boolean) {
  if (alertsOn === v) return;
  alertsOn = v;
  alertsListeners.forEach((cb) => cb());
}
const alertsStore = {
  subscribe(cb: () => void) {
    alertsListeners.add(cb);
    return () => {
      alertsListeners.delete(cb);
    };
  },
  get: () => alertsOn,
  server: () => null,
};

/** True once this phone has a push subscription (checked quietly once, then kept in sync by the panel). */
export function useScamAlertsOn(): boolean {
  const on = useSyncExternalStore(alertsStore.subscribe, alertsStore.get, alertsStore.server);
  useEffect(() => {
    if (alertsOn !== null) return;
    if (!("serviceWorker" in navigator) || !("PushManager" in window)) return;
    navigator.serviceWorker
      .getRegistration("/")
      .then((r) => r?.pushManager.getSubscription())
      .then((sub) => setAlertsOn(Boolean(sub)))
      .catch(() => undefined);
  }, []);
  return on === true;
}

function isIos(): boolean {
  return /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
}

/** Alerts are per phone: the phone's DNS setting must carry its device tag (see lib/device.ts). */
function ThisPhoneOnly() {
  const { t } = useLang();
  const device = getDeviceTag();
  return (
    <div className="space-y-2 text-[13px] leading-relaxed text-ink-soft">
      <p>{t("alOnlyThis")}</p>
      {isIos() ? (
        <a href={apiUrl(`/api/ios-dns-profile${device ? `?device=${device}` : ""}`)} className="btn-secondary min-h-11 text-[14px]">
          <Download className="size-4" aria-hidden /> {t("alLinkIos")}
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
      className="rounded-card border border-line bg-muted p-3.5"
      aria-hidden
    >
      <div className="flex items-center gap-2 text-[12px] font-semibold text-ink-soft">
        <span className="grid size-6 place-items-center rounded-md bg-obsidian">
          <SaqrLogo variant="icon" theme="dark" size={16} />
        </span>
        {t("alPreviewApp")}
        <span className="ms-auto font-medium">{t("alPreviewNow")}</span>
      </div>
      <p className="mt-1.5 text-[14px] font-semibold leading-snug text-ink">{t("alPreviewTitle")}</p>
      <p className="mt-0.5 text-[13px] leading-snug text-ink-soft">{t("alPreviewBody")}</p>
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
    <div>
      <p className="text-[15px] font-semibold text-ink">{t("alIosTitle")}</p>
      <p className="mt-0.5 text-[14px] text-ink-soft">{t("alIosIntro")}</p>
      <ol className="mt-3 space-y-2.5">
        {steps.map(({ icon: Icon, text }, i) => (
          <li key={i} className="flex items-center gap-3">
            <span className="grid size-9 shrink-0 place-items-center rounded-control bg-muted text-ink">
              <Icon className="size-4.5" aria-hidden />
            </span>
            <span className="text-[15px] text-ink">
              <span className="me-1.5 font-semibold tabular-nums text-ink-soft">{i + 1}.</span>
              {text}
            </span>
          </li>
        ))}
      </ol>
      <p className="mt-3 text-[13px] text-ink-soft">{t("alIosOld")}</p>
    </div>
  );
}

/** Content of the "Scam alerts" drawer (step 3). */
export function ScamAlertsPanel() {
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
        if (next === "on" || next === "off") setAlertsOn(next === "on");
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
      setAlertsOn(true);
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
      setAlertsOn(false);
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

  return (
    <div className="space-y-5" data-testid="scam-alerts-panel">
      <p className="text-[15px] leading-relaxed text-ink-soft">{state === "on" ? t("alOnSub") : t("alIntro")}</p>
      <AlertPreview />

      <AnimatePresence mode="wait" initial={false}>
        <motion.div key={state} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }} transition={{ duration: 0.18 }}>
          {state === "checking" && <div className="h-12 animate-pulse rounded-control bg-muted" />}

          {state === "ios-add-home" && <IosSteps />}

          {state === "unsupported" && (
            <p className="flex items-start gap-2 text-[14px] text-ink">
              <Info className="mt-0.5 size-4 shrink-0 text-ink-soft" aria-hidden />
              {t("alUnsupported")}
            </p>
          )}

          {state === "denied" && (
            <div className="rounded-control bg-muted p-3.5 text-[14px] text-ink">
              <p className="flex items-center gap-2 font-semibold">
                <BellOff className="size-4" aria-hidden /> {t("alDenied")}
              </p>
              <p className="mt-1.5 text-ink-soft">{isIos() ? t("alDeniedIos") : t("alDeniedAndroid")}</p>
            </div>
          )}

          {(state === "off" || state === "busy") && (
            <button type="button" onClick={enable} disabled={state === "busy"} className="btn-primary w-full" data-testid="alerts-enable">
              {state === "busy" ? <Loader2 className="size-5 animate-spin" aria-hidden /> : <BellRing className="size-5" aria-hidden />}
              {state === "busy" ? t("alEnabling") : t("alEnable")}
            </button>
          )}

          {state === "on" && (
            <div className="space-y-4">
              <p className="flex items-center gap-2.5 text-[15px] font-semibold text-safe-ink">
                <span className="grid size-6 place-items-center rounded-full bg-safe text-on-safe">
                  <Check className="size-3.5" aria-hidden />
                </span>
                {t("alOn")}
              </p>
              <ThisPhoneOnly />
              <div className="grid grid-cols-[1fr_auto] gap-2">
                <button type="button" onClick={test} disabled={testing} className="btn-secondary px-3">
                  {testing ? <Loader2 className="size-4 animate-spin" aria-hidden /> : <Send className="size-4" aria-hidden />}
                  {t("alTest")}
                </button>
                <button type="button" onClick={disable} className="btn-secondary px-3 text-ink-soft">
                  <BellOff className="size-4" aria-hidden />
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
            className="rounded-control bg-muted px-3 py-2 text-[14px] font-semibold text-ink"
          >
            {toast.text}
          </motion.p>
        )}
      </AnimatePresence>

      <p className="text-[13px] leading-relaxed text-ink-soft">{t("alHow")}</p>
    </div>
  );
}
