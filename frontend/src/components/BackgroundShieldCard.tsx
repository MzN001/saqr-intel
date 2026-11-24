"use client";

import { AnimatePresence, motion } from "framer-motion";
import { Check, Copy, Download, Info, ShieldCheck, Smartphone, Tablet } from "lucide-react";
import { useEffect, useState, useSyncExternalStore } from "react";
import { apiUrl, getNextDnsStatus, type NextDnsStatus } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { copyText } from "@/lib/share";
import { SetupVideoButton } from "./SetupVideo";

type Platform = "android" | "ios";

const NEXTDNS_ID = /^[a-z0-9]{4,16}$/;
const DEFAULT_DOT = "security.cloudflare-dns.com";

function detectPlatform(ua: string): Platform | null {
  if (/iphone|ipad|ipod/i.test(ua)) return "ios";
  if (/android/i.test(ua)) return "android";
  return null;
}

const noopSubscribe = () => () => {};

function Steps({ items }: { items: string[] }) {
  return (
    <ol className="space-y-2">
      {items.map((text, i) => (
        <li key={i} className="flex items-start gap-3">
          <span className="grid size-7 shrink-0 place-items-center rounded-full bg-navy-900 text-xs font-extrabold text-gold-500 dark:bg-navy-950 dark:ring-1 dark:ring-white/10">
            {i + 1}
          </span>
          <span className="pt-1 text-sm leading-relaxed text-ink">{text}</span>
        </li>
      ))}
    </ol>
  );
}

export function BackgroundShieldCard() {
  const { t } = useLang();
  const detected = useSyncExternalStore(noopSubscribe, () => detectPlatform(navigator.userAgent), () => null);
  const [choice, setChoice] = useState<Platform | null>(null);
  const platform: Platform = choice ?? detected ?? "android";
  const [rawId, setRawId] = useState("");
  const [copied, setCopied] = useState<"ok" | "fail" | null>(null);
  const [feed, setFeed] = useState<NextDnsStatus | null>(null);

  // When the backend syncs SAQR's detections to a NextDNS profile, use that profile by default.
  useEffect(() => {
    let alive = true;
    const load = () =>
      getNextDnsStatus()
        .then((s) => alive && setFeed(s))
        .catch(() => alive && setFeed(null));
    load();
    const timer = window.setInterval(load, 30_000);
    return () => {
      alive = false;
      window.clearInterval(timer);
    };
  }, []);

  const id = rawId.trim().toLowerCase();
  const idValid = id === "" || NEXTDNS_ID.test(id);
  const feedId = feed?.configured ? feed.profile_id : null;
  const activeId = idValid && id ? id : feedId;
  const usingFeed = Boolean(feedId && activeId === feedId);
  const dotHost = activeId ? `${activeId}.dns.nextdns.io` : DEFAULT_DOT;
  const profileHref = apiUrl(`/api/ios-dns-profile${activeId ? `?nextdns_id=${encodeURIComponent(activeId)}` : ""}`);

  const copyHost = async () => {
    const ok = await copyText(dotHost);
    setCopied(ok ? "ok" : "fail");
    window.setTimeout(() => setCopied(null), 3000);
  };

  const tabs: { id: Platform; label: string; icon: typeof Smartphone }[] = [
    { id: "android", label: t("bgAndroid"), icon: Smartphone },
    { id: "ios", label: t("bgIphone"), icon: Tablet },
  ];

  return (
    <section aria-labelledby="bg-shield-title" className="rounded-[20px] border border-line bg-surface p-4 sm:p-5">
      <div className="flex items-start gap-3">
        <span className="grid size-10 shrink-0 place-items-center rounded-xl bg-emerald-600 text-white shadow-sm">
          <ShieldCheck className="size-5" />
        </span>
        <div className="min-w-0">
          <h2 id="bg-shield-title" className="text-balance text-base font-extrabold leading-snug text-ink sm:text-lg sm:leading-tight">
            {t("bgTitle")}
          </h2>
          <p className="mt-1 text-sm leading-relaxed text-ink-soft">{t("bgIntro")}</p>
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <span className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t("bgPlatform")}</span>
        <div role="tablist" aria-label={t("bgPlatform")} className="flex rounded-full bg-muted p-1 ring-1 ring-line">
          {tabs.map(({ id: tabId, label, icon: Icon }) => (
            <button
              key={tabId}
              type="button"
              role="tab"
              aria-selected={platform === tabId}
              aria-controls={`bg-panel-${tabId}`}
              onClick={() => setChoice(tabId)}
              className={`relative flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-xs font-bold transition-colors ${
                platform === tabId ? "text-white dark:text-navy-900" : "text-ink-soft hover:text-ink"
              }`}
            >
              {platform === tabId && (
                <motion.span layoutId="bg-platform-knob" className="absolute inset-0 -z-0 rounded-full bg-navy-900 dark:bg-white" transition={{ type: "spring", stiffness: 500, damping: 34 }} />
              )}
              <Icon className="relative size-3.5" />
              <span className="relative">{label}</span>
              {detected === tabId && <span className="relative text-[10px] font-semibold opacity-75">· {t("bgDetected")}</span>}
            </button>
          ))}
        </div>
      </div>

      {feed?.configured && (
        <p
          className={`mt-4 flex items-start gap-2 rounded-2xl p-3 text-xs font-semibold ring-1 ${
            feed.last_error
              ? "bg-amber-50 text-amber-900 ring-amber-500/30 dark:bg-amber-500/10 dark:text-amber-200"
              : "bg-emerald-50 text-emerald-800 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-200"
          }`}
        >
          <span className="relative mt-1 flex size-2 shrink-0">
            {!feed.last_error && <span className="absolute inline-flex size-full animate-[ping_1.4s_cubic-bezier(0,0,0.2,1)_3] rounded-full bg-emerald-500 opacity-70" />}
            <span className={`relative inline-flex size-2 rounded-full ${feed.last_error ? "bg-amber-500" : "bg-emerald-500"}`} />
          </span>
          <span>
            {feed.last_error ? t("bgFeedError") : t("bgFeedOn")} · {feed.synced_domains} {t("bgFeedDomains")}
            {usingFeed && <span className="block font-normal opacity-80">{t("bgFeedUsing")}</span>}
          </span>
        </p>
      )}

      <label className="mt-4 block">
        <span className="text-xs font-semibold text-ink-soft">{t("bgNextdns")}</span>
        <input
          type="text"
          value={rawId}
          onChange={(e) => setRawId(e.target.value)}
          placeholder={feedId ?? "abc123"}
          dir="ltr"
          autoComplete="off"
          autoCapitalize="off"
          spellCheck={false}
          maxLength={16}
          aria-invalid={!idValid}
          className={`mt-1.5 w-full rounded-2xl bg-muted px-3.5 py-2.5 font-mono text-sm text-ink outline-none ring-1 focus:ring-2 sm:max-w-xs ${
            idValid ? "ring-line focus:ring-emerald-600" : "ring-crimson-600"
          }`}
        />
        <span className={`mt-1 block text-xs ${idValid ? "text-ink-soft/75" : "font-semibold text-crimson-700 dark:text-red-300"}`}>
          {idValid ? t("bgNextdnsHint") : t("bgNextdnsInvalid")}
        </span>
      </label>

      <AnimatePresence mode="wait" initial={false}>
        {platform === "android" ? (
          <motion.div
            key="android"
            id="bg-panel-android"
            role="tabpanel"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="mt-4 space-y-4"
          >
            <div className="rounded-2xl bg-muted p-3 ring-1 ring-line">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-soft/80">{t("bgAndroidHost")}</p>
              <div className="mt-2 flex flex-col gap-2 sm:flex-row sm:items-center">
                <code dir="ltr" className="min-w-0 flex-1 truncate rounded-xl bg-surface px-3 py-2.5 text-sm font-bold text-ink ring-1 ring-line">
                  {dotHost}
                </code>
                <button
                  type="button"
                  onClick={copyHost}
                  className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-emerald-700 px-4 py-2.5 text-sm font-bold text-white transition hover:bg-emerald-800 active:scale-[0.98]"
                >
                  {copied === "ok" ? <Check className="size-4" /> : <Copy className="size-4" />}
                  {t("bgCopyAndroid")}
                </button>
              </div>
              <p aria-live="polite" className="min-h-0">
                {copied && (
                  <span className={`mt-2 block text-xs font-semibold ${copied === "ok" ? "text-emerald-700 dark:text-emerald-300" : "text-amber-800 dark:text-amber-300"}`}>
                    {copied === "ok" ? t("bgCopied") : t("copyFailed")}
                  </span>
                )}
              </p>
            </div>
            <SetupVideoButton platform="android" host={dotHost} />
            <Steps items={[t("bgA1"), t("bgA2"), t("bgA3")]} />
            <p className="flex items-start gap-2 rounded-2xl bg-gold-100 p-3 text-xs font-medium text-navy-900 ring-1 ring-gold-500/40 dark:bg-gold-500/10 dark:text-gold-100">
              <Info className="mt-0.5 size-4 shrink-0 text-gold-500" />
              {t("bgAndroidTip")}
            </p>
          </motion.div>
        ) : (
          <motion.div
            key="ios"
            id="bg-panel-ios"
            role="tabpanel"
            initial={{ opacity: 0, y: 8 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            className="mt-4 space-y-4"
          >
            <a
              href={idValid ? profileHref : undefined}
              aria-disabled={!idValid}
              className={`flex w-full items-center justify-center gap-2 rounded-2xl px-4 py-3 text-sm font-bold text-white shadow-sm transition sm:w-auto sm:px-6 ${
                idValid ? "bg-navy-900 hover:bg-navy-800 dark:bg-white dark:text-navy-900 dark:hover:bg-white/90" : "pointer-events-none bg-navy-900/40"
              }`}
            >
              <Download className="size-4" /> {t("bgDownloadIos")}
            </a>
            <SetupVideoButton platform="ios" host={dotHost} />
            <Steps items={[t("bgI1"), t("bgI2"), t("bgI3")]} />
            <p className="flex items-start gap-2 text-xs text-ink-soft">
              <Info className="mt-0.5 size-4 shrink-0" />
              {t("bgIosNote")}
            </p>
          </motion.div>
        )}
      </AnimatePresence>

      <p className="mt-4 border-t border-line pt-3 text-xs leading-relaxed text-ink-soft/80">{t("bgFootnote")}</p>
    </section>
  );
}
