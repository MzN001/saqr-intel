"use client";

import { getDeviceTag } from "@/lib/device";
import { useHydrated } from "@/lib/useHydrated";
import { Check, Copy, Download, Info, SlidersHorizontal } from "lucide-react";
import { useEffect, useState } from "react";
import { apiUrl, getNextDnsStatus, type NextDnsStatus } from "@/lib/api";
import { Disclosure } from "./Disclosure";
import { useLang } from "@/lib/i18n";
import { copyText } from "@/lib/share";
import { SetupVideoButton } from "./SetupVideo";

/*
 * Phone shield setup, shown inside the SetupDrawer (one drawer per platform): iPhone gets the
 * .mobileconfig from /api/ios-dns-profile, Android the Private DNS hostname to copy. When the backend
 * syncs Saqr's detections to a NextDNS profile, that profile is used by default. Each phone's device tag
 * rides in its DNS setting so block alerts reach that phone only.
 */

export type Platform = "android" | "ios";

const NEXTDNS_ID = /^[a-z0-9]{4,16}$/;
const DEFAULT_DOT = "security.cloudflare-dns.com";

function Steps({ items }: { items: string[] }) {
  return (
    <ol className="space-y-3">
      {items.map((text, i) => (
        <li key={i} className="flex items-start gap-3">
          <span className="grid size-7 shrink-0 place-items-center rounded-full border border-line bg-surface text-[13px] font-semibold tabular-nums text-ink">
            {i + 1}
          </span>
          <span className="pt-0.5 text-[15px] leading-relaxed text-ink">{text}</span>
        </li>
      ))}
    </ol>
  );
}

export function PhoneShieldPanel({ platform }: { platform: Platform }) {
  const { t } = useLang();
  const hydrated = useHydrated();
  const [rawId, setRawId] = useState("");
  const [copied, setCopied] = useState<"ok" | "fail" | null>(null);
  const [feed, setFeed] = useState<NextDnsStatus | null>(null);

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
  const device = hydrated ? getDeviceTag() : null;
  const dotHost = activeId ? `${device ? `${device}-` : ""}${activeId}.dns.nextdns.io` : DEFAULT_DOT;
  const profileQuery = new URLSearchParams({ ...(activeId ? { nextdns_id: activeId } : {}), ...(activeId && device ? { device } : {}) }).toString();
  const profileHref = apiUrl(`/api/ios-dns-profile${profileQuery ? `?${profileQuery}` : ""}`);

  const copyHost = async () => {
    const ok = await copyText(dotHost);
    setCopied(ok ? "ok" : "fail");
    window.setTimeout(() => setCopied(null), 3000);
  };

  return (
    <div className="space-y-5" data-testid={`phone-shield-${platform}`}>
      <p className="text-[15px] leading-relaxed text-ink-soft">{t("shieldIntro")}</p>

      {feed?.configured && (
        <p className="flex items-start gap-2 text-[13px] text-ink-soft">
          <span className={`mt-1.5 size-2 shrink-0 rounded-full ${feed.last_error ? "bg-ink-soft" : "bg-ink"}`} aria-hidden />
          <span>
            <span className="font-semibold text-ink">{feed.last_error ? t("bgFeedError") : t("bgFeedOn")}</span> ·{" "}
            <span className="tabular-nums">{feed.synced_domains}</span> {t("bgFeedDomains")}
            {usingFeed && <span className="mt-0.5 block">{t("bgFeedUsing")}</span>}
          </span>
        </p>
      )}

      {platform === "android" ? (
        <>
          <div>
            <p className="label-caps">{t("bgAndroidHost")}</p>
            <code dir="ltr" className="mt-2 block truncate rounded-control border border-line bg-muted px-3 py-3 font-mono text-[14px] font-semibold text-ink">
              {dotHost}
            </code>
            <button type="button" onClick={copyHost} className="btn-primary mt-2 w-full" data-testid="shield-copy-android">
              {copied === "ok" ? <Check className="size-4" aria-hidden /> : <Copy className="size-4" aria-hidden />}
              {t("bgCopyAndroid")}
            </button>
            <p aria-live="polite" className="min-h-0">
              {copied && <span className="mt-2 block text-[13px] font-semibold text-ink">{copied === "ok" ? t("bgCopied") : t("copyFailed")}</span>}
            </p>
          </div>
          <Steps items={[t("bgA1"), t("bgA2"), t("bgA3")]} />
          <SetupVideoButton platform="android" host={dotHost} />
          <p className="flex items-start gap-2 text-[13px] leading-relaxed text-ink-soft">
            <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
            {t("bgAndroidTip")}
          </p>
        </>
      ) : (
        <>
          <a
            href={idValid ? profileHref : undefined}
            aria-disabled={!idValid}
            data-testid="shield-download-ios"
            className={`btn-primary w-full ${idValid ? "" : "pointer-events-none opacity-50"}`}
          >
            <Download className="size-4" aria-hidden /> {t("bgDownloadIos")}
          </a>
          <Steps items={[t("bgI1"), t("bgI2"), t("bgI3")]} />
          <SetupVideoButton platform="ios" host={dotHost} />
          <p className="flex items-start gap-2 text-[13px] leading-relaxed text-ink-soft">
            <Info className="mt-0.5 size-4 shrink-0" aria-hidden />
            {t("bgIosNote")}
          </p>
        </>
      )}

      <Disclosure summary={t("bgAdvanced")} icon={<SlidersHorizontal className="size-4" aria-hidden />} defaultOpen={!idValid}>
        <label className="block">
          <span className="text-[13px] font-semibold text-ink">{t("bgNextdns")}</span>
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
            className={`field mt-1.5 font-mono sm:max-w-xs ${idValid ? "" : "border-ink"}`}
          />
          <span className={`mt-1 block text-[13px] ${idValid ? "text-ink-soft" : "font-semibold text-ink"}`}>
            {idValid ? t("bgNextdnsHint") : t("bgNextdnsInvalid")}
          </span>
        </label>
        <p className="mt-3 text-[13px] leading-relaxed text-ink-soft">{t("bgFootnote")}</p>
      </Disclosure>
    </div>
  );
}
