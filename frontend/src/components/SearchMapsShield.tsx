"use client";

import { motion } from "framer-motion";
import {
  BadgeCheck,
  Bookmark,
  Globe,
  LoaderCircle,
  Mic,
  Navigation,
  Phone,
  Search,
  ShieldAlert,
  ShieldCheck,
  Star,
  TriangleAlert,
  WifiOff,
} from "lucide-react";
import { useEffect, useState, type MouseEvent } from "react";
import {
  analyzeUrl,
  batchVerdict,
  checkPhone,
  scanMaps,
  type BatchVerdictItem,
  type PhoneCheck,
  type ScanVerdict,
} from "@/lib/api";
import type { Lang } from "@/lib/i18n";
import { useLang } from "@/lib/i18n";
import { useHydrated } from "@/lib/useHydrated";
import { PhoneFrame } from "./Chrome";

export const SCAM_FINE_URL = "http://127.0.0.1:8000/mock-scam/tamm-fine";
export const SCAM_POST_URL = "http://127.0.0.1:8000/mock-scam/emiratespost";
/**
 * The example scam links point at the backend's built-in replica pages. The backend (local or Render)
 * resolves `/mock-scam/<slug>` on a loopback host in memory to the seeded scam domain, so the address
 * itself never has to load. Never show it raw to a citizen: use the `exampleScamLabel` text instead.
 */
export const isDemoScamUrl = (url: string): boolean => /\/mock-scam\//i.test(url);
const OFFICIAL_URL = "https://www.adpolice.gov.ae/";
const MAPS_NAME = "Emirates Post Customer Center - Abu Dhabi";
const MAPS_PHONE = "+971 50 000 7781";

type RunScan = (target: string, job: () => Promise<ScanVerdict>) => void;

// ---------------------------------------------------------------------------------------------
// Pre-click badges: the same live verdicts the browser extension paints on Google / Bing / Maps
// (POST /api/batch-verdict + /api/check-phone), fetched when the screen opens, before any tap.
// ---------------------------------------------------------------------------------------------
type PreClick =
  | { state: "checking" }
  | { state: "live"; links: Record<string, BatchVerdictItem>; phone: PhoneCheck | null }
  | { state: "offline" };

function usePreClickVerdicts(): PreClick {
  const [live, setLive] = useState<PreClick>({ state: "checking" });
  useEffect(() => {
    let cancelled = false;
    const load = async () => {
      try {
        const [items, phone] = await Promise.all([
          batchVerdict([SCAM_FINE_URL, SCAM_POST_URL, OFFICIAL_URL]),
          checkPhone(MAPS_PHONE, MAPS_NAME, "maps").catch(() => null),
        ]);
        if (!cancelled) setLive({ state: "live", links: Object.fromEntries(items.map((i) => [i.url, i])), phone });
      } catch {
        if (!cancelled) setLive({ state: "offline" });
      }
    };
    const id = window.setTimeout(() => void load(), 0);
    return () => {
      cancelled = true;
      window.clearTimeout(id);
    };
  }, []);
  return live;
}

interface Badge {
  level: "danger" | "warn" | "official";
  label: string;
  reason: string | null;
  tip: string;
}

const entityName = (e: BatchVerdictItem["entity"], lang: Lang) => (e ? (lang === "ar" ? e.name_ar : e.name_en) : "");
const reasonText = (r: { en: string; ar: string }, lang: Lang) => (lang === "ar" ? r.ar : r.en);

/** Same rules as the extension: red for scams, amber for suspicious, green only for official UAE sites. */
function linkBadge(v: BatchVerdictItem | undefined, lang: Lang): Badge | null {
  if (!v || !v.verdict) return null;
  const name = entityName(v.entity, lang);
  const reasons = v.reasons.map((r) => reasonText(r, lang));
  const tip = reasons.map((r) => `• ${r}`).join("\n");
  if (v.verdict === "HIGH-RISK SCAM" || v.score >= 65) {
    const label = lang === "ar" ? `صقر: احتيال${name ? ` — ينتحل صفة ${name}` : ""}` : `Saqr: scam${name ? ` — imitates ${name}` : ""}`;
    return { level: "danger", label, reason: reasons[0] ?? null, tip };
  }
  if (v.verdict === "SUSPICIOUS" || v.score >= 30) {
    return { level: "warn", label: lang === "ar" ? "صقر: مشبوه" : "Saqr: suspicious", reason: reasons[0] ?? null, tip };
  }
  if (v.official) {
    const label = name ? (lang === "ar" ? `رسمي: ${name}` : `Official: ${name}`) : lang === "ar" ? "موقع إماراتي رسمي" : "Official UAE website";
    return { level: "official", label, reason: null, tip };
  }
  return null;
}

function phoneBadge(p: PhoneCheck | null, lang: Lang): Badge | null {
  if (!p || p.level === "none") return null;
  const official = p.entity?.official_phones_display.join(", ") ?? "";
  const tip = p.reasons.map((r) => `• ${reasonText(r, lang)}`).join("\n");
  const reason = p.reasons[0] ? reasonText(p.reasons[0], lang) : null;
  if (p.level === "official") {
    return { level: "official", label: lang === "ar" ? "رقم رسمي" : "Official number", reason: null, tip };
  }
  if (p.level === "danger") {
    const label = official
      ? lang === "ar" ? `ليس الرقم الرسمي (الرسمي: ${official})` : `Not the official number (official: ${official})`
      : lang === "ar" ? "رقم احتيالي" : "Scam number";
    return { level: "danger", label, reason, tip };
  }
  const label = lang === "ar" ? `غير مدرج رسمياً (الرسمي: ${official})` : `Not on the official list (official: ${official})`;
  return { level: "warn", label, reason, tip };
}

/** Saqr verdict colours inside the simulated Google screen: crimson scam, amber suspicious, emerald official. */
const BADGE_TONE: Record<Badge["level"], string> = {
  danger: "border-scam bg-scam text-on-scam",
  warn: "border-suspicious bg-suspicious-soft text-suspicious-ink",
  official: "border-safe bg-safe-soft text-safe-ink",
};
const BADGE_ICON = { danger: ShieldAlert, warn: TriangleAlert, official: BadgeCheck };

function PreClickBadge({ badge, showReason = false }: { badge: Badge | null; showReason?: boolean }) {
  if (!badge) return null;
  const Icon = BADGE_ICON[badge.level];
  return (
    <motion.span
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className="mt-1 flex flex-col items-start gap-0.5"
      title={badge.tip || undefined}
    >
      <span role="note" className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[12px] font-semibold leading-tight ${BADGE_TONE[badge.level]}`}>
        <Icon className="size-3.5 shrink-0" aria-hidden />
        {badge.label}
      </span>
      {showReason && badge.reason ? <span className="text-[12px] leading-snug text-scam-ink">{badge.reason}</span> : null}
    </motion.span>
  );
}

function PreClickStatus({ live, lang }: { live: PreClick; lang: Lang }) {
  const ar = lang === "ar";
  if (live.state === "checking") {
    return (
      <p className="mt-3 flex items-center gap-1.5 text-[12px] text-gray-500 dark:text-gray-400">
        <LoaderCircle className="size-3.5 animate-spin" aria-hidden />
        {ar ? "صقر يفحص هذه النتائج قبل أن تنقر…" : "Saqr is checking these results before you tap…"}
      </p>
    );
  }
  if (live.state === "offline") {
    return (
      <p className="mt-3 flex items-center gap-1.5 text-[12px] text-gray-500 dark:text-gray-400">
        <WifiOff className="size-3.5" aria-hidden />
        {ar ? "الفحص المسبق غير متاح الآن. انقر على أي نتيجة لفحصها." : "Live pre-check unavailable right now. Tap any result to scan it."}
      </p>
    );
  }
  return (
    <p className="mt-3 flex items-center gap-1.5 text-[12px] font-medium text-gray-700 dark:text-gray-300">
      <ShieldCheck className="size-3.5" aria-hidden />
      {ar ? "فحص صقر كل نتيجة وإعلان ورقم قبل أن تنقر" : "Saqr checked every result, ad and phone number before you tap"}
    </p>
  );
}

function GoogleWordmark() {
  const letters: [string, string][] = [
    ["G", "#4285F4"],
    ["o", "#EA4335"],
    ["o", "#FBBC05"],
    ["g", "#4285F4"],
    ["l", "#34A853"],
    ["e", "#EA4335"],
  ];
  return (
    <span className="text-[26px] font-semibold tracking-tight" dir="ltr">
      {letters.map(([l, c], i) => (
        <span key={i} style={{ color: c }}>
          {l}
        </span>
      ))}
    </span>
  );
}

export function SearchMapsShield({ runScan }: { runScan: RunScan }) {
  const { t, lang } = useLang();
  const hydrated = useHydrated();
  const link = (url: string) => (hydrated ? url : undefined);
  const live = usePreClickVerdicts();
  const links = live.state === "live" ? live.links : {};
  const adBadge = linkBadge(links[SCAM_FINE_URL], lang);
  const mapsSiteBadge = linkBadge(links[SCAM_POST_URL], lang);
  const officialBadge = linkBadge(links[OFFICIAL_URL], lang);
  const mapsPhoneBadge = phoneBadge(live.state === "live" ? live.phone : null, lang);

  const interceptAd = (e: MouseEvent) => {
    e.preventDefault();
    runScan("tamm-smart-pay.net", () => analyzeUrl(SCAM_FINE_URL, "AUTO_TELECOM_DNS", "web"));
  };
  const interceptOfficial = (e: MouseEvent) => {
    e.preventDefault();
    runScan("www.adpolice.gov.ae", () => analyzeUrl(OFFICIAL_URL, "AUTO_TELECOM_DNS", "web"));
  };
  const interceptMaps = (e: MouseEvent) => {
    e.preventDefault();
    runScan("Emirates Post Customer Center - Abu Dhabi", () =>
      scanMaps(
        {
          business_name: "Emirates Post Customer Center - Abu Dhabi",
          website: SCAM_POST_URL,
          phone: "+971 50 000 7781",
          lat: 24.3497,
          lng: 54.5061,
        },
        "AUTO_TELECOM_DNS",
      ),
    );
  };

  const stagger = { hidden: {}, show: { transition: { staggerChildren: 0.12, delayChildren: 0.1 } } };
  const item = { hidden: { opacity: 0, y: 18 }, show: { opacity: 1, y: 0, transition: { type: "spring" as const, stiffness: 220, damping: 24 } } };

  return (
    <PhoneFrame>
      <div className="bg-screen px-4 pb-6 pt-2 dark:bg-[#202124]" dir="ltr">
        <div className="flex justify-center py-2">
          <GoogleWordmark />
        </div>
        <div className="flex items-center gap-3 rounded-full border border-gray-200 bg-white px-4 py-2.5 shadow-[0_1px_6px_rgba(32,33,36,0.18)] dark:border-[#5f6368] dark:bg-[#303134] dark:shadow-none">
          <Search className="size-4 text-gray-500 dark:text-gray-400" />
          <span className="flex-1 truncate text-[15px] text-gray-800 dark:text-gray-100" dir={lang === "ar" ? "rtl" : "ltr"}>
            {t("searchQuery")}
          </span>
          <Mic className="size-4 text-[#4285F4]" />
        </div>
        <div className="mt-3 flex gap-5 border-b border-gray-200 px-1 text-[13px] text-gray-600 dark:border-[#3c4043] dark:text-gray-400">
          {["All", "Maps", "News", "Images", "Videos"].map((tab, i) => (
            <span key={tab} className={`pb-2 ${i === 0 ? "border-b-[3px] border-[#1a73e8] font-semibold text-[#1a73e8] dark:border-[#8ab4f8] dark:text-[#8ab4f8]" : ""}`}>
              {tab}
            </span>
          ))}
        </div>
        <div dir={lang === "ar" ? "rtl" : "ltr"}>
          <PreClickStatus live={live} lang={lang} />
        </div>

        <motion.div variants={stagger} initial="hidden" animate="show" className="mt-4 space-y-4" dir={lang === "ar" ? "rtl" : "ltr"}>
          <motion.a variants={item} href={link(SCAM_FINE_URL)} onClick={interceptAd} className="group block cursor-pointer rounded-2xl p-1 transition active:scale-[0.99]">
            <p className="text-[13px] font-bold text-gray-900 dark:text-gray-100">{t("sponsored")}</p>
            <div className="mt-1.5 flex items-center gap-2.5">
              <span className="grid size-7 place-items-center rounded-full bg-[#0b3d2e] text-[11px] font-bold text-white">AD</span>
              <div className="min-w-0 leading-tight" dir="ltr">
                <p className="truncate text-[13px] text-gray-900 dark:text-gray-200">tamm-smart-pay.net</p>
                <p className="truncate text-[12px] text-gray-600 dark:text-gray-400">https://tamm-smart-pay.net › traffic-fines</p>
              </div>
            </div>
            <PreClickBadge badge={adBadge} showReason />
            <p
              className={`mt-1.5 text-[19px] leading-snug text-[#1a0dab] group-hover:underline dark:text-[#8ab4f8] ${adBadge?.level === "danger" ? "line-through decoration-scam" : ""}`}
            >
              {t("adTitle")}
            </p>
            <p className="mt-1 text-[14px] leading-snug text-gray-600 dark:text-[#bdc1c6]">{t("adBody")}</p>
          </motion.a>

          <motion.div variants={item} className="overflow-hidden rounded-2xl border border-gray-200 shadow-sm dark:border-[#3c4043] dark:bg-[#292a2d]">
            <div className="map-grid relative h-36">
              <motion.div
                initial={{ y: -60, opacity: 0 }}
                animate={{ y: 0, opacity: 1 }}
                transition={{ type: "spring", stiffness: 300, damping: 12, delay: 0.6 }}
                className="absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-full"
              >
                <svg width="34" height="44" viewBox="0 0 34 44" aria-hidden>
                  <path d="M17 0C7.6 0 0 7.5 0 16.8 0 29.4 17 44 17 44s17-14.6 17-27.2C34 7.5 26.4 0 17 0z" fill="#EA4335" />
                  <circle cx="17" cy="16.5" r="6.5" fill="#B31412" />
                </svg>
              </motion.div>
              <span className="absolute left-1/2 top-1/2 size-3 -translate-x-1/2 rounded-full bg-black/20 blur-[2px]" />
              <span className="absolute bottom-2 end-2 rounded bg-white/90 px-1.5 py-0.5 text-[11px] text-gray-600 dark:bg-black/60 dark:text-gray-300">Mussafah · Abu Dhabi</span>
            </div>
            <div className="p-3.5">
              <p className="text-[17px] font-medium leading-snug text-gray-900 dark:text-gray-100">{t("mapsCardTitle")}</p>
              <div className="mt-1 flex items-center gap-1 text-[13px] text-gray-600 dark:text-gray-400" dir="ltr">
                <span className="font-medium text-gray-800 dark:text-gray-200">4.9</span>
                {Array.from({ length: 5 }).map((_, i) => (
                  <Star key={i} className="size-3.5 fill-[#FBBC05] text-[#FBBC05]" />
                ))}
                <span>(12)</span>
              </div>
              <p className="mt-0.5 text-[13px] text-gray-600 dark:text-gray-400">{t("mapsCategory")}</p>
              <p className="mt-0.5 text-[13px] font-medium text-[#188038] dark:text-[#81c995]">{t("openNow")}</p>
              <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[13px] text-gray-700 dark:text-gray-300">
                <span className="inline-flex items-center gap-1" dir="ltr">
                  <Phone className="size-3.5" aria-hidden /> {MAPS_PHONE}
                </span>
                <PreClickBadge badge={mapsPhoneBadge} />
              </div>
              <PreClickBadge badge={mapsSiteBadge} showReason />
              <div className="mt-3 flex gap-2 overflow-x-auto no-scrollbar">
                <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full bg-[#0b57d0] px-3.5 py-2 text-[13px] font-medium text-white dark:bg-[#a8c7fa] dark:text-[#062e6f]">
                  <Navigation className="size-3.5" /> {t("directions")}
                </span>
                <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-gray-300 px-3.5 py-2 text-[13px] font-medium text-[#0b57d0] dark:border-[#5f6368] dark:text-[#a8c7fa]">
                  <Phone className="size-3.5" /> {t("call")}
                </span>
                <motion.a
                  href={link(SCAM_POST_URL)}
                  onClick={interceptMaps}
                  animate={{ boxShadow: ["0 0 0 0 rgba(11,87,208,0.45)", "0 0 0 8px rgba(11,87,208,0)"] }}
                  transition={{ duration: 1.6, repeat: 3 }}
                  className="inline-flex shrink-0 cursor-pointer items-center gap-1.5 rounded-full border border-[#0b57d0] bg-[#e8f0fe] px-3.5 py-2 text-[13px] font-semibold text-[#0b57d0] dark:border-[#a8c7fa] dark:bg-[#0b57d0]/35 dark:text-[#d3e3fd]"
                >
                  <Globe className="size-3.5" /> {t("visitWebsite")}
                </motion.a>
                <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-gray-300 px-3.5 py-2 text-[13px] font-medium text-[#0b57d0] dark:border-[#5f6368] dark:text-[#a8c7fa]">
                  <Bookmark className="size-3.5" /> {t("save")}
                </span>
              </div>
            </div>
          </motion.div>

          <motion.a variants={item} href={link(OFFICIAL_URL)} onClick={interceptOfficial} className="group block cursor-pointer rounded-2xl p-1">
            <div className="flex items-center gap-2.5">
              <span className="grid size-7 place-items-center rounded-full bg-obsidian text-[11px] font-bold text-ivory">ADP</span>
              <div className="min-w-0 leading-tight" dir="ltr">
                <p className="truncate text-[13px] text-gray-900 dark:text-gray-200">Abu Dhabi Police</p>
                <p className="truncate text-[12px] text-gray-600 dark:text-gray-400">https://www.adpolice.gov.ae</p>
              </div>
            </div>
            <PreClickBadge badge={officialBadge} />
            <p className="mt-1.5 text-[19px] leading-snug text-[#1a0dab] group-hover:underline dark:text-[#8ab4f8]">{t("organicTitle")}</p>
            <p className="mt-1 text-[14px] leading-snug text-gray-600 dark:text-[#bdc1c6]">{t("organicBody")}</p>
          </motion.a>
        </motion.div>
      </div>
    </PhoneFrame>
  );
}
