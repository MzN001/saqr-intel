"use client";

import { motion } from "framer-motion";
import { Bookmark, Globe, Mic, Navigation, Phone, Search, Star } from "lucide-react";
import type { MouseEvent } from "react";
import { analyzeUrl, scanMaps, type ScanVerdict } from "@/lib/api";
import { useLang } from "@/lib/i18n";
import { useHydrated } from "@/lib/useHydrated";
import { PhoneFrame } from "./Chrome";

export const SCAM_FINE_URL = "http://127.0.0.1:8000/mock-scam/tamm-fine";
export const SCAM_POST_URL = "http://127.0.0.1:8000/mock-scam/emiratespost";
const OFFICIAL_URL = "https://www.adpolice.gov.ae/";

type RunScan = (target: string, job: () => Promise<ScanVerdict>) => void;

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
            <p className="mt-1.5 text-[19px] leading-snug text-[#1a0dab] group-hover:underline dark:text-[#8ab4f8]">{t("adTitle")}</p>
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
              <span className="absolute bottom-2 end-2 rounded bg-white/90 px-1.5 py-0.5 text-[10px] text-gray-600 dark:bg-black/60 dark:text-gray-300">Mussafah · Abu Dhabi</span>
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
                  transition={{ duration: 1.6, repeat: Infinity }}
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
              <span className="grid size-7 place-items-center rounded-full bg-navy-900 text-[10px] font-bold text-gold-500">ADP</span>
              <div className="min-w-0 leading-tight" dir="ltr">
                <p className="truncate text-[13px] text-gray-900 dark:text-gray-200">Abu Dhabi Police</p>
                <p className="truncate text-[12px] text-gray-600 dark:text-gray-400">https://www.adpolice.gov.ae</p>
              </div>
            </div>
            <p className="mt-1.5 text-[19px] leading-snug text-[#1a0dab] group-hover:underline dark:text-[#8ab4f8]">{t("organicTitle")}</p>
            <p className="mt-1 text-[14px] leading-snug text-gray-600 dark:text-[#bdc1c6]">{t("organicBody")}</p>
          </motion.a>
        </motion.div>
      </div>
    </PhoneFrame>
  );
}
