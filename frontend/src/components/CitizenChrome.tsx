"use client";

import { Bell, BookOpen, Lock, Shield } from "lucide-react";
import { type MouseEvent } from "react";
import { useLang, type DictKey } from "@/lib/i18n";
import { mobileTabOf, MOBILE_TABS, viewHref, type MobileTab, type View } from "@/lib/view";
import { PrivacyNote } from "./PrivacyNote";
import { SaqrLogo } from "./SaqrLogo";
import { ShareQrButton } from "./ShareQrButton";
import { ThemeToggle } from "./ThemeToggle";

const NAV: { id: View; key: DictKey }[] = [
  { id: "check", key: "navCheck" },
  { id: "maps", key: "navMaps" },
  { id: "sms", key: "navSms" },
  { id: "email", key: "navEmail" },
  { id: "live", key: "navLive" },
];

/** A plain left click switches the window in place; modified clicks (new tab, etc.) follow the real link. */
function navClick(onView: (v: View) => void, id: View) {
  return (e: MouseEvent<HTMLAnchorElement>) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
    e.preventDefault();
    onView(id);
  };
}

/** EN | عربي segmented pill. Stays left-to-right in both languages. */
function LangPill() {
  const { lang, setLang } = useLang();
  return (
    <div role="radiogroup" aria-label="Language / اللغة" dir="ltr" className="flex shrink-0 rounded-full border border-line bg-surface p-0.5">
      {(["en", "ar"] as const).map((l) => (
        <button
          key={l}
          type="button"
          role="radio"
          aria-checked={lang === l}
          data-testid={`lang-${l}`}
          onClick={() => setLang(l)}
          lang={l}
          className={`min-h-9 min-w-10 rounded-full px-3 text-[13px] font-semibold transition-colors md:min-w-0 ${
            lang === l ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"
          }`}
        >
          {l === "en" ? (
            "EN"
          ) : (
            <>
              <span className="md:hidden">ع</span>
              <span className="hidden md:inline">عربي</span>
            </>
          )}
        </button>
      ))}
    </div>
  );
}

/**
 * Sticky header. Desktop / tablet: logo, the five window tabs, language, theme. Phone: logo, language, theme
 * (the windows move to the bottom navigation); on the phone result screen a "Shield set up" chip takes the
 * place of the toggles when the resident has opened the phone-shield setup (`shieldChip`).
 */
export function CitizenHeader({ view, onView, shieldChip = false }: { view: View; onView: (v: View) => void; shieldChip?: boolean }) {
  const { t } = useLang();

  return (
    <header className="sticky top-0 z-30 border-b border-line bg-surface/95 backdrop-blur-md">
      <div className="mx-auto flex h-14 max-w-6xl items-center gap-3 px-4 sm:px-6 md:h-16">
        <a
          href="/citizen"
          onClick={navClick(onView, "check")}
          aria-label={`Saqr · ${t("navCheck")}`}
          data-testid="header-logo"
          className="shrink-0 rounded-md"
        >
          <SaqrLogo variant="full" size={28} />
        </a>

        <nav aria-label={t("navLabel")} className="hidden min-w-0 flex-1 justify-center md:flex">
          <ul className="flex items-center gap-0.5 lg:gap-1">
            {NAV.map(({ id, key }) => {
              const active = view === id;
              return (
                <li key={id}>
                  <a
                    href={viewHref(id)}
                    onClick={navClick(onView, id)}
                    aria-current={active ? "page" : undefined}
                    data-testid={`tab-${id}`}
                    className={`relative inline-flex min-h-10 items-center whitespace-nowrap rounded-full px-2.5 text-[14px] transition-colors lg:px-3.5 after:pointer-events-none after:absolute after:inset-x-3 after:-bottom-[13px] after:h-0.5 after:rounded-full ${
                      active ? "font-semibold text-ink after:bg-ink" : "font-medium text-ink-soft hover:bg-muted hover:text-ink"
                    }`}
                  >
                    {t(key)}
                  </a>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="ms-auto flex shrink-0 items-center gap-2 md:ms-0">
          {shieldChip && (
            <span
              className="inline-flex items-center gap-1.5 rounded-full border border-brand-line bg-brand-soft px-2.5 py-1 text-[12px] font-semibold text-brand-ink md:hidden"
              data-testid="header-shield-chip"
            >
              <span className="size-1.5 rounded-full bg-brand" aria-hidden />
              {t("chipShieldSet")}
            </span>
          )}
          <div className={`items-center gap-2 ${shieldChip ? "hidden md:flex" : "flex"}`}>
            <LangPill />
            <ThemeToggle variant="saqr" />
          </div>
        </div>
      </div>
    </header>
  );
}

/** One understated line under the header (wraps on phones). */
export function NoticeStrip() {
  const { t } = useLang();
  return (
    <div className="hidden border-b border-line bg-muted md:block" data-testid="notice-strip">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-x-6 gap-y-1 px-4 py-2 text-[13px] leading-snug text-ink-soft sm:px-6">
        <p>{t("noticeDemo")}</p>
        <p className="whitespace-nowrap">
          {t("noticeReport")}{" "}
          <a href="tel:8002626" className="font-semibold text-ink underline-offset-2 hover:underline">
            {t("callAmanShort")}
          </a>{" "}
          <span aria-hidden>·</span>{" "}
          <a href="sms:2828" className="font-semibold text-ink underline-offset-2 hover:underline">
            {t("sms")} 2828
          </a>
        </p>
      </div>
    </div>
  );
}

/** Phone home: the notice as a small card (design-refs/citizen-mobile-reference.jpg). */
export function MobileNotice() {
  const { t } = useLang();
  return (
    <div className="rounded-control border border-line bg-surface px-3 py-2 text-[12px] leading-normal text-ink-soft" data-testid="notice-card">
      <span className="font-semibold text-ink">{t("mNoticeBold")}</span> {t("mNoticeRest")} {t("noticeReport")}{" "}
      <a href="tel:8002626" className="font-semibold text-ink underline-offset-2 hover:underline" data-testid="header-call-aman">
        {t("callAmanShort")}
      </a>{" "}
      <span aria-hidden>·</span>{" "}
      <a href="sms:2828" className="font-semibold text-ink underline-offset-2 hover:underline">
        {t("sms")} 2828
      </a>
    </div>
  );
}

const TAB_ICON: Record<MobileTab, typeof Shield> = { check: Shield, shield: Lock, alerts: Bell, learn: BookOpen };
const TAB_LABEL: Record<MobileTab, DictKey> = { check: "tabCheck", shield: "tabShield", alerts: "tabAlerts", learn: "tabLearn" };

/** Phone bottom navigation (< 768px): Check, Shield, Alerts, Learn. Fixed, translucent, safe-area aware. */
export function BottomNav({ view, onSelect }: { view: View; onSelect: (tab: MobileTab) => void }) {
  const { t } = useLang();
  const active = mobileTabOf(view);
  return (
    <nav
      aria-label={t("tabBarLabel")}
      className="fixed inset-x-0 bottom-0 z-30 border-t border-line bg-surface/92 px-2.5 pt-[9px] pb-[calc(9px+env(safe-area-inset-bottom))] backdrop-blur-md md:hidden"
      data-testid="bottom-nav"
    >
      <ul className="flex gap-0.5">
        {MOBILE_TABS.map((tab) => {
          const Icon = TAB_ICON[tab];
          const on = active === tab;
          return (
            <li key={tab} className="flex-1">
              <a
                href={viewHref(tab)}
                onClick={(e) => {
                  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
                  e.preventDefault();
                  onSelect(tab);
                }}
                aria-current={on ? "page" : undefined}
                data-testid={`bottom-nav-${tab}`}
                className={`flex min-h-12 flex-col items-center justify-center gap-1 rounded-control py-1 transition-colors ${
                  on ? "text-ink" : "text-ink-soft hover:text-ink"
                }`}
              >
                <Icon className="size-5" strokeWidth={on ? 2.2 : 1.8} aria-hidden />
                <span className="text-[11px] font-semibold leading-none">{t(TAB_LABEL[tab])}</span>
              </a>
            </li>
          );
        })}
      </ul>
    </nav>
  );
}

export function CitizenFooter() {
  const { t, lang } = useLang();
  return (
    <footer className="border-t border-line bg-surface" data-testid="site-footer">
      <div className="mx-auto max-w-6xl px-4 py-5 sm:px-6 md:py-6">
        <div className="flex flex-col gap-2 text-[14px] leading-relaxed md:flex-row md:items-start md:justify-between md:gap-8">
          <p className="hidden text-ink md:block">
            <span className="font-semibold">{t("footerScammed")}</span> {t("footerCall")}{" "}
            <a href="tel:8002626" className="font-semibold underline underline-offset-2">
              {lang === "ar" ? "8002626" : "Aman 8002626"}
            </a>{" "}
            {t("footerOr")}{" "}
            <a href="sms:2828" className="font-semibold underline underline-offset-2">
              2828
            </a>
            .
          </p>
          <p className="text-[12px] text-ink-soft md:max-w-[52ch] md:text-end md:text-[14px]">{t("footerProto")}</p>
        </div>
        <div className="mt-2 flex flex-wrap items-start justify-between gap-3 md:mt-4 md:border-t md:border-line md:pt-3">
          <PrivacyNote className="min-w-0 flex-1 basis-64" />
          <div className="hidden items-center gap-2 md:flex">
            <ShareQrButton />
          </div>
        </div>
      </div>
    </footer>
  );
}
