"use client";

import { Phone } from "lucide-react";
import { useEffect, useRef, type MouseEvent } from "react";
import { useLang, type DictKey } from "@/lib/i18n";
import { viewHref, type View } from "@/lib/view";
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
          className={`min-h-11 rounded-full px-3 text-[13px] font-semibold transition-colors md:min-h-9 ${
            lang === l ? "bg-primary text-on-primary" : "text-ink-soft hover:text-ink"
          }`}
        >
          {l === "en" ? "EN" : "عربي"}
        </button>
      ))}
    </div>
  );
}

export function CitizenHeader({ view, onView }: { view: View; onView: (v: View) => void }) {
  const { t } = useLang();
  const mobileBar = useRef<HTMLUListElement>(null);

  // Keep the active pill visible in the phone tab bar (no page scroll: the header is sticky and in view).
  useEffect(() => {
    const el = mobileBar.current?.querySelector<HTMLElement>(`[data-view="${view}"]`);
    if (!el || el.offsetParent === null) return;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    el.scrollIntoView({ behavior: reduce ? "auto" : "smooth", block: "nearest", inline: "center" });
  }, [view]);

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
          <LangPill />
          <ThemeToggle variant="saqr" className="hidden md:grid" />
          <a
            href="tel:8002626"
            aria-label={t("callAmanLabel")}
            data-testid="header-call-aman"
            className="inline-flex min-h-11 items-center gap-1.5 rounded-full border border-line bg-surface px-3 text-[13px] font-semibold text-ink hover:bg-muted md:hidden"
          >
            <Phone className="size-4 shrink-0" aria-hidden />
            <span dir="ltr" className="whitespace-nowrap tabular-nums">
              <span className="hidden min-[380px]:inline">{t("aman")} </span>8002626
            </span>
          </a>
        </div>
      </div>

      <nav aria-label={t("navLabel")} className="border-t border-line md:hidden">
        <ul ref={mobileBar} className="tab-scroller no-scrollbar flex gap-2 overflow-x-auto px-4 py-1 sm:px-6">
          {NAV.map(({ id, key }) => {
            const active = view === id;
            return (
              <li key={id} className="shrink-0">
                <a
                  href={viewHref(id)}
                  onClick={navClick(onView, id)}
                  aria-current={active ? "page" : undefined}
                  data-view={id}
                  data-testid={`tab-mobile-${id}`}
                  className={`inline-flex min-h-12 items-center whitespace-nowrap rounded-full px-4 text-[14px] transition-colors ${
                    active ? "bg-primary font-semibold text-on-primary" : "font-medium text-ink-soft hover:text-ink"
                  }`}
                >
                  {t(key)}
                </a>
              </li>
            );
          })}
        </ul>
      </nav>
    </header>
  );
}

/** One understated line under the header (wraps on phones). */
export function NoticeStrip() {
  const { t } = useLang();
  return (
    <div className="border-b border-line bg-muted" data-testid="notice-strip">
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

export function CitizenFooter() {
  const { t, lang } = useLang();
  return (
    <footer className="border-t border-line bg-surface" data-testid="site-footer">
      <div className="mx-auto max-w-6xl px-4 py-6 sm:px-6">
        <div className="flex flex-col gap-2 text-[14px] leading-relaxed md:flex-row md:items-start md:justify-between md:gap-8">
          <p className="text-ink">
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
          <p className="text-ink-soft md:max-w-[52ch] md:text-end">{t("footerProto")}</p>
        </div>
        <div className="mt-4 flex flex-wrap items-start justify-between gap-3 border-t border-line pt-3">
          <PrivacyNote className="min-w-0 flex-1 basis-64" />
          <div className="flex items-center gap-2">
            <ShareQrButton />
            <ThemeToggle variant="saqr" className="md:hidden" />
          </div>
        </div>
      </div>
    </footer>
  );
}
