"use client";

import type { AnimationItem } from "lottie-web";
import { useEffect, useRef, type MouseEvent } from "react";
import moonToSun from "@/assets/moon-to-sun.json";
import { useLang } from "@/lib/i18n";
import { prefersReducedMotion, useTheme } from "@/lib/theme";

// Lottie "moon-to-sun" by Christopher Raeside (LottieFiles, free animation).
// Frame 0 is the moon (dark mode), the last frame is the sun (light mode).
const PLAYBACK_SPEED = 2.4;

export function ThemeToggle() {
  const { t } = useLang();
  const { theme, toggle } = useTheme();
  const box = useRef<HTMLSpanElement>(null);
  const anim = useRef<AnimationItem | null>(null);

  // lottie touches `document` when imported, so load it in the browser only.
  useEffect(() => {
    let cancelled = false;
    let item: AnimationItem | null = null;
    import("lottie-web/build/player/lottie_light").then(({ default: lottie }) => {
      if (cancelled || !box.current) return;
      item = lottie.loadAnimation({
        container: box.current,
        renderer: "svg",
        loop: false,
        autoplay: false,
        animationData: moonToSun,
      });
      item.setSpeed(PLAYBACK_SPEED);
      const isDark = document.documentElement.getAttribute("data-theme") === "dark";
      item.goToAndStop(isDark ? 0 : item.totalFrames - 1, true);
      anim.current = item;
    });
    return () => {
      cancelled = true;
      item?.destroy();
      anim.current = null;
    };
  }, []);

  // Play moon → sun (to light) or sun → moon (to dark). Reverses smoothly if clicked mid-way.
  useEffect(() => {
    const a = anim.current;
    if (!a) return;
    if (prefersReducedMotion()) {
      a.goToAndStop(theme === "dark" ? 0 : a.totalFrames - 1, true);
      return;
    }
    a.setDirection(theme === "dark" ? -1 : 1);
    a.play();
  }, [theme]);

  const onClick = (e: MouseEvent<HTMLButtonElement>) => {
    const r = e.currentTarget.getBoundingClientRect();
    toggle({ x: r.left + r.width / 2, y: r.top + r.height / 2 });
  };

  const label = theme === "dark" ? t("themeToLight") : t("themeToDark");

  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={label}
      title={label}
      className="grid size-9 shrink-0 place-items-center rounded-full bg-navy-900 shadow-sm transition-transform hover:scale-105 active:scale-95 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-gold-500 ring-1 ring-gold-500/40 dark:bg-navy-800"
    >
      <span ref={box} aria-hidden className="block size-7" />
    </button>
  );
}
