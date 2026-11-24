import type { CSSProperties } from "react";

/*
 * Saqr logo: the faceted falcon + the "Saqr" wordmark.
 *
 * - Inline SVG (no network request). Path data mirrors src/brand/saqr-falcon-mono.svg (FULL)
 *   and src/brand/saqr-falcon-small.svg (SMALL, heavier strokes, used below 24px).
 * - The wordmark is live text in --font-wordmark (Gloock), so it stays crisp and selectable.
 * - Colour: "light" = obsidian ink, "dark" = ivory, "auto" = the page's ink token (flips with the theme).
 *   Never recolour the logo outside ink / ivory (DESIGN.md, Logo).
 * - RTL-safe: the lockup is always mark -> wordmark, left to right, also inside Arabic pages.
 */

const FULL =
  "M260 24L354 51L371 78L394 97C403 110 405 128 400 146L390 172L380 145L354 146L344 182L352 203L424 284L368 379L274 219L341 136L296 140L219 252L135 317L159 369L168 306L248 244L163 402L89 284L145 218L179 81ZM262 38L344 60L354 75L334 86L271 63L208 77ZM195 94L268 77L268 91L286 111L309 106L316 92L330 98L326 106L286 132L253 180ZM187 104L217 151L160 219ZM243 191L208 244L140 297L155 236ZM334 164L331 185L377 303L287 223ZM358 86L382 103L368 129L349 124L315 127L338 111L344 96ZM352 100L366 101L352 112ZM259 250L294 427L254 489L253 303L227 453L188 382ZM270 237L344 362L311 444Z";
const SMALL =
  "M260 24L354 51L371 78L394 97C403 110 405 128 400 146L390 172L380 145L354 146L344 182L352 203L424 284L368 379L274 219L341 136L289 141L213 249L128 312L159 369L168 306L248 244L163 402L89 284L145 218L179 81ZM210 101L259 89L259 97L283 121L317 112L253 164ZM191 127L206 150L177 184ZM211 212L196 234L153 268L161 238ZM323 188L356 272L299 222ZM357 97L371 106L362 119L344 116ZM259 250L294 427L254 489L253 303L227 453L188 382ZM270 237L344 362L311 444Z";

/** Tight box around the falcon (lockup) and a centred square (icon). */
const LOCKUP_BOX = { x: 89, y: 24, w: 335, h: 465 };
const ICON_BOX = "20 20 472 472";

const COLOUR = {
  light: "#111315",
  dark: "#FAF8F5",
  auto: "var(--color-ink)",
} as const;

export type SaqrLogoProps = {
  /** "full" = falcon + wordmark (default), "icon" = falcon only. */
  variant?: "full" | "icon";
  /** "light" = ink for light grounds, "dark" = ivory for dark grounds, "auto" = follows the theme (default). */
  theme?: "light" | "dark" | "auto";
  /** Adds the small tracked caps line "INTEL · ABU DHABI" under the wordmark (full variant only). */
  sublabel?: boolean;
  /** Height of the falcon in px (default 32). The wordmark scales from it. */
  size?: number;
  className?: string;
};

export function SaqrLogo({ variant = "full", theme = "auto", sublabel = false, size = 32, className }: SaqrLogoProps) {
  const colour = COLOUR[theme];
  const d = size < 24 ? SMALL : FULL;

  if (variant === "icon") {
    return (
      <svg
        role="img"
        aria-label="Saqr"
        viewBox={ICON_BOX}
        width={size}
        height={size}
        className={className}
        style={{ color: colour, flexShrink: 0 }}
      >
        <path fill="currentColor" fillRule="evenodd" d={d} />
      </svg>
    );
  }

  // Proportions measured on the reference lockup: cap height ~ 1/3 of the falcon height,
  // gap ~ 0.11 of it, wordmark optically centred on the falcon (Gloock caps sit high in the em box).
  const fontSize = Math.round(size * 0.46 * 10) / 10;
  const subSize = Math.max(11, Math.round(size * 0.15));
  const style: CSSProperties = { color: colour, gap: Math.round(size * 0.14), lineHeight: 1 };

  return (
    <span role="img" aria-label="Saqr" dir="ltr" className={`inline-flex shrink-0 items-center ${className ?? ""}`} style={style}>
      <svg
        aria-hidden
        viewBox={`${LOCKUP_BOX.x} ${LOCKUP_BOX.y} ${LOCKUP_BOX.w} ${LOCKUP_BOX.h}`}
        height={size}
        width={Math.round((size * LOCKUP_BOX.w) / LOCKUP_BOX.h)}
        style={{ flexShrink: 0 }}
      >
        <path fill="currentColor" fillRule="evenodd" d={d} />
      </svg>
      <span className="flex flex-col" style={{ gap: sublabel ? Math.round(size * 0.08) : 0 }}>
        <span
          dir="ltr"
          className="font-wordmark"
          // A hairline text stroke brings Gloock's weight up to the heavier reference lettering.
          style={{ fontSize, lineHeight: 1, letterSpacing: "-0.005em", WebkitTextStroke: "0.012em currentColor", transform: `translateY(${sublabel ? 0 : size * 0.02}px)` }}
        >
          Saqr
        </span>
        {sublabel && (
          <span
            dir="ltr"
            className="font-sans font-semibold uppercase"
            style={{ fontSize: subSize, letterSpacing: "0.18em", lineHeight: 1, paddingInlineStart: "0.08em" }}
          >
            Intel · Abu Dhabi
          </span>
        )}
      </span>
    </span>
  );
}
