"use client";

/**
 * Night Grid: Abu Dhabi drawn as a dot-matrix city at night. Land dots are brighter than sea dots;
 * live data lights it: crimson pins are scams, emerald pins are verified official places.
 * Pure SVG + HTML (no map service), so it renders the same on stage, offline and in both themes.
 */
import { memo, useMemo } from "react";

export interface GridPin {
  id: string;
  lat: number;
  lng: number;
  title: string;
  type: "SPOOFED" | "VERIFIED";
}

// Abu Dhabi city area (Corniche, Al Maryah, Saadiyat, Yas, Mussafah, Khalifa City).
const BOX = { minLat: 24.3, maxLat: 24.58, minLng: 54.27, maxLng: 54.67 };
const KX = Math.cos((24.44 * Math.PI) / 180); // equirectangular correction at this latitude
const W = (BOX.maxLng - BOX.minLng) * KX;
const H = BOX.maxLat - BOX.minLat;

type Poly = [number, number][]; // [lng, lat]
// Simplified outlines, generous enough to read as the city at a glance (demo-grade geography).
const LAND: Poly[] = [
  // mainland (Mussafah, Khalifa City, airport road)
  [[54.27, 24.3], [54.67, 24.3], [54.67, 24.455], [54.6, 24.44], [54.55, 24.445], [54.5, 24.42], [54.46, 24.4], [54.4, 24.383], [54.34, 24.372], [54.27, 24.362]],
  // Abu Dhabi island (Corniche to Al Maryah)
  [[54.31, 24.468], [54.33, 24.486], [54.36, 24.5], [54.395, 24.512], [54.425, 24.505], [54.45, 24.483], [54.462, 24.457], [54.44, 24.432], [54.405, 24.412], [54.37, 24.415], [54.34, 24.428], [54.318, 24.448]],
  // Saadiyat
  [[54.395, 24.53], [54.43, 24.555], [54.475, 24.558], [54.485, 24.54], [54.45, 24.523], [54.415, 24.52]],
  // Yas
  [[54.585, 24.47], [54.6, 24.5], [54.625, 24.505], [54.635, 24.48], [54.615, 24.455], [54.595, 24.455]],
  // Reem
  [[54.39, 24.497], [54.41, 24.505], [54.425, 24.497], [54.41, 24.49]],
];

function inside([x, y]: [number, number], poly: Poly): boolean {
  let hit = false;
  for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
    const [xi, yi] = poly[i];
    const [xj, yj] = poly[j];
    if (yi > y !== yj > y && x < ((xj - xi) * (y - yi)) / (yj - yi) + xi) hit = !hit;
  }
  return hit;
}

/** Position in % of the map box (clamped so off-map reports still show at the edge). */
export function project(lat: number, lng: number): { x: number; y: number } {
  const x = (((lng - BOX.minLng) * KX) / W) * 100;
  const y = ((BOX.maxLat - lat) / H) * 100;
  return { x: Math.min(97, Math.max(3, x)), y: Math.min(95, Math.max(5, y)) };
}

/** District names printed on the map so "where" reads at a glance (bilingual). */
const DISTRICTS: { en: string; ar: string; lat: number; lng: number }[] = [
  { en: "Corniche", ar: "الكورنيش", lat: 24.452, lng: 54.335 },
  { en: "Al Maryah", ar: "المارية", lat: 24.522, lng: 54.37 },
  { en: "Saadiyat", ar: "السعديات", lat: 24.566, lng: 54.44 },
  { en: "Yas", ar: "ياس", lat: 24.517, lng: 54.612 },
  { en: "Mussafah", ar: "مصفح", lat: 24.33, lng: 54.5 },
  { en: "Khalifa City", ar: "مدينة خليفة", lat: 24.4, lng: 54.6 },
];

const COLS = 64;
const ROWS = Math.round((COLS * H) / W);
/** The city's true proportions: give the map box this aspect ratio so dots stay round and pins exact. */
export const MAP_ASPECT = `${COLS} / ${ROWS}`;

const Dots = memo(function Dots({ glow, strong, crop }: { glow?: { lat: number; lng: number; r: number }; strong?: boolean; crop?: boolean }) {
  const dots = useMemo(() => {
    const out: { cx: number; cy: number; land: boolean; lit: boolean }[] = [];
    for (let r = 0; r < ROWS; r++) {
      for (let c = 0; c < COLS; c++) {
        const lng = BOX.minLng + ((c + 0.5) / COLS) * (BOX.maxLng - BOX.minLng);
        const lat = BOX.maxLat - ((r + 0.5) / ROWS) * H;
        const land = LAND.some((p) => inside([lng, lat], p));
        const lit = !!glow && land && Math.hypot((lng - glow.lng) * KX, lat - glow.lat) < glow.r;
        out.push({ cx: c + 0.5, cy: r + 0.5, land, lit });
      }
    }
    return out;
  }, [glow]);
  return (
    <svg viewBox={`0 0 ${COLS} ${ROWS}`} preserveAspectRatio={crop ? "xMidYMid slice" : "none"} className="absolute inset-0 size-full" aria-hidden>
      {dots.map((d, i) => (
        <circle
          key={i}
          cx={d.cx}
          cy={d.cy}
          r={d.land ? 0.2 : 0.11}
          className={d.lit ? "fill-emerald-500/85" : d.land ? (strong ? "fill-ink-soft/70" : "fill-ink-soft/45") : strong ? "fill-ink-soft/20" : "fill-ink-soft/15"}
        />
      ))}
    </svg>
  );
});

/** Interactive map for the police desk. */
export function CityGridMap({
  pins,
  selectedId,
  onSelect,
  label,
  lang = "en",
}: {
  pins: GridPin[];
  selectedId: string | null;
  onSelect: (pin: GridPin) => void;
  label: string;
  lang?: "en" | "ar";
}) {
  return (
    <div className="relative size-full" dir="ltr" role="group" aria-label={label}>
      <Dots />
      {DISTRICTS.map((d) => {
        const { x, y } = project(d.lat, d.lng);
        return (
          <span
            key={d.en}
            aria-hidden
            className="pointer-events-none absolute -translate-x-1/2 -translate-y-1/2 whitespace-nowrap rounded bg-canvas/90 px-1 text-[11px] font-semibold uppercase tracking-[0.14em] text-ink-soft"
            style={{ left: `${x}%`, top: `${y}%` }}
            lang={lang}
          >
            {lang === "ar" ? d.ar : d.en}
          </span>
        );
      })}
      {pins.map((p) => {
        const { x, y } = project(p.lat, p.lng);
        const scam = p.type === "SPOOFED";
        const on = p.id === selectedId;
        return (
          <button
            key={p.id}
            type="button"
            onClick={() => onSelect(p)}
            aria-pressed={on}
            aria-label={`${scam ? "Spoofed" : "Verified"}: ${p.title}`}
            title={p.title}
            className="group absolute -translate-x-1/2 -translate-y-1/2 rounded-full p-2"
            style={{ left: `${x}%`, top: `${y}%` }}
          >
            <span
              className={`block rounded-full transition-[width,height,box-shadow] duration-200 ${on ? "size-4" : "size-3 group-hover:size-3.5"} ${
                scam
                  ? "bg-scam shadow-[0_0_0_6px_color-mix(in_oklab,var(--color-scam)_22%,transparent),0_0_0_14px_color-mix(in_oklab,var(--color-scam)_9%,transparent)]"
                  : "bg-emerald-500 shadow-[0_0_0_5px_rgba(16,185,129,0.2)]"
              } ${on ? "ring-2 ring-ink ring-offset-2 ring-offset-surface" : ""}`}
            />
          </button>
        );
      })}
    </div>
  );
}

/** Decorative backdrop for the citizen hero: the city with your shield lit around the island. */
export function CityGridBackdrop() {
  return (
    <div className="pointer-events-none absolute inset-0 overflow-hidden" aria-hidden dir="ltr">
      <Dots strong crop glow={{ lat: 24.465, lng: 54.385, r: 0.05 }} />
    </div>
  );
}
