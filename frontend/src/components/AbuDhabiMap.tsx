"use client";

/**
 * Abu Dhabi Geo-Spoof Sentinel map (dark-styled OpenStreetMap). Client-only (Leaflet touches `window`): load it with
 * `dynamic(() => import("@/components/AbuDhabiMap"), { ssr: false })`.
 */
import L from "leaflet";
import "leaflet/dist/leaflet.css";
import { useEffect, useRef } from "react";
import type { MapPin } from "@/lib/police";

const CENTER: L.LatLngTuple = [24.4539, 54.3773];
const COLORS = { SPOOFED: "#c8102e", VERIFIED: "#0e9f6e" } as const;

export default function AbuDhabiMap({
  pins,
  selectedId,
  onSelect,
}: {
  pins: MapPin[];
  selectedId: string | null;
  onSelect: (pin: MapPin) => void;
}) {
  const box = useRef<HTMLDivElement>(null);
  const map = useRef<L.Map | null>(null);
  const layer = useRef<L.LayerGroup | null>(null);
  const onSelectRef = useRef(onSelect);
  useEffect(() => {
    onSelectRef.current = onSelect;
  }, [onSelect]);

  useEffect(() => {
    if (!box.current || map.current) return;
    const m = L.map(box.current, { center: CENTER, zoom: 11, zoomControl: true, attributionControl: true });
    // OpenStreetMap tiles (no API key), darkened with a CSS filter (.saqr-dark-tiles in globals.css).
    L.tileLayer("https://tile.openstreetmap.org/{z}/{x}/{y}.png", {
      maxZoom: 19,
      className: "saqr-dark-tiles",
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors',
    }).addTo(m);
    layer.current = L.layerGroup().addTo(m);
    map.current = m;
    // The card can change size after first paint (fonts, grid): keep the tiles aligned.
    const ro = new ResizeObserver(() => m.invalidateSize());
    ro.observe(box.current);
    return () => {
      ro.disconnect();
      m.remove();
      map.current = null;
      layer.current = null;
    };
  }, []);

  useEffect(() => {
    const lg = layer.current;
    if (!lg) return;
    lg.clearLayers();
    for (const p of pins) {
      const selected = p.id === selectedId;
      const color = COLORS[p.type];
      if (p.type === "SPOOFED") {
        L.circleMarker([p.lat, p.lng], { radius: selected ? 26 : 18, color, weight: 1, opacity: 0.35, fillOpacity: 0.12, interactive: false }).addTo(lg);
      }
      L.circleMarker([p.lat, p.lng], {
        radius: selected ? 11 : 8,
        color: selected ? "#ffffff" : color,
        weight: selected ? 3 : 2,
        fillColor: color,
        fillOpacity: 0.95,
      })
        .bindTooltip(p.title, { direction: "top", offset: [0, -8] })
        .on("click", () => onSelectRef.current(p))
        .addTo(lg);
    }
  }, [pins, selectedId]);

  useEffect(() => {
    const p = pins.find((x) => x.id === selectedId);
    if (p && map.current) map.current.flyTo([p.lat, p.lng], Math.max(map.current.getZoom(), 13), { duration: 0.8 });
  }, [selectedId, pins]);

  return <div ref={box} className="h-full w-full" aria-label="Abu Dhabi map of reported Google Maps pins" />;
}
