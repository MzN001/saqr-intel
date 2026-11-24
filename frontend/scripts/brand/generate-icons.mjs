// Generate every Saqr app icon from the master SVGs in src/brand/.
//
//   cd frontend
//   node scripts/brand/generate-icons.mjs
//
// Needs only `sharp` (already in node_modules via Next). Re-run after editing
// src/brand/saqr-falcon.svg or src/brand/saqr-falcon-small.svg, then commit the outputs:
//
//   frontend/public/icons/icon-192.png          PWA "any" icon, sandstone canvas, full mark
//   frontend/public/icons/icon-512.png          PWA "any" icon, sandstone canvas, full mark
//   frontend/public/icons/icon-maskable-512.png PWA maskable icon, mark inside the 80% safe circle
//   frontend/public/icons/badge-96.png          notification badge, white mark on transparent (sw.js)
//   frontend/public/apple-touch-icon.png        180px, solid canvas (iOS ignores transparency)
//   frontend/src/app/apple-icon.png             same 180px file, Next metadata file convention
//   frontend/src/app/icon.svg                   browser tab icon, ink / ivory via prefers-color-scheme
//   frontend/src/app/favicon.ico                16/32/48 fallback, small mark on a sandstone tile
//   extension/icons/icon16.png, icon48.png, icon128.png   sandstone tile + obsidian mark
//   android-app/app/src/main/res/drawable/ic_saqr_falcon.xml  VectorDrawable (24dp), small mark
import { readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontend = path.resolve(here, "../..");
const repo = path.resolve(frontend, "..");

const CANVAS = "#F7F5F0"; // light canvas token
const TILE = "#ECE7DB"; // sandstone tile: a step deeper than the canvas so the edge shows on white toolbars
const INK = "#111315";
const IVORY = "#FAF8F5";

const read = (f) => readFile(path.join(frontend, "src/brand", f), "utf8");
const pathsOf = (svg) => [...svg.matchAll(/<path\b[^>]*\bd="([^"]+)"/g)].map((m) => m[1].replace(/\s+/g, " ").trim());
const viewBoxOf = (svg) => svg.match(/viewBox="([^"]+)"/)[1].split(/\s+/).map(Number);

const full = await read("saqr-falcon-mono.svg");
const small = await read("saqr-falcon-small.svg");

/** SVG string: the mark (from `src`) in `fill`, `scale` of the box, on an optional rounded tile. */
function compose(src, { size, fill = INK, bg = null, scale = 0.8, radius = 0 }) {
  const [vx, vy, vw, vh] = viewBoxOf(src);
  const d = pathsOf(src).join(" ");
  const inner = size * scale;
  const k = inner / Math.max(vw, vh);
  const tx = (size - vw * k) / 2 - vx * k;
  const ty = (size - vh * k) / 2 - vy * k;
  const tile = bg ? `<rect width="${size}" height="${size}" rx="${radius}" fill="${bg}"/>` : "";
  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 ${size} ${size}">${tile}<path fill="${fill}" fill-rule="evenodd" transform="translate(${tx.toFixed(3)} ${ty.toFixed(3)}) scale(${k.toFixed(5)})" d="${d}"/></svg>`;
}

const toPng = (svg, size) => sharp(Buffer.from(svg), { density: 300 }).resize(size, size).png({ compressionLevel: 9 }).toBuffer();

async function png(file, src, opts) {
  const buf = await toPng(compose(src, opts), opts.size);
  await writeFile(file, buf);
  console.log("wrote", path.relative(repo, file));
  return buf;
}

// PWA + Apple. The full mark is ~0.72 as wide as it is tall, so "scale" is its height share.
await png(path.join(frontend, "public/icons/icon-192.png"), full, { size: 192, bg: CANVAS, scale: 0.78 });
await png(path.join(frontend, "public/icons/icon-512.png"), full, { size: 512, bg: CANVAS, scale: 0.78 });
// Maskable: launchers may crop to a circle of 80% diameter; the mark's bounding box stays inside it.
await png(path.join(frontend, "public/icons/icon-maskable-512.png"), full, { size: 512, bg: CANVAS, scale: 0.62 });
// Notification badge (Android status bar): monochrome mark on transparent, the OS tints it.
await png(path.join(frontend, "public/icons/badge-96.png"), small, { size: 96, fill: "#FFFFFF", scale: 0.92 });
const apple = await png(path.join(frontend, "public/apple-touch-icon.png"), full, { size: 180, bg: CANVAS, scale: 0.74 });
await writeFile(path.join(frontend, "src/app/apple-icon.png"), apple);
console.log("wrote frontend/src/app/apple-icon.png");

// Browser tab: an SVG that follows the browser's colour scheme (ink on light tab strips, ivory on dark).
{
  const [vx, vy, vw, vh] = viewBoxOf(small);
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="${vx} ${vy} ${vw} ${vh}"><style>path{fill:${INK}}@media (prefers-color-scheme:dark){path{fill:${IVORY}}}</style><path fill-rule="evenodd" d="${pathsOf(small).join(" ")}"/></svg>\n`;
  await writeFile(path.join(frontend, "src/app/icon.svg"), svg);
  console.log("wrote frontend/src/app/icon.svg");
}

// favicon.ico (PNG-in-ICO): small mark on a sandstone tile, readable on light and dark tab strips.
{
  const sizes = [16, 32, 48];
  const imgs = await Promise.all(sizes.map((s) => toPng(compose(small, { size: s, bg: TILE, scale: 0.86, radius: s * 0.22 }), s)));
  const header = Buffer.alloc(6 + 16 * sizes.length);
  header.writeUInt16LE(0, 0);
  header.writeUInt16LE(1, 2);
  header.writeUInt16LE(sizes.length, 4);
  let offset = header.length;
  sizes.forEach((s, i) => {
    const e = 6 + i * 16;
    header.writeUInt8(s, e);
    header.writeUInt8(s, e + 1);
    header.writeUInt8(0, e + 2);
    header.writeUInt8(0, e + 3);
    header.writeUInt16LE(1, e + 4);
    header.writeUInt16LE(32, e + 6);
    header.writeUInt32LE(imgs[i].length, e + 8);
    header.writeUInt32LE(offset, e + 12);
    offset += imgs[i].length;
  });
  await writeFile(path.join(frontend, "src/app/favicon.ico"), Buffer.concat([header, ...imgs]));
  console.log("wrote frontend/src/app/favicon.ico");
}

// Browser extension toolbar icons: sandstone tile + obsidian mark. A transparent obsidian mark disappears
// on dark toolbars and an ivory one on light toolbars; the tile reads on both.
for (const s of [16, 48, 128]) {
  await png(path.join(repo, `extension/icons/icon${s}.png`), s < 48 ? small : full, {
    size: s,
    bg: TILE,
    scale: s < 48 ? 0.88 : 0.8,
    radius: s * 0.22,
  });
}

// Android VectorDrawable: the small mark mapped onto a 24 x 24 viewport. Only M/L/C/Z commands are used.
{
  const [vx, vy, vw] = viewBoxOf(small);
  const k = 24 / vw;
  const d = pathsOf(small)
    .join(" ")
    .replace(/([MLC])([^MLCZ]+)/g, (_, cmd, nums) => {
      const n = nums.trim().split(/[\s,]+/).map(Number);
      const out = [];
      for (let i = 0; i < n.length; i += 2) out.push(`${+((n[i] - vx) * k).toFixed(3)},${+((n[i + 1] - vy) * k).toFixed(3)}`);
      return cmd + out.join(" ");
    });
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<!-- Saqr falcon (small-size master). Generated by frontend/scripts/brand/generate-icons.mjs; do not edit by hand.
     Tint it from code or with android:tint; the fill is plain obsidian ink. -->
<vector xmlns:android="http://schemas.android.com/apk/res/android"
    android:width="24dp"
    android:height="24dp"
    android:viewportWidth="24"
    android:viewportHeight="24">
    <path
        android:fillColor="#FF111315"
        android:fillType="evenOdd"
        android:pathData="${d}" />
</vector>
`;
  const file = path.join(repo, "android-app/app/src/main/res/drawable/ic_saqr_falcon.xml");
  await writeFile(file, xml);
  console.log("wrote", path.relative(repo, file));
}
