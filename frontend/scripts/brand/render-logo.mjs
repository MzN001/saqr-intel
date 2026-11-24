// Render the Saqr falcon next to the reference artwork for visual comparison.
//
//   cd frontend
//   node scripts/brand/render-logo.mjs [mark.svg] [out.png]
//
// Defaults: src/brand/saqr-falcon.svg -> ../../design-refs/saqr-logo-render.png
// Output (one PNG): reference emblem | our mark | our mark (red, 55%) over the reference,
// then a row of small sizes (16, 20, 24, 32, 48 px) of the full and the small-size marks,
// on ivory and on obsidian.
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import sharp from "sharp";

const here = path.dirname(fileURLToPath(import.meta.url));
const frontend = path.resolve(here, "../..");
const mark = path.resolve(process.argv[2] ?? path.join(frontend, "src/brand/saqr-falcon.svg"));
const out = path.resolve(process.argv[3] ?? path.join(frontend, "../../design-refs/saqr-logo-render.png"));
const small = path.join(frontend, "src/brand/saqr-falcon-small.svg");
const refPath = path.join(frontend, "../../design-refs/saqr-logo-reference.jpg");

const IVORY = "#F7F5F0";
const INK = "#111315";
const S = 512; // panel size

// Where the emblem sits in the 1024px reference, mapped onto the 512 viewBox of the master SVG.
// Same mapping that was used to trace and redraw the master from the reference.
const REF_BOX = { left: 120, top: 280, width: 330, height: 460 };
const VIEW = { scale: 1.06, dx: 79, dy: 11 }; // reference px -> viewBox units

const colour = (svg, fill) => svg.replace(/currentColor/g, fill);
const png = (svg, size) => sharp(Buffer.from(svg), { density: 72 * (size / 512) * 4 }).resize(size, size).png().toBuffer();

const svgText = await readFile(mark, "utf8");
let smallText = null;
try {
  smallText = await readFile(small, "utf8");
} catch {
  /* optional */
}

// Reference emblem placed into a 512 square with the same mapping as the master.
const refW = Math.round(REF_BOX.width * VIEW.scale);
const refH = Math.round(REF_BOX.height * VIEW.scale);
const refEmblem = await sharp(refPath).extract(REF_BOX).resize(refW, refH).toBuffer();
const refPanel = await sharp({ create: { width: S, height: S, channels: 4, background: "#EFEBDD" } })
  .composite([{ input: refEmblem, left: VIEW.dx, top: VIEW.dy }])
  .png()
  .toBuffer();

const ours = await png(colour(svgText, INK), S);
const oursPanel = await sharp({ create: { width: S, height: S, channels: 4, background: IVORY } })
  .composite([{ input: ours }])
  .png()
  .toBuffer();
const red = await png(colour(svgText, "rgba(220,38,38,0.55)"), S);
const overlay = await sharp(refPanel).composite([{ input: red }]).png().toBuffer();

// Small sizes row.
const sizes = [16, 20, 24, 32, 48];
const rowH = 140;
const tiles = [];
let x = 16;
for (const [bg, fg] of [
  [IVORY, INK],
  [INK, "#FAF8F5"],
]) {
  for (const src of [svgText, smallText].filter(Boolean)) {
    for (const size of sizes) {
      const buf = await png(colour(src, fg), size);
      tiles.push({ input: await sharp({ create: { width: size + 12, height: size + 12, channels: 4, background: bg } }).composite([{ input: buf, left: 6, top: 6 }]).png().toBuffer(), left: x, top: S + 20 + (src === svgText ? 0 : 64) });
      x += size + 20;
    }
    x -= sizes.reduce((a, s) => a + s + 20, 0);
  }
  x += sizes.reduce((a, s) => a + s + 20, 0) + 40;
}

await sharp({ create: { width: S * 3, height: S + rowH + 20, channels: 4, background: "#FFFFFF" } })
  .composite([
    { input: refPanel, left: 0, top: 0 },
    { input: oursPanel, left: S, top: 0 },
    { input: overlay, left: S * 2, top: 0 },
    ...tiles,
  ])
  .png()
  .toFile(out);
console.log("wrote", out);
