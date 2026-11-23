---
version: 1
slug: "src-app-police-page-tsx"
primary_target: "src/app/police/page.tsx"
related_targets: ["src/app/citizen/page.tsx"]
---

## Scope

`/police` (Command Center, desktop-first, projected on stage) and `/citizen` (phone-first portal). Visitor mode: **Operate** on both. Dark by default, light version of the same design behind the theme toggle on both pages. SAQR emerald + gold identity, crimson only for scam.

## Audience and job

Officers watch live interceptions and act (sync to e& / du, broadcast a warning, export a dossier). Citizens check one link, SMS, email or Maps pin and switch on the phone shield.

## Constraints

- Owner requirement: the police top bar follows the Abu Dhabi Police website layout: settings and search icons, a language link, uppercase menu items with a red underline on the active one, the bilingual wordmark "شرطة أبوظبي / ABU DHABI POLICE" at the reading-end edge with the crest slot (SAQR shield; the official emblem is not copied), and a menu button on small screens. Plus the same light/dark switch as `/citizen`.
- Bilingual EN / AR with RTL; WCAG AA in both themes; reduced motion.
- Reference supplied by the owner (Farider bento dashboard) is inspiration only.

## Direction contract

THESIS: Every scam is a light on the city. A dot-matrix night map of Abu Dhabi is the ground both pages stand on, and live data is what lights it; this refuses the category default of a grey card grid with a chart in every tile.

OWN-WORLD: Night navy ground (#0a1220) with a faint 14px dot grid, tiles one step lighter with 1px hairline edges and 20px radius, no glow halos. Emerald = official / safe / shield on, gold = verified police action, crimson = scam only, never swapped. Numbers in a light-weight large figure style; labels in small tracked caps. States stamp themselves (BLOCKED, SYNCED TO e& / du, FLAGGED ON X) and nothing silently disappears. Light version: the same structure on the cream ground with navy ink and the dot grid in warm grey.

STORY: Officers see where scams are landing right now, which campaign each belongs to, and act on it in one click; citizens see their link judged in seconds and their own shield as a lit area of the same city.

FIRST VIEWPORT: Police: Abu Dhabi Police–style top bar; a slim live strip (sync status, Citizen Portal, Stage QR); left column of KPI tiles; the dotted Abu Dhabi map as the large centre tile with crimson interception pins and emerald verified places, a click-to-inspect registry card; right column with the interception stream above the selected campaign's three actions. Citizen: header, then the link checker sitting on the dotted night map (primary action: Scan Now), shield and alerts tiles below.

FORM: grounded direction 3 of 3 (Abu Dhabi Night Grid); seed:31d896eb3bdde36a. Raises: fixed colour language (orienteering), ranked named campaign roster (character catalog), one-pixel hairline discipline (centre rail), self-stamping states (ticket wallet).

FINISH: unreviewed and undocumented is unfinished; this build ends with the finish review, the verdict, DESIGN.md, and every shipping raster carrying its provenance
