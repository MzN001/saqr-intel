---
name: SAQR-INTEL
description: Abu Dhabi Night Grid. A dot-matrix night map of the city, lit by live scam and shield data, shared by the police Command Center and the citizen portal.
colors:
  night-canvas: "#0a1220"
  night-surface: "#111c2e"
  night-muted: "#16243a"
  night-line: "#1f2d45"
  night-ink: "#e8eef7"
  night-ink-soft: "#a3b3c8"
  cream-canvas: "#f3ecdf"
  cream-surface: "#faf6ee"
  cream-muted: "#eee5d5"
  cream-line: "#e0d4bf"
  cream-ink: "#0b192c"
  cream-ink-soft: "#2b4568"
  shield-emerald: "#047857"
  shield-emerald-deep: "#065f46"
  shield-emerald-bright: "#10b981"
  shield-emerald-night: "#34d399"
  emerald-brand: "#0e9f6e"
  verified-gold: "#c5a572"
  gold-ink-cream: "#7a5a1f"
  gold-ink-night: "#d8bd8c"
  scam-crimson: "#e11d48"
  scam-ink-cream: "#be123c"
  scam-ink-night: "#fb7185"
  navy-900: "#0b192c"
  navy-950: "#060f1c"
typography:
  figure:
    fontFamily: "Barlow, Segoe UI, system-ui, sans-serif"
    fontSize: "42px"
    fontWeight: 300
    lineHeight: 1
    letterSpacing: "-0.025em"
  headline:
    fontFamily: "Barlow, Segoe UI, system-ui, sans-serif"
    fontSize: "1.125rem"
    fontWeight: 800
    lineHeight: 1.25
  nav:
    fontFamily: "Barlow, Segoe UI, system-ui, sans-serif"
    fontSize: "15px"
    fontWeight: 700
    letterSpacing: "0.02em"
  body:
    fontFamily: "Barlow, Segoe UI, system-ui, sans-serif"
    fontSize: "0.875rem"
    fontWeight: 400
    lineHeight: 1.5
  label:
    fontFamily: "Barlow, Segoe UI, system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 700
    letterSpacing: "0.14em"
  stamp:
    fontFamily: "Barlow, Segoe UI, system-ui, sans-serif"
    fontSize: "11px"
    fontWeight: 800
    lineHeight: 1
    letterSpacing: "0.12em"
  domain:
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace"
    fontSize: "13px"
    fontWeight: 700
  arabic:
    fontFamily: "Noto Kufi Arabic, Segoe UI, Tahoma, Geeza Pro, sans-serif"
rounded:
  stamp: "6px"
  control: "12px"
  inset: "16px"
  tile: "20px"
  pill: "9999px"
spacing:
  tile-gap: "16px"
  tile-pad: "16px"
  tile-pad-roomy: "24px"
  gutter: "16px"
  gutter-wide: "24px"
components:
  tile:
    backgroundColor: "{colors.night-surface}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.tile}"
    padding: "16px"
  button-primary:
    backgroundColor: "{colors.shield-emerald}"
    textColor: "#ffffff"
    rounded: "{rounded.inset}"
    padding: "12px 16px"
  button-primary-hover:
    backgroundColor: "{colors.shield-emerald-deep}"
  button-police-action:
    backgroundColor: "{colors.verified-gold}"
    textColor: "{colors.navy-950}"
    rounded: "{rounded.inset}"
    padding: "12px 16px"
  button-quiet:
    backgroundColor: "{colors.night-canvas}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.inset}"
    padding: "12px 16px"
  pill-strip:
    backgroundColor: "{colors.verified-gold}"
    textColor: "{colors.navy-950}"
    rounded: "{rounded.pill}"
    padding: "6px 12px"
  score-scam:
    backgroundColor: "{colors.scam-crimson}"
    textColor: "#ffffff"
    rounded: "{rounded.pill}"
    padding: "2px 8px"
  input-link:
    backgroundColor: "{colors.night-muted}"
    textColor: "{colors.night-ink}"
    rounded: "{rounded.inset}"
    padding: "12px 14px"
  crest:
    backgroundColor: "{colors.navy-900}"
    textColor: "{colors.verified-gold}"
    rounded: "{rounded.pill}"
    size: "54px"
---

# Design System: SAQR-INTEL

## Overview

**Creative North Star: "Abu Dhabi Night Grid"**

Every scam is a light on the city. Both surfaces, the police Command Center (desktop, projected on stage) and the citizen portal (phone first), stand on the same ground: Abu Dhabi drawn as a dot-matrix city at night, with live data as the only thing that lights it. Crimson pins are interceptions, emerald pins and the emerald glow around the island are verified places and the citizen's own shield. The system refuses the category default of a grey card grid with a chart in every tile; the map is the large tile, and numbers are figures, not charts.

Night Grid is the default theme: a night-navy ground, tiles one step lighter, 1px hairline edges, 20px corners, and nothing glowing. A light version keeps the identical structure on cream paper with navy ink. The theme is chosen before first paint (dark unless the visitor saved "light"), so a first visit never flashes cream. The colour language is fixed like an orienteering map: emerald, gold and crimson each mean one thing on every screen and are never swapped.

State is shown, not implied. When a campaign is blocked, synced to the telecoms or flagged on X, a rotated, bordered stamp lands on the row, so nothing changes silently. The police top bar follows the Abu Dhabi Police website layout, with the SAQR shield standing in the crest slot. Everything is bilingual (English and Arabic, with full RTL) and honours reduced motion.

**Key Characteristics:**
- Dot-matrix Abu Dhabi map as the signature ground, drawn in SVG, no map service.
- Night navy by default; cream light theme with the same structure.
- Flat tiles: surface, 1px hairline, 20px radius. No shadows on tiles, no glow halos, no nested cards.
- Fixed colour meanings: emerald = official / safe / shield on, gold = verified police action, crimson = scam only.
- Large light-weight figures; small tracked capital labels.
- Self-stamping states.
- Barlow (DIN-like, UAE road-sign register) with Noto Kufi Arabic.

## Colors

A night-navy (or cream) neutral field carrying three signal colours whose meanings never move.

### Primary
- **Shield Emerald** (`shield-emerald`, deep `shield-emerald-deep` on hover): the primary action fill (Scan Now, Sync to e& / du), the "shield on" state, verified pins and the live-sync dot. Bright (`shield-emerald-bright`) is for dots and pins; the night tint (`shield-emerald-night`) is for emerald text and icons on the dark ground, with the 600/700 steps on cream.
- **Brand Emerald** (`emerald-brand`): browser surfaces only: selection tint, caret, form accent, and the 2px focus outline.

### Secondary
- **Verified Gold** (`verified-gold`): fills for verified police actions (Broadcast Official Warning, Stage QR), the crest ring, the icon in navy shield badges, and outlined notices such as the demo-data mark. Gold text uses **Gold Ink** (`gold-ink-cream` on cream, `gold-ink-night` on night), never the fill value.

### Tertiary
- **Scam Crimson** (`scam-crimson`): fills only: scam pins, scam score pills (65 and above), the "Spoofed" chip, the active-nav underline in the police bar. Crimson text uses **Scam Ink** (`scam-ink-cream` / `scam-ink-night`), which passes AA on both grounds.

### Neutral
- **Night Canvas / Cream Canvas** (`night-canvas` / `cream-canvas`): page ground, the live strip, inset map wells, quiet buttons.
- **Night Surface / Cream Surface**: every tile, the sticky headers, popovers.
- **Night Muted / Cream Muted**: input wells, selected and hovered rows, segmented-control tracks, neutral score pills (under 30).
- **Night Line / Cream Line**: the 1px hairline on every tile, divider rows, header borders.
- **Night Ink / Cream Ink** and **Ink Soft**: primary text, and secondary text, tile labels, map dots and district names.
- **Navy 900 / 950**: the shield badge and crest backgrounds, and text on gold fills.

The semantic set (canvas, surface, muted, line, ink, ink-soft, scam-ink, gold-ink) is one set of CSS variables that flips under `[data-theme="dark"]`; components use the semantic names, never the raw night or cream hex.

### Named Rules
**The Crimson Means Scam Rule.** Crimson appears only where something is a scam. Scores below 65 are gold (30 to 64) or neutral muted (under 30), never crimson. Fills use Scam Crimson, text uses Scam Ink.

**The Gold Is Police Action Rule.** Gold marks a verified police act or an official notice. It is never decoration and never a warning colour for citizens.

**The One Meaning Rule.** Emerald, gold and crimson are never swapped between surfaces, themes or languages.

## Typography

**Display Font:** Barlow (with Segoe UI, system-ui)
**Body Font:** Barlow (with Segoe UI, system-ui)
**Label/Mono Font:** system monospace for domains, RPZ records and URLs
**Arabic Font:** Noto Kufi Arabic (with Segoe UI, Tahoma, Geeza Pro), applied to the whole page in Arabic and to any `lang="ar"` fragment inside English pages.

**Character:** A DIN-like grotesk in the register of UAE road signs and the Abu Dhabi Police site's capitals, from a whisper-light 300 for figures to a heavy 800 for stamps. Both fonts are self-hosted at build time.

### Hierarchy
- **Figure** (300, 42px, line-height 1, tight tracking, tabular): KPI numbers. The large light figure is the system's way of showing a number; it fades in when the value changes.
- **Headline** (800, 16 to 18px, snug): tile titles on the citizen portal (link checker, shield, alerts).
- **Nav** (700, 15px, uppercase, 0.02em): police top-bar menu items.
- **Body** (400, 14px, relaxed): explanations and registry notes, held to about 68ch.
- **Label** (700, 11px, uppercase, 0.10 to 0.14em): tile headers, KPI labels, map district names, live-strip status.
- **Stamp** (800, 11px, uppercase, 0.12em, line-height 1): state stamps.
- **Domain** (mono 700, 13px): defanged domains in the stream, roster and action center, always `dir="ltr"`.

### Named Rules
**The Figure Not Chart Rule.** Counts are shown as large light figures with one line of context ("+3 this session", the entities impersonated), not as charts.

**The Tracked Caps Label Rule.** Tile and KPI labels are small tracked capitals in Ink Soft; titles never compete with the figures.

## Layout

Police: a sticky two-row header (76px top bar, then the canvas-coloured live strip), then a three-column desk inside a 1500px container: 260px KPI column, flexible centre (map tile above the campaign roster), 380px right column (interception stream above the action center). Below the large breakpoint, KPIs become a two-up grid above a single column and the nav collapses into a menu button. Citizen: sticky header and a sticky tab bar inside a 1280px container; the link checker spans the width with its map panel (340px) beside the form on large screens and as a 128px strip above it on phones; the shield and alerts tiles sit two-up below.

Rhythm: 16px between tiles, 16px tile padding (24px on the roomy citizen link checker), 16px page gutter on phones and 24px from the small breakpoint. On phones the tab bar fades its trailing edge (mirrored in RTL) to show it scrolls. All direction-sensitive spacing uses logical properties (start / end) so RTL mirrors without extra rules.

## Elevation & Depth

Flat by design. Depth comes from tonal steps (canvas, then surface one step lighter, then muted for wells and selection) and the 1px hairline, not from shadows. Sticky headers use a translucent surface with backdrop blur. Shadows are reserved for things that float above the page.

### Shadow Vocabulary
- **Popover** (`box-shadow: 0 18px 40px -16px rgba(0,0,0,0.5)`): the police settings popover only.
- **Map pin rings** (no blur): scam pins carry two concentric translucent crimson rings (6px at 22%, 14px at 9%); verified pins one emerald ring. These are flat rings, not glows.

### Named Rules
**The No Halo Rule.** Tiles never glow and never cast shadows. A tile is surface plus a 1px hairline.

## Shapes

Generous, consistent corners: 20px on every tile, 16px on inset elements inside a tile (map wells, action buttons, input wells), 12px on icon badges and small rows, full pills for chips, score badges and strip buttons, and a tight 6px on stamps. Circles are reserved for the crest, pins and status dots. Stamps are the one deliberately skewed shape: rotated -3 degrees with a 2px border in their own text colour.

## Components

### Buttons
- **Shape:** gently rounded (16px) blocks for action buttons, full pills for compact strip actions.
- **Primary:** Shield Emerald fill, white 700 text, 12px by 16px; hover steps to the deep emerald.
- **Police action:** Verified Gold fill with Navy 950 text, same shape; hover brightens slightly. Used only for verified police acts.
- **Quiet:** canvas fill, hairline border, ink text; hover to muted (Export dossier, Citizen Portal).
- **Press:** primary actions squeeze to 0.97 for 120ms on press (`cubic-bezier(0.16, 1, 0.3, 1)`).
- **Focus:** a 2px Brand Emerald outline at 2px offset on every focusable element.
- **Done state:** a completed action keeps its button and stamps itself (SYNCED, BROADCAST) inside it.

### Chips
- **Score pill:** full pill, 12px bold tabular number; crimson fill at 65 and above, gold fill 30 to 64, muted below.
- **Legend and status dots:** 8 to 10px circles in the signal colours beside an Ink Soft label.
- **Demo-data mark:** gold-ink text in a 60% gold outline with 6px corners, always present while data is seeded.

### Cards / Containers
- **Corner Style:** 20px.
- **Background:** Surface.
- **Shadow Strategy:** none (see Elevation).
- **Border:** 1px Line.
- **Internal Padding:** 16px, 24px for the citizen link checker.
- **Header:** icon plus tracked-caps label in Ink Soft, with an optional count or legend at the end edge.

### Inputs / Fields
- **Style:** Muted well, 16px radius, 1px Line ring, 15px text, always LTR for URLs.
- **Focus:** the ring thickens to 2px emerald.
- **Search (police):** a canvas pill that expands from the search icon to 200px.

### Navigation
- **Police top bar:** Abu Dhabi Police site layout. Settings and search icon buttons (40px circles), a language link, uppercase 15px menu items with a 4px Scam Crimson underline under the active one (spring-animated between items), and the bilingual wordmark "شرطة أبوظبي / ABU DHABI POLICE" at the reading-end edge beside the crest: a navy circle with a 3px gold ring holding the SAQR shield. A menu button replaces the nav below the large breakpoint.
- **Live strip:** canvas band with the live-sync dot and status in tracked caps, the demo-data mark, then Citizen Portal, Stage QR and the theme toggle at the end edge.
- **Citizen tabs:** icon plus label, Ink Soft at rest, Ink when selected with an emerald icon and a 3px ink underline that slides between tabs.

### Stamp (signature)
Rotated (-3deg) bordered capitals marking a state on the row it belongs to: emerald for SYNCED TO e& / du, gold ink for FLAGGED ON X, scam ink for blocked or active. 2px border in the current colour, 6px corners, 11px 800 uppercase with 0.12em tracking.

### City Grid Map (signature)
Abu Dhabi (Corniche to Yas, Saadiyat to Mussafah) as a 64-column dot matrix in SVG, kept at the city's true aspect ratio so dots stay round and pins land exactly. Land dots are larger and brighter than sea dots, both in Ink Soft at low opacity. Six bilingual district names sit on the map in tracked caps. On the police desk it is interactive: crimson spoofed pins and emerald verified pins open a registry card below the map. On the citizen portal it is a decorative backdrop with the island lit emerald and a caption "Your shield · Abu Dhabi island". Inside its tile the map sits in its own inset canvas well (16px radius, hairline); this inner frame is the one intentional exception to the no-nesting rule, because it frames a canvas, not a card.

### KPI Tile
Tile with icon and tracked-caps label (full label on wide screens, a short one on phones), a Figure, and one truncated context line. The label icon carries the signal colour of what is counted.

## Do's and Don'ts

### Do:
- **Do** build every tile as Surface + 1px Line + 20px radius + 16px padding.
- **Do** fill with `--color-scam` and write crimson text with `--color-scam-ink`; write gold text with `--color-gold-ink`.
- **Do** use the semantic theme variables (canvas, surface, muted, line, ink, ink-soft) so both themes come from one structure.
- **Do** stamp a state onto the row or button it changed, with the rotated bordered caps stamp.
- **Do** show counts as large light figures with one line of context.
- **Do** use logical (start / end) spacing and keep domains and URLs `dir="ltr"` inside Arabic pages.
- **Do** wrap animated surfaces in `MotionConfig reducedMotion="user"`; reduced motion keeps fades and drops travel.
- **Do** keep the demo-data mark visible whenever the desk shows seeded data.

### Don't:
- **Don't** use crimson for anything that is not a scam: not for errors, warnings, low scores or decoration.
- **Don't** use gold except for verified police action and official notices.
- **Don't** add glow halos, drop shadows or blur glows to tiles.
- **Don't** nest a card inside a tile; the police map's inset canvas well is the only framed element inside a tile.
- **Don't** reproduce the official Abu Dhabi Police emblem; the crest slot holds the SAQR shield.
- **Don't** put a chart in every tile; the map and figures carry the data.
- **Don't** let a state change silently; nothing disappears without a stamp or a message.
