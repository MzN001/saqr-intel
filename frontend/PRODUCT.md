# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **Citizens** — residents of Abu Dhabi, mostly on their phones, who received a suspicious link by SMS, WhatsApp or email, met a doubtful Google Maps listing, or want their phone protected in the background. Job: find out in seconds whether something is a scam, and switch on the phone shield once.
- **Abu Dhabi Police officers** — the Cyber-Patrol desk, on desktop screens, watching live citizen interceptions and acting on them: block a domain for e& / du subscribers, broadcast an official warning to citizens, export a takedown dossier. Hackathon judges evaluate this view during the demo.

## Product Purpose

Saqr ("صقر", formerly SAQR-INTEL) is an anti-fraud shield for Abu Dhabi. The citizen portal (`/citizen`) checks links, SMS, emails and Maps pins and sets up a phone-wide DNS shield that blocks scam sites in every app; the police Command Center (`/police`) sees every interception live, clusters them into campaigns and lets officers act in one click. Success: a citizen never enters card, OTP or UAE PASS details on a fake site, and police see and stop a campaign while it is still spreading.

## Positioning

Two-way and live: what a citizen intercepts appears on the police desk within seconds, and what an officer does (telecom block, official warning) reaches citizens' pages and phones immediately. Detection combines a trained URL classifier, global phishing feeds, a UAE official-entity registry and an AI judge, and works without installing an app (DNS shield + browser extension).

## Operating Context

- Citizens: phone browsers (Safari on iPhone, Chrome on Android), often right after receiving a message; Home Screen web app for scam-alert notifications.
- Officers: desktop browser in a command-center setting; also projected on stage during the hackathon demo, with judges scanning a QR to try `/citizen` on their own phones.
- Backend on Render (FastAPI), site on Vercel (Next.js 16).

## Capabilities and Constraints

- Bilingual English / Arabic with full right-to-left layout on both pages.
- `/citizen`: one page with five windows (`?view=check|maps|sms|email|live`: Link checker, Search & Maps, SMS, Email, Live shield); inline verdict card for checks the resident starts, full-screen block page when they were about to open a scam (share target, `?alert=` links, Search & Maps and demo-SMS taps); phone DNS shield and scam-alert setup in slide-over drawers (Android / iPhone, with setup videos); X warning composer; official police warning banner. No link to `/police`.
- `/police`: live KPIs, interception stream, campaigns, Abu Dhabi geo-spoof map, 1-click action center, takedown dossier (JSON / PDF).
- Numbers shown on `/police` before real traffic are labeled demo data and reset when the backend restarts.

## Brand Commitments

- Name: **Saqr** / صقر (product name "Saqr — Abu Dhabi Anti-Scam Shield"; formerly SAQR-INTEL); Abu Dhabi Police context (Aman 8002626, SMS 2828). Saqr is not an official police brand: never use a police emblem.
- Identity: the faceted Saqr falcon + Gloock serif wordmark, obsidian ink on warm ivory (see `DESIGN.md`). Verdict colours carry one meaning each: emerald = safe / verified, amber = suspicious, crimson = scam.
- Theme: **light by default** (ivory canvas), dark version behind the toggle; a saved choice is kept.
- `/police` keeps the legacy Night Grid look (navy, emerald, gold; dark by default) until the owner supplies its new format.
- Visual references supplied by the owner: the Saqr logo and citizen wireframe in `design-refs/` (2026-11-24); earlier, a dark "bento" dashboard (Pinterest "Farider"), inspiration only.

## Evidence on Hand

- Real detection results from the live backend; seeded demo syndicates and campaigns (fictitious, labeled as such).
- No real citizen testimonials, crime statistics or partnership claims: the e& / du integration is a proposal; do not present it as live.

## Product Principles

1. Seconds matter: the verdict and the primary action are visible before anything else.
2. Danger is unmistakable, safety is calm: crimson only means scam.
3. Both languages are first-class; Arabic is never a mirrored afterthought.
4. Show the system working (live data, real verdicts), never decorative claims.
5. Officers act, they don't hunt: every insight sits next to the action it enables.

## Accessibility & Inclusion

WCAG AA contrast in both themes and both languages; reduced-motion support; usable one-handed on phones; keyboard-operable police desk.
