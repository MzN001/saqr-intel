# SAQR-INTEL — project notes for Claude

Abu Dhabi Police Hackathon project: autonomous anti-fraud & cybercrime intelligence system.
Owner is new to coding and runs this on Windows (Python + VS Code + Node.js). Explain steps simply.

## Layout
- `main.py` + `saqr/` — FastAPI backend on **port 8000** (Python 3.11+, aiosqlite, Playwright, rapidfuzz, dnspython, python-whois, google-genai/openai).
  - `saqr/intel/` — domain_intel (lookalike/homoglyph/WHOIS/DNS/TLS), sandbox (Playwright anti-cloaking), ai_inspector (rules engine + Gemini/OpenAI, rules are a floor), maps_sentinel, graph_engine (syndicate clustering), takedown, awareness, ct_monitor, registry (official UAE entities).
  - `saqr/seed_data.py` — fictitious demo syndicates (Sand Viper, Desert Mirage), replica scam pages, `MOCK_SCAM_SLUGS` (`/mock-scam/<slug>` on localhost resolves to a seeded scam domain).
  - `saqr/static/index.html` — simple built-in demo console at `http://localhost:8000/`.
  - `tests/` — run `pytest -q` (whole suite offline, ~600 tests; `tests/test_api.py` = core API).
- `frontend/` — Next.js 16 App Router + TS + Tailwind v4 + framer-motion + lucide-react, **port 3000**, main page `/citizen`.
  - `next.config.mjs` proxies `/api/*` to the backend; Tailwind needs the `turbopack.rules` entry there.
  - `src/components/` — CitizenShell (tabs + scan runner), SearchMapsShield, SmsGuard, AwarenessRadar, VerdictScreen (full-screen block page), Chrome (header/banner/phone frame).
  - `src/lib/` — api.ts, i18n.tsx (EN/AR + RTL), url.ts, useHydrated.ts, theme.tsx (light/dark).
  - Dark mode: `<html data-theme="dark">`, saved in localStorage `saqr-theme`. Use the semantic colours in `globals.css` (`bg-surface`, `bg-canvas`, `bg-muted`, `text-ink`, `text-ink-soft`, `border-line`) for app UI; the fake Google/SMS phone screens use explicit `dark:` classes. Toggle = `ThemeToggle.tsx` (Lottie `src/assets/moon-to-sun.json` via `lottie-web` light build); page-wide circle reveal uses the View Transitions API.
  - `src/app/manifest.ts` — PWA with Android `share_target` → `/citizen?url=&text=`.
  - Owner asked: NO `/police` page in the frontend (police side = backend console at :8000).
  - LinkChecker (scan bar, `CITIZEN_MANUAL_CHECK`), ShareQrButton (qrcode.react), XAlertComposer (permission prompt + X intent preview + Aman 2828 copy; prompt shows when verdict != SAFE and score >= 60; domains defanged with `[.]`), LiveCrowdShield (Tab 3, `/ws/live` via the `/ws` rewrite in next.config, falls back to :8000 on http). Shared helpers in `src/lib/share.ts`.
  - Backend `uvicorn` runs without `--reload`: restart it after Python changes (e.g. a new `Interception` value) or requests 422.
  - Next 16 differs from older versions: check `frontend/node_modules/next/dist/docs/` before changing Next APIs.

- `extension/` — Chrome/Edge MV3 extension "SAQR-INTEL | Citizen Web & Maps Scam Shield" (see `extension/README.md`).
  - `background.js`: onBeforeNavigate → fast scan (`run_sandbox:false`), deep scan only if score ≥ 30; blocks when HIGH-RISK or ≥ 70 by redirecting to `blocked.html?mode=block&d=<json>`; per-site cache in `chrome.storage.session`; channel `PC_BROWSER_EXTENSION`.
  - Skips: port 3000 app, x.com, official UAE domains, private IPs, backend host except `/mock-scam/`, session allow-list ("continue anyway").
  - Icons from `python extension/generate_icons.py` (stdlib only). No build step; load unpacked.

- Telecom feed: `GET /api/dns-blocklist` (JSON) / `?format=rpz` (zone file, `domain CNAME .` + wildcard). Sources: non-SAFE scans, seeded syndicate intel, CT detections; never publishes whitelisted/trusted domains (`saqr/routers/blocklist.py`). With `CT_MODE=simulated` most entries are synthetic CT names.
- Phone DNS shield: `GET /api/ios-dns-profile` (.mobileconfig, DoH host allow-listed) and `/api/android-dns-config` (`saqr/routers/mobile.py`); UI in `BackgroundShieldCard.tsx`.
- `interception_channel` defaults to `DIRECT_API` on both scan endpoints.
- Real phone protection (verified on the owner's iPhone): `saqr/intel/nextdns_sync.py` pushes blocklist domains (score ≥ NEXTDNS_MIN_SCORE, not CT-only) to the NextDNS denylist every 60 s and right after any high-risk scan; status at `/api/nextdns-status` (never returns the key). Needs NEXTDNS_PROFILE_ID + NEXTDNS_API_KEY in `.env`; restart backend after editing `.env`.
  - `saqr/self_hosts.py`: hostnames the API/WS is reached through (e.g. the Vercel tunnel) are never published and are deleted from NextDNS if present — otherwise phones block SAQR itself.
  - `start-phone-demo.ps1`: fresh tunnel serving `/mock-scam/tamm-fine` on a new public host → live scan (HIGH-RISK 70 via page content) → synced → link opens on laptop, blocked on a shielded phone ("Safari can't open the page").
  - Laptop-free phone demo: `demo-scam-site/` = the fake TAMM page as its own Vercel project, https://saqr-demo-scam.vercel.app and https://aed-refund-claim.vercel.app (both in `settings.demo_scam_domains`, always flagged + re-scanned on start; Render's own `/mock-scam/` links can never be DNS-blocked: they share SAQR's host). Already flagged (HIGH-RISK 70) and in NextDNS since 2026-11-23. `blocklist.SHARED_HOSTING_ROOTS` stops a whole platform (vercel.app, onrender.com…) from ever being published.
  - `tests/conftest.py` blanks real API keys so tests never touch live accounts.
- Scam-alert push (verified on the owner's iPhone): `saqr/push.py` + `saqr/routers/push.py` (VAPID key auto-generated in `data/vapid_private.pem`, gitignored); `BlockWatcher` in `nextdns_sync.py` polls NextDNS logs (logging must be ON in the profile) and alerts subscribed phones only for SAQR-flagged domains; `public/sw.js` shows the notification and opens `/citizen?alert=<domain>` → `/api/alerts/verdict`. UI: `ScamAlertsCard.tsx`. iPhone needs the site added to the Home Screen (iOS 16.4+).

- LIVE: backend on Render at https://saqr-intel-api.onrender.com (Blueprint `saqr-intel`, service `saqr-intel-api`, auto-deploys from GitHub main); Vercel `NEXT_PUBLIC_API_URL` (saved for Production + Preview) points there; `deploy-vercel.ps1` is laptop-fallback only. Removing Vercel env vars via CLI needs `--confirm-name` after the user approves. Don't run the laptop backend with the same NextDNS keys at the same time (double sync / double alerts / NextDNS rate limits).
- Cloud / Render free tier: `render.yaml` (repo root = backend). `ENABLE_PLAYWRIGHT=false` → no Chromium, pages fetched with httpx (`sandbox._from_http_only`, realistic UA), screenshots None, ~110 MB RAM. `requirements.txt` = runtime only (no Playwright/pytest); laptop uses `requirements-dev.txt`. `/mock-scam/<slug>` on loopback, `*.onrender.com` or any self host is resolved in memory (no self-request deadlock on one worker) and skips the LLM. Render disk is ephemeral: set `VAPID_PRIVATE_KEY` (PEM, `\n`-escaped) so push subscriptions survive restarts.

## Run
- One click: `start-windows.bat` (backend in a second window, frontend on 3000).
- Manually: `.venv\Scripts\activate` → `uvicorn main:app --port 8000`; then `cd frontend` → `npm run dev`.
- Gemini key goes in `.env` (`GEMINI_API_KEY=`); never print or commit it. Without keys the rules engine is used.

## Gotchas learned
- Short brand names (du, fab, tamm, adcb) must match as whole tokens to avoid false positives (dubai, fabric, tammy).
- Scoring (`ai_inspector.run_rules`): weak page signals (CLOAKING, BRAND_CONTENT, URGENCY, EXFIL_FORM, password/UAE PASS/Emirates ID fields) score 0 unless a strong signal exists (lookalike domain, new domain/cert, syndicate, or OTP/card/CVV/PIN fields). Real sites show weak signals all the time. Regression cases: `tests/test_false_positives.py`.
- Cloaking = bot sees a different page AND the real visitor gets a sensitive form; JS-built pages and 403s to bots are normal. Field patterns in `sandbox.py` are kept specific ("One time" donation radio, "الرمز" plate code, DD/MM/YYYY were false OTP/expiry hits).
- Trusted non-brand UAE sites live in `registry.TRUSTED_UAE_DOMAINS` (or `EXTRA_WHITELIST_DOMAINS` in `.env`).
- Scam links in the frontend only get an `href` after hydration so an early tap can't open the replica page.
- When restarting `next start`, kill `next-server` too or a stale build serves 500s for JS chunks.
- `next dev` (Turbopack) sometimes keeps serving an old `globals.css` after an edit; restart `npm run dev` if new CSS rules don't appear.
- Phone numbers / branch coordinates in `registry.py` are demo data; `185.220.101.44` in seed data is real IP space.

## Detection upgrade (2026-11-23) — any fraud site, not only UAE brands
- `registry.GLOBAL_BRANDS` (~50 most-phished brands: PayPal, Microsoft, Apple, banks, couriers, crypto…) + `ALL_BRANDS`. Global brands match whole tokens only; `common_keywords` (apple, chase, amazon, noon, wise) need a lure word; no TLD_SWAP for them (they own many ccTLDs); typosquat only for labels ≥7 chars at ≥88%. Maps/CT/awareness still use the UAE `ENTITIES`.
- `intel/url_model.py` + `url_model.bin` (1 MB): logistic regression on hashed char n-grams of the HOSTNAME only, pure Python at runtime. Retrain: `tools/train_url_model.py` (needs scikit-learn; data: PhiUSIIL, Phishing Army, Tranco). PhiUSIIL legit URLs are all bare homepages → never train on paths. Never judges Tranco top-100k sites (`intel/data/popular_domains.txt.gz`) unless on free hosting. Flags: ≥0.98 AI_PHISHING_URL 65 (45 on free hosting), ≥0.92 45, ≥0.80 AI_SUSPICIOUS_URL 20; AI_PHISHING_URL + any `ML_CORROBORATION` clue → 70.
- `intel/threat_feeds.py`: Phishing Army + OpenPhish, refreshed every 6 h, in memory; never lists platforms/official/top-10k sites. Hit = KNOWN_PHISHING_FEED 70. `THREAT_FEEDS=false` disables.
- LLM: `GEMINI_MODEL` is a comma list tried in order with a circuit breaker (busy 30 s, quota 10 min, retired 24 h). gemini-2.5-flash was retired for this key in Nov 2026 and the AI judge had been silently failing — `/health` now shows `llm.last_ok/last_error`. `ai_inspector.blend`: confident LLM scam verdict + corroboration → 0.25 rules + 0.75 LLM; confident SAFE halves a classifier-only warning; hard evidence is never lowered.
- Live evaluation (300 OpenPhish phishing vs 340 legit incl. login/bank pages and Tranco long tail), no LLM, no feeds: before 0% HIGH-RISK / 4% any warning; after: see commit message. 0 false alarms. Harness kept outside the repo (scratch `saqr-eval/`).

## Email scanning (2026-11-23, branch feature/email-scanning)
- Backend: `saqr/email_pipeline.py` + `saqr/intel/`: `email_types.py` (shared dataclasses), `email_parse.py` (.eml, .msg via olefile, pasted text, pasted raw source), `email_auth.py` (SPF pyspf, DKIM dkimpy, DMARC, ARC; Authentication-Results believed only from trusted hosts: Gmail/Outlook/Yahoo/iCloud/Zoho/Proton + `EMAIL_TRUSTED_AUTHSERV`), `email_unicode.py` (look-alike letters, bidi, invisible chars), `email_rules.py` (flags + score), `campaigns.py` (+ `data/campaigns_seed.json`: 37 seed campaigns, live RSS every 6 h), `user_model.py` (personal "email-v1" naive Bayes), `user_llm.py` (citizen's own OpenAI-compatible AI: SSRF-guarded, key never stored/logged/echoed).
- Endpoints: `POST /api/analyze-email` (JSON only, files as base64, 4 MB cap, own rate bucket), `GET /api/campaigns` (ETag → 304), `/api/email-model/label` + `GET|PUT|DELETE /api/email-model/{reporter_id}` (reporter_id = random id kept in the browser). WS: `email_scan.completed` / `email_scan.failed`. `/health` → `campaigns`.
- Scoring = same principle as websites: WEAK flags (SPF/DKIM fail, urgency, "sign in", brand mention…) count only when a STRONG flag exists (look-alike letters, scam link, brand from Gmail, .exe, campaign IOC, DMARC fail with reject/quarantine, OFFICIAL_SENDER_UNAUTHENTICATED). Authenticated official / top-10k sender with no link/Unicode/attachment/IOC evidence is capped at 20.
- Privacy: email scans are saved with `domain = NULL` (the blocklist publishes `scans.domain` of non-SAFE scans → `gmail.com` would get DNS-blocked), only a 500-char `body_excerpt`, no raw source, nothing from `llm`. Links (max 5 hosts; official, top-10k and ESP click trackers skipped) are scanned as normal URL scans, so scam links still reach the blocklist / NextDNS.
- Extension Email Shield: `content/common.js` + `gmail.js` (fetches the original message → real SPF/DKIM/DMARC) + `outlook.js` (page text only, headers not verified) + `wip.js` pill (Yahoo/Proton/iCloud/AOL/Zoho). `lib/` (features, model, campaign match) is loaded by the content scripts, `importScripts` in `background.js` and the node tests; `lib/config.js` is the ONE place for the API / web-app addresses. Content scripts may only send the `CONTENT_TYPES` messages; settings / model import / reset only from extension pages. Options page: auto-scan, Spam-folder learning, own AI, personal model export/import/erase.
- Web app: Email tab (`EmailGuard.tsx`, `api.ts analyzeEmail`): paste text or "Show original" source, or upload .eml/.msg.
- Env: `CAMPAIGN_FEEDS`, `CAMPAIGN_REFRESH_HOURS`, `EMAIL_RATE_LIMIT_PER_MINUTE` (default = `RATE_LIMIT_PER_MINUTE`), `EMAIL_TRUSTED_AUTHSERV`, `USER_LLM_ALLOW_PRIVATE` (laptop only, e.g. Ollama; never on Render). All in `saqr/config.py`.
- Deps: `dkimpy`, `pyspf`, `olefile` in requirements.txt (imported only when used, app stays light); `authres` is test-only (requirements-dev.txt).
- Tests: `pytest -q` (Linux: `.venv/bin/python -m pytest -q`; the venv is `.venv/bin/` on Linux, `.venv\Scripts\` on Windows) · `node --test extension/tests/*.test.js` · `node --test extension/tests/content/*.test.cjs` · `cd frontend && npm run lint && npx tsc --noEmit && npm run build`. Fixtures: `tests/fixtures/emails/`, `tests/fixtures/contract/`.
- Gotchas learned:
  - Every flag code `email_rules` can emit needs reason text in `extension/blocked.js` REASONS and `frontend/src/lib/share.ts` REASON_BY_FLAG; `tests/test_email_interop.py` fails otherwise.
  - Python/JS twins must stay identical: `campaigns.py` ↔ `lib/campaign_match.js`, `user_model.py` ↔ `lib/email_features.js` + `lib/user_model.js` (shared vectors `tests/fixtures/campaign_vectors.json`, `model_vectors.json`). Server model import is strict, JS is looser; export → import is tested both ways.
  - Only an uploaded .eml/.msg is byte-exact (DKIM verified); pasted raw source uses trusted Authentication-Results. The extension sends a cut original (`truncated`) as raw text, never as an .eml file (DKIM would fail on the missing part).
  - Short global brands (DHL, UPS) are not matched in a display name (`_entity_in_text` skips names under 4 letters), so "DHL Express <x@gmail.com>" needs another strong flag (e.g. its link). Known gap.
  - 6 seed campaigns are SMS/phone-only and never match emails (on purpose). Live RSS sources mostly carry general security news, so "live" campaigns are often 0; the seed list + SAQR's own detection waves do the matching.
  - FastAPI 0.165: `app.routes` holds `_IncludedRouter` objects; list paths with `app.openapi()["paths"]`.
  - ARC: anyone can make a VALID seal. `AuthARC.trusted` (internal, not in `to_dict`) = the provider's own A-R says arc=pass, or the newest seal's d= is a trusted provider (`TRUSTED_ARC_SEALERS`). Only a trusted pass suppresses weak flags; it never hides a DMARC fail the trusted provider itself reported, and never exempts OFFICIAL_SENDER_UNAUTHENTICATED otherwise.
  - SPF runs in its own daemon thread with a hard deadline (`email_auth.spf_deadline_s()`, 1.5 × DNS_TIMEOUT_SECONDS, 1–6 s): pyspf ignores its own timeout. Timeout = `temperror`; permerror/temperror never show SPF_FAIL.
  - OFFICIAL_SENDER_UNAUTHENTICATED needs a delivered copy (≥1 Received header); a draft/template source gets the info note HEADERS_NOT_AVAILABLE. Test helpers that build ParsedEmail by hand must add a Received header to mean "delivered".
  - Styled letters (math bold, small caps, full-width) that spell a brand name/alias/keyword (≥4 letters; 3-letter ones only in capitals; never common words like apple/amazon/google) → DISPLAY_NAME_CONFUSABLE 65 (`email_rules.styled_brand`). Other styled text stays FANCY_UNICODE (weak).
  - Common-word brands (Amazon, Apple, Google, Chase, Wise, noon, Steam, Ledger, DEWA) count in a display name only next to a role word (`ROLE_WORDS`: support, team, recruitment, id, ...): "Amazon Recruitment Team" yes, "Chase Smith" no. A brand in the SUBJECT is a claim only when it reads like a notice (`SUBJECT_NOTICE_RE` or "Brand:" prefix), not "DHL vs Aramex prices?".
  - Registry: `emiratesrc.ae` (Red Crescent) is trusted; `epg.gov.ae` is Emirates Post's via `registry.ENTITY_EXTRA_DOMAINS` (official, not a look-alike target: a 3-letter label would make typo noise); DEWA is a global brand with "dewa" as a common keyword (also a Balinese name). Verify a domain on the web before adding it.
  - Link sub-scans use `email_pipeline._scan_target`: a percent-encoded host is replaced by its punycode so the real domain reaches the blocklist.

## Possible next steps discussed
- Police Command Center dashboard (live WebSocket `/ws/live`, syndicate graph from `/api/syndicate-graph`).
- A "Check a Maps listing" form; Google Places API key (`GOOGLE_MAPS_API_KEY`) for real listing lookups.
