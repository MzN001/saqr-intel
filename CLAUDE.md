# SAQR-INTEL — project notes for Claude

Abu Dhabi Police Hackathon project: autonomous anti-fraud & cybercrime intelligence system.
Owner is new to coding and runs this on Windows (Python + VS Code + Node.js). Explain steps simply.

## Layout
- `main.py` + `saqr/` — FastAPI backend on **port 8000** (Python 3.11+, aiosqlite, Playwright, rapidfuzz, dnspython, python-whois, google-genai/openai).
  - `saqr/intel/` — domain_intel (lookalike/homoglyph/WHOIS/DNS/TLS), sandbox (Playwright anti-cloaking), ai_inspector (rules engine + Gemini/OpenAI, rules are a floor), maps_sentinel, graph_engine (syndicate clustering), takedown, awareness, ct_monitor, registry (official UAE entities).
  - `saqr/seed_data.py` — fictitious demo syndicates (Sand Viper, Desert Mirage), replica scam pages, `MOCK_SCAM_SLUGS` (`/mock-scam/<slug>` on localhost resolves to a seeded scam domain).
  - `saqr/static/index.html` — simple built-in demo console at `http://localhost:8000/`.
  - `tests/test_api.py` — run `pytest -q` (16 tests, offline).
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

## Possible next steps discussed
- Police Command Center dashboard (live WebSocket `/ws/live`, syndicate graph from `/api/syndicate-graph`).
- A "Check a Maps listing" form; Google Places API key (`GOOGLE_MAPS_API_KEY`) for real listing lookups.
