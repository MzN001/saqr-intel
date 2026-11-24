# SAQR-INTEL: ScamShield for Abu Dhabi

**Live:** citizen app https://saqr-intel.vercel.app/citizen · police command center https://saqr-intel.vercel.app/police (officer passcode) ·
API https://saqr-intel-api.onrender.com (`/docs`, `/health`) · 5-minute demo script: [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md)

## 1. Problem and solution

Scam links reach UAE residents through SMS, WhatsApp, email, search ads and fake Google Maps listings. They
imitate TAMM, Abu Dhabi Police, UAE PASS, Emirates Post, e&, du and the banks, are registered hours before
the campaign starts, hide behind URL shorteners and redirect chains, and show a harmless page to scanners
(cloaking). By the time a victim reports one, the money is gone.

SAQR-INTEL checks a link **before the citizen opens it** and explains the verdict in English and Arabic. Every
check runs the same pipeline: follow redirects to the real destination, look-alike rules for the official UAE
entities and ~50 global brands, a trained URL model, global phishing feeds, WHOIS / DNS / TLS age, a page check
that compares what a bot and a phone see, and an optional LLM judge. A **Proactive Hunter** finds look-alike
domains that nobody has reported yet. Confirmed scams flow to a DNS blocklist (phones with the SAQR DNS profile
stop opening them), to the police command center with an evidence dossier, and to registrar / hosting abuse
notices.

## 2. Judging criteria → where to see it

| Criterion | What SAQR does | Where in the demo |
|---|---|---|
| **Detection accuracy (30)** | Rules + URL model + feeds + network + page evidence; weak page signals score 0 without a strong signal (fewer false alarms on real bank / gov sites); redirect / shortener resolver; bot-vs-phone cloaking check | `/citizen` scan bar ("Test Fake TAMM Fine"); `tools/evaluate.py` and `tools/predict.py` (section 5); `/police` model card (`GET /api/model/metrics`) |
| **Early detection & coverage (25)** | Proactive Hunter (look-alike DNS sweep, newly registered domains, certificate search); pre-click badges on Google / Bing results, sponsored ads and Maps cards; phone DNS shield; email, SMS text, Maps listing and phone-number checks | `/police` "Proactive Hunt" card, "Threats Caught Pre-Victim" KPI, "Run sweep now"; `/citizen` Search & Maps tab; browser extension on google.com / bing.com / Maps |
| **Explainability & actionability (20)** | Every flag carries an EN + AR reason and its points; the URL model returns its top feature reasons; one-click takedown dossier with WHOIS, hosting, TLS, redirect chain, SHA-256 evidence hashes and ready-to-send abuse notices; evidence pack (.zip) | Verdict screen on `/citizen`; extension block page; `/police` evidence dossier + "Export Official Takedown Dossier" |
| **UAE relevance & innovation (15)** | UAE entity registry (Arabic names, aliases, official domains); Arabic field patterns (رمز التحقق, رقم الهوية ...); sandbox as a UAE phone (`ar-AE`, Asia/Dubai, Abu Dhabi location); bilingual RTL UI; police warning broadcast to citizens; X warning composer; RPZ feed format for telecom DNS | `/citizen` in العربية; `/police` "Broadcast Official Warning"; `GET /api/dns-blocklist?format=rpz` |
| **Feasibility (10)** | Pure-Python runtime on a 512 MB free Render instance (no numpy / sklearn / browser in the cloud); Next.js on Vercel; extension needs no build; offline test suite | `render.yaml`, `requirements.txt`, section 8 |

## 3. Architecture

```
 Citizen PWA (/citizen)   Browser extension (MV3)        Phone DNS shield (NextDNS profile)
 paste/share link, SMS,   every navigation, Gmail /      blocks published domains in every app
 email, Maps listing      Outlook, search + Maps badges          ^
          \                    |                                 |
           v                   v                                 |
   FastAPI  POST /api/analyze-url · /api/batch-verdict · /api/analyze-email · /api/analyze-message
            · /api/scan-maps · /api/check-phone
   pipeline.analyze_url:
     1 redirect resolver (30x, meta refresh, JS stubs, ?url= wrappers, 100+ shorteners; SSRF guard per hop)
     2 look-alike rules (typosquat, homoglyph / punycode, TLD swap, brand + lure words)
     3 URL model (pure-Python inference)        4 threat feeds (Phishing Army, OpenPhish)
     5 WHOIS / DNS / TLS (domain + cert age, registrar, ASN), known syndicate infrastructure
     6 page sandbox: Playwright as a UAE phone, or two-view HTTP fetch in the cloud; cloaking + form fields
     7 LLM judge (Gemini / OpenAI, optional; page text passed as untrusted <evidence>)
     -> score 0-100, verdict SAFE < 30 <= SUSPICIOUS < 65 <= HIGH-RISK SCAM, EN + AR reasons
          |                        |                               |
          v                        v                               v
   DNS blocklist (JSON / RPZ)   syndicate graph + WS /ws/live    /police command center, dossier,
   -> NextDNS denylist          (union-find clustering)          abuse notices, push alerts
          ^
   Proactive Hunter (look-alike sweep, newly-registered domains, crt.sh, CT monitor)
   -> offline triage -> the same pipeline (channel PROACTIVE_HUNTER)
```

Code: `main.py`, `saqr/pipeline.py`, `saqr/intel/` (one module per stage), `saqr/routers/` (HTTP API),
`frontend/` (Next.js 16), `extension/` (Chrome / Edge). SQLite via aiosqlite.

## 4. Detection before the victim interacts

- **Proactive Hunter** (`saqr/intel/hunter.py`, `lookalike_gen.py`; `GET /api/hunter/detections`, `/status`,
  `POST /api/hunter/sweep`). Sources: `lookalike_sweep` (deterministic typo / homoglyph / hyphen / TLD-swap /
  brand + lure names of the 8 official UAE entities, resolved in DNS: registered ones are leads),
  `nrd` (the free daily newly-registered-domains list from whoisds.com, filtered by brand keywords),
  `crtsh` (new certificates naming a UAE brand), `ct` (the certificate-transparency monitor). Each lead gets an
  offline triage (rules + URL model); registered look-alikes from the sweep and other leads scoring 35+
  get the full scan. Lead time and later citizen visits are
  computed per detection, so "caught before any citizen saw it" is measured, not claimed. LLM is off for the hunt.
- **Pre-click shield** (`POST /api/batch-verdict`, up to 200 links, offline evidence only, nothing saved;
  `POST /api/check-phone`). The extension badges organic results, sponsored ads (ad wrapper resolved to the
  advertiser), knowledge-panel and Maps "Website" buttons, and helpline numbers that are not the official ones.
- **Phone DNS shield**: `/api/ios-dns-profile`, `/api/android-dns-config`; high-risk domains are pushed to a
  NextDNS denylist every 60 s and right after a high-risk scan; blocked visits can trigger a Web Push alert.
- **Browser navigation**: the extension checks every page on navigation (fast check, deep scan only when
  suspicious) and replaces scams with a block page.
- **Telecom feed**: `GET /api/dns-blocklist` (JSON) and `?format=rpz` (zone file). Official, trusted and
  shared-hosting domains (vercel.app, onrender.com ...) are never published.

## 5. The AI model, data and bring-your-own-dataset

- **Model** (`saqr/intel/url_model.py`, `url_features.py`): stage 1 is logistic regression over hashed character
  n-grams and tokens of host, path and query; stage 2 is gradient-boosted trees over ~50 named features plus the
  stage-1 score, exported to JSON and walked in pure Python. Per-feature contributions become the EN / AR
  reasons. The model does not judge Tranco top-100k sites (unless on free hosting) or official domains.
- **Training data**: public labelled URL sets listed in section 11 (PhreshPhish, PhiUSIIL, Phishing.Database,
  Phishing Army, Tranco, HuggingFace sets), plus `tools/augment.py`: real deep links harvested from UAE official
  and Tranco sites, synthetic look-alikes of the protected brands (capped weight), and evasion rewrites
  (scheme, www, case, slashes, percent-encoding, port, userinfo). Known biases handled: PhiUSIIL legit rows are
  all bare homepages and host-only feeds have no paths, so those sources are trained as bare hosts.
- **Evaluation protocol** (`tools/train_url_model.py --build-holdout`, `tools/evaluate.py --suite`): fixed
  holdout sets in `datasets/holdout/`: `hannousse` (a whole dataset never trained on), `fresh_phishing` (newest
  JPCERT months, OpenPhish, PhishTank), `fp_suite` (real UAE government / bank login and service pages, official
  brand deep links, free-hosting legit pages, 6,000 Tranco long-tail sites), `robustness` (evasion variants of
  holdout URLs). Every holdout site is listed in `tools/holdout_sites.txt.gz` and removed from training;
  validation is split by site, never by URL. Results are stored in `saqr/intel/data/model_metrics.json`.

Measured on 2026-11-24 (offline system = look-alike rules + URL model only: no network, no page fetch, no LLM, no threat feeds; "block" = HIGH-RISK, score >= 65; "warn" = SUSPICIOUS or worse, score >= 30). "Before" is the previous hostname-only model.

| Test set | Cut | Before: precision / recall / false-alarm rate | After: precision / recall / false-alarm rate |
|---|---|---|---|
| Hannousse holdout (11,426 URLs, never trained on) | block | 0.992 / 0.172 / 0.14% | 0.997 / 0.314 / 0.10% |
| Hannousse holdout | warn | 0.878 / 0.318 / 4.41% | 0.987 / 0.537 / 0.70% |
| Fresh phishing (49,359 URLs: JPCERT 2026-08/09, OpenPhish, PhishTank) | block | recall 0.108 | recall 0.194 |
| Fresh phishing | warn | recall 0.312 | recall 0.415 |
| False-alarm suite (13,725 legitimate URLs) | block | 0.30% | 0.09% |
| False-alarm suite | warn | 16.52% | 0.63% |
| Evasion variants of holdout URLs (23,891) | warn | 0.913 / 0.330 / 6.42% | 0.994 / 0.558 / 0.75% |

- UAE official deep links (1,046), global-brand official pages (2,081), Tranco deep links (2,242) and 52 hand-picked bank / government login pages: **0 false alarms** at either cut.
- These are address-only numbers. Much of the held-out phishing sits on hosts an address model must not judge (Google Forms / Sites, QR and link shorteners, Dropbox, form builders) or on hacked older websites with ordinary addresses; the live checks below handle those.

**Live pipeline** (`tools/evaluate.py --mode live`: redirects and shorteners followed, WHOIS / DNS / TLS, page fetched as a UAE phone and as a bot, no LLM, no Chromium, i.e. the Render setup), 400 of the newest PhishTank phishing URLs (not trained on) + 400 legitimate pages (UAE government and bank deep links, bank / government login pages, global-brand official pages, Tranco long-tail, legit free hosting), scanned 2026-11-24. "Before" = the same scans judged by the previous rules. Threat feeds are left out because these URLs come from the same feeds (with feeds: warn recall 0.985).

| Live sample (800 URLs) | Cut | Before: precision / recall / false-alarm rate | After: precision / recall / false-alarm rate |
|---|---|---|---|
| without threat feeds | block | 0.984 / 0.605 / 1.00% | 0.984 / 0.630 / 1.00% |
| without threat feeds | warn | 0.970 / 0.725 / 2.25% | 0.984 / 0.750 / 1.25% |

- 0 false alarms on the 224 UAE official / bank / government / brand-official pages. Median scan 8.6 s, 95th percentile 16.5 s (20 scans in parallel). Of the 100 phishing URLs missed at warn, 53 were already offline or blocked when scanned and 45 showed the fetcher an ordinary-looking page.
- Full details, thresholds, per-set tables and what was tried and dropped: [docs/MODEL_CARD.md](docs/MODEL_CARD.md).

**UAE regression suite** (`tests/uae_suite/cases.json`, `tools/eval_uae.py`, also run by `pytest`): 50 cases
the team wrote by hand, 25 scams and 25 legitimate, 10 per input type (website link, email, Google Maps listing,
phone number, SMS / WhatsApp text), several in Arabic. Every scam domain is invented. The legitimate side includes
hard cases on purpose: a real-style bank email that talks about OTP and urgency, an official link with a long
tracking query, a shop called "Dubai Fabrics", a restaurant whose Maps "website" is WhatsApp. Run offline with
rules only (no LLM, no WHOIS / DNS / page fetch, no feeds). "Detected" = verdict not SAFE (phone: a caution /
danger level).

| Measured 2026-11-24, offline | Scams detected | Legitimate flagged | Precision | Recall | False-alarm rate |
|---|---:|---:|---:|---:|---:|
| 50 cases (5 types x 10) | 25 / 25 | 0 / 25 | 1.00 | 1.00 | 0% |

What this shows: the engine does not flag these common legitimate UAE cases and catches these common scam
patterns, and every official legitimate case comes back `verified_official`. What it does not show: accuracy on
real-world scams. The cases were written by people who know the rules, so a perfect score here is expected; the
real-data numbers are the ones above and in the model card. One engine gap was found while writing it and fixed
in general (Arabic polite requests such as "يرجى إرسال رمز التحقق" were not seen as asking for the code).

Commands (runtime venv, standard library only):

```bash
python tools/fetch_datasets.py                       # download the public sets -> datasets/ + MANIFEST.json
python tools/evaluate.py datasets/hannousse/dataset_B_05_2020.csv            # any labelled file
python tools/evaluate.py my.csv --url-col link --label-col verdict --positive bad,phish --mode system
python tools/evaluate.py sample.csv --mode live --records live.jsonl     # full pipeline, resumable
python tools/evaluate.py sample.csv --rescore live.jsonl                 # re-judge saved live evidence
python tools/evaluate.py --suite                     # the fixed holdout sets -> model_metrics.json
python tools/predict.py hidden_urls.csv -o predictions.csv [--url-col link] [--label-at block|warn] [--mode live]
python tools/eval_uae.py [--json out.json]           # the 50-case UAE suite, offline (--live: real network + LLM keys)
```

`--mode model` = URL model alone, `system` = the offline engine a scan runs first (rules + model, 65 = block,
30 = warn), `live` = the full pipeline with network (throw-away database, NextDNS and push disabled). Input can
be CSV / TSV / JSON / JSONL / TXT / parquet; URL and label columns are auto-detected. `predict.py` writes
url, label, score, verdict, reasons. Retraining needs numpy, scipy, scikit-learn and lightgbm in a separate
venv (developer machine only): `python tools/augment.py`, then
`python tools/train_url_model.py [--data extra.csv] [--data feed.txt:1] [--no-recipe]`.

## 6. Evidence and takedown

`POST /api/generate-takedown/{scan_id}` (JSON or Markdown), `GET /api/dossiers/{id}`,
`GET /api/dossiers/{id}/evidence-pack` (zip with a SHA-256 manifest), `GET /api/police/detections/{id}/dossier`.
A dossier holds the defanged URL, every reason (EN / AR), WHOIS (registrar, creation date, abuse contacts),
hosting / ASN, TLS certificate, redirect chain, UTC timestamps, SHA-256 of screenshot, DOM text and scan record,
hunter lead time, and drafted registrar and hosting abuse notices plus suggested actions (registrar suspension,
ISP-level block request to TDRA). Notices are drafted, not sent. `/police` also clusters scans into syndicates
(shared hosting IP, Maps pin, phone number or citizen report; IPs on CDNs / clouds never merge clusters) and can broadcast a bilingual warning
to every open `/citizen` page.

## 7. Arabic and UAE specifics

- Registry of 8 UAE entities (Abu Dhabi Police, TAMM, Emirates Post, e&, du, UAE PASS, FAB, ADCB) with Arabic
  names, aliases and official domains, plus 15 other trusted UAE sites (`saqr/intel/registry.py`). Any registered
  domain under `gov.ae` counts as official (TDRA only gives `gov.ae` names to government bodies; `gov.ae.evil.com`
  does not count).
- Phone numbers are parsed with `phonenumbers` (`saqr/intel/phone_intel.py`): UAE mobile / landline / 800 / 600 /
  short codes, foreign numbers. A personal `+971 5x` mobile or a foreign number shown for a UAE institution is a
  strong scam sign (banks and telecoms are left out of the foreign-number rule: they have real numbers abroad). Numbers in
  `registry.VERIFIED_PHONES` were checked on the entity's own website; the other registry numbers are demo data.
- SMS / WhatsApp text: `POST /api/analyze-message` (links, sender, call-back numbers, "send us the OTP" requests in
  English and Arabic). Wording such as "fine", "urgent" or "Emirates ID" never scores on its own.
- Short brand names (du, fab, tamm, adcb) match only as whole tokens (no alarms on dubai, fabric, tammy).
- Arabic form-field detection (OTP, card, CVV, Emirates ID, password, IBAN) and Arabic-first sandbox headers.
- All reasons, explanations, awareness alerts and the UI exist in English and Arabic (RTL).
- Email: SPF / DKIM / DMARC / ARC, look-alike Unicode letters, campaign matching (`POST /api/analyze-email`).

## 8. Build and run

Needs Python 3.11+ and Node.js 20+. **Windows (one click):** double-click `start-windows.bat` (macOS:
`./start-mac.sh`). It installs everything, starts the backend on port 8000 and opens http://localhost:3000/citizen.

Manually, **Windows (PowerShell)**:

```powershell
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements-dev.txt
python -m playwright install chromium
copy .env.example .env
uvicorn main:app --port 8000
```

If PowerShell refuses `activate`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once.

**Linux / macOS**: same steps with `python3 -m venv .venv`, `source .venv/bin/activate`, `cp .env.example .env`.

Frontend (second terminal): `cd frontend`, `npm install`, `npm run dev` → http://localhost:3000/citizen and
http://localhost:3000/police (open on a laptop when no `POLICE_PASSCODE` is set, marked "Dev: unlocked").
`/api/*` is proxied to `http://127.0.0.1:8000` (or `NEXT_PUBLIC_API_URL`).

`.env` notes: all keys are optional (without an LLM key the rules engine decides). Leave `NEXTDNS_PROFILE_ID` / `NEXTDNS_API_KEY` empty on a laptop while the cloud backend uses
them. `OFFLINE_MODE=true` runs a demo with no internet (seeded data, simulated CT and hunter).

Extension: `chrome://extensions` or `edge://extensions` → Developer mode → Load unpacked → `extension/`.
It uses the cloud API by default; see `extension/README.md`.

Tests (all offline):

```bash
python -m pytest -q                              # backend (Windows: .venv\Scripts\python -m pytest -q)
node --test extension/tests/*.test.js            # extension libs + background worker
node --test extension/tests/content/*.test.cjs   # content scripts on HTML fixtures
cd frontend && npm run lint && npx tsc --noEmit && npm run build
```

Cloud: `render.yaml` (backend, auto-deploys from `main`, `ENABLE_PLAYWRIGHT=false`); Vercel project for `frontend/`.

## 9. Real vs simulated / demo

| Part | Status |
|---|---|
| Rules, URL model, redirect resolver, WHOIS / DNS / TLS, HTTP page fetch | Real, on every scan |
| Threat feeds (Phishing Army, OpenPhish) | Real, refreshed every 6 h (`THREAT_FEEDS=false` disables) |
| LLM judge | Real when `GEMINI_API_KEY` / `OPENAI_API_KEY` is set; free-tier quotas; off for hunter scans. The prompt carries 6 invented UAE calibration examples (few-shot). An unsure first answer (score 40-69 or confidence < 0.8) gets one second opinion from another model; the default second-opinion model `gemini-4-argon` is not on the free tier, so on a free key the next model in `GEMINI_MODEL` answers. No second opinion for email scans yet |
| Phone checks (`/api/check-phone`, numbers in SMS, emails and Maps listings) | Real parsing (`phonenumbers`, offline). Only the numbers in `registry.VERIFIED_PHONES` are checked against the entities' own websites; the rest of the registry numbers are demo data |
| `verified_official` field (URL, email, Maps, message, phone responses) | Real: official domain / `gov.ae` domain, authenticated official sender (DMARC pass), or registry number, with nothing contradicting it |
| SMS / WhatsApp check (`/api/analyze-message`) | Real rules on the pasted text; its links are scanned as normal URL scans (they can reach the blocklist); the message itself is saved without a domain and with a short excerpt only |
| Email call-back numbers and MX check | Real: a mobile / foreign call-back number for a claimed institution is strong; "sender domain has no mail server" (MX) is weak and needs the network (skipped offline) |
| TLS certificate problem | Real but weak: counts (+10) only next to a strong signal such as a look-alike domain |
| Maps "website" that is WhatsApp / link-in-bio / a short link | Real: flagged only when the listing uses a UAE institution's name (a restaurant using WhatsApp is normal); these hosts never enter the blocklist or the graph |
| UAE regression suite (50 cases) | Hand-written synthetic cases, run offline with rules only (section 5); not real-world accuracy |
| Phone DNS block and push alert | Real (NextDNS denylist), tested on the owner's iPhone; one shared NextDNS profile |
| "Sync to e& / du Telecom Blocklist" | Adds the domain to SAQR's own blocklist + NextDNS. No telecom consumes the RPZ feed yet |
| Proactive Hunter | `HUNTER_MODE=live` by default: real DNS sweep, whoisds list and crt.sh. crt.sh answered HTTP 502 when tested on 2026-11-24 (the source backs off). `OFFLINE_MODE` or `HUNTER_MODE=simulated` = synthetic leads, labelled "simulated", never published |
| CT monitor | `CT_MODE=simulated` by default and on Render: synthetic certificate stream. `certstream` mode exists, not tested here; synthetic CT leads are ignored by the live hunter |
| Syndicates Sand Viper / Desert Mirage, seeded scans `SCN-SEED-*`, map pins, citizen reports | Fictitious demo data (`saqr/seed_data.py`); replica scam pages are rendered from stored HTML |
| Police command center counters, campaigns, warnings | In memory, reset on every restart. "Citizens Protected Today" and "Community X Alerts Dispatched" start from a fixed demo baseline (1,284 and 37); the tile shows "Includes 1,284 demo baseline · N live" and the API returns `demo_baseline` and `live_counts` separately. Pre-loaded stream rows are tagged "Demo" |
| `/police` sign-in | Real: one shared passcode, signed httpOnly cookie, police key added on the web server (see section 10). Not per-officer accounts |
| "Report a false alarm" | Real: stored in SQLite, reviewed in the `/police` queue; the officer's decision is recorded only (nothing is unblocked or whitelisted automatically) |
| Official phone numbers and branch coordinates | Branch coordinates: demo data. Phone numbers: 9 checked on the entities' own websites (`registry.VERIFIED_PHONES`, source URL per number, `verified_official: true`); the rest are demo data that must be checked against official sources |
| Maps listing lookup | Google Places only with `GOOGLE_MAPS_API_KEY` (not set in `render.yaml`); otherwise seeded listings + OSM reverse geocoding |
| Screenshots | Only with Playwright (laptop). Render has no browser: no screenshots, cloaking check = two HTTP views |
| Search & Maps badges (extension) | Tested on saved HTML fixtures of Google, Bing and Maps, not yet against live Google markup |
| SMS guard tab on `/citizen` | A simulated phone screen with a demo SMS (checked by `/api/analyze-message`); real messages are pasted or shared to the PWA (Android share target). SAQR cannot read a phone's SMS inbox |
| Demo scam sites (saqr-demo-scam.vercel.app, aed-refund-claim.vercel.app) | Harmless training replicas with an inert form |

## 10. Limitations and route to a police pilot

Security and privacy today:
- **`/police` is private.** `/police/login` asks for one shared passcode (`POLICE_PASSCODE`, 5 tries per 10 minutes);
  the browser then gets a signed, httpOnly cookie for 12 hours. Every officer call goes through the website's own
  `/api/officer/...` route, which adds the police API key (`POLICE_API_KEY`) on the server, so the key never reaches
  a browser. With the same key set on the backend, police endpoints refuse direct calls, and citizen pages only get
  public live events (official warnings and anonymised scan results, no IPs or email senders). The officer page
  refreshes every 4 seconds.
- **Retention.** Safe results and email checks are deleted after `SCAN_RETENTION_DAYS` (30). Links judged to be
  scams are kept as blocklist / dossier evidence, but the message text a citizen pasted is removed after 30 days.
  A safe link's query string (the part after "?") is never stored. Emails keep only sender, subject and a
  500-character excerpt. No account, name or phone number is asked for. The citizen app explains this next to
  every verdict and in the footer.
- **False alarms.** Any warning has "Report a false alarm" (domain, verdict, score and an optional note; no full
  URL). Reports are rate limited and appear in the `/police` "False-alarm reports" queue, where an officer
  confirms or dismisses them.

Limitations (known, not hidden):
- Measured accuracy is on public international datasets. The only UAE set is the team's own 50-case synthetic
  regression suite (section 5): it checks common UAE cases, not real-world accuracy, so the hidden test set may
  behave differently. A brand-new scam on an innocent-looking, aged domain needs page evidence.
- Most registry phone numbers and all branch coordinates are demo data; only `registry.VERIFIED_PHONES` was
  checked on the entities' websites. A scam SMS that uses a spoofed alphanumeric sender id ("ADCB") and asks for
  nothing (no link, no number, no code) cannot be told apart from a real one by its text.
- Brands outside the registry (for example Darb tolls) are caught only by generic signals (URL model, lure
  words): `darb` is not a brand token, so a Darb look-alike scores lower (SUSPICIOUS 31 in the suite).
- The LLM second opinion is not used for email scans. The email MX check needs DNS (skipped offline).
- The cloud runs without a browser: JavaScript-built scam pages, IP / geo cloaking and screenshot evidence need
  Playwright workers with a UAE egress (`SANDBOX_PROXY_SERVER` exists but is not configured).
- WHOIS is often redacted or rate-limited; crt.sh is unreliable; whoisds covers only domains it publishes.
- `/police` uses one shared passcode, not personal officer accounts, and there is no audit log of officer actions.
  Police endpoints are locked on the backend only once `POLICE_API_KEY` is also set on Render.
  SQLite on Render's ephemeral disk and the in-memory police state are lost on restart.
- Phishing Army (CC BY-NC) and OpenPhish (community, non-commercial) licences need clearing for operational use.

Route to a pilot (each step uses what exists today):
1. **Shadow mode, 4-6 weeks**: run on Abu Dhabi Police infrastructure, feed it links already reported via Aman and
   the hunter's leads; analysts label verdicts; measure precision, recall and lead time against the first report;
   calibrate the 30 / 65 thresholds and retrain with `tools/train_url_model.py --data <ADP labels>`.
2. **Official data**: replace demo registry phone numbers / branches with entity-verified lists; extend the
   registry to more UAE banks and government services.
3. **Hardening**: police SSO in place of the shared passcode, Postgres in place of SQLite, audit log of officer
   actions, Playwright workers behind a UAE egress, a retention period agreed with the police legal team.
4. **Enforcement loop**: officer-approved domains published as RPZ to telecom resolvers through TDRA; dossiers
   and abuse notices sent to registrars / hosts by the cyber-crime unit (a human approves every send).
5. **Citizen rollout**: the extension through the Chrome / Edge stores, the DNS profile and PWA through official
   police channels.

## 11. Data sources and licences

| Source | Use | Licence / terms |
|---|---|---|
| Tranco top-1M (Le Pochat et al., NDSS 2019) | legit training rows; top-100k "popular" list shipped at runtime | free, cite the paper |
| PhiUSIIL (UCI) | training (as bare hosts) | CC BY 4.0 |
| PhreshPhish (HuggingFace) | training | CC BY 4.0 |
| Phishing.Database | training | MIT |
| Phishing Army | training + runtime feed | CC BY-NC 4.0 |
| OpenPhish community feed | holdout + runtime feed | community feed, non-commercial |
| PhishTank | holdout | CC BY-SA 2.5 |
| JPCERT/CC phishurl-list | training + holdout (newest months) | see github.com/JPCERTCC/phishurl-list |
| Hannousse & Yahiouche (Mendeley; HF pirocheto re-host) | holdout, never trained on | CC BY 4.0 |
| HuggingFace ealvaradob/phishing-dataset | training | Apache-2.0 |
| HuggingFace kmack/Phishing_urls | training | licence not stated |
| whoisds.com newly registered domains | hunter source | free daily list |
| crt.sh, CertStream | certificate sources | public services |
| OpenStreetMap (tiles, Nominatim reverse geocoding) | maps | ODbL, © OpenStreetMap contributors |

URLhaus was in the fetch list but returned HTTP 410 and is not used. Exact files, row counts and SHA-256 hashes
are in `datasets/MANIFEST.json` (datasets are downloaded locally, not committed).
