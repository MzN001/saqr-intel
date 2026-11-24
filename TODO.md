# TODO

## Email scanning
- [ ] **Email attachment scanning** — today SAQR only looks at an attachment's *name* (dangerous types such as `.exe`, `.html`, double extensions like `invoice.pdf.exe`, hidden right-to-left characters). It does not open the file. To add:
  - scan the attachment's contents: links and QR codes inside PDFs / images ("quishing"), HTML attachments that contain a fake login form, Office files with macros, archives (`.zip`, `.iso`) and what is inside them;
  - send any links found inside attachments through the normal link scan;
  - check file hashes against a malware feed;
  - size limits and safe handling (never run or render an attachment);
  - show the result in the web app verdict screen and the extension banner.

## Police Command Center (`/police`)

The **Abu Dhabi Police Cyber-Patrol Command Center** is merged into `main` (branch `feature/police-command-center`)
and was put live on 2026-11-23: https://saqr-intel.vercel.app/police

Open items:
- [ ] **Turn on the `/police` lock in the cloud** (branch `feature/police-lock`, after it is merged): follow
  "0. Lock `/police`" below. Do the steps in that order.
- [ ] Police state is in memory: move it to a real database if counters/warnings must survive Render restarts.
- [ ] Before a real pilot: personal officer accounts (police single sign-on) and an audit log instead of one shared passcode.

How to deploy it again after changes:

| Part | Where it runs | Status |
|---|---|---|
| Backend (FastAPI, `main.py` + `saqr/`) | Render, service `saqr-intel-api` | **Deploys by itself** when `main` is pushed (autoDeploy). Only check it (step 1). |
| Website (Next.js, `frontend/`) | Vercel, project `saqr-intel` | **Needs a manual redeploy** (step 2). Vercel is not connected to GitHub. |

---

### 0. Lock `/police` (one time)

Pick two different long random strings (for example from a password manager). Keep them private.
- `POLICE_PASSCODE` = what officers type on the sign-in page.
- `POLICE_API_KEY` = the secret the website uses to talk to the backend. Nobody types it.

Do these steps **in this order**:

1. **Vercel** → project `saqr-intel` → Settings → Environment Variables → add `POLICE_PASSCODE` and
   `POLICE_API_KEY` for Production (and Preview). Do **not** tick anything that makes them public, and never name them `NEXT_PUBLIC_...`.
2. **Redeploy Vercel** (step 2 below). Environment changes only apply after a new deploy.
3. **Check the sign-in:** open https://saqr-intel.vercel.app/police. You should land on **Officer sign-in**.
   Type the passcode → the Command Center loads and fills. (Still open in the backend at this point: that is fine.)
4. **Render** → `saqr-intel-api` → Environment → add `POLICE_API_KEY` with **exactly the same value** as in
   Vercel → Save (Render restarts the backend, about 2 minutes).
5. Check `/police` again: it still loads. Then open https://saqr-intel-api.onrender.com/api/police/state directly:
   it should now answer `401`. That means nobody can skip the sign-in page.

Why this order: the website sends the key with every officer call. If Render gets the key first, the backend
starts refusing the website (which does not have the key yet) and `/police` stops working until Vercel is
redeployed. Vercel first means there is never a broken moment.

If `/police` stays on **RECONNECTING TO BACKEND…** after step 4 (and Render is awake), the two `POLICE_API_KEY` values are probably different: copy the value again into both places and redeploy Vercel.

### 1. Render (backend): check it is live

1. Open https://saqr-intel-api.onrender.com/health in a browser.
   - You should see JSON with `"status"`. (Before the lock, `/api/police/state` also shows JSON; after step 0 it answers `401`, which is correct.)
   - `404 Not Found` on a new endpoint = the deploy hasn't finished yet. Render dashboard → `saqr-intel-api` → **Events**: wait for "Deploy live" (about 2–4 min), or click **Manual Deploy → Deploy latest commit**.
2. `POLICE_API_KEY` on Render: only as step 4 of "0. Lock `/police`" above, never before Vercel has it.

### 2. Vercel (website): redeploy so `/police` exists

From a terminal (Windows PowerShell), in the project folder:

```powershell
cd frontend
npm install
npx vercel@latest deploy --prod --yes
```

- First time on your laptop? `npx vercel@latest login` first. Pick the project **saqr-intel** if asked.
- `NEXT_PUBLIC_API_URL` is already saved in Vercel (Production + Preview) → `https://saqr-intel-api.onrender.com`. Do **not** change it.
- Do **not** run `deploy-vercel.ps1`. That script switches the site back to a laptop tunnel.

Then open **https://saqr-intel.vercel.app/police** and sign in with the passcode.

### 3. Smoke test (2 minutes, two tabs)

The full rehearsable version (with what to say and what to do when something fails) is `docs/DEMO_SCRIPT.md`.

1. Tab A: https://saqr-intel.vercel.app/police (sign in). The header badge should say **● LIVE SYNCED WITH CITIZEN SHIELD**. The KPIs, stream, map and campaigns should be filled (demo data is loaded on every start).
2. Tab B: https://saqr-intel.vercel.app/citizen. Click **Test Fake TAMM Fine**.
   → In Tab A (within 4 seconds), **Citizens Protected Today** goes up by 1, the line under it ("· N live") goes up, and a new row without the **Demo** tag appears at the top of the stream.
3. Tab B: on the red verdict screen, open the X warning and press **Open X to Post** (you don't have to actually post).
   → In Tab A, **Community X Alerts Dispatched** goes up by 1, and the campaign shows "Community-flagged on X".
4. Tab A: select a campaign, then click **Broadcast Official Warning to /citizen**.
   → In Tab B, the **"Abu Dhabi Police Verified Alert"** banner appears at the top.
5. Tab A: click **Export Official Takedown Dossier** and check that **Download JSON** and **Print / Save PDF** work.
6. Tab A: switch to **العربية**. The whole layout should flip right-to-left.

### Good to know

- **Police state is in memory.** Counters, X alerts, telecom syncs and warnings reset when Render restarts or redeploys (free tier). The demo data comes back automatically.
- **"Sync to e& / du Telecom Blocklist" is real.** It adds the domain to `/api/dns-blocklist` and to the NextDNS phone shield, so shielded phones block it within seconds. Official sites, SAQR's own sites and IPs are refused.
- **Every Render redeploy clears the phone push-alert sign-ups.** After deploying, open the SAQR app on each demo phone once.
- **Never run a local backend with the real NextDNS keys** in `.env` while Render is live: it double-syncs the block list and sends double alerts. The local test setup forces NextDNS off.
- **Tests:** `.venv\Scripts\python -m pytest -q` in the project root (about 940 pass). `cd frontend; npm run lint; npx tsc --noEmit; npm run build`.
- **Map:** the `/police` map is drawn by SAQR itself (no map service, no API key).

## ScamShield submission (2026-11-24)
- [ ] Test the Search & Maps content script against live Google / Bing / Maps pages (only HTML fixtures so far).
- [ ] crt.sh answered HTTP 502 on 2026-11-24: add a second certificate source (e.g. a self-hosted CertStream server) and test `CT_MODE=certstream`.
- [ ] Cloud page checks have no browser: no screenshots in cloud dossiers, no JavaScript rendering. Needs a Playwright worker, ideally behind a UAE egress (`SANDBOX_PROXY_SERVER`).
- [ ] Training data: confirm the licence of HuggingFace `kmack/Phishing_urls` or drop it; Phishing Army (CC BY-NC) and OpenPhish (non-commercial) need clearing before operational police use.
- [ ] Replace demo registry phone numbers and branch coordinates with entity-verified data before a pilot.

## Detection upgrade (branch `feature/detection-upgrade`, 2026-11-24)
- [ ] Verify the registry numbers that are still demo data (listed in the comment above `VERIFIED_PHONES` in
  `saqr/intel/registry.py`): e& `800101`, du `155` / `800155`, UAE PASS `600561111`, ADCB `600502030` (its pages also
  list `600 50 2322`). Add each one to `VERIFIED_PHONES` only with the entity's own web page as the source.
- [ ] LLM second opinion for email scans (today only website scans get it).
- [ ] Add real, labelled UAE scam examples (e.g. from Aman reports) next to the 50-case synthetic suite in
  `tests/uae_suite/cases.json`; the synthetic suite is a regression check, not real-world accuracy.
- [ ] Deploy this branch (nothing is pushed yet):
  1. Commit, then push / merge to `main` on GitHub. Render deploys the backend by itself; check
     https://saqr-intel-api.onrender.com/health and that `POST /api/analyze-message` exists in `/docs`.
  2. Vercel (website) needs a manual deploy. `frontend/src/components/CityGrid.tsx` has local changes that are not
     part of this branch: stash them first (`git stash push frontend/src/components/CityGrid.tsx`), then
     `cd frontend` and `npx vercel@latest deploy --prod --yes`, then `git stash pop`.
