# TODO — put the Police Command Center (`/police`) live

The **Abu Dhabi Police Cyber-Patrol Command Center** is merged into `main`
(branch `feature/police-command-center`, commit "Add Abu Dhabi Police Cyber-Patrol Command Center").

| Part | Where it runs | Status |
|---|---|---|
| Backend (FastAPI, `main.py` + `saqr/`) | Render, service `saqr-intel-api` | **Deploys by itself** when `main` is pushed (autoDeploy). Only check it (step 1). |
| Website (Next.js, `frontend/`) | Vercel, project `saqr-intel` | **Needs a manual redeploy** (step 2). Vercel is not connected to GitHub. |

---

## 1. Render (backend): check it is live

1. Open https://saqr-intel-api.onrender.com/api/police/state in a browser.
   - You should see JSON with `kpis`, `campaigns`, `recent_events`, `map_pins`.
   - `404 Not Found` = the deploy hasn't finished yet. Render dashboard → `saqr-intel-api` → **Events**: wait for "Deploy live" (about 2–4 min), or click **Manual Deploy → Deploy latest commit**.
2. Optional but recommended before real use: Render → `saqr-intel-api` → **Environment** → add `POLICE_API_KEY` (any long random string).
   Without it, the officer buttons (sync to telecom, broadcast warning, takedown) are open to anyone who finds `/police`.
   **Warning:** the `/police` page does not send this key yet. If you set it, the whole dashboard stops loading (401 on `/api/police/state` and the live feed) until `frontend/src/lib/police.ts` sends an `X-API-Key` header (plus `?token=` on the WebSocket). For the hackathon demo, **leave it unset**.

## 2. Vercel (website): redeploy so `/police` exists

From a terminal (Windows PowerShell), in the project folder:

```powershell
cd frontend
npm install
npx vercel@latest deploy --prod --yes
```

- First time on your laptop? `npx vercel@latest login` first. Pick the project **saqr-intel** if asked.
- `NEXT_PUBLIC_API_URL` is already saved in Vercel (Production + Preview) → `https://saqr-intel-api.onrender.com`. Do **not** change it.
- Do **not** run `deploy-vercel.ps1`. That script switches the site back to a laptop tunnel.

Then open **https://saqr-intel.vercel.app/police**.

## 3. Smoke test (2 minutes, two tabs)

1. Tab A: https://saqr-intel.vercel.app/police. The header badge should say **● LIVE SYNCED WITH CITIZEN SHIELD**. The KPIs, stream, map and campaigns should be filled (demo data is loaded on every start).
2. Tab B: https://saqr-intel.vercel.app/citizen. Click **Test Fake TAMM Fine**.
   → In Tab A, **Citizens Protected Today** goes up by 1 and a new row appears at the top of the stream.
3. Tab B: on the red verdict screen, open the X warning and press **Open X to Post** (you don't have to actually post).
   → In Tab A, **Community X Alerts Dispatched** goes up by 1, and the campaign shows "Community-flagged on X".
4. Tab A: select a campaign, then click **Broadcast Official Warning to /citizen**.
   → In Tab B, the **"Abu Dhabi Police Verified Alert"** banner appears at the top.
5. Tab A: click **Export Official Takedown Dossier** and check that **Download JSON** and **Print / Save PDF** work.
6. Tab A: switch to **العربية**. The whole layout should flip right-to-left.

## Good to know

- **Police state is in memory.** Counters, X alerts, telecom syncs and warnings reset when Render restarts or redeploys (free tier). The demo data comes back automatically.
- **"Sync to e& / du Telecom Blocklist" is real.** It adds the domain to `/api/dns-blocklist` and to the NextDNS phone shield, so shielded phones block it within seconds. Official sites, SAQR's own sites and IPs are refused.
- **Every Render redeploy clears the phone push-alert sign-ups.** After deploying, open the SAQR app on each demo phone once.
- **Never run a local backend with the real NextDNS keys** in `.env` while Render is live: it double-syncs the block list and sends double alerts. The local test setup forces NextDNS off.
- **Tests:** `pytest -q` in the project root (123 pass). `cd frontend; npm run build` builds cleanly.
- **Map tiles:** OpenStreetMap, darkened with CSS. CARTO's dark tiles now require an API key.
