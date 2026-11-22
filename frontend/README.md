# SAQR-INTEL Citizen Shield (frontend)

Next.js 16 (App Router) + TypeScript + Tailwind CSS v4 + framer-motion + Lucide.
All API calls use relative `/api/...` paths, which `next.config.mjs` proxies to the FastAPI backend
(`http://127.0.0.1:8000`, override with `SAQR_BACKEND_URL`).

```bash
npm install
npm run dev -- -H 0.0.0.0     # http://localhost:3000/citizen
```

Start the backend first (`uvicorn main:app --port 8000` in the project root).

## Screens (`/citizen`)
1. **Search & Maps Shield**: tap the sponsored ad, the Maps "Visit Website" button or the official result;
   the telecom DNS shield (`AUTO_TELECOM_DNS`) intercepts and shows the full-screen block page.
2. **SMS Smishing Guard**: a scam SMS arrives, is scanned in the background (`AUTO_SMS_GUARD`),
   moves to *Quarantined Phishing* and the warning opens automatically.
3. **Public Awareness Radar**: live scam waves from `GET /api/awareness-alert` with bilingual alerts.

## Phone share sheet
- `/citizen?url=...` or `/citizen?text=...` auto-scans on load (`MOBILE_OS_SHARE_SHEET`); Google Maps
  links go to `/api/scan-maps`, everything else to `/api/analyze-url`.
- On Android, install the PWA (Chrome menu → *Install app*) over HTTPS and **SAQR Verify** appears in
  the native Share sheet. A quick HTTPS tunnel for the demo:
  `cloudflared tunnel --url http://localhost:3000` (`*.trycloudflare.com` is already allowed).
