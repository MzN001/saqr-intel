# SAQR-INTEL — Backend

Autonomous anti-fraud & cybercrime intelligence system (Abu Dhabi Police Hackathon).
FastAPI + WebSockets + Playwright + SQLite, with Gemini/OpenAI and a fully offline rules-engine fallback.

## Quick start

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium          # headless sandbox browser
cp .env.example .env                 # add GEMINI_API_KEY or OPENAI_API_KEY (optional)
uvicorn main:app --reload --port 8000
```

Open http://localhost:8000/docs. CORS allows `http://localhost:3000`.
For a demo with no internet, set `OFFLINE_MODE=true`: the seeded syndicate, replica screenshots, rules engine and simulated CT feed all keep working.

Run tests with `pytest -q` (on Linux: `.venv/bin/python -m pytest -q`).

## Email scam check (new)

SAQR can now check an email, not only a website or an SMS.

- **What you can give it:** paste the email text, paste the full original ("Show original" in Gmail,
  "View message source" in Outlook), or upload a saved `.eml` / `.msg` file. In the web app this is
  the **Email Scam Check** tab; in Chrome/Edge the extension checks emails in Gmail and Outlook by itself.
- **What it looks at:** whether the sender is really who they say (SPF, DKIM and DMARC checks),
  fake look-alike letters (a Russian "а" inside "pаypal"), hidden or reversed characters, a company
  name sent from a free Gmail/Outlook account, dangerous attachments (`.exe`, `.html`, …), and every link
  (each link is scanned like a website). It also compares the email with known scam campaigns.
- **Your own filter (optional):** press "scam" or "not scam" on checked emails; after 10 of each,
  SAQR also tells you how much an email looks like the ones you marked. You can download, import or
  erase it at any time. You can also plug in your own AI service (OpenAI-compatible address + key);
  the key is used for that one check and never saved on the server.
- **Privacy:** SAQR keeps only the first 500 characters of the email, never the whole message, and
  never puts the sender's domain (like `gmail.com`) on the DNS blocklist. Only scam links are blocked.

```bash
curl -X POST localhost:8000/api/analyze-email -H 'content-type: application/json' \
  -d '{"source":"text","text":"From: PayPal <service@paypa1-secure.com>\nSubject: Account limited\n\nVerify your account now."}'
```

## Folder structure

```
saqr-intel/
├── main.py                    # FastAPI app, lifespan (DB, seed, CT monitor), CORS, routers
├── requirements.txt
├── .env.example
├── saqr/
│   ├── config.py              # env-driven settings, LLM provider auto-selection
│   ├── db.py                  # aiosqlite schema + idempotent seeding
│   ├── seed_data.py           # Sand Viper / Desert Mirage syndicates, pins, reports, replica pages
│   ├── schemas.py             # request models
│   ├── security.py            # SSRF guard, rate limiter, police API key
│   ├── ws_hub.py              # WebSocket broadcast hub (topic filters, replay buffer)
│   ├── pipeline.py            # URL analysis orchestration
│   ├── intel/
│   │   ├── registry.py        # official UAE entities: domains, phones, branches, aliases
│   │   ├── domain_intel.py    # lookalike/homoglyph/punycode + WHOIS/DNS/ASN/TLS
│   │   ├── ct_monitor.py      # zero-hour CertStream monitor (live or simulated)
│   │   ├── sandbox.py         # Playwright anti-cloaking sandbox
│   │   ├── ai_inspector.py    # rules engine + Gemini/OpenAI bilingual verdicts
│   │   ├── maps_sentinel.py   # Google Maps geo-spoof checks
│   │   ├── graph_engine.py    # syndicate clustering (union-find)
│   │   ├── takedown.py        # law-enforcement dossier + abuse notices
│   │   └── awareness.py       # trending wave detection + bilingual public alert
│   └── routers/               # analysis, maps, ct, graph, takedown, live, system
└── tests/test_api.py          # end-to-end tests (offline)
```

## Endpoints

| Method | Path | Module | Access |
|---|---|---|---|
| POST | `/api/analyze-url` | 1 + 3: lookalike detection, sandbox, AI verdict | citizen (rate-limited) |
| POST | `/api/scan-maps` | 2: Maps geo-spoof sentinel | citizen (rate-limited) |
| GET | `/api/ct-stream` · `/api/ct-stream/sse` | 1: zero-hour CT detections (JSON snapshot / SSE) | police |
| GET | `/api/syndicate-graph?syndicate_id=&include_reports=` | 4: force-graph nodes + links + syndicates | police |
| GET | `/api/syndicates` · `/api/syndicates/{id}` | 4 | police |
| POST | `/api/generate-takedown/{scan_id}?format=json\|markdown` | 5: takedown dossier | police |
| GET | `/api/awareness-alert?hours=72&entity=` | 5: bilingual AD Police warning | police |
| GET | `/api/scans` · `/api/scans/{id}` · `/api/scans/{id}/screenshot` | history / evidence | police |
| GET | `/api/dossiers/{id}` | stored dossiers | police |
| WS | `/ws/live?topics=&token=` | 6: live command-center feed | police |
| POST | `/api/analyze-email` | email scam check (text, raw source, .eml/.msg as base64) | citizen (rate-limited) |
| GET | `/api/campaigns` | known phishing campaigns (ETag / 304) | public |
| POST · GET · PUT · DELETE | `/api/email-model/label` · `/api/email-model/{reporter_id}` | personal scam filter: label, download, import, erase | citizen |
| GET | `/health` · `/api/stats` · `/api/whitelist` | system | public |

"Police" endpoints are open while `POLICE_API_KEY` is empty (demo mode). Once it is set, they need an `X-API-Key` header, and the WebSocket needs `?token=`.

### Example calls

```bash
# Citizen pastes the SMS. The URL is extracted and refanged automatically.
curl -X POST localhost:8000/api/analyze-url -H 'content-type: application/json' \
  -d '{"message_text":"TAMM: refund AED 340 pending hxxps://tamm-smart-pay[.]net","channel":"sms"}'

curl -X POST localhost:8000/api/scan-maps -H 'content-type: application/json' \
  -d '{"maps_url":"https://www.google.com/maps/place/Abu+Dhabi+Police+Traffic+Fines+Payment+Center/@24.3489,54.5052,17z"}'

curl localhost:8000/api/syndicate-graph
curl -X POST "localhost:8000/api/generate-takedown/SCN-SEED-0001?format=markdown"
curl localhost:8000/api/awareness-alert
```

Seeded scans `SCN-SEED-0001` … `SCN-SEED-0006` exist on first boot, so the takedown flow can be demoed immediately.

### WebSocket events (`/ws/live`)

Envelope: `{"event": "...", "ts": "...", "data": {...}}`

| event | when |
|---|---|
| `hello` | on connect: stats plus the last 20 events |
| `citizen_report.received` | as soon as a URL or Maps pin is submitted, before analysis |
| `url_scan.completed` / `maps_scan.completed` / `email_scan.completed` | verdict ready |
| `graph.updated` | new nodes/edges, with the syndicate the scan joined |
| `ct.detection` | a lookalike certificate was issued |
| `takedown.generated` · `awareness.drafted` | officer actions |

Filter with `?topics=ct,graph`. Client messages: `"ping"`, `{"action":"subscribe","topics":[...]}`, `{"action":"snapshot"}`.

## Design notes

- **Rules engine sets the floor, the LLM can only raise the score.** Every verdict is explainable and works offline. Gemini or OpenAI can escalate the score and write richer citizen text. Their output is schema-validated and clamped, and if a provider errors or times out, the next one in the chain is tried, then the rules engine.
- **Prompt-injection hardening.** Scraped page content is attacker-controlled. It goes to the LLM inside `<evidence>` tags, with an instruction to ignore any commands found there.
- **Anti-cloaking.** The sandbox renders the page as a UAE iPhone user would see it: `ar-AE` locale, Asia/Dubai timezone, Abu Dhabi geolocation, `navigator.webdriver` masked. A plain bot fetch runs in parallel, and a large difference between the two pages is flagged as cloaking. Set `SANDBOX_PROXY_SERVER` to a UAE residential egress to beat IP-based cloaking too.
- **SSRF guard.** Targets and every sub-request are resolved. Loopback, private, link-local and metadata addresses are blocked.
- **No false syndicate links through CDNs.** IPs on shared-infrastructure ASNs (Cloudflare, AWS, Google, …) stay in the graph but don't merge clusters. Short brand names (`du`, `fab`, `tamm`) only match as whole tokens, so `dubai`, `fabric` and `tammy` don't fire.
- **Evidence integrity.** Screenshot, DOM text and the scan record are SHA-256 hashed at capture time and included in the dossier.
- **Seed data is fictitious.** Hostile seed domains are never fetched live; the sandbox renders stored replica HTML instead. ASNs use the private range (AS64512+). Official phone numbers and branch coordinates are demo reference data and must be checked against official sources before operational use.
