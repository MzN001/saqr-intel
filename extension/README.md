# SAQR-INTEL | Citizen Web & Maps Scam Shield (Chrome & Edge, Manifest V3)

Automatic scam protection for PC and laptop users. Every website you open is checked with the
SAQR-INTEL backend; dangerous sites are replaced by an Abu Dhabi Police block page before you can
type a password or card number. Every block also appears live on the `/citizen` Crowd-Shield radar.
The **Email Shield** also checks the emails you open in Gmail and Outlook (see below).

## Install (unpacked)

1. Nothing to start: the extension uses the cloud backend at `https://saqr-intel-api.onrender.com`.
2. Chrome: open `chrome://extensions` · Edge: open `edge://extensions`.
3. Turn on **Developer mode**.
4. Click **Load unpacked** and choose this `extension/` folder.
5. Pin the SAQR shield icon to the toolbar.

The icons are already generated. To recreate them: `python extension/generate_icons.py`.

## Stage demo (1 click)

Open the popup and press **Fake TAMM Fine** or **Fake Emirates Post**. A demo scam page opens and
is replaced by the block page within about a second. The block also shows up on `/citizen` → Tab 3
(Crowd-Shield Radar) as *PC Browser Shield*.

## How it works

| Piece | File |
|---|---|
| Navigation interceptor, badge, right-click menu, cache | `background.js` |
| Block / verdict page with risk gauge, EN + AR cards, X warning, Aman report | `blocked.html`, `blocked.js` |
| Toolbar popup: backend status, API address, scan this tab, demo buttons | `popup.html`, `popup.js` |
| Shared design (navy / emerald / crimson, cream light mode, dark mode) | `shield.css` |

- **Fast, then deep:** each site first gets a quick check (address, domain age, known scam
  networks, no browser). Only if that looks suspicious does the full cloud-sandbox scan run.
  A site is blocked when the verdict is `HIGH-RISK SCAM` or the risk score is 70 or more.
- **Cached:** safe sites are remembered for 30 minutes, risky ones for 10, so normal browsing does
  not hit the backend's 30-scans-per-minute limit.
- **Never in the way:** the `/citizen` app (port 3000), `x.com`, official UAE domains
  (`adpolice.gov.ae`, `tamm.abudhabi`, `uaepass.ae`, `emiratespost.ae`), browser pages and private
  network addresses are not scanned. If the backend is offline the badge shows `OFF` and pages load
  normally.
- **Badge:** `SAFE` (green), `!` amber (suspicious), `!` red (blocked), `…` scanning, `OFF` no backend.
- **Right-click → "Verify Link with SAQR-INTEL"** on any link, selected text or page.
- **Continue anyway:** the block page has a small "continue" link for false alarms; that site is then
  allowed until the browser is closed.

## Email Shield

| Webmail | Status |
|---|---|
| Gmail (`mail.google.com`) | ✓ works. The original message is fetched, so SPF / DKIM / DMARC are really checked. |
| Outlook (`outlook.live.com`, `outlook.office.com`, `outlook.office365.com`, `outlook.cloud.microsoft`) | ✓ works, but only the visible email is checked (headers not verified). |
| Yahoo, Proton, iCloud, AOL, Zoho Mail | work in progress: a small pill tells you to paste the email in the SAQR web app. |

- **Open an email:** a SAQR banner appears above it (Safe / Suspicious / Scam) with the reasons,
  the SPF/DKIM/DMARC result, look-alike letters, a **Full report** button, and **Scam** / **Not scam**
  buttons. Links in a scam email are guarded (you are warned before they open).
- **Inbox:** each row gets a small badge from quick local checks (known scam campaigns, your personal
  model, look-alike letters); **Scan all** checks every visible email with the backend (2 at a time,
  so the rate limit is respected).
- **Options page** (right-click the SAQR icon → Options): turn automatic scanning on/off, opt in to
  learning from your Spam folder, add **your own AI** (any OpenAI-compatible address, model name and
  key — the key stays in this browser and is sent only with each check over https), and manage the
  **personal model**: export it as a JSON file, import one (from another browser or the web app's
  server copy), or erase it.
- **Personal model:** your "scam / not scam" clicks train a tiny model stored only in this browser
  (`chrome.storage.local`); it gives an opinion after 10 emails of each kind. The server keeps a copy
  only for emails you label after a scan (hashed numbers, never the email text).
- Files: `content/common.js` (shared logic, banner, badges), `content/gmail.js`, `content/outlook.js`,
  `content/wip.js`, `content/mail.css`, `lib/` (feature hashing, personal model, campaign matching,
  `config.js` = backend and web-app addresses), `options.html` / `options.js`.

## Tests

No install needed (Node.js 20+):

```bash
node --test extension/tests/*.test.js              # background worker, libs, manifest
node --test extension/tests/content/*.test.cjs     # content-script helpers
```

## Limits

- A brand-new scam on an innocent-looking address can load for a few seconds while the deep scan
  runs. The fast check stops the typical look-alike scam almost instantly.
- The backend address defaults to the cloud backend `https://saqr-intel-api.onrender.com` (older installs
  pointing at `http://127.0.0.1:8000` are switched automatically). For a laptop backend, set it in the popup.
