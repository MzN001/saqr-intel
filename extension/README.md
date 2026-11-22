# SAQR-INTEL | Citizen Web & Maps Scam Shield (Chrome & Edge, Manifest V3)

Automatic scam protection for PC and laptop users. Every website you open is checked with the
SAQR-INTEL backend; dangerous sites are replaced by an Abu Dhabi Police block page before you can
type a password or card number. Every block also appears live on the `/citizen` Crowd-Shield radar.

## Install (unpacked)

1. Start the backend (`start-windows.bat`, or `uvicorn main:app --port 8000`).
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

## Limits

- A brand-new scam on an innocent-looking address can load for a few seconds while the deep scan
  runs. The fast check stops the typical look-alike scam almost instantly.
- The backend address defaults to `http://127.0.0.1:8000`; change it in the popup for a deployed
  backend.
