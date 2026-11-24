# Saqr demo script (about 5 minutes)

A step-by-step script you can rehearse. Two browser tabs (or two screens):

- **Tab A, officer:** https://saqr-intel.vercel.app/police
- **Tab B, citizen:** https://saqr-intel.vercel.app/citizen

Button names below are written exactly as they appear on screen (English).

How the citizen page works: it is one page with five "windows", picked with the tabs in the header
(on a phone: the pill bar under the header): **Link checker**, **Search & Maps**, **SMS**, **Email**,
**Live shield**. The address changes to `/citizen?view=maps|sms|email|live` so you can open a window directly.
A check you start yourself shows its result in the **result card** next to the input. The full-screen red
block page only appears when the citizen was about to *open* something: a tap in the Search & Maps demo, a tap on
the link in the demo SMS, a link shared to the app, or a scam-alert notification (`?alert=`).

The police page keeps its older dark "Night Grid" look on purpose (a new police design comes later).

---

## Pre-demo checklist (the day before / 10 minutes before)

- [ ] You know the officer passcode (the `POLICE_PASSCODE` you saved in Vercel). Do not say it out loud on stage.
- [ ] Laptop charged, browser zoom at 100 %, notifications off, other tabs closed.
- [ ] A phone hotspot ready in case the venue Wi-Fi fails.
- [ ] Optional phone step: the demo phone has the Saqr DNS profile ("Saqr Shield") installed and works (step 8).
- [ ] Optional: the browser extension is loaded (`extension/`, version 1.3.1) and/or the Android emulator runs the
      Saqr app (step 9).
- [ ] Rehearsed once end to end with a timer.
- [ ] Local fallback ready (see "If something goes wrong"): `start-windows.bat` works on this laptop.

## Step 0: two minutes before you start

1. Open **Tab B** (`/citizen`). This wakes the server (the citizen page sends a quiet "wake up" ping to it).
   The free server sleeps after a while and can take up to about a minute to wake up.
2. Open **Tab A** (`/police`). It asks for the passcode: type it, press **Sign in**.
3. Check Tab A: the strip under the header says **LIVE SYNCED WITH CITIZEN SHIELD** and the KPIs, map and
   campaigns are filled. You also see the gold **Demo data · resets on restart** chip.
4. Leave both tabs open. Do not refresh Tab A during the demo.

## Step 1: a citizen checks a scam link (about 45 s)

Tab B, **Link checker** window. In the **Check a link** card, press **Try a fake TAMM fine**.

- The box shows **Example scam page (safe demo)**. The result card beside it (below it on a phone) switches from
  the grey **Demo example** to the scanning steps, then to **Live verdict**: the score out of 100, the
  **HIGH-RISK SCAM / احتيال عالي الخطورة** stamp, the Safe | Suspicious | Scam meter and the top three reasons in
  English and Arabic.
- Press **Full report**: a side panel opens with every reason, the domain and hosting details and the privacy
  line. Close it with **Back to safety**.

> **Say:** "A resident got this link by SMS. Before they open it, Saqr follows it, checks the domain, the page and our
> model, and gives a clear verdict. Every reason is in English and Arabic."

## Step 2: the full-screen block (about 30 s)

Tab B: open the **Search & Maps** tab. In the fake Google results, tap the sponsored ad
**Abu Dhabi Police Traffic Fine Payment**.

- This time the whole screen turns into the red block page **Website blocked for your protection**, because the
  resident was about to open the link (the demo plays the phone's DNS shield catching it).
- Close it with **Back to safety**.

> **Say:** "When you check something, you get an answer next to it. When you are about to open a scam, Saqr stops you
> with a full-screen warning."

## Step 3: the Crowd-Shield shows it (about 20 s)

Tab B: open the **Live shield** tab. The **Live Crowd-Shield** list (under **Active scam waves**) shows the blocks
you just made at the top.

> **Say:** "Every block is shared anonymously with other residents in real time: no names, no numbers, no locations."

## Step 4: the officer sees it (about 30 s)

Tab A. Within about 4 seconds:

- New rows appear at the top of **Live Citizen Interception Stream**. Rows without the small grey **Demo** tag are real.
- **Citizens Protected Today** goes up. Under the number it says, for example,
  "Includes 1,284 demo baseline · 2 live".

> **Say:** "The big number includes a demo baseline so the screen is not empty; the line under it shows exactly how
> many are live right now."

Optional (20 s): back in Tab B, **Link checker**, on the result card press **Warn community on X**, then
**Approve & Open X to Post** in the preview (you don't have to post). In Tab A, **Community X Alerts Dispatched**
goes up by 1. **Copy Aman 8002626 report** copies a ready-made report (paste it into an SMS to 2828).

## Step 5: the officer warns the public (about 45 s)

Tab A. Pick a campaign in **Coordinated Phishing Campaigns** (for example the TAMM one), then in
**1-Click Law-Enforcement Action Center** press **Broadcast Official Warning to /citizen**.

Tab B: the **Abu Dhabi Police verified alert** banner appears at the top (within about 20 seconds at most).

> **Say:** "One click and every open citizen app shows an official, bilingual warning."

Optional: press **Sync to e& / du Telecom Blocklist**. This is real: the domain is added to Saqr's DNS blocklist
and to the phone shield (step 8).

## Step 6: evidence for a takedown (about 45 s)

Tab A, same campaign: press **Export Official Takedown Dossier (PDF / JSON)**. Show the hosting IP, registrar,
red flags and requested actions. **Download JSON** and **Print / Save PDF** work.

Then scroll to **Proactive Hunt**, open an **Evidence dossier** and show **Download evidence pack (.zip)**
(the zip has a SHA-256 list so nobody can change the evidence unnoticed).

> **Say:** "Everything a registrar or the cyber-crime unit needs, ready in one click. Notices are drafted, never sent
> automatically: a person decides."

## Step 7: a false alarm goes to the officer (about 30 s)

Tab B, **Link checker**: on the result card (still showing the TAMM verdict; if not, press
**Try a fake TAMM fine** again) press **Report a false alarm** (it only appears on warnings, not on safe
results), type a short note, press **Send for review**.

Tab A: scroll to **False-alarm reports**. The report is there. Show **Confirm false alarm** / **Dismiss**.

> **Say:** "If we are ever wrong, the citizen tells us in one tap. The officer's decision is recorded; nothing is
> unblocked automatically."

## Step 8 (optional): the phone blocks the scam in every app (about 30 s)

On the demo phone that has the Saqr DNS profile, open https://saqr-demo-scam.vercel.app.
The page does not open (Safari: "Safari can't open the page"). On the laptop the same link opens: it is a
harmless training copy.

> **Say:** "No app needed: the phone's DNS refuses scam sites in Safari, WhatsApp, everywhere."

## Step 9 (optional, only if time is left): extension and Android app (about 30 s each)

- **Browser extension:** click the Saqr icon in the toolbar, open **Connection and demo**, press
  **Demo: fake TAMM fine**. The demo page is replaced by the Saqr block page: one language at a time (the
  **العربية** button switches it) with the top three reasons.
- **Android app** (emulator): send the demo scam SMS (command in `android-app/README.md`). A two-line notification
  appears, for example "Scam SMS blocked · 96/100" and "Fake TAMM (…) — Do not tap." The **Scanner** tab shows the
  same kind of verdict card as the website. Tested in the emulator only, not yet on a real phone.

---

## If something goes wrong

| Problem | What you see | What to do |
|---|---|---|
| Server asleep | Tab A says **RECONNECTING TO BACKEND…**, or the citizen result card says **Could not complete the scan** with "Can't reach the Saqr server right now (it may be waking up)" | Wait 30-60 s and press **Try again**. Next time open the citizen site 2 minutes before. |
| AI judge (Gemini) down or out of quota | Nothing breaks; the reasons come from the rules engine | Keep going. The rules and the URL model decide on their own (the example scam page does not use the AI at all). |
| Venue Wi-Fi down | Pages do not load | Switch the laptop to the phone hotspot. If there is no internet at all: run `start-windows.bat` on the laptop and use http://localhost:3000/citizen and http://localhost:3000/police (locally `/police` is unlocked when no passcode is set). |
| Logged out of `/police` | Tab A jumps to **Officer sign-in** | Type the passcode again and press **Sign in** (a session lasts 12 hours; 5 wrong tries lock you out for 10 minutes). |
| Render restarted / redeployed | KPIs are back to the demo baseline, your earlier warning and X alerts are gone | Normal: the officer view lives in memory. Do step 1 again so the live count moves. Phone push sign-ups also need to be renewed after a redeploy. |
| "Police access is not configured on this server." on the login page | Vercel has no `POLICE_PASSCODE` | Set it in Vercel and redeploy (see `TODO.md`). |
| You are in the wrong window | The result card or the button is not on screen | Use the header tabs, or **Back to link checker** at the top of each tool window. |

## Honest answers to likely judge questions

**"Is 1,284 real?"**
No. It is a fixed demo baseline so the dashboard is not empty on a cold start. The line under the number shows how
many are live (real scans since the server started). Rows tagged **Demo** in the stream are pre-loaded too, and the
syndicates Sand Viper and Desert Mirage are made up.

**"Is `/police` secure?"**
For a hackathon, yes; for real police use it needs more. It is behind one shared passcode; after sign-in the browser
gets a signed cookie that scripts cannot read. The police API key stays on the web server and is never sent to the
browser; with the key also set on the backend, nobody can call the police API directly. A real rollout would use
police single sign-on, one account per officer and an audit log.

**"Is Saqr an official police app?"**
No. It is a hackathon prototype with its own brand (the falcon logo); it does not use any police emblem.

**"What do you store about citizens?"**
The link they check and its result, any message text they paste with it, and for emails the sender, subject and a
short excerpt (never the full email or files). For a safe link the part after "?" is not stored. Safe results and
email checks are deleted after 30 days. Scam links are kept as evidence for the blocklist, but the pasted message
text is removed after 30 days. No account, name or phone number is asked for.

**"What about false positives?"**
Weak signals (a log-in form, urgent words) count for nothing unless there is strong evidence, because real bank
and government sites show them all the time. Measured numbers (README section 5, `docs/MODEL_CARD.md`):
offline, the false-alarm rate on 13,725 legitimate URLs is 0.09 % at "block" and 0.63 % at "warn"; in the
live test (800 URLs) it was 1.25 % at "warn", with 0 false alarms on the 224 UAE official, bank and government
pages. And citizens can report a false alarm in one tap (step 7).

**"Where does the training data come from, and may you use it?"**
Public labelled sets (README section 11). Most are open (CC BY 4.0, MIT, Apache-2.0). Phishing Army (CC BY-NC) and
the OpenPhish community feed (non-commercial) must be cleared before real police use, and one HuggingFace set has
no stated licence. We say that openly in the README.

**"Is the telecom block real?"**
The blocklist and the phone DNS shield are real (tested on the owner's iPhone). No telecom (e& / du) uses the feed
yet: that is the pilot step.
