# SAQR Shield (Android)

Native Android app for SAQR-INTEL (Kotlin + Jetpack Compose). Hackathon demo, not an official government service.

## What it does

- **Shield tab**: shows if the phone is protected (emerald "Protected" ring, or amber "Action needed") and real
  counters ("Blocked today" from the local alert list, "Checked today" = server checks made today). Three steps:
  1. alert notifications (asks for `POST_NOTIFICATIONS` on Android 13+),
  2. message guard (plain consent dialog first, then Android's Notification access screen),
  3. web blocker (recommended, not required: "Protected" needs steps 1-2 only; consent dialog first, then
     Android's Accessibility settings).
  The **API server** pill edits the backend URL, pings `/health` (status + latency) and resets to the default.
- **Scanner tab**: "Is this link safe to open?" Paste a link, message, email or phone number. Modes
  Auto | Web | Message | Email | Phone | Maps. Auto decides on the phone: a bare URL goes to
  `/api/analyze-url` (a Google Maps URL to `/api/scan-maps`), a number only to `/api/check-phone`, text with
  `From:` + `Subject:` lines to `/api/analyze-email`, anything else to `/api/analyze-message`. Three example chips.
  After 8 s the app says the server is waking up (Render free tier can take ~50 s).
- **Alerts tab**: timeline of the last 50 alerts (guard + manual checks that were not safe); tap one for details,
  "Clear all" removes them.
- **Verdict sheet** (used everywhere): score, verdict, one-line instruction, Safe / Suspicious / Scam meter,
  impersonated entity + official website, up to 3 reasons (EN/AR), links / numbers found, "Verified" row,
  and actions: Warn others on X (only when not safe and score >= 60; logs `/api/police/log-x-alert`),
  Call Aman 8002626 (opens the dialer), Copy report, Report a false alarm.
- **Message guard** (`guard/SaqrNotificationListenerService`): reads new notifications from Google / Samsung
  Messages, AOSP MMS, Gmail, Outlook, WhatsApp (+ Business) and Telegram only. `guard/MessageFilter` decides on
  the phone; a message is sent to the server only if it has a non-official link, a phone number together with a
  claim / lure (police, fine, bank, prize, parcel...), or a request to send / share / enter a code, OTP, PIN, CVV or
  card details (EN + AR; "never share your OTP" advice is not a request). Standalone 4-8 digit codes are masked
  before sending. HIGH-RISK (>= 65) gives a "Scam SMS blocked · 96% risk" alert, SUSPICIOUS (30-64) a quieter
  "check before you tap" one; SAFE gives nothing. The app warns; it cannot delete the original message.
- **Web blocker** (`guard/SaqrBrowserGuardService`, an AccessibilityService): reads ONLY the address bar of
  Chrome, Samsung Internet, Firefox and Edge, found by view id (`WebGuardPolicy.URL_BAR_IDS`); never page
  content, passwords or typed text, and nothing while the address bar is focused (the user is typing).
  `guard/WebGuardPolicy` (pure, unit-tested) normalises the address (adds the hidden scheme, lower-cases the host,
  drops `user@` and `#fragment`; ignores `about:` / `chrome:` / search queries / Google, Bing, DuckDuckGo result
  pages) and never sends official UAE domains, private / loopback hosts or the API host (both allowed only for
  `/mock-scam/` demo pages), or hosts on the session "continue anyway" list. 5 s per-URL cooldown, per-host
  in-flight de-duplication, `ScanCache` first (safe 30 min, risky 10 min). Scan = the Chrome extension's flow:
  fast `POST /api/analyze-url` (`run_sandbox:false, use_llm:false`, 15 s), and one deep scan
  (`run_sandbox:true, use_llm:true`, 75 s) only for a fast score of 30-64. HIGH-RISK (verdict or score >= 65)
  opens `ui/BlockAlertActivity`; SUSPICIOUS (30-64) gets the quieter caution notification. Server asleep or
  unreachable = fail open, silently.
- **Block screen** (`ui/BlockAlertActivity`, not exported, own task, not in recents): "Blocked by SAQR-INTEL",
  defanged address, animated risk ring, impersonated entity + official website, two reasons (EN/AR).
  **Close & stay safe** (also the Back key) finishes the screen, then the service presses BACK in the browser;
  if the browser still shows the site 1.8 s later it opens the official site (or adpolice.gov.ae) in that
  browser. In the emulator BACK went back to the previous page when the tab had history, and closed the tab
  when it was opened from another app. **Warn community on X** (`XAlert`), **Call Aman 8002626**,
  **Continue anyway** (needs a second tap; allows that host until the app process ends).

## Permissions and why

| Permission | Why |
|---|---|
| `INTERNET` | talk to the SAQR backend |
| `POST_NOTIFICATIONS` | show scam alerts (asked at runtime on Android 13+; the app works without it, just silently) |
| Notification access (`BIND_NOTIFICATION_LISTENER_SERVICE`, granted by the user in Settings) | read incoming message notifications for the message guard |
| Accessibility (`BIND_ACCESSIBILITY_SERVICE`, "SAQR web blocker", switched on by the user in Settings > Accessibility) | read the address bar of four browsers for the web blocker (`res/xml/accessibility_service_config.xml`: those packages only, window events only) |

**Android 13+ and a sideloaded APK**: the Accessibility switch may be greyed out ("Restricted setting"). Open
Settings > Apps > SAQR Shield, tap ⋮ (top right) > **Allow restricted settings**, then switch on SAQR web
blocker again. The Shield tab shows the same steps (EN/AR).

No SMS, contacts, phone-call or location permission. "Call Aman" uses `ACTION_DIAL` (you press call yourself).

## Privacy summary

- Ordinary chats never leave the phone (on-device filter above). Guard scans use `use_llm: false`.
- The sender is sent only when it is a phone number or an SMS business sender id (e.g. `ADPolice`), never a
  contact or chat name.
- The phone keeps only: the alert list (time, kind, defanged domain or "text message", score, verdict, entity,
  scan id, up to 2 reasons), the API URL, the guard consent flag, a random reporter id (`r-` + 32 hex) and
  today's check counter. Never the message text or the sender number.
- The server (see `saqr/message_pipeline.py`) never stores the full text: for a flagged message it keeps a
  300-character excerpt with digits hidden; results are pruned after 30 days. Scam links are saved as URL scans
  (they feed the blocklist).
- Turn the guard off in the Shield tab (Message guard pill) and remove SAQR from Settings > Notification access.
- Web blocker: only the web address leaves the phone (official UAE sites, local addresses and "continue anyway"
  hosts never do), with `interception_channel: ANDROID_APP_GUARD` and channel `web`. It does nothing until the
  user accepted its own consent dialog (separate from the message guard's). Turn it off with the Web blocker
  pill and switch off SAQR web blocker in Settings > Accessibility.

## Web blocker: known limits

- Only Chrome, Samsung Internet, Firefox and Edge. Other browsers and in-app web views (links opened inside
  WhatsApp, Instagram, Gmail...) are not covered; the message guard checks those links instead.
- The address bar is found by view id; a browser update can rename it, and then the blocker silently does
  nothing for that browser until the id list is updated.
- Chrome may hide the path of some addresses; the check then uses the host.
- The page starts loading before the verdict arrives (about 1-6 s); the block covers it before the user is
  likely to type, but it is not a network-level block (the NextDNS profile is that).
- Tested in the Android 16 (API 36) emulator with Chrome 133 only, not on a real phone or the other browsers.

## Build

Needs JDK 17+ (JDK 21 used here) and the Android SDK (platform 36, build-tools 36.x).

1. Create `local.properties` (git-ignored) in this folder:

   ```
   sdk.dir=C\:/Users/<you>/Android/sdk
   ```

2. Build, lint and unit-test (PowerShell, from `android-app/`):

   ```powershell
   $env:JAVA_HOME = 'C:\Users\<you>\Android\jdk21'
   .\gradlew.bat assembleDebug lintDebug testDebugUnitTest
   .\gradlew.bat --stop   # free the Gradle daemon's RAM
   ```

   APK: `app/build/outputs/apk/debug/app-debug.apk`; lint report `app/build/reports/lint-results-debug.html`;
   test report `app/build/reports/tests/testDebugUnitTest/index.html`.

3. Install on a running emulator or a USB-debugging phone:

   ```powershell
   adb install -r app\build\outputs\apk\debug\app-debug.apk
   ```

## Testing on the emulator

```powershell
# Grant notification access without the Settings screen (then accept the consent dialog in the Shield tab,
# or the guard stays off)
adb shell cmd notification allow_listener ae.saqrintel.shield/ae.saqrintel.shield.guard.SaqrNotificationListenerService

# Android 13+: grant the alert permission
adb shell pm grant ae.saqrintel.shield android.permission.POST_NOTIFICATIONS

# Send a fake SMS into the emulator (Google Messages shows a notification the guard reads)
adb emu sms send 0500007781 "TAMM: You have an unpaid fine of AED 350. Pay today at https://tamm-smart-pay.net/fine"
```

### Web blocker

```bash
# Git Bash: export MSYS_NO_PATHCONV=1 first
adb shell am start -n ae.saqrintel.shield/.MainActivity --ez web_consent true     # debug-only consent hook
adb shell settings put secure enabled_accessibility_services ae.saqrintel.shield/ae.saqrintel.shield.guard.SaqrBrowserGuardService
adb shell settings put secure accessibility_enabled 1
# Chrome first-run screens off (once)
adb shell 'echo "chrome --disable-fre --no-default-browser-check --no-first-run" > /data/local/tmp/chrome-command-line'
adb shell am start -a android.intent.action.VIEW -d http://10.0.2.2:8011/mock-scam/tamm-fine com.android.chrome
adb shell dumpsys activity activities | grep topResumedActivity   # -> .ui.BlockAlertActivity
adb logcat -s SaqrWebGuard        # debug builds: "scan fast", "verdict", "block screen launched", "skip OFFICIAL ..."
```

`uiautomator dump` pauses other accessibility services while it runs (the blocker reconnects afterwards) and
could not read the Compose block screen; use screenshots there. The app-wide "continue anyway" list lives in
memory: force-stop the app to clear it.

### Local backend

From the emulator the laptop is `10.0.2.2`. Start the backend on the laptop (e.g. port 8011), then either open
Shield > API server and enter `http://10.0.2.2:8011`, or use the debug-only hook:

```powershell
adb shell am start -n ae.saqrintel.shield/.MainActivity --es api_url http://10.0.2.2:8011
```

Plain `http://` is accepted only in debug builds and only for `10.0.2.2`, `localhost` and `127.0.0.1`
(`app/src/debug/res/xml/network_security_config.xml`; add a LAN IP there for a real phone). Release is HTTPS-only.
Default: `https://saqr-intel-api.onrender.com`.

The live server may not know `interception_channel: ANDROID_APP_GUARD` yet; on that 422 the app retries once
with `AUTO_SMS_GUARD` and keeps that for the rest of the process.

## Layout

- `app/src/main/kotlin/ae/saqrintel/shield/`
  - `MainActivity.kt` – Compose host; opens an alert from a notification; debug `api_url` hook.
  - `SaqrApp.kt` – `AppGraph` singletons (settings, alert store, cache, API client, app scope).
  - `data/` – `ApiClient` (OkHttp, `ApiResult`), wire `Models`, `Verdict`/`VerdictInfo`, `Settings`, `ScanCache`,
    `OfficialDomains`, `AlertStore`, `AutoRouter`.
  - `guard/` – `SaqrNotificationListenerService`, `MessageFilter`, `GuardEngine`, `AlertNotifier`,
    `SaqrBrowserGuardService` (web blocker), `WebGuardPolicy` (+ `UrlThrottle`, `BlockGate`, `WebSession`).
  - `ui/BlockAlertActivity.kt` – full-screen block.
  - `util/` – `Defang`, `XAlert` (same templates as `frontend/src/lib/share.ts`), `Aman`.
  - `ui/` – `shell/`, `shield/`, `scanner/`, `alerts/`, `verdict/VerdictSheet`, `common/`, `theme/` (Night Grid tokens).
  - `locale/LocaleController.kt` – runtime EN | AR switch; `settings/ThemeController.kt` – light / dark.
- `app/src/test/` – JVM unit tests (filter, official domains, defang, X text, auto routing, JSON parsing,
  web-blocker URL rules / cooldown / thresholds).
- `licenses/` – OFL licences of the bundled fonts.
