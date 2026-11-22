# Live phone demo: a fake TAMM scam page on its own brand-new public address. SAQR scans it,
# flags it, pushes it to your NextDNS denylist, and a phone using the SAQR DNS shield can no longer
# open it, in Safari, Chrome, WhatsApp or any app.
#
# Needs: backend running (start-windows.bat) and NEXTDNS_PROFILE_ID + NEXTDNS_API_KEY in .env.
# Run from the saqr-intel folder:
#   powershell -ExecutionPolicy Bypass -File .\start-phone-demo.ps1
#
# Leave the minimized "cloudflared" window open during the demo. Every run gives a new address,
# so the phone has never seen it before (no DNS cache).

$ErrorActionPreference = "Stop"
$api = "http://127.0.0.1:8000"
$cloudflared = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
if (-not (Test-Path $cloudflared)) { $cloudflared = "cloudflared" }

function Say($text, $color = "Gray") { Write-Host $text -ForegroundColor $color }

try { $null = Invoke-RestMethod "$api/health" -TimeoutSec 5 } catch {
    Say "Backend is not running on port 8000. Start it first (start-windows.bat)." Red; exit 1
}
$status = Invoke-RestMethod "$api/api/nextdns-status"
if (-not $status.configured) {
    Say "NextDNS sync is not set up. Add NEXTDNS_PROFILE_ID and NEXTDNS_API_KEY to .env and restart the backend." Red
    exit 1
}
if ($status.last_error) { Say "Warning: last NextDNS sync failed: $($status.last_error)" Yellow }

$log = Join-Path $env:TEMP "saqr-phone-demo-tunnel.log"
if (Test-Path $log) { Remove-Item $log -Force }
Say "1/4  Creating a fresh public address for the fake TAMM page..." Cyan
Start-Process -FilePath $cloudflared -ArgumentList "tunnel", "--no-autoupdate", "--url", "$api", "--logfile", "`"$log`"" -WindowStyle Minimized
$base = $null
for ($i = 0; $i -lt 60 -and -not $base; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $log) {
        $m = [regex]::Match((Get-Content $log -Raw), "https://[a-z0-9-]+\.trycloudflare\.com")
        if ($m.Success) { $base = $m.Value }
    }
}
if (-not $base) { Say "Could not create the tunnel. See $log" Red; exit 1 }
$scam = "$base/mock-scam/tamm-fine"
$hostName = ([uri]$base).Host
for ($i = 0; $i -lt 30; $i++) {
    try { if ((Invoke-WebRequest -UseBasicParsing $scam -TimeoutSec 5).StatusCode -eq 200) { break } } catch { Start-Sleep -Seconds 2 }
}

Say "2/4  SAQR is scanning it in the cloud sandbox..." Cyan
$body = @{ url = $scam; channel = "sms"; interception_channel = "AUTO_SMS_GUARD"; include_screenshot = $false } | ConvertTo-Json
$r = Invoke-RestMethod -Method Post "$api/api/analyze-url" -ContentType "application/json" -Body $body -TimeoutSec 90
Say "     Verdict: $($r.verdict) ($($r.risk_score)/100), impersonating $($r.impersonated_entity)" $(if ($r.risk_score -ge 65) { "Green" } else { "Yellow" })
if ($r.risk_score -lt $status.min_score) { Say "     Score is below the sync threshold ($($status.min_score)); it will not be blocked." Red; exit 1 }

Say "3/4  Pushing it to your phones' DNS shield (NextDNS)..." Cyan
$synced = $false
for ($i = 0; $i -lt 30 -and -not $synced; $i++) {
    Start-Sleep -Seconds 1
    $s = Invoke-RestMethod "$api/api/nextdns-status"
    if ($s.last_added -contains $hostName) { $synced = $true }
    elseif ($s.last_error) { Say "     NextDNS error: $($s.last_error)" Red; exit 1 }
}
if (-not $synced) { Say "     Not confirmed yet; it will sync within $($status.interval_seconds) seconds." Yellow }
else { Say "     Blocked on NextDNS profile $($status.profile_id)." Green }

Set-Clipboard -Value $scam
Say ""
Say "4/4  Demo link (copied to clipboard):" Cyan
Say "     $scam" White
Say ""
Say "Send it to your phone (WhatsApp / iMessage / email) and tap it:" Gray
Say "  * Phone WITH the SAQR DNS shield -> the page will not load (blocked in every app)." Green
Say "  * Phone or laptop WITHOUT it      -> the fake TAMM payment page opens." Yellow
Say ""
Say "Tip: on the phone, test.nextdns.io should say status: ok (shield active)." Gray
