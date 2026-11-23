# One-click: expose the local backend through a Cloudflare quick tunnel and redeploy the
# citizen site to Vercel (https://saqr-intel.vercel.app) pointing at it.
#
# Run from the saqr-intel folder (backend must already be running on port 8000):
#   powershell -ExecutionPolicy Bypass -File .\deploy-vercel.ps1
#
# Keep the "cloudflared" window open while the site is in use. The tunnel address changes every
# time it starts, which is why this script redeploys.

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$cloudflared = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
if (-not (Test-Path $cloudflared)) { $cloudflared = "cloudflared" }

try {
    $health = Invoke-RestMethod "http://127.0.0.1:8000/health" -TimeoutSec 5
    if ($health.status -ne "ok") { throw "unhealthy" }
} catch {
    Write-Host "The backend is not running on port 8000. Start it first (start-windows.bat)." -ForegroundColor Red
    exit 1
}

$log = Join-Path $env:TEMP "saqr-cloudflared.log"
if (Test-Path $log) { Remove-Item $log -Force }
Write-Host "Starting Cloudflare tunnel..." -ForegroundColor Cyan
Start-Process -FilePath $cloudflared -ArgumentList "tunnel", "--no-autoupdate", "--url", "http://127.0.0.1:8000", "--logfile", "`"$log`"" -WindowStyle Minimized

$tunnel = $null
for ($i = 0; $i -lt 60 -and -not $tunnel; $i++) {
    Start-Sleep -Seconds 1
    if (Test-Path $log) {
        $m = [regex]::Match((Get-Content $log -Raw), "https://[a-z0-9-]+\.trycloudflare\.com")
        if ($m.Success) { $tunnel = $m.Value }
    }
}
if (-not $tunnel) {
    Write-Host "Could not get a tunnel address. See $log" -ForegroundColor Red
    exit 1
}
Write-Host "Tunnel: $tunnel" -ForegroundColor Green

for ($i = 0; $i -lt 30; $i++) {
    try { if ((Invoke-RestMethod "$tunnel/health" -TimeoutSec 5).status -eq "ok") { break } } catch { Start-Sleep -Seconds 2 }
}

# NEXT_PUBLIC_API_URL: the browser calls the tunnel directly for /api and the /ws/live feed
# (the backend's CORS allows saqr-intel*.vercel.app); next.config also proxies /api to it.
# The Vercel CLI writes normal progress to stderr; Windows PowerShell would treat that as a fatal
# error under "Stop", so let native commands run in "Continue" mode from here on.
$ErrorActionPreference = "Continue"
Push-Location (Join-Path $root "frontend")
try {
    # Save it as the project's environment variable too (Vercel Dashboard -> Settings -> Environment
    # Variables), so a later "Redeploy" from the dashboard or a GitHub push keeps the same backend.
    foreach ($target in "production", "preview") {
        npx --yes vercel@latest env rm NEXT_PUBLIC_API_URL $target --yes 2>&1 | Out-Null
        $tunnel | npx --yes vercel@latest env add NEXT_PUBLIC_API_URL $target | Out-Null
    }
    npx --yes vercel@latest deploy --prod --yes `
        --build-env "NEXT_PUBLIC_API_URL=$tunnel" `
        --env "NEXT_PUBLIC_API_URL=$tunnel"
} finally {
    Pop-Location
}
Write-Host ""
Write-Host "Live at https://saqr-intel.vercel.app/citizen (backend: $tunnel)" -ForegroundColor Green
Write-Host "Keep this laptop on, the backend running and the cloudflared window open."
