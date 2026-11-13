# After the training queue: bring the whole system up with the new URL models and measure it.
# Run from the repo root when data\train_logs\summary.log says QUEUE FINISHED:
#   powershell -ExecutionPolicy Bypass -File ml\after_training.ps1
# It never chooses the stage-1 band for you (that is your decision, from the printed table), never
# opens the locked test set, and sends only development legitimate URLs to the API.
# Everything it prints is also saved in data\after_training_<time>.log.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$py = Join-Path $root "backend\.venv\Scripts\python.exe"
$log = Join-Path $root ("data\after_training_{0}.log" -f (Get-Date -Format "yyyyMMdd-HHmm"))
Start-Transcript -Path $log | Out-Null

function Step($text) { Write-Host ""; Write-Host "== $text" -ForegroundColor Cyan }
function Stop-With($text) { Write-Host "STOPPED: $text" -ForegroundColor Red; Stop-Transcript | Out-Null; exit 1 }

# 1. Are the models there?
Step "1. Training finished and URL models registered?"
$summary = Join-Path $root "data\train_logs\summary.log"
$lines = @(Get-Content $summary)
$lastStart = -1; $lastFinished = -1
for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "^\S+ START ") { $lastStart = $i }
    if ($lines[$i] -match "^\S+ QUEUE FINISHED$") { $lastFinished = $i }  # not the text queue's line
}
if ($lastFinished -lt $lastStart) {
    Stop-With "the training queue has not finished (data\train_logs\summary.log)"
}
$registry = Get-Content (Join-Path $root "data\models\registry.json") -Raw | ConvertFrom-Json
$sets = @($registry | Where-Object { $_.modality -eq "url" } | ForEach-Object { $_.feature_set }) | Sort-Object -Unique
foreach ($needed in @("live", "live_stage1")) {
    if ($sets -notcontains $needed) { Stop-With "no registered url/$needed model yet" }
}
Write-Host "url feature sets registered: $($sets -join ', ')"

# 2. The stage-1 band: a table for you to choose from.
Step "2. Stage-1 band table (choose the band, then set PHISHGUARD_STAGE1_BAND_LOW/HIGH in .env)"
Set-Location (Join-Path $root "ml")
& $py -m phishguard_ml choose-band
if ($LASTEXITCODE -ne 0) { Stop-With "choose-band failed" }
$env_text = Get-Content (Join-Path $root ".env") -Raw
if ($env_text -notmatch "(?m)^PHISHGUARD_STAGE1_BAND_LOW=") {
    Write-Host "NOTE: no band in .env yet, so the provisional 0.15-0.85 is used for the steps below." -ForegroundColor Yellow
}

# 3. Rebuild and start the API and the evidence collector with the new code and models.
Step "3. Rebuild and start the API and the evidence collector (this takes a while)"
Set-Location $root
docker compose up -d --build api
if ($LASTEXITCODE -ne 0) { Stop-With "the API did not build or start" }
docker compose --profile live up -d --build evidence-collector
if ($LASTEXITCODE -ne 0) { Stop-With "the evidence collector did not build or start" }

# 4. Wait until the API answers and has its models.
Step "4. API health and models"
$key = (Select-String -Path (Join-Path $root ".env") -Pattern "^PHISHGUARD_API_KEY=(.+)$").Matches.Groups[1].Value.Trim()
$headers = @{ "X-API-Key" = $key }
$ready = $false
for ($i = 0; $i -lt 60 -and -not $ready; $i++) {
    try {
        $status = Invoke-RestMethod -Uri "http://127.0.0.1:8000/admin/status" -Headers $headers -TimeoutSec 5
        $ready = [bool]$status.models_loaded
    } catch { }
    if (-not $ready) { Start-Sleep -Seconds 5 }
}
if (-not $ready) { Stop-With "the API did not report its models within 5 minutes" }
Write-Host "API up; models loaded."

# 5. One URL scan and one email scan, end to end.
Step "5. One URL scan and one email scan"
$url = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/scan/url" -Headers $headers `
    -ContentType "application/json" -Body (@{ url = "https://example.com/" } | ConvertTo-Json)
Write-Host ("URL  https://example.com/  -> {0}, score {1:N3}, stage {2}, {3} ms" -f $url.verdict, $url.score, $url.stage, $url.latency_ms)
$mail = "From: a@example.com`nTo: b@example.com`nSubject: Hello`n`nSee you at the meeting tomorrow."
$email = Invoke-RestMethod -Method Post -Uri "http://127.0.0.1:8000/scan/email" -Headers $headers `
    -ContentType "application/json" -Body (@{ raw_email = $mail } | ConvertTo-Json)
Write-Host ("Email (plain test message) -> {0}, score {1:N3}" -f $email.verdict, $email.score)

# 6. Latency: median and p95, and the time limit to set for the extension's checking page.
Step "6. Live latency on 200 development legitimate URLs (about 4 minutes)"
Set-Location (Join-Path $root "ml")
& $py -m phishguard_ml live-latency --n 200
if ($LASTEXITCODE -ne 0) { Stop-With "live-latency failed" }
Write-Host "Saved in data\models\latency_live.json. Put suggested_gate_timeout_ms into GATE_TIMEOUT_MS"
Write-Host "(frontend\extension\src\precheck.ts) and rebuild the extension, or ask Claude to."

# 7. Every table, from the saved files.
Step "7. make results"
& $py -m phishguard_ml results
if ($LASTEXITCODE -ne 0) { Stop-With "results failed" }

Step "Done. Next: load the rebuilt extension (npm run build in frontend\extension) and browse."
Stop-Transcript | Out-Null
