# Phase 3 training queue. Safe to run again after a crash or power loss: `--resume` skips every
# model that already finished. Start it from anywhere with:
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\PhishGuard\ml\train_queue.ps1
# Progress: data\train_logs\summary.log, and one log per run next to it.
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\backend\.venv\Scripts\python.exe"
$logs = "$root\data\train_logs"
New-Item -ItemType Directory -Force $logs | Out-Null
Set-Location "$root\ml"
$runs = @(
    @("email", "no_header"), @("url", "all"), @("email", "all"),
    @("url", "no_path"), @("url", "no_tranco"), @("url", "no_rdap"),
    @("url", "live"), @("url", "live_stage1"),  # M2 and M1, the deployed models (D11)
    @("email", "no_age")  # RQ1 email without the age-sensitive F96-F101, F109, F110
)
foreach ($r in $runs) {
    $name = "$($r[0])_$($r[1])"
    Add-Content "$logs\summary.log" "$(Get-Date -Format s) START $name"
    # cmd for the redirect: plain text appended to the log (PowerShell 5 would write UTF-16)
    cmd /c "`"$py`" -u -m phishguard_ml train --modality $($r[0]) --feature-set $($r[1]) --resume >> `"$logs\$name.log`" 2>&1"
    Add-Content "$logs\summary.log" "$(Get-Date -Format s) END $name exit $LASTEXITCODE"
}
Add-Content "$logs\summary.log" "$(Get-Date -Format s) QUEUE FINISHED"
