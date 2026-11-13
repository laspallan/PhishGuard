# RQ2 daily threat-intelligence recorder. Runs ti-record --daily (an infinite loop that records
# one VirusTotal/OTX batch, then sleeps 30 min). Safe to re-run: a day already at the 500/day cap
# records nothing more. Started by the "PhishGuard TI" scheduled task (IgnoreNew, so one at a time).
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\PhishGuard\ml\ti_daily.ps1
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\backend\.venv\Scripts\python.exe"
Set-Location "$root\ml"
& $py -u -m phishguard_ml ti-record --daily
