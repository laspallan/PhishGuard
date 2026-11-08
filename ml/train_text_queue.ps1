# Phase 3 CNN queue. Run it after ml/train_queue.ps1 has finished, so the two do not fight over the
# CPU. Safe to run again after a crash or power loss: `--resume` skips finished models.
# CNN only: the LSTM takes hundreds of hours per run on this CPU, so it runs on Colab (train_lstm.py).
#   powershell -NoProfile -ExecutionPolicy Bypass -File D:\PhishGuard\ml\train_text_queue.ps1
# Progress: data\train_logs\summary.log, and one log per run next to it.
$root = Split-Path -Parent $PSScriptRoot
$py = "$root\ml\.venv-text\Scripts\python.exe"
$logs = "$root\data\train_logs"
New-Item -ItemType Directory -Force $logs | Out-Null
Set-Location "$root\ml"
# ZKBioTime sets PYTHONHOME for the whole machine. Cleared for this process only, or this
# environment would load ZKBioTime's standard library. The machine setting is not changed.
Remove-Item Env:PYTHONHOME -ErrorAction SilentlyContinue
$runs = @(
    @("email", "text_body"), @("url", "text_host"), @("url", "text_full")
)
foreach ($r in $runs) {
    $name = "$($r[0])_$($r[1])"
    Add-Content "$logs\summary.log" "$(Get-Date -Format s) START $name"
    cmd /c "`"$py`" -u -m phishguard_ml train-text --modality $($r[0]) --input $($r[1]) --models cnn_1d --resume >> `"$logs\$name.log`" 2>&1"
    Add-Content "$logs\summary.log" "$(Get-Date -Format s) END $name exit $LASTEXITCODE"
}
Add-Content "$logs\summary.log" "$(Get-Date -Format s) TEXT QUEUE FINISHED"
