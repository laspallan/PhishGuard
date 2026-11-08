# Shows a Windows notification when a long job reaches a milestone. Run every 30 minutes by the
# scheduled task "PhishGuard status" (see ml/README.md). Reads only local files; sends nothing.
#   - training queues: each new END / QUEUE FINISHED line in data\train_logs\summary.log
#     (a non-zero exit is shown as FAILED)
#   - SpamAssassin baseline: its result file appears
#   - RQ2: today's lookups reach the daily quota (500), once per day
# Remembers what it has already shown in data\notify_state.json.
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$data = Join-Path $root "data"
$statePath = Join-Path $data "notify_state.json"

function Show-Toast([string]$title, [string]$text) {
    [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime] | Out-Null
    $xml = [Windows.UI.Notifications.ToastNotificationManager]::GetTemplateContent(
        [Windows.UI.Notifications.ToastTemplateType]::ToastText02)
    $lines = $xml.GetElementsByTagName("text")
    $lines.Item(0).AppendChild($xml.CreateTextNode($title)) | Out-Null
    $lines.Item(1).AppendChild($xml.CreateTextNode($text)) | Out-Null
    # PowerShell's own app id, so Windows shows the toast without registering a new app.
    $app = "{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe"
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($app).Show(
        [Windows.UI.Notifications.ToastNotification]::new($xml))
}

$state = @{ summary_lines = -1; baseline_done = $false; rq2_days = @() }
if (Test-Path $statePath) {
    $saved = Get-Content $statePath -Raw | ConvertFrom-Json
    $state.summary_lines = [int]$saved.summary_lines
    $state.baseline_done = [bool]$saved.baseline_done
    $state.rq2_days = @($saved.rq2_days | Where-Object { $_ })
}
$first = $state.summary_lines -lt 0   # first run: remember the current state, show nothing old

# Training queues
$summary = Join-Path $data "train_logs\summary.log"
if (Test-Path $summary) {
    $all = @(Get-Content $summary)
    if (-not $first -and $all.Count -gt $state.summary_lines) {
        foreach ($line in $all[$state.summary_lines..($all.Count - 1)]) {
            if ($line -match "END (\S+) exit (\d+)") {
                $status = if ($Matches[2] -eq "0") { "finished" } else { "FAILED (exit $($Matches[2]))" }
                Show-Toast "PhishGuard training" "$($Matches[1]) $status"
            } elseif ($line -match "QUEUE FINISHED") {
                Show-Toast "PhishGuard training" ($line -replace "^\S+ ", "")
            }
        }
    }
    $state.summary_lines = $all.Count
} elseif ($first) {
    $state.summary_lines = 0
}

# SpamAssassin baseline
$baseline = Join-Path $data "models\baseline\email_spamassassin.parquet"
if ((Test-Path $baseline) -and -not $state.baseline_done) {
    if (-not $first) { Show-Toast "PhishGuard baseline" "SpamAssassin scores imported; run: python -m phishguard_ml report" }
    $state.baseline_done = $true
}

# RQ2: today's (UTC) lookups
$today = (Get-Date).ToUniversalTime().ToString("yyyy-MM-dd")
$ti = Join-Path $data "ti_responses\ti_$today.jsonl"
if ((Test-Path $ti) -and ($state.rq2_days -notcontains $today)) {
    $n = @(Select-String -Path $ti -Pattern '"sample_id": "' -SimpleMatch).Count
    if ($n -ge 500) {
        Show-Toast "PhishGuard RQ2" "Today's $n lookups are done ($today)"
        $state.rq2_days = @($state.rq2_days) + $today
    }
}

$state | ConvertTo-Json | Set-Content -Path $statePath -Encoding utf8
